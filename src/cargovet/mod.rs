//! The cargo-vet fast path: the `audits.toml` parser, and the multi-source
//! sync that mirrors every configured trusted audit set into the local
//! database.
//!
//! [`parse::parse_audits_toml`] is pure. It does no I/O, so tests call it
//! directly against TOML. [`CargoVetSync`] is the only part of this
//! module that touches the network. It fetches each configured source's
//! `audits.toml`, parses the body, and calls
//! [`crate::db::cargo_vet::CargoVetStore::replace_source`] for that source
//! alone.
//!
//! Sources are independent. This is the one place where this sync differs
//! from [`crate::advisory::osv::OsvSync`]. There, a bad feed leaves the
//! whole existing mirror untouched. Here, the sync logs a source's failure
//! and skips it, then fetches the next source. A down Mozilla endpoint
//! must not stop Google's audits or the org's own audits from updating. It
//! must also not erase what that source last published.

pub mod parse;

use std::time::Duration;

use anyhow::Context;

use crate::config::CargoVetSource;
use crate::db::cargo_vet::CargoVetStore;

/// Upper bound on establishing the TCP/TLS connection to one audit source.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on an entire `audits.toml` request. The file is a small
/// document, so a total deadline is the right shape.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Sent on every audit fetch. crates.io and the audit mirrors are public
/// services, and an anonymous client with no identifier is not welcome
/// traffic.
const USER_AGENT: &str = concat!(
    "supply-chain-scanner/",
    env!("CARGO_PKG_VERSION"),
    " (cargo-vet audit sync)"
);

/// Mirrors every configured cargo-vet audit set into the local database.
///
/// The sync holds a [`CargoVetStore`] and the configured source list. The
/// source list comes from `[cargo_registry].cargo_vet_sources`. The sync
/// builds its own HTTP client. The two timeouts and the User-Agent below
/// belong to this sync, so a shared client must not carry them.
pub struct CargoVetSync {
    store: std::sync::Arc<CargoVetStore>,
    sources: Vec<CargoVetSource>,
    http: reqwest::Client,
}

impl CargoVetSync {
    /// Builds a sync over `sources`. The sync writes into `store`.
    ///
    /// This fails only when the HTTP client cannot be built. A broken TLS
    /// backend can cause that failure, so the function returns a `Result`
    /// even though it makes no network call.
    pub fn new(
        store: std::sync::Arc<CargoVetStore>,
        sources: Vec<CargoVetSource>,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .context("building the cargo-vet sync HTTP client")?;
        Ok(Self {
            store,
            sources,
            http,
        })
    }

    /// Fetches every configured source's `audits.toml`, parses the body,
    /// and replaces that source's rows with the freshly parsed set.
    ///
    /// The return value is the total number of full audit entries stored
    /// across every source that answered. The sync logs a source whose
    /// fetch, parse, or store write fails, then it skips that source. The
    /// remaining sources still sync, and the failed source keeps the rows
    /// it last published. The module docs explain why this is deliberate.
    ///
    /// The function attempts every source, so it returns an error only
    /// when no source synced and at least one source failed. A caller that
    /// needs "did every source answer" must compare the returned count
    /// against its own expectation. The contract here is "sync what you
    /// can".
    pub async fn sync_all(&self) -> anyhow::Result<usize> {
        let mut total = 0;
        let mut failures = 0;

        for source in &self.sources {
            match self.sync_one(source).await {
                Ok(count) => {
                    tracing::info!(
                        source = %source.name,
                        count,
                        "cargo-vet audit source synced"
                    );
                    total += count;
                }
                Err(err) => {
                    failures += 1;
                    tracing::warn!(
                        source = %source.name,
                        error = %err,
                        "cargo-vet audit source sync failed; keeping its existing audits"
                    );
                }
            }
        }

        if failures > 0 && failures == self.sources.len() {
            anyhow::bail!("every cargo-vet audit source failed to sync ({failures} sources)");
        }

        Ok(total)
    }

    /// Fetches, parses, and stores one source's `audits.toml`.
    async fn sync_one(&self, source: &CargoVetSource) -> anyhow::Result<usize> {
        let response = self
            .http
            .get(source.url.clone())
            .send()
            .await
            .with_context(|| format!("requesting audits.toml from {}", source.url))?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!(
                "audits.toml request to {} returned status {status}",
                source.url
            );
        }

        let body = response
            .text()
            .await
            .with_context(|| format!("reading audits.toml body from {}", source.url))?;

        let entries = parse::parse_audits_toml(&body, &source.name)
            .with_context(|| format!("parsing audits.toml from {}", source.url))?;

        self.store
            .replace_source(&source.name, &entries)
            .with_context(|| format!("storing audits for source {:?}", source.name))
    }
}

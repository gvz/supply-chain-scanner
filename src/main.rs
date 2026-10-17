//! Supply chain scanner binary: a thin wrapper around the library's own
//! fail-closed startup sequence ([`supply_chain_scanner::http::bootstrap`]),
//! plus the operational concerns that only make sense for a real running
//! process — the periodic advisory-sync and cache-eviction tickers, the
//! `SIGHUP` config-reload handler, and binding the actual listener.
//!
//! Served HTTP/1.1 only: `axum` and `hyper` are both built here with only
//! the `http1` Cargo feature enabled (see `Cargo.toml`), so this process
//! cannot speak HTTP/2 even if asked to — pip's error reporting depends
//! on the HTTP/1.1 status line's reason phrase, which has no HTTP/2
//! equivalent.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::config::Config;
use supply_chain_scanner::http::{bootstrap, watch_for_reload};

/// An HTTP proxy that scans PyPI artifacts before serving them.
#[derive(Debug, Parser)]
#[command(name = "supply-chain-scanner", version)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long)]
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    let runtime = tokio::runtime::Runtime::new().context("building the tokio runtime")?;
    runtime.block_on(run(config, cli.config))
}

async fn run(config: Config, config_path: PathBuf) -> anyhow::Result<()> {
    let bind = config.bind;
    let cache_dir = config.cache_dir.clone();
    let cache_ttl = config.cache_ttl;
    let db_path = config.db_path.clone();
    let advisory_sync_interval = config.advisory_sync_interval;
    let advisory_source_url = config.advisory_source_url.clone();

    tracing::info!(?bind, config = %config_path.display(), "starting up");

    let wired = bootstrap(config).await.context("startup failed")?;
    tracing::info!("startup sequence completed; every configured check is available");

    spawn_advisory_sync_ticker(db_path.clone(), advisory_source_url, advisory_sync_interval);
    spawn_cache_eviction_ticker(db_path, cache_dir, cache_ttl);

    // Say up front which fields a later SIGHUP can and cannot change, so
    // an operator learns it from the log rather than from a reload that
    // appeared to succeed.
    tracing::info!(
        reloadable = "cve, plugins, allowlist, public_url, scan_budget",
        restart_only = "bind, db_path, cache_dir, upstream_url, advisory_source_url, \
                        advisory_sync_interval, cache_ttl",
        "SIGHUP reloads the fields under `reloadable` (rebuilding the policy, the \
         fingerprint and the plugin sandbox); a SIGHUP whose file changes any field \
         under `restart_only` is rejected in full and names the field"
    );

    let reloader = Arc::clone(&wired.reloader);
    tokio::spawn(async move {
        if let Err(err) = watch_for_reload(reloader, config_path).await {
            tracing::error!(error = %err, "SIGHUP reload handler exited");
        }
    });

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding listener on {bind}"))?;
    tracing::info!(%bind, "listening");

    // `axum::serve` here only ever negotiates HTTP/1.1: neither `axum`
    // nor `hyper` were built with their `http2` Cargo feature, so the h2
    // crate is not even compiled into this binary.
    axum::serve(listener, wired.router)
        .await
        .context("serving HTTP")
}

/// Periodically re-syncs the OSV advisory mirror, reusing one database
/// connection pool and HTTP client for the life of the ticker. A failed
/// sync is logged and simply tried again next tick, leaving the existing
/// mirror untouched in the meantime (see
/// [`supply_chain_scanner::advisory::osv::OsvSync::sync_pypi`]).
fn spawn_advisory_sync_ticker(db_path: PathBuf, source_url: url::Url, interval: Duration) {
    tokio::spawn(async move {
        let db = match supply_chain_scanner::db::Db::open(&db_path)
            .context("opening database for the advisory sync ticker")
        {
            Ok(db) => db,
            Err(err) => {
                tracing::error!(error = %err, "advisory sync ticker could not open the database; it will not run");
                return;
            }
        };
        let http = match reqwest::Client::builder()
            .build()
            .context("building the advisory sync HTTP client")
        {
            Ok(http) => http,
            Err(err) => {
                tracing::error!(error = %err, "advisory sync ticker could not build an HTTP client; it will not run");
                return;
            }
        };
        let store = supply_chain_scanner::db::advisory::AdvisoryStore::new(db);
        let sync = supply_chain_scanner::advisory::osv::OsvSync::new(store, http, source_url);

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // the first tick fires immediately; bootstrap already synced once.
        loop {
            ticker.tick().await;
            match sync.sync_pypi().await {
                Ok(count) => tracing::info!(count, "advisory mirror synced"),
                Err(err) => tracing::warn!(
                    error = %err,
                    "periodic advisory sync failed; keeping the existing mirror"
                ),
            }
        }
    });
}

/// Periodically evicts artifact-cache entries whose sliding TTL has
/// expired, reusing one database connection pool for the life of the
/// ticker. Purely a performance feature (see
/// [`supply_chain_scanner::artifact_cache::ArtifactCache`]'s own docs):
/// a failed eviction sweep never affects what the scanner is willing to
/// serve.
fn spawn_cache_eviction_ticker(db_path: PathBuf, cache_dir: PathBuf, ttl: Duration) {
    tokio::spawn(async move {
        let cache = match supply_chain_scanner::db::Db::open(&db_path)
            .context("opening database for the cache eviction ticker")
            .and_then(|db| {
                ArtifactCache::new(db, cache_dir)
                    .context("opening artifact cache for the eviction ticker")
            }) {
            Ok(cache) => Arc::new(cache),
            Err(err) => {
                tracing::error!(error = %err, "cache eviction ticker could not start; it will not run");
                return;
            }
        };

        let mut ticker = tokio::time::interval(ttl.max(Duration::from_secs(60)));
        loop {
            ticker.tick().await;
            let cache = Arc::clone(&cache);
            let result = tokio::task::spawn_blocking(move || cache.evict_expired(ttl)).await;

            match result {
                Ok(Ok(removed)) => tracing::info!(removed, "artifact cache eviction swept"),
                Ok(Err(err)) => tracing::warn!(error = %err, "artifact cache eviction failed"),
                Err(join_err) => {
                    tracing::warn!(error = %join_err, "artifact cache eviction task panicked")
                }
            }
        }
    });
}

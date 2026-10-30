//! Startup for a cargo/crates.io deployment: the cargo counterpart to
//! [`super::bootstrap`].
//!
//! The two deployments share a binary but not a wiring. A cargo
//! deployment has no PEP 503 simple index, no wheel or sdist artifact
//! path, and no `Scanner`; it has a sparse index, a `.crate` download
//! gate, and a [`CargoScanner`]. So this module builds its own
//! [`CargoAppState`] and mounts its own router
//! ([`crate::http::cargo_index::cargo_router`]) instead of reusing
//! [`super::Wired`].
//!
//! # The dispatch rule
//!
//! `[cargo_registry]`'s presence is the switch. `main`'s `run` checks
//! `config.cargo_registry.is_some()` and calls
//! [`bootstrap_cargo`] instead of [`super::bootstrap`]. `Config` is one
//! struct with both halves `Option`-al at once, and this module does not
//! restructure it into an enum: the design spec ships the two ecosystems
//! as two deployments of one binary, and an enum would ripple through
//! every existing PyPI test's config fixture for no behavioural gain.
//!
//! One consequence is documented rather than removed: `Config::upstream_url`
//! is required whether or not `[cargo_registry]` is present, and a cargo
//! deployment never reads it. An operator running cargo sets it to
//! anything valid and it stays unused — see
//! [`crate::config::CargoRegistryConfig`].
//!
//! # Fail-closed order
//!
//! The sequence mirrors [`super::bootstrap`] step for step, and a failure
//! anywhere returns `Err` rather than a `CargoWired` backed by fewer
//! checks than the configuration asked for:
//!
//! 1. `Db::open` (migrations run inside it).
//! 2. `Policy::build` — fails if a configured plugin binary is missing or
//!    unreadable.
//! 3. The sandbox from [`super::default_sandbox_factory`] — fails if
//!    `bwrap` is absent while plugins or `[ai_review]` are configured.
//! 4. `PluginRunner`, then the `AiReviewer` via [`super::build_ai_reviewer`].
//! 5. `ArtifactCache`, then the `CargoUpstream`.
//! 6. An initial OSV sync for `"crates.io"` when that mirror is empty, on
//!    the same `advisory_source_url` the PyPI path uses.
//! 7. An initial `CargoVetSync::sync_all` when the cargo-vet store is
//!    empty.
//! 8. `CargoScanner`, the state, and the router.
//!
//! # No `Reloader`
//!
//! [`super::Wired`] carries a `Reloader` so `SIGHUP` can swap in a new
//! policy, plugin list and reviewer. [`CargoWired`] does not, and
//! `[cargo_registry]` is not among the reloadable or the restart-only
//! fields: `SIGHUP` reload is a PyPI-path feature for now. A cargo
//! deployment logs a warning at startup saying so instead of spawning
//! [`super::watch_for_reload`], so an operator learns that a
//! configuration change needs a restart rather than from a signal that
//! silently changed nothing.
//!
//! # Why two `CargoUpstream` clients
//!
//! [`CargoScanner`] takes its upstream by value, and [`CargoAppState`]
//! needs one too: the download gate reads the matched index entry's
//! `cksum` and fetches the `.crate` bytes directly, and `CargoScanner`
//! exposes neither. Building two clients against the same index root is
//! what [`crate::http::cargo_download`]'s own tests do. Each keeps its own
//! lazily fetched `dl` template.

use std::sync::Arc;

use anyhow::Context;
use axum::Router;

use crate::advisory::osv::OsvSync;
use crate::artifact_cache::ArtifactCache;
use crate::cargovet::CargoVetSync;
use crate::config::{Config, ConfigHandle};
use crate::db::advisory::AdvisoryStore;
use crate::db::cargo_vet::CargoVetStore;
use crate::db::review::ReviewStore;
use crate::db::verdict::VerdictStore;
use crate::db::Db;
use crate::ecosystem::cargo::normalize_name;
use crate::ecosystem::cargo::upstream::CargoUpstream;
use crate::plugin::PluginRunner;
use crate::policy::Policy;
use crate::scan::cargo::CargoScanner;
use crate::scan::coordinator::ScanCoordinator;

use super::cargo_index::{cargo_router, CargoAppState};
use super::{build_ai_reviewer, default_sandbox_factory, SandboxFactory};

/// The advisory ecosystem id a cargo deployment syncs. The OSV feed for
/// crates.io is published under this id, and
/// [`crate::scan::cargo`] consults it alongside its own `"cargo"`
/// ecosystem.
pub const CARGO_ADVISORY_ECOSYSTEM: &str = "crates.io";

/// Everything [`bootstrap_cargo`] produces: the router ready to be
/// served, the [`CargoAppState`] it was built from (so `main` or an
/// integration test can reach the scanner, the verdicts and the config
/// directly), and the opened [`Db`] (so a caller can inspect, for
/// example, the cargo-vet mirror without reopening the same SQLite
/// file).
///
/// There is deliberately no `reloader` field: see this module's docs.
pub struct CargoWired {
    pub router: Router,
    pub state: CargoAppState,
    pub db: Db,
}

/// The production startup sequence for a cargo deployment. See this
/// module's docs for the exact, fail-closed order.
///
/// Requires `config.cargo_registry`; a config without it is an error
/// here, because `main` only takes this path when the table is present.
pub async fn bootstrap_cargo(config: Config) -> anyhow::Result<CargoWired> {
    bootstrap_cargo_with_sandbox_factory(config, default_sandbox_factory()).await
}

/// [`bootstrap_cargo`] with an injectable sandbox factory.
///
/// Exists for the same reason [`super::Reloader::with_sandbox_factory`]
/// does: the end-to-end bootstrap test needs the whole wiring — the
/// plugin gate and the AI reviewer's collector included — without
/// depending on `bwrap` and usable user namespaces existing in the test
/// environment. Production always goes through [`bootstrap_cargo`], which
/// passes [`super::default_sandbox_factory`], so no deployment can select
/// a weaker sandbox by accident. Everything except the sandbox is
/// identical between the two entry points.
pub async fn bootstrap_cargo_with_sandbox_factory(
    config: Config,
    sandbox_factory: SandboxFactory,
) -> anyhow::Result<CargoWired> {
    let Some(cargo) = config.cargo_registry.clone() else {
        anyhow::bail!(
            "a cargo deployment needs a [cargo_registry] table, and this configuration \
             has none; refusing to start rather than serve a cargo router with no \
             upstream index"
        );
    };

    let db = Db::open(&config.db_path)
        .with_context(|| format!("opening database at {}", config.db_path.display()))?;

    let config = Arc::new(config);
    let policy = Arc::new(
        Policy::build(Arc::clone(&config))
            .context("building policy (a configured plugin binary may be missing or unreadable)")?,
    );

    let sandbox = sandbox_factory(&config)?;
    let plugin_runner = PluginRunner::new(Arc::clone(&sandbox));

    // `build_ai_reviewer` is private to `super`, and a child module can
    // reach a private item of its ancestor, so the cargo path reuses it
    // unchanged rather than widening or moving it. It is already
    // ecosystem-agnostic: `AiReviewer::review` takes an `ArtifactKey` and
    // a directory, which is all a cargo review needs too.
    let ai_reviewer = match config.ai_review() {
        Some(cfg) => Some(build_ai_reviewer(cfg, Arc::clone(&sandbox), db.clone())?),
        None => None,
    };

    let artifact_cache = ArtifactCache::new(db.clone(), config.cache_dir.clone())
        .context("opening the artifact cache")?;

    let upstream = CargoUpstream::with_limits(cargo.upstream_index_url.clone(), &config.download)
        .context("constructing the cargo upstream client")?;
    // See this module's docs: the download gate needs a client of its own.
    let download_upstream =
        CargoUpstream::with_limits(cargo.upstream_index_url.clone(), &config.download)
            .context("constructing the download gate's cargo upstream client")?;

    let advisory_store = AdvisoryStore::new(db.clone());
    if advisory_store
        .is_empty(CARGO_ADVISORY_ECOSYSTEM)
        .context("checking whether the crates.io advisory mirror is empty")?
    {
        let osv_http = reqwest::Client::builder()
            .build()
            .context("building the advisory sync HTTP client")?;
        let sync = OsvSync::new(
            AdvisoryStore::new(db.clone()),
            osv_http,
            config.advisory_source_url.clone(),
        );
        sync.sync(CARGO_ADVISORY_ECOSYSTEM, normalize_name)
            .await
            .context("running the initial crates.io advisory sync")?;
    }

    let vet_store = CargoVetStore::new(db.clone());
    if vet_store
        .is_empty()
        .context("checking whether the cargo-vet audit store is empty")?
    {
        // `sync_all` already logs and skips one source's failure; it
        // only returns `Err` when every configured source failed. That is
        // propagated here for the same reason a failed initial advisory
        // sync is: a deployment that cannot populate the store it booted
        // to populate should not claim startup succeeded.
        let sync = CargoVetSync::new(
            Arc::new(CargoVetStore::new(db.clone())),
            cargo.cargo_vet_sources,
        )
        .context("building the cargo-vet sync")?;
        sync.sync_all()
            .await
            .context("running the initial cargo-vet audit sync")?;
    }

    let config_handle = Arc::new(ConfigHandle::new((*config).clone()));

    let scanner = CargoScanner::new(
        upstream,
        AdvisoryStore::new(db.clone()),
        vet_store,
        VerdictStore::new(db.clone()),
        policy,
        ai_reviewer,
        Arc::clone(&config_handle),
        Arc::new(ScanCoordinator::new()),
    );

    let state = CargoAppState {
        cargo_scanner: Arc::new(scanner),
        config: config_handle,
        upstream: Arc::new(download_upstream),
        verdicts: Arc::new(VerdictStore::new(db.clone())),
        plugins: Arc::new(plugin_runner),
        artifact_cache: Arc::new(artifact_cache),
        // The AI-review audit table. `/why/<id>` reads the report behind a
        // refusal out of it, and `/api/reviews` lists it. The reviewer
        // that writes these rows is built above from this same database.
        reviews: Arc::new(ReviewStore::new(db.clone())),
        // A coordinator of its own, separate from the one `CargoScanner`
        // holds internally for the AI-review cascade: that one
        // deduplicates by (package, candidate version) at index time,
        // this one deduplicates `.crate` downloads by artifact sha256 at
        // download time, exactly as the PyPI path keeps its full-scan
        // and fetch coordinators separate (`Scanner::coordinator` vs.
        // `Scanner::fetch_coordinator`).
        plugin_run_coordinator: Arc::new(ScanCoordinator::new()),
    };

    let router = cargo_router(state.clone());

    Ok(CargoWired { router, state, db })
}

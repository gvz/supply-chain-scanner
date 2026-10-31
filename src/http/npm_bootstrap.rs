//! Startup for an npm registry deployment: the npm counterpart to
//! [`super::cargo_bootstrap`].
//!
//! The deployments share a binary but not a wiring. An npm deployment has
//! no PEP 503 simple index, no `Scanner`, and no sparse index; it has a
//! packument route, a `.tgz` download gate, and an [`NpmScanner`]. So this
//! module builds its own [`NpmAppState`] and mounts its own router
//! ([`super::npm_packument::npm_router`]) instead of reusing
//! [`super::Wired`] or [`super::CargoWired`].
//!
//! # The dispatch rule
//!
//! `[npm_registry]`'s presence is the switch. `main`'s `run` checks
//! `config.npm_registry.is_some()` first and calls [`bootstrap_npm`] when
//! it holds. [`crate::config::Config::validate`] already rejects a config
//! carrying both `[cargo_registry]` and `[npm_registry]`, so the two
//! tables cannot both select a deployment.
//!
//! # An npm deployment requires a reviewer
//!
//! [`bootstrap_npm`] refuses to start without a usable `[ai_review]`
//! table, and that is deliberate. The npm cascade has no fast path past
//! AI review — no cargo-vet equivalent, nothing that can stand in for a
//! reviewer — so a deployment without one can never forward a single
//! version that is not already allowlisted. Serving a registry that
//! answers every install with an empty packument is worse than a clear
//! startup failure, because the failure is visible at once and the empty
//! registry looks like an upstream problem for as long as it runs. See
//! [`crate::scan::npm`]'s module docs for the cascade's own statement of
//! the same fact.
//!
//! The check uses [`crate::config::Config::ai_review`], which reports
//! `None` for a table that is present but has `enabled = false`. A
//! disabled reviewer cannot review, so it is refused exactly like an
//! absent one.
//!
//! # Fail-closed order
//!
//! The sequence mirrors [`super::cargo_bootstrap`] step for step, and a
//! failure anywhere returns `Err` rather than an [`NpmWired`] backed by
//! fewer checks than the configuration asked for:
//!
//! 1. The `[npm_registry]` table, then the `[ai_review]` requirement.
//! 2. `Db::open` (migrations run inside it).
//! 3. `Policy::build` — fails if a configured plugin binary is missing or
//!    unreadable.
//! 4. The sandbox from [`super::default_sandbox_factory`] — fails if
//!    `bwrap` is absent while plugins or `[ai_review]` are configured.
//! 5. `PluginRunner`, then the [`AiReviewer`] via
//!    [`super::build_ai_reviewer`].
//! 6. `ArtifactCache`, then the two `NpmUpstream` clients.
//! 7. An initial OSV sync for `"npm"` when that mirror is empty, on the
//!    same `advisory_source_url` the PyPI path uses.
//! 8. [`NpmScanner::new`], the state, and the router.
//!
//! # No second ecosystem constant
//!
//! The cargo path keeps two ids because OSV publishes its feed under
//! `"crates.io"` while verdicts are stored under `"cargo"`. npm has no
//! such split: OSV's own feed spells the ecosystem `"npm"`, and so does
//! every artifact key and verdict row here. [`super::npm_packument::NPM_ECOSYSTEM`]
//! is that one value, and this module reuses it rather than introducing a
//! second name for the same string.
//!
//! # No `Reloader`
//!
//! [`super::Wired`] carries a `Reloader` so `SIGHUP` can swap in a new
//! policy, plugin list and reviewer. [`NpmWired`] does not: `SIGHUP`
//! reload is a PyPI-path feature for now, and `main` logs the same
//! restart-only warning it logs for a cargo deployment instead of
//! spawning [`super::watch_for_reload`].
//!
//! # Why two `NpmUpstream` clients
//!
//! [`NpmScanner`] takes its upstream by value, and [`NpmAppState`] needs
//! one too: the tarball gate reads the matched version's `dist` object and
//! fetches the `.tgz` bytes directly, and `NpmScanner` exposes neither.
//! Building two clients against the same registry base is what
//! [`crate::http::npm_download`]'s own tests do. Each keeps its own
//! packument ETag/body cache, which costs a redundant metadata fetch on a
//! download-gate cache miss and nothing in correctness.

use std::sync::Arc;

use anyhow::Context;
use axum::Router;

use crate::advisory::osv::OsvSync;
use crate::artifact_cache::ArtifactCache;
use crate::config::{Config, ConfigHandle};
use crate::db::advisory::AdvisoryStore;
use crate::db::review::ReviewStore;
use crate::db::verdict::VerdictStore;
use crate::db::Db;
use crate::ecosystem::npm::normalize_name;
use crate::ecosystem::npm::upstream::NpmUpstream;
use crate::plugin::PluginRunner;
use crate::policy::Policy;
use crate::scan::coordinator::ScanCoordinator;
use crate::scan::npm::NpmScanner;

use super::npm_packument::{npm_router, NpmAppState, NPM_ECOSYSTEM};
use super::{build_ai_reviewer, default_sandbox_factory, SandboxFactory};

/// Everything [`bootstrap_npm`] produces: the router ready to be served,
/// the [`NpmAppState`] it was built from (so `main` or an integration test
/// can reach the scanner, the verdicts and the config directly), and the
/// opened [`Db`] (so a caller can inspect, for example, the advisory
/// mirror without reopening the same SQLite file).
///
/// There is deliberately no `reloader` field: see this module's docs.
pub struct NpmWired {
    pub router: Router,
    pub state: NpmAppState,
    pub db: Db,
}

/// The production startup sequence for an npm deployment. See this
/// module's docs for the exact, fail-closed order.
///
/// Requires `config.npm_registry`; a config without it is an error here,
/// because `main` only takes this path when the table is present.
pub async fn bootstrap_npm(config: Config) -> anyhow::Result<NpmWired> {
    bootstrap_npm_with_sandbox_factory(config, default_sandbox_factory()).await
}

/// [`bootstrap_npm`] with an injectable sandbox factory.
///
/// Exists for the same reason [`super::bootstrap_cargo_with_sandbox_factory`]
/// does: the end-to-end bootstrap test needs the whole wiring — the plugin
/// gate and the AI reviewer's collector included — without depending on
/// `bwrap` and usable user namespaces existing in the test environment.
/// Production always goes through [`bootstrap_npm`], which passes
/// [`super::default_sandbox_factory`], so no deployment can select a
/// weaker sandbox by accident. Everything except the sandbox is identical
/// between the two entry points.
pub async fn bootstrap_npm_with_sandbox_factory(
    config: Config,
    sandbox_factory: SandboxFactory,
) -> anyhow::Result<NpmWired> {
    let Some(npm) = config.npm_registry.clone() else {
        anyhow::bail!(
            "an npm deployment needs an [npm_registry] table, and this configuration \
             has none; refusing to start rather than serve an npm router with no \
             upstream registry"
        );
    };

    // An npm deployment with no usable reviewer can never forward a
    // version. See this module's docs for why that is a refusal and not a
    // warning.
    let Some(ai_config) = config.ai_review() else {
        tracing::error!(
            "no [ai_review] is configured for this npm deployment; the npm cascade has no \
             fast path past AI review, so no version could ever be forwarded. Refusing to \
             start rather than serve a registry that can never answer"
        );
        anyhow::bail!(
            "an npm deployment requires a configured [ai_review] table: without a reviewer \
             nothing could be forwarded, because npm has no cargo-vet-shaped fast path past \
             AI review; refusing to start rather than serve a registry that can never answer"
        );
    };
    let ai_config = ai_config.clone();

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
    // reach a private item of its ancestor, so the npm path reuses it
    // unchanged rather than widening or moving it. It is already
    // ecosystem-agnostic: `AiReviewer::review` takes an `ArtifactKey` and
    // a directory, which is all an npm review needs too.
    let ai_reviewer = build_ai_reviewer(&ai_config, Arc::clone(&sandbox), db.clone())
        .context("building the ai reviewer from the [ai_review] table")?;

    let artifact_cache = ArtifactCache::new(db.clone(), config.cache_dir.clone())
        .context("opening the artifact cache")?;
    // `ArtifactCache` is not `Clone`, and both the scanner and the state
    // need one: the cascade stores a reviewed tarball's bytes for the
    // download gate to reuse, and the download gate serves and stores its
    // own. Two handles over the same directory and database are the same
    // cache — see [`crate::artifact_cache`] — so this costs no duplicate
    // storage.
    let download_artifact_cache = ArtifactCache::new(db.clone(), config.cache_dir.clone())
        .context("opening the download gate's artifact cache")?;

    let upstream = NpmUpstream::with_limits(
        npm.upstream_registry_url.clone(),
        npm.max_packument_bytes,
        &config.download,
    )
    .context("constructing the npm upstream client")?;
    // See this module's docs: the download gate needs a client of its own.
    let download_upstream = NpmUpstream::with_limits(
        npm.upstream_registry_url.clone(),
        npm.max_packument_bytes,
        &config.download,
    )
    .context("constructing the download gate's npm upstream client")?;

    let advisory_store = AdvisoryStore::new(db.clone());
    if advisory_store
        .is_empty(NPM_ECOSYSTEM)
        .context("checking whether the npm advisory mirror is empty")?
    {
        let osv_http = reqwest::Client::builder()
            .build()
            .context("building the advisory sync HTTP client")?;
        let sync = OsvSync::new(
            AdvisoryStore::new(db.clone()),
            osv_http,
            config.advisory_source_url.clone(),
        );
        sync.sync(NPM_ECOSYSTEM, normalize_name)
            .await
            .context("running the initial npm advisory sync")?;
    }

    let config_handle = Arc::new(ConfigHandle::new((*config).clone()));

    let scanner = NpmScanner::new(
        upstream,
        AdvisoryStore::new(db.clone()),
        VerdictStore::new(db.clone()),
        policy,
        Some(ai_reviewer),
        Arc::clone(&config_handle),
        Arc::new(ScanCoordinator::new()),
        Arc::new(artifact_cache),
    );

    let state = NpmAppState {
        npm_scanner: Arc::new(scanner),
        config: config_handle,
        upstream: Arc::new(download_upstream),
        verdicts: Arc::new(VerdictStore::new(db.clone())),
        plugins: Arc::new(plugin_runner),
        artifact_cache: Arc::new(download_artifact_cache),
        // The AI-review audit table. `/why/<id>` reads the report behind a
        // refusal out of it, and `/api/reviews` lists it. The reviewer
        // that writes these rows is built above from this same database.
        reviews: Arc::new(ReviewStore::new(db.clone())),
        // A coordinator of its own, separate from the one `NpmScanner`
        // holds for its AI-review cascade: that one deduplicates by
        // (package, candidate version) at packument time, this one
        // deduplicates `.tgz` downloads by artifact digest at download
        // time. See `super::npm_download`'s docs.
        plugin_run_coordinator: Arc::new(ScanCoordinator::new()),
    };

    let router = npm_router(state.clone());

    Ok(NpmWired { router, state, db })
}

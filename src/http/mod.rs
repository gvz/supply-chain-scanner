//! The HTTP surface a developer's package manager actually talks to.
//!
//! [`AppState`] is shared by every handler; [`router`] wires it to the
//! actual routes: the PEP 503 simple index passthrough (`simple`), the
//! download/metadata proxy (`artifact`), the `/why/<id>` explanation page
//! (`why`), and the reason-phrase refusal responses (`refusal`) every
//! blocked or unverifiable request falls back to.
//!
//! The simple-index and artifact handlers take `Arc<dyn
//! crate::ecosystem::Ecosystem>` rather than a concrete PyPI type, so this
//! module does not change when a second ecosystem backend arrives. The
//! one exception is the PEP 658/714 `.metadata` sidecar: it is PyPI's own
//! extension to the simple index format, so the artifact handler reaches
//! past the trait and calls [`crate::ecosystem::pypi::upstream::Upstream::metadata_sidecar`]
//! directly, via an `Extension` layered onto the router alongside
//! `AppState`.

pub mod artifact;
pub mod refusal;
pub mod simple;
pub mod why;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::Router;

use crate::artifact_cache::ArtifactCache;
use crate::config::{Config, ConfigHandle};
use crate::db::advisory::AdvisoryStore;
use crate::db::index_cache::IndexCache;
use crate::db::verdict::VerdictStore;
use crate::db::Db;
use crate::ecosystem::pypi::upstream::Upstream;
use crate::ecosystem::pypi::PyPi;
use crate::ecosystem::Ecosystem;
use crate::plugin::{BubblewrapSandbox, PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec};
use crate::policy::Policy;
use crate::scan::Scanner;

/// Shared state handed to every HTTP handler.
///
/// Cheap to clone (every field is an `Arc`), as required by axum's
/// `State` extractor.
#[derive(Clone)]
pub struct AppState {
    pub scanner: Arc<Scanner>,
    pub verdicts: Arc<VerdictStore>,
    pub config: Arc<ConfigHandle>,
    pub ecosystem: Arc<dyn Ecosystem>,
}

/// Builds the router: the simple index, the artifact/metadata proxy,
/// `/why/<id>`, and `/healthz`. `upstream` is layered on as an
/// [`Extension`] so the artifact handler can call the PEP 658/714
/// metadata sidecar directly (see the module docs) without widening
/// [`AppState`] or the [`Ecosystem`] trait for a PyPI-only concern.
pub fn router(state: AppState, upstream: Arc<Upstream>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/simple/{package}/", get(simple::simple_handler))
        .route(
            "/files/{package}/{version}/{filename}",
            get(artifact::artifact_handler),
        )
        .route("/why/{id}", get(why::why_handler))
        .layer(Extension(upstream))
        .with_state(state)
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

/// Builds the `/why/<id>` URL for a stored verdict, rooted at
/// `config.public_url`. `None` only if `public_url` cannot be joined at
/// all (an operator misconfiguration), in which case the reason phrase
/// still names the refusal code, just without a link to expand on it.
pub(crate) fn why_url(config: &Config, why_id: &str) -> Option<String> {
    config
        .public_url
        .join(&format!("why/{why_id}"))
        .ok()
        .map(|url| url.to_string())
}

/// A plain-text 400, used when a package name arriving from a URL path
/// fails [`crate::ecosystem::traits::Ecosystem::validate_name`] — not a
/// refusal (nothing was scanned), just a malformed request.
pub(crate) fn bad_request_response(detail: &str) -> Response {
    plain_text_response(StatusCode::BAD_REQUEST, detail)
}

/// A plain-text 404, used when a package, version, or filename simply
/// does not exist in the upstream index — never used for an artifact that
/// *does* exist but was blocked, which goes through
/// [`refusal::refusal_response`] instead.
pub(crate) fn not_found_response() -> Response {
    plain_text_response(StatusCode::NOT_FOUND, "not found")
}

fn plain_text_response(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )
        .body(axum::body::Body::from(format!("{body}\n")))
        .unwrap_or_else(|_| {
            let mut response = Response::new(axum::body::Body::from("request failed\n"));
            *response.status_mut() = status;
            response
        })
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

/// Everything [`bootstrap`] produces: the router ready to be served, the
/// [`AppState`] it was built from (so a caller — `main` or an integration
/// test — can reach `config`/`scanner`/`verdicts` directly), and the
/// opened [`Db`] (so a caller can inspect, e.g., the advisory mirror
/// without reopening the same SQLite file).
pub struct Wired {
    pub router: Router,
    pub state: AppState,
    pub db: Db,
    /// Applies a `SIGHUP` reload to this already-running wiring; hand it
    /// to [`watch_for_reload`]. Built here rather than in `main` because
    /// it has to capture the exact [`Config`] this process booted under
    /// (see [`RESTART_ONLY_FIELDS`]).
    pub reloader: Arc<Reloader>,
}

/// The fail-closed startup sequence, in order: open the database
/// (migrations run inside [`Db::open`]), build the [`Policy`] (fails if
/// a configured plugin binary is missing or unreadable), detect the
/// sandbox only if plugins are configured at all (fails if `bwrap` is
/// absent from `PATH`), build the [`Scanner`], and run an initial
/// advisory sync if the mirror is empty. A failure anywhere in that
/// chain is returned as `Err` — this function never produces a `Wired`
/// backed by fewer checks than the configuration asked for.
///
/// Deliberately stops short of binding a listener, spawning the
/// periodic sync/eviction tickers, or installing the `SIGHUP` reload
/// handler: those are ongoing-operation concerns [`main`] layers on top
/// once this fallible sequence has already succeeded, kept separate so
/// an integration test can call this one function directly against a
/// stand-in upstream.
pub async fn bootstrap(config: Config) -> anyhow::Result<Wired> {
    let db = Db::open(&config.db_path)
        .with_context(|| format!("opening database at {}", config.db_path.display()))?;

    let config = Arc::new(config);
    let policy = Policy::build(Arc::clone(&config))
        .context("building policy (a configured plugin binary may be missing or unreadable)")?;

    let sandbox_factory = default_sandbox_factory();
    let sandbox = sandbox_factory(&config)?;
    let plugin_runner = PluginRunner::new(sandbox);

    let index_cache = IndexCache::new(db.clone());
    let simple_base = config
        .upstream_url
        .join("simple/")
        .context("building the upstream simple-index base URL")?;
    let scanner_upstream = Upstream::new(simple_base.clone(), index_cache.clone())
        .context("constructing the scanner's upstream client")?;
    let ecosystem_upstream = Arc::new(
        Upstream::new(simple_base, index_cache)
            .context("constructing the ecosystem's upstream client")?,
    );

    let advisory_store = AdvisoryStore::new(db.clone());
    if advisory_store
        .is_empty("pypi")
        .context("checking whether the advisory mirror is empty")?
    {
        let osv_http = reqwest::Client::builder()
            .build()
            .context("building the advisory sync HTTP client")?;
        let sync = crate::advisory::osv::OsvSync::new(
            AdvisoryStore::new(db.clone()),
            osv_http,
            config.advisory_source_url.clone(),
        );
        sync.sync_pypi()
            .await
            .context("running the initial advisory sync")?;
    }

    let artifact_cache = ArtifactCache::new(db.clone(), config.cache_dir.clone())
        .context("opening the artifact cache")?;
    let config_handle = Arc::new(ConfigHandle::new((*config).clone()));

    let scanner = Scanner::new(
        VerdictStore::new(db.clone()),
        scanner_upstream,
        policy,
        AdvisoryStore::new(db.clone()),
        plugin_runner,
        artifact_cache,
        Arc::clone(&config_handle),
    );

    let pypi: Arc<dyn Ecosystem> = Arc::new(PyPi::new(Arc::clone(&ecosystem_upstream)));

    let state = AppState {
        scanner: Arc::new(scanner),
        verdicts: Arc::new(VerdictStore::new(db.clone())),
        config: Arc::clone(&config_handle),
        ecosystem: pypi,
    };

    let reloader = Arc::new(Reloader::with_sandbox_factory(
        config_handle,
        Arc::clone(&state.scanner),
        &config,
        sandbox_factory,
    ));

    let router = router(state.clone(), ecosystem_upstream);

    Ok(Wired {
        router,
        state,
        db,
        reloader,
    })
}

/// A [`SandboxRunner`] that must never actually be invoked: used only
/// when no plugins are configured at all, in which case
/// [`PluginRunner::run_all`] never calls into it (its loop is over an
/// empty plugin list), but [`PluginRunner::new`] still needs a sandbox
/// value to hold. Mirrors the same fixture used in this crate's own
/// `src/scan/mod.rs` and `tests/http_refusal.rs` tests.
struct NeverCalledSandbox;

impl SandboxRunner for NeverCalledSandbox {
    fn run(&self, _spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        panic!("no plugins are configured; the sandbox must never run");
    }
}

// ---------------------------------------------------------------------------
// Configuration reload
// ---------------------------------------------------------------------------

/// Builds the sandbox a configuration calls for. Injectable so a test can
/// exercise a reload that adds a plugin without `bwrap` being involved;
/// production always uses [`default_sandbox_factory`].
pub type SandboxFactory =
    Arc<dyn Fn(&Config) -> anyhow::Result<Arc<dyn SandboxRunner>> + Send + Sync>;

/// The production sandbox: a real [`BubblewrapSandbox`] when plugins are
/// configured (failing if `bwrap` is absent, so the proxy never runs
/// fewer checks than the org asked for), and the panicking
/// [`NeverCalledSandbox`] stub when the plugin list is empty and
/// [`PluginRunner::run_all`]'s loop can therefore never reach it.
pub fn default_sandbox_factory() -> SandboxFactory {
    Arc::new(
        |config: &Config| -> anyhow::Result<Arc<dyn SandboxRunner>> {
            if config.plugins.is_empty() {
                Ok(Arc::new(NeverCalledSandbox))
            } else {
                Ok(Arc::new(BubblewrapSandbox::detect().context(
                    "detecting the bubblewrap sandbox (required because plugins are configured)",
                )?))
            }
        },
    )
}

/// Configuration fields that only take effect at process startup, with the
/// reason each one is stuck there.
///
/// Every entry here is captured as a local in `main::run` or baked into
/// something built once by [`bootstrap`]: `bind` into the bound listener,
/// `db_path` into every open connection pool, `cache_dir` into the
/// [`ArtifactCache`] root, `upstream_url` into both HTTP clients' base
/// URLs, `advisory_source_url`/`advisory_sync_interval` into the sync
/// ticker, and `cache_ttl` into the eviction ticker.
///
/// A reload that changes any of them is **rejected in full**. That is a
/// deliberate choice over the alternative of applying the rest: applying
/// part of a file while logging "configuration reloaded" is how an
/// operator comes to believe a tightened CVE line is live when it is not.
/// Rejecting, and naming the field, sends them to a restart instead.
const RESTART_ONLY_FIELDS: &[&str] = &[
    "bind",
    "db_path",
    "cache_dir",
    "upstream_url",
    "advisory_source_url",
    "advisory_sync_interval",
    "cache_ttl",
];

/// Configuration fields a reload genuinely applies, for the log line that
/// says so.
const RELOADABLE_FIELDS: &[&str] = &["cve", "plugins", "allowlist", "public_url", "scan_budget"];

/// Which restart-only fields `candidate` changes relative to the values
/// this process actually booted under.
fn restart_only_changes(boot: &Config, candidate: &Config) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if boot.bind != candidate.bind {
        changed.push("bind");
    }
    if boot.db_path != candidate.db_path {
        changed.push("db_path");
    }
    if boot.cache_dir != candidate.cache_dir {
        changed.push("cache_dir");
    }
    if boot.upstream_url != candidate.upstream_url {
        changed.push("upstream_url");
    }
    if boot.advisory_source_url != candidate.advisory_source_url {
        changed.push("advisory_source_url");
    }
    if boot.advisory_sync_interval != candidate.advisory_sync_interval {
        changed.push("advisory_sync_interval");
    }
    if boot.cache_ttl != candidate.cache_ttl {
        changed.push("cache_ttl");
    }
    changed
}

/// What a successful [`Reloader::apply`] changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadSummary {
    pub old_fingerprint: String,
    pub new_fingerprint: String,
    pub plugins: usize,
    pub allowlist: usize,
}

impl ReloadSummary {
    pub fn fingerprint_changed(&self) -> bool {
        self.old_fingerprint != self.new_fingerprint
    }
}

/// Applies a configuration file to a *running* proxy, as one atomic
/// all-or-nothing step.
///
/// This exists because swapping the [`ConfigHandle`] alone is not a
/// reload. The policy fingerprint and the CVE line are compiled into a
/// [`Policy`], and the plugin list needs a [`SandboxRunner`] built for
/// it, so a handle-only swap left the CVE line frozen while the plugin
/// list went live — a reload that logged success and changed nothing for
/// most of the file, with the fingerprint column no longer identifying
/// the checks that produced a row.
///
/// `apply` therefore parses, validates, builds the new `Policy` and the
/// new sandbox *first*, and only swaps anything in once all of that has
/// succeeded. A failure anywhere — malformed TOML, a `scan_budget` over
/// the ceiling, a plugin binary that cannot be read, no usable `bwrap`
/// for a newly added plugin, a restart-only field that changed — returns
/// `Err` with the previous configuration, policy and sandbox all still in
/// force. That is [`Policy::build`]'s fail-closed contract extended
/// across reload.
pub struct Reloader {
    config: Arc<ConfigHandle>,
    scanner: Arc<Scanner>,
    /// The values this process booted under, for [`restart_only_changes`].
    boot: Config,
    sandbox_factory: SandboxFactory,
}

impl Reloader {
    /// The production constructor: [`default_sandbox_factory`].
    pub fn new(config: Arc<ConfigHandle>, scanner: Arc<Scanner>, boot: &Config) -> Self {
        Self::with_sandbox_factory(config, scanner, boot, default_sandbox_factory())
    }

    pub fn with_sandbox_factory(
        config: Arc<ConfigHandle>,
        scanner: Arc<Scanner>,
        boot: &Config,
        sandbox_factory: SandboxFactory,
    ) -> Self {
        Self {
            config,
            scanner,
            boot: boot.clone(),
            sandbox_factory,
        }
    }

    /// Reads `path` and applies it, or returns `Err` having changed
    /// nothing. See the type docs.
    pub fn apply(&self, path: &std::path::Path) -> anyhow::Result<ReloadSummary> {
        let candidate = Config::load(path)?;

        let frozen = restart_only_changes(&self.boot, &candidate);
        if !frozen.is_empty() {
            anyhow::bail!(
                "reload rejected: {} can only change at startup and this process \
                 is already running under the previous value(s). Nothing was \
                 applied — the whole reload was refused rather than applying the \
                 rest and logging a success this proxy did not deliver. Restart \
                 to pick these up.",
                frozen.join(", ")
            );
        }

        let candidate = Arc::new(candidate);
        let policy = Policy::build(Arc::clone(&candidate)).context(
            "building the policy for the reloaded configuration (a configured plugin \
             binary may be missing or unreadable); keeping the previous policy",
        )?;
        let sandbox = (self.sandbox_factory)(&candidate).context(
            "building the sandbox for the reloaded configuration; keeping the \
             previous policy",
        )?;

        let summary = ReloadSummary {
            old_fingerprint: self.scanner.fingerprint(),
            new_fingerprint: policy.fingerprint().to_string(),
            plugins: candidate.plugins.len(),
            allowlist: candidate.allowlist.len(),
        };

        // Everything above succeeded, so from here nothing can fail and
        // leave the proxy half-reloaded.
        self.config.store((*candidate).clone());
        self.scanner.apply_reloaded_rules(
            policy,
            PluginRunner::new(sandbox),
            candidate.plugins.clone(),
        );

        tracing::info!(
            path = %path.display(),
            applied = %RELOADABLE_FIELDS.join(", "),
            restart_only = %RESTART_ONLY_FIELDS.join(", "),
            plugins = summary.plugins,
            allowlist = summary.allowlist,
            policy_fingerprint_changed = summary.fingerprint_changed(),
            old_fingerprint = %summary.old_fingerprint,
            new_fingerprint = %summary.new_fingerprint,
            "configuration reloaded; the fields under `applied` are now live, and \
             a change to any field under `restart_only` would have rejected this \
             reload outright rather than being ignored"
        );
        if summary.fingerprint_changed() {
            tracing::warn!(
                old_fingerprint = %summary.old_fingerprint,
                new_fingerprint = %summary.new_fingerprint,
                "the policy fingerprint changed: every verdict stored under the \
                 previous fingerprint is now disregarded, and the next request for \
                 each affected artifact triggers a full rescan under the new checks"
            );
        }

        Ok(summary)
    }
}

/// Loops forever, applying `config_path` through `reloader` on every
/// `SIGHUP` received, until the signal stream itself ends (which only
/// happens if the underlying OS facility is torn down — effectively
/// never in this process's lifetime). A failed reload (malformed TOML, a
/// validation failure, a missing plugin binary, a restart-only field
/// that changed) is logged and leaves the previously running
/// configuration, policy and sandbox all in place, per
/// [`Reloader::apply`]'s own guarantee.
pub async fn watch_for_reload(reloader: Arc<Reloader>, config_path: PathBuf) -> anyhow::Result<()> {
    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("installing the SIGHUP handler")?;

    loop {
        match signal.recv().await {
            Some(()) => {
                if let Err(err) = reloader.apply(&config_path) {
                    tracing::warn!(
                        path = %config_path.display(),
                        error = %format!("{err:#}"),
                        "configuration reload failed; keeping the previous \
                         configuration, policy and sandbox"
                    );
                }
            }
            None => return Ok(()),
        }
    }
}

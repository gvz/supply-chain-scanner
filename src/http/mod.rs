//! The HTTP surface a developer's package manager actually talks to.
//!
//! [`AppState`] is shared by every handler; [`router`] wires it to the
//! actual routes: the PEP 503 simple index passthrough (`simple`), the
//! download/metadata proxy (`artifact`), the `/why/<id>` explanation page
//! (`why`), the `/refusals` listing of recent blocks (`refusals`), and
//! the reason-phrase refusal responses (`refusal`) every blocked or
//! unverifiable request falls back to.
//!
//! The cargo deployment has its own surface, mounted by its own router:
//! the sparse index (`cargo_index`) and the `.crate` download with its
//! plugin gate (`cargo_download`). Its startup sequence is, for the same
//! reason, its own function: [`bootstrap_cargo`] in `cargo_bootstrap`,
//! which produces a [`CargoWired`] instead of a [`Wired`].
//!
//! The npm deployment likewise has its own surface and its own state
//! struct, [`npm_packument::NpmAppState`]: the packument route npm's
//! client actually talks to (`npm_packument`), the `/-/ping` and audit
//! stub routes, and (mounted by a later task) the tarball download.
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
pub mod cargo_bootstrap;
pub mod cargo_download;
pub mod cargo_index;
pub mod npm_bootstrap;
pub mod npm_download;
pub mod npm_packument;
pub mod refusal;
pub mod refusals;
pub mod reviews;
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

use crate::ai::provider::OpenAiCompatible;
use crate::ai::AiReviewer;
use crate::artifact_cache::ArtifactCache;
use crate::audit::{AuditLog, AuditRecord};
use crate::config::{AiReviewConfig, Config, ConfigHandle};
use crate::db::advisory::AdvisoryStore;
use crate::db::index_cache::IndexCache;
use crate::db::review::ReviewStore;
use crate::db::verdict::VerdictStore;
use crate::db::Db;
use crate::ecosystem::pypi::upstream::Upstream;
use crate::ecosystem::pypi::PyPi;
use crate::ecosystem::Ecosystem;
use crate::plugin::{BubblewrapSandbox, PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec};
use crate::policy::Policy;
use crate::scan::Scanner;

pub use cargo_bootstrap::{bootstrap_cargo, bootstrap_cargo_with_sandbox_factory, CargoWired};
pub use npm_bootstrap::{bootstrap_npm, bootstrap_npm_with_sandbox_factory, NpmWired};

/// Shared state handed to every HTTP handler.
///
/// Cheap to clone (every field is an `Arc`), as required by axum's
/// `State` extractor.
#[derive(Clone)]
pub struct AppState {
    pub scanner: Arc<Scanner>,
    pub verdicts: Arc<VerdictStore>,
    pub reviews: Arc<ReviewStore>,
    pub config: Arc<ConfigHandle>,
    pub ecosystem: Arc<dyn Ecosystem>,
    /// The fetch audit log. `artifact::artifact_handler` writes to this
    /// directly (via [`audit_or_500`]) rather than through `crate::scan`,
    /// because the client address this log exists to record is an HTTP
    /// concept — [`crate::scan::Scanner`] never sees a `SocketAddr` and
    /// must not start to, since the design keeps the client IP out of
    /// everything SQLite-backed.
    pub audit: Arc<AuditLog>,
}

/// Builds the router: the simple index, the artifact/metadata proxy,
/// `/why/<id>`, `/refusals`, `/api/reviews`, and `/healthz`. `upstream`
/// is layered on as an [`Extension`] so the artifact handler can call the PEP 658/714
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
        .route("/api/reviews", get(reviews::reviews_handler))
        .route("/refusals", get(refusals::refusals_handler))
        .layer(Extension(upstream))
        .layer(axum::middleware::from_fn(access_log))
        .with_state(state)
}

/// One line per request: method, path, status, and how long it took.
///
/// Without this there was no record that a request had happened at all, so
/// an organization could not measure its own refusal rate — which is the
/// only way anyone notices the false-positive anti-goal firing. A
/// developer who gives up and switches back to `--index-url
/// https://pypi.org/simple` produces no other signal.
///
/// Logged at `info!` so it is on by default, and paired with the
/// per-decision `warn!`s in [`crate::scan`]: this line says a 403 happened
/// on this URL, that one says which check produced it. `/healthz` is
/// logged at `debug!` instead — it is a liveness probe, typically once a
/// second, and would otherwise drown everything else.
async fn access_log(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let started = std::time::Instant::now();

    let response = next.run(request).await;

    let status = response.status().as_u16();
    let elapsed_ms = started.elapsed().as_millis();
    if path == "/healthz" {
        tracing::debug!(%method, %path, status, elapsed_ms, "request");
    } else {
        tracing::info!(%method, %path, status, elapsed_ms, "request");
    }
    response
}

/// `GET /healthz`: an unconditional liveness probe.
///
/// `pub(crate)` so [`cargo_index::cargo_router`] can register the same
/// handler. It reads no state at all, so both deployments share it
/// unchanged rather than each carrying a copy. An operator's probe must
/// answer on a cargo deployment too, or the deployment looks dead to
/// whatever is watching it.
pub(crate) async fn healthz() -> StatusCode {
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

/// Writes `records` to `audit`, or reports the one response every caller
/// must substitute for whatever it was about to send.
///
/// The spec's non-negotiable is that an un-logged fetch must never
/// happen: if this write fails, the request has to fail with a 500
/// rather than complete — serving the artifact, or returning a refusal
/// that implies the artifact *was* evaluated — on a fetch that was never
/// actually recorded. A 403 is deliberately never substituted here, even
/// when the record being written is itself a `refused` one: a write
/// failure is an operational fault in this process (a full disk, a
/// permissions change, a vanished mount), not a verdict about the
/// package, and collapsing the two into the same status code would send
/// an operator hunting a policy problem that does not exist. The failure
/// is logged at `error!` here — the one place both outcomes
/// (`Ok`/caller proceeds, `Err`/caller returns 500) share a call site —
/// so a caller cannot forward the 500 without the cause also reaching
/// the operator's logs.
///
/// The write runs on the blocking pool (`tokio::task::spawn_blocking`),
/// not on the calling async worker thread, for the same reason every
/// other synchronous I/O in this codebase does (`Scanner::file_verdicts`
/// and `file_verdicts_by_version` included): [`AuditLog::write`] takes a
/// `std::sync::Mutex` and does a synchronous `write_all`/`flush` and,
/// on a period boundary, an `open` + `metadata` + a pruning `read_dir`.
/// A degraded filesystem — the exact condition this feature exists to
/// notice, e.g. the volume remounted read-only — would otherwise block
/// one async worker thread per in-flight request while holding that
/// lock, and with workers equal to core count a listing-heavy request
/// storm could stall the whole runtime rather than just the audit path.
/// This call still awaits the write before returning, so fail-closed is
/// unchanged: a `JoinError` (the blocking task panicked) is treated as a
/// failure exactly like an `io::Error` would be, never as success.
///
/// Returns `None` on success, so the caller's own response path runs
/// completely unchanged; `artifact::artifact_handler` is the first
/// caller, and a later task's cargo and npm download handlers call this
/// same function rather than each growing their own copy of this
/// tradeoff.
pub(crate) async fn audit_or_500(
    audit: &Arc<AuditLog>,
    records: &[AuditRecord],
) -> Option<Response> {
    let audit = Arc::clone(audit);
    let records = records.to_vec();
    let outcome = tokio::task::spawn_blocking(move || audit.write(&records)).await;

    let err = match outcome {
        Ok(Ok(())) => return None,
        Ok(Err(err)) => err,
        Err(join_err) => {
            anyhow::anyhow!(join_err).context("the audit write task panicked on the blocking pool")
        }
    };

    tracing::error!(
        error = %err,
        "failed to write a fetch audit record; refusing to serve rather than let this \
         fetch go unlogged"
    );
    Some(
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::empty())
            .unwrap_or_else(|_| {
                let mut response = Response::new(axum::body::Body::empty());
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                response
            }),
    )
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
/// (migrations run inside [`Db::open`]), open the fetch audit log (fails
/// if the configured path cannot be created or appended to), build the
/// [`Policy`] (fails if a configured plugin binary is missing or
/// unreadable), detect the sandbox when plugins or the AI reviewer are
/// configured (fails if `bwrap` is absent from `PATH`), build the
/// [`Scanner`], and run an initial advisory sync if the mirror is empty.
/// A failure anywhere in that chain is returned as `Err` — this function
/// never produces a `Wired` backed by fewer checks than the configuration
/// asked for.
///
/// The audit log is opened this early, well before anything that touches
/// a request, specifically so an unwritable path aborts startup outright
/// rather than surfacing later as a 500 on a developer's first fetch:
/// the fail-closed guarantee [`AuditLog`] and [`audit_or_500`] exist to
/// provide only holds if this process never finishes booting on a path
/// it cannot actually write to.
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

    let audit = Arc::new(AuditLog::open(&config.audit).with_context(|| {
        format!(
            "opening the fetch audit log at {}",
            config.audit.path.display()
        )
    })?);

    let config = Arc::new(config);
    let policy = Policy::build(Arc::clone(&config))
        .context("building policy (a configured plugin binary may be missing or unreadable)")?;

    let sandbox_factory = default_sandbox_factory();
    let sandbox = sandbox_factory(&config)?;
    let plugin_runner = PluginRunner::new(Arc::clone(&sandbox));

    // The reviewer, when `[ai_review]` is present. It reuses the sandbox
    // built above (the same `bwrap` configuration the plugins get, which
    // `default_sandbox_factory` already failed closed on), the review
    // store on this same database, and this process's own executable as
    // the collector binary it runs under the sandbox.
    let ai_reviewer = match config.ai_review() {
        Some(cfg) => Some(build_ai_reviewer(cfg, Arc::clone(&sandbox), db.clone())?),
        None => None,
    };

    let index_cache = IndexCache::new(db.clone());
    let simple_base = config
        .upstream_url
        .join("simple/")
        .context("building the upstream simple-index base URL")?;
    let scanner_upstream =
        Upstream::with_limits(simple_base.clone(), index_cache.clone(), &config.download)
            .context("constructing the scanner's upstream client")?;
    let ecosystem_upstream = Arc::new(
        Upstream::with_limits(simple_base, index_cache, &config.download)
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
        ai_reviewer,
    );

    let pypi: Arc<dyn Ecosystem> = Arc::new(PyPi::new(Arc::clone(&ecosystem_upstream)));

    let state = AppState {
        scanner: Arc::new(scanner),
        verdicts: Arc::new(VerdictStore::new(db.clone())),
        reviews: Arc::new(ReviewStore::new(db.clone())),
        config: Arc::clone(&config_handle),
        ecosystem: pypi,
        audit,
    };

    let reloader = Arc::new(Reloader::with_sandbox_factory(
        config_handle,
        Arc::clone(&state.scanner),
        &config,
        sandbox_factory,
        db.clone(),
    ));

    let router = router(state.clone(), ecosystem_upstream);

    Ok(Wired {
        router,
        state,
        db,
        reloader,
    })
}

/// Builds the [`AiReviewer`] a configuration calls for, or `None` when
/// `[ai_review]` is absent. Fails — propagating `Err`, so startup and
/// reload both keep the fail-closed contract — when the provider cannot
/// be built (an unresolvable `api_key_env`, an unusable `base_url`) or
/// this process cannot learn its own executable path. Both reload and
/// startup share this function, so a reload cannot wire a reviewer that
/// a cold boot would have refused.
///
/// Takes the sandbox the caller already built, not the config's: the
/// reviewer runs the collector under the same sandbox configuration the
/// plugins get, and the caller (`bootstrap`, a reload,
/// [`cargo_bootstrap::bootstrap_cargo`]) has already failed closed on it
/// when the configuration requires a real one.
///
/// `pub(crate)` rather than private because the cargo bootstrap reuses it
/// verbatim: the reviewer is ecosystem-agnostic, and a cargo deployment
/// must not be able to acquire a reviewer built by a second copy of this
/// function that a later change could leave behind.
pub(crate) fn build_ai_reviewer(
    cfg: &AiReviewConfig,
    sandbox: Arc<dyn SandboxRunner>,
    db: Db,
) -> anyhow::Result<Arc<AiReviewer>> {
    let provider = OpenAiCompatible::new(cfg)
        .context("building the model provider for the [ai_review] table")?;
    let collector_binary = std::env::current_exe().context(
        "learning this process's own executable path, which the ai_review collector runs",
    )?;
    Ok(Arc::new(AiReviewer::new(
        cfg.clone(),
        sandbox,
        Arc::new(provider),
        Arc::new(ReviewStore::new(db)),
        collector_binary,
    )))
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

/// The production sandbox: a real [`BubblewrapSandbox`] when plugins or
/// the AI reviewer are configured (failing if `bwrap` is absent, so the
/// proxy never runs fewer checks than the org asked for), and the
/// panicking [`NeverCalledSandbox`] stub when neither is configured and
/// neither [`PluginRunner::run_all`]'s loop nor the reviewer can
/// therefore ever reach it.
pub fn default_sandbox_factory() -> SandboxFactory {
    Arc::new(
        |config: &Config| -> anyhow::Result<Arc<dyn SandboxRunner>> {
            let sandboxed_checks = !config.plugins.is_empty() || config.ai_review().is_some();
            if !sandboxed_checks {
                Ok(Arc::new(NeverCalledSandbox))
            } else {
                Ok(Arc::new(BubblewrapSandbox::detect().context(
                    "detecting the bubblewrap sandbox (required because plugins or ai_review are configured)",
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
/// ticker, `cache_ttl` into the eviction ticker, `download` into the
/// upstream clients' timeout configuration, `max_concurrent_scans` into
/// the initial permit count of the `Scanner`'s full-scan semaphore
/// (shrinking a `tokio::sync::Semaphore` that already has permits checked
/// out is not well-defined, so this can't be live-reloaded either), and
/// `audit` into the open file handle the rolling appender holds for the
/// whole life of the process (opened once at startup; there is no
/// "close the old file, open the new one" step a reload could trigger).
///
/// A reload that changes any of them is **rejected in full**. That is a
/// deliberate choice over the alternative of applying the rest: applying
/// part of a file while logging "configuration reloaded" is how an
/// operator comes to believe a tightened CVE line is live when it is not.
/// Rejecting, and naming the field, sends them to a restart instead.
pub const RESTART_ONLY_FIELDS: &[&str] = &[
    "bind",
    "db_path",
    "cache_dir",
    "upstream_url",
    "advisory_source_url",
    "advisory_sync_interval",
    "cache_ttl",
    "download",
    "max_concurrent_scans",
    "audit",
];

/// Configuration fields a reload genuinely applies, for the log line that
/// says so.
pub const RELOADABLE_FIELDS: &[&str] = &[
    "cve",
    "plugins",
    "allowlist",
    "public_url",
    "scan_budget",
    "ai_review",
];

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
    if boot.download != candidate.download {
        changed.push("download");
    }
    if boot.max_concurrent_scans != candidate.max_concurrent_scans {
        changed.push("max_concurrent_scans");
    }
    if boot.audit != candidate.audit {
        changed.push("audit");
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
/// `apply` therefore parses, validates, builds the new `Policy`, the new
/// sandbox and the new reviewer *first*, and only swaps anything in once
/// all of that has succeeded. A failure anywhere — malformed TOML, a
/// `scan_budget` over the ceiling, a plugin binary that cannot be read,
/// no usable `bwrap` for a newly added plugin, an `[ai_review]` table
/// whose reviewer cannot be built, a restart-only field that changed —
/// returns `Err` with the previous configuration, policy and checks all
/// still in force. That is [`Policy::build`]'s fail-closed contract extended
/// across reload.
pub struct Reloader {
    config: Arc<ConfigHandle>,
    scanner: Arc<Scanner>,
    /// The values this process booted under, for [`restart_only_changes`].
    boot: Config,
    sandbox_factory: SandboxFactory,
    /// The reload's own connection to the database, for rebuilding the
    /// reviewer's review store against the same SQLite file.
    db: Db,
}

impl Reloader {
    /// The production constructor: [`default_sandbox_factory`].
    pub fn new(config: Arc<ConfigHandle>, scanner: Arc<Scanner>, boot: &Config, db: Db) -> Self {
        Self::with_sandbox_factory(config, scanner, boot, default_sandbox_factory(), db)
    }

    pub fn with_sandbox_factory(
        config: Arc<ConfigHandle>,
        scanner: Arc<Scanner>,
        boot: &Config,
        sandbox_factory: SandboxFactory,
        db: Db,
    ) -> Self {
        Self {
            config,
            scanner,
            boot: boot.clone(),
            sandbox_factory,
            db,
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
        // The reviewer is rebuilt here, from the same candidate config that
        // produced the policy above, so the two can never disagree: a
        // reload that turns the reviewer on lands a new fingerprint (which
        // it must, see [`crate::policy`]) and a reviewer sealed to it in one
        // atomic swap. A build failure keeps the previous reviewer exactly
        // as a plugin failure keeps the previous plugins.
        let ai_reviewer = match candidate.ai_review() {
            Some(cfg) => Some(
                build_ai_reviewer(cfg, Arc::clone(&sandbox), self.db.clone()).context(
                    "building the ai reviewer for the reloaded configuration; keeping the \
                     previous policy",
                )?,
            ),
            None => None,
        };

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
            ai_reviewer,
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

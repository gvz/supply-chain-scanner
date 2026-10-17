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

    let sandbox: Arc<dyn SandboxRunner> = if config.plugins.is_empty() {
        Arc::new(NeverCalledSandbox)
    } else {
        Arc::new(BubblewrapSandbox::detect().context(
            "detecting the bubblewrap sandbox (required because plugins are configured)",
        )?)
    };
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
        config: config_handle,
        ecosystem: pypi,
    };

    let router = router(state.clone(), ecosystem_upstream);

    Ok(Wired { router, state, db })
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

/// Loops forever, reloading `config_handle` from `config_path` on every
/// `SIGHUP` received, until the signal stream itself ends (which only
/// happens if the underlying OS facility is torn down — effectively
/// never in this process's lifetime). A failed reload (malformed TOML, a
/// validation failure) is logged and leaves the previously running
/// configuration in place, per [`ConfigHandle::reload`]'s own guarantee.
pub async fn watch_for_reload(
    config_handle: Arc<ConfigHandle>,
    config_path: PathBuf,
) -> anyhow::Result<()> {
    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("installing the SIGHUP handler")?;

    loop {
        match signal.recv().await {
            Some(()) => match config_handle.reload(&config_path) {
                Ok(()) => tracing::info!(
                    path = %config_path.display(),
                    "configuration reloaded on SIGHUP"
                ),
                Err(err) => tracing::warn!(
                    path = %config_path.display(),
                    error = %err,
                    "configuration reload failed; keeping the previous configuration"
                ),
            },
            None => return Ok(()),
        }
    }
}

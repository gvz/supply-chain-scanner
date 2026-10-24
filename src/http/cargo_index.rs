//! The cargo sparse-index surface: `config.json` and the per-crate index
//! file.
//!
//! This is the cargo deployment's counterpart to [`super::simple`] and
//! [`super::artifact`]. It serves the same two touchpoints the crates.io
//! sparse index defines. The second one is the gate, and it runs
//! [`CargoScanner::decide_index`] before it answers:
//!
//! - `GET /config.json` — the registry's own configuration. Its `dl`
//!   template points back at *this* proxy, so cargo returns here for the
//!   `.crate` file and the plugin gate stays in the loop.
//! - `GET /<prefix>/<name>` — one crate's index file, rendered as JSON
//!   lines. Only versions the cascade forwards appear.
//!
//! # Why a sibling state struct
//!
//! [`super::AppState`] carries `scanner: Arc<Scanner>` and `ecosystem:
//! Arc<dyn Ecosystem>`. Both are PyPI-shaped. A cargo deployment never
//! boots either of them: the design spec makes cargo a second deployment,
//! so no process needs both. Widening `AppState` would give every cargo
//! deployment two fields it can never use, and every PyPI deployment one
//! it can never use. [`CargoAppState`] is therefore a separate struct, not
//! a superset.
//!
//! # Why one catch-all route
//!
//! The sparse index path is variable-length by design: `1/a`, `2/ab`,
//! `3/a/abc`, `ca/rg/cargo`. A single axum `:param` cannot express that,
//! so this module uses a catch-all, `/{*path}`, and reads the whole path
//! from it. The alternative — registering the four shapes the scheme
//! produces — cannot satisfy the malformed-path rule below. A traversal
//! like `/../../etc/passwd` has four segments, matches no shape, and would
//! return axum's 404 instead of the 400 a malformed index path must get.
//! A catch-all sees every path this router receives, so every malformed
//! one reaches the validator.
//!
//! `/config.json` is a static route and takes precedence over the
//! catch-all, as `matchit` resolves a static segment before a wildcard.
//! Task 11 mounts this router on its own path prefix, so the catch-all
//! only ranges over the cargo index paths and not over another router's
//! routes.
//!
//! # Why `text/plain`
//!
//! crates.io serves a crate's index file as plain text, and cargo parses
//! the body as JSON lines whatever the `Content-Type` says. This handler
//! therefore sends `text/plain; charset=utf-8`, the safe choice. Do not
//! change it to `application/json`: a client that trusts the header to
//! decide how to parse a JSON-lines body has nothing good to do with that
//! answer.
//!
//! # Conditional requests
//!
//! `ETag` and `Last-Modified` are not implemented. The design spec leaves
//! conditional-request support to the builder, and this task does not
//! require it. Every index response is a full body.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;

use crate::artifact_cache::ArtifactCache;
use crate::config::ConfigHandle;
use crate::db::review::ReviewStore;
use crate::db::verdict::VerdictStore;
use crate::ecosystem::cargo::index::{index_path_for, validate_name, CargoIndexEntry};
use crate::ecosystem::cargo::index_name;
use crate::ecosystem::cargo::upstream::CargoUpstream;
use crate::plugin::PluginRunner;
use crate::scan::cargo::{CargoIndexDecision, CargoScanner};

use super::bad_request_response;
use super::cargo_download::cargo_download_handler;
use super::refusal::in_progress_response;

/// Shared state for every handler in this module and for
/// [`super::cargo_download`].
///
/// Cheap to clone: every field is an `Arc`, as axum's `State` extractor
/// requires. See the module docs for why this is not [`super::AppState`].
///
/// Each field is here because a handler in this router reads it:
///
/// - `cargo_scanner` — the cascade behind the index gate
///   ([`cargo_index_handler`]). Its `fingerprint()` is also the policy
///   fingerprint the download gate stores and looks up verdicts under, so
///   the verdict the index path writes is the verdict the download path
///   reads.
/// - `config` — `public_url` for the `dl` template and for every
///   `/why/<id>` link, and `plugins` for the download gate's plugin list.
///   Read through [`ConfigHandle::current`] so a reload takes effect.
/// - `upstream` — the cargo sparse index and `.crate` client. The index
///   handler reaches upstream through `cargo_scanner`; the download
///   handler needs the index entry's `cksum` and the `.crate` bytes
///   directly, and `CargoScanner` exposes neither.
/// - `verdicts` — the durable verdict store the download gate reads and
///   writes.
/// - `plugins` — the runner that executes the organization's plugin
///   binaries over the unpacked `.crate`.
/// - `artifact_cache` — the content-addressed cache the download gate
///   serves already-verified bytes from.
/// - `reviews` — the AI-review audit table, read by `/why/<id>` (the
///   report behind a refusal) and by `/api/reviews`. The same store the
///   PyPI path serves; a cargo verdict's review row lives there too,
///   because [`crate::ai::AiReviewer`] writes it without knowing which
///   ecosystem asked.
/// - `plugin_run_coordinator` — deduplicates concurrent first-touch
///   `.crate` downloads for the same artifact hash, the download gate's
///   own instance of the same single-flight pattern [`CargoScanner`]
///   already uses for the AI-review cascade (and the PyPI path uses for
///   its own full scan and cache-miss re-download). Without it, two
///   concurrent `cargo build`/`cargo check` calls that both hit a
///   never-plugin-checked artifact each independently download, unpack,
///   and run every plugin — exactly the N-times cost
///   [`crate::scan::coordinator`]'s own module docs describe, just on the
///   download side of the cargo gate rather than the index side.
#[derive(Clone)]
pub struct CargoAppState {
    pub cargo_scanner: Arc<CargoScanner>,
    pub config: Arc<ConfigHandle>,
    /// The cargo upstream client: index entries and `.crate` downloads.
    pub upstream: Arc<CargoUpstream>,
    /// The durable per-artifact verdict store.
    pub verdicts: Arc<VerdictStore>,
    /// The runner for the organization's plugin binaries.
    pub plugins: Arc<PluginRunner>,
    /// The on-disk cache of verified artifact bytes.
    pub artifact_cache: Arc<ArtifactCache>,
    /// The AI-review audit table behind `/why/<id>` and `/api/reviews`.
    pub reviews: Arc<ReviewStore>,
    /// Single-flight dedup for the `.crate` download's plugin run, keyed
    /// by artifact sha256. See the field's own doc line above.
    pub plugin_run_coordinator: Arc<crate::scan::coordinator::ScanCoordinator>,
}

/// Builds the cargo deployment's router: `/config.json`, the `.crate`
/// download route, `/refusals`, `/why/<id>`, `/api/reviews`, `/healthz`,
/// and the catch-all sparse-index route. Task 11 mounts this.
///
/// The download route is a static-prefix route registered on the same
/// router as the `/{*path}` catch-all. `matchit` resolves a static segment
/// before a wildcard, so `/crates/{crate}/{version}/download` reaches
/// [`cargo_download_handler`] and every other path still reaches
/// [`cargo_index_handler`]. `tests/http_cargo_download.rs` pins this: it
/// downloads an artifact, fetches an index path, and posts a traversal
/// path through the same router and checks that each handler answered.
/// `/refusals`, `/why/<id>`, `/api/reviews` and `/healthz` resolve the
/// same way, as static segments.
///
/// The three routes this deployment shares with the PyPI path are served
/// by thin extractors in this module. [`super::refusals::refusals_handler`],
/// [`super::why::why_handler`] and [`super::reviews::reviews_handler`] take
/// `State<AppState>`, and this router carries [`CargoAppState`]. The
/// lookup, the rendering and the gate live in one place in each module,
/// and only the extractor differs. See each module's docs.
///
/// `/why/<id>` matters more here than on the PyPI path, not less. A
/// plugin refusal arrives as a real status line with a reason phrase, and
/// that phrase carries a `/why/<id>` link. Without this route the link a
/// cargo developer is given would be a 404.
pub fn cargo_router(state: CargoAppState) -> Router {
    Router::new()
        .route("/config.json", get(cargo_config_handler))
        .route("/refusals", get(cargo_refusals_handler))
        .route("/why/{id}", get(cargo_why_handler))
        .route("/api/reviews", get(cargo_reviews_handler))
        .route("/healthz", get(super::healthz))
        .route(
            "/crates/{crate}/{version}/download",
            get(cargo_download_handler),
        )
        .route("/{*path}", get(cargo_index_handler))
        .with_state(state)
}

/// The ecosystem id every cargo artifact key carries, and therefore the
/// id [`super::refusals`] queries for on this deployment. It is
/// [`crate::scan::cargo`]'s own constant value; repeated here because
/// that constant is private and this is the one place the HTTP layer has
/// to name the ecosystem itself.
const CARGO_ECOSYSTEM: &str = "cargo";

/// `GET /refusals` on a cargo deployment: the same listing
/// [`super::refusals::refusals_handler`] serves on the PyPI path, read
/// out of [`CargoAppState`].
pub async fn cargo_refusals_handler(State(state): State<CargoAppState>) -> Response {
    super::refusals::refusals_for(state.verdicts, CARGO_ECOSYSTEM.to_string()).await
}

/// `GET /why/<id>` on a cargo deployment: the explanation page every
/// refusal's reason phrase links to, read out of [`CargoAppState`].
pub async fn cargo_why_handler(
    State(state): State<CargoAppState>,
    Path(why_id): Path<String>,
) -> Response {
    super::why::why_for(state.verdicts, state.reviews, why_id).await
}

/// `GET /api/reviews` on a cargo deployment: the same audit listing
/// [`super::reviews::reviews_handler`] serves on the PyPI path, read out
/// of [`CargoAppState`].
pub async fn cargo_reviews_handler(
    State(state): State<CargoAppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    super::reviews::reviews_for(state.reviews, state.config, query).await
}

/// `GET /config.json`: the registry configuration cargo reads first.
///
/// The body is one field, `dl`, because `dl` is the only field cargo
/// requires to resolve and download a crate. Each field is deliberate:
///
/// - `dl` — the download URL template. It points at this proxy's own
///   `/crates/{crate}/{version}/download` route rooted at the configured
///   `public_url`, never at crates.io. Cargo must come back here for the
///   `.crate` file, or the plugin gate never runs.
/// - `api` — omitted. crates.io's own `config.json` carries one, but this
///   deployment does not serve that API. Advertising it would turn a clean
///   `cargo publish` failure into a confusing 404.
pub async fn cargo_config_handler(State(state): State<CargoAppState>) -> Response {
    let config = state.config.current();
    let base = config.public_url.as_str().trim_end_matches('/');
    // `{crate}` and `{version}` are cargo's own template markers, not a
    // Rust format argument, so they are written as escaped braces.
    let dl = format!("{base}/crates/{{crate}}/{{version}}/download");

    let body = serde_json::json!({ "dl": dl }).to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| {
            let mut response = Response::new(axum::body::Body::from("{\"dl\":\"\"}".to_string()));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        })
}

/// `GET /<prefix>/<name>`: one crate's index file.
///
/// `path` is everything the catch-all captured, with its leading `/`
/// removed and percent-decoding already applied by axum. The last segment
/// is the crate name. This handler validates that name, then checks that
/// the whole path is exactly the path that name implies. The second check
/// is what makes a traversal like `/../../etc/passwd` a 400 rather than a
/// lookup of `passwd`: the last segment alone is a valid crate name, and
/// only the full-path comparison rejects it.
pub async fn cargo_index_handler(
    State(state): State<CargoAppState>,
    Path(path): Path<String>,
) -> Response {
    let segments: Vec<&str> = path.split('/').collect();
    let Some(name) = segments.last() else {
        return bad_request_response("invalid crate name: the path has no segments");
    };

    let name = match validate_name(name) {
        Ok(name) => name,
        Err(err) => return bad_request_response(&format!("invalid crate name: {err}")),
    };

    // The canonical path keeps the crate's published spelling, lowercased,
    // with its underscores intact. crates.io serves `se/rd/serde_json`, and
    // cargo asks for exactly that, so a hyphenated canonical path here
    // would reject every legitimate request for a crate whose name carries
    // an underscore.
    let canonical = index_path_for(&index_name(&name));
    if path != canonical {
        return bad_request_response(&format!(
            "invalid crate index path: {name:?} is served at {canonical:?}"
        ));
    }

    match state.cargo_scanner.decide_index(&name).await {
        CargoIndexDecision::Entries(entries) => index_response(&entries),
        // The same retryable status the PyPI path uses for a scan still
        // running. See `super::refusal`'s module docs for why it is 429
        // and not 503.
        CargoIndexDecision::InProgress => in_progress_response(),
    }
}

/// Renders forwarded versions as an index file: one JSON object per line.
///
/// An empty entry list renders as an empty body with status 200. That is
/// deliberate. It reads the way a crate with no published version reads,
/// which is how `cargo add` must fail for a crate where every version is
/// blocked.
///
/// `deps` is always an empty array. This proxy does not model dependency
/// resolution, but cargo requires the field to exist. Cargo resolves this
/// crate's own dependencies by querying this same index for each of them,
/// so each of those queries passes through the cascade too.
fn index_response(entries: &[CargoIndexEntry]) -> Response {
    let mut body = String::new();
    for entry in entries {
        let line = serde_json::json!({
            "name": entry.name,
            "vers": entry.vers,
            "cksum": entry.cksum,
            "yanked": entry.yanked,
            "deps": [],
        });
        body.push_str(&line.to_string());
        body.push('\n');
    }

    Response::builder()
        .status(StatusCode::OK)
        // See the module docs: crates.io serves this as plain text.
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| {
            let mut response = Response::new(axum::body::Body::from(String::new()));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        })
}

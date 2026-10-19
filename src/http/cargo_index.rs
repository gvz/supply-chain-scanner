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

use crate::config::ConfigHandle;
use crate::ecosystem::cargo::index::{index_path_for, validate_name, CargoIndexEntry};
use crate::scan::cargo::{CargoIndexDecision, CargoScanner};

use super::bad_request_response;
use super::refusal::in_progress_response;

/// Shared state for every handler in this module.
///
/// Cheap to clone: both fields are `Arc`s, as axum's `State` extractor
/// requires. See the module docs for why this is not [`super::AppState`].
#[derive(Clone)]
pub struct CargoAppState {
    pub cargo_scanner: Arc<CargoScanner>,
    pub config: Arc<ConfigHandle>,
}

/// Builds the cargo deployment's router: `/config.json` and the
/// catch-all sparse-index route. Task 11 mounts this.
///
/// `/refusals` is deliberately absent. [`super::refusals::refusals_handler`]
/// takes `State<AppState>`, and this router carries [`CargoAppState`].
/// Task 11 must resolve that mismatch rather than this module widening
/// either state struct.
pub fn cargo_router(state: CargoAppState) -> Router {
    Router::new()
        .route("/config.json", get(cargo_config_handler))
        .route("/{*path}", get(cargo_index_handler))
        .with_state(state)
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

    let canonical = index_path_for(&name);
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

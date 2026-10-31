//! The npm registry surface: the packument route npm's own client talks
//! to, plus the handful of auxiliary routes a working deployment needs.
//!
//! This is the npm deployment's counterpart to [`super::cargo_index`]:
//!
//! - `GET /<name>` (or `/@<scope>%2f<name>` for a scoped package) — the
//!   package's packument, filtered to only the versions
//!   [`NpmScanner::decide_packument`] forwards. npm itself resolves and
//!   installs from whatever document this proxy returns, so a version
//!   removed here can never be installed, however it got filtered.
//! - `GET /-/ping` — npm's own liveness probe, answered unconditionally.
//! - `POST /-/npm/v1/security/advisories/bulk` and
//!   `POST /-/npm/v1/security/audits/quick` — npm's audit summary
//!   requests. See "The audit endpoints are a privacy decision" below.
//!
//! The tarball route (`/{*name}/-/{file}`) belongs to Task 11's
//! `npm_download`, which registers it on this same router. This module
//! does not define or register it.
//!
//! # Why this proxy always serves the full packument
//!
//! npm's client requests the abbreviated packument shape (`Accept:
//! application/vnd.npm.install-v1+json`), which omits the `time` map.
//! [`NpmScanner`]'s release-age gate needs that map, so
//! [`crate::ecosystem::npm::upstream::NpmUpstream::packument`] always
//! fetches and this handler always serves the full document regardless
//! of what npm asked for. A real `npm` client was verified against this
//! proxy serving the full shape — see the npm-ecosystem task's report for
//! the exact commands and npm version.
//!
//! # The audit endpoints are a privacy decision, not an oversight
//!
//! Proxying npm's bulk-advisory or quick-audit request to the real
//! registry would ship the org's entire dependency tree to npmjs.org on
//! every install — a data-egress change nobody asked for. Both routes
//! answer 404 unconditionally and never make an upstream request. A 404
//! makes npm skip its audit summary quietly; this proxy's own CVE gate
//! already blocks rather than merely reports, which is strictly stronger
//! coverage for the one thing an audit summary is for.
//!
//! # Why one catch-all route for the packument
//!
//! Exactly [`super::cargo_index`]'s reasoning: a package name can be a
//! single segment (`lodash`) or carry a literal `/` once decoded
//! (`@babel/core`, requested by npm as `@babel%2fcore` with the scope
//! separator percent-encoded so it stays one path segment on the wire).
//! axum decodes the captured value, not the routing match itself, so a
//! scoped name's encoded `%2f` still resolves through `/{*path}` and
//! reaches this handler as `@babel/core`, ready for
//! [`crate::ecosystem::npm::validate_name`].
//!
//! `/-/ping`, the two audit routes, `/refusals`, `/why/<id>`,
//! `/api/reviews`, `/healthz`, and (once Task 11 registers it) the
//! tarball route are all static-prefix routes on the same router as the
//! `/{*path}` catch-all. `matchit` resolves a static segment before a
//! wildcard, so every one of them is reachable even though the catch-all
//! would otherwise swallow anything.
//!
//! # Why the three shared routes are thin extractors
//!
//! Exactly [`super::cargo_index`]'s pattern: [`super::refusals::refusals_for`],
//! [`super::why::why_for`] and [`super::reviews::reviews_for`] take the
//! stores directly, not `State<AppState>`, so this module calls them with
//! fields read out of [`NpmAppState`] instead of duplicating the lookup,
//! the gate or the rendering.

use std::sync::Arc;

use axum::extract::{Path, RawQuery, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;

use crate::artifact_cache::ArtifactCache;
use crate::config::ConfigHandle;
use crate::db::review::ReviewStore;
use crate::db::verdict::VerdictStore;
use crate::ecosystem::npm::upstream::NpmUpstream;
use crate::ecosystem::npm::validate_name;
use crate::plugin::PluginRunner;
use crate::scan::coordinator::ScanCoordinator;
use crate::scan::npm::{NpmIndexDecision, NpmScanner};

use super::refusal::in_progress_response;
use super::{bad_request_response, not_found_response};

/// The ecosystem id every npm artifact key carries, and therefore the id
/// [`super::refusals`] queries for on this deployment.
pub const NPM_ECOSYSTEM: &str = "npm";

/// Shared state for every handler in this module and for Task 11's
/// `npm_download`.
///
/// Cheap to clone: every field is an `Arc`, as axum's `State` extractor
/// requires. Mirrors [`super::cargo_index::CargoAppState`]'s own
/// reasoning for why this is a sibling struct rather than a widened
/// [`super::AppState`]: a cargo or npm deployment never boots the PyPI
/// fields, and a PyPI deployment never boots these.
///
/// Each field is here because a handler in this router (or Task 11's)
/// reads it:
///
/// - `npm_scanner` — the cascade behind the packument gate
///   ([`npm_packument_handler`]). Its `fingerprint()` is the policy
///   fingerprint the download gate's stored verdicts are looked up
///   under, so the verdict the packument path writes is the verdict the
///   download path reads.
/// - `config` — `public_url` (read inside the cascade itself for the
///   rewritten tarball URLs) and `ai_review` for `/api/reviews`'s gate.
/// - `upstream` — the npm registry client. Task 11's download handler
///   needs the version's `dist` object and tarball bytes directly;
///   `NpmScanner` exposes neither beyond what the packument cascade
///   already consumed.
/// - `verdicts` — the durable verdict store the download gate reads and
///   writes, and that `/refusals` and `/why/<id>` read from.
/// - `plugins` — the runner Task 11's download gate executes the org's
///   plugin binaries through.
/// - `artifact_cache` — the content-addressed cache Task 11's download
///   gate serves already-verified bytes from.
/// - `reviews` — the AI-review audit table, read by `/why/<id>` and
///   `/api/reviews`. The same store the PyPI and cargo paths serve from.
/// - `plugin_run_coordinator` — deduplicates concurrent first-touch
///   tarball downloads for the same artifact digest, Task 11's own
///   instance of the single-flight pattern [`NpmScanner`] already uses
///   for its own AI-review cascade.
#[derive(Clone)]
pub struct NpmAppState {
    pub npm_scanner: Arc<NpmScanner>,
    pub config: Arc<ConfigHandle>,
    /// The npm upstream client: packument and tarball fetches.
    pub upstream: Arc<NpmUpstream>,
    /// The durable per-artifact verdict store.
    pub verdicts: Arc<VerdictStore>,
    /// The runner for the organization's plugin binaries.
    pub plugins: Arc<PluginRunner>,
    /// The on-disk cache of verified artifact bytes.
    pub artifact_cache: Arc<ArtifactCache>,
    /// The AI-review audit table behind `/why/<id>` and `/api/reviews`.
    pub reviews: Arc<ReviewStore>,
    /// Single-flight dedup for a tarball download's plugin run, keyed by
    /// artifact sha256. See the field's own doc line above.
    pub plugin_run_coordinator: Arc<ScanCoordinator>,
}

/// Builds the npm deployment's router: `/-/ping`, the two audit stubs,
/// `/refusals`, `/why/<id>`, `/api/reviews`, `/healthz`, and the catch-all
/// packument route. Task 11 mounts the tarball route on this same
/// `Router` by modifying this function; this task's router does not
/// carry it.
///
/// Route precedence is exactly [`super::cargo_index::cargo_router`]'s:
/// every static-prefix route here resolves before the `/{*path}`
/// catch-all, because `matchit` always tries a static segment first.
pub fn npm_router(state: NpmAppState) -> Router {
    Router::new()
        .route("/-/ping", get(npm_ping_handler))
        .route(
            "/-/npm/v1/security/advisories/bulk",
            post(npm_audit_stub_handler),
        )
        .route(
            "/-/npm/v1/security/audits/quick",
            post(npm_audit_stub_handler),
        )
        .route("/refusals", get(npm_refusals_handler))
        .route("/why/{id}", get(npm_why_handler))
        .route("/api/reviews", get(npm_reviews_handler))
        .route("/healthz", get(super::healthz))
        .route("/{*path}", get(npm_packument_handler))
        .with_state(state)
}

/// `GET /refusals` on an npm deployment: the same listing
/// [`super::refusals::refusals_handler`] serves on the PyPI path, read
/// out of [`NpmAppState`].
pub async fn npm_refusals_handler(State(state): State<NpmAppState>) -> Response {
    super::refusals::refusals_for(state.verdicts, NPM_ECOSYSTEM.to_string()).await
}

/// `GET /why/<id>` on an npm deployment: the explanation page every
/// refusal's reason phrase links to, read out of [`NpmAppState`].
pub async fn npm_why_handler(
    State(state): State<NpmAppState>,
    Path(why_id): Path<String>,
) -> Response {
    super::why::why_for(state.verdicts, state.reviews, why_id).await
}

/// `GET /api/reviews` on an npm deployment: the same audit listing
/// [`super::reviews::reviews_handler`] serves on the PyPI path, read out
/// of [`NpmAppState`].
pub async fn npm_reviews_handler(
    State(state): State<NpmAppState>,
    RawQuery(query): RawQuery,
) -> Response {
    super::reviews::reviews_for(state.reviews, state.config, query).await
}

/// `GET /-/ping`: npm's own liveness probe. Answered unconditionally,
/// with no state read at all — a probe that depended on this process's
/// own gates would fail the moment any cascade is slow, which is exactly
/// when an operator most needs to know the process itself is still
/// alive.
pub async fn npm_ping_handler() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from("{}"))
        .unwrap_or_else(|_| {
            let mut response = Response::new(axum::body::Body::from("{}".to_string()));
            *response.status_mut() = StatusCode::OK;
            response
        })
}

/// `POST /-/npm/v1/security/advisories/bulk` and
/// `POST /-/npm/v1/security/audits/quick`: npm's audit summary requests,
/// both answered 404 and never forwarded upstream. See the module docs
/// for why this is a privacy decision, not an oversight: proxying either
/// request would ship the org's entire dependency tree to npmjs.org on
/// every install.
pub async fn npm_audit_stub_handler() -> Response {
    not_found_response()
}

/// `GET /<name>` (or the decoded form of a scoped name): one package's
/// packument.
///
/// `path` is everything the catch-all captured, already percent-decoded
/// by axum — see the module docs for why a scoped name's `%2f` survives
/// routing as one segment and arrives here as a literal `/`. It is
/// validated before anything else: an invalid name is a 400 and the
/// scanner is never consulted, so it never reaches upstream.
pub async fn npm_packument_handler(
    State(state): State<NpmAppState>,
    Path(path): Path<String>,
) -> Response {
    let name = match validate_name(&path) {
        Ok(name) => name,
        Err(err) => return bad_request_response(&format!("invalid npm package name: {err}")),
    };

    match state.npm_scanner.decide_packument(&name).await {
        NpmIndexDecision::Packument(doc) => packument_response(&doc),
        // Upstream has spoken: no such package. Distinct from the
        // in-progress case below, and never retried the same way.
        NpmIndexDecision::NotFound => not_found_response(),
        // The same retryable status the PyPI and cargo paths use for a
        // scan still running. See `super::refusal`'s module docs for why
        // it is 429 and not 503.
        NpmIndexDecision::InProgress => in_progress_response(),
    }
}

/// Renders the filtered packument as the JSON document npm's client
/// parses, regardless of what `Accept` header it sent. See the module
/// docs for why this proxy always serves the full shape rather than
/// npm's requested abbreviated one.
fn packument_response(doc: &serde_json::Value) -> Response {
    let body = doc.to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| {
            let mut response = Response::new(axum::body::Body::from(
                "{\"error\":\"internal\"}".to_string(),
            ));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        })
}

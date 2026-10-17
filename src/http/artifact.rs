//! `GET /files/<package>/<version>/<filename>`: the download proxy that
//! gates every artifact byte a developer's package manager receives, and
//! its PEP 658/714 `.metadata` sidecar counterpart, which passes through
//! unscanned.
//!
//! The authoritative SHA-256 used to build the [`ArtifactKey`] handed to
//! [`crate::scan::Scanner::decide`] always comes from the upstream
//! index's declared hash for the matched filename — never from the URL
//! path, a client header, or anything else a request could supply —
//! because the artifact cache is content-addressed: a key built from any
//! other source could let a cache hit serve bytes this request never
//! verified. An index entry with no declared hash is `Unverifiable`,
//! exactly as [`crate::scan::Scanner::decide`] already treats it.

use std::path::Path as FsPath;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Extension, Path, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use tokio_util::io::ReaderStream;

use crate::ecosystem::pypi::index::IndexEntry;
use crate::ecosystem::pypi::upstream::{Upstream, UpstreamError};
use crate::model::{ArtifactKey, RefusalReason};
use crate::scan::Decision;

use super::refusal::{in_progress_response, refusal_response, unverifiable_response};
use super::{bad_request_response, not_found_response, why_url, AppState};

pub async fn artifact_handler(
    State(state): State<AppState>,
    Extension(upstream): Extension<Arc<Upstream>>,
    Path((raw_package, raw_version, raw_filename)): Path<(String, String, String)>,
) -> Response {
    let package = match state.ecosystem.validate_name(&raw_package) {
        Ok(name) => name,
        Err(err) => return bad_request_response(&format!("invalid package name: {err}")),
    };

    let fetched = match state.ecosystem.simple_page(&package).await {
        Ok(fetched) => fetched,
        Err(UpstreamError::NotFound) => return not_found_response(),
        Err(err) => return unverifiable_response(&upstream_unverifiable_reason(&err)),
    };

    // The PEP 658/714 metadata sidecar lives at the artifact's own
    // filename with ".metadata" appended, in the same path segment —
    // there is no separate route for it. It passes through unscanned:
    // see the module docs for why that is safe (the artifact itself is
    // still gated below, independently of this).
    if let Some(real_filename) = raw_filename.strip_suffix(".metadata") {
        return serve_metadata(&fetched.value, &upstream, real_filename).await;
    }

    let entry = match fetched.value.iter().find(|e| e.filename == raw_filename) {
        Some(entry) => entry.clone(),
        None => return not_found_response(),
    };

    let Some(parsed) = state.ecosystem.parse_filename(&entry.filename) else {
        return not_found_response();
    };
    if parsed.version != raw_version {
        // The URL's version segment does not match what the filename
        // itself parses to; treat it the same as "this artifact does not
        // exist at this URL" rather than trusting the client-supplied
        // segment for anything.
        return not_found_response();
    }

    let Some(sha256) = entry.sha256.clone() else {
        return unverifiable_response(&no_hash_reason());
    };

    let key = ArtifactKey {
        ecosystem: state.ecosystem.id().to_string(),
        package,
        version: parsed.version,
        filename: entry.filename.clone(),
        sha256,
    };

    match state.scanner.decide(&key, &entry).await {
        Decision::Serve(path) => serve_file(&path).await,
        Decision::Refuse { reason, why_id } => {
            let link = why_id.and_then(|id| why_url(&state.config.current(), &id));
            refusal_response(&reason, link.as_deref())
        }
        Decision::InProgress => in_progress_response(),
        Decision::Unverifiable(reason) => unverifiable_response(&reason),
    }
}

/// Fetches and passes through the `.metadata` sidecar for `filename`
/// (already stripped of its `.metadata` suffix) without ever touching
/// [`crate::scan::Scanner`] — PEP 658/714 metadata is inert, and
/// resolution depends on it staying cheap. The artifact itself goes
/// through [`artifact_handler`]'s normal gate regardless of what this
/// sidecar said.
async fn serve_metadata(entries: &[IndexEntry], upstream: &Upstream, filename: &str) -> Response {
    let Some(entry) = entries.iter().find(|e| e.filename == filename) else {
        return not_found_response();
    };

    match upstream.metadata_sidecar(entry).await {
        Ok(bytes) => octet_response(bytes),
        Err(UpstreamError::NotFound) => not_found_response(),
        Err(err) => unverifiable_response(&upstream_unverifiable_reason(&err)),
    }
}

/// Streams the cached, already-scanned file at `path` back to the client
/// as `application/octet-stream`. If the cached path has vanished from
/// disk between the scanner's decision and this read (e.g. an operator
/// manually pruned the cache directory), that is reported as
/// unverifiable, never silently as a 404 or an empty 200 — the artifact
/// *was* verified a moment ago, this is a transient failure to serve it.
async fn serve_file(path: &FsPath) -> Response {
    match tokio::fs::File::open(path).await {
        Ok(file) => {
            let stream = ReaderStream::new(file);
            let body = Body::from_stream(stream);
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(body)
                .unwrap_or_else(|_| {
                    unverifiable_response(&internal_reason("building the artifact response"))
                })
        }
        Err(err) => unverifiable_response(&internal_reason(&format!(
            "opening the cached artifact: {err}"
        ))),
    }
}

fn octet_response(bytes: Bytes) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| not_found_response())
}

fn no_hash_reason() -> RefusalReason {
    RefusalReason {
        code: "unverifiable:no-hash".to_string(),
        detail: "the package index did not declare a hash for this artifact".to_string(),
    }
}

fn internal_reason(context: &str) -> RefusalReason {
    RefusalReason {
        code: "unverifiable:internal".to_string(),
        detail: sanitize(context),
    }
}

fn upstream_unverifiable_reason(err: &UpstreamError) -> RefusalReason {
    RefusalReason {
        code: "unverifiable:upstream".to_string(),
        detail: sanitize(&format!(
            "could not verify this artifact right now: {err:#}"
        )),
    }
}

/// Strips ASCII control characters (including CR/LF) and non-ASCII bytes
/// before this text can reach an HTTP reason phrase, mirroring the same
/// discipline `crate::scan` and `crate::plugin` apply to their own
/// refusal details.
fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .take(200)
        .collect()
}

//! `GET /simple/<package>/`: the PEP 503 simple index passthrough.
//!
//! This handler never serves bytes itself — it fetches upstream's index
//! page for `package` through [`crate::ecosystem::Ecosystem::simple_page`],
//! drops any entry [`crate::scan::Scanner::blocked_filenames`] says is
//! blocked under today's policy (unless that version is allowlisted, in
//! which case it must stay visible so pip can still select it), rewrites
//! every surviving entry's URL to this proxy's own `/files/...` form, and
//! renders the result with [`crate::ecosystem::pypi::index::render_simple_page`].
//!
//! Filtering here is a convenience, not the gate: [`super::artifact::artifact_handler`]
//! independently re-decides every download regardless of what this page
//! showed, exactly as [`crate::scan::Scanner::blocked_filenames`]'s own
//! docs describe.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::config::AllowEntry;
use crate::ecosystem::pypi::index::{normalize_name, render_simple_page, IndexEntry};
use crate::ecosystem::pypi::upstream::UpstreamError;

use super::{bad_request_response, not_found_response, AppState};

pub async fn simple_handler(
    State(state): State<AppState>,
    Path(raw_package): Path<String>,
) -> Response {
    let package = match state.ecosystem.validate_name(&raw_package) {
        Ok(name) => name,
        Err(err) => return bad_request_response(&format!("invalid package name: {err}")),
    };

    let fetched = match state.ecosystem.simple_page(&package).await {
        Ok(fetched) => fetched,
        Err(UpstreamError::NotFound) => return not_found_response(),
        Err(err) => return super::refusal::unverifiable_response(&upstream_unverifiable(&err)),
    };

    let blocked = state
        .scanner
        .blocked_filenames(state.ecosystem.id(), &package)
        .await;

    let config = state.config.current();
    let public_url = &config.public_url;

    let filtered: Vec<IndexEntry> = fetched
        .value
        .into_iter()
        .filter_map(|entry| {
            let parsed = state.ecosystem.parse_filename(&entry.filename)?;

            if blocked.contains(&entry.filename)
                && !is_allowlisted(&config.allowlist, &package, &parsed.version)
            {
                return None;
            }

            let rewritten_path = format!("files/{package}/{}/{}", parsed.version, entry.filename);
            let rewritten_url = public_url.join(&rewritten_path).ok()?;

            Some(IndexEntry {
                filename: entry.filename,
                url: rewritten_url,
                sha256: entry.sha256,
                requires_python: entry.requires_python,
                metadata_hash: entry.metadata_hash,
                yanked: entry.yanked,
            })
        })
        .collect();

    let page = render_simple_page(&package, &filtered);
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(axum::body::Body::from(page))
        .unwrap_or_else(|_| not_found_response())
}

/// Whether `package`@`version` is explicitly allowlisted, overriding the
/// blocked-filename filter so the entry stays visible on the index page.
/// Mirrors [`crate::policy::Policy::allows`] exactly (package names
/// compared after PEP 503 normalization, versions compared verbatim) —
/// duplicated rather than reused because this is a display-only decision
/// with no [`crate::policy::Policy`] handle available here, while
/// [`crate::scan::Scanner::decide`] independently re-applies the real
/// allowlist check on every download regardless of what this page shows.
fn is_allowlisted(allowlist: &[AllowEntry], package: &str, version: &str) -> bool {
    let normalized = normalize_name(package);
    allowlist
        .iter()
        .any(|entry| normalize_name(&entry.package) == normalized && entry.version == version)
}

fn upstream_unverifiable(err: &UpstreamError) -> crate::model::RefusalReason {
    crate::model::RefusalReason {
        code: "unverifiable:upstream".to_string(),
        detail: sanitize(&format!(
            "could not fetch the package index right now: {err:#}"
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

//! `GET /simple/<package>/`: the PEP 503 simple index passthrough.
//!
//! This handler never serves bytes itself — it fetches upstream's index
//! page for `package` through [`crate::ecosystem::Ecosystem::simple_page`],
//! drops any entry [`crate::scan::Scanner::file_verdicts`] says is blocked
//! under today's policy (unless that version is allowlisted, in which
//! case it must stay visible so pip can still select it), rewrites every
//! surviving entry's URL to this proxy's own `/files/...` form, and
//! renders the result with [`crate::ecosystem::pypi::index::render_simple_page`].
//!
//! Filtering here is a convenience, not the gate: [`super::artifact::artifact_handler`]
//! independently re-decides every download regardless of what this page
//! showed.
//!
//! **One lookup, not two.** A predecessor of this handler read the
//! blocked set from [`crate::scan::Scanner::blocked_filenames`] and the
//! audit reasons from [`crate::scan::Scanner::file_verdicts`] as two
//! separate, sequential DB round-trips. That let a verdict write landing
//! between the two awaits (a concurrent re-scan flipping a verdict) make
//! the page's filtering decision and the audit log's decision disagree
//! about the very same request — exactly the kind of drift this audit
//! feature exists to rule out. `file_verdicts` already carries `blocked`
//! per filename, so the filtering decision below is derived from the
//! same single read the audit decision uses: one row, one `blocked`
//! bool, both consumers. `Scanner::blocked_filenames` and
//! `VerdictStore::blocked_filenames` are untouched and keep their own
//! tests; this handler simply no longer calls them.
//!
//! **The audit side of this handler.** PyPI has no cascade: most of
//! upstream's entries have never been scanned at all, so "evaluated"
//! here means "has a stored verdict under today's policy fingerprint" —
//! [`crate::scan::Scanner::file_verdicts`] is exactly that lookup. One
//! `listing` record is written counting how many entries upstream's
//! page carried against how many of those were actually evaluated, and
//! one `listed` record follows per evaluated entry, naming both its
//! `version` and `filename` (PyPI decides per file, so one version can
//! be part-blocked) and whether it was allowed or denied and why. An
//! entry upstream listed but this proxy never scanned gets no `listed`
//! record at all — counting it as "evaluated" would make "never looked
//! at" indistinguishable from "looked at and let through", which is
//! exactly the confusion the design calls out. A blocked-but-allowlisted
//! entry stays visible on the page as it always has, but its audit line
//! still has to say the scan itself found something: it is logged
//! `allowed` with `reason_code: "allowlisted"` rather than as an
//! ordinary pass, so a reader of the log can tell the two apart. Written
//! before the rendered page is returned, and — like every write
//! `audit_or_500` guards — a write failure here is a 500 with no index
//! HTML, never a page that implies this listing was recorded when it
//! was not.

use std::collections::HashMap;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::audit::{AuditContext, ListingAudit, VersionDecision};
use crate::db::verdict::FileVerdict;
use crate::ecosystem::pypi::index::{render_simple_page, IndexEntry};
use crate::ecosystem::pypi::upstream::UpstreamError;
use crate::scan::is_allowlisted;

use super::{audit_or_500, bad_request_response, not_found_response, AppState};

pub async fn simple_handler(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(raw_package): Path<String>,
) -> Response {
    // See `artifact_handler`'s own doc comment for why this is built
    // from the real TCP peer and never from a client-supplied header.
    let ctx = AuditContext::new(state.ecosystem.id(), peer);

    let package = match state.ecosystem.validate_name(&raw_package) {
        Ok(name) => name,
        Err(err) => return bad_request_response(&format!("invalid package name: {err}")),
    };

    let fetched = match state.ecosystem.simple_page(&package).await {
        Ok(fetched) => fetched,
        Err(UpstreamError::NotFound) => return not_found_response(),
        Err(err) => return super::refusal::unverifiable_response(&upstream_unverifiable(&err)),
    };

    // The single source of truth for both this page's filtering and its
    // audit decisions: one row per scanned filename, carrying `blocked`
    // alongside the reason, detail and why_id the `listed` audit records
    // need to report. Reading it once and deriving `is_blocked` from the
    // same row the audit decision reads (below) is the whole point —
    // two independent reads (one for filtering, one for the audit) could
    // straddle a concurrent re-scan and see two different answers for
    // the same filename on the same request.
    let file_verdicts = state
        .scanner
        .file_verdicts(state.ecosystem.id(), &package)
        .await;
    let verdicts_by_filename: HashMap<&str, &FileVerdict> = file_verdicts
        .iter()
        .map(|verdict| (verdict.filename.as_str(), verdict))
        .collect();

    let config = state.config.current();
    let public_url = &config.public_url;

    let versions_upstream = fetched.value.len();
    let mut decisions = Vec::new();
    let mut filtered = Vec::new();

    for entry in fetched.value {
        let Some(parsed) = state.ecosystem.parse_filename(&entry.filename) else {
            continue;
        };

        let allowlisted = is_allowlisted(&config, &package, &parsed.version);
        let verdict = verdicts_by_filename.get(entry.filename.as_str());
        // An entry with no stored verdict has never been scanned, so it
        // was never blocked by this proxy — it stays on the page exactly
        // as it always has, and (per the audit doc comment above) gets
        // no `listed` line at all.
        let is_blocked = verdict.is_some_and(|verdict| verdict.blocked);

        if let Some(verdict) = verdict {
            let (allowed, reason_code, reason_detail) = if verdict.blocked && allowlisted {
                (
                    true,
                    Some("allowlisted".to_string()),
                    Some(verdict.reason_detail.clone()),
                )
            } else if verdict.blocked {
                (
                    false,
                    Some(verdict.reason_code.clone()),
                    Some(verdict.reason_detail.clone()),
                )
            } else {
                (true, None, None)
            };
            decisions.push(VersionDecision {
                version: parsed.version.clone(),
                filename: Some(entry.filename.clone()),
                allowed,
                reason_code,
                reason_detail,
                why_id: Some(verdict.why_id.clone()),
            });
        }

        if is_blocked && !allowlisted {
            continue;
        }

        let rewritten_path = format!("files/{package}/{}/{}", parsed.version, entry.filename);
        let Ok(rewritten_url) = public_url.join(&rewritten_path) else {
            continue;
        };

        filtered.push(IndexEntry {
            filename: entry.filename,
            url: rewritten_url,
            sha256: entry.sha256,
            requires_python: entry.requires_python,
            metadata_hash: entry.metadata_hash,
            yanked: entry.yanked,
        });
    }

    let listing_audit = ListingAudit {
        versions_upstream,
        decisions,
    };
    let records = listing_audit.records(&ctx, &package);
    if let Some(failure) = audit_or_500(&state.audit, &records) {
        return failure;
    }

    let page = render_simple_page(&package, &filtered);
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(axum::body::Body::from(page))
        .unwrap_or_else(|_| not_found_response())
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

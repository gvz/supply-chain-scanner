//! `GET /why/<id>`: the server-rendered explanation page a `/why/<id>`
//! link (built from the reason phrase) takes a developer to.
//!
//! Every stored field rendered onto this page — including
//! `RefusalReason.detail`, which can contain attacker-influenced text
//! that originated inside the package the scan was blocking — is
//! HTML-escaped. The page must not become the delivery vehicle for what
//! the scan caught.
//!
//! # One lookup, two extractors
//!
//! Both deployments serve this page, and they carry different state
//! types: [`super::AppState`] on the PyPI path,
//! [`super::cargo_index::CargoAppState`] on the cargo one. The lookup and
//! the rendering therefore live in [`why_for`], which takes the two
//! stores it actually reads. [`why_handler`] and
//! [`super::cargo_index::cargo_why_handler`] are thin extractors over it,
//! the same split [`super::refusals`] uses for the same reason. There is
//! exactly one copy of the lookup and one copy of the HTML.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::db::review::{ReviewStore, StoredReview};
use crate::db::verdict::{StoredVerdict, VerdictStore};
use crate::model::{ArtifactKey, RefusalReason, Verdict};

use super::AppState;

/// `GET /why/:id`. Resolves `why_id` back to the artifact and verdict it
/// was issued for and renders an HTML explanation page.
///
/// An unknown or expired `why_id` is a 404, not an error page — a
/// `why_id` lives exactly as long as its verdict row, so once that row is
/// gone (or never existed) there is nothing to explain. A lookup failure
/// (e.g. the database is unreachable) never renders as a 200: it falls
/// back to a generic 500 rather than fabricating or guessing at content
/// that was never actually read.
pub async fn why_handler(State(state): State<AppState>, Path(why_id): Path<String>) -> Response {
    why_for(state.verdicts, state.reviews, why_id).await
}

/// The shared lookup-and-render body of every `/why/<id>` handler: resolves
/// `why_id` through `verdicts`, attaches the review that belongs to the
/// verdict's own fingerprint, and renders the page.
///
/// `pub(crate)` because the cargo router's own handler calls it. See this
/// module's docs for why the split is here and not inside the renderer.
pub(crate) async fn why_for(
    verdicts: Arc<VerdictStore>,
    reviews: Arc<ReviewStore>,
    why_id: String,
) -> Response {
    let lookup_id = why_id.clone();
    let lookup = tokio::task::spawn_blocking(move || verdicts.get_by_why_id(&lookup_id)).await;

    match lookup {
        Ok(Ok(Some((key, stored)))) => {
            // The review that goes with this verdict. Looked up by the
            // verdict's own fingerprint, never the scanner's current
            // one: this verdict may predate the running policy, and a
            // lookup with the live fingerprint would attach the wrong
            // report or none. A missing review is not an error — every
            // verdict without an AI gate has none — so it renders as no
            // section, and a lookup failure costs the report, not the
            // explanation.
            let reviews = reviews.clone();
            let review_key = key.clone();
            let review_fingerprint = stored.fingerprint.clone();
            let review = tokio::task::spawn_blocking(move || {
                reviews.newest_for_artifact(&review_key, &review_fingerprint)
            })
            .await
            .ok()
            .and_then(|result| result.ok())
            .flatten();
            render_why_page(&key, &stored, review.as_ref())
        }
        Ok(Ok(None)) => not_found_response(),
        Ok(Err(_)) | Err(_) => lookup_failed_response(),
    }
}

fn not_found_response() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(
            "<!doctype html><html><body><h1>404 Not Found</h1>\
             <p>This why-id is unknown or has expired.</p></body></html>",
        ))
        .unwrap_or_else(|_| fail_closed())
}

fn lookup_failed_response() -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(
            "<!doctype html><html><body><h1>500 Internal Server Error</h1>\
             <p>Could not look up this why-id right now.</p></body></html>",
        ))
        .unwrap_or_else(|_| fail_closed())
}

/// The absolute last resort if even the hardcoded bodies above somehow
/// fail to build into a `Response`. Still a server error, never a 200.
fn fail_closed() -> Response {
    let mut response = Response::new(Body::from("internal error"));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

fn render_why_page(
    key: &ArtifactKey,
    stored: &StoredVerdict,
    review: Option<&StoredReview>,
) -> Response {
    let html = match &stored.verdict {
        Verdict::Blocked(reason) => blocked_page(
            key,
            stored.why_id.as_str(),
            stored.scanned_at,
            reason,
            review,
        ),
        Verdict::Clean => clean_page(key, stored.why_id.as_str(), stored.scanned_at, review),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap_or_else(|_| fail_closed())
}

fn blocked_page(
    key: &ArtifactKey,
    why_id: &str,
    scanned_at: i64,
    reason: &RefusalReason,
    review: Option<&StoredReview>,
) -> String {
    format!(
        "<!doctype html>\
<html><head><meta charset=\"utf-8\"><title>Blocked: {code}</title></head>\
<body>\
<h1>This artifact was blocked</h1>\
<table>\
<tr><th>Check</th><td>{code}</td></tr>\
<tr><th>Detail</th><td>{detail}</td></tr>\
<tr><th>Ecosystem</th><td>{ecosystem}</td></tr>\
<tr><th>Package</th><td>{package}</td></tr>\
<tr><th>Version</th><td>{version}</td></tr>\
<tr><th>Filename</th><td>{filename}</td></tr>\
<tr><th>SHA-256</th><td>{sha256}</td></tr>\
<tr><th>Scanned at</th><td>{scanned_at} (unix epoch seconds)</td></tr>\
<tr><th>why-id</th><td>{why_id}</td></tr>\
</table>\
<h2>What you can do</h2>\
<p>If your organization has reviewed this exact package and version and \
decided it is safe to use anyway, ask whoever manages this proxy's \
configuration to add an allowlist entry for <strong>{package} \
{version}</strong>. An allowlist entry overrides this verdict but never \
the integrity check the download still has to pass.</p>\
<p>If you believe the severity of this finding is wrong, raise it with \
whoever owns this proxy's CVE line (the <code>cve.min_severity</code> \
and <code>cve.require_fix_available</code> settings) — adjusting that \
line changes which advisories block a package going forward.</p>\
{review_section}
</body></html>",
        code = escape_html(&reason.code),
        detail = escape_html(&reason.detail),
        ecosystem = escape_html(&key.ecosystem),
        package = escape_html(&key.package),
        version = escape_html(&key.version),
        filename = escape_html(&key.filename),
        sha256 = escape_html(&key.sha256),
        scanned_at = scanned_at,
        why_id = escape_html(why_id),
        review_section = review_section(Some(reason.code.as_str()), review),
    )
}

fn clean_page(
    key: &ArtifactKey,
    why_id: &str,
    scanned_at: i64,
    review: Option<&StoredReview>,
) -> String {
    format!(
        "<!doctype html>\
<html><head><meta charset=\"utf-8\"><title>Scanned clean</title></head>\
<body>\
<h1>This artifact was scanned and found clean</h1>\
<table>\
<tr><th>Ecosystem</th><td>{ecosystem}</td></tr>\
<tr><th>Package</th><td>{package}</td></tr>\
<tr><th>Version</th><td>{version}</td></tr>\
<tr><th>Filename</th><td>{filename}</td></tr>\
<tr><th>SHA-256</th><td>{sha256}</td></tr>\
<tr><th>Scanned at</th><td>{scanned_at} (unix epoch seconds)</td></tr>\
<tr><th>why-id</th><td>{why_id}</td></tr>\
</table>\
<p>No check blocked this artifact. If you were expecting a refusal here, \
the verdict may have been recorded before a later policy change.</p>\
{review_section}
</body></html>",
        ecosystem = escape_html(&key.ecosystem),
        package = escape_html(&key.package),
        version = escape_html(&key.version),
        filename = escape_html(&key.filename),
        sha256 = escape_html(&key.sha256),
        scanned_at = scanned_at,
        why_id = escape_html(why_id),
        review_section = review_section(None, review),
    )
}

/// What the `/why` page shows when the difference is coverage rather
/// than what was found: the block is lifted by a human sign-off, which
/// is the allowlist.
const COVERAGE_REMEDY: &str = "\
<h3>What lifts this</h3>\
<p>This block is about how much source the review saw, not what it \
found. To let this artifact through, ask whoever manages this proxy's \
configuration to add an allowlist entry for this exact package and \
version. That is the required sign-off. No coverage figure improves \
until an operator changes the policy.</p>";

/// Renders the AI review section for a why page, or an empty string when
/// this verdict has no review. Each field on the page — the model's own
/// summary above all — is attacker-influenced text, so every fragment
/// goes through [`escape_html`] on its way in.
///
/// `reason_code` is the refusal code on the page, or `None` on a clean
/// page. A coverage block adds the sign-off paragraph of its own,
/// because that is what tells the person reading the page what actually
/// lifts the block, and it differs from every other refusal on this page.
fn review_section(reason_code: Option<&str>, review: Option<&StoredReview>) -> String {
    let Some(review) = review else {
        return String::new();
    };

    let findings = findings_html(review);
    let coverage = coverage_html(review);
    let opaque = opaque_html(review);
    let paths = paths_html(review);

    let coverage_remedy = match reason_code {
        Some(crate::ai::code::COVERAGE) => COVERAGE_REMEDY,
        _ => "",
    };

    format!(
        "<h2>AI review</h2>\
<p>The review that produced the verdict above, recorded under \
the same policy fingerprint. Nothing on this page is a prompt to \
execute — it is the model's opinion, reported as it was recorded.</p>\
<table>
<tr><th>Model verdict</th><td>{verdict}</td></tr>\
<tr><th>Summary</th><td>{summary}</td></tr>\
<tr><th>Coverage</th><td>{coverage}</td></tr>\
<tr><th>Opaque content</th><td>{opaque}</td></tr>\
<tr><th>Model</th><td>{model}</td></tr>\
<tr><th>Prompt version</th><td>{prompt_version}</td></tr>\
</table>\
<h3>What the model claimed</h3>\
<ul>
{findings}</ul>\
<h3>What the model received</h3>\
<ul>
{paths}</ul>\
{coverage_remedy}",
        verdict = escape_html(&review.verdict),
        summary = escape_html(&review.summary),
        coverage = coverage,
        opaque = opaque,
        model = escape_html(&review.model),
        prompt_version = escape_html(&review.prompt_version),
        findings = findings,
        paths = paths,
        coverage_remedy = coverage_remedy,
    )
}

/// The coverage figure as the page states it, or the plain statement
/// that there was no source to review.
fn coverage_html(review: &StoredReview) -> String {
    match review.coverage {
        Some(figure) => escape_html(&format!(
            "{:.1} percent of reviewable bytes \
({} of {} bytes)",
            figure * 100.0,
            review.reviewable_bytes_sent,
            review.reviewable_bytes_total
        )),
        None => "There was no source to review in this artifact.".to_string(),
    }
}

/// The opaque content figures with byte counts. The reviewable bytes
/// the model did not receive are named with their count; the opaque
/// executables and opaque data come from the row's own JSON object,
/// which is what the collector measured.
fn opaque_html(review: &StoredReview) -> String {
    let opaque: serde_json::Value =
        serde_json::from_str(&review.opaque_json).unwrap_or_else(|_| serde_json::json!({}));
    let opaque_data_bytes = opaque
        .get("opaque_data_bytes")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    escape_html(&format!(
        "opaque data: {opaque_data_bytes} bytes; opaque executables: {}",
        opaque_executable_names(review)
    ))
}

/// Each finding's path and claimed behaviour, as a single escaped HTML
/// list. The row stores them as a JSON array; a parse failure degrades
/// to an empty list rather than failing the page.
fn findings_html(review: &StoredReview) -> String {
    let empty: Vec<serde_json::Value> = Vec::new();
    let findings = serde_json::from_str(&review.findings_json).unwrap_or(empty);
    findings
        .iter()
        .map(|finding| {
            let path = finding.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let behavior = finding
                .get("behavior")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            format!(
                "<li><code>{path}</code>: {behavior}</li>",
                path = escape_html(path),
                behavior = escape_html(behavior)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The paths the model actually received, escaped, as a single list.
fn paths_html(review: &StoredReview) -> String {
    let empty: Vec<String> = Vec::new();
    let paths: Vec<String> = serde_json::from_str(&review.reviewed_paths_json).unwrap_or(empty);
    paths
        .iter()
        .map(|path| format!("<li><code>{path}</code></li>", path = escape_html(path)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The opaque executables with their byte counts, read out of the row's
/// own JSON object. Names and sizes both, because a reviewer reading the
/// page needs to be able to see which parts nobody could read.
fn opaque_executable_names(review: &StoredReview) -> String {
    let opaque: serde_json::Value =
        serde_json::from_str(&review.opaque_json).unwrap_or_else(|_| serde_json::json!({}));
    let empty: Vec<serde_json::Value> = Vec::new();
    let executables: Vec<serde_json::Value> = opaque
        .get("opaque_executables")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or(empty);
    if executables.is_empty() {
        return "none".to_string();
    }
    executables
        .iter()
        .map(|exe| {
            let path = exe
                .get("path")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let bytes = exe
                .get("bytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            format!("{path} ({bytes} bytes)")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Escapes the five bytes that matter for safely embedding arbitrary text
/// inside HTML element content and double-quoted attribute values:
/// `&`, `<`, `>`, `"`, and `'`. Every stored field rendered on this page
/// goes through this — the `detail` field in particular can originate
/// inside a hostile package, so this page must never become the delivery
/// vehicle for what the scan caught.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_html_escapes_all_five_special_characters() {
        let input = "<script>alert('x')&\"y\"</script>";
        let escaped = escape_html(input);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(!escaped.contains('\''));
        assert!(!escaped.contains('"'));
        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&#39;x&#39;)&amp;&quot;y&quot;&lt;/script&gt;"
        );
    }
}

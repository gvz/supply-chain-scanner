//! `GET /why/<id>`: the server-rendered explanation page a `/why/<id>`
//! link (built from the reason phrase) takes a developer to.
//!
//! Every stored field rendered onto this page — including
//! `RefusalReason.detail`, which can contain attacker-influenced text
//! that originated inside the package the scan was blocking — is
//! HTML-escaped. The page must not become the delivery vehicle for what
//! the scan caught.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::db::verdict::StoredVerdict;
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
    let verdicts = state.verdicts;
    let lookup_id = why_id.clone();
    let lookup = tokio::task::spawn_blocking(move || verdicts.get_by_why_id(&lookup_id)).await;

    match lookup {
        Ok(Ok(Some((key, stored)))) => render_why_page(&key, &stored),
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

fn render_why_page(key: &ArtifactKey, stored: &StoredVerdict) -> Response {
    let html = match &stored.verdict {
        Verdict::Blocked(reason) => {
            blocked_page(key, stored.why_id.as_str(), stored.scanned_at, reason)
        }
        Verdict::Clean => clean_page(key, stored.why_id.as_str(), stored.scanned_at),
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
    )
}

fn clean_page(key: &ArtifactKey, why_id: &str, scanned_at: i64) -> String {
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
</body></html>",
        ecosystem = escape_html(&key.ecosystem),
        package = escape_html(&key.package),
        version = escape_html(&key.version),
        filename = escape_html(&key.filename),
        sha256 = escape_html(&key.sha256),
        scanned_at = scanned_at,
        why_id = escape_html(why_id),
    )
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

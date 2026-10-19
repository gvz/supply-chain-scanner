//! `GET /refusals`: the unauthenticated HTML listing of this proxy's
//! most recent blocks, newest first.
//!
//! Cargo's sparse-registry protocol gives a client almost nothing to show
//! a developer when the proxy refuses an index entry — no HTTP body worth
//! reading, just a failed resolution. This page is where the refusals that
//! happened that way become visible: one row per blocked artifact, with
//! the package, the version, the refusal code, when it happened, and a
//! link to the `/why/<id>` page that explains it in full.
//!
//! There is no authentication, exactly like `/why`: a developer holding a
//! `why_id` already has the explanation, and this page only adds the list
//! of recent ones for the same audience.
//!
//! Every value read out of the database is HTML-escaped on the way onto
//! the page. `reason_detail` in particular can quote text that originated
//! inside the blocked package, so this page must never become the
//! delivery vehicle for what the scan caught. The escaping helper here is
//! a deliberate copy of the private one in [`super::why`]: it escapes the
//! same five characters, and the two pages must not share a helper that
//! one of them could widen without the other noticing.

use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;

use crate::db::verdict::BlockedVerdict;

use super::AppState;

/// How many blocks the page lists. Fixed rather than query-controlled:
/// this is a "what has just been refused" view, not a searchable audit
/// trail (that is `/api/reviews`), and a caller-supplied limit on an
/// unauthenticated endpoint is a free way to make the database do work.
const RECENT_REFUSALS_LIMIT: usize = 100;

/// `GET /refusals`. Lists the most recent blocked artifacts for this
/// deployment's ecosystem and renders them as a plain HTML table.
///
/// A lookup failure is a 500, never an empty 200: "no refusals" and
/// "could not read the refusals" are different answers, and a page that
/// showed an empty table for a database error would tell an operator
/// their proxy had blocked nothing when it may have blocked plenty.
pub async fn refusals_handler(State(state): State<AppState>) -> Response {
    let verdicts = state.verdicts;
    let ecosystem = state.ecosystem.id().to_string();
    let listed = tokio::task::spawn_blocking(move || {
        verdicts.recent_blocked(&ecosystem, RECENT_REFUSALS_LIMIT)
    })
    .await;

    match listed {
        Ok(Ok(blocked)) => render_refusals_page(&blocked),
        Ok(Err(_)) | Err(_) => lookup_failed_response(),
    }
}

fn render_refusals_page(blocked: &[BlockedVerdict]) -> Response {
    let rows = blocked
        .iter()
        .map(|verdict| {
            format!(
                "<tr>\
<td>{package}</td>\
<td>{version}</td>\
<td>{code}</td>\
<td>{detail}</td>\
<td>{scanned_at} (unix epoch seconds)</td>\
<td><a href=\"/why/{why_id}\">why</a></td>\
</tr>",
                package = escape_html(&verdict.package),
                version = escape_html(&verdict.version),
                code = escape_html(&verdict.reason_code),
                detail = escape_html(&verdict.reason_detail),
                scanned_at = verdict.scanned_at,
                why_id = escape_html(&verdict.why_id),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let html = format!(
        "<!doctype html>\
<html><head><meta charset=\"utf-8\"><title>Recent refusals</title></head>\
<body>\
<h1>Recent refusals</h1>\
<p>Artifacts this proxy refused, newest first, up to the last {RECENT_REFUSALS_LIMIT}. \
Each row links to the page that explains the refusal.</p>\
<table>\
<tr><th>Package</th><th>Version</th><th>Refusal code</th><th>Detail</th>\
<th>Blocked at</th><th>Explanation</th></tr>\
{rows}
</table>\
</body></html>"
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap_or_else(|_| fail_closed())
}

fn lookup_failed_response() -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(
            "<!doctype html><html><body><h1>500 Internal Server Error</h1>\
             <p>Could not read the recent refusals right now.</p></body></html>",
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

/// Escapes the five bytes that matter for safely embedding arbitrary text
/// inside HTML element content and double-quoted attribute values:
/// `&`, `<`, `>`, `"`, and `'`. Identical in behaviour to the private
/// helper in [`super::why`] — see this module's docs for why it is a
/// copy rather than a shared function.
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

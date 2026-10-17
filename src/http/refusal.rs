//! The reason-phrase channel: the only part of a refusal pip ever shows a
//! developer.
//!
//! pip never prints an HTTP response body (verified against pip 25.3,
//! whose `pip/_internal/network/utils.py` builds its error message from
//! the status code and reason phrase alone). What it does print is the
//! status line's reason phrase and the URL it requested. That makes the
//! reason phrase the primary channel for telling a blocked developer
//! which check refused them and where to read the detail — and it makes
//! [`sanitize_phrase`] a security boundary, not cosmetics: a CR or LF
//! reaching the status line is HTTP response splitting.
//!
//! Status codes are chosen for how pip actually behaves, not for REST
//! aesthetics:
//! - 403 ([`refusal_response`]) — blocked.
//! - 429 ([`in_progress_response`]) — scan still running. Deliberately
//!   not 503: pip's session retries 500/503 automatically (urllib3's
//!   `status_forcelist`), which would bury the message; 429 surfaces
//!   straight to the developer.
//! - 503 ([`unverifiable_response`]) — cannot verify (e.g. upstream
//!   unreachable). Here the automatic retry is desirable, so 503 is
//!   correct, and the phrase says "UNVERIFIABLE", never "BLOCKED" — "we
//!   could not check" and "we checked and it is bad" must never look the
//!   same to a developer.

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use hyper::ext::ReasonPhrase;

use crate::model::RefusalReason;

/// The largest reason phrase this proxy will ever put on an HTTP/1.1
/// status line.
const MAX_PHRASE_BYTES: usize = 120;

/// Sanitizes `s` into something safe to put on an HTTP/1.1 status line:
/// printable ASCII only (0x20-0x7E), every control byte (CR and LF
/// included — the bytes a response-splitting attack needs) and every
/// non-ASCII byte dropped entirely, then capped at 120 bytes.
///
/// Filtering to printable ASCII happens *before* the length cap, so the
/// cap only ever has to slice a string made entirely of one-byte
/// characters — it can never land inside a multi-byte UTF-8 sequence.
/// [`cap_bytes`] still cuts on a character boundary defensively, in case
/// a future caller changes that order.
///
/// This is called independently of (and in addition to) the sanitizing
/// `crate::advisory::matching`, `crate::plugin`, and `crate::scan` already
/// apply to a `RefusalReason`'s fields: this module does not trust that
/// upstream discipline, because this is the boundary that actually
/// matters — the one byte sequence that reaches the wire.
pub fn sanitize_phrase(s: &str) -> String {
    let printable_ascii: String = s.chars().filter(|&c| (' '..='~').contains(&c)).collect();
    cap_bytes(&printable_ascii, MAX_PHRASE_BYTES)
}

/// Truncates `s` to at most `max_bytes` bytes, cutting on a UTF-8 char
/// boundary rather than panicking mid-character.
fn cap_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Builds a [`hyper::ext::ReasonPhrase`] from already-sanitized ASCII
/// text. Every byte `sanitize_phrase` can produce (0x20-0x7E) is a byte
/// hyper itself accepts in a reason phrase, so this should never fail in
/// practice — but on the off chance it ever does, it falls back to
/// `fallback` rather than leaving the response with no explicit phrase at
/// all (which would silently fall back to the canonical phrase for the
/// status code, e.g. plain "Forbidden", losing the explanation).
fn reason_phrase(sanitized: &str, fallback: &'static [u8]) -> ReasonPhrase {
    ReasonPhrase::try_from(sanitized.as_bytes().to_vec())
        .unwrap_or_else(|_| ReasonPhrase::from_static(fallback))
}

/// Builds a response that can never accidentally pass a request through:
/// a fixed `status`, a sanitized reason phrase inserted into the
/// extensions (read by hyper's HTTP/1.1 encoder), and a plain-text body
/// repeating the same text for clients that aren't pip (curl, browsers,
/// other installers don't suppress response bodies the way pip does).
fn status_response(
    status: StatusCode,
    phrase_text: &str,
    fallback_phrase: &'static [u8],
) -> Response {
    let sanitized = sanitize_phrase(phrase_text);
    let body = format!("{sanitized}\n");

    let mut response = Response::builder()
        .status(status)
        .header(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )
        .body(Body::from(body))
        .unwrap_or_else(|_| fail_closed_response(status, fallback_phrase));

    response
        .extensions_mut()
        .insert(reason_phrase(&sanitized, fallback_phrase));
    response
}

/// The last-resort response when something above fails to build at all.
/// Never a 200, never a pass-through: always the refusal status the
/// caller asked for, with a generic, hardcoded-safe phrase.
fn fail_closed_response(status: StatusCode, fallback_phrase: &'static [u8]) -> Response {
    let mut response = Response::new(Body::from(
        "the proxy refused this request but could not render an explanation\n",
    ));
    *response.status_mut() = status;
    response
        .extensions_mut()
        .insert(ReasonPhrase::from_static(fallback_phrase));
    response
}

/// 403: the artifact was scanned and blocked. The phrase is shaped
/// `BLOCKED <code> - why <url>` (or just `BLOCKED <code>` when no stored
/// verdict exists to link to, e.g. a hash mismatch that was never
/// persisted) so a developer reading pip's error line learns both which
/// check refused them and where to read the detail.
pub fn refusal_response(reason: &RefusalReason, why_url: Option<&str>) -> Response {
    let phrase_text = build_blocked_phrase(&reason.code, why_url);
    status_response(StatusCode::FORBIDDEN, &phrase_text, b"Blocked")
}

/// Fixed scaffold text around the variable-length `code` and `url`.
const BLOCKED_PREFIX: &str = "BLOCKED ";
const WHY_SEPARATOR: &str = " - why ";
const ELLIPSIS: &str = "...";

/// Builds the `BLOCKED <code> - why <url>` phrase so that when the
/// combined length would exceed [`MAX_PHRASE_BYTES`], it is the
/// variable-length `code` that gets shortened, never the `why` URL — a
/// phrase is still useful to a developer with a code they have to look
/// up themselves, but a URL truncated mid-path looks clickable and
/// isn't, leaving them with no path to the detail page at all. The URL
/// is why this channel exists, so it is reserved first; the code gets
/// whatever bytes are left over, ellipsized if it doesn't fit.
///
/// If the URL alone (plus the fixed scaffold) does not fit in the
/// budget — an absurdly long `public_url` — the code is dropped
/// entirely rather than ellipsized to nothing: a developer with a link
/// can always find the code on the page it points to, but a code with
/// no link is a dead end.
fn build_blocked_phrase(code: &str, why_url: Option<&str>) -> String {
    let Some(url) = why_url else {
        return format!("{BLOCKED_PREFIX}{code}");
    };

    let scaffold_and_url = BLOCKED_PREFIX.len() + WHY_SEPARATOR.len() + url.len();
    if scaffold_and_url > MAX_PHRASE_BYTES {
        return format!("BLOCKED{WHY_SEPARATOR}{url}");
    }

    let code_budget = MAX_PHRASE_BYTES - scaffold_and_url;
    let shortened_code = ellipsize(code, code_budget);
    format!("{BLOCKED_PREFIX}{shortened_code}{WHY_SEPARATOR}{url}")
}

/// Shortens `s` to at most `max_bytes` bytes, replacing any truncated
/// tail with an ellipsis so a shortened code reads as visibly
/// incomplete rather than silently cut (and, unlike a cut URL, a
/// shortened code was never going to be the whole story anyway — the
/// full text is always in `RefusalReason.detail` on the `/why` page).
/// Cuts on a char boundary; if `max_bytes` is too small to fit even the
/// ellipsis, returns an empty string rather than panicking.
fn ellipsize(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    if ELLIPSIS.len() >= max_bytes {
        return cap_bytes(ELLIPSIS, max_bytes);
    }
    let truncated = cap_bytes(s, max_bytes - ELLIPSIS.len());
    format!("{truncated}{ELLIPSIS}")
}

/// 429: the scan for this artifact is still running. Deliberately not
/// 503 — see the module docs for why pip's automatic retry-on-503 would
/// bury this message.
pub fn in_progress_response() -> Response {
    status_response(
        StatusCode::TOO_MANY_REQUESTS,
        "SCAN IN PROGRESS - please retry shortly",
        b"Scan in progress",
    )
}

/// 503: the artifact cannot currently be confirmed safe or unsafe (e.g.
/// upstream is unreachable, or an internal failure happened partway
/// through a scan). The phrase always says "UNVERIFIABLE", never
/// "BLOCKED" — this is "we could not check", not "we checked and it is
/// bad", and the two must never look the same on pip's error line.
pub fn unverifiable_response(reason: &RefusalReason) -> Response {
    let phrase_text = format!(
        "UNVERIFIABLE {} - could not check this artifact",
        reason.code
    );
    status_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &phrase_text,
        b"Unverifiable",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_bytes_never_panics_on_a_boundary_straddling_cut() {
        // 'é' is 2 bytes; put it exactly where a naive byte-index slice
        // would land mid-character, and confirm no panic and no partial
        // character in the output.
        let mut s = "a".repeat(4);
        s.push('é');
        let capped = cap_bytes(&s, 5);
        assert!(capped.len() <= 5);
        assert!(String::from_utf8(capped.into_bytes()).is_ok());
    }

    #[test]
    fn fail_closed_response_is_never_2xx() {
        let response = fail_closed_response(StatusCode::FORBIDDEN, b"Blocked");
        assert!(response.status().is_client_error());
    }

    #[test]
    fn build_blocked_phrase_drops_the_code_when_even_the_bare_url_does_not_fit() {
        // An absurdly long `public_url` leaves no room for the scaffold
        // plus the URL, let alone any code. The code must be dropped
        // (not ellipsized into nothing), and the full URL must still be
        // present verbatim.
        let url = format!("http://localhost:8080/why/{}", "a".repeat(130));
        let phrase = build_blocked_phrase("cve:high", Some(&url));

        assert!(!phrase.contains("cve:high"));
        assert!(
            phrase.contains(&url),
            "the full URL must survive, got {phrase:?}"
        );
    }
}

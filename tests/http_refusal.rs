//! Integration tests for `supply_chain_scanner::http::refusal` and
//! `supply_chain_scanner::http::why`: the only HTTP surface a blocked
//! developer ever sees.
//!
//! pip never prints an HTTP response body — only the status line's reason
//! phrase and the requested URL. These tests prove three things: the
//! phrase is injection-safe by construction (`sanitize_phrase`), the three
//! refusal shapes (blocked/in-progress/unverifiable) are distinguishable
//! by status code and by wording, and the `/why/<id>` page never echoes
//! stored (attacker-influenced) text unescaped.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::extract::{Path, State};

use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::config::{Config, ConfigHandle, CveLine, UnknownSeverity};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::index_cache::IndexCache;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::pypi::upstream::Upstream;
use supply_chain_scanner::ecosystem::pypi::PyPi;
use supply_chain_scanner::http::refusal::{
    in_progress_response, refusal_response, sanitize_phrase, unverifiable_response,
};
use supply_chain_scanner::http::why::why_handler;
use supply_chain_scanner::http::AppState;
use supply_chain_scanner::model::{ArtifactKey, RefusalReason, Verdict};
use supply_chain_scanner::plugin::{PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec};
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::Scanner;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// No plugins are configured in any of these tests, so this must never run.
struct NeverCalledSandbox;
impl SandboxRunner for NeverCalledSandbox {
    fn run(&self, _spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        panic!("no plugins are configured in this test; the sandbox must never run");
    }
}

fn base_config() -> Config {
    Config {
        bind: "127.0.0.1:8080".parse().unwrap(),
        db_path: PathBuf::from("data/scanner.db"),
        cache_dir: PathBuf::from("data/cache"),
        upstream_url: "https://pypi.org".parse().unwrap(),
        public_url: "http://localhost:8080".parse().unwrap(),
        scan_budget: Duration::from_secs(10),
        cache_ttl: Duration::from_secs(24 * 60 * 60),
        advisory_sync_interval: Duration::from_secs(60 * 60),
        advisory_source_url: "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
            .parse()
            .unwrap(),
        cve: CveLine {
            min_severity: 7.0,
            require_fix_available: false,
            unknown_severity: UnknownSeverity::Allow,
        },
        download: Default::default(),
        allowlist: Vec::new(),
        plugins: Vec::new(),
        max_concurrent_scans: None,
    }
}

/// Builds a full `AppState` against a fresh temp-file SQLite database. No
/// network call is ever made in these tests, so `Upstream`'s base URL is
/// never actually dialed.
fn app_state() -> (tempfile::TempDir, tempfile::TempDir, AppState) {
    let db_dir = tempfile::tempdir().expect("create db temp dir");
    let db = Db::open(&db_dir.path().join("scanner.db")).expect("open db");
    let cache_dir = tempfile::tempdir().expect("create cache temp dir");
    let artifact_cache = ArtifactCache::new(db.clone(), cache_dir.path().join("artifacts"))
        .expect("create artifact cache");
    let index_cache = IndexCache::new(db.clone());
    let upstream = Upstream::new(
        "https://example.invalid/simple/".parse().unwrap(),
        index_cache.clone(),
    )
    .expect("construct upstream");
    let ecosystem_upstream = Upstream::new(
        "https://example.invalid/simple/".parse().unwrap(),
        index_cache,
    )
    .expect("construct ecosystem upstream");
    let verdict_store = VerdictStore::new(db.clone());
    let advisory_store = AdvisoryStore::new(db.clone());
    let plugin_runner = PluginRunner::new(Arc::new(NeverCalledSandbox));
    let cfg = base_config();
    let policy = Policy::build(Arc::new(cfg.clone())).expect("build policy");
    let config_handle = Arc::new(ConfigHandle::new(cfg));

    let scanner = Scanner::new(
        VerdictStore::new(db.clone()),
        upstream,
        policy,
        advisory_store,
        plugin_runner,
        artifact_cache,
        Arc::clone(&config_handle),
    );

    let state = AppState {
        scanner: Arc::new(scanner),
        verdicts: Arc::new(verdict_store),
        config: config_handle,
        ecosystem: Arc::new(PyPi::new(Arc::new(ecosystem_upstream))),
    };

    (db_dir, cache_dir, state)
}

fn artifact_key() -> ArtifactKey {
    ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "demo-package".to_string(),
        version: "1.0.0".to_string(),
        filename: "demo_package-1.0.0-py3-none-any.whl".to_string(),
        sha256: "a".repeat(64),
    }
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    String::from_utf8(bytes.to_vec()).expect("response body is valid UTF-8")
}

// ---------------------------------------------------------------------------
// sanitize_phrase
// ---------------------------------------------------------------------------

#[test]
fn sanitize_strips_cr_and_lf() {
    // Genuinely hostile input: a plugin or advisory detail that tries to
    // smuggle a second header into the response via CRLF (HTTP response
    // splitting). The sanitized phrase must contain neither byte, not just
    // "look okay" by returning without panicking.
    let hostile = "blocked\r\nX-Evil: 1";
    let sanitized = sanitize_phrase(hostile);

    assert!(
        !sanitized.contains('\r') && !sanitized.contains('\n'),
        "sanitized phrase must contain no CR or LF, got {sanitized:?}"
    );
    assert!(
        sanitized.contains("X-Evil: 1"),
        "non-CRLF bytes around the injection attempt should survive, got {sanitized:?}"
    );
}

#[test]
fn sanitize_strips_non_ascii_and_control_bytes() {
    let input = "bad\u{0007}\u{001b}[31mtext\u{007f}\u{00e9}end";
    let sanitized = sanitize_phrase(input);

    assert!(sanitized.is_ascii(), "got {sanitized:?}");
    assert!(
        sanitized.chars().all(|c| (' '..='~').contains(&c)),
        "every surviving byte must be printable ASCII (0x20-0x7E), got {sanitized:?}"
    );
    assert_eq!(sanitized, "bad[31mtextend");
}

#[test]
fn sanitize_caps_length_at_120_bytes() {
    // 119 ASCII bytes, then a 2-byte UTF-8 character straddling the would-be
    // 120-byte cut point, then more ASCII. A naive implementation that
    // truncates the *raw* string to 120 bytes before filtering non-ASCII
    // would slice into the middle of that multi-byte character and panic.
    let mut input = "a".repeat(119);
    input.push('\u{00e9}'); // 'é', 2 bytes in UTF-8, non-ASCII
    input.push_str(&"b".repeat(50));

    let sanitized = sanitize_phrase(&input);

    assert!(
        sanitized.len() <= 120,
        "sanitized phrase must be capped at 120 bytes, got {} bytes",
        sanitized.len()
    );
    assert!(sanitized.is_ascii());
    // The non-ASCII 'é' is stripped entirely (not replaced), so the cap
    // lands on 120 plain 'a'/'b' bytes.
    assert_eq!(sanitized.len(), 120);
    assert_eq!(sanitized, "a".repeat(119) + "b");
}

// ---------------------------------------------------------------------------
// refusal_response / in_progress_response / unverifiable_response
// ---------------------------------------------------------------------------

fn reason_phrase_of(response: &axum::response::Response) -> String {
    let phrase = response
        .extensions()
        .get::<hyper::ext::ReasonPhrase>()
        .expect("response must carry a hyper::ext::ReasonPhrase");
    String::from_utf8(phrase.as_bytes().to_vec()).expect("reason phrase is valid UTF-8")
}

#[test]
fn refusal_response_is_403_with_code_and_why_url_in_reason_phrase() {
    let reason = RefusalReason {
        code: "cve:high".to_string(),
        detail: "CVE-2024-99999 (CVSS 9.8)".to_string(),
    };
    let response = refusal_response(&reason, Some("http://localhost:8080/why/abc123"));

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    let phrase = reason_phrase_of(&response);
    assert!(phrase.contains("cve:high"), "got {phrase:?}");
    assert!(
        phrase.contains("http://localhost:8080/why/abc123"),
        "got {phrase:?}"
    );
}

#[test]
fn refusal_response_phrase_survives_a_hostile_plugin_detail() {
    // RefusalReason.detail is documented as attacker-influenced (it flows
    // from plugin stdout and advisory summaries). The code can carry the
    // same kind of hostile content if a plugin names its own check code.
    let reason = RefusalReason {
        code: "blocked\r\nX-Evil: 1".to_string(),
        detail: "irrelevant".to_string(),
    };
    let response = refusal_response(&reason, Some("http://localhost:8080/why/abc123"));

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    let phrase = reason_phrase_of(&response);
    assert!(
        !phrase.contains('\r') && !phrase.contains('\n'),
        "a hostile code must never put CR or LF on the wire, got {phrase:?}"
    );
    assert!(phrase.is_ascii());
    assert!(phrase.len() <= 120);
}

#[test]
fn refusal_response_keeps_the_full_why_url_and_shortens_an_overlong_code() {
    // A long package name folded into the check code, plus a long
    // advisory identifier, plus a deep `public_url` path: a plausible
    // real-world combination where `code` + `why_url` together exceed
    // the 120-byte budget even though the URL alone fits comfortably.
    let long_package = "a".repeat(40);
    let long_advisory_id = format!("GHSA-{}", "x".repeat(80));
    let code = format!("cve:{long_package}:{long_advisory_id}");
    let why_url = format!("http://localhost:8080/why/{}", "c".repeat(60));

    const PREFIX_LEN: usize = "BLOCKED ".len();
    const SEP_LEN: usize = " - why ".len();

    // Sanity on the fixture itself: the URL alone must fit inside the
    // budget (otherwise this test would exercise the "drop the code
    // entirely" fallback, not the ellipsize-the-code path), but the URL
    // together with the unshortened code must not fit (otherwise this
    // test would not exercise truncation at all).
    assert!(
        PREFIX_LEN + SEP_LEN + why_url.len() <= 120,
        "fixture bug: the why_url must fit in the budget on its own"
    );
    assert!(
        PREFIX_LEN + SEP_LEN + why_url.len() + code.len() > 120,
        "fixture bug: code + why_url must exceed the budget to exercise truncation"
    );

    let reason = RefusalReason {
        code: code.clone(),
        detail: "irrelevant".to_string(),
    };
    let response = refusal_response(&reason, Some(&why_url));

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    let phrase = reason_phrase_of(&response);

    assert!(
        phrase.len() <= 120,
        "phrase must stay within the 120-byte budget, got {} bytes: {phrase:?}",
        phrase.len()
    );
    assert!(
        phrase.contains(&why_url),
        "the full, unmangled why URL must survive truncation, got {phrase:?}"
    );
    assert!(
        !phrase.contains(&code),
        "the overlong code must have been shortened, not fully retained: {phrase:?}"
    );
    assert!(
        phrase.contains("..."),
        "a shortened code should read as visibly incomplete, got {phrase:?}"
    );
}

#[test]
fn in_progress_response_is_429_so_pip_does_not_silently_retry() {
    let response = in_progress_response();

    assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    let phrase = reason_phrase_of(&response);
    assert!(!phrase.contains('\r') && !phrase.contains('\n'));
    assert!(phrase.is_ascii());
    assert!(phrase.len() <= 120);
}

#[test]
fn unverifiable_response_is_503_with_distinct_code() {
    let reason = RefusalReason {
        code: "unverifiable:upstream".to_string(),
        detail: "could not reach upstream".to_string(),
    };
    let response = unverifiable_response(&reason);

    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    let phrase = reason_phrase_of(&response);
    assert!(
        phrase.contains("UNVERIFIABLE"),
        "unverifiable must say UNVERIFIABLE, got {phrase:?}"
    );
    assert!(
        !phrase.contains("BLOCKED"),
        "unverifiable must never look like a block, got {phrase:?}"
    );
}

// ---------------------------------------------------------------------------
// /why/<id>
// ---------------------------------------------------------------------------

#[tokio::test]
async fn why_page_shows_check_code_detail_and_artifact() {
    let (_db_dir, _cache_dir, state) = app_state();
    let key = artifact_key();
    let reason = RefusalReason {
        code: "cve:high".to_string(),
        detail: "CVE-2024-12345, CVSS 9.1".to_string(),
    };
    let why_id = state
        .verdicts
        .put(&key, &Verdict::Blocked(reason.clone()), "fp")
        .expect("store verdict");

    let response = why_handler(State(state), Path(why_id)).await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = body_text(response).await;

    assert!(body.contains("cve:high"), "{body}");
    assert!(body.contains("CVE-2024-12345, CVSS 9.1"), "{body}");
    assert!(body.contains(&key.package), "{body}");
    assert!(body.contains(&key.version), "{body}");
    assert!(body.contains(&key.filename), "{body}");
    // Mentions what the org can actually do about it.
    assert!(
        body.to_lowercase().contains("allowlist"),
        "page must mention the allowlist remedy: {body}"
    );
}

#[tokio::test]
async fn why_page_escapes_html_in_stored_detail() {
    let (_db_dir, _cache_dir, state) = app_state();
    let key = artifact_key();
    let reason = RefusalReason {
        code: "plugin:yara".to_string(),
        detail: "<script>alert(document.cookie)</script>".to_string(),
    };
    let why_id = state
        .verdicts
        .put(&key, &Verdict::Blocked(reason), "fp")
        .expect("store verdict");

    let response = why_handler(State(state), Path(why_id)).await;
    let body = body_text(response).await;

    assert!(
        !body.contains("<script>"),
        "stored markup must not reach the page unescaped: {body}"
    );
    assert!(
        body.contains("&lt;script&gt;"),
        "stored markup must appear HTML-escaped: {body}"
    );
}

#[tokio::test]
async fn unknown_why_id_is_404() {
    let (_db_dir, _cache_dir, state) = app_state();

    let response = why_handler(State(state), Path("doesnotexist000".to_string())).await;
    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// The reason phrase actually on the wire (not just in `extensions()`)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refusal_reason_phrase_reaches_the_wire_over_real_http1() {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept connection");
        let io = TokioIo::new(stream);
        let reason = RefusalReason {
            code: "cve:high".to_string(),
            detail: "irrelevant".to_string(),
        };
        let service = service_fn(move |_req: hyper::Request<hyper::body::Incoming>| {
            let reason = reason.clone();
            async move {
                Ok::<_, Infallible>(refusal_response(
                    &reason,
                    Some("http://localhost:8080/why/wire-test-id"),
                ))
            }
        });
        http1::Builder::new()
            .serve_connection(io, service)
            .await
            .expect("serve one connection");
    });

    let mut client = TcpStream::connect(addr).await.expect("connect to server");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    let mut raw = Vec::new();
    client
        .read_to_end(&mut raw)
        .await
        .expect("read full response");
    server.await.expect("server task did not panic");

    let raw = String::from_utf8_lossy(&raw);
    let status_line = raw.lines().next().expect("response has a status line");

    assert!(
        status_line.starts_with("HTTP/1.1 403 "),
        "expected an HTTP/1.1 403 status line, got {status_line:?}"
    );
    assert!(
        status_line.contains("cve:high"),
        "the reason phrase on the wire must carry the check code, got {status_line:?}"
    );
    assert!(
        status_line.contains("wire-test-id"),
        "the reason phrase on the wire must carry the why URL, got {status_line:?}"
    );
    assert!(
        !status_line.contains('\r') && status_line.is_ascii(),
        "status line must be clean ASCII, got {status_line:?}"
    );
}

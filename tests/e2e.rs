//! End-to-end integration tests: the real axum router, built by
//! `supply_chain_scanner::http::bootstrap`, served on an ephemeral TCP
//! port, in front of a `wiremock` stand-in for upstream PyPI (and for the
//! OSV advisory feed). These are the tests that prove the twelve earlier
//! tasks actually compose into a working proxy, not just that each piece
//! works in isolation.
//!
//! Most tests use `reqwest` to talk to the server, since only the status
//! code and body matter. A few — anywhere the *reason phrase* on the
//! HTTP/1.1 status line is the thing under test — use [`raw_get`] instead,
//! a bare `TcpStream` client, because `reqwest` (like most HTTP client
//! libraries) does not surface a server's non-canonical reason phrase to
//! its caller; only the raw wire bytes reliably show what pip itself
//! would see.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use supply_chain_scanner::config::{AllowEntry, Config, CveLine, UnknownSeverity};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::http::{bootstrap, watch_for_reload, Wired};

// ---------------------------------------------------------------------------
// Fixtures and harness
// ---------------------------------------------------------------------------

/// A well-formed, minimal wheel: a zip with one file entry, enough for
/// `unpack` to accept it without any plugin needing to look past that.
fn build_wheel_bytes() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(cursor);
        let options = SimpleFileOptions::default();
        zip.start_file("demo/__init__.py", options)
            .expect("start zip entry");
        zip.write_all(b"VERSION = '1.0.0'\n")
            .expect("write zip entry contents");
        zip.finish().expect("finish zip fixture");
    }
    buf
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// An empty OSV feed zip (zero entries): enough for `OsvSync::sync_pypi`
/// to succeed with nothing to ingest, so tests that don't care about
/// advisories can mount it and never touch the real network.
fn empty_osv_zip() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let writer = ZipWriter::new(cursor);
        writer.finish().expect("finish empty zip");
    }
    buf
}

/// An OSV feed zip containing one advisory document for `package`, at
/// `version`, with `severity` (a bare numeric CVSS-equivalent score, the
/// form `severity_score` accepts directly).
fn osv_zip_with_one_advisory(id: &str, package: &str, version: &str, severity: f32) -> Vec<u8> {
    let doc = format!(
        r#"{{
            "id": "{id}",
            "summary": "a seeded blocking advisory",
            "severity": [{{"type": "CVSS_V3", "score": "{severity}"}}],
            "affected": [
                {{"package": {{"name": "{package}"}}, "versions": ["{version}"]}}
            ]
        }}"#
    );
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut writer = ZipWriter::new(cursor);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer.start_file("advisory-0.json", options).unwrap();
        writer.write_all(doc.as_bytes()).unwrap();
        writer.finish().unwrap();
    }
    buf
}

async fn mount_empty_osv_feed(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(empty_osv_zip()))
        .mount(server)
        .await;
}

/// A minimal, fully valid `Config` pointed at `server` for both the
/// upstream index/download endpoints and the OSV advisory feed, with
/// `public_url` set to this proxy's own (already-bound) address so a
/// rewritten `/files/...` or `/why/...` URL actually resolves against
/// the server under test.
fn base_config(
    server: &MockServer,
    public_url: Url,
    db_path: PathBuf,
    cache_dir: PathBuf,
) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        db_path,
        cache_dir,
        upstream_url: Url::parse(&server.uri()).expect("valid upstream url"),
        public_url,
        scan_budget: Duration::from_secs(10),
        cache_ttl: Duration::from_secs(60 * 60),
        advisory_sync_interval: Duration::from_secs(60 * 60),
        advisory_source_url: Url::parse(&format!("{}/all.zip", server.uri()))
            .expect("valid advisory url"),
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

/// Binds an ephemeral TCP listener, builds `config_fn(public_url)` against
/// it (so `public_url` already matches the port the server will serve
/// on), runs the fail-closed startup sequence, and spawns the server in
/// the background. Returns the base URL a test can issue requests
/// against, the socket address (for [`raw_get`]), and everything
/// [`bootstrap`] produced.
async fn start_server(
    config_fn: impl FnOnce(Url) -> Config,
) -> anyhow::Result<(Url, SocketAddr, Wired)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let base_url = Url::parse(&format!("http://127.0.0.1:{}/", addr.port()))?;

    let config = config_fn(base_url.clone());
    let wired = bootstrap(config).await?;

    let router = wired.router.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    Ok((base_url, addr, wired))
}

/// Seeds a blocking advisory directly into the mirror (bypassing any
/// sync), so a test can make one artifact scan-and-block without relying
/// on OSV feed fetch timing.
fn seed_blocking_advisory(db: &supply_chain_scanner::db::Db, package: &str, version: &str) {
    use supply_chain_scanner::advisory::Advisory;

    let store = AdvisoryStore::new(db.clone());
    store
        .replace_all(
            "pypi",
            &[Advisory {
                id: "TEST-BLOCK-1".to_string(),
                package: package.to_string(),
                summary: "seeded for test".to_string(),
                severity: Some(9.8),
                versions: vec![version.to_string()],
                ranges: vec![],
                fixed_versions: vec![],
            }],
        )
        .expect("seed blocking advisory");
}

/// Sends a bare HTTP/1.1 GET over a fresh `TcpStream`, with
/// `Connection: close`, and returns `(status_line, headers_and_body)` —
/// the one way to see a server's literal, non-canonical reason phrase,
/// which higher-level HTTP client crates (including `reqwest`) do not
/// surface to callers.
async fn raw_get(addr: SocketAddr, request_path: &str) -> (String, String) {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to test server");
    let request =
        format!("GET {request_path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write raw request");

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .expect("read raw response");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let mut parts = text.splitn(2, "\r\n");
    let status_line = parts.next().unwrap_or("").to_string();
    let rest = parts.next().unwrap_or("").to_string();
    (status_line, rest)
}

// ---------------------------------------------------------------------------
// Simple index
// ---------------------------------------------------------------------------

#[tokio::test]
async fn simple_page_is_served_and_rewrites_urls_to_the_proxy() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);
    let index_html = format!(
        r#"<!DOCTYPE html><html><body>
        <a href="{}/packages/{filename}#sha256={sha256}">{filename}</a>
        </body></html>"#,
        server.uri()
    );

    Mock::given(method("GET"))
        .and(path("/simple/demo-package/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index_html))
        .mount(&server)
        .await;

    let db_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let (base_url, _addr, _wired) = start_server(|public_url| {
        base_config(
            &server,
            public_url,
            db_dir.path().join("scanner.db"),
            cache_dir.path().join("cache"),
        )
    })
    .await
    .expect("start server");

    let response = reqwest::get(format!("{base_url}simple/demo-package/"))
        .await
        .expect("request simple index");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body_text = response.text().await.expect("read body");

    let expected_href = format!("{base_url}files/demo-package/1.0.0/{filename}#sha256={sha256}");
    assert!(
        body_text.contains(&expected_href),
        "expected rewritten href {expected_href:?} in body: {body_text}"
    );
    assert!(
        !body_text.contains(&server.uri()),
        "the upstream (wiremock) host must never leak into the rendered page: {body_text}"
    );
}

#[tokio::test]
async fn simple_page_omits_known_blocked_artifacts() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    let clean_filename = "demo_package-1.0.0-py3-none-any.whl";
    let blocked_filename = "demo_package-2.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    let index_html = format!(
        r#"<!DOCTYPE html><html><body>
        <a href="{uri}/packages/{clean_filename}#sha256={sha256}">{clean_filename}</a>
        <a href="{uri}/packages/{blocked_filename}#sha256={sha256}">{blocked_filename}</a>
        </body></html>"#,
        uri = server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/simple/demo-package/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index_html))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/packages/{blocked_filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let db_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let (base_url, _addr, wired) = start_server(|public_url| {
        base_config(
            &server,
            public_url,
            db_dir.path().join("scanner.db"),
            cache_dir.path().join("cache"),
        )
    })
    .await
    .expect("start server");

    seed_blocking_advisory(&wired.db, "demo-package", "2.0.0");

    // Trigger a real scan of the blocked artifact so a verdict is
    // actually stored: `blocked_filenames` only ever reflects stored
    // verdicts, never a live advisory lookup.
    let blocked_response = reqwest::get(format!(
        "{base_url}files/demo-package/2.0.0/{blocked_filename}"
    ))
    .await
    .expect("request blocked artifact");
    assert_eq!(blocked_response.status(), reqwest::StatusCode::FORBIDDEN);

    let response = reqwest::get(format!("{base_url}simple/demo-package/"))
        .await
        .expect("request simple index");
    let body_text = response.text().await.expect("read body");

    assert!(
        !body_text.contains(blocked_filename),
        "the blocked filename must be absent from the served page: {body_text}"
    );
    assert!(
        body_text.contains(clean_filename),
        "an unscanned, non-blocked filename must still be listed: {body_text}"
    );
}

#[tokio::test]
async fn simple_page_keeps_allowlisted_artifacts_visible() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    let blocked_filename = "demo_package-2.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    let index_html = format!(
        r#"<!DOCTYPE html><html><body>
        <a href="{uri}/packages/{blocked_filename}#sha256={sha256}">{blocked_filename}</a>
        </body></html>"#,
        uri = server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/simple/demo-package/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index_html))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/packages/{blocked_filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let db_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("scanner.db");
    let cache_path = cache_dir.path().join("cache");

    // First server: no allowlist. Scan and store a blocked verdict.
    let (base_url, _addr, wired) = start_server(|public_url| {
        base_config(&server, public_url, db_path.clone(), cache_path.clone())
    })
    .await
    .expect("start first server");
    seed_blocking_advisory(&wired.db, "demo-package", "2.0.0");
    let first = reqwest::get(format!(
        "{base_url}files/demo-package/2.0.0/{blocked_filename}"
    ))
    .await
    .expect("request artifact");
    assert_eq!(first.status(), reqwest::StatusCode::FORBIDDEN);

    // Second server: same database (so the stored blocked verdict
    // persists — the policy fingerprint is unaffected by the allowlist,
    // see `crate::policy`'s own docs), now with an allowlist entry for
    // this exact package and version.
    let (base_url_2, _addr2, _wired2) = start_server(|public_url| {
        let mut cfg = base_config(&server, public_url, db_path.clone(), cache_path.clone());
        cfg.allowlist = vec![AllowEntry {
            package: "demo-package".to_string(),
            version: "2.0.0".to_string(),
        }];
        cfg
    })
    .await
    .expect("start second server");

    let response = reqwest::get(format!("{base_url_2}simple/demo-package/"))
        .await
        .expect("request simple index");
    let body_text = response.text().await.expect("read body");

    assert!(
        body_text.contains(blocked_filename),
        "an allowlisted version must stay visible even though it was previously blocked: {body_text}"
    );
}

// ---------------------------------------------------------------------------
// Artifact download / refusal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pinned_blocked_artifact_returns_403_with_reason_phrase() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);
    let index_html = format!(
        r#"<!DOCTYPE html><html><body>
        <a href="{uri}/packages/{filename}#sha256={sha256}">{filename}</a>
        </body></html>"#,
        uri = server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/simple/demo-package/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index_html))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let db_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let (_base_url, addr, wired) = start_server(|public_url| {
        base_config(
            &server,
            public_url,
            db_dir.path().join("scanner.db"),
            cache_dir.path().join("cache"),
        )
    })
    .await
    .expect("start server");
    seed_blocking_advisory(&wired.db, "demo-package", "1.0.0");

    let (status_line, _rest) =
        raw_get(addr, &format!("/files/demo-package/1.0.0/{filename}")).await;

    assert!(
        status_line.contains("403"),
        "expected a 403 status line, got {status_line:?}"
    );
    assert!(
        status_line.contains("BLOCKED"),
        "the reason phrase must carry the BLOCKED marker: {status_line:?}"
    );
    assert!(
        status_line.contains("cve:TEST-BLOCK-1"),
        "the reason phrase must carry the refusal code: {status_line:?}"
    );
    assert!(
        status_line.contains("why "),
        "the reason phrase must link to a /why/<id> page: {status_line:?}"
    );

    // Extract the why URL from the phrase and confirm it actually
    // explains the block.
    let why_marker = "why ";
    let why_start = status_line.find(why_marker).expect("why marker present") + why_marker.len();
    let why_url = status_line[why_start..]
        .trim_end_matches(['\r', '\n'])
        .trim();
    let why_path = why_url
        .splitn(4, '/')
        .nth(3)
        .map(|p| format!("/{p}"))
        .expect("why url has a path");

    let (_why_status_line, why_body) = raw_get(addr, &why_path).await;
    assert!(
        why_body.contains("blocked") || why_body.contains("Blocked"),
        "the /why page must explain the block: {why_body}"
    );
}

#[tokio::test]
async fn clean_artifact_download_returns_bytes_with_matching_sha256() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);
    let index_html = format!(
        r#"<!DOCTYPE html><html><body>
        <a href="{uri}/packages/{filename}#sha256={sha256}">{filename}</a>
        </body></html>"#,
        uri = server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/simple/demo-package/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index_html))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let db_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let (base_url, _addr, _wired) = start_server(|public_url| {
        base_config(
            &server,
            public_url,
            db_dir.path().join("scanner.db"),
            cache_dir.path().join("cache"),
        )
    })
    .await
    .expect("start server");

    let response = reqwest::get(format!("{base_url}files/demo-package/1.0.0/{filename}"))
        .await
        .expect("request artifact");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let bytes = response.bytes().await.expect("read body");
    assert_eq!(sha256_hex(&bytes), sha256);
    assert_eq!(bytes.as_ref(), body.as_slice());
}

#[tokio::test]
async fn pep658_metadata_request_is_passed_through_without_scanning() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);
    let metadata_body = b"Metadata-Version: 2.1\nName: demo-package\n".to_vec();

    let index_html = format!(
        r#"<!DOCTYPE html><html><body>
        <a href="{uri}/packages/{filename}#sha256={sha256}" data-core-metadata="true">{filename}</a>
        </body></html>"#,
        uri = server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/simple/demo-package/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index_html))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}.metadata")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(metadata_body.clone()))
        .mount(&server)
        .await;
    // The real artifact download endpoint is intentionally left
    // unmounted-with-an-expectation-of-zero: a metadata request must
    // never trigger a scan, which would have to download the artifact
    // itself first.
    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .expect(0)
        .mount(&server)
        .await;

    let db_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let (base_url, _addr, wired) = start_server(|public_url| {
        base_config(
            &server,
            public_url,
            db_dir.path().join("scanner.db"),
            cache_dir.path().join("cache"),
        )
    })
    .await
    .expect("start server");

    let response = reqwest::get(format!(
        "{base_url}files/demo-package/1.0.0/{filename}.metadata"
    ))
    .await
    .expect("request metadata sidecar");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let bytes = response.bytes().await.expect("read body");
    assert_eq!(bytes.as_ref(), metadata_body.as_slice());

    server.verify().await;

    // Stronger proof that no scan ran at all: no verdict row exists for
    // this artifact under *any* policy fingerprint — a plain `get()`
    // lookup can't express "regardless of fingerprint", so this queries
    // the verdicts table directly.
    let conn = wired.db.conn().expect("open db connection");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM verdicts WHERE ecosystem = ?1 AND package = ?2 \
             AND version = ?3 AND filename = ?4 AND sha256 = ?5",
            rusqlite::params!["pypi", "demo-package", "1.0.0", filename, sha256],
            |row| row.get(0),
        )
        .expect("count verdict rows");
    assert_eq!(
        count, 0,
        "a .metadata request must never trigger a scan or store a verdict"
    );
}

#[tokio::test]
async fn invalid_package_name_in_path_is_400() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    let db_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let (base_url, addr, _wired) = start_server(|public_url| {
        base_config(
            &server,
            public_url,
            db_dir.path().join("scanner.db"),
            cache_dir.path().join("cache"),
        )
    })
    .await
    .expect("start server");

    // `..` is sent over a raw TCP connection (see [`raw_get`]), bypassing
    // `reqwest`/the `url` crate entirely: `.` is an RFC 3986 "unreserved"
    // character, so any URL-normalizing HTTP client (reqwest included)
    // unescapes `%2e` back to a literal `.` during parsing and then
    // collapses the resulting `../` dot-segment away before the request
    // is ever sent — which would prove this path never reaches the
    // server at all, not that the server rejects it. A misbehaving or
    // deliberately crafted client has no such scruples, so this is the
    // case that actually exercises `validate_package_name`'s traversal
    // check.
    let (status_line, _) = raw_get(addr, "/simple/../").await;
    assert!(
        status_line.contains("400"),
        "expected 400 for a raw '..' package segment, got {status_line:?}"
    );

    // "a%2Fb" (a slash smuggled inside one path segment) and "%C3%A9"
    // ("é", non-ASCII) are *reserved*/non-ASCII bytes that a conforming
    // URL client must not silently unescape, so `reqwest` delivers them
    // to the server exactly as encoded.
    for bad_segment in ["a%2Fb", "%C3%A9"] {
        let response = reqwest::get(format!("{base_url}simple/{bad_segment}/"))
            .await
            .expect("request simple index with a bad package name");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "expected 400 for package segment {bad_segment:?}"
        );
    }
}

#[tokio::test]
async fn filename_not_present_in_upstream_index_is_404() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    Mock::given(method("GET"))
        .and(path("/simple/demo-package/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<!DOCTYPE html><html><body></body></html>"),
        )
        .mount(&server)
        .await;

    let db_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let (base_url, _addr, _wired) = start_server(|public_url| {
        base_config(
            &server,
            public_url,
            db_dir.path().join("scanner.db"),
            cache_dir.path().join("cache"),
        )
    })
    .await
    .expect("start server");

    let response = reqwest::get(format!(
        "{base_url}files/demo-package/1.0.0/does-not-exist-1.0.0-py3-none-any.whl"
    ))
    .await
    .expect("request nonexistent artifact");
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unknown_route_is_404_and_healthz_is_200() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    let db_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let (base_url, _addr, _wired) = start_server(|public_url| {
        base_config(
            &server,
            public_url,
            db_dir.path().join("scanner.db"),
            cache_dir.path().join("cache"),
        )
    })
    .await
    .expect("start server");

    let healthz = reqwest::get(format!("{base_url}healthz"))
        .await
        .expect("request healthz");
    assert_eq!(healthz.status(), reqwest::StatusCode::OK);

    let unknown = reqwest::get(format!("{base_url}totally/unknown/route"))
        .await
        .expect("request unknown route");
    assert_eq!(unknown.status(), reqwest::StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

#[tokio::test]
async fn startup_syncs_advisories_when_the_mirror_is_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/all.zip"))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(osv_zip_with_one_advisory(
                "TEST-STARTUP-SYNC-1",
                "some-package",
                "1.0.0",
                9.0,
            )),
        )
        .mount(&server)
        .await;

    let db_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let public_url = Url::parse("http://127.0.0.1:1/").unwrap(); // unused by bootstrap itself
    let config = base_config(
        &server,
        public_url,
        db_dir.path().join("scanner.db"),
        cache_dir.path().join("cache"),
    );

    let wired = bootstrap(config).await.expect("bootstrap should succeed");

    let advisory_store = AdvisoryStore::new(wired.db.clone());
    let advisories = advisory_store
        .for_package("pypi", "some-package")
        .expect("lookup advisories");
    assert_eq!(
        advisories.len(),
        1,
        "the initial sync must have populated the mirror before bootstrap returned"
    );
    assert_eq!(advisories[0].id, "TEST-STARTUP-SYNC-1");
}

#[tokio::test]
async fn startup_fails_when_a_configured_plugin_has_no_sandbox_available() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    let db_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let plugin_dir = tempfile::tempdir().unwrap();
    let plugin_path = plugin_dir.path().join("some-plugin");
    std::fs::write(&plugin_path, b"pretend plugin binary").expect("write plugin binary");

    let mut config = base_config(
        &server,
        Url::parse("http://127.0.0.1:1/").unwrap(),
        db_dir.path().join("scanner.db"),
        cache_dir.path().join("cache"),
    );
    config.plugins = vec![supply_chain_scanner::config::PluginConfig {
        name: "some-plugin".to_string(),
        binary: plugin_path,
        timeout: Duration::from_secs(5),
    }];

    // Deliberately, narrowly hide `bwrap` from this one call by clearing
    // `PATH` for its duration: `bwrap` really is installed in this
    // environment (the task's own real-pip smoke check depends on it),
    // so this is the only way to exercise "no sandbox available" without
    // actually uninstalling anything. Restored immediately afterward via
    // the guard below, and no other test in this file configures
    // plugins, so no other test's sandbox detection can observe the gap.
    struct RestorePath(Option<std::ffi::OsString>);
    impl Drop for RestorePath {
        fn drop(&mut self) {
            match self.0.take() {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
        }
    }
    let _restore = RestorePath(std::env::var_os("PATH"));
    std::env::set_var("PATH", "");

    let result = bootstrap(config).await;
    assert!(
        result.is_err(),
        "bootstrap must fail closed when a plugin is configured but no sandbox is available"
    );
}

#[tokio::test]
async fn config_reload_signal_applies_a_new_allowlist_entry() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    let filename = "demo_package-3.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);
    let index_html = format!(
        r#"<!DOCTYPE html><html><body>
        <a href="{uri}/packages/{filename}#sha256={sha256}">{filename}</a>
        </body></html>"#,
        uri = server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/simple/demo-package/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index_html))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let db_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("scanner.db");
    let cache_path = cache_dir.path().join("cache");

    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("scanner.toml");
    write_config_toml(&config_path, &server, &db_path, &cache_path, &[]);

    let initial_config =
        Config::load(&config_path).expect("load the initial config file from disk");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://127.0.0.1:{}/", addr.port());

    let wired = bootstrap(initial_config)
        .await
        .expect("bootstrap should succeed");
    seed_blocking_advisory(&wired.db, "demo-package", "3.0.0");

    let router = wired.router.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    // Before the reload: the advisory blocks this version.
    let before = reqwest::get(format!("{base_url}files/demo-package/3.0.0/{filename}"))
        .await
        .expect("request artifact before reload");
    assert_eq!(before.status(), reqwest::StatusCode::FORBIDDEN);

    // Install the SIGHUP watcher, then rewrite the config file on disk
    // with a new allowlist entry, then signal this process.
    let reloader = std::sync::Arc::clone(&wired.reloader);
    let watcher_path = config_path.clone();
    tokio::spawn(async move {
        let _ = watch_for_reload(reloader, watcher_path).await;
    });
    // Give the spawned task a chance to actually run and register the
    // SIGHUP handler (via `tokio::signal::unix::signal`) before this
    // test raises the signal below — `tokio::spawn` only schedules the
    // task, it does not run it synchronously, and the OS default
    // disposition for SIGHUP (terminate the process) is still in effect
    // until that registration call actually executes.
    tokio::time::sleep(Duration::from_millis(100)).await;

    write_config_toml(
        &config_path,
        &server,
        &db_path,
        &cache_path,
        &[("demo-package", "3.0.0")],
    );

    // SAFETY: `raise` with a valid signal number and no shared memory
    // access; delivering SIGHUP to this process's own default handler
    // set is exactly what this test means to exercise. This test is the
    // only one in this crate that configures a SIGHUP watcher, so this
    // signal does not interact with any other running test.
    unsafe {
        libc::raise(libc::SIGHUP);
    }

    // The reload is asynchronous; poll briefly for it to take effect
    // rather than assuming a fixed delay is enough.
    let mut served = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if wired.state.config.current().allowlist.len() == 1 {
            served = true;
            break;
        }
    }
    assert!(
        served,
        "the SIGHUP handler must have reloaded the config with the new allowlist entry"
    );

    let after = reqwest::get(format!("{base_url}files/demo-package/3.0.0/{filename}"))
        .await
        .expect("request artifact after reload");
    assert_eq!(
        after.status(),
        reqwest::StatusCode::OK,
        "the newly allowlisted version must now be served despite the stored blocked verdict"
    );
    let bytes = after.bytes().await.expect("read body");
    assert_eq!(bytes.as_ref(), body.as_slice());
}

/// Writes a minimal, fully valid config TOML file to `path`, pointed at
/// `server` for upstream and the (empty) OSV feed, with `allowlist`
/// entries appended as `[[allowlist]]` tables.
fn write_config_toml(
    path: &std::path::Path,
    server: &MockServer,
    db_path: &std::path::Path,
    cache_dir: &std::path::Path,
    allowlist: &[(&str, &str)],
) {
    let advisory_url = format!("{}/all.zip", server.uri());
    let mut toml = format!(
        r#"
bind = "127.0.0.1:0"
db_path = "{db_path}"
cache_dir = "{cache_dir}"
upstream_url = "{upstream_url}"
public_url = "http://127.0.0.1:1/"
scan_budget = "10s"
cache_ttl = "1h"
advisory_sync_interval = "1h"
advisory_source_url = "{advisory_url}"

[cve]
min_severity = 7.0
require_fix_available = false
unknown_severity = "allow"
"#,
        db_path = db_path.display(),
        cache_dir = cache_dir.display(),
        upstream_url = server.uri(),
    );

    for (package, version) in allowlist {
        toml.push_str(&format!(
            "\n[[allowlist]]\npackage = \"{package}\"\nversion = \"{version}\"\n"
        ));
    }

    std::fs::write(path, toml).expect("write config toml");
}

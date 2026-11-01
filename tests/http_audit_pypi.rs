//! Integration tests for the fetch audit log on the PyPI artifact
//! download path (`GET /files/<package>/<version>/<filename>`).
//!
//! Every test drives the real router over real HTTP/1.1 on loopback,
//! against a `wiremock` stand-in for upstream PyPI, with the audit log
//! opened on a tempdir path. No plugin, AI reviewer, or advisory sync is
//! configured here — these tests are about *who gets logged for which
//! download*, not about the scan cascade that decides allow/refuse
//! (that is `tests/scan.rs`); a `refused` record is produced by seeding
//! a pinned `Verdict::Blocked` directly, the same shortcut
//! `tests/http_refusal.rs` uses for the same reason.

use std::io;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use url::Url;
use wiremock::matchers::{method, path as mock_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::audit::AuditLog;
use supply_chain_scanner::config::{
    AuditConfig, AuditRotation, Config, ConfigHandle, CveLine, UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::index_cache::IndexCache;
use supply_chain_scanner::db::review::ReviewStore;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::pypi::upstream::Upstream;
use supply_chain_scanner::ecosystem::pypi::PyPi;
use supply_chain_scanner::ecosystem::Ecosystem;
use supply_chain_scanner::http::{router, AppState};
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

/// A writer that always fails, so [`AuditLog::with_writer`] over it
/// proves the fail-closed path: a request whose audit record cannot be
/// written must 500, never serve bytes, and never read as a 403.
struct AlwaysFailingWriter;
impl io::Write for AlwaysFailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("audit disk is unavailable in this test"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("audit disk is unavailable in this test"))
    }
}

fn base_config() -> Config {
    Config {
        bind: "127.0.0.1:8080".parse().unwrap(),
        db_path: PathBuf::from("data/scanner.db"),
        cache_dir: PathBuf::from("data/cache"),
        upstream_url: "https://pypi.org/".parse().unwrap(),
        public_url: "http://proxy.example:8080".parse().unwrap(),
        scan_budget: std::time::Duration::from_secs(10),
        cache_ttl: std::time::Duration::from_secs(60 * 60),
        advisory_sync_interval: std::time::Duration::from_secs(60 * 60),
        advisory_source_url: "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
            .parse()
            .unwrap(),
        cve: CveLine {
            min_severity: 7.0,
            require_fix_available: false,
            unknown_severity: UnknownSeverity::Allow,
        },
        min_release_age_days: None,
        download: Default::default(),
        allowlist: Vec::new(),
        plugins: Vec::new(),
        max_concurrent_scans: None,
        ai_review: None,
        cargo_registry: None,
        npm_registry: None,
        // Unused by this file's harness: it builds `AppState` directly
        // rather than through `bootstrap`, so this value is never read.
        // Each test opens its own `AuditLog` over its own tempdir path
        // and passes it straight to `start`.
        audit: AuditConfig::default(),
    }
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

/// A trivial, valid zip: enough for the cascade's unpack step to accept
/// it without any plugin needing to look past that.
fn build_wheel_bytes() -> Vec<u8> {
    use std::io::Write as _;
    let mut buf = Vec::new();
    {
        let cursor = io::Cursor::new(&mut buf);
        let mut zip = zip::ZipWriter::new(cursor);
        zip.start_file("demo/__init__.py", zip::write::SimpleFileOptions::default())
            .expect("start zip entry");
        zip.write_all(b"VERSION = '1.0.0'\n")
            .expect("write zip entry");
        zip.finish().expect("finish zip fixture");
    }
    buf
}

/// Mounts a one-version package whose artifact is a servable, clean
/// wheel: the simple-index page, the artifact bytes, and the PEP
/// 658/714 `.metadata` sidecar. Returns the filename and its sha256.
async fn mount_clean_package(
    server: &MockServer,
    package: &str,
    version: &str,
) -> (String, String) {
    let filename = format!("{}-{version}-py3-none-any.whl", package.replace('-', "_"));
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);
    let index_html = format!(
        r#"<!DOCTYPE html><html><body>
        <a href="{uri}/packages/{filename}#sha256={sha256}">{filename}</a>
        </body></html>"#,
        uri = server.uri()
    );
    Mock::given(method("GET"))
        .and(mock_path(format!("/simple/{package}/")))
        .respond_with(ResponseTemplate::new(200).set_body_string(index_html))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(mock_path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(mock_path(format!("/packages/{filename}.metadata")))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(b"Metadata-Version: 2.1\n".to_vec()),
        )
        .mount(server)
        .await;
    (filename, sha256)
}

/// Mounts a one-version package's simple-index page, declaring a real
/// sha256, but mounts no artifact-bytes endpoint at all: enough for a
/// pinned `Verdict::Blocked` to be found and refused before any download
/// is ever attempted, and a download attempted anyway would fail the
/// test loudly (wiremock has no matching mock).
async fn mount_blockable_package(
    server: &MockServer,
    package: &str,
    version: &str,
) -> (String, String) {
    let filename = format!("{}-{version}-py3-none-any.whl", package.replace('-', "_"));
    let sha256 = "b".repeat(64);
    let index_html = format!(
        r#"<!DOCTYPE html><html><body>
        <a href="{uri}/packages/{filename}#sha256={sha256}">{filename}</a>
        </body></html>"#,
        uri = server.uri()
    );
    Mock::given(method("GET"))
        .and(mock_path(format!("/simple/{package}/")))
        .respond_with(ResponseTemplate::new(200).set_body_string(index_html))
        .mount(server)
        .await;
    (filename, sha256)
}

/// Reads every audit line written so far, across however many rotated
/// files that turned out to be (these tests never cross a rotation
/// boundary, so there is only ever one), in file-name order.
fn read_audit_lines(dir: &FsPath, prefix: &str) -> Vec<serde_json::Value> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read audit directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
        .collect();
    paths.sort();

    let mut lines = Vec::new();
    for path in paths {
        let contents = std::fs::read_to_string(&path).expect("read audit file");
        for line in contents.lines() {
            if !line.trim().is_empty() {
                lines.push(serde_json::from_str(line).expect("audit line is valid JSON"));
            }
        }
    }
    lines
}

struct Harness {
    _db_dir: tempfile::TempDir,
    _cache_dir: tempfile::TempDir,
    server: MockServer,
    scanner: Arc<Scanner>,
    verdicts: Arc<VerdictStore>,
    addr: SocketAddr,
}

/// Builds the real PyPI router, with `audit` wired into its `AppState`,
/// served over real HTTP/1.1 on an ephemeral loopback port via
/// `into_make_service_with_connect_info`, exactly as `main.rs`'s `serve`
/// does — without that, `ConnectInfo<SocketAddr>` extraction in
/// `artifact_handler` fails on every request.
async fn start(audit: Arc<AuditLog>) -> Harness {
    let server = MockServer::start().await;

    let db_dir = tempfile::tempdir().expect("create db temp dir");
    let cache_dir = tempfile::tempdir().expect("create cache temp dir");
    let db = Db::open(&db_dir.path().join("scanner.db")).expect("open db");

    let cfg = base_config();
    let base = Url::parse(&format!("{}/simple/", server.uri())).expect("valid base url");
    let upstream =
        Upstream::new(base.clone(), IndexCache::new(db.clone())).expect("construct upstream");
    let ecosystem_upstream = Arc::new(
        Upstream::new(base, IndexCache::new(db.clone())).expect("construct ecosystem upstream"),
    );
    let artifact_cache = ArtifactCache::new(db.clone(), cache_dir.path().join("artifacts"))
        .expect("create artifact cache");
    let policy = Policy::build(Arc::new(cfg.clone())).expect("build policy");
    let config_handle = Arc::new(ConfigHandle::new(cfg));

    let scanner = Arc::new(Scanner::new(
        VerdictStore::new(db.clone()),
        upstream,
        policy,
        AdvisoryStore::new(db.clone()),
        PluginRunner::new(Arc::new(NeverCalledSandbox)),
        artifact_cache,
        Arc::clone(&config_handle),
        None,
    ));

    let pypi: Arc<dyn Ecosystem> = Arc::new(PyPi::new(Arc::clone(&ecosystem_upstream)));
    let verdicts = Arc::new(VerdictStore::new(db.clone()));
    let state = AppState {
        scanner: Arc::clone(&scanner),
        verdicts: Arc::clone(&verdicts),
        reviews: Arc::new(ReviewStore::new(db.clone())),
        config: config_handle,
        ecosystem: pypi,
        audit,
    };

    let app = router(state, ecosystem_upstream);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    Harness {
        _db_dir: db_dir,
        _cache_dir: cache_dir,
        server,
        scanner,
        verdicts,
        addr,
    }
}

fn audit_log_over_tempdir() -> (tempfile::TempDir, Arc<AuditLog>) {
    let dir = tempfile::tempdir().expect("create audit temp dir");
    let config = AuditConfig {
        path: dir.path().join("audit.jsonl"),
        rotation: AuditRotation::Daily,
        max_files: 14,
    };
    let log = Arc::new(AuditLog::open(&config).expect("open audit log"));
    (dir, log)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_served_artifact_writes_a_served_line_naming_the_client_ip() {
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(audit).await;
    let (filename, _sha256) =
        mount_clean_package(&harness.server, "example-package", "1.0.0").await;

    let response = reqwest::get(format!(
        "http://{}/files/example-package/1.0.0/{filename}",
        harness.addr
    ))
    .await
    .expect("request artifact");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "served")
        .expect("a served record was written");
    assert_eq!(record["event"], "served");
    assert_eq!(record["ecosystem"], "pypi");
    assert_eq!(record["client_ip"], "127.0.0.1");
    assert_eq!(record["package"], "example-package");
}

#[tokio::test]
async fn a_refused_artifact_writes_a_refused_line_with_the_stored_reason() {
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(audit).await;
    let (filename, sha256) =
        mount_blockable_package(&harness.server, "blocked-package", "2.0.0").await;

    let key = ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "blocked-package".to_string(),
        version: "2.0.0".to_string(),
        filename: filename.clone(),
        sha256,
    };
    let reason = RefusalReason {
        code: "plugin:yara".to_string(),
        detail: "yara matched a known malware signature".to_string(),
    };
    let fingerprint = harness.scanner.fingerprint();
    harness
        .verdicts
        .put(&key, &Verdict::Blocked(reason), &fingerprint)
        .expect("seed pinned blocked verdict");

    let response = reqwest::get(format!(
        "http://{}/files/blocked-package/2.0.0/{filename}",
        harness.addr
    ))
    .await
    .expect("request artifact");
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "refused")
        .expect("a refused record was written");
    assert_eq!(record["event"], "refused");
    assert_eq!(record["reason_code"], "plugin:yara");
    assert!(record["why_id"].is_string());
}

#[tokio::test]
async fn the_metadata_sidecar_writes_no_audit_line() {
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(audit).await;
    let (filename, _sha256) =
        mount_clean_package(&harness.server, "example-package", "1.0.0").await;

    let response = reqwest::get(format!(
        "http://{}/files/example-package/1.0.0/{filename}.metadata",
        harness.addr
    ))
    .await
    .expect("request metadata sidecar");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    assert_eq!(lines.len(), 0);
}

#[tokio::test]
async fn healthz_writes_no_audit_line() {
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(audit).await;

    let response = reqwest::get(format!("http://{}/healthz", harness.addr))
        .await
        .expect("request healthz");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    assert_eq!(lines.len(), 0);
}

#[tokio::test]
async fn no_open_route_renders_a_client_ip() {
    let (_audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(audit).await;

    let (served_filename, _sha256) =
        mount_clean_package(&harness.server, "example-package", "1.0.0").await;
    let served_response = reqwest::get(format!(
        "http://{}/files/example-package/1.0.0/{served_filename}",
        harness.addr
    ))
    .await
    .expect("request clean artifact");
    assert_eq!(served_response.status(), reqwest::StatusCode::OK);

    let (blocked_filename, blocked_sha256) =
        mount_blockable_package(&harness.server, "blocked-package", "2.0.0").await;
    let key = ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "blocked-package".to_string(),
        version: "2.0.0".to_string(),
        filename: blocked_filename.clone(),
        sha256: blocked_sha256,
    };
    let reason = RefusalReason {
        code: "plugin:yara".to_string(),
        detail: "yara matched a known malware signature".to_string(),
    };
    let fingerprint = harness.scanner.fingerprint();
    let why_id = harness
        .verdicts
        .put(&key, &Verdict::Blocked(reason), &fingerprint)
        .expect("seed pinned blocked verdict");
    let blocked_response = reqwest::get(format!(
        "http://{}/files/blocked-package/2.0.0/{blocked_filename}",
        harness.addr
    ))
    .await
    .expect("request blocked artifact");
    assert_eq!(blocked_response.status(), reqwest::StatusCode::FORBIDDEN);

    let refusals = reqwest::get(format!("http://{}/refusals", harness.addr))
        .await
        .expect("request /refusals")
        .text()
        .await
        .expect("read /refusals body");
    let why = reqwest::get(format!("http://{}/why/{why_id}", harness.addr))
        .await
        .expect("request /why/<id>")
        .text()
        .await
        .expect("read /why/<id> body");
    let reviews = reqwest::get(format!("http://{}/api/reviews", harness.addr))
        .await
        .expect("request /api/reviews")
        .text()
        .await
        .expect("read /api/reviews body");

    for body in [refusals, why, reviews] {
        assert!(
            !body.contains("127.0.0.1"),
            "a route leaked a client address: {body}"
        );
    }
}

#[tokio::test]
async fn a_spoofed_x_forwarded_for_header_is_ignored() {
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(audit).await;
    let (filename, _sha256) =
        mount_clean_package(&harness.server, "example-package", "1.0.0").await;

    let response = reqwest::Client::new()
        .get(format!(
            "http://{}/files/example-package/1.0.0/{filename}",
            harness.addr
        ))
        .header("X-Forwarded-For", "203.0.113.9")
        .send()
        .await
        .expect("request artifact with a spoofed X-Forwarded-For header");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "served")
        .expect("a served record was written");
    assert_eq!(
        record["client_ip"], "127.0.0.1",
        "the header must never reach the log"
    );
}

#[tokio::test]
async fn a_failed_audit_write_returns_500_and_no_artifact_bytes() {
    let audit = Arc::new(AuditLog::with_writer(AlwaysFailingWriter));
    let harness = start(audit).await;
    let (filename, _sha256) =
        mount_clean_package(&harness.server, "example-package", "1.0.0").await;

    let response = reqwest::get(format!(
        "http://{}/files/example-package/1.0.0/{filename}",
        harness.addr
    ))
    .await
    .expect("request artifact");
    let status = response.status();
    let body = response.bytes().await.expect("read response body");

    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.is_empty(), "no artifact bytes may be served: {body:?}");
    assert_ne!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "a write failure must not read as a refusal"
    );
}

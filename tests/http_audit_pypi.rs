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
    AiReviewConfig, AllowEntry, AuditConfig, AuditRotation, BlockOn, Config, ConfigHandle, CveLine,
    UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::index_cache::IndexCache;
use supply_chain_scanner::db::review::{NewReview, ReviewStore};
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

/// Mounts a one-version package's simple-index page for an *sdist*
/// filename (`<package>-<version>.tar.gz`, hyphenated exactly as the
/// package name itself), declaring a real sha256 but no artifact-bytes
/// endpoint — the listing audit tests only ever request `/simple/...`,
/// never the artifact itself, through this fixture.
async fn mount_blockable_sdist(
    server: &MockServer,
    package: &str,
    version: &str,
) -> (String, String) {
    let filename = format!("{package}-{version}.tar.gz");
    let sha256 = "c".repeat(64);
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

/// Mounts a `count`-entry simple-index page for `package`, one wheel per
/// version `1.0.0, 2.0.0, ...`, each declaring a real (but arbitrary)
/// sha256. No artifact-bytes endpoint is mounted: these entries are only
/// ever used to drive the `/simple/...` listing audit, never a download.
/// Returns each entry's filename, in the same order they appear on the
/// page.
async fn mount_multi_version_package(
    server: &MockServer,
    package: &str,
    count: usize,
) -> Vec<String> {
    let underscored = package.replace('-', "_");
    let filenames: Vec<String> = (1..=count)
        .map(|n| format!("{underscored}-{n}.0.0-py3-none-any.whl"))
        .collect();
    let links: String = filenames
        .iter()
        .map(|filename| {
            let sha256 = sha256_hex(filename.as_bytes());
            format!(
                r#"<a href="{uri}/packages/{filename}#sha256={sha256}">{filename}</a>"#,
                uri = server.uri()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let index_html = format!("<!DOCTYPE html><html><body>{links}</body></html>");
    Mock::given(method("GET"))
        .and(mock_path(format!("/simple/{package}/")))
        .respond_with(ResponseTemplate::new(200).set_body_string(index_html))
        .mount(server)
        .await;
    filenames
}

/// Mounts a one-entry simple-index page whose `<a href>` declares no
/// `#sha256=...` fragment at all — [`crate::ecosystem::pypi::index`]
/// parses that as `IndexEntry::sha256 == None`, which is the only way to
/// reach `artifact_handler`'s `no_hash_reason` / `Unverifiable` path.
async fn mount_package_with_no_declared_hash(
    server: &MockServer,
    package: &str,
    version: &str,
) -> String {
    let filename = format!("{}-{version}-py3-none-any.whl", package.replace('-', "_"));
    let index_html = format!(
        r#"<!DOCTYPE html><html><body>
        <a href="{uri}/packages/{filename}">{filename}</a>
        </body></html>"#,
        uri = server.uri()
    );
    Mock::given(method("GET"))
        .and(mock_path(format!("/simple/{package}/")))
        .respond_with(ResponseTemplate::new(200).set_body_string(index_html))
        .mount(server)
        .await;
    filename
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
    reviews: Arc<ReviewStore>,
    addr: SocketAddr,
}

/// Builds the real PyPI router, with `audit` wired into its `AppState`,
/// served over real HTTP/1.1 on an ephemeral loopback port via
/// `into_make_service_with_connect_info`, exactly as `main.rs`'s `serve`
/// does — without that, `ConnectInfo<SocketAddr>` extraction in
/// `artifact_handler` fails on every request.
///
/// `cfg` is the base `Config` this run boots from, so tests that need a
/// non-default allowlist (or any other config knob) can pass their own
/// mutated copy of [`base_config`] in rather than this harness only ever
/// offering one shape of config.
async fn start(cfg: Config, audit: Arc<AuditLog>) -> Harness {
    let server = MockServer::start().await;

    let db_dir = tempfile::tempdir().expect("create db temp dir");
    let cache_dir = tempfile::tempdir().expect("create cache temp dir");
    let db = Db::open(&db_dir.path().join("scanner.db")).expect("open db");

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
    let reviews = Arc::new(ReviewStore::new(db.clone()));
    let state = AppState {
        scanner: Arc::clone(&scanner),
        verdicts: Arc::clone(&verdicts),
        reviews: Arc::clone(&reviews),
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
        reviews,
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
    let harness = start(base_config(), audit).await;
    let (filename, sha256) = mount_clean_package(&harness.server, "example-package", "1.0.0").await;

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
    // Regression protection: the argument order into `AuditRecord::served`
    // was hand-verified as correct, but nothing pinned it. A served line
    // must name the exact version, filename and hash the artifact was
    // served under, not just that *a* served line was written.
    assert_eq!(record["version"], "1.0.0");
    assert_eq!(record["filename"], filename);
    assert_eq!(record["sha256"], sha256);
}

#[tokio::test]
async fn a_refused_artifact_writes_a_refused_line_with_the_stored_reason() {
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(base_config(), audit).await;
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
    let harness = start(base_config(), audit).await;
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
    let harness = start(base_config(), audit).await;

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
    // `/api/reviews` 404s outright when `ai_review` is unset (see
    // `reviews_handler`), which would make its leg of this test pass for
    // the wrong reason — the route never renders, not "it renders and
    // leaks nothing". Configuring it (no real reviewer is ever built or
    // called here) lets the planted review row below actually reach the
    // response this test inspects.
    let mut cfg = base_config();
    cfg.ai_review = Some(AiReviewConfig {
        enabled: true,
        base_url: "http://127.0.0.1:9/chat/".parse().unwrap(),
        model: "test-model".to_string(),
        api_key_env: None,
        timeout: std::time::Duration::from_secs(5),
        max_payload_bytes: 262_144,
        max_output_tokens: 256,
        coverage_threshold: 0.8,
        block_on: BlockOn::Malicious,
        block_opaque_executables: false,
    });
    let harness = start(cfg, audit).await;

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

    // Plant a review row too, so `/api/reviews` is checked against a real
    // row exactly as `/refusals` and `/why/<id>` are above — an empty
    // listing never had a chance to leak a client address, so it was not
    // actually exercising this route's own rendering.
    harness
        .reviews
        .put(&NewReview {
            key: key.clone(),
            fingerprint: fingerprint.clone(),
            verdict: "malicious",
            blocked: true,
            summary: "the model judged this package malicious".to_string(),
            findings_json: "[]".to_string(),
            coverage: Some(1.0),
            reviewable_bytes_total: 100,
            reviewable_bytes_sent: 100,
            opaque_json: "{}".to_string(),
            reviewed_paths_json: "[]".to_string(),
            model: "test-model".to_string(),
            prompt_version: "1",
            collector_version: "1".to_string(),
        })
        .expect("seed review row");

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
    assert!(
        reviews.contains("malicious"),
        "the seeded review row must actually render, or this route was never \
         exercised against real content: {reviews}"
    );

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
    let harness = start(base_config(), audit).await;
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
    let serialized = serde_json::to_string(record).expect("serialize record for the spoof check");
    assert!(
        !serialized.contains("203.0.113.9"),
        "the spoofed address must not appear anywhere in the record, not just \
         be absent from client_ip: {serialized}"
    );
}

#[tokio::test]
async fn a_failed_audit_write_returns_500_and_no_artifact_bytes() {
    let audit = Arc::new(AuditLog::with_writer(AlwaysFailingWriter));
    let harness = start(base_config(), audit).await;
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

// ---------------------------------------------------------------------------
// Decisions that never reach the scan cascade write no audit line at all
// ---------------------------------------------------------------------------

/// `Decision::Unverifiable` (here, an index entry with no declared hash,
/// which `artifact_handler` catches before `Scanner::decide` is ever
/// called) and `Decision::InProgress` both short-circuit before any
/// fetch verdict exists to describe — there is nothing yet for an audit
/// line to report, so neither may write one. This pins the
/// `no_hash_reason` half of that pair: a 503, and zero audit lines.
#[tokio::test]
async fn an_artifact_with_no_declared_hash_is_unverifiable_and_writes_no_audit_line() {
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(base_config(), audit).await;
    let filename =
        mount_package_with_no_declared_hash(&harness.server, "no-hash-package", "1.0.0").await;

    let response = reqwest::get(format!(
        "http://{}/files/no-hash-package/1.0.0/{filename}",
        harness.addr
    ))
    .await
    .expect("request artifact with no declared hash");
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    assert_eq!(
        lines.len(),
        0,
        "an unverifiable request with no verdict ever reached must write no \
         audit line: {lines:?}"
    );
}

// ---------------------------------------------------------------------------
// PyPI index listing events (`listing` / `listed`)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_simple_page_writes_a_listing_line_counting_evaluated_of_upstream() {
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(base_config(), audit).await;
    let filenames = mount_multi_version_package(&harness.server, "multi-version-package", 5).await;

    // Seed stored verdicts for exactly two of the five upstream entries —
    // one clean, one blocked — so most of the page stays "never
    // evaluated", which is the normal PyPI shape this test exists to pin.
    let fingerprint = harness.scanner.fingerprint();
    let clean_key = ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "multi-version-package".to_string(),
        version: "1.0.0".to_string(),
        filename: filenames[0].clone(),
        sha256: sha256_hex(filenames[0].as_bytes()),
    };
    harness
        .verdicts
        .put(&clean_key, &Verdict::Clean, &fingerprint)
        .expect("seed clean verdict");
    let blocked_key = ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "multi-version-package".to_string(),
        version: "2.0.0".to_string(),
        filename: filenames[1].clone(),
        sha256: sha256_hex(filenames[1].as_bytes()),
    };
    let reason = RefusalReason {
        code: "plugin:yara".to_string(),
        detail: "yara matched a known malware signature".to_string(),
    };
    harness
        .verdicts
        .put(&blocked_key, &Verdict::Blocked(reason), &fingerprint)
        .expect("seed blocked verdict");

    let response = reqwest::get(format!(
        "http://{}/simple/multi-version-package/",
        harness.addr
    ))
    .await
    .expect("request simple index");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let listing = lines
        .iter()
        .find(|line| line["event"] == "listing")
        .expect("a listing record was written");
    assert_eq!(listing["event"], "listing");
    assert_eq!(listing["package"], "multi-version-package");
    assert_eq!(listing["versions_upstream"], 5);
    assert_eq!(listing["versions_evaluated"], 2);

    let listed: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|line| line["event"] == "listed")
        .collect();
    assert_eq!(listed.len(), 2, "unscanned entries get no verdict line");
}

#[tokio::test]
async fn a_blocked_entry_is_a_denied_line_naming_its_version_and_filename() {
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(base_config(), audit).await;
    let (filename, sha256) =
        mount_blockable_sdist(&harness.server, "example-package", "1.0.0").await;

    let key = ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "example-package".to_string(),
        version: "1.0.0".to_string(),
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

    let response = reqwest::get(format!("http://{}/simple/example-package/", harness.addr))
        .await
        .expect("request simple index");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let denied = lines
        .iter()
        .find(|line| line["event"] == "listed" && line["decision"] == "denied")
        .expect("a denied listed record was written");
    assert_eq!(denied["decision"], "denied");
    assert_eq!(denied["version"], "1.0.0");
    assert_eq!(denied["filename"], "example-package-1.0.0.tar.gz");
    assert_eq!(denied["reason_code"], "plugin:yara");
}

/// A blocked-but-allowlisted entry stays visible on the rendered page (as
/// it does today), but its audit line must not read as an ordinary pass:
/// the scan itself found something, and the allowlist only overrode the
/// *serving* decision, not the finding. It is logged `allowed` with
/// `reason_code: "allowlisted"` so a reader of the log can tell this
/// apart from a version that was simply clean.
#[tokio::test]
async fn an_allowlisted_blocked_entry_is_an_allowed_line_coded_allowlisted() {
    let (audit_dir, audit) = audit_log_over_tempdir();
    let mut cfg = base_config();
    cfg.allowlist = vec![AllowEntry {
        package: "example-package".to_string(),
        version: "1.0.0".to_string(),
    }];
    let harness = start(cfg, audit).await;
    let (filename, sha256) =
        mount_blockable_sdist(&harness.server, "example-package", "1.0.0").await;

    let key = ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "example-package".to_string(),
        version: "1.0.0".to_string(),
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

    let response = reqwest::get(format!("http://{}/simple/example-package/", harness.addr))
        .await
        .expect("request simple index");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.expect("read simple index body");
    assert!(
        body.contains(&filename),
        "an allowlisted blocked entry must stay visible on the page: {body}"
    );

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "listed")
        .expect("a listed record was written");
    assert_eq!(record["decision"], "allowed");
    assert_eq!(record["reason_code"], "allowlisted");
}

#[tokio::test]
async fn a_failed_audit_write_on_a_simple_page_returns_500_and_no_index_html() {
    let audit = Arc::new(AuditLog::with_writer(AlwaysFailingWriter));
    let harness = start(base_config(), audit).await;
    mount_clean_package(&harness.server, "example-package", "1.0.0").await;

    let response = reqwest::get(format!("http://{}/simple/example-package/", harness.addr))
        .await
        .expect("request simple index");
    let status = response.status();
    let body = response.text().await.expect("read response body");

    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.contains("<a href"), "no index may be served: {body}");
}

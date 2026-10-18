//! Integration tests for what this proxy tells its operator.
//!
//! Before these, the entire `tracing` inventory was four startup lines,
//! two ticker results, three `warn!`s and one `debug!`. Nothing in the
//! serving path was logged: no record of a refusal, no record of a blocked
//! verdict, and — most seriously — no record of a **hash mismatch**, whose
//! computed expected/actual digests reached nobody at all (the refusal is
//! never persisted, so there is no `/why` page for it either). An
//! organization being fed tampered bytes got zero signal, and no
//! organization could measure its own refusal rate, which is the only way
//! anyone notices the false-positive anti-goal firing.
//!
//! These tests install a global `tracing` subscriber writing into a shared
//! buffer. That is a per-process resource, which is exactly why this is
//! its own test binary.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use sha2::{Digest, Sha256};
use url::Url;
use wiremock::matchers::{method, path as mock_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use supply_chain_scanner::advisory::Advisory;
use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::config::{Config, ConfigHandle, CveLine, UnknownSeverity};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::index_cache::IndexCache;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::pypi::index::IndexEntry;
use supply_chain_scanner::ecosystem::pypi::upstream::Upstream;
use supply_chain_scanner::ecosystem::pypi::PyPi;
use supply_chain_scanner::ecosystem::Ecosystem;
use supply_chain_scanner::http::{router, AppState};
use supply_chain_scanner::model::ArtifactKey;
use supply_chain_scanner::plugin::{PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec};
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::Scanner;

// ---------------------------------------------------------------------------
// Captured log output
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = CapturedLog;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Installs the global subscriber exactly once and returns the buffer every
/// test in this binary shares. Tests assert on substrings, so sharing one
/// buffer across them is harmless.
fn log_buffer() -> &'static Arc<Mutex<Vec<u8>>> {
    static BUFFER: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    BUFFER.get_or_init(|| {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(CapturedLog(Arc::clone(&buffer)))
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("this binary installs the global subscriber exactly once");
        buffer
    })
}

fn logged() -> String {
    String::from_utf8_lossy(&log_buffer().lock().unwrap()).into_owned()
}

/// Polls the captured log for `needle`, since a detached scan task may log
/// after `decide` has already returned to its caller.
async fn wait_for_log(needle: &str) -> String {
    for _ in 0..100 {
        let text = logged();
        if text.contains(needle) {
            return text;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    logged()
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct NeverCalledSandbox;
impl SandboxRunner for NeverCalledSandbox {
    fn run(&self, _spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        panic!("no plugins are configured in these tests");
    }
}

fn base_config() -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        db_path: PathBuf::from("data/scanner.db"),
        cache_dir: PathBuf::from("data/cache"),
        upstream_url: "https://pypi.org".parse().unwrap(),
        public_url: "http://localhost:8080/".parse().unwrap(),
        scan_budget: Duration::from_secs(12),
        cache_ttl: Duration::from_secs(60 * 60),
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
        ai_review: None,
    }
}

struct Harness {
    _db_dir: tempfile::TempDir,
    _cache_dir: tempfile::TempDir,
    db: Db,
    scanner: Arc<Scanner>,
    state: AppState,
    ecosystem_upstream: Arc<Upstream>,
}

fn build_harness(server: &MockServer) -> Harness {
    log_buffer();

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
    let state = AppState {
        scanner: Arc::clone(&scanner),
        verdicts: Arc::new(VerdictStore::new(db.clone())),
        config: config_handle,
        ecosystem: pypi,
    };

    Harness {
        _db_dir: db_dir,
        _cache_dir: cache_dir,
        db,
        scanner,
        state,
        ecosystem_upstream,
    }
}

fn build_wheel_bytes() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = zip::ZipWriter::new(cursor);
        zip.start_file("demo/__init__.py", zip::write::SimpleFileOptions::default())
            .expect("start zip entry");
        zip.write_all(b"VERSION = '1.0.0'\n")
            .expect("write zip entry");
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

fn key_for(sha256: &str, filename: &str) -> ArtifactKey {
    ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "demo-package".to_string(),
        version: "1.0.0".to_string(),
        filename: filename.to_string(),
        sha256: sha256.to_string(),
    }
}

fn entry_for(server: &MockServer, filename: &str, sha256: &str) -> IndexEntry {
    IndexEntry {
        filename: filename.to_string(),
        url: Url::parse(&format!("{}/packages/{filename}", server.uri())).expect("valid url"),
        sha256: Some(sha256.to_string()),
        requires_python: None,
        metadata_hash: None,
        yanked: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The most security-significant event this system can detect must reach
/// an operator, with both digests. There is no `/why` page for a hash
/// mismatch (it is deliberately not persisted, since it may be transient
/// transfer corruption), so this log line is the only place the computed
/// hashes exist at all.
#[tokio::test]
async fn a_hash_mismatch_is_logged_at_error_with_both_digests() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let served = b"these are not the bytes the index promised".to_vec();
    let declared = sha256_hex(&build_wheel_bytes());
    let actual = sha256_hex(&served);

    Mock::given(method("GET"))
        .and(mock_path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(served))
        .mount(&server)
        .await;

    let harness = build_harness(&server);
    let key = key_for(&declared, filename);
    let entry = entry_for(&server, filename, &declared);

    let _ = harness.scanner.decide(&key, &entry).await;

    let text = wait_for_log("HASH MISMATCH").await;
    assert!(
        text.contains("HASH MISMATCH"),
        "a hash mismatch must be logged; log was:\n{text}"
    );
    assert!(
        text.contains("ERROR"),
        "a hash mismatch must be logged at error level; log was:\n{text}"
    );
    assert!(
        text.contains(&declared) && text.contains(&actual),
        "both the expected and the actual digest must appear; log was:\n{text}"
    );
    assert!(
        text.contains("demo-package") && text.contains(filename),
        "the log must identify which artifact; log was:\n{text}"
    );
}

/// Every refusal is logged with enough identity to act on, and with
/// "blocked" distinguishable from "could not check" — the same distinction
/// the HTTP status codes make.
#[tokio::test]
async fn a_blocked_verdict_is_logged_with_code_package_version_and_filename() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(mock_path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let harness = build_harness(&server);
    AdvisoryStore::new(harness.db.clone())
        .replace_all(
            "pypi",
            &[Advisory {
                id: "TEST-LOG-1".to_string(),
                package: "demo-package".to_string(),
                summary: "seeded for the logging test".to_string(),
                severity: Some(9.8),
                versions: vec!["1.0.0".to_string()],
                ranges: vec![],
                fixed_versions: vec![],
            }],
        )
        .expect("seed advisory");

    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, &sha256);
    let _ = harness.scanner.decide(&key, &entry).await;

    let text = wait_for_log("artifact was checked and blocked").await;
    assert!(
        text.contains("artifact was checked and blocked"),
        "a blocked verdict must be logged; log was:\n{text}"
    );
    assert!(
        text.contains("package=demo-package")
            && text.contains("version=1.0.0")
            && text.contains(filename),
        "the refusal log must carry package, version and filename; log was:\n{text}"
    );
    assert!(
        text.contains("code=cve"),
        "the refusal log must name the check that refused; log was:\n{text}"
    );
}

/// An unverifiable outcome must say "could not be checked", never
/// "blocked": an organization measuring its refusal rate has to be able to
/// tell a false positive from an outage.
#[tokio::test]
async fn an_unverifiable_outcome_is_logged_as_could_not_check_not_as_blocked() {
    let server = MockServer::start().await;
    let filename = "demo_package-2.0.0-py3-none-any.whl";
    let harness = build_harness(&server);

    // No declared hash at all: nothing to verify against, so this can
    // never be scanned honestly.
    let key = key_for(&"b".repeat(64), filename);
    let entry = IndexEntry {
        filename: filename.to_string(),
        url: Url::parse(&format!("{}/packages/{filename}", server.uri())).unwrap(),
        sha256: None,
        requires_python: None,
        metadata_hash: None,
        yanked: None,
    };

    let _ = harness.scanner.decide(&key, &entry).await;

    let text = wait_for_log("artifact could not be checked").await;
    assert!(
        text.contains("artifact could not be checked"),
        "an unverifiable outcome must be logged as such; log was:\n{text}"
    );
    assert!(
        text.contains("code=unverifiable:no-hash"),
        "the log must name why it could not be checked; log was:\n{text}"
    );
}

/// There was no record a request had even happened, so no organization
/// could measure its refusal rate. The access log is also where a 404 or a
/// 400 — neither of which produces a scan decision — becomes visible.
#[tokio::test]
async fn every_request_produces_an_access_log_line_with_its_status() {
    let server = MockServer::start().await;
    let harness = build_harness(&server);

    let app = router(
        harness.state.clone(),
        Arc::clone(&harness.ecosystem_upstream),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let response = reqwest::get(format!("http://{addr}/why/no-such-verdict"))
        .await
        .expect("request the why page");
    let status = response.status().as_u16();

    let text = wait_for_log("/why/no-such-verdict").await;
    assert!(
        text.contains("path=/why/no-such-verdict"),
        "the request path must be logged; log was:\n{text}"
    );
    assert!(
        text.contains(&format!("status={status}")),
        "the response status must be logged; log was:\n{text}"
    );
    assert!(
        text.contains("method=GET") && text.contains("elapsed_ms="),
        "the access log must carry the method and the latency; log was:\n{text}"
    );

    // Keep the scanner handle alive for the duration of the served
    // request, so this reads as intentional rather than an unused field.
    assert!(!harness.scanner.fingerprint().is_empty());
}

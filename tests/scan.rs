//! Integration tests for `supply_chain_scanner::scan`: the decision path
//! that composes every earlier task into the single place that decides
//! whether an artifact may be served.
//!
//! Each test builds a full [`Scanner`] against a real (temp-file) SQLite
//! database, a `wiremock` stand-in for upstream PyPI, and a scripted fake
//! [`SandboxRunner`] (the same style of fake `tests/plugin.rs` uses) so
//! plugin behavior is deterministic and independent of `bwrap`.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use supply_chain_scanner::advisory::Advisory;
use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::config::{
    AllowEntry, Config, ConfigHandle, CveLine, PluginConfig, UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::index_cache::IndexCache;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::pypi::index::IndexEntry;
use supply_chain_scanner::ecosystem::pypi::upstream::Upstream;
use supply_chain_scanner::model::{ArtifactKey, RefusalReason, Verdict};
use supply_chain_scanner::plugin::{PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec};
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::{Decision, Scanner};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

/// A minimal, fully valid `Config` with no plugins, no advisories source
/// of its own, and no allowlist entries. Individual tests clone and
/// mutate the fields they care about.
fn base_config(scan_budget: Duration) -> Config {
    Config {
        bind: "127.0.0.1:8080".parse().unwrap(),
        db_path: PathBuf::from("data/scanner.db"),
        cache_dir: PathBuf::from("data/cache"),
        upstream_url: "https://pypi.org".parse().unwrap(),
        public_url: "http://localhost:8080".parse().unwrap(),
        scan_budget,
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
        ai_review: None,
    }
}

/// Builds a well-formed, minimal wheel's raw bytes: a zip with one file
/// entry, enough for `unpack` to accept it without any plugin needing to
/// look past that.
fn build_wheel_bytes() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("demo/__init__.py", options)
            .expect("start zip entry");
        zip.write_all(b"VERSION = '1.0.0'\n")
            .expect("write zip entry contents");
        zip.finish().expect("finish zip fixture");
    }
    buf
}

/// A wheel carrying one entry that escapes `dest` via a `..` component —
/// the kind of deliberate attack N3's regression test needs, as opposed to
/// [`build_wheel_bytes`]'s ordinary well-formed contents.
fn build_wheel_bytes_with_traversal_entry() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("../escape.txt", options)
            .expect("start zip entry");
        zip.write_all(b"pwned\n").expect("write zip entry contents");
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

fn entry_for(server: &MockServer, filename: &str, sha256: Option<&str>) -> IndexEntry {
    let url = Url::parse(&format!("{}/packages/{filename}", server.uri())).expect("valid url");
    IndexEntry {
        filename: filename.to_string(),
        url,
        sha256: sha256.map(|s| s.to_string()),
        requires_python: None,
        metadata_hash: None,
        yanked: None,
    }
}

/// A deterministic [`SandboxRunner`]: records every spec it is handed and
/// replays a scripted outcome (or error) keyed by plugin binary path.
/// Mirrors the fake in `tests/plugin.rs`, but keyed by owned `PathBuf`
/// rather than `&'static str`, since these tests build plugin binaries
/// under a fresh temp directory each run.
struct FakeSandbox {
    scripted: HashMap<PathBuf, Result<SandboxOutcome, String>>,
    calls: Mutex<Vec<SandboxSpec>>,
}

impl FakeSandbox {
    fn new<I, P>(scripted: I) -> Arc<Self>
    where
        I: IntoIterator<Item = (P, Result<SandboxOutcome, String>)>,
        P: Into<PathBuf>,
    {
        Arc::new(Self {
            scripted: scripted.into_iter().map(|(b, o)| (b.into(), o)).collect(),
            calls: Mutex::new(Vec::new()),
        })
    }

    /// No plugins are expected to run at all.
    fn empty() -> Arc<Self> {
        Arc::new(Self {
            scripted: HashMap::new(),
            calls: Mutex::new(Vec::new()),
        })
    }
}

impl SandboxRunner for FakeSandbox {
    fn run(&self, spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        self.calls.lock().unwrap().push(spec.clone());
        match self.scripted.get(&spec.binary) {
            Some(Ok(outcome)) => Ok(outcome.clone()),
            Some(Err(message)) => Err(anyhow::anyhow!(message.clone())),
            None => panic!(
                "fake sandbox was asked to run an unscripted binary: {}",
                spec.binary.display()
            ),
        }
    }
}

/// A `SandboxRunner` that records the highest number of concurrent
/// invocations it ever observed, by sleeping for `delay` on every call
/// between incrementing and decrementing a shared counter. Safe to block
/// synchronously here: `PluginRunner::run_one` always calls
/// `SandboxRunner::run` inside `tokio::task::spawn_blocking`.
struct ConcurrencyTrackingSandbox {
    current: Arc<AtomicUsize>,
    max_seen: Arc<AtomicUsize>,
    delay: Duration,
}

impl ConcurrencyTrackingSandbox {
    fn new(current: Arc<AtomicUsize>, max_seen: Arc<AtomicUsize>, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            current,
            max_seen,
            delay,
        })
    }
}

impl SandboxRunner for ConcurrencyTrackingSandbox {
    fn run(&self, _spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_seen.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.current.fetch_sub(1, Ordering::SeqCst);
        Ok(exited(0, "clean\n"))
    }
}

fn exited(code: i32, output: &str) -> SandboxOutcome {
    SandboxOutcome {
        exit_code: Some(code),
        output: output.to_string(),
        timed_out: false,
        signal: None,
    }
}

/// Everything one test needs to drive a [`Scanner`] plus the raw stores
/// to assert against directly, bypassing the scanner's own decision path.
struct Harness {
    _db_dir: tempfile::TempDir,
    cache_dir: tempfile::TempDir,
    db: Db,
    scanner: Scanner,
    verdict_store: VerdictStore,
    advisory_store: AdvisoryStore,
    fingerprint: String,
}

/// Builds a `Scanner` (and the policy fingerprint it was built under)
/// against an already-open `db` and `cache_root`, so a test can build a
/// *second* scanner sharing the same durable state under a different
/// policy (see `policy_fingerprint_change_triggers_a_rescan`).
fn scanner_from(
    cfg: Config,
    server: &MockServer,
    sandbox: Arc<dyn SandboxRunner>,
    db: Db,
    cache_root: PathBuf,
) -> (Scanner, String) {
    let artifact_cache = ArtifactCache::new(db.clone(), cache_root).expect("create artifact cache");
    let index_cache = IndexCache::new(db.clone());
    let base = Url::parse(&format!("{}/simple/", server.uri())).expect("valid base url");
    let upstream = Upstream::new(base, index_cache).expect("construct upstream");
    let verdict_store = VerdictStore::new(db.clone());
    let advisory_store = AdvisoryStore::new(db.clone());
    let plugin_runner = PluginRunner::new(sandbox);
    let policy = Policy::build(Arc::new(cfg.clone())).expect("build policy");
    let fingerprint = policy.fingerprint().to_string();
    let config_handle = Arc::new(ConfigHandle::new(cfg));

    let scanner = Scanner::new(
        verdict_store,
        upstream,
        policy,
        advisory_store,
        plugin_runner,
        artifact_cache,
        config_handle,
    );
    (scanner, fingerprint)
}

fn build_harness(cfg: Config, server: &MockServer, sandbox: Arc<dyn SandboxRunner>) -> Harness {
    let (db_dir, db) = open_db();
    let cache_dir = tempfile::tempdir().expect("create cache temp dir");
    let (scanner, fingerprint) = scanner_from(
        cfg,
        server,
        sandbox,
        db.clone(),
        cache_dir.path().join("artifacts"),
    );

    Harness {
        _db_dir: db_dir,
        cache_dir,
        verdict_store: VerdictStore::new(db.clone()),
        advisory_store: AdvisoryStore::new(db.clone()),
        db,
        scanner,
        fingerprint,
    }
}

fn blocking_advisory(id: &str, package: &str, version: &str, severity: f32) -> Advisory {
    Advisory {
        id: id.to_string(),
        package: package.to_string(),
        summary: "a blocking advisory".to_string(),
        severity: Some(severity),
        versions: vec![version.to_string()],
        ranges: vec![],
        fixed_versions: vec![],
    }
}

fn blocked_reason(code: &str) -> RefusalReason {
    RefusalReason {
        code: code.to_string(),
        detail: "pre-seeded for the test".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clean_artifact_is_served_and_verdict_stored() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
    );
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    let decision = harness.scanner.decide(&key, &entry).await;

    match decision {
        Decision::Serve(served_path) => {
            assert_eq!(std::fs::read(&served_path).expect("read served file"), body);
        }
        other => panic!("expected Serve, got {other:?}"),
    }

    let stored = harness
        .verdict_store
        .get(&key, &harness.fingerprint)
        .expect("query verdict")
        .expect("a clean scan must store its verdict");
    assert_eq!(stored.verdict, Verdict::Clean);
}

#[tokio::test]
async fn blocking_advisory_refuses_before_any_download() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let sha256 = "a".repeat(64);

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(build_wheel_bytes()))
        .expect(0)
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
    );
    harness
        .advisory_store
        .replace_all(
            "pypi",
            &[blocking_advisory("OSV-1", "demo-package", "1.0.0", 9.0)],
        )
        .expect("seed blocking advisory");

    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    let decision = harness.scanner.decide(&key, &entry).await;
    match decision {
        Decision::Refuse { reason, why_id } => {
            assert_eq!(reason.code, "cve:OSV-1");
            assert!(
                why_id.is_some(),
                "an advisory block must be a stored verdict"
            );
        }
        other => panic!("expected Refuse, got {other:?}"),
    }

    server.verify().await;
}

#[tokio::test]
async fn hash_mismatch_refuses_with_hash_mismatch_code() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let declared_sha256 = "f".repeat(64); // not the real hash of `body`

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
    );
    let key = key_for(&declared_sha256, filename);
    let entry = entry_for(&server, filename, Some(&declared_sha256));

    let decision = harness.scanner.decide(&key, &entry).await;
    match decision {
        Decision::Refuse { reason, why_id } => {
            assert_eq!(reason.code, "hash-mismatch");
            assert!(
                why_id.is_none(),
                "a hash mismatch must not be persisted as a stored verdict"
            );
        }
        other => panic!("expected Refuse, got {other:?}"),
    }

    assert!(
        harness
            .verdict_store
            .get(&key, &harness.fingerprint)
            .expect("query verdict")
            .is_none(),
        "a hash mismatch must never be stored"
    );
}

#[tokio::test]
async fn entry_without_declared_hash_is_unverifiable_and_never_served() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(build_wheel_bytes()))
        .expect(0)
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
    );
    let key = key_for(&"0".repeat(64), filename);
    let entry = entry_for(&server, filename, None);

    let decision = harness.scanner.decide(&key, &entry).await;
    match decision {
        Decision::Unverifiable(reason) => assert_eq!(reason.code, "unverifiable:no-hash"),
        other => panic!("expected Unverifiable, got {other:?}"),
    }

    server.verify().await;
}

#[tokio::test]
async fn failing_plugin_refuses_and_stores_the_blocked_verdict() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let plugin_dir = tempfile::tempdir().expect("create plugin temp dir");
    let plugin_path = plugin_dir.path().join("strict-plugin");
    std::fs::write(&plugin_path, b"pretend plugin binary").expect("write plugin binary");

    let mut cfg = base_config(Duration::from_secs(12));
    cfg.plugins = vec![PluginConfig {
        name: "strict".to_string(),
        binary: plugin_path.clone(),
        timeout: Duration::from_secs(5),
    }];
    let sandbox = FakeSandbox::new([(plugin_path, Ok(exited(1, "malware found\n")))]);

    let harness = build_harness(cfg, &server, sandbox);
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    let decision = harness.scanner.decide(&key, &entry).await;
    match decision {
        Decision::Refuse { reason, why_id } => {
            assert_eq!(reason.code, "plugin:strict");
            assert!(why_id.is_some());
        }
        other => panic!("expected Refuse, got {other:?}"),
    }

    let stored = harness
        .verdict_store
        .get(&key, &harness.fingerprint)
        .expect("query verdict")
        .expect("a plugin block must store its verdict");
    assert!(matches!(stored.verdict, Verdict::Blocked(_)));
}

#[tokio::test]
async fn stored_blocked_verdict_refuses_without_contacting_upstream() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let sha256 = sha256_hex(&build_wheel_bytes());

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(build_wheel_bytes()))
        .expect(0)
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
    );
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    harness
        .verdict_store
        .put(
            &key,
            &Verdict::Blocked(blocked_reason("plugin:yara")),
            &harness.fingerprint,
        )
        .expect("seed blocked verdict");

    let decision = harness.scanner.decide(&key, &entry).await;
    match decision {
        Decision::Refuse { reason, why_id } => {
            assert_eq!(reason.code, "plugin:yara");
            assert!(why_id.is_some());
        }
        other => panic!("expected Refuse, got {other:?}"),
    }

    server.verify().await;
}

#[tokio::test]
async fn stored_clean_verdict_refuses_when_a_new_advisory_appeared() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let sha256 = sha256_hex(&build_wheel_bytes());

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(build_wheel_bytes()))
        .expect(0)
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
    );
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    harness
        .verdict_store
        .put(&key, &Verdict::Clean, &harness.fingerprint)
        .expect("seed clean verdict");
    harness
        .advisory_store
        .replace_all(
            "pypi",
            &[blocking_advisory("OSV-2", "demo-package", "1.0.0", 8.0)],
        )
        .expect("seed newly-appeared advisory");

    let decision = harness.scanner.decide(&key, &entry).await;
    match decision {
        Decision::Refuse { reason, why_id } => {
            assert_eq!(reason.code, "cve:OSV-2");
            assert!(why_id.is_some());
        }
        other => panic!("expected Refuse, got {other:?}"),
    }

    let stored = harness
        .verdict_store
        .get(&key, &harness.fingerprint)
        .expect("query verdict")
        .expect("the re-check must update the stored verdict");
    assert!(matches!(stored.verdict, Verdict::Blocked(_)));

    server.verify().await;
}

#[tokio::test]
async fn allowlisted_package_is_served_despite_stored_blocked_verdict() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let mut cfg = base_config(Duration::from_secs(12));
    cfg.allowlist = vec![AllowEntry {
        package: "demo-package".to_string(),
        version: "1.0.0".to_string(),
    }];
    let harness = build_harness(cfg, &server, FakeSandbox::empty());
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    harness
        .verdict_store
        .put(
            &key,
            &Verdict::Blocked(blocked_reason("plugin:yara")),
            &harness.fingerprint,
        )
        .expect("seed blocked verdict");

    let decision = harness.scanner.decide(&key, &entry).await;
    match decision {
        Decision::Serve(served_path) => {
            assert_eq!(std::fs::read(&served_path).expect("read served file"), body);
        }
        other => panic!("expected the allowlist to override the stored block, got {other:?}"),
    }
}

#[tokio::test]
async fn allowlisted_package_with_hash_mismatch_is_still_refused() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let declared_sha256 = "b".repeat(64); // not the real hash of `body`

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let mut cfg = base_config(Duration::from_secs(12));
    cfg.allowlist = vec![AllowEntry {
        package: "demo-package".to_string(),
        version: "1.0.0".to_string(),
    }];
    let harness = build_harness(cfg, &server, FakeSandbox::empty());
    let key = key_for(&declared_sha256, filename);
    let entry = entry_for(&server, filename, Some(&declared_sha256));

    let decision = harness.scanner.decide(&key, &entry).await;
    match decision {
        Decision::Refuse { reason, .. } => assert_eq!(reason.code, "hash-mismatch"),
        other => panic!("allowlisting must never bypass hash verification, got {other:?}"),
    }
}

#[tokio::test]
async fn policy_fingerprint_change_triggers_a_rescan() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let (_db_dir, db) = open_db();
    let cache_dir = tempfile::tempdir().expect("create cache temp dir");
    let cache_root = cache_dir.path().join("artifacts");
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    // Policy A: no plugins, scans clean.
    let (scanner_a, _fp_a) = scanner_from(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
        db.clone(),
        cache_root.clone(),
    );
    let decision_a = scanner_a.decide(&key, &entry).await;
    assert!(
        matches!(decision_a, Decision::Serve(_)),
        "policy A must scan clean: {decision_a:?}"
    );

    // Policy B: adds a plugin that always blocks. Its fingerprint differs
    // from A's, so the stored clean verdict (under A's fingerprint) must
    // not be reused.
    let plugin_dir = tempfile::tempdir().expect("create plugin temp dir");
    let plugin_path = plugin_dir.path().join("new-plugin");
    std::fs::write(&plugin_path, b"new plugin binary").expect("write plugin binary");
    let mut cfg_b = base_config(Duration::from_secs(12));
    cfg_b.plugins = vec![PluginConfig {
        name: "new-plugin".to_string(),
        binary: plugin_path.clone(),
        timeout: Duration::from_secs(5),
    }];
    let sandbox_b = FakeSandbox::new([(plugin_path, Ok(exited(1, "now blocked\n")))]);

    let (scanner_b, _fp_b) = scanner_from(cfg_b, &server, sandbox_b, db.clone(), cache_root);
    let decision_b = scanner_b.decide(&key, &entry).await;
    match decision_b {
        Decision::Refuse { reason, why_id } => {
            assert_eq!(reason.code, "plugin:new-plugin");
            assert!(why_id.is_some());
        }
        other => {
            panic!("a fingerprint change must force a rescan under the new policy, got {other:?}")
        }
    }
}

#[tokio::test]
async fn scan_exceeding_budget_returns_in_progress_then_stores_a_verdict() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    // The delay is well past the budget below, so the owning scan cannot
    // finish before the caller's timeout elapses.
    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(body)
                .set_delay(Duration::from_millis(150)),
        )
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_millis(20)),
        &server,
        FakeSandbox::empty(),
    );
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    let decision = harness.scanner.decide(&key, &entry).await;
    assert_eq!(decision, Decision::InProgress);

    // The budget timeout must not have cancelled the scan: give the
    // detached task time to finish and store its verdict on its own.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let stored = harness
        .verdict_store
        .get(&key, &harness.fingerprint)
        .expect("query verdict")
        .expect("the detached scan must have stored a verdict after InProgress was returned");
    assert_eq!(stored.verdict, Verdict::Clean);
}

#[tokio::test]
async fn concurrent_requests_for_same_artifact_download_once() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(body.clone())
                .set_delay(Duration::from_millis(50)),
        )
        .expect(1)
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
    );
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    let (first, second) = tokio::join!(
        harness.scanner.decide(&key, &entry),
        harness.scanner.decide(&key, &entry)
    );

    for decision in [first, second] {
        match decision {
            Decision::Serve(served_path) => {
                assert_eq!(std::fs::read(&served_path).expect("read served file"), body);
            }
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    server.verify().await;
}

/// Regression test for the full-scan concurrency bound: each full scan
/// holds a `spawn_blocking` slot for the whole of a plugin's timeout
/// (plus further OS threads for the sandbox run), and that same blocking
/// pool serves every SQLite call this crate makes, so an unbounded
/// number of concurrent full scans can starve ordinary verdict lookups
/// under a parallel dependency resolution or a pip retry storm.
///
/// `max_concurrent_scans = Some(1)` bounds the scanner to one full scan
/// at a time. Two *different* artifacts (so the single-flight
/// coordinator, keyed by sha256, never merges them into one scan) are
/// requested concurrently; the `ConcurrencyTrackingSandbox` records the
/// highest number of simultaneous plugin invocations it ever saw, which
/// can only exceed 1 if two full scans ran at once.
#[tokio::test]
async fn full_scans_beyond_the_configured_limit_queue_rather_than_run_concurrently() {
    let server = MockServer::start().await;

    let filename_a = "demo_package_a-1.0.0-py3-none-any.whl";
    let filename_b = "demo_package_b-1.0.0-py3-none-any.whl";
    let body_a = build_wheel_bytes();
    let mut body_b = build_wheel_bytes();
    body_b.extend_from_slice(b"extra-padding-so-this-hashes-differently");
    let sha256_a = sha256_hex(&body_a);
    let sha256_b = sha256_hex(&body_b);
    assert_ne!(
        sha256_a, sha256_b,
        "the two artifacts must differ so the single-flight coordinator \
         (keyed by sha256) does not merge them into one scan"
    );

    for (filename, body) in [(filename_a, body_a.clone()), (filename_b, body_b.clone())] {
        Mock::given(method("GET"))
            .and(path(format!("/packages/{filename}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;
    }

    let plugin_dir = tempfile::tempdir().expect("create plugin temp dir");
    let plugin_path = plugin_dir.path().join("tracking-plugin");
    std::fs::write(&plugin_path, b"pretend plugin binary").expect("write plugin binary");

    let mut cfg = base_config(Duration::from_secs(5));
    cfg.plugins = vec![PluginConfig {
        name: "tracking".to_string(),
        binary: plugin_path.clone(),
        timeout: Duration::from_secs(5),
    }];
    cfg.max_concurrent_scans = Some(1);

    let current = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let sandbox = ConcurrencyTrackingSandbox::new(
        Arc::clone(&current),
        Arc::clone(&max_seen),
        Duration::from_millis(150),
    );

    let harness = build_harness(cfg, &server, sandbox);

    let key_a = key_for(&sha256_a, filename_a);
    let entry_a = entry_for(&server, filename_a, Some(&sha256_a));
    let key_b = key_for(&sha256_b, filename_b);
    let entry_b = entry_for(&server, filename_b, Some(&sha256_b));

    let started = std::time::Instant::now();
    let (first, second) = tokio::join!(
        harness.scanner.decide(&key_a, &entry_a),
        harness.scanner.decide(&key_b, &entry_b)
    );
    let elapsed = started.elapsed();

    for decision in [first, second] {
        match decision {
            Decision::Serve(_) => {}
            other => panic!(
                "a request that had to queue for a scan slot must still resolve \
                 to a correct decision, not a spurious refusal, got {other:?}"
            ),
        }
    }

    assert_eq!(
        max_seen.load(Ordering::SeqCst),
        1,
        "the configured limit of 1 concurrent full scan must never be \
         exceeded, even for two unrelated artifacts requested at the same \
         time"
    );
    assert!(
        elapsed >= Duration::from_millis(280),
        "two 150ms scans serialized by a one-slot limit must take roughly \
         300ms end to end (proving they ran one after another, not \
         concurrently); took {elapsed:?}"
    );
}

#[tokio::test]
async fn unreachable_upstream_for_unscanned_artifact_is_unverifiable() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let sha256 = sha256_hex(&build_wheel_bytes());

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
    );
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    let decision = harness.scanner.decide(&key, &entry).await;
    match decision {
        Decision::Unverifiable(reason) => assert_eq!(reason.code, "unverifiable:upstream"),
        other => panic!("expected Unverifiable, got {other:?}"),
    }

    assert!(
        harness
            .verdict_store
            .get(&key, &harness.fingerprint)
            .expect("query verdict")
            .is_none(),
        "an upstream outage must never produce a stored verdict"
    );
}

#[tokio::test]
async fn unreachable_upstream_for_cached_clean_artifact_still_serves() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(503))
        .expect(0)
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
    );
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    harness
        .verdict_store
        .put(&key, &Verdict::Clean, &harness.fingerprint)
        .expect("seed clean verdict");

    // Pre-warm the artifact cache directly, simulating "already known
    // and cached from an earlier, successful scan."
    let source_dir = tempfile::tempdir().expect("create cache source temp dir");
    let source_file = source_dir.path().join(filename);
    std::fs::write(&source_file, &body).expect("write cache source file");
    let artifact_cache = ArtifactCache::new(
        harness.db.clone(),
        harness.cache_dir.path().join("artifacts"),
    )
    .expect("open artifact cache");
    artifact_cache
        .insert(&key, &source_file)
        .expect("pre-warm artifact cache");

    let decision = harness.scanner.decide(&key, &entry).await;
    match decision {
        Decision::Serve(served_path) => {
            assert_eq!(std::fs::read(&served_path).expect("read served file"), body);
        }
        other => panic!(
            "an outage must not block serving an already-known-clean, cached artifact: {other:?}"
        ),
    }

    server.verify().await;
}

#[tokio::test]
async fn served_bytes_come_from_cache_on_the_second_request() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .expect(1)
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
    );
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    let first = harness.scanner.decide(&key, &entry).await;
    assert!(
        matches!(first, Decision::Serve(_)),
        "first request must scan and serve: {first:?}"
    );

    let second = harness.scanner.decide(&key, &entry).await;
    assert!(
        matches!(second, Decision::Serve(_)),
        "second request must still serve: {second:?}"
    );

    // Exactly one download: the second request's verdict is clean and
    // already cached, so it must never touch upstream again.
    server.verify().await;
}

#[tokio::test]
async fn allowlisted_package_behind_a_slow_upstream_returns_in_progress_within_budget() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    // The delay is well past the budget below, so the allowlist path's
    // fetch cannot finish before `decide()`'s own timeout elapses.
    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(body.clone())
                .set_delay(Duration::from_millis(150)),
        )
        .mount(&server)
        .await;

    let mut cfg = base_config(Duration::from_millis(20));
    cfg.allowlist = vec![AllowEntry {
        package: "demo-package".to_string(),
        version: "1.0.0".to_string(),
    }];
    let harness = build_harness(cfg, &server, FakeSandbox::empty());
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    let started = std::time::Instant::now();
    let decision = harness.scanner.decide(&key, &entry).await;
    let elapsed = started.elapsed();

    assert_eq!(
        decision,
        Decision::InProgress,
        "a slow upstream must not block an allowlisted request past its budget"
    );
    assert!(
        elapsed < Duration::from_millis(100),
        "decide() took {elapsed:?}, which is not within the configured budget"
    );

    // The budget timeout must not have cancelled the fetch: give it time
    // to finish in the background, then confirm a retried request finds
    // the artifact already warm in the cache rather than paying for the
    // download all over again.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let retried = harness.scanner.decide(&key, &entry).await;
    match retried {
        Decision::Serve(served_path) => {
            assert_eq!(std::fs::read(&served_path).expect("read served file"), body);
        }
        other => panic!(
            "a retried request must find the warm cache from the undetached fetch, got {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// "We could not check" must never look like "we checked and it is bad"
// ---------------------------------------------------------------------------

/// An archive this unpacker cannot read is a gap in *our* coverage — an
/// unsupported format, a tar quirk, a truncated transfer. Storing that as
/// `Verdict::Blocked` made a format gap permanently indistinguishable from
/// a malware finding, and the refusal read to a developer as "we found
/// malware in your package".
#[tokio::test]
async fn an_unreadable_archive_is_unverifiable_and_stores_no_verdict() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    // Well-formed HTTP, correct hash, but not a zip at all.
    let body = b"this is not a zip archive".to_vec();
    let sha256 = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
    );
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    match harness.scanner.decide(&key, &entry).await {
        Decision::Unverifiable(reason) => assert_eq!(reason.code, "unverifiable:unpack-failed"),
        other => panic!(
            "an archive we cannot read must be Unverifiable, never a stored \
             Blocked verdict, got {other:?}"
        ),
    }

    assert!(
        harness
            .verdict_store
            .get(&key, &harness.fingerprint)
            .expect("query verdict")
            .is_none(),
        "an unpack failure must not be persisted as a verdict"
    );
}

/// N3 regression test: an archive attempting a deliberate path-escape — a
/// `..` component here, but the same rule covers absolute paths, symlinks,
/// hard links, and device/FIFO entries — is an unambiguous attack, not a
/// format gap, and must be `Blocked` with a stored, `/why`-visible verdict.
/// Before the fix, every `unpack` failure (benign or hostile alike) mapped
/// to `unverifiable:unpack-failed`, storing nothing — so an attack like
/// this read to a developer as "we could not check this artifact" and pip
/// retried the download up to five times.
#[tokio::test]
async fn an_archive_with_a_path_escape_is_blocked_and_stores_the_verdict() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes_with_traversal_entry();
    let sha256 = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config(Duration::from_secs(12)),
        &server,
        FakeSandbox::empty(),
    );
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    match harness.scanner.decide(&key, &entry).await {
        Decision::Refuse { reason, why_id } => {
            assert_eq!(reason.code, "unpack:escape");
            assert!(
                why_id.is_some(),
                "a deliberate escape attempt must produce a /why-visible verdict"
            );
        }
        other => panic!(
            "a deliberate path-escape attempt must be Blocked, not {other:?} \
             (an unreadable/unsupported archive is the only case that stays \
             Unverifiable)"
        ),
    }

    let stored = harness
        .verdict_store
        .get(&key, &harness.fingerprint)
        .expect("query verdict")
        .expect("a path-escape attempt must store a durable verdict");
    assert!(matches!(stored.verdict, Verdict::Blocked(_)));
}

/// A plugin that could not be run has not examined the artifact, so there
/// is no verdict to store. Storing one would outlive the broken plugin and
/// leave a developer reading "we found malware" about an artifact nothing
/// ever looked at.
#[tokio::test]
async fn a_plugin_that_cannot_run_is_unverifiable_and_stores_no_verdict() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let plugin_dir = tempfile::tempdir().expect("create plugin temp dir");
    let plugin_path = plugin_dir.path().join("broken-plugin");
    std::fs::write(&plugin_path, b"pretend plugin binary").expect("write plugin binary");

    let mut cfg = base_config(Duration::from_secs(12));
    cfg.plugins = vec![PluginConfig {
        name: "broken".to_string(),
        binary: plugin_path.clone(),
        timeout: Duration::from_secs(5),
    }];
    // The sandbox itself fails: the check never ran.
    let sandbox = FakeSandbox::new([(
        plugin_path,
        Err("bubblewrap could not run the plugin".to_string()),
    )]);

    let harness = build_harness(cfg, &server, sandbox);
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    match harness.scanner.decide(&key, &entry).await {
        Decision::Unverifiable(reason) => assert_eq!(reason.code, "plugin:broken:error"),
        other => panic!(
            "a plugin that could not run must be Unverifiable, never a stored \
             Blocked verdict, got {other:?}"
        ),
    }

    assert!(
        harness
            .verdict_store
            .get(&key, &harness.fingerprint)
            .expect("query verdict")
            .is_none(),
        "a check that never ran must not be persisted as a verdict"
    );
}

/// A plugin killed at its timeout also never reached a verdict.
#[tokio::test]
async fn a_plugin_that_timed_out_is_unverifiable_and_stores_no_verdict() {
    let server = MockServer::start().await;
    let filename = "demo_package-1.0.0-py3-none-any.whl";
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let plugin_dir = tempfile::tempdir().expect("create plugin temp dir");
    let plugin_path = plugin_dir.path().join("slow-plugin");
    std::fs::write(&plugin_path, b"pretend plugin binary").expect("write plugin binary");

    let mut cfg = base_config(Duration::from_secs(12));
    cfg.plugins = vec![PluginConfig {
        name: "slow".to_string(),
        binary: plugin_path.clone(),
        timeout: Duration::from_millis(50),
    }];
    let sandbox = FakeSandbox::new([(
        plugin_path,
        Ok(SandboxOutcome {
            exit_code: None,
            output: String::new(),
            timed_out: true,
            signal: None,
        }),
    )]);

    let harness = build_harness(cfg, &server, sandbox);
    let key = key_for(&sha256, filename);
    let entry = entry_for(&server, filename, Some(&sha256));

    match harness.scanner.decide(&key, &entry).await {
        Decision::Unverifiable(reason) => assert_eq!(reason.code, "plugin:slow:timeout"),
        other => panic!("a timed-out plugin must be Unverifiable, got {other:?}"),
    }

    assert!(
        harness
            .verdict_store
            .get(&key, &harness.fingerprint)
            .expect("query verdict")
            .is_none(),
        "a check that never finished must not be persisted as a verdict"
    );
}

//! Integration tests for `supply_chain_scanner::db::verdict::recent_blocked`
//! and `supply_chain_scanner::http::refusals`: the unauthenticated
//! `GET /refusals` listing of recent index-time blocks.
//!
//! The store test plants rows through `VerdictStore` directly and reads
//! them back with no HTTP involved. The handler tests drive the real
//! router over real HTTP/1.1 on loopback, with rows planted the same way.
//! No network call ever leaves the process.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::config::{
    AiReviewConfig, AuditConfig, BlockOn, Config, ConfigHandle, CveLine, UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::index_cache::IndexCache;
use supply_chain_scanner::db::review::ReviewStore;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::pypi::upstream::Upstream;
use supply_chain_scanner::ecosystem::pypi::PyPi;
use supply_chain_scanner::http::router;
use supply_chain_scanner::http::AppState;
use supply_chain_scanner::model::{ArtifactKey, RefusalReason, Verdict};
use supply_chain_scanner::plugin::{PluginRunner, SandboxRunner, SandboxSpec};
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::Scanner;

const FINGERPRINT: &str = "fingerprint";

// ---------------------------------------------------------------------------
// Store-level fixtures
// ---------------------------------------------------------------------------

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

fn key(ecosystem: &str, package: &str, version: &str) -> ArtifactKey {
    ArtifactKey {
        ecosystem: ecosystem.to_string(),
        package: package.to_string(),
        version: version.to_string(),
        filename: format!("{package}-{version}.tar.gz"),
        sha256: format!("{package}-{version}-sha256"),
    }
}

fn blocked(code: &str, detail: &str) -> Verdict {
    Verdict::Blocked(RefusalReason {
        code: code.to_string(),
        detail: detail.to_string(),
    })
}

// ---------------------------------------------------------------------------
// `VerdictStore::recent_blocked`
// ---------------------------------------------------------------------------

#[test]
fn recent_blocked_returns_newest_first_up_to_the_limit() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db);

    for package in ["cargo-a", "cargo-b", "cargo-c"] {
        store
            .put(
                &key("cargo", package, "1.0.0"),
                &blocked("plugin:fail", &format!("{package} failed")),
                FINGERPRINT,
            )
            .expect("put blocked verdict");
    }
    store
        .put(
            &key("pypi", "pypi-d", "1.0.0"),
            &blocked("cve:high", "pypi-d failed"),
            FINGERPRINT,
        )
        .expect("put blocked verdict");

    let recent = store
        .recent_blocked("cargo", 2)
        .expect("query recent blocked verdicts");

    let packages: Vec<&str> = recent
        .iter()
        .map(|verdict| verdict.package.as_str())
        .collect();
    assert_eq!(packages, vec!["cargo-c", "cargo-b"], "newest first, capped");
    assert!(
        recent.iter().all(|verdict| verdict.package != "pypi-d"),
        "another ecosystem's blocks must not appear"
    );
}

#[test]
fn recent_blocked_excludes_clean_verdicts() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db);

    store
        .put(
            &key("cargo", "clean-crate", "1.0.0"),
            &Verdict::Clean,
            FINGERPRINT,
        )
        .expect("put clean verdict");
    store
        .put(
            &key("cargo", "blocked-crate", "1.0.0"),
            &blocked("plugin:fail", "blocked-crate failed"),
            FINGERPRINT,
        )
        .expect("put blocked verdict");

    let recent = store
        .recent_blocked("cargo", 100)
        .expect("query recent blocked verdicts");

    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].package, "blocked-crate");
    assert_eq!(recent[0].version, "1.0.0");
    assert_eq!(recent[0].reason_code, "plugin:fail");
    assert_eq!(recent[0].reason_detail, "blocked-crate failed");
    assert!(
        !recent[0].why_id.is_empty(),
        "the row's why_id is what the page links to"
    );
    assert!(
        recent[0].scanned_at > 0,
        "the page renders the scan timestamp"
    );
}

// ---------------------------------------------------------------------------
// HTTP harness
// ---------------------------------------------------------------------------

/// No plugins are configured in any of these tests, so this must never run.
struct NeverCalledSandbox;
impl SandboxRunner for NeverCalledSandbox {
    fn run(
        &self,
        _spec: &SandboxSpec,
    ) -> anyhow::Result<supply_chain_scanner::plugin::SandboxOutcome> {
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
        min_release_age_days: None,
        download: Default::default(),
        allowlist: Vec::new(),
        plugins: Vec::new(),
        max_concurrent_scans: None,
        ai_review: Some(AiReviewConfig {
            enabled: true,
            base_url: "http://127.0.0.1:9/chat/".parse().unwrap(),
            model: "test-model".to_string(),
            api_key_env: None,
            timeout: Duration::from_secs(5),
            max_payload_bytes: 262_144,
            max_output_tokens: 256,
            coverage_threshold: 0.8,
            block_on: BlockOn::Malicious,
            block_opaque_executables: false,
        }),
        cargo_registry: None,
        npm_registry: None,
        audit: AuditConfig::default(),
    }
}

/// One router wired to a fresh temp-file SQLite database, listening on a
/// fresh loopback port. `verdicts` plants rows; `addr` is where the real
/// HTTP client connects. The mock upstream is never dialed.
struct Harness {
    _db_dir: tempfile::TempDir,
    _cache_dir: tempfile::TempDir,
    verdicts: VerdictStore,
    addr: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn harness() -> Harness {
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
        None,
    );

    let state = AppState {
        scanner: Arc::new(scanner),
        verdicts: Arc::new(VerdictStore::new(db.clone())),
        reviews: Arc::new(ReviewStore::new(db.clone())),
        config: config_handle,
        ecosystem: Arc::new(PyPi::new(Arc::new(ecosystem_upstream))),
    };

    let app = router(
        state,
        Arc::new(
            Upstream::new(
                "https://example.invalid/simple/".parse().unwrap(),
                IndexCache::new(db.clone()),
            )
            .expect("construct router upstream"),
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Harness {
        _db_dir: db_dir,
        _cache_dir: cache_dir,
        verdicts: verdict_store,
        addr,
        server,
    }
}

/// Plants one blocked verdict for the PyPI ecosystem and returns its
/// `why_id` as the page will print it.
fn plant_blocked(harness: &Harness, package: &str, detail: &str) -> String {
    harness
        .verdicts
        .put(
            &key("pypi", package, "1.2.3"),
            &blocked("plugin:fail", detail),
            FINGERPRINT,
        )
        .expect("plant blocked verdict")
}

async fn get_refusals(harness: &Harness) -> (reqwest::StatusCode, String) {
    let response = reqwest::get(format!("http://{}/refusals", harness.addr))
        .await
        .expect("request the refusals page");
    let status = response.status();
    let body = response.text().await.expect("read response body");
    (status, body)
}

// ---------------------------------------------------------------------------
// `GET /refusals`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refusals_page_lists_recent_blocks_with_why_links() {
    let harness = harness().await;
    let why_id = plant_blocked(&harness, "evil-package", "plugin found something");

    let (status, body) = get_refusals(&harness).await;

    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(body.contains("/why/"));
    assert!(
        body.contains(&format!("/why/{why_id}")),
        "the link points at the row's own why-id"
    );
    assert!(
        body.contains("evil-package"),
        "the page names the blocked package"
    );
}

#[tokio::test]
async fn refusals_page_escapes_attacker_influenced_detail_text() {
    let harness = harness().await;
    plant_blocked(&harness, "hostile-package", "<script>alert('x')</script>");

    let (status, body) = get_refusals(&harness).await;

    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(
        !body.contains("<script>"),
        "the stored detail must never reach the page as markup"
    );
    assert!(
        body.contains("&lt;script&gt;"),
        "the detail is shown, escaped, so the operator can read it"
    );
}

#[tokio::test]
async fn refusals_page_renders_an_empty_table_rather_than_erroring() {
    let harness = harness().await;

    let (status, body) = get_refusals(&harness).await;

    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(
        body.contains("<table"),
        "the page keeps its shape when there is nothing to list"
    );
    assert!(!body.contains("/why/"), "no rows means no why links");
}

#[tokio::test]
async fn refusals_page_excludes_clean_verdicts() {
    let harness = harness().await;
    harness
        .verdicts
        .put(
            &key("pypi", "innocent-package", "1.2.3"),
            &Verdict::Clean,
            FINGERPRINT,
        )
        .expect("plant clean verdict");
    plant_blocked(&harness, "guilty-package", "plugin found something");

    let (status, body) = get_refusals(&harness).await;

    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(body.contains("guilty-package"));
    assert!(!body.contains("innocent-package"));
}

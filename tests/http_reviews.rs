//! Integration tests for `supply_chain_scanner::http::reviews`: the
//! unauthenticated `GET /api/reviews` listing of every completed AI
//! review. Every test drives the real router over real HTTP/1.1 on
//! loopback, with rows planted through `ReviewStore` directly. No
//! network call ever leaves the process.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::audit::AuditLog;
use supply_chain_scanner::config::{
    AiReviewConfig, AuditConfig, BlockOn, Config, ConfigHandle, CveLine, UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::index_cache::IndexCache;
use supply_chain_scanner::db::review::{NewReview, ReviewStore};
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::pypi::upstream::Upstream;
use supply_chain_scanner::ecosystem::pypi::PyPi;
use supply_chain_scanner::http::router;
use supply_chain_scanner::http::AppState;
use supply_chain_scanner::model::ArtifactKey;
use supply_chain_scanner::plugin::{PluginRunner, SandboxRunner, SandboxSpec};
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::Scanner;

// ---------------------------------------------------------------------------
// Harness
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
        // `/api/reviews` 404s when `ai_review` is unset (see
        // `reviews_handler`); these tests are about the listing's own
        // behavior, not about that gate, so they need it configured.
        // `ai_review_route_is_not_found_when_ai_review_is_unset` is the
        // one test for the gate itself and builds its own config.
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
/// fresh loopback port. `store` plants rows; `addr` is where the real
/// HTTP client connects. The mock server is never dialed.
struct Harness {
    _db_dir: tempfile::TempDir,
    _cache_dir: tempfile::TempDir,
    store: ReviewStore,
    addr: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn harness() -> Harness {
    harness_with_config(base_config()).await
}

async fn harness_with_config(cfg: Config) -> Harness {
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
    let reviews_store = ReviewStore::new(db.clone());
    let advisory_store = AdvisoryStore::new(db.clone());
    let plugin_runner = PluginRunner::new(Arc::new(NeverCalledSandbox));
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
        verdicts: Arc::new(verdict_store),
        reviews: Arc::new(ReviewStore::new(db.clone())),
        config: config_handle,
        ecosystem: Arc::new(PyPi::new(Arc::new(ecosystem_upstream))),
        // No test in this file exercises the fetch audit log; it covers
        // `/api/reviews` instead. A sink keeps that true without a test
        // writing an audit file into the repo working directory.
        audit: Arc::new(AuditLog::with_writer(std::io::sink())),
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
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });

    Harness {
        _db_dir: db_dir,
        _cache_dir: cache_dir,
        store: reviews_store,
        addr,
        server,
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn key(package: &str) -> ArtifactKey {
    ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: package.to_string(),
        version: "1.2.3".to_string(),
        filename: format!("{package}-1.2.3-py3-none-any.whl"),
        sha256: format!("{package}-sha256"),
    }
}

/// One planted review row. `verdict` and blocked travel together the
/// way `AiReviewer` records them; the summary names the verifier so a
/// test can tell its rows apart.
fn review(key: &ArtifactKey, verifier: &str) -> NewReview {
    NewReview {
        key: key.clone(),
        fingerprint: "fingerprint".to_string(),
        verdict: "clean",
        blocked: false,
        summary: format!("{verifier} found nothing"),
        findings_json: "[]".to_string(),
        coverage: Some(1.0),
        reviewable_bytes_total: 100,
        reviewable_bytes_sent: 100,
        opaque_json: "{}".to_string(),
        reviewed_paths_json: "[]".to_string(),
        model: "test-model".to_string(),
        prompt_version: "1",
        collector_version: "1".to_string(),
    }
}

/// Stores one row and blocks until the put is visible to the endpoint.
fn plant(store: &ReviewStore, review: &NewReview) -> i64 {
    store.put(review).expect("store review row")
}

async fn get_json(harness: &Harness, query: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let response = reqwest::get(format!("http://{}/api/reviews{query}", harness.addr))
        .await
        .expect("request the reviews endpoint");
    let status = response.status();
    let body = response.text().await.expect("read response body");
    // A 400 carries a plain-text detail, not JSON, so a parse failure
    // degrades to a null value the caller's status assert catches
    // before any body assertion runs.
    let json = body
        .parse::<serde_json::Value>()
        .unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// `reviews` entries of a response body, as (id, package) pairs.
fn entries(json: &serde_json::Value) -> Vec<(i64, String)> {
    json.get("reviews")
        .and_then(|reviews| reviews.as_array())
        .expect("body carries a reviews array")
        .iter()
        .map(|entry| {
            let id = entry.get("id").and_then(|id| id.as_i64()).expect("row id");
            let package = entry
                .get("key")
                .and_then(|key| key.get("package"))
                .and_then(|package| package.as_str())
                .expect("row package")
                .to_string();
            (id, package)
        })
        .collect()
}

#[tokio::test]
async fn the_endpoint_returns_stored_reviews_newest_first() {
    let harness = harness().await;
    let first = plant(&harness.store, &review(&key("pkg-a"), "first"));
    let second = plant(&harness.store, &review(&key("pkg-b"), "second"));
    let (status, json) = get_json(&harness, "").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let entries = entries(&json);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0, second, "newest row leads the page");
    assert_eq!(entries[1].0, first, "oldest row closes the page");
}

#[tokio::test]
async fn the_endpoint_filters_by_verdict() {
    let harness = harness().await;
    plant(
        &harness.store,
        &NewReview {
            verdict: "malicious",
            blocked: true,
            summary: "planted malicious row".to_string(),
            ..review(&key("pkg-bad"), "bad")
        },
    );
    plant(&harness.store, &review(&key("pkg-good"), "good"));

    let (status, json) = get_json(&harness, "?verdict=malicious").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let entries = entries(&json);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1, "pkg-bad");
}

#[tokio::test]
async fn the_endpoint_filters_by_package() {
    let harness = harness().await;
    plant(&harness.store, &review(&key("pkg-a"), "a"));
    plant(&harness.store, &review(&key("pkg-b"), "b"));

    let (status, json) = get_json(&harness, "?package=pkg-b").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let entries = entries(&json);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1, "pkg-b");
}

#[tokio::test]
async fn the_endpoint_filters_by_since() {
    let harness = harness().await;
    let old_row = plant(&harness.store, &review(&key("pkg-old"), "old"));
    let new_row = plant(&harness.store, &review(&key("pkg-new"), "new"));

    // `since` filters on reviewed_at, and both rows were stored in the
    // same second, so the cutoff uses the row the store is known to
    // stamp: query the newest row's own timestamp back.
    let stored = harness
        .store
        .newest_for_artifact(&key("pkg-new"), "fingerprint")
        .expect("read newest row")
        .expect("row exists");
    assert_eq!(stored.id, new_row);

    let (status, json) = get_json(&harness, "?package=pkg-new").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(entries(&json).len(), 1);

    // A since above the newest stamp excludes the row; a since at or
    // below the older row's stamp keeps it. Both rows share the same
    // second, so the exclusion query asks for everything strictly
    // after that second, which is nothing.
    let since = stored.reviewed_at;
    let (status, json) = get_json(&harness, &format!("?since={}", since + 1)).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(entries(&json).len(), 0, "both rows predate the cutoff");
    let _ = old_row;
}

#[tokio::test]
async fn the_endpoint_paginates_with_before_id_and_reports_the_next_cursor() {
    let harness = harness().await;
    let ids: Vec<i64> = (0..3)
        .map(|_index| plant(&harness.store, &review(&key("pkg-a"), "page")))
        .collect();
    // ids run oldest to newest, so the page order is newest first.
    let newest = ids[2];
    let middle = ids[1];
    let oldest = ids[0];

    let (status, first_page) = get_json(&harness, "?limit=2").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let first_entries = entries(&first_page);
    assert_eq!(first_entries.len(), 2);
    let cursor = first_page
        .get("next_before_id")
        .and_then(|cursor| cursor.as_i64())
        .expect("full page reports a cursor");
    assert_eq!(cursor, middle, "cursor is the page's oldest row id");

    let (status, second_page) = get_json(&harness, &format!("?limit=2&before_id={middle}")).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let second_entries = entries(&second_page);
    assert_eq!(second_entries.len(), 1);
    assert_eq!(second_entries[0].0, oldest);
    assert!(
        second_page
            .get("next_before_id")
            .and_then(|cursor| cursor.as_i64())
            .is_none(),
        "short page reports a null cursor"
    );
    let _ = newest;
}

#[tokio::test]
async fn the_endpoint_clamps_an_oversized_limit() {
    let harness = harness().await;
    for index in 0..5 {
        plant(&harness.store, &review(&key("pkg-a"), "clamp"));
        let _ = index;
    }

    let (status, json) = get_json(&harness, "?limit=10000").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(entries(&json).len(), 5, "clamp only bounds the page size");
}

#[tokio::test]
async fn the_endpoint_rejects_an_unparseable_limit() {
    let harness = harness().await;
    let (status, _) = get_json(&harness, "?limit=abc").await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_endpoint_rejects_an_unknown_verdict_filter() {
    let harness = harness().await;
    let (status, _) = get_json(&harness, "?verdict=bogus").await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_endpoint_returns_an_empty_list_rather_than_404_when_nothing_matches() {
    let harness = harness().await;
    let (status, json) = get_json(&harness, "?package=pkg-absent").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(entries(&json).len(), 0);
}

#[tokio::test]
async fn the_endpoint_is_not_found_when_ai_review_is_unset() {
    // The route is always registered -- `ai_review` is reloadable, so it
    // cannot be added or removed from the router at runtime -- but an
    // unconfigured deployment must not gain a new always-on, enumerable
    // endpoint just by upgrading to a binary that carries this feature.
    let mut cfg = base_config();
    cfg.ai_review = None;
    let harness = harness_with_config(cfg).await;

    let (status, _json) = get_json(&harness, "").await;

    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_endpoint_is_not_found_when_ai_review_is_disabled() {
    // A table that is present but `enabled = false` must gate the route
    // the same way an absent table does, not the way a configured one does.
    let mut cfg = base_config();
    cfg.ai_review.as_mut().expect("table present").enabled = false;
    let harness = harness_with_config(cfg).await;

    let (status, _json) = get_json(&harness, "").await;

    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_endpoint_never_returns_the_api_key_or_the_payload() {
    let harness = harness().await;
    let mut row = review(&key("pkg-a"), "secret");
    row.findings_json =
        r#"[{"path":"evil.py","lines":"1-2","behavior":"calls os.environ","severity":"high"}]"#
            .to_string();
    plant(&harness.store, &row);

    let (status, json) = get_json(&harness, "").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let body = serde_json::to_string(&json).expect("serialize body for scanning");
    assert!(!body.contains("api_key"));
    assert!(!body.contains("SCS_"));
    assert!(!body.contains("Bearer"));
    assert!(
        body.contains("evil.py"),
        "a finding's path is report data and is served"
    );
    assert!(
        !body.contains("def evil"),
        "file payload content is not stored and cannot be served"
    );
}

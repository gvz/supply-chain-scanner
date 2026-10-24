//! Integration tests for `supply_chain_scanner::http::cargo_index`: the
//! cargo sparse-index surface this deployment serves.
//!
//! Every test drives the real [`cargo_router`] over real HTTP/1.1 on
//! loopback, with a `wiremock` stand-in for the crates.io index. The
//! requests use hyper's own client, not a higher-level one: a client that
//! normalizes `..` path segments before they leave the process would
//! defeat the traversal test below.
//!
//! Nothing here talks to a model provider, to `bwrap`, or to a real
//! registry.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use supply_chain_scanner::ai::provider::{ChatProvider, ProviderError};
use supply_chain_scanner::ai::AiReviewer;
use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::cargovet::parse::AuditEntry;
use supply_chain_scanner::config::{
    AiReviewConfig, BlockOn, Config, ConfigHandle, CveLine, UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::cargo_vet::CargoVetStore;
use supply_chain_scanner::db::review::ReviewStore;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::cargo::index::index_path_for;
use supply_chain_scanner::ecosystem::cargo::upstream::CargoUpstream;
use supply_chain_scanner::http::cargo_index::{cargo_router, CargoAppState};
use supply_chain_scanner::plugin::PluginRunner;
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::cargo::CargoScanner;
use supply_chain_scanner::scan::coordinator::ScanCoordinator;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

/// A minimal, valid `Config`. `public_url` is the one value the
/// `config.json` handler reads, so it is a distinctive host on purpose.
fn base_config() -> Config {
    Config {
        bind: "127.0.0.1:8080".parse().unwrap(),
        db_path: PathBuf::from("data/scanner.db"),
        cache_dir: PathBuf::from("data/cache"),
        upstream_url: "https://index.crates.io/".parse().unwrap(),
        public_url: "http://proxy.example:8080".parse().unwrap(),
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
        ai_review: None,
        cargo_registry: None,
    }
}

fn ai_review_cfg() -> AiReviewConfig {
    AiReviewConfig {
        base_url: "http://127.0.0.1:9/chat/".parse().unwrap(),
        model: "test-model".to_string(),
        api_key_env: None,
        timeout: Duration::from_secs(5),
        max_payload_bytes: 262_144,
        max_output_tokens: 256,
        coverage_threshold: 0.8,
        block_on: BlockOn::Malicious,
        block_opaque_executables: false,
    }
}

/// No plugins are configured in these tests, and the reviewer is never
/// reached (see [`Harness::in_progress`]), so this must never run.
struct NeverCalledSandbox;

impl supply_chain_scanner::plugin::SandboxRunner for NeverCalledSandbox {
    fn run(
        &self,
        _spec: &supply_chain_scanner::plugin::SandboxSpec,
    ) -> anyhow::Result<supply_chain_scanner::plugin::SandboxOutcome> {
        panic!("the sandbox must never run in the cargo index tests");
    }
}

/// A provider that must never be called. The reviewer these tests
/// configure fails before it reaches the provider, because the `.crate`
/// download is not mounted.
struct NeverCalledProvider;

#[async_trait]
impl ChatProvider for NeverCalledProvider {
    async fn complete(
        &self,
        _request: &serde_json::Value,
        _remaining: Duration,
    ) -> Result<String, ProviderError> {
        panic!("the model provider must never be called in these tests");
    }
}

/// One `AuditEntry::Full`, which is the only form that makes a version
/// forwardable without an AI review.
fn full_audit(package: &str, version: &str) -> AuditEntry {
    AuditEntry::Full {
        package: package.to_string(),
        version: version.to_string(),
        who: vec!["trusted-auditor".to_string()],
        criteria: vec!["safe-to-deploy".to_string()],
        source: "test".to_string(),
    }
}

/// Mounts one crate's index file with the given versions.
async fn mount_index(server: &MockServer, name: &str, versions: &[&str]) {
    let body: String = versions
        .iter()
        .map(|vers| {
            format!(
                "{{\"name\":\"{name}\",\"vers\":\"{vers}\",\"cksum\":\"cksum-{vers}\",\
                 \"yanked\":false,\"deps\":[]}}\n"
            )
        })
        .collect();
    Mock::given(method("GET"))
        .and(path(index_path(name)))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
        .await;
}

/// The sparse-index path for a test crate name, as the proxy itself
/// computes it, so a short name gets the right prefix.
fn index_path(name: &str) -> String {
    format!("/{}", index_path_for(name))
}

// ---------------------------------------------------------------------------
// The router under test
// ---------------------------------------------------------------------------

struct Harness {
    _db_dir: tempfile::TempDir,
    _review_dir: tempfile::TempDir,
    _cache_dir: tempfile::TempDir,
    server: MockServer,
    addr: std::net::SocketAddr,
    _listener: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// A harness whose cascade can forward every version in `versions`,
    /// because a cargo-vet audit covers each one and no AI reviewer is
    /// configured. The stand-in upstream serves those versions in the
    /// order given.
    async fn with_vet_covered(name: &str, versions: &[&str]) -> Harness {
        let (harness, db) = Self::start(base_config()).await;
        mount_index(&harness.server, name, versions).await;
        let vet_store = CargoVetStore::new(db);
        harness.mount_covered(&vet_store, name, versions);
        harness
    }

    /// A harness whose cascade answers `InProgress`: one AI reviewer is
    /// configured, and the `.crate` download is not mounted, so the
    /// review cannot run and the cascade must ask for a retry.
    async fn in_progress(name: &str) -> Harness {
        let (harness, _db) = Self::start_with_reviewer(base_config()).await;
        harness.server.reset().await;
        mount_index(&harness.server, name, &["1.0.0"]).await;
        harness
    }

    fn mount_covered(&self, vet_store: &CargoVetStore, name: &str, versions: &[&str]) {
        let entries: Vec<AuditEntry> = versions.iter().map(|vers| full_audit(name, vers)).collect();
        vet_store
            .replace_source("test", &entries)
            .expect("store the cargo-vet audits");
    }

    async fn start(cfg: Config) -> (Harness, Db) {
        Self::build(cfg, false).await
    }

    async fn start_with_reviewer(cfg: Config) -> (Harness, Db) {
        Self::build(cfg, true).await
    }

    async fn build(mut cfg: Config, with_reviewer: bool) -> (Harness, Db) {
        let server = MockServer::start().await;
        let (db_dir, db) = open_db();
        let review_dir = tempfile::tempdir().expect("create review db temp dir");
        let review_db = Db::open(&review_dir.path().join("reviews.db")).expect("open review db");

        let base = Url::parse(&format!("{}/", server.uri())).expect("valid index base url");
        let upstream =
            CargoUpstream::with_limits(base.clone(), &Default::default()).expect("cargo upstream");
        // A second client for the download route's state. These tests only
        // exercise the index surface, so it is never dialed.
        let download_upstream =
            CargoUpstream::with_limits(base, &Default::default()).expect("cargo upstream");
        let cache_dir = tempfile::tempdir().expect("create artifact cache temp dir");

        let ai_reviewer = if with_reviewer {
            cfg.ai_review = Some(ai_review_cfg());
            Some(Arc::new(AiReviewer::new(
                ai_review_cfg(),
                Arc::new(NeverCalledSandbox),
                Arc::new(NeverCalledProvider) as Arc<dyn ChatProvider>,
                Arc::new(ReviewStore::new(review_db)),
                PathBuf::from(env!("CARGO_BIN_EXE_supply-chain-scanner")),
            )))
        } else {
            None
        };

        let policy = Arc::new(Policy::build(Arc::new(cfg.clone())).expect("build policy"));
        let config_handle = Arc::new(ConfigHandle::new(cfg));

        let scanner = CargoScanner::new(
            upstream,
            AdvisoryStore::new(db.clone()),
            CargoVetStore::new(db.clone()),
            VerdictStore::new(db.clone()),
            policy,
            ai_reviewer,
            Arc::clone(&config_handle),
            Arc::new(ScanCoordinator::new()),
        );

        let app = cargo_router(CargoAppState {
            cargo_scanner: Arc::new(scanner),
            config: config_handle,
            upstream: Arc::new(download_upstream),
            verdicts: Arc::new(VerdictStore::new(db.clone())),
            plugins: Arc::new(PluginRunner::new(Arc::new(NeverCalledSandbox))),
            artifact_cache: Arc::new(
                ArtifactCache::new(db.clone(), cache_dir.path().join("artifacts"))
                    .expect("create artifact cache"),
            ),
            reviews: Arc::new(supply_chain_scanner::db::review::ReviewStore::new(
                db.clone(),
            )),
            plugin_run_coordinator: Arc::new(ScanCoordinator::new()),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("local addr");
        let served = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        (
            Harness {
                _db_dir: db_dir,
                _review_dir: review_dir,
                _cache_dir: cache_dir,
                server,
                addr,
                _listener: served,
            },
            db,
        )
    }

    /// One `GET`, sent through hyper's HTTP/1.1 client over a loopback
    /// `TcpStream`, so the request target reaches the server exactly as
    /// written in `target` — `..` segments included. Returns the status,
    /// the `Content-Type` header, and the body text.
    async fn get(&self, target: &str) -> (u16, Option<String>, String) {
        use hyper::client::conn::http1;
        use hyper_util::rt::TokioIo;

        let stream = tokio::net::TcpStream::connect(self.addr)
            .await
            .expect("connect to the test server");
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .expect("http1 handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let request = hyper::Request::builder()
            .method("GET")
            .uri(target)
            .header(hyper::header::HOST, self.addr.to_string())
            .header(hyper::header::CONNECTION, "close")
            .body(axum::body::Body::empty())
            .expect("build the request");

        let response = sender
            .send_request(request)
            .await
            .expect("send the request");
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let bytes = axum::body::to_bytes(axum::body::Body::new(response.into_body()), usize::MAX)
            .await
            .expect("read the response body");
        (
            status,
            content_type,
            String::from_utf8(bytes.to_vec()).expect("the body is UTF-8"),
        )
    }

    /// How many requests the stand-in upstream received for `path`.
    async fn upstream_hits(&self, path: &str) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| request.url.path() == path)
            .count()
    }
}

/// Parses an index body into one map per line, keyed by field name.
fn index_lines(body: &str) -> Vec<serde_json::Map<String, serde_json::Value>> {
    body.lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|err| panic!("index line {line:?} is not JSON: {err}"))
                .as_object()
                .unwrap_or_else(|| panic!("index line {line:?} is not a JSON object"))
                .clone()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// config.json
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_json_reports_the_configured_dl_template() {
    let harness = Harness::with_vet_covered("demo-crate", &["1.0.0"]).await;

    let (status, _content_type, body) = harness.get("/config.json").await;

    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("config.json is JSON");
    let dl = parsed["dl"]
        .as_str()
        .expect("config.json carries a string `dl`");
    assert!(
        dl.contains("{crate}"),
        "cargo substitutes `{{crate}}` into the `dl` template, got {dl:?}"
    );
    assert!(
        dl.contains("{version}"),
        "cargo substitutes `{{version}}` into the `dl` template, got {dl:?}"
    );
    assert_eq!(
        dl, "http://proxy.example:8080/crates/{crate}/{version}/download",
        "the `dl` template must send cargo back to this proxy's own download \
         route, so the plugin gate stays in the loop, and it must read the \
         configured `public_url`"
    );
}

#[tokio::test]
async fn config_json_carries_the_dl_template_and_no_api_field() {
    let harness = Harness::with_vet_covered("demo-crate", &["1.0.0"]).await;

    let (status, content_type, body) = harness.get("/config.json").await;

    assert_eq!(status, 200);
    assert_eq!(
        content_type.as_deref(),
        Some("application/json"),
        "config.json is a JSON document"
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("config.json is JSON");
    let object = parsed.as_object().expect("config.json is a JSON object");
    assert_eq!(
        object.keys().collect::<Vec<_>>(),
        vec!["dl"],
        "the body must stay minimal: `dl` is the only key cargo requires, and \
         claiming an `api` this deployment does not serve would turn a clean \
         `cargo publish` error into a confusing 404"
    );
}

// ---------------------------------------------------------------------------
// The per-crate index route
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_index_route_serves_the_cascades_forwarded_entries_as_json_lines() {
    let harness = Harness::with_vet_covered("demo-crate", &["1.0.0"]).await;

    let (status, _content_type, body) = harness.get("/de/mo/demo-crate").await;

    assert_eq!(status, 200);
    assert_eq!(
        body.lines().count(),
        1,
        "one forwarded version is one JSON line, got {body:?}"
    );
    let line = &index_lines(&body)[0];
    assert_eq!(line["name"], "demo-crate");
    assert_eq!(line["vers"], "1.0.0");
    assert_eq!(line["cksum"], "cksum-1.0.0");
    assert_eq!(line["yanked"], false);
    assert_eq!(
        line["deps"],
        serde_json::json!([]),
        "cargo requires the `deps` field to exist, even though this proxy does \
         not model dependency resolution itself"
    );
}

#[tokio::test]
async fn the_index_route_names_every_forwarded_version_newest_first() {
    let harness = Harness::with_vet_covered("demo-crate", &["1.0.0", "1.1.0"]).await;

    let (status, _content_type, body) = harness.get("/de/mo/demo-crate").await;

    assert_eq!(status, 200);
    let versions: Vec<String> = index_lines(&body)
        .iter()
        .map(|line| {
            line["vers"]
                .as_str()
                .expect("each line carries a `vers` string")
                .to_string()
        })
        .collect();
    assert_eq!(
        versions,
        vec!["1.1.0".to_string(), "1.0.0".to_string()],
        "the cascade emits newest first, and the handler must not reorder it"
    );
}

#[tokio::test]
async fn the_index_route_serves_text_plain() {
    let harness = Harness::with_vet_covered("demo-crate", &["1.0.0"]).await;

    let (status, content_type, _body) = harness.get("/de/mo/demo-crate").await;

    assert_eq!(status, 200);
    assert_eq!(
        content_type.as_deref(),
        Some("text/plain; charset=utf-8"),
        "crates.io serves index files as plain text, and cargo parses the body \
         as JSON lines regardless of the header"
    );
}

#[tokio::test]
async fn an_empty_forwarded_list_yields_200_with_an_empty_body() {
    // No cargo-vet coverage and no AI reviewer, so the cascade can forward
    // nothing. The crate still exists upstream.
    let (harness, _db) = Harness::start(base_config()).await;
    mount_index(&harness.server, "demo-crate", &["1.0.0"]).await;

    let (status, _content_type, body) = harness.get("/de/mo/demo-crate").await;

    assert_eq!(
        status, 200,
        "a crate with no forwardable version must read the way a crate with no \
         versions reads, not as an error"
    );
    assert_eq!(body, "", "an empty version list is an empty body");
}

#[tokio::test]
async fn an_invalid_crate_name_in_the_path_is_a_400_not_a_500() {
    let harness = Harness::with_vet_covered("demo-crate", &["1.0.0"]).await;

    let (status, _content_type, body) = harness.get("/../../etc/passwd").await;

    assert_eq!(status, 400, "got body {body:?}");
    assert_eq!(
        harness.upstream_hits("/../../etc/passwd").await,
        0,
        "an invalid path must never reach upstream"
    );
}

#[tokio::test]
async fn a_path_that_does_not_match_the_prefix_scheme_is_a_400() {
    let harness = Harness::with_vet_covered("demo-crate", &["1.0.0"]).await;

    let (status, _content_type, body) = harness.get("/xx/yy/demo-crate").await;

    assert_eq!(
        status, 400,
        "the prefix is derived from the name, so a mismatched prefix is a \
         malformed request, got body {body:?}"
    );
    assert_eq!(
        harness.upstream_hits("/xx/yy/demo-crate").await,
        0,
        "a malformed path must never reach upstream"
    );
}

#[tokio::test]
async fn a_trailing_slash_on_the_index_route_is_a_400() {
    let harness = Harness::with_vet_covered("demo-crate", &["1.0.0"]).await;

    let (status, _content_type, _body) = harness.get("/de/mo/demo-crate/").await;

    assert_eq!(status, 400, "the crate name is the last path segment");
}

#[tokio::test]
async fn a_one_character_crate_name_uses_the_1_prefix() {
    let harness = Harness::with_vet_covered("a", &["1.0.0"]).await;

    let (status, _content_type, _body) = harness.get("/1/a").await;

    assert_eq!(status, 200, "the one-character shape must route");
}

#[tokio::test]
async fn an_in_progress_cascade_is_a_429() {
    let harness = Harness::in_progress("demo-crate").await;

    let (status, content_type, body) = harness.get("/de/mo/demo-crate").await;

    assert_eq!(
        status, 429,
        "an in-progress scan maps to the same retryable status the PyPI path \
         uses, got body {body:?}"
    );
    assert_eq!(
        content_type.as_deref(),
        Some("text/plain; charset=utf-8"),
        "the in-progress response is the shared reason-phrase response"
    );
}

// ---------------------------------------------------------------------------
// The route reaches the cascade
// ---------------------------------------------------------------------------

/// Cargo asks for the crate under its published spelling, so a name that
/// carries an underscore arrives at `nu/m_/num_cpus`-shaped paths. The
/// canonical-path check must accept that spelling and reach the cascade.
/// Refusing it here would make every such crate unresolvable through the
/// proxy, which is the whole population of crates that publish with `_`.
#[tokio::test]
async fn an_underscore_name_is_served_at_its_published_index_path() {
    let harness = Harness::with_vet_covered("num_cpus", &["1.16.0"]).await;

    let (status, _content_type, body) = harness.get("/nu/m_/num_cpus").await;

    assert_eq!(status, 200, "an underscore crate path must not be a 400");
    assert!(
        body.contains("1.16.0"),
        "the forwarded entry must reach the client: {body:?}"
    );
}

#[tokio::test]
async fn a_valid_name_round_trips_through_the_index_route_into_decide_index() {
    let harness = Harness::with_vet_covered("demo-crate", &["1.0.0"]).await;

    let (status, _content_type, _body) = harness.get("/de/mo/demo-crate").await;

    assert_eq!(status, 200);
    assert_eq!(
        harness.upstream_hits("/de/mo/demo-crate").await,
        1,
        "the handler must hand the name to the cascade, which fetches that \
         crate's index file from upstream"
    );
}

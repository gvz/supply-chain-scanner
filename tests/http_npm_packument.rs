//! Integration tests for `supply_chain_scanner::http::npm_packument`: the
//! npm packument surface and the handful of auxiliary routes a working
//! npm deployment needs.
//!
//! Every test drives the real [`npm_router`] over real HTTP/1.1 on
//! loopback, with a `wiremock` stand-in for the npm registry. The
//! requests use hyper's own client, not a higher-level one: a client
//! that normalizes `..` path segments before they leave the process
//! would defeat the traversal test below.
//!
//! Nothing here talks to a model provider or to a real registry. Where a
//! test needs the npm cascade to actually forward a version, it uses the
//! same real [`AiReviewer`] over a scripted fake [`ChatProvider`] that
//! `tests/scan_npm.rs` uses — npm has no cargo-vet-shaped fast path, so
//! there is no cheaper way to make a version forwardable.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use supply_chain_scanner::ai::provider::{ChatProvider, ProviderError};
use supply_chain_scanner::ai::AiReviewer;
use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::audit::AuditLog;
use supply_chain_scanner::config::{
    AiReviewConfig, AuditConfig, BlockOn, Config, ConfigHandle, CveLine, NpmRegistryConfig,
    UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::review::ReviewStore;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::npm::packument_path;
use supply_chain_scanner::ecosystem::npm::upstream::NpmUpstream;
use supply_chain_scanner::http::npm_packument::{npm_router, NpmAppState};
use supply_chain_scanner::plugin::{
    PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec, SANDBOX_PACKAGE_DIR,
};
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::coordinator::ScanCoordinator;
use supply_chain_scanner::scan::npm::NpmScanner;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

/// A minimal, valid `Config` whose only interesting npm-specific knobs
/// live in `npm_registry`. `public_url` is a distinctive host, since
/// it is what a forwarded version's rewritten `dist.tarball` must carry.
fn base_config(server: &MockServer, scan_budget: Duration) -> Config {
    Config {
        bind: "127.0.0.1:8080".parse().unwrap(),
        db_path: PathBuf::from("data/scanner.db"),
        cache_dir: PathBuf::from("data/cache"),
        upstream_url: "https://registry.npmjs.org/".parse().unwrap(),
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
        npm_registry: Some(NpmRegistryConfig {
            upstream_registry_url: Url::parse(&format!("{}/", server.uri())).expect("valid url"),
            scan_budget,
            max_packument_bytes: 67_108_864,
            min_release_age_days: None,
        }),
        audit: AuditConfig::default(),
    }
}

fn ai_review_cfg(timeout: Duration) -> AiReviewConfig {
    AiReviewConfig {
        enabled: true,
        base_url: "http://127.0.0.1:9/chat/".parse().unwrap(),
        model: "test-model".to_string(),
        api_key_env: None,
        timeout,
        max_payload_bytes: 262_144,
        max_output_tokens: 256,
        coverage_threshold: 0.8,
        block_on: BlockOn::Malicious,
        block_opaque_executables: false,
    }
}

fn sha1_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Builds one npm version's tarball bytes: a gzipped tar containing a
/// minimal `package/package.json`. The unscoped filename mirrors
/// `tarball_path`'s own unscoping, so `name` here should already be
/// unscoped.
fn tarball_bytes(name: &str, vers: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(GzEncoder::new(&mut buf, Compression::fast()));
        let body = format!("{{\"name\":\"{name}\",\"version\":\"{vers}\"}}").into_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", &body[..])
            .expect("append npm tarball entry");
        builder.finish().expect("finish npm tarball fixture");
    }
    buf
}

/// One published version of a test package, with the shasum the
/// packument's `dist` object declares for its bytes.
struct Version {
    vers: &'static str,
    bytes: Vec<u8>,
    shasum: String,
}

fn version(name: &str, vers: &'static str) -> Version {
    let bytes = tarball_bytes(name, vers);
    let shasum = sha1_hex(&bytes);
    Version {
        vers,
        bytes,
        shasum,
    }
}

/// Mounts `name`'s packument at the exact wire path
/// [`NpmUpstream::packument`] requests it at — built with the crate's own
/// [`packument_path`], so a scoped name's `%2f` separator matches
/// whatever the upstream client actually sends.
async fn mount_packument(server: &MockServer, name: &str, versions: &[Version]) {
    let versions_json: String = versions
        .iter()
        .map(|v| {
            format!(
                r#""{vers}":{{"version":"{vers}","dist":{{"tarball":"{server_uri}/{name}/-/{name}-{vers}.tgz","shasum":"{shasum}"}}}}"#,
                vers = v.vers,
                server_uri = server.uri(),
                name = name,
                shasum = v.shasum,
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let latest = versions.last().map(|v| v.vers).unwrap_or("");
    let body = format!(
        r#"{{"name":"{name}","versions":{{{versions_json}}},"dist-tags":{{"latest":"{latest}"}},"time":{{}}}}"#
    );

    Mock::given(method("GET"))
        .and(path(format!("/{}", packument_path(name))))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
        .await;
}

/// Mounts each version's tarball download.
async fn mount_downloads(server: &MockServer, name: &str, versions: &[Version]) {
    for v in versions {
        Mock::given(method("GET"))
            .and(path(format!("/{name}/-/{name}-{}.tgz", v.vers)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(v.bytes.clone()))
            .mount(server)
            .await;
    }
}

// ---------------------------------------------------------------------------
// Reviewer fixtures — the same shape `tests/scan_npm.rs` uses
// ---------------------------------------------------------------------------

struct StubProvider {
    delay: Duration,
    calls: AtomicUsize,
}

impl StubProvider {
    fn new(delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            delay,
            calls: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl ChatProvider for StubProvider {
    async fn complete(
        &self,
        _request: &serde_json::Value,
        _remaining: Duration,
    ) -> Result<String, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        Ok(model_reply_body(
            r#"{"verdict":"clean","summary":"ordinary library code","findings":[]}"#,
        ))
    }
}

fn model_reply_body(reply_json: &str) -> String {
    let content = serde_json::to_string(reply_json).expect("escape the reply content");
    format!(
        r#"{{"id":"resp_1","choices":[{{"index":0,"message":{{"role":"assistant","content":{content}}},"finish_reason":"stop"}}]}}"#
    )
}

struct ServingSandbox;

impl SandboxRunner for ServingSandbox {
    fn run(&self, spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        let host = spec.package_dir.to_string_lossy().to_string();
        let args: Vec<String> = spec
            .args
            .iter()
            .map(|arg| {
                if arg == SANDBOX_PACKAGE_DIR {
                    host.clone()
                } else {
                    arg.clone()
                }
            })
            .collect();
        let output = std::process::Command::new(&spec.binary)
            .args(&args)
            .output()
            .map_err(|e| anyhow::anyhow!("the stub could not spawn the collector: {e}"))?;
        Ok(SandboxOutcome {
            exit_code: output.status.code(),
            output: String::from_utf8_lossy(&output.stdout).to_string(),
            timed_out: false,
            signal: None,
        })
    }
}

/// No plugins are registered in this task's router at all (Task 11 owns
/// the tarball route), so this must never run.
struct NeverCalledSandbox;

impl SandboxRunner for NeverCalledSandbox {
    fn run(&self, _spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        panic!("the sandbox must never run in the npm packument tests");
    }
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
    /// A harness with no AI reviewer configured at all: nothing can ever
    /// be forwarded, but every route must still resolve.
    async fn without_reviewer(server: MockServer, cfg: Config) -> (Harness, Db) {
        Self::build(server, cfg, Duration::ZERO, false).await
    }

    /// A harness with a real [`AiReviewer`] over a `StubProvider` that
    /// always replies clean, after `provider_delay`.
    async fn with_reviewer(
        server: MockServer,
        cfg: Config,
        provider_delay: Duration,
    ) -> (Harness, Db) {
        Self::build(server, cfg, provider_delay, true).await
    }

    async fn build(
        server: MockServer,
        mut cfg: Config,
        provider_delay: Duration,
        with_reviewer: bool,
    ) -> (Harness, Db) {
        let (db_dir, db) = open_db();
        let review_dir = tempfile::tempdir().expect("create review db temp dir");
        let review_db = Db::open(&review_dir.path().join("reviews.db")).expect("open review db");

        let ai_reviewer = if with_reviewer {
            let review_cfg = ai_review_cfg(Duration::from_secs(30));
            cfg.ai_review = Some(review_cfg.clone());
            let provider = StubProvider::new(provider_delay);
            Some(Arc::new(AiReviewer::new(
                review_cfg,
                Arc::new(ServingSandbox),
                provider as Arc<dyn ChatProvider>,
                Arc::new(ReviewStore::new(review_db)),
                PathBuf::from(env!("CARGO_BIN_EXE_supply-chain-scanner")),
            )))
        } else {
            None
        };

        let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
        let upstream = NpmUpstream::with_limits(base.clone(), 67_108_864, &Default::default())
            .expect("construct npm upstream");
        // A second client for the shared state. These tests only exercise
        // the packument surface, so this is never dialed by this router.
        let state_upstream = NpmUpstream::with_limits(base, 67_108_864, &Default::default())
            .expect("construct npm upstream for state");

        let policy = Arc::new(Policy::build(Arc::new(cfg.clone())).expect("build policy"));
        let config_handle = Arc::new(ConfigHandle::new(cfg));
        let cache_dir = tempfile::tempdir().expect("create artifact cache temp dir");
        let artifact_cache = Arc::new(
            ArtifactCache::new(db.clone(), cache_dir.path().join("artifacts"))
                .expect("create artifact cache"),
        );

        let scanner = NpmScanner::new(
            upstream,
            AdvisoryStore::new(db.clone()),
            VerdictStore::new(db.clone()),
            policy,
            ai_reviewer,
            Arc::clone(&config_handle),
            Arc::new(ScanCoordinator::new()),
            Arc::clone(&artifact_cache),
        );

        let app = npm_router(NpmAppState {
            npm_scanner: Arc::new(scanner),
            config: config_handle,
            upstream: Arc::new(state_upstream),
            verdicts: Arc::new(VerdictStore::new(db.clone())),
            plugins: Arc::new(PluginRunner::new(Arc::new(NeverCalledSandbox))),
            artifact_cache,
            reviews: Arc::new(ReviewStore::new(db.clone())),
            plugin_run_coordinator: Arc::new(ScanCoordinator::new()),
            // These tests are about the packument surface's own
            // behaviour, not the fetch audit log (that is
            // `tests/http_audit_npm.rs`), so a discarding writer is
            // enough to keep every request from 500ing on the new
            // fail-closed write.
            audit: Arc::new(AuditLog::with_writer(std::io::sink())),
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("local addr");
        let served = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
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

    /// One request, sent through hyper's HTTP/1.1 client over a loopback
    /// `TcpStream`, so the request target reaches the server exactly as
    /// written in `target` — `..` segments and `%2f` escapes included.
    /// Returns the status, the `Content-Type` header, and the body text.
    async fn request(&self, method: &str, target: &str) -> (u16, Option<String>, String) {
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
            .method(method)
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

    async fn get(&self, target: &str) -> (u16, Option<String>, String) {
        self.request("GET", target).await
    }

    async fn post(&self, target: &str) -> (u16, Option<String>, String) {
        self.request("POST", target).await
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

    /// How many requests the stand-in upstream received at all, on any
    /// path.
    async fn total_upstream_hits(&self) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .len()
    }
}

// ---------------------------------------------------------------------------
// The packument route
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_packument_request_serves_the_filtered_document() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let cfg = base_config(&server, Duration::from_secs(10));
    let (harness, _db) = Harness::with_reviewer(server, cfg, Duration::ZERO).await;

    let (status, content_type, body) = harness.get("/demo").await;

    assert_eq!(status, 200, "got body {body:?}");
    assert_eq!(content_type.as_deref(), Some("application/json"));
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("packument is JSON");
    assert_eq!(
        parsed["versions"].as_object().map(|o| o.len()),
        Some(1),
        "the one clean version must survive the cascade, got {body:?}"
    );
    assert_eq!(parsed["versions"]["1.0.0"]["version"], "1.0.0");
    let tarball = parsed["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .expect("a forwarded version carries a dist.tarball string");
    assert!(
        tarball.starts_with("http://proxy.example:8080/"),
        "the tarball must be rewritten to point at this proxy's public_url, got {tarball:?}"
    );
    assert_eq!(parsed["dist-tags"]["latest"], "1.0.0");
}

#[tokio::test]
async fn a_scoped_packument_path_resolves() {
    let server = MockServer::start().await;
    let core = vec![version("core", "7.0.0")];
    mount_packument(&server, "@babel/core", &core).await;

    let cfg = base_config(&server, Duration::from_secs(10));
    let (harness, _db) = Harness::without_reviewer(server, cfg).await;

    let (status, content_type, body) = harness.get("/@babel%2fcore").await;

    assert_eq!(status, 200, "got body {body:?}");
    assert_eq!(content_type.as_deref(), Some("application/json"));
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("packument is JSON");
    assert_eq!(
        parsed["name"], "@babel/core",
        "the percent-decoded, slash-bearing name must reach the scanner intact"
    );
    assert_eq!(
        harness
            .upstream_hits(&format!("/{}", packument_path("@babel/core")))
            .await,
        1,
        "the scoped name must round-trip through to the upstream packument fetch"
    );
}

#[tokio::test]
async fn an_invalid_package_name_is_a_400_and_never_reaches_upstream() {
    let server = MockServer::start().await;
    let cfg = base_config(&server, Duration::from_secs(10));
    let (harness, _db) = Harness::without_reviewer(server, cfg).await;

    let (status, _content_type, body) = harness.get("/../../etc/passwd").await;

    assert_eq!(status, 400, "got body {body:?}");
    assert_eq!(
        harness.total_upstream_hits().await,
        0,
        "an invalid path must never reach upstream"
    );
}

#[tokio::test]
async fn an_unknown_package_is_a_404() {
    let server = MockServer::start().await;
    // No packument mock for `ghost`: wiremock answers 404, exactly as
    // `tests/scan_npm.rs` relies on for the same situation.
    let cfg = base_config(&server, Duration::from_secs(10));
    let (harness, _db) = Harness::without_reviewer(server, cfg).await;

    let (status, _content_type, body) = harness.get("/ghost").await;

    assert_eq!(status, 404, "got body {body:?}");
}

#[tokio::test]
async fn a_budget_exhausted_cascade_answers_retryable() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let budget = Duration::from_millis(400);
    let cfg = base_config(&server, budget);
    let (harness, _db) = Harness::with_reviewer(server, cfg, Duration::from_secs(3)).await;

    let started = Instant::now();
    let (status, content_type, body) = harness.get("/demo").await;
    let elapsed = started.elapsed();

    assert_eq!(
        status, 429,
        "an in-progress scan maps to the same retryable status the PyPI and \
         cargo paths use, got body {body:?}"
    );
    assert_eq!(
        content_type.as_deref(),
        Some("text/plain; charset=utf-8"),
        "the in-progress response is the shared reason-phrase response"
    );
    assert!(
        elapsed < budget + Duration::from_secs(2),
        "the request took {elapsed:?}, over the {budget:?} budget plus tolerance"
    );
}

// ---------------------------------------------------------------------------
// The audit stub routes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_audit_endpoints_answer_404_and_never_reach_upstream() {
    let server = MockServer::start().await;
    let cfg = base_config(&server, Duration::from_secs(10));
    let (harness, _db) = Harness::without_reviewer(server, cfg).await;

    let (bulk_status, _ct, _body) = harness.post("/-/npm/v1/security/advisories/bulk").await;
    let (quick_status, _ct, _body) = harness.post("/-/npm/v1/security/audits/quick").await;

    assert_eq!(bulk_status, 404);
    assert_eq!(quick_status, 404);
    assert_eq!(
        harness.total_upstream_hits().await,
        0,
        "the org's dependency tree must never be shipped to the real \
         registry through either audit endpoint"
    );
}

// ---------------------------------------------------------------------------
// The auxiliary routes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ping_answers_success() {
    let server = MockServer::start().await;
    let cfg = base_config(&server, Duration::from_secs(10));
    let (harness, _db) = Harness::without_reviewer(server, cfg).await;

    let (status, _content_type, _body) = harness.get("/-/ping").await;

    assert_eq!(status, 200);
}

#[tokio::test]
async fn healthz_refusals_why_and_api_reviews_all_resolve_on_this_router() {
    let server = MockServer::start().await;
    let cfg = base_config(&server, Duration::from_secs(10));
    let (harness, _db) = Harness::without_reviewer(server, cfg).await;

    let (healthz_status, _ct, _body) = harness.get("/healthz").await;
    assert_eq!(healthz_status, 200);

    let (refusals_status, refusals_ct, _body) = harness.get("/refusals").await;
    assert_eq!(refusals_status, 200);
    assert_eq!(refusals_ct.as_deref(), Some("text/html; charset=utf-8"));

    let (why_status, why_ct, why_body) = harness.get("/why/does-not-exist").await;
    assert_eq!(why_status, 404);
    assert_eq!(why_ct.as_deref(), Some("text/html; charset=utf-8"));
    assert!(
        why_body.contains("unknown or has expired"),
        "the real why handler must have run, got {why_body:?}"
    );

    let (reviews_status, reviews_ct, reviews_body) = harness.get("/api/reviews").await;
    assert_eq!(
        reviews_status, 404,
        "no [ai_review] table is configured in this harness"
    );
    assert_eq!(reviews_ct.as_deref(), Some("text/plain; charset=utf-8"));
    assert!(reviews_body.contains("not found"));
}

// ---------------------------------------------------------------------------
// Write and auth endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_write_method_is_refused_with_an_explanation_and_never_reaches_upstream() {
    let server = MockServer::start().await;
    let cfg = base_config(&server, Duration::from_secs(10));
    let (harness, _db) = Harness::without_reviewer(server, cfg).await;

    // The shapes `npm publish`, `npm login`, `npm token` and `npm dist-tag`
    // actually send.
    for (method, target) in [
        ("PUT", "/demo"),
        ("PUT", "/@babel/core"),
        ("POST", "/demo"),
        ("PATCH", "/demo"),
        ("DELETE", "/demo"),
    ] {
        let (status, content_type, body) = harness.request(method, target).await;
        assert_eq!(
            status, 403,
            "{method} {target} must be refused, got {body:?}"
        );
        assert_eq!(
            content_type.as_deref(),
            Some("text/plain; charset=utf-8"),
            "{method} {target} must answer a readable explanation"
        );
        assert!(
            body.contains("read-only"),
            "{method} {target} must say this is a read-only gateway, got {body:?}"
        );
    }

    assert_eq!(
        harness.total_upstream_hits().await,
        0,
        "a write request must never reach the public registry; a proxied \
         publish would be a data-egress change nobody asked for"
    );
}

#[tokio::test]
async fn the_audit_stubs_still_answer_post_despite_the_write_refusal() {
    let server = MockServer::start().await;
    let cfg = base_config(&server, Duration::from_secs(10));
    let (harness, _db) = Harness::without_reviewer(server, cfg).await;

    // A static route must beat the wildcard, so these keep their 404 stub
    // rather than inheriting the write refusal.
    let (bulk_status, _ct, _body) = harness.post("/-/npm/v1/security/advisories/bulk").await;
    let (quick_status, _ct, _body) = harness.post("/-/npm/v1/security/audits/quick").await;

    assert_eq!(bulk_status, 404);
    assert_eq!(quick_status, 404);
    assert_eq!(harness.total_upstream_hits().await, 0);
}

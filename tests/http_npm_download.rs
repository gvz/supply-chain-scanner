//! Integration tests for `supply_chain_scanner::http::npm_download`: the
//! npm tarball gate, which requires a packument-gate approval before it
//! consults the organization's plugins.
//!
//! Every test drives the real `npm_router` over real HTTP/1.1 on
//! loopback, with a `wiremock` stand-in for the npm registry. The plugin
//! seam is a `SandboxRunner` stub, so no test runs `bwrap` or a real
//! plugin binary. Nothing here talks to a model provider or to a real
//! registry.
//!
//! Approval is seeded directly into the `VerdictStore` rather than bought
//! with a real AI review. That is faithful to production: the packument
//! gate writes exactly this durable `Clean` verdict for every version it
//! forwards, and `approved_for_download` reads it and nothing else. See
//! `tests/scan_npm.rs` for the review that writes it in the first place.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use flate2::write::GzEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::audit::AuditLog;
use supply_chain_scanner::config::{
    AllowEntry, AuditConfig, Config, ConfigHandle, CveLine, NpmRegistryConfig, PluginConfig,
    UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::review::ReviewStore;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::npm::packument::{DeclaredDigest, DigestAlgorithm};
use supply_chain_scanner::ecosystem::npm::packument_path;
use supply_chain_scanner::ecosystem::npm::upstream::NpmUpstream;
use supply_chain_scanner::http::npm_packument::{npm_router, NpmAppState};
use supply_chain_scanner::model::{ArtifactKey, RefusalReason, Verdict};
use supply_chain_scanner::plugin::{PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec};
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::coordinator::ScanCoordinator;
use supply_chain_scanner::scan::npm::{artifact_key, NpmScanner};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

fn base_config(server: &MockServer, plugin_binary: PathBuf) -> Config {
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
        plugins: vec![PluginConfig {
            name: "yara".to_string(),
            binary: plugin_binary,
            timeout: Duration::from_secs(5),
        }],
        max_concurrent_scans: None,
        ai_review: None,
        cargo_registry: None,
        npm_registry: Some(NpmRegistryConfig {
            upstream_registry_url: Url::parse(&format!("{}/", server.uri())).expect("valid url"),
            scan_budget: Duration::from_secs(10),
            max_packument_bytes: 67_108_864,
            min_release_age_days: None,
        }),
        audit: AuditConfig::default(),
    }
}

fn sha1_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// One published version's tarball bytes: a gzipped tar holding a minimal
/// `package/package.json`, which is what `unpack` expects to find.
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

/// A published version of a test package: its bytes, the shasum the
/// packument's `dist` declares for them, and the unscoped filename npm
/// would publish it under.
struct Version {
    vers: &'static str,
    unscoped: &'static str,
    bytes: Vec<u8>,
    shasum: String,
}

fn version(unscoped: &'static str, vers: &'static str) -> Version {
    let bytes = tarball_bytes(unscoped, vers);
    let shasum = sha1_hex(&bytes);
    Version {
        vers,
        unscoped,
        bytes,
        shasum,
    }
}

/// Mounts `name`'s packument, built with the crate's own `packument_path`
/// so a scoped name's `%2f` separator matches what the upstream client
/// sends.
async fn mount_packument(server: &MockServer, name: &str, versions: &[Version]) {
    let entries: String = versions
        .iter()
        .map(|v| {
            format!(
                r#""{vers}":{{"version":"{vers}","dist":{{"tarball":"{uri}/{name}/-/{un}-{vers}.tgz","shasum":"{shasum}"}}}}"#,
                vers = v.vers,
                uri = server.uri(),
                name = name,
                un = v.unscoped,
                shasum = v.shasum,
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let latest = versions.last().map(|v| v.vers).unwrap_or("");
    let body = format!(
        r#"{{"name":"{name}","versions":{{{entries}}},"dist-tags":{{"latest":"{latest}"}},"time":{{}}}}"#
    );

    Mock::given(method("GET"))
        .and(path(format!("/{}", packument_path(name))))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
        .await;
}

async fn mount_tarball(server: &MockServer, name: &str, v: &Version) {
    Mock::given(method("GET"))
        .and(path(format!("/{name}/-/{}-{}.tgz", v.unscoped, v.vers)))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(v.bytes.clone()))
        .mount(server)
        .await;
}

/// The artifact key the packument gate would derive for `v`, which is
/// also the key `approved_for_download` derives. Seeding a verdict under
/// this key is exactly what the packument cascade does after a pass.
fn key_for(name: &str, v: &Version) -> ArtifactKey {
    let digest = DeclaredDigest {
        algorithm: DigestAlgorithm::Sha1,
        hex: v.shasum.clone(),
    };
    artifact_key(name, name, v.vers, &digest)
}

// ---------------------------------------------------------------------------
// The plugin stub
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum Behaviour {
    Clean,
    Block(String),
    SlowThenClean(Duration),
}

struct StubSandbox {
    behaviour: Behaviour,
    calls: AtomicUsize,
}

impl StubSandbox {
    fn new(behaviour: Behaviour) -> Arc<Self> {
        Arc::new(Self {
            behaviour,
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SandboxRunner for StubSandbox {
    fn run(&self, _spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.behaviour {
            Behaviour::Clean => Ok(SandboxOutcome {
                exit_code: Some(0),
                output: String::new(),
                timed_out: false,
                signal: None,
            }),
            Behaviour::Block(message) => Ok(SandboxOutcome {
                exit_code: Some(1),
                output: message.clone(),
                timed_out: false,
                signal: None,
            }),
            Behaviour::SlowThenClean(duration) => {
                std::thread::sleep(*duration);
                Ok(SandboxOutcome {
                    exit_code: Some(0),
                    output: String::new(),
                    timed_out: false,
                    signal: None,
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The router under test
// ---------------------------------------------------------------------------

struct Harness {
    _db_dir: tempfile::TempDir,
    _cache_dir: tempfile::TempDir,
    server: MockServer,
    addr: std::net::SocketAddr,
    sandbox: Arc<StubSandbox>,
    verdicts: Arc<VerdictStore>,
    artifact_cache: Arc<ArtifactCache>,
    fingerprint: String,
    _listener: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start(server: MockServer, behaviour: Behaviour) -> Harness {
        Self::start_with(server, behaviour, |_cfg| {}).await
    }

    /// Like [`Harness::start`], but `configure` runs on the built `Config`
    /// before the policy and scanner are constructed from it — the seam
    /// the allowlist tests use to add a `[[allowlist]]` entry.
    async fn start_with(
        server: MockServer,
        behaviour: Behaviour,
        configure: impl FnOnce(&mut Config),
    ) -> Harness {
        let (db_dir, db) = open_db();
        let plugin_dir = tempfile::tempdir().expect("plugin dir");
        let plugin_binary = plugin_dir.path().join("yara");
        std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");
        // Keep the plugin directory alive for the harness's lifetime.
        std::mem::forget(plugin_dir);

        let mut cfg = base_config(&server, plugin_binary);
        configure(&mut cfg);
        let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");

        let policy = Arc::new(Policy::build(Arc::new(cfg.clone())).expect("build policy"));
        let config_handle = Arc::new(ConfigHandle::new(cfg));
        let cache_dir = tempfile::tempdir().expect("cache dir");

        let sandbox = StubSandbox::new(behaviour);
        let artifact_cache = Arc::new(
            ArtifactCache::new(db.clone(), cache_dir.path().join("artifacts"))
                .expect("create artifact cache"),
        );

        let scanner = NpmScanner::new(
            NpmUpstream::with_limits(base.clone(), 67_108_864, &Default::default())
                .expect("scanner upstream"),
            AdvisoryStore::new(db.clone()),
            VerdictStore::new(db.clone()),
            Arc::clone(&policy),
            // The download gate never reviews inline, so no reviewer is
            // needed to exercise it.
            None,
            Arc::clone(&config_handle),
            Arc::new(ScanCoordinator::new()),
            Arc::clone(&artifact_cache),
        );

        let verdicts = Arc::new(VerdictStore::new(db.clone()));
        let fingerprint = policy.fingerprint().to_string();

        let app = npm_router(NpmAppState {
            npm_scanner: Arc::new(scanner),
            config: config_handle,
            upstream: Arc::new(
                NpmUpstream::with_limits(base, 67_108_864, &Default::default())
                    .expect("download upstream"),
            ),
            verdicts: Arc::clone(&verdicts),
            plugins: Arc::new(PluginRunner::new(sandbox.clone())),
            artifact_cache: Arc::clone(&artifact_cache),
            reviews: Arc::new(ReviewStore::new(db.clone())),
            plugin_run_coordinator: Arc::new(ScanCoordinator::new()),
            // These tests are about the tarball gate's own behaviour, not
            // the fetch audit log (that is `tests/http_audit_npm.rs`), so
            // a discarding writer is enough to keep every request from
            // 500ing on the new fail-closed write.
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

        Harness {
            _db_dir: db_dir,
            _cache_dir: cache_dir,
            server,
            addr,
            sandbox,
            verdicts,
            artifact_cache,
            fingerprint,
            _listener: served,
        }
    }

    /// Seeds the durable `Clean` verdict the packument gate writes when it
    /// forwards a version.
    fn approve(&self, key: &ArtifactKey) {
        self.verdicts
            .put(key, &Verdict::Clean, &self.fingerprint)
            .expect("store the packument gate's clean verdict");
    }

    fn block(&self, key: &ArtifactKey, reason: RefusalReason) {
        self.verdicts
            .put(key, &Verdict::Blocked(reason), &self.fingerprint)
            .expect("store a blocked verdict");
    }

    /// One request through hyper's HTTP/1.1 client, so the target reaches
    /// the server exactly as written — unencoded `/` segments included.
    async fn get(&self, target: &str) -> (u16, String) {
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

        let response = sender.send_request(request).await.expect("send request");
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(axum::body::Body::new(response.into_body()), usize::MAX)
            .await
            .expect("read the body");
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    async fn hits(&self, path: &str) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| request.url.path() == path)
            .count()
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_approved_artifact_passes_the_plugins_and_is_served() {
    let server = MockServer::start().await;
    let v = version("demo", "1.0.0");
    mount_packument(&server, "demo", &[version("demo", "1.0.0")]).await;
    mount_tarball(&server, "demo", &v).await;

    let harness = Harness::start(server, Behaviour::Clean).await;
    harness.approve(&key_for("demo", &v));

    let (status, body) = harness.get("/demo/-/demo-1.0.0.tgz").await;

    assert_eq!(status, 200, "got body {body:?}");
    assert_eq!(harness.sandbox.calls(), 1, "the plugin must run once");
    assert_eq!(harness.hits("/demo/-/demo-1.0.0.tgz").await, 1);
}

#[tokio::test]
async fn a_version_the_packument_gate_never_approved_is_refused_without_a_download() {
    let server = MockServer::start().await;
    let v = version("demo", "1.0.0");
    mount_packument(&server, "demo", &[version("demo", "1.0.0")]).await;
    mount_tarball(&server, "demo", &v).await;

    let harness = Harness::start(server, Behaviour::Clean).await;
    // No stored verdict: the packument gate never admitted this version.

    let (status, body) = harness.get("/demo/-/demo-1.0.0.tgz").await;

    assert_eq!(status, 403, "got body {body:?}");
    assert!(
        body.contains("not-packument-approved"),
        "the refusal must name the missing admission, got {body:?}"
    );
    assert_eq!(
        harness.hits("/demo/-/demo-1.0.0.tgz").await,
        0,
        "no tarball bytes may be fetched for an unapproved version"
    );
    assert_eq!(
        harness.sandbox.calls(),
        0,
        "no plugin may run for an unapproved version"
    );
}

#[tokio::test]
async fn a_failing_plugin_refuses_with_a_reason_phrase_and_a_why_link() {
    let server = MockServer::start().await;
    let v = version("demo", "1.0.0");
    mount_packument(&server, "demo", &[version("demo", "1.0.0")]).await;
    mount_tarball(&server, "demo", &v).await;

    let harness = Harness::start(server, Behaviour::Block("malware found".to_string())).await;
    harness.approve(&key_for("demo", &v));

    let (status, body) = harness.get("/demo/-/demo-1.0.0.tgz").await;

    assert_eq!(status, 403, "got body {body:?}");
    assert!(
        body.contains("BLOCKED"),
        "the refusal phrase must carry BLOCKED, got {body:?}"
    );
    assert!(
        body.contains("/why/"),
        "a stored block must link to its explanation, got {body:?}"
    );
    assert_eq!(harness.sandbox.calls(), 1);
}

#[tokio::test]
async fn a_stored_block_is_refused_without_contacting_upstream() {
    let server = MockServer::start().await;
    let v = version("demo", "1.0.0");
    mount_packument(&server, "demo", &[version("demo", "1.0.0")]).await;
    mount_tarball(&server, "demo", &v).await;

    let harness = Harness::start(server, Behaviour::Clean).await;
    harness.block(
        &key_for("demo", &v),
        RefusalReason {
            code: "ai-review:malicious".to_string(),
            detail: "the reviewer refused this package".to_string(),
        },
    );

    let (status, body) = harness.get("/demo/-/demo-1.0.0.tgz").await;

    assert_eq!(status, 403, "got body {body:?}");
    assert_eq!(
        harness.hits("/demo/-/demo-1.0.0.tgz").await,
        0,
        "a stored block must be answered without fetching bytes"
    );
    assert_eq!(harness.sandbox.calls(), 0);
}

#[tokio::test]
async fn an_already_plugin_checked_artifact_is_served_without_rerunning_plugins() {
    let server = MockServer::start().await;
    let v = version("demo", "1.0.0");
    mount_packument(&server, "demo", &[version("demo", "1.0.0")]).await;
    mount_tarball(&server, "demo", &v).await;

    let harness = Harness::start(server, Behaviour::Clean).await;
    let key = key_for("demo", &v);
    harness.approve(&key);
    harness
        .verdicts
        .mark_plugin_checked(&key, &harness.fingerprint)
        .expect("mark plugin-checked");

    // Seed the cache so the fast path has bytes to serve.
    let stage = tempfile::tempdir().expect("stage dir");
    let staged = stage.path().join(&key.filename);
    std::fs::write(&staged, &v.bytes).expect("write staged bytes");
    harness
        .artifact_cache
        .insert(&key, &staged)
        .expect("insert into the artifact cache");

    let (status, body) = harness.get("/demo/-/demo-1.0.0.tgz").await;

    assert_eq!(status, 200, "got body {body:?}");
    assert_eq!(
        harness.sandbox.calls(),
        0,
        "an already plugin-checked artifact must not run the plugins again"
    );
    assert_eq!(
        harness.hits("/demo/-/demo-1.0.0.tgz").await,
        0,
        "the cached bytes must be served without contacting upstream"
    );
}

#[tokio::test]
async fn a_digest_mismatch_is_refused_even_for_an_approved_version() {
    let server = MockServer::start().await;
    let good = version("demo", "1.0.0");
    mount_packument(&server, "demo", &[version("demo", "1.0.0")]).await;

    // Upstream serves bytes that do not match the shasum its own
    // packument declared for them.
    let mut tampered = good.bytes.clone();
    tampered.extend_from_slice(b"tampered");
    Mock::given(method("GET"))
        .and(path("/demo/-/demo-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tampered))
        .mount(&server)
        .await;

    let harness = Harness::start(server, Behaviour::Clean).await;
    harness.approve(&key_for("demo", &good));

    let (status, body) = harness.get("/demo/-/demo-1.0.0.tgz").await;

    assert_ne!(status, 200, "mismatched bytes must never be served");
    assert!(
        status >= 400,
        "the refusal must be an error status, got {status} with body {body:?}"
    );
    assert_eq!(
        harness.sandbox.calls(),
        0,
        "the plugins must not see bytes that failed verification"
    );
}

#[tokio::test]
async fn two_concurrent_first_downloads_run_the_plugin_set_once_between_them() {
    let server = MockServer::start().await;
    let v = version("demo", "1.0.0");
    mount_packument(&server, "demo", &[version("demo", "1.0.0")]).await;
    mount_tarball(&server, "demo", &v).await;

    let harness =
        Harness::start(server, Behaviour::SlowThenClean(Duration::from_millis(150))).await;
    harness.approve(&key_for("demo", &v));

    let first = harness.get("/demo/-/demo-1.0.0.tgz");
    let second = harness.get("/demo/-/demo-1.0.0.tgz");
    let (a, b) = tokio::join!(first, second);

    assert_eq!(a.0, 200, "first request body {:?}", a.1);
    assert_eq!(b.0, 200, "second request body {:?}", b.1);
    assert_eq!(
        harness.sandbox.calls(),
        1,
        "two concurrent first downloads must share one plugin run"
    );
}

#[tokio::test]
async fn a_scoped_package_tarball_path_routes_and_is_served() {
    let server = MockServer::start().await;
    let v = version("core", "7.0.0");
    mount_packument(&server, "@babel/core", &[version("core", "7.0.0")]).await;
    mount_tarball(&server, "@babel/core", &v).await;

    let harness = Harness::start(server, Behaviour::Clean).await;
    harness.approve(&key_for("@babel/core", &v));

    // The literal, unencoded slash of a scoped package.
    let (status, body) = harness.get("/@babel/core/-/core-7.0.0.tgz").await;

    assert_eq!(
        status, 200,
        "a scoped tarball path must route rather than be rejected: {body:?}"
    );
    assert_eq!(harness.sandbox.calls(), 1);
}

#[tokio::test]
async fn a_tarball_filename_that_does_not_match_its_package_is_a_400() {
    let server = MockServer::start().await;
    let v = version("demo", "1.0.0");
    mount_packument(&server, "demo", &[version("demo", "1.0.0")]).await;
    mount_tarball(&server, "demo", &v).await;

    let harness = Harness::start(server, Behaviour::Clean).await;
    harness.approve(&key_for("demo", &v));

    let (status, body) = harness.get("/demo/-/other-1.0.0.tgz").await;

    assert_eq!(status, 400, "got body {body:?}");
    assert_eq!(harness.sandbox.calls(), 0);
}

#[tokio::test]
async fn a_path_traversal_in_the_tarball_filename_is_a_400() {
    let server = MockServer::start().await;
    let harness = Harness::start(server, Behaviour::Clean).await;

    let (status, body) = harness.get("/demo/-/demo-../../etc/passwd.tgz").await;

    assert_eq!(status, 400, "got body {body:?}");
    assert_eq!(harness.sandbox.calls(), 0);
}

// ---------------------------------------------------------------------------
// I2: an allowlisted version has no stored verdict (the packument gate
// never reviews an allowlisted survivor), so it must still be downloadable
// here, with its digest verified regardless.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_allowlisted_never_reviewed_version_downloads_with_its_digest_verified() {
    let server = MockServer::start().await;
    let v = version("demo", "1.0.0");
    mount_packument(&server, "demo", &[version("demo", "1.0.0")]).await;
    mount_tarball(&server, "demo", &v).await;

    let harness = Harness::start_with(server, Behaviour::Clean, |cfg| {
        cfg.allowlist = vec![AllowEntry {
            package: "demo".to_string(),
            version: "1.0.0".to_string(),
        }];
    })
    .await;

    assert_eq!(
        harness
            .verdicts
            .get(&key_for("demo", &v), &harness.fingerprint)
            .expect("read the verdict store"),
        None,
        "this test only means something without a stored verdict to fall back on: the \
         packument gate never reviews an allowlisted survivor"
    );

    let (status, body) = harness.get("/demo/-/demo-1.0.0.tgz").await;

    assert_eq!(
        status, 200,
        "an allowlisted version with no stored verdict must still be served: {body:?}"
    );
    assert_eq!(
        harness.sandbox.calls(),
        1,
        "the allowlist lifts the judgement checks, never the plugin gate"
    );
    assert_eq!(harness.hits("/demo/-/demo-1.0.0.tgz").await, 1);
}

#[tokio::test]
async fn a_digest_mismatch_on_an_allowlisted_version_is_still_refused() {
    let server = MockServer::start().await;
    let good = version("demo", "1.0.0");
    mount_packument(&server, "demo", &[version("demo", "1.0.0")]).await;

    // Upstream serves bytes that do not match the shasum its own
    // packument declared for them.
    let mut tampered = good.bytes.clone();
    tampered.extend_from_slice(b"tampered");
    Mock::given(method("GET"))
        .and(path("/demo/-/demo-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tampered))
        .mount(&server)
        .await;

    let harness = Harness::start_with(server, Behaviour::Clean, |cfg| {
        cfg.allowlist = vec![AllowEntry {
            package: "demo".to_string(),
            version: "1.0.0".to_string(),
        }];
    })
    .await;

    let (status, body) = harness.get("/demo/-/demo-1.0.0.tgz").await;

    assert_ne!(
        status, 200,
        "mismatched bytes must never be served, even for an allowlisted version"
    );
    assert!(
        status >= 400,
        "the refusal must be an error status, got {status} with body {body:?}"
    );
    assert_eq!(
        harness.sandbox.calls(),
        0,
        "the plugins must not see bytes that failed verification"
    );
}

//! Integration tests for `supply_chain_scanner::http::cargo_download`: the
//! `.crate` download route and its org-plugin gate.
//!
//! Every test drives the real `cargo_router` over real HTTP/1.1 on
//! loopback, with a `wiremock` stand-in for the crates.io sparse index and
//! its `dl` endpoint. The plugin seam is a `SandboxRunner` stub, so no test
//! runs `bwrap` or a real plugin binary. Nothing here talks to a model
//! provider or to a real registry.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::config::{
    AllowEntry, AuditConfig, Config, ConfigHandle, CveLine, PluginConfig, UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::cargo_vet::CargoVetStore;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::cargo::index::index_path_for;
use supply_chain_scanner::ecosystem::cargo::upstream::CargoUpstream;
use supply_chain_scanner::http::cargo_index::{cargo_router, CargoAppState};
use supply_chain_scanner::model::{ArtifactKey, Verdict};
use supply_chain_scanner::plugin::{PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec};
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

fn base_config(plugin_binary: PathBuf) -> Config {
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
        plugins: vec![PluginConfig {
            name: "yara".to_string(),
            binary: plugin_binary,
            timeout: Duration::from_secs(5),
        }],
        max_concurrent_scans: None,
        ai_review: None,
        cargo_registry: None,
        npm_registry: None,
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

/// Builds a `.crate`'s bytes: a gzipped tar of a small, ordinary Rust
/// crate, wrapped in the `<name>-<version>/` directory cargo publishes.
fn crate_bytes(name: &str, vers: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(GzEncoder::new(&mut buf, Compression::fast()));
        let root = format!("{name}-{vers}");
        for (rel, body) in [
            (
                "Cargo.toml".to_string(),
                format!("[package]\nname = \"{name}\"\nversion = \"{vers}\"\n"),
            ),
            (
                "src/lib.rs".to_string(),
                "pub fn add(a: i32, b: i32) -> i32 { a + b }\n".to_string(),
            ),
        ] {
            let body = body.into_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            let entry_path = format!("{root}/{rel}");
            builder
                .append_data(&mut header, entry_path, &body[..])
                .expect("append crate entry");
        }
        builder.finish().expect("finish crate fixture");
    }
    buf
}

/// One published version of a test crate, plus the checksum the index file
/// declares for it. `declared_cksum` is separate from the bytes' real hash
/// so a test can make the two disagree.
struct Version {
    vers: String,
    bytes: Vec<u8>,
    declared_cksum: String,
}

fn version(name: &str, vers: &str) -> Version {
    let bytes = crate_bytes(name, vers);
    let declared_cksum = sha256_hex(&bytes);
    Version {
        vers: vers.to_string(),
        bytes,
        declared_cksum,
    }
}

fn with_wrong_cksum(mut v: Version) -> Version {
    v.declared_cksum = "0".repeat(64);
    v
}

/// Mounts the sparse index's `config.json`, one crate's index file, and
/// one download per version. The `dl` template points back at the
/// wiremock server, exactly as the proxy's own `config.json` points back
/// at the proxy.
async fn mount(server: &MockServer, name: &str, versions: &[&Version]) {
    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{{\"dl\":\"{}/crates/{{crate}}/{{version}}/download\"}}",
            server.uri()
        )))
        .mount(server)
        .await;

    let body: String = versions
        .iter()
        .map(|v| {
            format!(
                "{{\"name\":\"{name}\",\"vers\":\"{}\",\"cksum\":\"{}\",\"yanked\":false,\"deps\":[]}}\n",
                v.vers, v.declared_cksum
            )
        })
        .collect();
    Mock::given(method("GET"))
        .and(path(format!("/{}", index_path_for(name))))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
        .await;

    for v in versions {
        Mock::given(method("GET"))
            .and(path(format!("/crates/{name}/{}/download", v.vers)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(v.bytes.clone()))
            .mount(server)
            .await;
    }
}

// ---------------------------------------------------------------------------
// The plugin seam
// ---------------------------------------------------------------------------

/// What the plugin stub does when the gate runs it.
#[derive(Clone)]
enum Behaviour {
    /// Exits 0: the plugin ran and passed.
    Clean,
    /// Exits 1 with this stdout: the plugin ran and blocked.
    Block(String),
    /// The sandbox cannot run the plugin at all.
    CannotRun(String),
    /// Sleeps, then exits 0. Gives a concurrency test a window in which
    /// two requests for the same artifact are both genuinely in flight at
    /// once, rather than one finishing before the other starts.
    SlowThenClean(Duration),
}

/// A `SandboxRunner` stub that counts its invocations and answers with a
/// scripted outcome.
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
            Behaviour::CannotRun(message) => Err(anyhow::anyhow!(message.clone())),
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
    _plugin_dir: tempfile::TempDir,
    _cache_dir: tempfile::TempDir,
    server: MockServer,
    db: Db,
    fingerprint: String,
    sandbox: Arc<StubSandbox>,
    addr: std::net::SocketAddr,
    _served: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start(name: &str, versions: &[&Version], behaviour: Behaviour) -> Harness {
        Harness::start_with(name, versions, behaviour, |_| {}).await
    }

    /// Starts the router with a chance to adjust the config first: an
    /// allowlist entry, an extra plugin, a different CVE line.
    async fn start_with(
        name: &str,
        versions: &[&Version],
        behaviour: Behaviour,
        configure: impl FnOnce(&mut Config),
    ) -> Harness {
        let server = MockServer::start().await;
        mount(&server, name, versions).await;

        let (db_dir, db) = open_db();
        let cache_dir = tempfile::tempdir().expect("create cache temp dir");
        let plugin_dir = tempfile::tempdir().expect("create plugin temp dir");
        let plugin_binary = plugin_dir.path().join("yara");
        std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");

        let mut cfg = base_config(plugin_binary);
        configure(&mut cfg);
        let policy = Policy::build(Arc::new(cfg.clone())).expect("build policy");
        let fingerprint = policy.fingerprint().to_string();
        let config_handle = Arc::new(ConfigHandle::new(cfg));

        let base = Url::parse(&format!("{}/", server.uri())).expect("valid index base url");
        // Two clients against the same stand-in: one for the index cascade
        // (unused here), one for the download gate this test exercises.
        let scanner_upstream =
            CargoUpstream::with_limits(base.clone(), &Default::default()).expect("cargo upstream");
        let download_upstream =
            CargoUpstream::with_limits(base, &Default::default()).expect("cargo upstream");

        let sandbox = StubSandbox::new(behaviour);

        let scanner = CargoScanner::new(
            scanner_upstream,
            AdvisoryStore::new(db.clone()),
            CargoVetStore::new(db.clone()),
            VerdictStore::new(db.clone()),
            Arc::new(policy),
            None,
            Arc::clone(&config_handle),
            Arc::new(ScanCoordinator::new()),
        );

        let state = CargoAppState {
            cargo_scanner: Arc::new(scanner),
            config: config_handle,
            upstream: Arc::new(download_upstream),
            verdicts: Arc::new(VerdictStore::new(db.clone())),
            plugins: Arc::new(PluginRunner::new(sandbox.clone())),
            artifact_cache: Arc::new(
                ArtifactCache::new(db.clone(), cache_dir.path().join("artifacts"))
                    .expect("create artifact cache"),
            ),
            reviews: Arc::new(supply_chain_scanner::db::review::ReviewStore::new(
                db.clone(),
            )),
            plugin_run_coordinator: Arc::new(ScanCoordinator::new()),
        };

        let app = cargo_router(state);
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
            _plugin_dir: plugin_dir,
            _cache_dir: cache_dir,
            server,
            db,
            fingerprint,
            sandbox,
            addr,
            _served: served,
        }
    }

    /// One `GET` over hyper's HTTP/1.1 client. Returns the status, the
    /// `Content-Type`, the `Content-Length`, and the body bytes.
    async fn get(&self, target: &str) -> (u16, Option<String>, Option<String>, Vec<u8>) {
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
        let header = |name: hyper::header::HeaderName| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string())
        };
        let content_type = header(hyper::header::CONTENT_TYPE);
        let content_length = header(hyper::header::CONTENT_LENGTH);
        let body = axum::body::to_bytes(axum::body::Body::new(response.into_body()), usize::MAX)
            .await
            .expect("read the response body");
        (status, content_type, content_length, body.to_vec())
    }

    /// One `GET` read straight off the socket, so the status line's reason
    /// phrase can be asserted on the bytes that actually reach the wire.
    async fn status_line(&self, target: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut client = tokio::net::TcpStream::connect(self.addr)
            .await
            .expect("connect to the test server");
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.addr
        );
        client
            .write_all(request.as_bytes())
            .await
            .expect("write request");

        let mut raw = Vec::new();
        client
            .read_to_end(&mut raw)
            .await
            .expect("read the response");
        let raw = String::from_utf8_lossy(&raw);
        raw.lines()
            .next()
            .expect("response has a status line")
            .to_string()
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

    /// Starts a harness in which every one of `versions` already carries
    /// the `Clean` verdict the index gate stores when its cascade admits
    /// the version. This is the state a real `.crate` download runs in: a
    /// version is only downloadable here because the index gate admitted
    /// it first.
    async fn start_index_approved(
        name: &str,
        versions: &[&Version],
        behaviour: Behaviour,
    ) -> Harness {
        let harness = Harness::start(name, versions, behaviour).await;
        for v in versions {
            harness.seed_clean_verdict(&key(name, &v.vers, &v.declared_cksum));
        }
        harness
    }

    /// Stores the `Clean` verdict the index cascade stores for a version
    /// it admitted, without the plugin-checked flag: exactly the state the
    /// download gate has to run the plugins against.
    fn seed_clean_verdict(&self, key: &ArtifactKey) {
        VerdictStore::new(self.db.clone())
            .put(key, &Verdict::Clean, &self.fingerprint)
            .expect("seed the index gate's clean verdict");
    }

    /// The verdict stored for one artifact, under this harness's policy
    /// fingerprint.
    fn stored_verdict(&self, key: &ArtifactKey) -> Option<Verdict> {
        VerdictStore::new(self.db.clone())
            .get(key, &self.fingerprint)
            .expect("read the stored verdict")
            .map(|stored| stored.verdict)
    }

    fn plugin_checked(&self, key: &ArtifactKey) -> bool {
        VerdictStore::new(self.db.clone())
            .is_plugin_checked(key, &self.fingerprint)
            .expect("read the plugin-checked flag")
    }
}

fn key(name: &str, vers: &str, cksum: &str) -> ArtifactKey {
    ArtifactKey {
        ecosystem: "cargo".to_string(),
        package: name.to_string(),
        version: vers.to_string(),
        filename: format!("{name}-{vers}.crate"),
        sha256: cksum.to_string(),
    }
}

fn download_target(name: &str, vers: &str) -> String {
    format!("/crates/{name}/{vers}/download")
}

/// The `dl` path the stand-in upstream serves one version's bytes at.
fn upstream_download_path(name: &str, vers: &str) -> String {
    format!("/crates/{name}/{vers}/download")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_first_download_of_a_clean_artifact_runs_plugins_and_serves_the_bytes() {
    let v = version("demo-crate", "1.0.0");
    let harness = Harness::start_index_approved("demo-crate", &[&v], Behaviour::Clean).await;
    harness.server.reset().await;
    mount(&harness.server, "demo-crate", &[&v]).await;

    let (status, content_type, content_length, body) =
        harness.get(&download_target("demo-crate", "1.0.0")).await;

    assert_eq!(status, 200, "a clean first download must be served");
    assert_eq!(
        content_type.as_deref(),
        Some("application/gzip"),
        "a .crate is a gzipped tar"
    );
    assert_eq!(
        content_length.as_deref(),
        Some(body.len().to_string().as_str()),
        "the response must declare the length of what it sends"
    );
    assert_eq!(
        body, v.bytes,
        "the served bytes must be upstream's .crate bytes"
    );
    assert_eq!(
        harness.sandbox.calls(),
        1,
        "the plugin must run exactly once on the first download"
    );

    let stored = harness
        .stored_verdict(&key("demo-crate", "1.0.0", &v.declared_cksum))
        .expect("a clean verdict must be stored");
    assert_eq!(stored, Verdict::Clean);
    assert!(
        harness.plugin_checked(&key("demo-crate", "1.0.0", &v.declared_cksum)),
        "the verdict must be marked plugin-checked"
    );
}

#[tokio::test]
async fn the_download_route_takes_precedence_over_the_catch_all_index_route() {
    // The cargo router has a `/{*path}` catch-all for the sparse index.
    // This test pins that the static `/crates/{crate}/{version}/download`
    // route wins over it: an index handler answering instead would return
    // a 400 (the path is not a valid index path) and would never reach the
    // plugin gate.
    let v = version("demo-crate", "1.0.0");
    let harness = Harness::start_index_approved("demo-crate", &[&v], Behaviour::Clean).await;

    let (download_status, download_type, _, _) =
        harness.get(&download_target("demo-crate", "1.0.0")).await;
    assert_eq!(download_status, 200);
    assert_eq!(download_type.as_deref(), Some("application/gzip"));

    // The catch-all still serves the index paths it is meant for.
    // The index cascade forwards nothing here (no cargo-vet coverage and
    // no reviewer), so the body is empty — but its status and media type
    // prove the index handler, not the download handler, answered.
    let (index_status, index_type, _, _) = harness
        .get(&format!("/{}", index_path_for("demo-crate")))
        .await;
    assert_eq!(index_status, 200);
    assert_eq!(index_type.as_deref(), Some("text/plain; charset=utf-8"));

    // And a malformed index path still reaches the index handler's
    // validator rather than the download route.
    let (malformed_status, _, _, _) = harness.get("/../../etc/passwd").await;
    assert_eq!(malformed_status, 400);
}

#[tokio::test]
async fn a_plugin_refusal_is_a_403_with_a_reason_phrase_and_a_why_link() {
    let v = version("demo-crate", "1.0.0");
    let harness = Harness::start_index_approved(
        "demo-crate",
        &[&v],
        Behaviour::Block("malware found".to_string()),
    )
    .await;

    let (status, _, _, body) = harness.get(&download_target("demo-crate", "1.0.0")).await;
    assert_eq!(status, 403, "a plugin block must be a 403");

    let body = String::from_utf8(body).expect("the refusal body is UTF-8");
    assert!(
        body.contains("plugin:yara"),
        "the body must name the check code: {body}"
    );

    let status_line = harness
        .status_line(&download_target("demo-crate", "1.0.0"))
        .await;
    assert!(
        status_line.starts_with("HTTP/1.1 403 "),
        "expected a 403 status line, got {status_line:?}"
    );
    assert!(
        status_line.contains("plugin:yara"),
        "the reason phrase must name the plugin: {status_line:?}"
    );
    assert!(
        status_line.contains("/why/"),
        "the reason phrase must carry a /why link: {status_line:?}"
    );

    let stored = harness
        .stored_verdict(&key("demo-crate", "1.0.0", &v.declared_cksum))
        .expect("a blocked verdict must be stored");
    match stored {
        Verdict::Blocked(reason) => assert_eq!(reason.code, "plugin:yara"),
        Verdict::Clean => panic!("a plugin block must be stored as blocked"),
    }
}

#[tokio::test]
async fn a_second_download_of_the_same_artifact_does_not_re_run_plugins() {
    let v = version("demo-crate", "1.0.0");
    let harness = Harness::start_index_approved("demo-crate", &[&v], Behaviour::Clean).await;
    let target = download_target("demo-crate", "1.0.0");

    let (first_status, _, _, first_body) = harness.get(&target).await;
    assert_eq!(first_status, 200);
    assert_eq!(harness.sandbox.calls(), 1);

    let (second_status, second_type, _, second_body) = harness.get(&target).await;
    assert_eq!(second_status, 200);
    assert_eq!(second_type.as_deref(), Some("application/gzip"));
    assert_eq!(second_body, first_body);
    assert_eq!(
        harness.sandbox.calls(),
        1,
        "a second download of the same artifact must not re-run the plugins"
    );
    assert_eq!(
        harness
            .upstream_hits(&upstream_download_path("demo-crate", "1.0.0"))
            .await,
        1,
        "the second download must be served from the cache, not re-fetched"
    );
}

#[tokio::test]
async fn two_concurrent_first_downloads_of_the_same_artifact_only_run_the_plugin_once() {
    // Without `CargoAppState::plugin_run_coordinator`, two requests that
    // both arrive before either has stored a verdict would each
    // independently download, unpack, and run the plugin set. The slow
    // behaviour gives both requests a real window to be in flight at
    // once, rather than the first completing (and caching its verdict)
    // before the second even starts.
    let v = version("demo-crate", "1.0.0");
    let harness = Harness::start_index_approved(
        "demo-crate",
        &[&v],
        Behaviour::SlowThenClean(Duration::from_millis(200)),
    )
    .await;
    let target = download_target("demo-crate", "1.0.0");

    let (first, second) = tokio::join!(harness.get(&target), harness.get(&target));

    assert_eq!(first.0, 200, "the first concurrent download must succeed");
    assert_eq!(second.0, 200, "the second concurrent download must succeed");
    assert_eq!(
        first.3, v.bytes,
        "the first response must carry the real .crate bytes"
    );
    assert_eq!(
        second.3, v.bytes,
        "the second response must carry the real .crate bytes too, whether \
         it owned the plugin run or joined the other request's"
    );
    assert_eq!(
        harness.sandbox.calls(),
        1,
        "two concurrent first-touch downloads of the same artifact must run \
         the plugin set exactly once between them, not once each"
    );
    assert_eq!(
        harness
            .upstream_hits(&upstream_download_path("demo-crate", "1.0.0"))
            .await,
        1,
        "only the owning request should have fetched the .crate bytes from \
         upstream; a joiner reuses them from the artifact cache"
    );

    let stored = harness
        .stored_verdict(&key("demo-crate", "1.0.0", &v.declared_cksum))
        .expect("a clean verdict must be stored exactly once");
    assert_eq!(stored, Verdict::Clean);
    assert!(harness.plugin_checked(&key("demo-crate", "1.0.0", &v.declared_cksum)));
}

#[tokio::test]
async fn a_second_download_re_verifies_the_hash_when_the_cache_entry_is_gone() {
    let v = version("demo-crate", "1.0.0");
    let harness = Harness::start_index_approved("demo-crate", &[&v], Behaviour::Clean).await;
    let target = download_target("demo-crate", "1.0.0");

    let (first_status, _, _, _) = harness.get(&target).await;
    assert_eq!(first_status, 200);
    assert_eq!(harness.sandbox.calls(), 1);

    // Empty the cache by hand, the way an operator pruning the cache
    // directory would.
    for entry in std::fs::read_dir(harness._cache_dir.path().join("artifacts"))
        .expect("read the cache root")
        .flatten()
    {
        if entry.path().is_dir() {
            for shard in std::fs::read_dir(entry.path())
                .expect("read a shard")
                .flatten()
            {
                std::fs::remove_file(shard.path()).expect("remove a cached file");
            }
        }
    }

    let (second_status, _, _, second_body) = harness.get(&target).await;
    assert_eq!(second_status, 200);
    assert_eq!(second_body, v.bytes);
    assert_eq!(
        harness.sandbox.calls(),
        1,
        "a re-downloaded, already plugin-checked artifact must not re-run the plugins"
    );
    assert_eq!(
        harness
            .upstream_hits(&upstream_download_path("demo-crate", "1.0.0"))
            .await,
        2,
        "the missing cache entry must be re-downloaded"
    );
}

#[tokio::test]
async fn a_hash_mismatch_is_refused_and_nothing_is_stored() {
    let good = version("demo-crate", "1.0.0");
    let lying = with_wrong_cksum(version("demo-crate", "1.0.0"));
    // Allowlisted, so the request reaches the integrity check on the
    // allowlist override rather than on a stored verdict. A seeded verdict
    // would make the "nothing is stored" assertion below vacuous.
    let harness = Harness::start_with("demo-crate", &[&lying], Behaviour::Clean, |cfg| {
        cfg.allowlist = vec![AllowEntry {
            package: "demo-crate".to_string(),
            version: "1.0.0".to_string(),
        }];
    })
    .await;

    let (status, _, _, body) = harness.get(&download_target("demo-crate", "1.0.0")).await;
    assert_eq!(
        status, 403,
        "bytes that do not match the index checksum must be refused"
    );
    let body = String::from_utf8(body).expect("the refusal body is UTF-8");
    assert!(
        body.contains("hash-mismatch"),
        "the refusal must name the hash mismatch: {body}"
    );
    assert_eq!(
        harness.sandbox.calls(),
        0,
        "the plugins must never see bytes that failed the hash check"
    );
    assert_eq!(
        harness.stored_verdict(&key("demo-crate", "1.0.0", &lying.declared_cksum)),
        None,
        "an unverified download must not leave a stored verdict"
    );
    assert!(
        !harness.plugin_checked(&key("demo-crate", "1.0.0", &good.declared_cksum)),
        "an unverified download must not be marked plugin-checked"
    );
}

#[tokio::test]
async fn a_plugin_that_could_not_run_is_a_503_not_a_stored_block() {
    let v = version("demo-crate", "1.0.0");
    // Allowlisted: this test is about what a plugin check that could not
    // run leaves in the store, so it must start with no stored verdict.
    let harness = Harness::start_with(
        "demo-crate",
        &[&v],
        Behaviour::CannotRun("no such sandbox namespace".to_string()),
        |cfg| {
            cfg.allowlist = vec![AllowEntry {
                package: "demo-crate".to_string(),
                version: "1.0.0".to_string(),
            }];
        },
    )
    .await;
    let target = download_target("demo-crate", "1.0.0");

    let (status, _, _, body) = harness.get(&target).await;
    assert_eq!(
        status, 503,
        "a plugin that could not run is unverifiable, never a block"
    );
    let body = String::from_utf8(body).expect("the refusal body is UTF-8");
    assert!(
        body.contains("UNVERIFIABLE"),
        "the body must say unverifiable: {body}"
    );
    assert_eq!(
        harness.stored_verdict(&key("demo-crate", "1.0.0", &v.declared_cksum)),
        None,
        "a check that could not run must not be stored as a durable block"
    );

    // And the next attempt tries again rather than serving a block.
    let (second_status, _, _, _) = harness.get(&target).await;
    assert_eq!(second_status, 503);
    assert_eq!(
        harness.sandbox.calls(),
        2,
        "an unverifiable plugin result must not be cached as a decision"
    );
}

#[tokio::test]
async fn an_unknown_version_is_404_and_never_downloads() {
    let v = version("demo-crate", "1.0.0");
    let harness = Harness::start("demo-crate", &[&v], Behaviour::Clean).await;

    let (status, _, _, _) = harness.get(&download_target("demo-crate", "2.0.0")).await;
    assert_eq!(status, 404, "a version the index does not list is a 404");
    assert_eq!(
        harness.sandbox.calls(),
        0,
        "no plugin runs for a version that does not exist"
    );
    assert_eq!(
        harness
            .upstream_hits(&upstream_download_path("demo-crate", "2.0.0"))
            .await,
        0,
        "a version the index does not list is never downloaded"
    );
}

#[tokio::test]
async fn an_unknown_crate_is_404() {
    let v = version("demo-crate", "1.0.0");
    let harness = Harness::start("demo-crate", &[&v], Behaviour::Clean).await;

    let (status, _, _, _) = harness.get(&download_target("other-crate", "1.0.0")).await;
    assert_eq!(status, 404);
    assert_eq!(harness.sandbox.calls(), 0);
}

#[tokio::test]
async fn an_invalid_crate_name_is_400() {
    let v = version("demo-crate", "1.0.0");
    let harness = Harness::start("demo-crate", &[&v], Behaviour::Clean).await;

    let (status, _, _, _) = harness.get("/crates/..%2Fetc/1.0.0/download").await;
    assert_eq!(status, 400, "a malformed crate name must be a 400");
    assert_eq!(harness.sandbox.calls(), 0);
}

// ---------------------------------------------------------------------------
// The index gate is the admission (Task 12)
// ---------------------------------------------------------------------------

/// A version the sparse-index cascade never admitted has no stored
/// verdict, so nothing has CVE-filtered it, age-checked it, or reviewed
/// it. Downloading it and serving it on plugin-pass alone would hand a
/// developer an artifact only one of the four checks ever saw.
#[tokio::test]
async fn a_version_the_index_cascade_never_approved_is_refused_without_a_download() {
    let v = version("demo-crate", "1.0.0");
    // Deliberately not `start_index_approved`: this is the version the
    // cascade never reached, so there is no stored verdict for it.
    let harness = Harness::start("demo-crate", &[&v], Behaviour::Clean).await;

    let (status, _, _, body) = harness.get(&download_target("demo-crate", "1.0.0")).await;
    assert_eq!(
        status, 403,
        "a version the index gate never admitted must be refused"
    );
    let body = String::from_utf8(body).expect("the refusal body is UTF-8");
    assert!(
        body.contains("not-index-approved"),
        "the refusal must name the missing index-gate admission: {body}"
    );

    let status_line = harness
        .status_line(&download_target("demo-crate", "1.0.0"))
        .await;
    assert!(
        status_line.starts_with("HTTP/1.1 403 "),
        "expected a 403 status line, got {status_line:?}"
    );
    assert!(
        status_line.contains("not-index-approved"),
        "the reason phrase must name the missing admission: {status_line:?}"
    );

    assert_eq!(
        harness
            .upstream_hits(&upstream_download_path("demo-crate", "1.0.0"))
            .await,
        0,
        "a version with no stored verdict must not have its bytes fetched at all"
    );
    assert_eq!(
        harness.sandbox.calls(),
        0,
        "the plugins must not run for a version the index gate never admitted"
    );
    assert_eq!(
        harness.stored_verdict(&key("demo-crate", "1.0.0", &v.declared_cksum)),
        None,
        "a refused download must not leave a stored verdict"
    );
}

/// The happy path: a version the cascade admitted has a stored `Clean`
/// verdict, so it still reaches the plugins and is served.
#[tokio::test]
async fn an_index_approved_version_still_runs_the_plugins_and_is_served() {
    let v = version("demo-crate", "1.0.0");
    let harness = Harness::start_index_approved("demo-crate", &[&v], Behaviour::Clean).await;

    let (status, content_type, _, body) =
        harness.get(&download_target("demo-crate", "1.0.0")).await;
    assert_eq!(
        status, 200,
        "an admitted, plugin-passing artifact is served"
    );
    assert_eq!(content_type.as_deref(), Some("application/gzip"));
    assert_eq!(body, v.bytes, "the served bytes are upstream's .crate");
    assert_eq!(
        harness.sandbox.calls(),
        1,
        "the plugin gate still runs for an admitted but not yet plugin-checked artifact"
    );
    assert!(
        harness.plugin_checked(&key("demo-crate", "1.0.0", &v.declared_cksum)),
        "the served artifact's verdict must be marked plugin-checked"
    );
}

/// The allowlist is an operator's explicit decision in the config. It
/// stands in for the index gate's judgement checks, so a version with no
/// stored verdict is still served when it is allowlisted — and the bytes
/// still have to match the index `cksum`.
#[tokio::test]
async fn an_allowlisted_version_is_still_served_without_a_stored_verdict() {
    let v = version("demo-crate", "1.0.0");
    let harness = Harness::start_with("demo-crate", &[&v], Behaviour::Clean, |cfg| {
        cfg.allowlist = vec![AllowEntry {
            package: "demo-crate".to_string(),
            version: "1.0.0".to_string(),
        }];
    })
    .await;

    assert_eq!(
        harness.stored_verdict(&key("demo-crate", "1.0.0", &v.declared_cksum)),
        None,
        "this test only means something without a stored verdict to fall back on"
    );

    let (status, content_type, _, body) =
        harness.get(&download_target("demo-crate", "1.0.0")).await;
    assert_eq!(
        status, 200,
        "the allowlist override must still serve a version the index gate never admitted"
    );
    assert_eq!(content_type.as_deref(), Some("application/gzip"));
    assert_eq!(body, v.bytes, "the served bytes are upstream's .crate");
    assert_eq!(
        harness.sandbox.calls(),
        1,
        "the allowlist lifts the judgement checks, never the plugin gate"
    );
}

/// A version the index does not list is a 404 even when the crate is
/// allowlisted: the allowlist cannot invent a `cksum` to verify against.
#[tokio::test]
async fn an_allowlisted_version_the_index_never_published_is_404() {
    let v = version("demo-crate", "1.0.0");
    let harness = Harness::start_with("demo-crate", &[&v], Behaviour::Clean, |cfg| {
        cfg.allowlist = vec![AllowEntry {
            package: "demo-crate".to_string(),
            version: "9.9.9".to_string(),
        }];
    })
    .await;

    let (status, _, _, _) = harness.get(&download_target("demo-crate", "9.9.9")).await;
    assert_eq!(status, 404);
    assert_eq!(harness.sandbox.calls(), 0);
    assert_eq!(
        harness
            .upstream_hits(&upstream_download_path("demo-crate", "9.9.9"))
            .await,
        0,
        "a version the index does not list is never downloaded"
    );
}

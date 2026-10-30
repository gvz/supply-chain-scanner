//! Integration tests for `supply_chain_scanner::scan::cargo`, the cargo
//! cascade orchestration. They use a real (temp-file) SQLite database, a
//! `wiremock` stand-in crates.io, and a real [`AiReviewer`] over a
//! scripted fake [`ChatProvider`].
//!
//! The reviewer seam is the one `tests/scan.rs` and `tests/ai_review.rs`
//! already use: a `StubProvider` behind `ChatProvider`, plus a sandbox
//! that runs the real collector binary over the unpacked tree. Nothing
//! here talks to a model provider or to `bwrap`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use supply_chain_scanner::ai::provider::{ChatProvider, ProviderError};
use supply_chain_scanner::ai::AiReviewer;
use supply_chain_scanner::config::{
    AiReviewConfig, BlockOn, CargoRegistryConfig, Config, ConfigHandle, CveLine, UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::cargo_vet::CargoVetStore;
use supply_chain_scanner::db::review::ReviewStore;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::cargo::index::CargoIndexEntry;
use supply_chain_scanner::ecosystem::cargo::upstream::CargoUpstream;
use supply_chain_scanner::model::{ArtifactKey, Verdict};
use supply_chain_scanner::plugin::{
    SandboxOutcome, SandboxRunner, SandboxSpec, SANDBOX_PACKAGE_DIR,
};
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::cargo::{CargoIndexDecision, CargoScanner};
use supply_chain_scanner::scan::coordinator::ScanCoordinator;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

/// A minimal, valid `Config` whose only interesting knob is
/// `scan_budget`, which is the cascade's shared budget.
fn base_config(scan_budget: Duration) -> Config {
    Config {
        bind: "127.0.0.1:8080".parse().unwrap(),
        db_path: PathBuf::from("data/scanner.db"),
        cache_dir: PathBuf::from("data/cache"),
        upstream_url: "https://index.crates.io/".parse().unwrap(),
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
        min_release_age_days: None,
        download: Default::default(),
        allowlist: Vec::new(),
        plugins: Vec::new(),
        max_concurrent_scans: None,
        ai_review: None,
        cargo_registry: None,
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

/// One published version of a test crate, with the checksum wiremock's
/// index file must declare for its bytes.
struct Version {
    vers: &'static str,
    bytes: Vec<u8>,
    cksum: String,
}

fn version(name: &str, vers: &'static str) -> Version {
    let bytes = crate_bytes(name, vers);
    let cksum = sha256_hex(&bytes);
    Version { vers, bytes, cksum }
}

/// Mounts the sparse index's `config.json` and one crate's index file.
async fn mount_index(server: &MockServer, name: &str, versions: &[Version]) {
    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{{\"dl\":\"{}/crates/{{crate}}/{{version}}/download\",\"api\":\"{}\"}}",
            server.uri(),
            server.uri()
        )))
        .mount(server)
        .await;

    let body: String = versions
        .iter()
        .map(|v| {
            format!(
                "{{\"name\":\"{name}\",\"vers\":\"{}\",\"cksum\":\"{}\",\"yanked\":false,\"deps\":[]}}\n",
                v.vers, v.cksum
            )
        })
        .collect();
    Mock::given(method("GET"))
        .and(path(index_path(name)))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
        .await;
}

/// Mounts each version's `.crate` download.
async fn mount_downloads(server: &MockServer, name: &str, versions: &[Version]) {
    for v in versions {
        Mock::given(method("GET"))
            .and(path(format!("/crates/{name}/{}/download", v.vers)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(v.bytes.clone()))
            .mount(server)
            .await;
    }
}

/// The sparse-index path for a test crate name. All test names are four
/// or more characters, so the prefix is `xy/zw`.
fn index_path(name: &str) -> String {
    format!("/{}/{}/{}", &name[0..2], &name[2..4], name)
}

/// Mounts the registry API's `GET /api/v1/crates/{name}` response for the
/// release-age gate, with `created_at` taken verbatim from `ages`
/// (version string -> RFC 3339 timestamp).
async fn mount_release_times(server: &MockServer, name: &str, ages: &[(&str, String)]) {
    let versions: String = ages
        .iter()
        .map(|(vers, created_at)| format!("{{\"num\":\"{vers}\",\"created_at\":\"{created_at}\"}}"))
        .collect::<Vec<_>>()
        .join(",");
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/crates/{name}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!("{{\"versions\":[{versions}]}}")),
        )
        .mount(server)
        .await;
}

/// `base_config` plus a `[cargo_registry]` table with
/// `min_release_age_days` set, pointed at `server`.
fn config_with_min_release_age(
    scan_budget: Duration,
    server: &MockServer,
    min_release_age_days: u64,
) -> Config {
    let mut cfg = base_config(scan_budget);
    cfg.cargo_registry = Some(CargoRegistryConfig {
        upstream_index_url: Url::parse(&format!("{}/", server.uri())).expect("valid url"),
        cargo_vet_sync_interval: Duration::from_secs(60 * 60),
        cargo_vet_sources: Vec::new(),
        required_criterion: "safe-to-deploy".to_string(),
        trusted_reviewers: Vec::new(),
        min_release_age_days: Some(min_release_age_days),
    });
    cfg
}

// ---------------------------------------------------------------------------
// Reviewer fixtures
// ---------------------------------------------------------------------------

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

/// What the provider stub replies for one review.
#[derive(Clone)]
enum Reply {
    Clean,
    Malicious,
}

/// Scripts the reply for each reviewed version, and counts every provider
/// call. The version comes out of the request body the reviewer built.
/// The stub can therefore answer differently for `1.0.0` and `0.9.0`,
/// with no extra seam.
struct StubProvider {
    /// Version string to reply with, e.g. `("1.0.0", Reply::Malicious)`.
    scripted: HashMap<String, Reply>,
    default: Reply,
    /// How long every call sleeps before answering, so a concurrency
    /// test can hold two callers overlapping.
    delay: Duration,
    calls: AtomicUsize,
}

impl StubProvider {
    fn new(scripted: HashMap<String, Reply>, default: Reply) -> Arc<Self> {
        Arc::new(Self {
            scripted,
            default,
            delay: Duration::ZERO,
            calls: AtomicUsize::new(0),
        })
    }

    fn with_delay(self: &Arc<Self>, delay: Duration) -> Arc<Self> {
        let provider = Arc::clone(self);
        // The delay is set before any request is served, so a plain
        // interior-mutation-free rebuild is enough.
        Arc::new(Self {
            scripted: provider.scripted.clone(),
            default: provider.default.clone(),
            delay,
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ChatProvider for StubProvider {
    async fn complete(
        &self,
        request: &serde_json::Value,
        _remaining: Duration,
    ) -> Result<String, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let body = request.to_string();
        let reply = self
            .scripted
            .iter()
            .find(|(vers, _)| body.contains(&format!("Version: {vers}")))
            .map(|(_, reply)| reply.clone())
            .unwrap_or_else(|| self.default.clone());
        match reply {
            Reply::Clean => Ok(model_reply_body(
                r#"{"verdict":"clean","summary":"ordinary library code","findings":[]}"#,
            )),
            Reply::Malicious => Ok(model_reply_body(
                r#"{"verdict":"malicious","summary":"builds a reverse shell","findings":[]}"#,
            )),
        }
    }
}

fn model_reply_body(reply_json: &str) -> String {
    let content = serde_json::to_string(reply_json).expect("escape the reply content");
    format!(
        r#"{{"id":"resp_1","choices":[{{"index":0,"message":{{"role":"assistant","content":{content}}},"finish_reason":"stop"}}]}}"#
    )
}

/// The reviewer's serving sandbox: runs the real collector binary over
/// the host tree the spec mounts, unconfined, exactly like
/// `ServingSandbox` in `tests/scan.rs`.
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

// ---------------------------------------------------------------------------
// The scanner under test
// ---------------------------------------------------------------------------

struct Harness {
    _db_dir: tempfile::TempDir,
    _review_dir: tempfile::TempDir,
    db: Db,
    scanner: CargoScanner,
    provider: Arc<StubProvider>,
    fingerprint: String,
}

fn build_harness(
    cfg: Config,
    server: &MockServer,
    scripted: HashMap<String, Reply>,
    default_reply: Reply,
    review_timeout: Duration,
    provider_delay: Duration,
) -> Harness {
    let (db_dir, db) = open_db();
    let review_dir = tempfile::tempdir().expect("create review db temp dir");
    let review_db = Db::open(&review_dir.path().join("reviews.db")).expect("open review db");

    let provider = StubProvider::new(scripted, default_reply).with_delay(provider_delay);
    let reviewer = AiReviewer::new(
        ai_review_cfg(review_timeout),
        Arc::new(ServingSandbox),
        Arc::clone(&provider) as Arc<dyn ChatProvider>,
        Arc::new(ReviewStore::new(review_db)),
        PathBuf::from(env!("CARGO_BIN_EXE_supply-chain-scanner")),
    );

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid index base url");
    let upstream =
        CargoUpstream::with_limits(base, &Default::default()).expect("construct cargo upstream");
    let policy = Arc::new(Policy::build(Arc::new(cfg.clone())).expect("build policy"));
    let fingerprint = policy.fingerprint().to_string();
    let config_handle = Arc::new(ConfigHandle::new(cfg));

    let scanner = CargoScanner::new(
        upstream,
        AdvisoryStore::new(db.clone()),
        CargoVetStore::new(db.clone()),
        VerdictStore::new(db.clone()),
        policy,
        Some(Arc::new(reviewer)),
        config_handle,
        Arc::new(ScanCoordinator::new()),
    );

    Harness {
        _db_dir: db_dir,
        _review_dir: review_dir,
        db,
        scanner,
        provider,
        fingerprint,
    }
}

impl Harness {
    /// The verdict stored for one candidate version, under the key scheme
    /// the cascade uses.
    fn stored_verdict(&self, name: &str, vers: &str, cksum: &str) -> Option<Verdict> {
        let store = VerdictStore::new(self.db.clone());
        store
            .get(&key(name, vers, cksum), &self.fingerprint)
            .expect("read the stored verdict")
            .map(|stored| stored.verdict)
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

fn versions_of(decision: &CargoIndexDecision) -> Vec<String> {
    match decision {
        CargoIndexDecision::Entries(entries) => {
            entries.iter().map(|entry| entry.vers.clone()).collect()
        }
        CargoIndexDecision::InProgress => panic!("expected entries, got InProgress"),
    }
}

fn clean_scripts() -> HashMap<String, Reply> {
    HashMap::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_never_before_seen_crate_with_one_clean_version_is_forwarded() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_index(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config(Duration::from_secs(5)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(5),
        Duration::ZERO,
    );

    let decision = harness.scanner.decide_index("demo").await;

    assert_eq!(
        decision,
        CargoIndexDecision::Entries(vec![CargoIndexEntry {
            name: "demo".to_string(),
            vers: "1.0.0".to_string(),
            cksum: demo[0].cksum.clone(),
            yanked: false,
        }]),
        "a single CVE-clean version that passes review must be forwarded"
    );
    assert_eq!(harness.provider.calls(), 1, "exactly one review must run");
    assert_eq!(
        harness.stored_verdict("demo", "1.0.0", &demo[0].cksum),
        Some(Verdict::Clean),
        "the review verdict must be stored under the cascade's artifact key"
    );
}

#[tokio::test]
async fn a_version_published_too_recently_is_skipped_in_favor_of_an_older_one() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0"), version("demo", "0.9.0")];
    mount_index(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;
    mount_release_times(
        &server,
        "demo",
        &[
            ("1.0.0", chrono::Utc::now().to_rfc3339()),
            (
                "0.9.0",
                (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339(),
            ),
        ],
    )
    .await;

    let harness = build_harness(
        config_with_min_release_age(Duration::from_secs(10), &server, 7),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
    );

    let decision = harness.scanner.decide_index("demo").await;

    assert_eq!(
        versions_of(&decision),
        vec!["0.9.0".to_string()],
        "the version published today must be skipped under a 7-day release-age \
         gate, forwarding only the one published 30 days ago"
    );
    assert_eq!(
        harness.stored_verdict("demo", "1.0.0", &demo[0].cksum),
        None,
        "a version the release-age gate removed must never be reviewed or stored"
    );
}

#[tokio::test]
async fn the_cascade_moves_past_a_version_that_fails_review() {
    let server = MockServer::start().await;
    // The index lists the newer version first, so the cascade reaches it
    // first.
    let demo = vec![version("demo", "1.0.0"), version("demo", "0.9.0")];
    mount_index(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config(Duration::from_secs(10)),
        &server,
        HashMap::from([("1.0.0".to_string(), Reply::Malicious)]),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
    );

    let decision = harness.scanner.decide_index("demo").await;

    assert_eq!(
        versions_of(&decision),
        vec!["0.9.0".to_string()],
        "the version that failed review must not be forwarded, and the older clean one must be"
    );
    assert_eq!(
        harness.provider.calls(),
        2,
        "both candidates get one review"
    );
    assert!(
        harness
            .stored_verdict("demo", "1.0.0", &demo[0].cksum)
            .is_some(),
        "a review-failed version keeps its durable verdict"
    );
}

#[tokio::test]
async fn the_cascade_returns_in_progress_rather_than_hanging_past_its_shared_budget() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_index(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let budget = Duration::from_millis(400);
    let harness = build_harness(
        base_config(budget),
        &server,
        clean_scripts(),
        Reply::Clean,
        // The reviewer's own timeout is far longer than the cascade's
        // budget, so only the shared deadline can end the wait.
        Duration::from_secs(30),
        Duration::from_secs(3),
    );

    let started = Instant::now();
    let decision = harness.scanner.decide_index("demo").await;
    let elapsed = started.elapsed();

    assert_eq!(
        decision,
        CargoIndexDecision::InProgress,
        "a cascade that cannot finish in budget must ask the client to retry"
    );
    assert!(
        elapsed < budget + Duration::from_secs(2),
        "decide_index took {elapsed:?}, over the {budget:?} budget plus tolerance"
    );
}

#[tokio::test]
async fn two_concurrent_requests_for_the_same_never_seen_crate_only_review_the_candidate_once() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_index(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config(Duration::from_secs(10)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        // Long enough that the second caller certainly arrives while the
        // first review is still running.
        Duration::from_millis(300),
    );

    let (first, second) = tokio::join!(
        harness.scanner.decide_index("demo"),
        harness.scanner.decide_index("demo"),
    );

    assert_eq!(
        versions_of(&first),
        vec!["1.0.0".to_string()],
        "the owning request must get the forwarded version"
    );
    assert_eq!(
        versions_of(&second),
        vec!["1.0.0".to_string()],
        "the joining request must get the same forwarded version"
    );
    assert_eq!(
        harness.provider.calls(),
        1,
        "two concurrent requests for one never-seen candidate must run one review"
    );
}

#[tokio::test]
async fn an_upstream_blip_forwards_the_versions_already_known_to_pass() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0"), version("demo", "0.9.0")];
    mount_index(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config(Duration::from_secs(10)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
    );

    // Warm the cache: the first request forwards both versions.
    let first = harness.scanner.decide_index("demo").await;
    assert_eq!(
        versions_of(&first),
        vec!["1.0.0".to_string(), "0.9.0".to_string()]
    );
    assert_eq!(harness.provider.calls(), 2);

    // The index now fails: an outage, not a 404.
    server.reset().await;
    Mock::given(method("GET"))
        .and(path(index_path("demo")))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let second = harness.scanner.decide_index("demo").await;

    assert_eq!(
        versions_of(&second),
        vec!["1.0.0".to_string(), "0.9.0".to_string()],
        "an upstream blip must forward what is already known to pass, not an empty list"
    );
    assert_eq!(
        harness.provider.calls(),
        2,
        "no review may run during an outage"
    );
    for v in &demo {
        assert_eq!(
            harness.stored_verdict("demo", v.vers, &v.cksum),
            Some(Verdict::Clean),
            "a transient upstream failure must not mark a previously passed version bad"
        );
    }
}

#[tokio::test]
async fn a_crate_that_upstream_does_not_have_forwards_an_empty_list() {
    let server = MockServer::start().await;
    // No index mock for `demo`: wiremock answers 404.

    let harness = build_harness(
        base_config(Duration::from_secs(5)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(5),
        Duration::ZERO,
    );

    let decision = harness.scanner.decide_index("demo").await;

    assert_eq!(
        decision,
        CargoIndexDecision::Entries(Vec::new()),
        "a genuinely missing crate is an empty list, not an error and not InProgress"
    );
    assert_eq!(harness.provider.calls(), 0);
}

#[tokio::test]
async fn an_invalid_crate_name_never_reaches_upstream() {
    let server = MockServer::start().await;
    let harness = build_harness(
        base_config(Duration::from_secs(5)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(5),
        Duration::ZERO,
    );

    let decision = harness.scanner.decide_index("../etc/passwd").await;

    assert_eq!(decision, CargoIndexDecision::Entries(Vec::new()));
    assert_eq!(harness.provider.calls(), 0);
    // The mock server received nothing at all.
    let received = server.received_requests().await.expect("request log");
    assert!(received.is_empty(), "an invalid name must not be fetched");
}

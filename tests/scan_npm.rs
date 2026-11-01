//! Integration tests for `supply_chain_scanner::scan::npm`, the npm
//! cascade orchestration. They use a real (temp-file) SQLite database, a
//! `wiremock` stand-in npm registry, and a real [`AiReviewer`] over a
//! scripted fake [`ChatProvider`].
//!
//! The reviewer seam is the one `tests/scan_cargo.rs` already uses: a
//! `StubProvider` behind `ChatProvider`, plus a sandbox that runs the real
//! collector binary over the unpacked tree. Nothing here talks to a model
//! provider or to `bwrap`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
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

use supply_chain_scanner::advisory::Advisory;
use supply_chain_scanner::ai::provider::{ChatProvider, ProviderError};
use supply_chain_scanner::ai::AiReviewer;
use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::config::{
    AiReviewConfig, AuditConfig, BlockOn, Config, ConfigHandle, CveLine, NpmRegistryConfig,
    UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::review::ReviewStore;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::npm::packument::{DeclaredDigest, DigestAlgorithm, Packument};
use supply_chain_scanner::ecosystem::npm::upstream::NpmUpstream;
use supply_chain_scanner::model::{ArtifactKey, Verdict};
use supply_chain_scanner::plugin::{
    SandboxOutcome, SandboxRunner, SandboxSpec, SANDBOX_PACKAGE_DIR,
};
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::coordinator::ScanCoordinator;
use supply_chain_scanner::scan::npm::{
    artifact_key, DownloadApproval, LastGoodPackumentCache, NpmIndexDecision, NpmScanner,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

/// Drops the `advisories` table out from under an already-open `Db`, via
/// a fresh raw connection to the same file. A later `AdvisoryStore::for_package`
/// call then fails with "no such table", simulating an advisory-mirror
/// outage without any filesystem trickery that an already-open pooled
/// connection would simply ignore.
fn break_advisory_table(db_path: &Path) {
    let conn = rusqlite::Connection::open(db_path).expect("open raw connection to break schema");
    conn.execute("DROP TABLE advisories", [])
        .expect("drop the advisories table");
}

/// A minimal, valid `Config` whose only interesting npm-specific knobs
/// live in `npm_registry`.
fn base_config(public_url: &str, server: &MockServer, scan_budget: Duration) -> Config {
    Config {
        bind: "127.0.0.1:8080".parse().unwrap(),
        db_path: PathBuf::from("data/scanner.db"),
        cache_dir: PathBuf::from("data/cache"),
        upstream_url: "https://registry.npmjs.org/".parse().unwrap(),
        public_url: public_url.parse().unwrap(),
        scan_budget: Duration::from_secs(5),
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

fn with_min_release_age(mut cfg: Config, min_release_age_days: u64) -> Config {
    if let Some(npm) = cfg.npm_registry.as_mut() {
        npm.min_release_age_days = Some(min_release_age_days);
    }
    cfg
}

fn with_allowlist(mut cfg: Config, package: &str, version: &str) -> Config {
    cfg.allowlist
        .push(supply_chain_scanner::config::AllowEntry {
            package: package.to_string(),
            version: version.to_string(),
        });
    cfg
}

fn sha1_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Builds one npm version's tarball bytes: a gzipped tar containing a
/// minimal `package/package.json`, wrapped the way npm itself wraps a
/// published tarball.
fn tarball_bytes(name: &str, vers: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(GzEncoder::new(&mut buf, Compression::fast()));
        for (rel, body) in [
            (
                "package/package.json".to_string(),
                format!("{{\"name\":\"{name}\",\"version\":\"{vers}\"}}"),
            ),
            (
                "package/index.js".to_string(),
                "module.exports = 1;\n".to_string(),
            ),
        ] {
            let body = body.into_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, rel, &body[..])
                .expect("append npm tarball entry");
        }
        builder.finish().expect("finish npm tarball fixture");
    }
    buf
}

/// One published version of a test package, with the shasum the
/// packument's `dist` object must declare for its bytes.
struct Version {
    vers: &'static str,
    bytes: Vec<u8>,
    shasum: String,
    /// `None` means this version is omitted from the packument's `time`
    /// map entirely.
    published: Option<String>,
}

fn version(name: &str, vers: &'static str) -> Version {
    version_with_time(name, vers, Some(chrono::Utc::now().to_rfc3339()))
}

fn version_with_time(name: &str, vers: &'static str, published: Option<String>) -> Version {
    let bytes = tarball_bytes(name, vers);
    let shasum = sha1_hex(&bytes);
    Version {
        vers,
        bytes,
        shasum,
        published,
    }
}

/// Mounts the packument endpoint (`GET /<name>`) for an unscoped test
/// package name.
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

    let time_json: String = versions
        .iter()
        .filter_map(|v| {
            v.published
                .as_ref()
                .map(|t| format!(r#""{}":"{t}""#, v.vers))
        })
        .collect::<Vec<_>>()
        .join(",");

    let latest = versions.last().map(|v| v.vers).unwrap_or("");
    let body = format!(
        r#"{{"name":"{name}","versions":{{{versions_json}}},"dist-tags":{{"latest":"{latest}"}},"time":{{{time_json}}}}}"#
    );

    Mock::given(method("GET"))
        .and(path(format!("/{name}")))
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

/// Seeds the advisory mirror with one CVE that blocks `vers`.
fn seed_cve(advisory_store: &AdvisoryStore, package: &str, vers: &str) {
    advisory_store
        .replace_all(
            "npm",
            &[Advisory {
                id: "TEST-CVE-0001".to_string(),
                package: package.to_string(),
                summary: "test advisory".to_string(),
                severity: Some(9.0),
                versions: vec![vers.to_string()],
                ranges: Vec::new(),
                fixed_versions: Vec::new(),
            }],
        )
        .expect("seed advisory");
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

#[derive(Clone)]
enum Reply {
    Clean,
    Malicious,
}

struct StubProvider {
    scripted: HashMap<String, Reply>,
    default: Reply,
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
    db_path: PathBuf,
    scanner: NpmScanner,
    provider: Arc<StubProvider>,
    fingerprint: String,
}

#[allow(clippy::too_many_arguments)]
fn build_harness(
    cfg: Config,
    server: &MockServer,
    scripted: HashMap<String, Reply>,
    default_reply: Reply,
    review_timeout: Duration,
    provider_delay: Duration,
    with_reviewer: bool,
) -> Harness {
    let (db_dir, db) = open_db();
    let db_path = db_dir.path().join("scanner.db");
    let review_dir = tempfile::tempdir().expect("create review db temp dir");
    let review_db = Db::open(&review_dir.path().join("reviews.db")).expect("open review db");

    let provider = StubProvider::new(scripted, default_reply).with_delay(provider_delay);
    let ai_reviewer = if with_reviewer {
        Some(Arc::new(AiReviewer::new(
            ai_review_cfg(review_timeout),
            Arc::new(ServingSandbox),
            Arc::clone(&provider) as Arc<dyn ChatProvider>,
            Arc::new(ReviewStore::new(review_db)),
            PathBuf::from(env!("CARGO_BIN_EXE_supply-chain-scanner")),
        )))
    } else {
        None
    };

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
    let upstream = NpmUpstream::with_limits(base, 67_108_864, &Default::default())
        .expect("construct npm upstream");
    let policy = Arc::new(Policy::build(Arc::new(cfg.clone())).expect("build policy"));
    let fingerprint = policy.fingerprint().to_string();
    let config_handle = Arc::new(ConfigHandle::new(cfg));
    let cache_root = db_dir.path().join("artifacts");
    let artifact_cache =
        Arc::new(ArtifactCache::new(db.clone(), cache_root).expect("open artifact cache"));

    let scanner = NpmScanner::new(
        upstream,
        AdvisoryStore::new(db.clone()),
        VerdictStore::new(db.clone()),
        policy,
        ai_reviewer,
        config_handle,
        Arc::new(ScanCoordinator::new()),
        artifact_cache,
    );

    Harness {
        _db_dir: db_dir,
        _review_dir: review_dir,
        db,
        db_path,
        scanner,
        provider,
        fingerprint,
    }
}

impl Harness {
    fn advisory_store(&self) -> AdvisoryStore {
        AdvisoryStore::new(self.db.clone())
    }

    fn stored_verdict(&self, name: &str, vers: &str, shasum: &str) -> Option<Verdict> {
        let store = VerdictStore::new(self.db.clone());
        store
            .get(&key(name, vers, shasum), &self.fingerprint)
            .expect("read the stored verdict")
            .map(|stored| stored.verdict)
    }

    fn stored_why_id(&self, name: &str, vers: &str, shasum: &str) -> Option<String> {
        let store = VerdictStore::new(self.db.clone());
        store
            .get(&key(name, vers, shasum), &self.fingerprint)
            .expect("read the stored verdict")
            .map(|stored| stored.why_id)
    }
}

fn key(name: &str, vers: &str, shasum: &str) -> ArtifactKey {
    let digest = DeclaredDigest {
        algorithm: DigestAlgorithm::Sha1,
        hex: shasum.to_string(),
    };
    artifact_key(name, name, vers, &digest)
}

fn forwarded_versions(decision: &NpmIndexDecision) -> Vec<String> {
    match decision {
        NpmIndexDecision::Packument { doc, .. } => {
            let mut vs: Vec<String> = doc["versions"]
                .as_object()
                .expect("versions object")
                .keys()
                .cloned()
                .collect();
            vs.sort();
            vs
        }
        other => panic!("expected a Packument decision, got {other:?}"),
    }
}

fn latest_tag(decision: &NpmIndexDecision) -> Option<String> {
    match decision {
        NpmIndexDecision::Packument { doc, .. } => {
            doc["dist-tags"]["latest"].as_str().map(str::to_string)
        }
        other => panic!("expected a Packument decision, got {other:?}"),
    }
}

fn tarball_url(decision: &NpmIndexDecision, vers: &str) -> String {
    match decision {
        NpmIndexDecision::Packument { doc, .. } => doc["versions"][vers]["dist"]["tarball"]
            .as_str()
            .expect("tarball url")
            .to_string(),
        other => panic!("expected a Packument decision, got {other:?}"),
    }
}

fn clean_scripts() -> HashMap<String, Reply> {
    HashMap::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_never_seen_package_forwards_its_newest_clean_version() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    let decision = harness.scanner.decide_packument("demo").await;

    assert_eq!(forwarded_versions(&decision), vec!["1.0.0".to_string()]);
    assert_eq!(harness.provider.calls(), 1, "exactly one review must run");
    assert_eq!(
        harness.stored_verdict("demo", "1.0.0", &demo[0].shasum),
        Some(Verdict::Clean)
    );
}

#[tokio::test]
async fn one_passing_version_per_major_line_reaches_the_packument() {
    let server = MockServer::start().await;
    let demo = vec![
        version("demo", "1.9.0"),
        version("demo", "2.4.0"),
        version("demo", "3.1.0"),
    ];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    let decision = harness.scanner.decide_packument("demo").await;

    assert_eq!(
        forwarded_versions(&decision),
        vec![
            "1.9.0".to_string(),
            "2.4.0".to_string(),
            "3.1.0".to_string()
        ],
        "one passing version per major line must reach the packument"
    );
}

#[tokio::test]
async fn the_cascade_moves_past_a_version_that_fails_review() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "0.9.0"), version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        HashMap::from([("1.0.0".to_string(), Reply::Malicious)]),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    let decision = harness.scanner.decide_packument("demo").await;

    assert_eq!(
        forwarded_versions(&decision),
        vec!["0.9.0".to_string()],
        "the version that failed review must not be forwarded, and the older clean one must be"
    );
    assert_eq!(
        harness.provider.calls(),
        2,
        "both candidates get one review"
    );
    assert!(harness
        .stored_verdict("demo", "1.0.0", &demo[1].shasum)
        .is_some());
}

#[tokio::test]
async fn a_cve_blocked_version_is_absent_from_the_forwarded_packument() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "0.9.0"), version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );
    seed_cve(&harness.advisory_store(), "demo", "1.0.0");

    let decision = harness.scanner.decide_packument("demo").await;

    assert_eq!(
        forwarded_versions(&decision),
        vec!["0.9.0".to_string()],
        "a CVE-blocked version must never reach the forwarded packument"
    );
    assert_eq!(
        harness.provider.calls(),
        1,
        "the blocked version is never reviewed"
    );
}

#[tokio::test]
async fn a_version_published_too_recently_is_absent_under_a_seven_day_gate() {
    let server = MockServer::start().await;
    let demo = vec![
        version_with_time(
            "demo",
            "0.9.0",
            Some((chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339()),
        ),
        version_with_time("demo", "1.0.0", Some(chrono::Utc::now().to_rfc3339())),
    ];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        with_min_release_age(
            base_config("http://localhost:8080", &server, Duration::from_secs(10)),
            7,
        ),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    let decision = harness.scanner.decide_packument("demo").await;

    assert_eq!(
        forwarded_versions(&decision),
        vec!["0.9.0".to_string()],
        "the version published today must be skipped under a 7-day release-age gate"
    );
    assert_eq!(
        harness.stored_verdict("demo", "1.0.0", &demo[1].shasum),
        None,
        "a version the release-age gate removed must never be reviewed or stored"
    );
}

#[tokio::test]
async fn a_version_with_no_publish_time_is_not_blocked_on_age() {
    let server = MockServer::start().await;
    let demo = vec![version_with_time("demo", "1.0.0", None)];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        with_min_release_age(
            base_config("http://localhost:8080", &server, Duration::from_secs(10)),
            7,
        ),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    let decision = harness.scanner.decide_packument("demo").await;

    assert_eq!(
        forwarded_versions(&decision),
        vec!["1.0.0".to_string()],
        "a version with no usable publish timestamp must not be blocked on age"
    );
}

#[tokio::test]
async fn an_allowlisted_version_is_forwarded_without_any_review() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        with_allowlist(
            base_config("http://localhost:8080", &server, Duration::from_secs(10)),
            "demo",
            "1.0.0",
        ),
        &server,
        clean_scripts(),
        Reply::Malicious,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    let decision = harness.scanner.decide_packument("demo").await;

    assert_eq!(forwarded_versions(&decision), vec!["1.0.0".to_string()]);
    assert_eq!(
        harness.provider.calls(),
        0,
        "an allowlisted version is never reviewed"
    );
}

#[tokio::test]
async fn forwarded_tarball_urls_all_point_at_the_proxy() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config(
            "http://proxy.example.test:9999",
            &server,
            Duration::from_secs(10),
        ),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    let decision = harness.scanner.decide_packument("demo").await;

    let tarball = tarball_url(&decision, "1.0.0");
    assert!(
        tarball.starts_with("http://proxy.example.test:9999/"),
        "forwarded tarball {tarball} must point at the proxy's public_url"
    );
    assert!(
        !tarball.contains(&server.uri()),
        "forwarded tarball {tarball} must not point at the upstream registry"
    );
}

#[tokio::test]
async fn dist_tags_latest_always_names_a_forwarded_version() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0"), version("demo", "2.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        HashMap::from([("2.0.0".to_string(), Reply::Malicious)]),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    let decision = harness.scanner.decide_packument("demo").await;

    assert_eq!(forwarded_versions(&decision), vec!["1.0.0".to_string()]);
    assert_eq!(
        latest_tag(&decision),
        Some("1.0.0".to_string()),
        "latest must be repointed at a survivor once its original target is gone"
    );
}

#[tokio::test]
async fn a_missing_package_upstream_is_not_found_not_an_empty_packument() {
    let server = MockServer::start().await;
    // No packument mock for `demo`: wiremock answers 404.

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(5)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(5),
        Duration::ZERO,
        true,
    );

    let decision = harness.scanner.decide_packument("demo").await;

    assert_eq!(decision, NpmIndexDecision::NotFound);
    assert_eq!(harness.provider.calls(), 0);
}

#[tokio::test]
async fn the_cascade_returns_in_progress_rather_than_hanging_past_its_budget() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let budget = Duration::from_millis(400);
    let harness = build_harness(
        base_config("http://localhost:8080", &server, budget),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(30),
        Duration::from_secs(3),
        true,
    );

    let started = Instant::now();
    let decision = harness.scanner.decide_packument("demo").await;
    let elapsed = started.elapsed();

    assert_eq!(decision, NpmIndexDecision::InProgress);
    assert!(
        elapsed < budget + Duration::from_secs(2),
        "decide_packument took {elapsed:?}, over the {budget:?} budget plus tolerance"
    );
}

#[tokio::test]
async fn two_concurrent_requests_for_the_same_candidate_review_it_once() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::from_millis(300),
        true,
    );

    let (first, second) = tokio::join!(
        harness.scanner.decide_packument("demo"),
        harness.scanner.decide_packument("demo"),
    );

    assert_eq!(forwarded_versions(&first), vec!["1.0.0".to_string()]);
    assert_eq!(forwarded_versions(&second), vec!["1.0.0".to_string()]);
    assert_eq!(
        harness.provider.calls(),
        1,
        "two concurrent requests for one never-seen candidate must run one review"
    );
}

#[tokio::test]
async fn with_no_reviewer_configured_nothing_is_forwardable() {
    // The honest consequence of no fast path: with no [ai_review] table
    // at all, every unreviewed version is locally marked review-failed,
    // so nothing can ever be forwarded.
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        false,
    );

    let decision = harness.scanner.decide_packument("demo").await;

    assert_eq!(
        forwarded_versions(&decision),
        Vec::<String>::new(),
        "with no reviewer configured, nothing is forwardable"
    );
    assert_eq!(harness.provider.calls(), 0);
}

#[tokio::test]
async fn an_advisory_lookup_failure_forwards_nothing_rather_than_failing_open() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );
    break_advisory_table(&harness.db_path);

    let decision = harness.scanner.decide_packument("demo").await;

    assert_eq!(
        forwarded_versions(&decision),
        Vec::<String>::new(),
        "an advisory lookup failure must forward nothing rather than fail open"
    );
    assert_eq!(
        harness.provider.calls(),
        0,
        "no review may run once the advisory lookup itself has failed"
    );
}

#[tokio::test]
async fn approved_for_download_refuses_a_version_the_packument_gate_never_passed() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    let approval = harness.scanner.approved_for_download("demo", "1.0.0").await;

    assert_eq!(
        approval,
        DownloadApproval::NotApproved,
        "a version the packument gate never reviewed must not be approved for download"
    );
}

#[tokio::test]
async fn approved_for_download_approves_a_stored_clean_version() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    let first = harness.scanner.decide_packument("demo").await;
    assert_eq!(forwarded_versions(&first), vec!["1.0.0".to_string()]);

    let approval = harness.scanner.approved_for_download("demo", "1.0.0").await;

    match approval {
        DownloadApproval::Approved {
            key: approved_key,
            dist,
        } => {
            assert_eq!(approved_key, key("demo", "1.0.0", &demo[0].shasum));
            assert_eq!(dist.shasum, Some(demo[0].shasum.clone()));
        }
        other => panic!("expected Approved, got {other:?}"),
    }
}

#[tokio::test]
async fn approved_for_download_returns_the_stored_block_and_its_why_id() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        HashMap::from([("1.0.0".to_string(), Reply::Malicious)]),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    let _ = harness.scanner.decide_packument("demo").await;
    let expected_why_id = harness
        .stored_why_id("demo", "1.0.0", &demo[0].shasum)
        .expect("a why_id must be stored for the blocked version");

    let approval = harness.scanner.approved_for_download("demo", "1.0.0").await;

    match approval {
        DownloadApproval::Refused(reason, why_id) => {
            assert_eq!(reason.code, "ai:malicious");
            assert_eq!(why_id, Some(expected_why_id));
        }
        other => panic!("expected Refused, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// I5: a packument-fetch outage during `approved_for_download` must answer
// `Unverifiable` (retryable), never the hard `NotApproved` refusal that
// reads as "the packument gate never admitted this version" — which is
// false for a version that may already carry a stored `Clean` verdict.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approved_for_download_falls_back_to_the_last_good_packument_during_an_outage() {
    let server = MockServer::start().await;
    let demo = vec![version("demo", "1.0.0")];
    mount_packument(&server, "demo", &demo).await;
    mount_downloads(&server, "demo", &demo).await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    // Populate both the stored verdict and the last-good packument cache
    // via an ordinary successful cascade run first.
    let first = harness.scanner.decide_packument("demo").await;
    assert_eq!(forwarded_versions(&first), vec!["1.0.0".to_string()]);

    // Now take the packument endpoint down. `approved_for_download` has
    // to re-fetch the packument (it never trusts a cached verdict's `dist`
    // without re-reading it), so this forces it onto the outage path.
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/demo"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let approval = harness.scanner.approved_for_download("demo", "1.0.0").await;

    match approval {
        DownloadApproval::Approved {
            key: approved_key,
            dist,
        } => {
            assert_eq!(approved_key, key("demo", "1.0.0", &demo[0].shasum));
            assert_eq!(
                dist.shasum,
                Some(demo[0].shasum.clone()),
                "the dist used to verify the download must come from the last-good packument"
            );
        }
        other => panic!(
            "an already-reviewed version must still approve via the last-good packument \
             fallback during an outage, got {other:?}"
        ),
    }
}

#[tokio::test]
async fn approved_for_download_during_an_outage_with_nothing_cached_is_unverifiable_not_refused() {
    let server = MockServer::start().await;
    // No successful fetch has ever happened, so there is nothing in the
    // last-good packument cache to fall back to.
    Mock::given(method("GET"))
        .and(path("/demo"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let harness = build_harness(
        base_config("http://localhost:8080", &server, Duration::from_secs(10)),
        &server,
        clean_scripts(),
        Reply::Clean,
        Duration::from_secs(10),
        Duration::ZERO,
        true,
    );

    let approval = harness.scanner.approved_for_download("demo", "1.0.0").await;

    match approval {
        DownloadApproval::Unverifiable(reason) => {
            assert_eq!(reason.code, "unverifiable:upstream");
        }
        other => panic!(
            "an outage with no stored pass to fall back on must be unverifiable (retryable), \
             never the hard not-approved refusal, got {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// I4: `LastGoodPackumentCache` (the bounding `src/scan/npm.rs` adds for
// `last_good_packument`, mirroring `EtagCache`'s shape in
// `src/ecosystem/npm/upstream.rs`). Driven directly with tiny caps, the
// same seam `tests/ecosystem_npm_upstream.rs` uses for `EtagCache`'s own
// eviction tests, rather than needing hundreds of distinct packages to hit
// the production caps.
// ---------------------------------------------------------------------------

/// A packument whose `raw` is a plain JSON string of `filler_len`
/// characters, so its re-serialized length — and therefore its cache
/// weight — is exactly `filler_len + 2` (the two quote bytes) before the
/// cache's own weight multiplier.
fn weighted_packument(name: &str, filler_len: usize) -> Packument {
    Packument {
        name: name.to_string(),
        versions: BTreeMap::new(),
        dist_tags: BTreeMap::new(),
        time: BTreeMap::new(),
        raw: serde_json::Value::String("x".repeat(filler_len)),
    }
}

#[test]
fn last_good_packument_cache_evicts_the_oldest_entry_past_its_entry_cap() {
    let mut cache = LastGoodPackumentCache::with_limits(2, 1_000_000);

    cache.insert("a".to_string(), weighted_packument("a", 10));
    cache.insert("b".to_string(), weighted_packument("b", 10));
    cache.insert("c".to_string(), weighted_packument("c", 10));

    assert!(
        cache.get("a").is_none(),
        "the oldest entry must be evicted once the entry cap is exceeded"
    );
    assert!(cache.get("b").is_some());
    assert!(cache.get("c").is_some());
    assert_eq!(cache.len(), 2);
}

#[test]
fn last_good_packument_cache_evicts_oldest_entries_past_its_weight_cap() {
    // Each entry here weighs the same, and the cap sits between one and
    // two entries' worth of weight, so every insert past the first must
    // evict down to just the newest — the same shape
    // `etag_cache_evicts_oldest_entries_past_its_total_bytes_cap` uses for
    // `EtagCache`.
    let mut cache = LastGoodPackumentCache::with_limits(100, 50);

    cache.insert("a".to_string(), weighted_packument("a", 10));
    cache.insert("b".to_string(), weighted_packument("b", 10));
    cache.insert("c".to_string(), weighted_packument("c", 10));

    assert!(
        cache.get("a").is_none(),
        "the oldest entry must be evicted once the weight cap is exceeded"
    );
    assert!(
        cache.get("b").is_none(),
        "eviction must repeat until the weight cap is satisfied again"
    );
    assert!(cache.get("c").is_some());
}

#[test]
fn last_good_packument_cache_moves_a_re_inserted_name_to_the_back_instead_of_evicting_it_as_stale()
{
    let mut cache = LastGoodPackumentCache::with_limits(2, 1_000_000);

    cache.insert("a".to_string(), weighted_packument("a", 10));
    cache.insert("b".to_string(), weighted_packument("b", 10));
    // Refresh "a" — it must now be the most-recently-used entry, not the
    // oldest, even though it was inserted first.
    cache.insert("a".to_string(), weighted_packument("a", 20));
    cache.insert("c".to_string(), weighted_packument("c", 10));

    assert!(
        cache.get("b").is_none(),
        "the entry that was never refreshed must be the one evicted"
    );
    assert!(cache.get("a").is_some());
    assert!(cache.get("c").is_some());
}

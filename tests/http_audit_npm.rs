//! Integration tests for the fetch audit log on the npm deployment: the
//! packument listing (`GET /<name>`) and the tarball download
//! (`GET /<name>/-/<file>`).
//!
//! On npm, the *packument is the gate*: a denied version is simply
//! absent from the filtered document, with no 403 anywhere a reader
//! could find it by. These tests exist to pin that the listing audit
//! carries exactly the versions the cascade actually evaluated, with the
//! reason vocabulary
//! `docs/superpowers/specs/2026-11-01-fetch-audit-log-design.md`
//! specifies (minus `yanked`, which has no npm equivalent — see the npm
//! design's "Deprecated versions stay candidates"), and that a
//! never-evaluated version stays silent rather than reporting a
//! fabricated "no opinion".
//!
//! Every test drives the real [`npm_router`] over real HTTP/1.1 on
//! loopback, against a `wiremock` stand-in for the npm registry, with the
//! audit log opened on a tempdir path. `NpmAppState` is built directly
//! rather than through `bootstrap_npm`, exactly as `tests/http_npm_download.rs`
//! and `tests/http_npm_packument.rs` already do, so these tests stay
//! about the audit wiring and not about startup. No AI reviewer is
//! configured anywhere in this file: every forwarded version here is
//! forwarded purely via the allowlist, which is cheaper to set up than a
//! real review and exercises the exact same `listing_audit` code path
//! (`reason_code: "allowlisted"` is itself one of the things under test).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use flate2::write::GzEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use supply_chain_scanner::advisory::Advisory;
use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::audit::AuditLog;
use supply_chain_scanner::config::{
    AllowEntry, AuditConfig, AuditRotation, Config, ConfigHandle, CveLine, NpmRegistryConfig,
    PluginConfig, UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::review::ReviewStore;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::npm::packument::{DeclaredDigest, DigestAlgorithm};
use supply_chain_scanner::ecosystem::npm::packument_path;
use supply_chain_scanner::ecosystem::npm::upstream::NpmUpstream;
use supply_chain_scanner::http::npm_packument::{npm_router, NpmAppState};
use supply_chain_scanner::model::{RefusalReason, Verdict};
use supply_chain_scanner::plugin::{PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec};
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::coordinator::ScanCoordinator;
use supply_chain_scanner::scan::npm::{artifact_key, NpmScanner};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create db temp dir");
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
        // Each test opens its own `AuditLog` over its own tempdir path
        // (or an always-failing writer) and passes it straight to
        // `start`; this field is unused by this file's harness.
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

/// A published version of a test package, unscoped names only (none of
/// this file's download tests need a scoped name).
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

/// Mounts `name`'s packument, built with the crate's own `packument_path`
/// so a scoped name's `%2f` separator matches what the upstream client
/// sends. Every version carries a real `shasum`, so a download test can
/// drive it all the way to the plugin gate.
async fn mount_packument(server: &MockServer, name: &str, versions: &[Version]) {
    let entries: String = versions
        .iter()
        .map(|v| {
            format!(
                r#""{vers}":{{"version":"{vers}","dist":{{"tarball":"{uri}/{name}/-/{name}-{vers}.tgz","shasum":"{shasum}"}}}}"#,
                vers = v.vers,
                uri = server.uri(),
                name = name,
                shasum = v.shasum,
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let latest = versions.last().map(|v| v.vers).unwrap_or("");
    let body = format!(
        r#"{{"name":"{name}","versions":{{{entries}}},"dist-tags":{{"latest":"{latest}"}},"time":{{}}}}"#
    );
    mount_raw_packument(server, name, body).await;
}

/// Mounts a hand-built packument body at the exact wire path a real
/// packument fetch would use. Used by the listing tests, which need
/// version entries this crate's own `Version` fixture does not shape
/// (no `shasum` at all, or a deliberately recent `time` entry).
async fn mount_raw_packument(server: &MockServer, name: &str, body: String) {
    Mock::given(method("GET"))
        .and(path(format!("/{}", packument_path(name))))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
        .await;
}

async fn mount_tarball(server: &MockServer, name: &str, v: &Version) {
    Mock::given(method("GET"))
        .and(path(format!("/{name}/-/{name}-{}.tgz", v.vers)))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(v.bytes.clone()))
        .mount(server)
        .await;
}

/// The artifact key the packument gate would derive for `v`, which is
/// also the key `approved_for_download` derives. Seeding a verdict under
/// this key is exactly what the packument cascade does after a pass.
fn key_for(name: &str, v: &Version) -> supply_chain_scanner::model::ArtifactKey {
    let digest = DeclaredDigest {
        algorithm: DigestAlgorithm::Sha1,
        hex: v.shasum.clone(),
    };
    artifact_key(name, name, v.vers, &digest)
}

/// Seeds one CVE advisory that enumerates exactly `version`, with a
/// severity above `base_config`'s `min_severity` so it blocks regardless
/// of `require_fix_available`.
fn seed_cve(db: &Db, package: &str, version: &str, id: &str, summary: &str) {
    let store = AdvisoryStore::new(db.clone());
    store
        .replace_all(
            "npm",
            &[Advisory {
                id: id.to_string(),
                package: package.to_string(),
                summary: summary.to_string(),
                severity: Some(9.0),
                versions: vec![version.to_string()],
                ranges: Vec::new(),
                fixed_versions: Vec::new(),
            }],
        )
        .expect("seed advisory");
}

/// Reads every audit line written so far, across however many rotated
/// files that turned out to be (these tests never cross a rotation
/// boundary, so there is only ever one), in file-name order.
fn read_audit_lines(dir: &FsPath, prefix: &str) -> Vec<serde_json::Value> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read audit directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
        .collect();
    paths.sort();

    let mut lines = Vec::new();
    for path in paths {
        let contents = std::fs::read_to_string(&path).expect("read audit file");
        for line in contents.lines() {
            if !line.trim().is_empty() {
                lines.push(serde_json::from_str(line).expect("audit line is valid JSON"));
            }
        }
    }
    lines
}

fn audit_log_over_tempdir() -> (tempfile::TempDir, Arc<AuditLog>) {
    let dir = tempfile::tempdir().expect("create audit temp dir");
    let config = AuditConfig {
        path: dir.path().join("audit.jsonl"),
        rotation: AuditRotation::Daily,
        max_files: 14,
    };
    let log = Arc::new(AuditLog::open(&config).expect("open audit log"));
    (dir, log)
}

/// A writer that always fails, so [`AuditLog::with_writer`] over it proves
/// the fail-closed path: a request whose audit record cannot be written
/// must 500, never serve a packument or tarball bytes, and never read as
/// a 403/429.
struct AlwaysFailingWriter;
impl io::Write for AlwaysFailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("audit disk is unavailable in this test"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("audit disk is unavailable in this test"))
    }
}

// ---------------------------------------------------------------------------
// The plugin stub
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum Behaviour {
    Clean,
    Block(String),
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
        }
    }
}

// ---------------------------------------------------------------------------
// The router under test
// ---------------------------------------------------------------------------

struct Harness {
    _db_dir: tempfile::TempDir,
    _cache_dir: tempfile::TempDir,
    _server: MockServer,
    db: Db,
    verdicts: Arc<VerdictStore>,
    fingerprint: String,
    addr: SocketAddr,
    _listener: tokio::task::JoinHandle<()>,
}

/// [`start_with_sandbox`] with a sandbox that always passes: every test
/// except the plugin-block one either never downloads a tarball or wants
/// the plugin gate to pass cleanly.
async fn start(server: MockServer, cfg: Config, audit: Arc<AuditLog>) -> Harness {
    start_with_sandbox(server, cfg, audit, Behaviour::Clean).await
}

/// Builds the real npm router, with `audit` wired into its `NpmAppState`,
/// served over real HTTP/1.1 on an ephemeral loopback port via
/// `into_make_service_with_connect_info`, exactly as `main.rs`'s `serve`
/// does — without that, `ConnectInfo<SocketAddr>` extraction in
/// `npm_packument_handler` fails on every request. No AI reviewer is
/// configured: every forwarded version in this file is forwarded purely
/// via the allowlist, which exercises the real `listing_audit` code path
/// without the cost of a scripted model provider.
async fn start_with_sandbox(
    server: MockServer,
    cfg: Config,
    audit: Arc<AuditLog>,
    behaviour: Behaviour,
) -> Harness {
    let (db_dir, db) = open_db();
    let cache_dir = tempfile::tempdir().expect("create cache temp dir");

    let npm = cfg.npm_registry.clone().expect("npm_registry configured");
    let upstream = NpmUpstream::with_limits(
        npm.upstream_registry_url.clone(),
        npm.max_packument_bytes,
        &cfg.download,
    )
    .expect("npm upstream");
    let download_upstream = NpmUpstream::with_limits(
        npm.upstream_registry_url,
        npm.max_packument_bytes,
        &cfg.download,
    )
    .expect("npm download upstream");

    let policy = Arc::new(Policy::build(Arc::new(cfg.clone())).expect("build policy"));
    let fingerprint = policy.fingerprint().to_string();
    let config_handle = Arc::new(ConfigHandle::new(cfg));

    let artifact_cache = Arc::new(
        ArtifactCache::new(db.clone(), cache_dir.path().join("artifacts"))
            .expect("create artifact cache"),
    );
    let sandbox = StubSandbox::new(behaviour);

    let scanner = NpmScanner::new(
        upstream,
        AdvisoryStore::new(db.clone()),
        VerdictStore::new(db.clone()),
        Arc::clone(&policy),
        // No reviewer: every forwarded version in this file's tests
        // comes from the allowlist, and every denied version comes from
        // CVE/too-new/a stored block, none of which need a live review.
        None,
        Arc::clone(&config_handle),
        Arc::new(ScanCoordinator::new()),
        Arc::clone(&artifact_cache),
    );

    let verdicts = Arc::new(VerdictStore::new(db.clone()));

    let state = NpmAppState {
        npm_scanner: Arc::new(scanner),
        config: config_handle,
        upstream: Arc::new(download_upstream),
        verdicts: Arc::clone(&verdicts),
        plugins: Arc::new(PluginRunner::new(sandbox)),
        artifact_cache,
        reviews: Arc::new(ReviewStore::new(db.clone())),
        plugin_run_coordinator: Arc::new(ScanCoordinator::new()),
        audit,
    };

    let app = npm_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("local addr");
    let served = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    Harness {
        _db_dir: db_dir,
        _cache_dir: cache_dir,
        _server: server,
        db,
        verdicts,
        fingerprint,
        addr,
        _listener: served,
    }
}

async fn get(addr: SocketAddr, target: &str) -> (u16, String) {
    let response = reqwest::get(format!("http://{addr}{target}"))
        .await
        .expect("send GET request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("read response body");
    (status, body)
}

async fn post(addr: SocketAddr, target: &str) -> u16 {
    let response = reqwest::Client::new()
        .post(format!("http://{addr}{target}"))
        .send()
        .await
        .expect("send POST request");
    response.status().as_u16()
}

async fn put(addr: SocketAddr, target: &str) -> u16 {
    let response = reqwest::Client::new()
        .put(format!("http://{addr}{target}"))
        .send()
        .await
        .expect("send PUT request");
    response.status().as_u16()
}

// ---------------------------------------------------------------------------
// The packument listing
// ---------------------------------------------------------------------------

/// The listing's one `listing` line counts all forty upstream versions
/// against the three the cascade actually evaluated, and each evaluated
/// version's own `listed` line carries the reason vocabulary the design
/// spec defines for npm: `cve:<advisory-id>` (not the bare `cve` an
/// earlier draft of this plan called for — see
/// `src/advisory/matching.rs`'s own `cve:<advisory-id>` spelling), and
/// `too-new`. The thirty-seven versions the cascade never evaluated (no
/// reviewer is configured here, so an unreviewed survivor defaults to
/// `ReviewStatus::Failed` with no verdict ever stored for it — see
/// `NpmScanner::listing_audit`'s own doc comment for why that must not
/// count as evaluated) get no `listed` line at all. A right-sized
/// implementation of the never-evaluated filter is pinned from both
/// directions at once: if it under-counts, `versions_evaluated` would
/// read below 3 and some of the three assertions below would find no
/// line; if it over-counts, `listed.len()` would exceed 3.
#[tokio::test]
async fn a_packument_listing_logs_only_the_versions_the_cascade_evaluated() {
    let server = MockServer::start().await;
    let name = "demo";

    // Thirty-seven ordinary versions: no reviewer is configured, so each
    // defaults to `ReviewStatus::Failed` locally, with no row ever
    // stored for it — never evaluated, by `listing_audit`'s own rule.
    let plain: Vec<String> = (1..=37).map(|i| format!("0.0.{i}")).collect();
    let mut versions: Vec<String> = plain.clone();
    versions.push("1.0.0".to_string()); // allowlisted -> forwarded
    versions.push("2.0.0".to_string()); // cve-blocked
    versions.push("3.0.0".to_string()); // too-new
    assert_eq!(versions.len(), 40, "forty upstream versions total");

    let entries: String = versions
        .iter()
        .map(|v| {
            format!(
                r#""{v}":{{"version":"{v}","dist":{{"tarball":"{uri}/{name}/-/{name}-{v}.tgz"}}}}"#,
                uri = server.uri(),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let now = chrono::Utc::now().to_rfc3339();
    let body = format!(
        r#"{{"name":"{name}","versions":{{{entries}}},"dist-tags":{{"latest":"1.0.0"}},"time":{{"3.0.0":"{now}"}}}}"#
    );
    mount_raw_packument(&server, name, body).await;

    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");

    let mut cfg = base_config(&server, plugin_binary);
    cfg.npm_registry.as_mut().unwrap().min_release_age_days = Some(30);
    cfg.allowlist = vec![AllowEntry {
        package: name.to_string(),
        version: "1.0.0".to_string(),
    }];

    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;
    seed_cve(
        &harness.db,
        name,
        "2.0.0",
        "OSV-TEST-0001",
        "a vulnerable version",
    );

    let (status, body) = get(harness.addr, &format!("/{name}")).await;
    assert_eq!(status, 200, "got body {body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("packument is JSON");
    assert_eq!(
        parsed["versions"].as_object().map(|o| o.len()),
        Some(1),
        "only the allowlisted version survives the cascade, got {body}"
    );

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let listing = lines
        .iter()
        .find(|line| line["event"] == "listing")
        .expect("a listing record was written");
    assert_eq!(listing["package"], name);
    assert_eq!(listing["versions_upstream"], 40);
    assert_eq!(listing["versions_evaluated"], 3);

    let listed: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|line| line["event"] == "listed")
        .collect();
    assert_eq!(
        listed.len(),
        3,
        "the thirty-seven never-evaluated versions must get no listed line: {listed:?}"
    );

    let by_version: HashMap<String, &serde_json::Value> = listed
        .iter()
        .map(|line| (line["version"].as_str().unwrap().to_string(), *line))
        .collect();

    let cve_line = by_version
        .get("2.0.0")
        .expect("a listed line for the cve-blocked version");
    assert_eq!((*cve_line)["decision"], "denied");
    assert_eq!(
        (*cve_line)["reason_code"],
        "cve:OSV-TEST-0001",
        "the reason vocabulary is reused verbatim from src/advisory/matching.rs's own \
         cve:<advisory-id> spelling, not a bare \"cve\""
    );

    let too_new_line = by_version
        .get("3.0.0")
        .expect("a listed line for the too-new version");
    assert_eq!((*too_new_line)["decision"], "denied");
    assert_eq!((*too_new_line)["reason_code"], "too-new");

    let allowed_line = by_version
        .get("1.0.0")
        .expect("a listed line for the forwarded version");
    assert_eq!((*allowed_line)["decision"], "allowed");
    assert_eq!(
        (*allowed_line)["reason_code"],
        "allowlisted",
        "a forwarded version that is also allowlisted must say so, not read as an ordinary pass"
    );
}

/// When more than one advisory blocks the same version, the lowest id
/// wins deterministically, and the advisory summary reaching the audit
/// line is sanitized of control characters and capped — the exact
/// defect correction 2 flags in cargo's own equivalent code, which this
/// implementation must not copy.
#[tokio::test]
async fn a_cve_blocked_npm_version_is_denied_with_the_lowest_advisory_id_sanitized_and_capped() {
    let server = MockServer::start().await;
    let name = "demo";

    let entries = format!(
        r#""2.0.0":{{"version":"2.0.0","dist":{{"tarball":"{uri}/{name}/-/{name}-2.0.0.tgz"}}}},"1.0.0":{{"version":"1.0.0","dist":{{"tarball":"{uri}/{name}/-/{name}-1.0.0.tgz"}}}}"#,
        uri = server.uri(),
    );
    let body = format!(
        r#"{{"name":"{name}","versions":{{{entries}}},"dist-tags":{{"latest":"2.0.0"}},"time":{{}}}}"#
    );
    mount_raw_packument(&server, name, body).await;

    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");

    let mut cfg = base_config(&server, plugin_binary);
    cfg.allowlist = vec![AllowEntry {
        package: name.to_string(),
        version: "2.0.0".to_string(),
    }];

    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;

    // A long summary with an embedded control character: sanitizing must
    // strip the newline entirely (not merely stop at it) and then cap
    // the result, so the final text is exactly 200 of the 300
    // non-control characters, not 150 (stopping at the newline) and not
    // 301 (left unsanitized and uncapped).
    let long_summary = format!("{}\n{}", "x".repeat(150), "y".repeat(150));
    let store = AdvisoryStore::new(harness.db.clone());
    store
        .replace_all(
            "npm",
            &[
                Advisory {
                    id: "OSV-2024-5000".to_string(),
                    package: name.to_string(),
                    summary: "a higher-id advisory that must not win the tie-break".to_string(),
                    severity: Some(9.0),
                    versions: vec!["1.0.0".to_string()],
                    ranges: Vec::new(),
                    fixed_versions: Vec::new(),
                },
                Advisory {
                    id: "OSV-2024-0001".to_string(),
                    package: name.to_string(),
                    summary: long_summary,
                    severity: Some(9.0),
                    versions: vec!["1.0.0".to_string()],
                    ranges: Vec::new(),
                    fixed_versions: Vec::new(),
                },
            ],
        )
        .expect("seed advisories");

    let (status, body) = get(harness.addr, &format!("/{name}")).await;
    assert_eq!(status, 200, "got body {body}");

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "listed" && line["version"] == "1.0.0")
        .expect("a listed record for the cve-blocked version was written");
    assert_eq!(record["decision"], "denied");
    assert_eq!(
        record["reason_code"], "cve:OSV-2024-0001",
        "the lowest advisory id must win deterministically, not whatever order was iterated"
    );
    let detail = record["reason_detail"]
        .as_str()
        .expect("reason_detail is a string");
    assert!(
        !detail.contains('\n'),
        "the advisory summary must be sanitized of control characters: {detail:?}"
    );
    assert!(
        detail.starts_with(&"x".repeat(150)),
        "the sanitized text must keep its non-control characters: {detail:?}"
    );
    assert!(
        detail.len() <= 220,
        "the advisory summary must be capped at 200 characters plus the severity suffix, \
         got {} chars: {detail:?}",
        detail.len()
    );
    assert!(record.get("filename").is_none(), "npm decides per version");
}

/// A version that is simultaneously CVE-blocked and too-new is reported
/// as CVE-denied, not too-new: `listing_audit`'s own `cve_blocked`-then-
/// `too_new` chain matches the cascade's own filtering order (CVE first,
/// per `plan_npm_cascade`'s module docs), and nothing currently pins that
/// order, so a future edit that swapped the two `if`/`else if` arms would
/// pass every other test in this file silently.
#[tokio::test]
async fn a_version_both_cve_blocked_and_too_new_is_denied_as_cve_not_too_new() {
    let server = MockServer::start().await;
    let name = "demo";

    let entries = format!(
        r#""2.0.0":{{"version":"2.0.0","dist":{{"tarball":"{uri}/{name}/-/{name}-2.0.0.tgz"}}}},"1.0.0":{{"version":"1.0.0","dist":{{"tarball":"{uri}/{name}/-/{name}-1.0.0.tgz"}}}}"#,
        uri = server.uri(),
    );
    let now = chrono::Utc::now().to_rfc3339();
    let body = format!(
        r#"{{"name":"{name}","versions":{{{entries}}},"dist-tags":{{"latest":"2.0.0"}},"time":{{"1.0.0":"{now}"}}}}"#
    );
    mount_raw_packument(&server, name, body).await;

    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");

    let mut cfg = base_config(&server, plugin_binary);
    cfg.npm_registry.as_mut().unwrap().min_release_age_days = Some(30);
    cfg.allowlist = vec![AllowEntry {
        package: name.to_string(),
        version: "2.0.0".to_string(),
    }];

    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;
    // "1.0.0" is both too-new (seeded above via `time`) and CVE-blocked
    // (seeded here): the cascade's own filtering order checks CVE first.
    seed_cve(
        &harness.db,
        name,
        "1.0.0",
        "OSV-TEST-0002",
        "a vulnerable version",
    );

    let (status, body) = get(harness.addr, &format!("/{name}")).await;
    assert_eq!(status, 200, "got body {body}");

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "listed" && line["version"] == "1.0.0")
        .expect("a listed record for the doubly-blocked version was written");
    assert_eq!(record["decision"], "denied");
    assert_eq!(
        record["reason_code"], "cve:OSV-TEST-0002",
        "CVE must win over too-new, matching the cascade's own filtering order"
    );
}

/// A version the cascade marked review-failed from a *real* stored
/// verdict (not merely defaulted because no reviewer is configured)
/// carries that verdict's own `reason_code` and `why_id` on its `listed`
/// line, read back from `VerdictStore::file_verdicts` rather than
/// fabricated.
#[tokio::test]
async fn a_review_failed_npm_version_carries_the_stored_reason_and_why_id() {
    let server = MockServer::start().await;
    let name = "demo";
    let failed_shasum = sha1_hex(b"failed-bytes");

    let entries = format!(
        r#""2.0.0":{{"version":"2.0.0","dist":{{"tarball":"{uri}/{name}/-/{name}-2.0.0.tgz"}}}},"1.0.0":{{"version":"1.0.0","dist":{{"tarball":"{uri}/{name}/-/{name}-1.0.0.tgz","shasum":"{failed_shasum}"}}}}"#,
        uri = server.uri(),
    );
    let body = format!(
        r#"{{"name":"{name}","versions":{{{entries}}},"dist-tags":{{"latest":"2.0.0"}},"time":{{}}}}"#
    );
    mount_raw_packument(&server, name, body).await;

    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");

    let mut cfg = base_config(&server, plugin_binary);
    cfg.allowlist = vec![AllowEntry {
        package: name.to_string(),
        version: "2.0.0".to_string(),
    }];

    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;

    // A real, pre-existing stored verdict: this version failed review on
    // an earlier request, and that earlier request's reason is what this
    // listing's audit line must report back, unchanged.
    let digest = DeclaredDigest {
        algorithm: DigestAlgorithm::Sha1,
        hex: failed_shasum,
    };
    let blocked_key = artifact_key(name, name, "1.0.0", &digest);
    let reason = RefusalReason {
        code: "ai:malicious".to_string(),
        detail: "the model judged this package malicious".to_string(),
    };
    harness
        .verdicts
        .put(
            &blocked_key,
            &Verdict::Blocked(reason),
            &harness.fingerprint,
        )
        .expect("seed pinned blocked verdict");

    let (status, body) = get(harness.addr, &format!("/{name}")).await;
    assert_eq!(status, 200, "got body {body}");

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "listed" && line["version"] == "1.0.0")
        .expect("a listed record for the review-failed version was written");
    assert_eq!(record["decision"], "denied");
    assert_eq!(record["reason_code"], "ai:malicious");
    assert!(record["why_id"].is_string());
}

// ---------------------------------------------------------------------------
// The tarball download
// ---------------------------------------------------------------------------

/// An npm tarball download that delivers bytes writes a `served` line
/// naming the exact package, version, filename and digest served.
#[tokio::test]
async fn an_npm_tarball_download_writes_a_served_line() {
    let server = MockServer::start().await;
    let name = "lodash";
    let v = version(name, "4.17.21");
    mount_packument(&server, name, &[version(name, "4.17.21")]).await;
    mount_tarball(&server, name, &v).await;

    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");
    let cfg = base_config(&server, plugin_binary);

    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;

    // The state a real download runs in: the packument gate already
    // admitted this version (a stored `Clean` verdict), not yet
    // plugin-checked.
    harness
        .verdicts
        .put(&key_for(name, &v), &Verdict::Clean, &harness.fingerprint)
        .expect("seed the packument gate's clean verdict");

    let (status, body) = get(harness.addr, &format!("/{name}/-/{name}-4.17.21.tgz")).await;
    assert_eq!(status, 200, "got body {body}");

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "served")
        .expect("a served record was written");
    assert_eq!(record["event"], "served");
    assert_eq!(record["ecosystem"], "npm");
    assert_eq!(record["package"], name);
    assert_eq!(record["version"], "4.17.21");
    assert_eq!(record["filename"], "lodash-4.17.21.tgz");
    assert_eq!(record["sha256"], v.shasum);
}

/// An npm tarball download refused on a pre-existing stored block writes
/// a `refused` line carrying that block's reason and `why_id`.
#[tokio::test]
async fn a_refused_npm_tarball_writes_a_refused_line_with_its_why_id() {
    let server = MockServer::start().await;
    let name = "demo";
    let v = version(name, "1.0.0");
    mount_packument(&server, name, &[version(name, "1.0.0")]).await;

    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");
    let cfg = base_config(&server, plugin_binary);

    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;

    let reason = RefusalReason {
        code: "ai-review:malicious".to_string(),
        detail: "the reviewer refused this package".to_string(),
    };
    harness
        .verdicts
        .put(
            &key_for(name, &v),
            &Verdict::Blocked(reason),
            &harness.fingerprint,
        )
        .expect("seed pinned blocked verdict");

    let (status, body) = get(harness.addr, &format!("/{name}/-/{name}-1.0.0.tgz")).await;
    assert_eq!(status, 403, "got body {body}");

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "refused")
        .expect("a refused record was written");
    assert_eq!(record["event"], "refused");
    assert_eq!(record["package"], name);
    assert_eq!(record["version"], "1.0.0");
    assert_eq!(record["reason_code"], "ai-review:malicious");
    assert!(record["why_id"].is_string());
}

/// A version the packument gate never admitted (no stored verdict at
/// all) still gets a `refused` line when the download is refused: the
/// design spec defines `refused` as "a download that got a refusal
/// response", and a 403 reaches the client here exactly as it does for a
/// pre-existing stored block. This is the exact shape correction 3 (and
/// cargo's own review before it) calls out: `NotApproved` is a 403 that
/// a naive implementation writes no record for.
#[tokio::test]
async fn a_not_approved_npm_download_writes_a_refused_line() {
    let server = MockServer::start().await;
    let name = "demo";
    let v = version(name, "1.0.0");
    mount_packument(&server, name, &[version(name, "1.0.0")]).await;
    mount_tarball(&server, name, &v).await;

    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");
    let cfg = base_config(&server, plugin_binary);

    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;
    // Deliberately no stored verdict: the packument gate never admitted
    // this version, so `approved_for_download` answers `NotApproved`.

    let (status, body) = get(harness.addr, &format!("/{name}/-/{name}-1.0.0.tgz")).await;
    assert_eq!(status, 403, "got body {body}");

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "refused")
        .expect("a refused record was written for the never-admitted version");
    assert_eq!(record["package"], name);
    assert_eq!(record["version"], "1.0.0");
    assert_eq!(record["reason_code"], "not-packument-approved");
}

/// A packument-approved version (a stored `Clean` verdict, exactly as
/// `an_npm_tarball_download_writes_a_served_line` seeds) is not yet a
/// *decided* download: the plugin gate still has to run, and here it
/// blocks. The response must be a refusal, and the audit line must say
/// `refused`, never `served` — pinning the very defect correction 5 (and
/// `npm_download.rs`'s `DownloadOutcome` threading) exists to prevent:
/// writing `served` as soon as the packument gate's admission is
/// matched, before the plugin gate has had its say.
#[tokio::test]
async fn a_fresh_plugin_block_on_an_approved_npm_version_writes_a_refused_line() {
    let server = MockServer::start().await;
    let name = "demo";
    let v = version(name, "1.0.0");
    mount_packument(&server, name, &[version(name, "1.0.0")]).await;
    mount_tarball(&server, name, &v).await;

    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");
    let cfg = base_config(&server, plugin_binary);

    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start_with_sandbox(
        server,
        cfg,
        audit,
        Behaviour::Block("malware found".to_string()),
    )
    .await;

    // Packument-admitted, not yet plugin-checked: exactly the state a
    // real tarball download runs in before its first plugin pass.
    harness
        .verdicts
        .put(&key_for(name, &v), &Verdict::Clean, &harness.fingerprint)
        .expect("seed the packument gate's clean verdict");

    let (status, body) = get(harness.addr, &format!("/{name}/-/{name}-1.0.0.tgz")).await;
    assert_eq!(
        status, 403,
        "a fresh plugin block must be a 403, got body {body}"
    );

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    assert!(
        lines.iter().all(|line| line["event"] != "served"),
        "an approval the plugin gate went on to refuse must never be logged served: {lines:?}"
    );
    let record = lines
        .iter()
        .find(|line| line["event"] == "refused")
        .expect("a refused record was written for the fresh plugin block");
    assert_eq!(record["package"], name);
    assert_eq!(record["version"], "1.0.0");
    assert_eq!(record["filename"], "demo-1.0.0.tgz");
    assert_eq!(record["reason_code"], "plugin:yara");
    assert!(record["why_id"].is_string());
}

// A hash-mismatch refusal (`download_and_verify`'s own
// `actual != target.key.sha256` check, 403, `reason_code: "hash-mismatch"`)
// has no test here on purpose: on npm, `NpmUpstream::download_tarball`
// already verifies the downloaded bytes against the registry-declared
// digest before `download_and_verify` ever runs, and every call site
// builds `target.key` and `target.dist` from the same live packument
// entry, so the two can never disagree over HTTP. Tampering with the
// mocked bytes here (as `tests/http_npm_download.rs`'s own
// `a_digest_mismatch_is_refused_even_for_an_approved_version` does) is
// caught one layer up as an `unverifiable:upstream` 503 instead — which is
// exactly why that test only asserts `status >= 400`, not `== 403`. The
// `download_and_verify` branch itself is still covered, directly, by
// `src/http/npm_download.rs`'s own
// `download_and_verify_reports_a_mismatch_as_a_refused_hash_mismatch` unit
// test, which can disagree the two values the way nothing over HTTP can.

// ---------------------------------------------------------------------------
// Non-events
// ---------------------------------------------------------------------------

/// A missing npm package is a 404 from upstream, distinct from a denial:
/// no audit line may be written for it.
#[tokio::test]
async fn a_missing_npm_package_writes_no_audit_lines() {
    let server = MockServer::start().await;
    // No packument mock for `ghost`: wiremock answers 404.
    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");
    let cfg = base_config(&server, plugin_binary);

    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;

    let (status, body) = get(harness.addr, "/ghost").await;
    assert_eq!(status, 404, "got body {body}");

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    assert_eq!(lines.len(), 0);
}

/// `/-/ping`, both audit stubs, `/refusals`, and every write/auth
/// endpoint fetch no package: none of them may write an audit line.
#[tokio::test]
async fn ping_audit_stubs_and_write_refusals_write_no_audit_lines() {
    let server = MockServer::start().await;
    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");
    let cfg = base_config(&server, plugin_binary);

    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;

    let (ping_status, _) = get(harness.addr, "/-/ping").await;
    assert_eq!(ping_status, 200);

    let bulk_status = post(harness.addr, "/-/npm/v1/security/advisories/bulk").await;
    assert_eq!(bulk_status, 404);
    let quick_status = post(harness.addr, "/-/npm/v1/security/audits/quick").await;
    assert_eq!(quick_status, 404);

    let (refusals_status, _) = get(harness.addr, "/refusals").await;
    assert_eq!(refusals_status, 200);

    let write_status = put(harness.addr, "/demo").await;
    assert_eq!(write_status, 403);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    assert_eq!(lines.len(), 0);
}

// ---------------------------------------------------------------------------
// Fail-closed: a failed audit write
// ---------------------------------------------------------------------------

/// A failed audit write on a packument listing fails the whole request
/// closed: a 500 with an empty body, never the packument JSON the
/// cascade would otherwise have served.
///
/// Carries its own positive control: the same package and request driven
/// a second time through a harness with a *working* audit log must
/// actually serve the forwarded version. Without that control,
/// `!body.contains("\"versions\"")` on the failing-writer harness could
/// pass for a reason that has nothing to do with the audit write at all
/// (a typo in the mount, a cascade that never forwards this package) —
/// the control proves this exact scenario really does produce a real
/// packument when the only thing that changes is the audit writer.
#[tokio::test]
async fn a_failed_audit_write_on_a_packument_returns_500_and_no_packument_json() {
    let name = "demo";

    let failing_server = MockServer::start().await;
    mount_packument(&failing_server, name, &[version(name, "1.0.0")]).await;
    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");
    let mut cfg = base_config(&failing_server, plugin_binary);
    cfg.allowlist = vec![AllowEntry {
        package: name.to_string(),
        version: "1.0.0".to_string(),
    }];
    let failing_harness = start(
        failing_server,
        cfg,
        Arc::new(AuditLog::with_writer(AlwaysFailingWriter)),
    )
    .await;

    let (status, body) = get(failing_harness.addr, &format!("/{name}")).await;
    assert_eq!(status, 500);
    assert!(
        !body.contains("\"versions\""),
        "no packument may be served: {body}"
    );
    assert_ne!(status, 403, "a write failure must not read as a refusal");

    // Positive control: the identical scenario, with a working audit
    // log, must actually serve the forwarded version.
    let working_server = MockServer::start().await;
    mount_packument(&working_server, name, &[version(name, "1.0.0")]).await;
    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");
    let mut cfg = base_config(&working_server, plugin_binary);
    cfg.allowlist = vec![AllowEntry {
        package: name.to_string(),
        version: "1.0.0".to_string(),
    }];
    let (_working_audit_dir, working_audit) = audit_log_over_tempdir();
    let working_harness = start(working_server, cfg, working_audit).await;

    let (control_status, control_body) = get(working_harness.addr, &format!("/{name}")).await;
    assert_eq!(control_status, 200);
    assert!(
        control_body.contains("1.0.0"),
        "the control harness (a working audit writer) must actually serve the \
         forwarded version, or the empty body above proves nothing about the \
         audit write: {control_body}"
    );
}

/// The download path's own fail-closed guarantee: a failed audit write
/// on a tarball download must 500 with no tarball bytes, never serve the
/// artifact and never read as a refusal.
///
/// Carries the same kind of positive control as the packument test
/// above: the identical scenario through a harness with a working audit
/// log must actually serve the bytes.
#[tokio::test]
async fn a_failed_audit_write_on_an_npm_download_returns_500_and_no_tarball_bytes() {
    let name = "demo";
    let v = version(name, "1.0.0");

    let server = MockServer::start().await;
    mount_packument(&server, name, &[version(name, "1.0.0")]).await;
    mount_tarball(&server, name, &v).await;
    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");
    let cfg = base_config(&server, plugin_binary);
    let failing_harness = start(
        server,
        cfg,
        Arc::new(AuditLog::with_writer(AlwaysFailingWriter)),
    )
    .await;

    // The state a real download runs in: the packument gate already
    // admitted this version (a stored `Clean` verdict), not yet
    // plugin-checked — exactly the served test's own setup, so the only
    // variable between the two tests is the audit writer.
    failing_harness
        .verdicts
        .put(
            &key_for(name, &v),
            &Verdict::Clean,
            &failing_harness.fingerprint,
        )
        .expect("seed the packument gate's clean verdict");

    let (status, body) = get(failing_harness.addr, &format!("/{name}/-/{name}-1.0.0.tgz")).await;
    assert_eq!(status, 500);
    assert!(body.is_empty(), "no tarball bytes may be served: {body:?}");
    assert_ne!(status, 403, "a write failure must not read as a refusal");

    // Positive control.
    let working_server = MockServer::start().await;
    mount_packument(&working_server, name, &[version(name, "1.0.0")]).await;
    mount_tarball(&working_server, name, &v).await;
    let plugin_dir = tempfile::tempdir().expect("plugin dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");
    let cfg = base_config(&working_server, plugin_binary);
    let (_working_audit_dir, working_audit) = audit_log_over_tempdir();
    let working_harness = start(working_server, cfg, working_audit).await;
    working_harness
        .verdicts
        .put(
            &key_for(name, &v),
            &Verdict::Clean,
            &working_harness.fingerprint,
        )
        .expect("seed the packument gate's clean verdict");

    let (control_status, control_body) =
        get(working_harness.addr, &format!("/{name}/-/{name}-1.0.0.tgz")).await;
    assert_eq!(control_status, 200);
    assert!(
        !control_body.is_empty(),
        "the control harness (a working audit writer) must actually serve the \
         tarball bytes, or the empty body above proves nothing about the audit \
         write"
    );
}

//! Integration tests for the fetch audit log on the cargo deployment: the
//! sparse index listing (`GET /<prefix>/<name>`) and the `.crate` download
//! (`GET /crates/{crate}/{version}/download`).
//!
//! On cargo, the *index listing is the gate*: a denied version is simply
//! absent from the rendered index, with no 403 anywhere a reader could
//! find it by. These tests exist to pin that the listing audit carries
//! exactly the versions the cascade actually evaluated, with the reason
//! vocabulary `docs/superpowers/specs/2026-11-01-fetch-audit-log-design.md`
//! specifies, and that a never-evaluated version stays silent rather than
//! reporting a fabricated "no opinion".
//!
//! Every test drives the real [`cargo_router`] over real HTTP/1.1 on
//! loopback, against a `wiremock` stand-in for the crates.io sparse index,
//! with the audit log opened on a tempdir path. `CargoAppState` is built
//! directly rather than through `bootstrap_cargo`, exactly as
//! `tests/http_cargo_index.rs` and `tests/http_cargo_download.rs` already
//! do, so these tests stay about the audit wiring and not about startup.

use std::io;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use supply_chain_scanner::advisory::Advisory;
use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::audit::AuditLog;
use supply_chain_scanner::config::{
    AiReviewConfig, AuditConfig, AuditRotation, BlockOn, CargoRegistryConfig, Config, ConfigHandle,
    CveLine, PluginConfig, UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::cargo_vet::CargoVetStore;
use supply_chain_scanner::db::review::ReviewStore;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::cargo::index::index_path_for;
use supply_chain_scanner::ecosystem::cargo::upstream::CargoUpstream;
use supply_chain_scanner::http::cargo_index::{cargo_router, CargoAppState};
use supply_chain_scanner::model::{ArtifactKey, RefusalReason, Verdict};
use supply_chain_scanner::plugin::{PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec};
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::cargo::CargoScanner;
use supply_chain_scanner::scan::coordinator::ScanCoordinator;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// No plugins are configured in any of these tests (an empty plugin list
/// never calls its sandbox at all), and the reviewer — when one is
/// configured — never reaches a review (the `.crate` download it would
/// need is not mounted), so this must never run.
struct NeverCalledSandbox;
impl SandboxRunner for NeverCalledSandbox {
    fn run(&self, _spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        panic!("no plugin or review run is expected in these tests; the sandbox must never run");
    }
}

/// A writer that always fails, so [`AuditLog::with_writer`] over it proves
/// the fail-closed path: a request whose audit record cannot be written
/// must 500, never serve index entries, and never read as a 403/429.
struct AlwaysFailingWriter;
impl io::Write for AlwaysFailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("audit disk is unavailable in this test"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("audit disk is unavailable in this test"))
    }
}

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create db temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

fn base_config(server: &MockServer) -> Config {
    Config {
        bind: "127.0.0.1:8080".parse().unwrap(),
        db_path: PathBuf::from("data/scanner.db"),
        cache_dir: PathBuf::from("data/cache"),
        upstream_url: "https://index.crates.io/".parse().unwrap(),
        public_url: "http://proxy.example:8080".parse().unwrap(),
        scan_budget: Duration::from_secs(10),
        cache_ttl: Duration::from_secs(60 * 60),
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
        cargo_registry: Some(CargoRegistryConfig {
            upstream_index_url: Url::parse(&format!("{}/", server.uri())).expect("valid url"),
            cargo_vet_sync_interval: Duration::from_secs(60 * 60),
            cargo_vet_sources: Vec::new(),
            required_criterion: "safe-to-deploy".to_string(),
            trusted_reviewers: Vec::new(),
            min_release_age_days: None,
        }),
        npm_registry: None,
        // Unused by this file's harness: it builds `CargoAppState`
        // directly rather than through `bootstrap_cargo`, and each test
        // opens its own `AuditLog` over its own tempdir path (or an
        // always-failing writer) and passes it straight to `start`.
        audit: AuditConfig::default(),
    }
}

fn ai_review_cfg() -> AiReviewConfig {
    AiReviewConfig {
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

/// One index line, as the sparse index's JSON-lines body carries it.
struct IndexLine {
    vers: String,
    cksum: String,
    yanked: bool,
}

fn line(vers: &str, cksum: &str, yanked: bool) -> IndexLine {
    IndexLine {
        vers: vers.to_string(),
        cksum: cksum.to_string(),
        yanked,
    }
}

/// Mounts one crate's index file with the given lines.
async fn mount_index(server: &MockServer, name: &str, lines: &[IndexLine]) {
    let body: String = lines
        .iter()
        .map(|l| {
            format!(
                "{{\"name\":\"{name}\",\"vers\":\"{}\",\"cksum\":\"{}\",\"yanked\":{},\"deps\":[]}}\n",
                l.vers, l.cksum, l.yanked
            )
        })
        .collect();
    Mock::given(method("GET"))
        .and(path(format!("/{}", index_path_for(name))))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
        .await;
}

/// Mounts `config.json` with both the `dl` template and an `api` base
/// pointed back at `server`. `CargoUpstream::release_times` reads `api`
/// to build the registry-API URL it fetches `created_at` from; without
/// this, the release-age gate's lookup is `UpstreamError::NotFound`
/// (a sparse-index-only registry) and `min_release_age_days` never flags
/// anything.
async fn mount_config_json_with_api(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{{\"dl\":\"{0}/crates/{{crate}}/{{version}}/download\",\"api\":\"{0}\"}}",
            server.uri()
        )))
        .mount(server)
        .await;
}

/// Mounts the registry API's `GET /api/v1/crates/{name}` response for the
/// release-age gate, with `created_at` taken verbatim from `ages`
/// (version string -> RFC 3339 timestamp).
async fn mount_release_times(server: &MockServer, name: &str, ages: &[(&str, &str)]) {
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

/// Mounts `config.json` and one version's `.crate` download, both needed
/// by the download tests: `config.json`'s `dl` template points back at
/// this same stand-in server, exactly as the proxy's own `config.json`
/// points back at the proxy.
async fn mount_download(server: &MockServer, name: &str, vers: &str, bytes: &[u8]) {
    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{{\"dl\":\"{}/crates/{{crate}}/{{version}}/download\"}}",
            server.uri()
        )))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/crates/{name}/{vers}/download")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
        .mount(server)
        .await;
}

/// Seeds one CVE advisory that enumerates exactly `version`, with a
/// severity above `base_config`'s `min_severity` so it blocks regardless
/// of `require_fix_available`.
fn seed_cve(db: &Db, package: &str, version: &str) {
    let store = AdvisoryStore::new(db.clone());
    store
        .replace_all(
            "cargo",
            &[Advisory {
                id: "OSV-TEST-0001".to_string(),
                package: package.to_string(),
                summary: "test vulnerability".to_string(),
                severity: Some(9.0),
                versions: vec![version.to_string()],
                ranges: Vec::new(),
                fixed_versions: Vec::new(),
            }],
        )
        .expect("seed advisory");
}

/// The key scheme `crate::scan::cargo::artifact_key` uses: ecosystem
/// `"cargo"`, package as published (none of this file's crate names need
/// normalizing), filename `"{name}-{vers}.crate"`, and `cksum` lowercased.
fn key(name: &str, vers: &str, cksum: &str) -> ArtifactKey {
    ArtifactKey {
        ecosystem: "cargo".to_string(),
        package: name.to_string(),
        version: vers.to_string(),
        filename: format!("{name}-{vers}.crate"),
        sha256: cksum.to_lowercase(),
    }
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

struct Harness {
    _db_dir: tempfile::TempDir,
    _cache_dir: tempfile::TempDir,
    // Never read directly: every mock is registered on it before it
    // moves in here. Kept only so the `MockServer` (and its mounted
    // responders) stays alive for as long as the harness does.
    _server: MockServer,
    db: Db,
    fingerprint: String,
    addr: SocketAddr,
}

/// [`start_with_sandbox`] with [`NeverCalledSandbox`]: every test except
/// `a_fresh_plugin_block_on_an_approved_version_writes_a_refused_line`
/// configures no plugins at all (an empty plugin list never calls its
/// sandbox) and never reaches a live AI review either, so the sandbox
/// must never run.
async fn start(server: MockServer, cfg: Config, audit: Arc<AuditLog>) -> Harness {
    start_with_sandbox(server, cfg, audit, Arc::new(NeverCalledSandbox)).await
}

/// Builds the real cargo router, with `audit` wired into its
/// `CargoAppState`, served over real HTTP/1.1 on an ephemeral loopback
/// port via `into_make_service_with_connect_info`, exactly as `main.rs`'s
/// `serve` does — without that, `ConnectInfo<SocketAddr>` extraction in
/// `cargo_index_handler`/`cargo_download_handler` fails on every request.
async fn start_with_sandbox(
    server: MockServer,
    cfg: Config,
    audit: Arc<AuditLog>,
    sandbox: Arc<dyn SandboxRunner>,
) -> Harness {
    let (db_dir, db) = open_db();
    let cache_dir = tempfile::tempdir().expect("create cache temp dir");

    let index_base = cfg
        .cargo_registry
        .as_ref()
        .expect("cargo_registry configured")
        .upstream_index_url
        .clone();
    let upstream =
        CargoUpstream::with_limits(index_base.clone(), &cfg.download).expect("cargo upstream");
    let download_upstream =
        CargoUpstream::with_limits(index_base, &cfg.download).expect("cargo upstream");

    let policy = Arc::new(Policy::build(Arc::new(cfg.clone())).expect("build policy"));
    let fingerprint = policy.fingerprint().to_string();
    let config_handle = Arc::new(ConfigHandle::new(cfg.clone()));

    // Built only when a test configures `[ai_review]`
    // (`an_in_progress_cargo_index_writes_no_verdict_lines`); every other
    // test leaves it `None`, matching `review_disabled = true` in
    // `CargoScanner::facts`, so an unreviewed survivor defaults to
    // `ReviewStatus::Failed` without a real review ever running.
    let ai_reviewer = cfg.ai_review.as_ref().map(|ai_cfg| {
        Arc::new(supply_chain_scanner::ai::AiReviewer::new(
            ai_cfg.clone(),
            Arc::new(NeverCalledSandbox),
            Arc::new(NeverCalledProvider)
                as Arc<dyn supply_chain_scanner::ai::provider::ChatProvider>,
            Arc::new(ReviewStore::new(db.clone())),
            PathBuf::from(env!("CARGO_BIN_EXE_supply-chain-scanner")),
        ))
    });

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

    let state = CargoAppState {
        cargo_scanner: Arc::new(scanner),
        config: config_handle,
        upstream: Arc::new(download_upstream),
        verdicts: Arc::new(VerdictStore::new(db.clone())),
        plugins: Arc::new(PluginRunner::new(Arc::clone(&sandbox))),
        artifact_cache: Arc::new(
            ArtifactCache::new(db.clone(), cache_dir.path().join("artifacts"))
                .expect("create artifact cache"),
        ),
        reviews: Arc::new(ReviewStore::new(db.clone())),
        plugin_run_coordinator: Arc::new(ScanCoordinator::new()),
        audit,
    };

    let app = cargo_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
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
        fingerprint,
        addr,
    }
}

/// A provider that must never be called: the one reviewer test
/// (`an_in_progress_cargo_index_writes_no_verdict_lines`) fails before it
/// ever reaches the provider, because the `.crate` download it would need
/// is not mounted.
struct NeverCalledProvider;

#[async_trait::async_trait]
impl supply_chain_scanner::ai::provider::ChatProvider for NeverCalledProvider {
    async fn complete(
        &self,
        _request: &serde_json::Value,
        _remaining: Duration,
    ) -> Result<String, supply_chain_scanner::ai::provider::ProviderError> {
        panic!("the model provider must never be called in these tests");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The listing's one `listing` line counts all six upstream versions
/// against the four the cascade actually evaluated, and each evaluated
/// version's own `listed` line carries the reason vocabulary the design
/// spec defines verbatim: `"yanked"`, `"cve"`, `"too-new"`. The two
/// versions the cascade never looked at (no reviewer is configured here,
/// so an unreviewed survivor defaults to `ReviewStatus::Failed` with no
/// verdict ever stored for it — see `CargoScanner::listing_audit`'s own
/// doc comment for why that must not count as evaluated) get no `listed`
/// line at all.
#[tokio::test]
async fn a_cargo_index_listing_logs_forwarded_and_filtered_versions_with_reasons() {
    let server = MockServer::start().await;
    let name = "demo-crate";
    let forwarded_cksum = sha256_hex(b"3.0.0");
    let too_new_cksum = sha256_hex(b"2.0.0");
    let cve_cksum = sha256_hex(b"1.5.0");
    let yanked_cksum = sha256_hex(b"0.9.0");
    let never_1_cksum = sha256_hex(b"0.5.0");
    let never_2_cksum = sha256_hex(b"0.4.0");
    mount_index(
        &server,
        name,
        &[
            line("3.0.0", &forwarded_cksum, false),
            line("2.0.0", &too_new_cksum, false),
            line("1.5.0", &cve_cksum, false),
            line("0.9.0", &yanked_cksum, true),
            line("0.5.0", &never_1_cksum, false),
            line("0.4.0", &never_2_cksum, false),
        ],
    )
    .await;
    mount_config_json_with_api(&server).await;
    mount_release_times(&server, name, &[("2.0.0", "2026-10-31T00:00:00Z")]).await;

    let mut cfg = base_config(&server);
    cfg.cargo_registry.as_mut().unwrap().min_release_age_days = Some(30);

    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;
    seed_cve(&harness.db, name, "1.5.0");
    // The forwarded version is forwardable purely via cargo-vet coverage,
    // so the cascade never needs a live AI review for it either.
    CargoVetStore::new(harness.db.clone())
        .replace_source(
            "test",
            &[supply_chain_scanner::cargovet::parse::AuditEntry::Full {
                package: name.to_string(),
                version: "3.0.0".to_string(),
                who: vec!["trusted-auditor".to_string()],
                criteria: vec!["safe-to-deploy".to_string()],
                source: "test".to_string(),
            }],
        )
        .expect("store the cargo-vet audit");

    let response = reqwest::get(format!("http://{}/{}", harness.addr, index_path_for(name)))
        .await
        .expect("request cargo index");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let listing = lines
        .iter()
        .find(|line| line["event"] == "listing")
        .expect("a listing record was written");
    assert_eq!(listing["package"], name);
    assert_eq!(listing["versions_upstream"], 6);
    assert_eq!(listing["versions_evaluated"], 4);

    let listed: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|line| line["event"] == "listed")
        .collect();
    assert_eq!(
        listed.len(),
        4,
        "the two never-evaluated versions must get no listed line: {listed:?}"
    );

    let codes_by_version: std::collections::HashMap<String, String> = listed
        .iter()
        .map(|line| {
            (
                line["version"].as_str().unwrap().to_string(),
                line["reason_code"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    assert_eq!(codes_by_version["0.9.0"], "yanked");
    assert_eq!(codes_by_version["2.0.0"], "too-new");
    assert_eq!(codes_by_version["1.5.0"], "cve");

    let allowed = listed
        .iter()
        .find(|line| line["version"] == "3.0.0")
        .expect("the forwarded version has a listed line");
    assert_eq!(allowed["decision"], "allowed");
}

/// A version the cascade marked review-failed from a *real* stored
/// verdict (not merely defaulted because no reviewer is configured)
/// carries that verdict's own `reason_code` and `why_id` on its `listed`
/// line, read back from `VerdictStore::file_verdicts` rather than
/// fabricated.
#[tokio::test]
async fn a_review_failed_version_carries_the_stored_reason_and_why_id() {
    let server = MockServer::start().await;
    let name = "demo-crate";
    let forwarded_cksum = sha256_hex(b"2.0.0-forward");
    let failed_cksum = sha256_hex(b"1.0.0-failed");
    mount_index(
        &server,
        name,
        &[
            line("2.0.0", &forwarded_cksum, false),
            line("1.0.0", &failed_cksum, false),
        ],
    )
    .await;

    let cfg = base_config(&server);
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;

    CargoVetStore::new(harness.db.clone())
        .replace_source(
            "test",
            &[supply_chain_scanner::cargovet::parse::AuditEntry::Full {
                package: name.to_string(),
                version: "2.0.0".to_string(),
                who: vec!["trusted-auditor".to_string()],
                criteria: vec!["safe-to-deploy".to_string()],
                source: "test".to_string(),
            }],
        )
        .expect("store the cargo-vet audit");

    // A real, pre-existing stored verdict: this version failed review on
    // an earlier request, and that earlier request's reason is what this
    // listing's audit line must report back, unchanged.
    let blocked_key = key(name, "1.0.0", &failed_cksum);
    let reason = RefusalReason {
        code: "ai:malicious".to_string(),
        detail: "the model judged this package malicious".to_string(),
    };
    VerdictStore::new(harness.db.clone())
        .put(
            &blocked_key,
            &Verdict::Blocked(reason),
            &harness.fingerprint,
        )
        .expect("seed pinned blocked verdict");

    let response = reqwest::get(format!("http://{}/{}", harness.addr, index_path_for(name)))
        .await
        .expect("request cargo index");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "listed" && line["version"] == "1.0.0")
        .expect("a listed record for the review-failed version was written");
    assert_eq!(record["decision"], "denied");
    assert_eq!(record["reason_code"], "ai:malicious");
    assert!(record["why_id"].is_string());
}

/// A `.crate` download that delivers bytes writes a `served` line naming
/// the exact version, filename and hash served.
#[tokio::test]
async fn a_cargo_crate_download_writes_a_served_line() {
    let server = MockServer::start().await;
    let name = "serde";
    let bytes = crate_bytes(name, "1.0.0");
    let cksum = sha256_hex(&bytes);
    mount_index(&server, name, &[line("1.0.0", &cksum, false)]).await;
    mount_download(&server, name, "1.0.0", &bytes).await;

    let cfg = base_config(&server);
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;

    // The state a real download runs in: the index gate already admitted
    // this version (a stored `Clean` verdict), not yet plugin-checked.
    let artifact_key = key(name, "1.0.0", &cksum);
    VerdictStore::new(harness.db.clone())
        .put(&artifact_key, &Verdict::Clean, &harness.fingerprint)
        .expect("seed the index gate's clean verdict");

    let response = reqwest::get(format!(
        "http://{}/crates/{name}/1.0.0/download",
        harness.addr
    ))
    .await
    .expect("request crate download");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "served")
        .expect("a served record was written");
    assert_eq!(record["event"], "served");
    assert_eq!(record["ecosystem"], "cargo");
    assert_eq!(record["package"], name);
    assert_eq!(record["version"], "1.0.0");
    assert_eq!(record["filename"], format!("{name}-1.0.0.crate"));
    assert_eq!(record["sha256"], cksum);
}

/// A `.crate` download refused on a pre-existing stored block writes a
/// `refused` line carrying that block's reason and `why_id`.
#[tokio::test]
async fn a_refused_cargo_download_writes_a_refused_line() {
    let server = MockServer::start().await;
    let name = "serde";
    let bytes = crate_bytes(name, "1.0.0");
    let cksum = sha256_hex(&bytes);
    mount_index(&server, name, &[line("1.0.0", &cksum, false)]).await;

    let cfg = base_config(&server);
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;

    let artifact_key = key(name, "1.0.0", &cksum);
    let reason = RefusalReason {
        code: "plugin:yara".to_string(),
        detail: "yara matched a known malware signature".to_string(),
    };
    VerdictStore::new(harness.db.clone())
        .put(
            &artifact_key,
            &Verdict::Blocked(reason),
            &harness.fingerprint,
        )
        .expect("seed pinned blocked verdict");

    let response = reqwest::get(format!(
        "http://{}/crates/{name}/1.0.0/download",
        harness.addr
    ))
    .await
    .expect("request crate download");
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    let record = lines
        .iter()
        .find(|line| line["event"] == "refused")
        .expect("a refused record was written");
    assert_eq!(record["event"], "refused");
    assert_eq!(record["reason_code"], "plugin:yara");
    assert!(record["why_id"].is_string());
}

/// A sandbox stub that always reports a plugin block, for
/// `a_fresh_plugin_block_on_an_approved_version_writes_a_refused_line`
/// below: the one test in this file that configures a real plugin and
/// needs the sandbox to actually run.
struct BlockingSandbox;
impl SandboxRunner for BlockingSandbox {
    fn run(&self, _spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        Ok(SandboxOutcome {
            exit_code: Some(1),
            output: "malware found".to_string(),
            timed_out: false,
            signal: None,
        })
    }
}

/// An index-approved version (a stored `Clean` verdict, exactly as
/// `a_cargo_crate_download_writes_a_served_line` seeds) is not yet a
/// *decided* download: the plugin gate still has to run, and here it
/// blocks. The response must be a refusal, and the audit line must say
/// `refused`, never `served` — pinning the very defect
/// `cargo_download.rs`'s `DownloadOutcome` threading exists to prevent:
/// writing `served` as soon as the index gate's admission is matched,
/// before the plugin gate has had its say.
#[tokio::test]
async fn a_fresh_plugin_block_on_an_approved_version_writes_a_refused_line() {
    let server = MockServer::start().await;
    let name = "serde";
    let bytes = crate_bytes(name, "1.0.0");
    let cksum = sha256_hex(&bytes);
    mount_index(&server, name, &[line("1.0.0", &cksum, false)]).await;
    mount_download(&server, name, "1.0.0", &bytes).await;

    let plugin_dir = tempfile::tempdir().expect("create plugin temp dir");
    let plugin_binary = plugin_dir.path().join("yara");
    std::fs::write(&plugin_binary, b"pretend plugin binary").expect("write plugin binary");

    let mut cfg = base_config(&server);
    cfg.plugins = vec![PluginConfig {
        name: "yara".to_string(),
        binary: plugin_binary,
        timeout: Duration::from_secs(5),
    }];

    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start_with_sandbox(server, cfg, audit, Arc::new(BlockingSandbox)).await;

    // Index-admitted, not yet plugin-checked: exactly the state a real
    // `.crate` download runs in before its first plugin pass.
    let artifact_key = key(name, "1.0.0", &cksum);
    VerdictStore::new(harness.db.clone())
        .put(&artifact_key, &Verdict::Clean, &harness.fingerprint)
        .expect("seed the index gate's clean verdict");

    let response = reqwest::get(format!(
        "http://{}/crates/{name}/1.0.0/download",
        harness.addr
    ))
    .await
    .expect("request crate download");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a fresh plugin block must be a 403"
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
    assert_eq!(record["filename"], format!("{name}-1.0.0.crate"));
    assert_eq!(record["reason_code"], "plugin:yara");
    assert!(record["why_id"].is_string());
}

/// `CargoIndexDecision::InProgress` — the cascade's shared budget answer
/// for a review that cannot run yet — writes no audit lines at all: no
/// verdict was reached, so there is nothing yet to describe.
#[tokio::test]
async fn an_in_progress_cargo_index_writes_no_verdict_lines() {
    let server = MockServer::start().await;
    let name = "demo-crate";
    // A reviewer is configured, but the `.crate` download is deliberately
    // not mounted, so the review this candidate needs can never run —
    // `CargoScanner::run_cascade` answers `InProgress` without ever
    // reaching a verdict.
    mount_index(&server, name, &[line("1.0.0", "cksum-1.0.0", false)]).await;

    let mut cfg = base_config(&server);
    cfg.ai_review = Some(ai_review_cfg());
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;

    let response = reqwest::get(format!("http://{}/{}", harness.addr, index_path_for(name)))
        .await
        .expect("request cargo index");
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    assert_eq!(lines.len(), 0);
}

/// `/config.json` and `/refusals` fetch no package, so neither may write
/// an audit line.
#[tokio::test]
async fn cargo_config_json_and_refusals_write_no_audit_lines() {
    let server = MockServer::start().await;
    let cfg = base_config(&server);
    let (audit_dir, audit) = audit_log_over_tempdir();
    let harness = start(server, cfg, audit).await;

    let config_response = reqwest::get(format!("http://{}/config.json", harness.addr))
        .await
        .expect("request config.json");
    assert_eq!(config_response.status(), reqwest::StatusCode::OK);

    let refusals_response = reqwest::get(format!("http://{}/refusals", harness.addr))
        .await
        .expect("request /refusals");
    assert_eq!(refusals_response.status(), reqwest::StatusCode::OK);

    let lines = read_audit_lines(audit_dir.path(), "audit.jsonl");
    assert_eq!(lines.len(), 0);
}

/// A failed audit write on a cargo index listing fails the whole request
/// closed: a 500 with an empty body, never the index entries the cascade
/// would otherwise have served.
#[tokio::test]
async fn a_failed_audit_write_on_a_cargo_index_returns_500_and_no_entries() {
    let server = MockServer::start().await;
    let name = "demo-crate";
    mount_index(&server, name, &[line("1.0.0", "cksum-1.0.0", false)]).await;

    let cfg = base_config(&server);
    let harness = start(
        server,
        cfg,
        Arc::new(AuditLog::with_writer(AlwaysFailingWriter)),
    )
    .await;
    CargoVetStore::new(harness.db.clone())
        .replace_source(
            "test",
            &[supply_chain_scanner::cargovet::parse::AuditEntry::Full {
                package: name.to_string(),
                version: "1.0.0".to_string(),
                who: vec!["trusted-auditor".to_string()],
                criteria: vec!["safe-to-deploy".to_string()],
                source: "test".to_string(),
            }],
        )
        .expect("store the cargo-vet audit");

    let response = reqwest::get(format!("http://{}/{}", harness.addr, index_path_for(name)))
        .await
        .expect("request cargo index");
    let status = response.status();
    let body = response.bytes().await.expect("read response body");

    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.is_empty(), "no index entries may be served: {body:?}");
    assert_ne!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "a write failure must not read as a refusal"
    );
}

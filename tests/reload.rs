//! Integration tests for a live `SIGHUP` configuration reload.
//!
//! These exist because of a specific defect: the `SIGHUP` handler used to
//! swap only the `ConfigHandle`, while the policy fingerprint and the CVE
//! line were compiled once into a `Policy` at startup and never rebuilt.
//! The result was a reload that logged success and changed nothing for
//! nine of the twelve configuration fields — including the CVE line, which
//! is the whole point of the fingerprint design.
//!
//! `tests/scan.rs::policy_fingerprint_change_triggers_a_rescan` cannot
//! catch that: it builds a *second* `Scanner` over the same database,
//! which is a restart, not a reload. Every test here drives
//! [`supply_chain_scanner::http::Reloader::apply`] against one long-lived
//! `Scanner`, which is the gap that defect lived in.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use url::Url;
use wiremock::matchers::{method, path as mock_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use supply_chain_scanner::advisory::Advisory;
use supply_chain_scanner::ai::AiReviewer;
use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::config::{Config, ConfigHandle};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::index_cache::IndexCache;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::pypi::index::IndexEntry;
use supply_chain_scanner::ecosystem::pypi::upstream::Upstream;
use supply_chain_scanner::http::{Reloader, SandboxFactory};
use supply_chain_scanner::model::{ArtifactKey, Verdict};
use supply_chain_scanner::plugin::{PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec};
use supply_chain_scanner::policy::Policy;
use supply_chain_scanner::scan::{Decision, Scanner};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A scripted [`SandboxRunner`], keyed by plugin binary path, so a reload
/// that adds a plugin can be exercised without depending on `bwrap`.
struct FakeSandbox {
    scripted: HashMap<PathBuf, SandboxOutcome>,
    calls: Mutex<Vec<SandboxSpec>>,
}

impl FakeSandbox {
    fn new<I, P>(scripted: I) -> Arc<Self>
    where
        I: IntoIterator<Item = (P, SandboxOutcome)>,
        P: Into<PathBuf>,
    {
        Arc::new(Self {
            scripted: scripted.into_iter().map(|(b, o)| (b.into(), o)).collect(),
            calls: Mutex::new(Vec::new()),
        })
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl SandboxRunner for FakeSandbox {
    fn run(&self, spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        self.calls.lock().unwrap().push(spec.clone());
        match self.scripted.get(&spec.binary) {
            Some(outcome) => Ok(outcome.clone()),
            None => panic!(
                "the fake sandbox was asked to run an unscripted binary: {}",
                spec.binary.display()
            ),
        }
    }
}

/// A [`SandboxFactory`] that always hands back `sandbox`, so a reload's
/// sandbox rebuild is observable without `bwrap` being involved.
fn fixed_sandbox_factory(sandbox: Arc<dyn SandboxRunner>) -> SandboxFactory {
    Arc::new(move |_config| Ok(Arc::clone(&sandbox)))
}

fn build_wheel_bytes() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("demo/__init__.py", options)
            .expect("start zip entry");
        zip.write_all(b"VERSION = '1.0.0'\n")
            .expect("write zip entry contents");
        zip.finish().expect("finish zip fixture");
    }
    buf
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

/// Options for the config file one test writes, reloads, and rewrites.
struct ConfigFile {
    min_severity: f32,
    plugins: Vec<(String, PathBuf)>,
    cache_ttl: &'static str,
    /// `None` writes no `[ai_review]` table at all (the reviewer is off);
    /// `Some(text)` writes `text` verbatim under `[ai_review]` header, so
    /// a test can write either a valid table or a deliberately broken
    /// one.
    ai_review: Option<String>,
}

impl ConfigFile {
    fn new() -> Self {
        Self {
            min_severity: 9.0,
            plugins: Vec::new(),
            cache_ttl: "1h",
            ai_review: None,
        }
    }

    fn write(&self, path: &Path, db_path: &Path, cache_dir: &Path, upstream: &str) {
        let mut toml = format!(
            r#"
bind = "127.0.0.1:8080"
db_path = "{db_path}"
cache_dir = "{cache_dir}"
upstream_url = "{upstream}"
public_url = "http://localhost:8080/"
scan_budget = "12s"
cache_ttl = "{cache_ttl}"
advisory_sync_interval = "1h"
advisory_source_url = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"

[cve]
min_severity = {min_severity:?}
require_fix_available = false
unknown_severity = "allow"
"#,
            db_path = db_path.display(),
            cache_dir = cache_dir.display(),
            cache_ttl = self.cache_ttl,
            min_severity = self.min_severity,
        );
        for (name, binary) in &self.plugins {
            toml.push_str(&format!(
                "\n[[plugins]]\nname = \"{name}\"\nbinary = \"{binary}\"\ntimeout = \"5s\"\n",
                binary = binary.display()
            ));
        }
        if let Some(ai) = self.ai_review.as_deref() {
            toml.push_str("\n[ai_review]\n");
            toml.push_str(ai);
        }
        std::fs::write(path, toml).expect("write config toml");
    }
}

/// A valid `[ai_review]` table body: loopback HTTP, small caps, no key.
/// The provider is never dialed in these tests, so the unreachable port
/// is fine.
fn ai_review_table() -> String {
    r#"base_url = "http://127.0.0.1:9/v1/"
model = "test-model"
timeout = "5s"
max_payload_bytes = 8192
max_output_tokens = 256
coverage_threshold = 0.8
block_on = "malicious"
block_opaque_executables = false
"#
    .to_string()
}

/// An `[ai_review]` table that fails validation: a `coverage_threshold`
/// outside 0.0 to 1.0.
fn invalid_ai_review_table() -> String {
    r#"base_url = "http://127.0.0.1:9/v1/"
model = "test-model"
coverage_threshold = 1.5
"#
    .to_string()
}

/// Everything one reload test drives: one long-lived `Scanner`, the
/// `Reloader` wired to it, and the config file on disk it reloads from.
struct Harness {
    _db_dir: tempfile::TempDir,
    _cache_dir: tempfile::TempDir,
    _config_dir: tempfile::TempDir,
    db: Db,
    db_path: PathBuf,
    cache_root: PathBuf,
    config_path: PathBuf,
    upstream_uri: String,
    scanner: Arc<Scanner>,
    config: Arc<ConfigHandle>,
    reloader: Reloader,
}

impl Harness {
    fn new(server: &MockServer, initial: &ConfigFile, sandbox: Arc<dyn SandboxRunner>) -> Self {
        let db_dir = tempfile::tempdir().expect("create db temp dir");
        let cache_dir = tempfile::tempdir().expect("create cache temp dir");
        let config_dir = tempfile::tempdir().expect("create config temp dir");

        let db_path = db_dir.path().join("scanner.db");
        let cache_root = cache_dir.path().join("artifacts");
        let config_path = config_dir.path().join("scanner.toml");
        initial.write(&config_path, &db_path, &cache_root, &server.uri());

        let config = Config::load(&config_path).expect("load the initial config");
        let db = Db::open(&db_path).expect("open db");

        let artifact_cache =
            ArtifactCache::new(db.clone(), cache_root.clone()).expect("create artifact cache");
        let index_cache = IndexCache::new(db.clone());
        let base = Url::parse(&format!("{}/simple/", server.uri())).expect("valid base url");
        let upstream = Upstream::new(base, index_cache).expect("construct upstream");
        let policy = Policy::build(Arc::new(config.clone())).expect("build policy");
        let config_handle = Arc::new(ConfigHandle::new(config.clone()));

        // A reviewer for the initial config when it has an `[ai_review]`
        // table: production startup builds one, so a harness that boots
        // with the reviewer on must hand the scanner one too, or the
        // first scan would run without the gate the config promised.
        // The provider points at an unreachable loopback port, which no
        // reload test ever dials: the scanner is never asked to decide
        // here, and the reload under test rebuilds this exact shape.
        let ai_reviewer = match config.ai_review.as_ref() {
            Some(cfg) => {
                let provider = supply_chain_scanner::ai::provider::OpenAiCompatible::new(cfg)
                    .expect("build the test provider");
                let store = supply_chain_scanner::db::review::ReviewStore::new(db.clone());
                Some(Arc::new(AiReviewer::new(
                    cfg.clone(),
                    Arc::clone(&sandbox),
                    Arc::new(provider),
                    Arc::new(store),
                    std::env::current_exe().expect("this test's own executable"),
                )))
            }
            None => None,
        };

        let scanner = Arc::new(Scanner::new(
            VerdictStore::new(db.clone()),
            upstream,
            policy,
            AdvisoryStore::new(db.clone()),
            PluginRunner::new(Arc::clone(&sandbox)),
            artifact_cache,
            Arc::clone(&config_handle),
            ai_reviewer,
        ));

        let reloader = Reloader::with_sandbox_factory(
            Arc::clone(&config_handle),
            Arc::clone(&scanner),
            &config,
            fixed_sandbox_factory(sandbox),
            db.clone(),
        );

        Self {
            _db_dir: db_dir,
            _cache_dir: cache_dir,
            _config_dir: config_dir,
            db,
            db_path,
            cache_root,
            config_path,
            upstream_uri: server.uri(),
            scanner,
            config: config_handle,
            reloader,
        }
    }

    fn rewrite(&self, file: &ConfigFile) {
        file.write(
            &self.config_path,
            &self.db_path,
            &self.cache_root,
            &self.upstream_uri,
        );
    }

    fn reload(&self) -> anyhow::Result<()> {
        self.reloader.apply(&self.config_path).map(|_| ())
    }

    /// Like [`Harness::reload`], but hands back the reload summary so a
    /// test can assert on the fingerprints.
    fn reload_summary(&self) -> anyhow::Result<supply_chain_scanner::http::ReloadSummary> {
        self.reloader.apply(&self.config_path)
    }

    fn seed_advisory(&self, package: &str, version: &str, severity: f32) {
        AdvisoryStore::new(self.db.clone())
            .replace_all(
                "pypi",
                &[Advisory {
                    id: "TEST-RELOAD-1".to_string(),
                    package: package.to_string(),
                    summary: "seeded for the reload test".to_string(),
                    severity: Some(severity),
                    versions: vec![version.to_string()],
                    ranges: vec![],
                    fixed_versions: vec![],
                }],
            )
            .expect("seed advisory");
    }
}

fn key_for(sha256: &str, filename: &str) -> ArtifactKey {
    ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "demo-package".to_string(),
        version: "1.0.0".to_string(),
        filename: filename.to_string(),
        sha256: sha256.to_string(),
    }
}

fn entry_for(server: &MockServer, filename: &str, sha256: &str) -> IndexEntry {
    IndexEntry {
        filename: filename.to_string(),
        url: Url::parse(&format!("{}/packages/{filename}", server.uri())).expect("valid url"),
        sha256: Some(sha256.to_string()),
        requires_python: None,
        metadata_hash: None,
        yanked: None,
    }
}

/// Mounts the artifact download endpoint and returns the fixture's
/// filename plus its sha256.
async fn mount_artifact(server: &MockServer) -> (String, String) {
    let filename = "demo_package-1.0.0-py3-none-any.whl".to_string();
    let body = build_wheel_bytes();
    let sha256 = sha256_hex(&body);
    Mock::given(method("GET"))
        .and(mock_path(format!("/packages/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(server)
        .await;
    (filename, sha256)
}

fn exited(code: i32, output: &str) -> SandboxOutcome {
    SandboxOutcome {
        exit_code: Some(code),
        output: output.to_string(),
        timed_out: false,
        signal: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The core B1 defect: tightening `cve.min_severity` and reloading used to
/// log success and change nothing, because the CVE line and the
/// fingerprint both lived in a `Policy` built once at startup.
#[tokio::test]
async fn reload_that_tightens_the_cve_line_refuses_a_previously_clean_artifact() {
    let server = MockServer::start().await;
    let (filename, sha256) = mount_artifact(&server).await;

    let harness = Harness::new(
        &server,
        &ConfigFile::new(),
        FakeSandbox::new::<_, PathBuf>([]),
    );
    // Severity 7.5 is below the initial 9.0 line, so this artifact scans
    // clean to begin with.
    harness.seed_advisory("demo-package", "1.0.0", 7.5);

    let key = key_for(&sha256, &filename);
    let entry = entry_for(&server, &filename, &sha256);

    let before = harness.scanner.decide(&key, &entry).await;
    assert!(
        matches!(before, Decision::Serve(_)),
        "a 7.5 advisory must not block under a 9.0 CVE line, got {before:?}"
    );

    let mut tightened = ConfigFile::new();
    tightened.min_severity = 7.0;
    harness.rewrite(&tightened);
    harness.reload().expect("the reload itself must succeed");

    assert_eq!(
        harness.config.current().cve.min_severity,
        7.0,
        "the reloaded config snapshot must carry the new CVE line"
    );

    let after = harness.scanner.decide(&key, &entry).await;
    match after {
        Decision::Refuse { reason, .. } => assert!(
            reason.code.starts_with("cve"),
            "the refusal must come from the advisory line, got {reason:?}"
        ),
        other => panic!(
            "a reload that tightens the CVE line must refuse an artifact the \
             old line allowed, got {other:?}"
        ),
    }
}

/// A reload is all-or-nothing: if the new plugin list does not validate,
/// the old policy stays in force and the proxy keeps serving under it,
/// which is `Policy::build`'s own fail-closed contract applied to reload.
#[tokio::test]
async fn reload_with_a_missing_plugin_binary_keeps_the_old_policy_and_keeps_serving() {
    let server = MockServer::start().await;
    let (filename, sha256) = mount_artifact(&server).await;

    let harness = Harness::new(
        &server,
        &ConfigFile::new(),
        FakeSandbox::new::<_, PathBuf>([]),
    );
    let key = key_for(&sha256, &filename);
    let entry = entry_for(&server, &filename, &sha256);

    let before = harness.scanner.decide(&key, &entry).await;
    assert!(matches!(before, Decision::Serve(_)), "{before:?}");
    let fingerprint_before = harness.scanner.fingerprint();

    let mut broken = ConfigFile::new();
    broken.plugins = vec![(
        "ghost".to_string(),
        PathBuf::from("/nonexistent/plugin/binary"),
    )];
    harness.rewrite(&broken);

    let err = harness
        .reload()
        .expect_err("a reload naming a missing plugin binary must fail");
    let message = format!("{err:#}");
    assert!(
        message.contains("plugin") || message.contains("binary"),
        "the error must name the plugin problem, got {message}"
    );

    assert_eq!(
        harness.scanner.fingerprint(),
        fingerprint_before,
        "a rejected reload must leave the policy fingerprint untouched"
    );
    assert!(
        harness.config.current().plugins.is_empty(),
        "a rejected reload must leave the previous config in place"
    );

    let after = harness.scanner.decide(&key, &entry).await;
    assert!(
        matches!(after, Decision::Serve(_)),
        "the proxy must keep serving under the old policy after a rejected \
         reload, got {after:?}"
    );
}

/// Adding a plugin must invalidate verdicts stored under the old
/// fingerprint, so an already-`Clean` artifact actually meets the new
/// check instead of being served from a verdict that never saw it.
#[tokio::test]
async fn reload_that_adds_a_plugin_invalidates_stored_clean_verdicts() {
    let server = MockServer::start().await;
    let (filename, sha256) = mount_artifact(&server).await;

    let plugin_dir = tempfile::tempdir().expect("create plugin temp dir");
    let plugin_path = plugin_dir.path().join("blocker");
    std::fs::write(&plugin_path, b"#!/bin/false\n").expect("write plugin binary");

    let sandbox = FakeSandbox::new([(plugin_path.clone(), exited(1, "malware found\n"))]);
    let harness = Harness::new(&server, &ConfigFile::new(), Arc::clone(&sandbox) as _);

    let key = key_for(&sha256, &filename);
    let entry = entry_for(&server, &filename, &sha256);

    let before = harness.scanner.decide(&key, &entry).await;
    assert!(matches!(before, Decision::Serve(_)), "{before:?}");
    let fingerprint_before = harness.scanner.fingerprint();
    assert_eq!(
        sandbox.call_count(),
        0,
        "no plugin is configured yet, so the sandbox must not have run"
    );

    let stored_clean = VerdictStore::new(harness.db.clone())
        .get(&key, &fingerprint_before)
        .expect("query verdict")
        .expect("the first scan must have stored a verdict");
    assert_eq!(stored_clean.verdict, Verdict::Clean);

    let mut with_plugin = ConfigFile::new();
    with_plugin.plugins = vec![("blocker".to_string(), plugin_path.clone())];
    harness.rewrite(&with_plugin);
    harness.reload().expect("the reload must succeed");

    let fingerprint_after = harness.scanner.fingerprint();
    assert_ne!(
        fingerprint_after, fingerprint_before,
        "adding a plugin must change the policy fingerprint"
    );

    let after = harness.scanner.decide(&key, &entry).await;
    match after {
        Decision::Refuse { reason, why_id } => {
            assert_eq!(reason.code, "plugin:blocker");
            assert!(why_id.is_some(), "a blocked verdict must be linkable");
        }
        other => panic!(
            "an artifact stored Clean under the old fingerprint must be \
             rescanned under the new one, got {other:?}"
        ),
    }
    assert_eq!(
        sandbox.call_count(),
        1,
        "the newly added plugin must actually have run"
    );
    // The stored row now identifies the checks that produced it.
    assert!(
        VerdictStore::new(harness.db.clone())
            .get(&key, &fingerprint_after)
            .expect("query verdict")
            .is_some(),
        "the new verdict must be stored under the new fingerprint"
    );
}

/// A field that cannot take effect without a restart must say so. Silently
/// ignoring it while logging a successful reload is the failure mode this
/// rejects.
#[tokio::test]
async fn reload_naming_a_restart_only_field_is_rejected_and_names_it() {
    let server = MockServer::start().await;
    let _ = mount_artifact(&server).await;

    let harness = Harness::new(
        &server,
        &ConfigFile::new(),
        FakeSandbox::new::<_, PathBuf>([]),
    );

    let mut changed = ConfigFile::new();
    changed.cache_ttl = "48h";
    harness.rewrite(&changed);

    let err = harness
        .reload()
        .expect_err("changing a restart-only field must reject the reload");
    let message = format!("{err:#}");
    assert!(
        message.contains("cache_ttl"),
        "the rejection must name the offending field, got {message}"
    );
    assert_eq!(
        harness.config.current().cache_ttl,
        Duration::from_secs(60 * 60),
        "a rejected reload must change nothing"
    );
}

// ---------------------------------------------------------------------------
// Task 9: the reviewer under reload
// ---------------------------------------------------------------------------

/// The environment variable the reload tests' `[ai_review]` tables name.
/// It must resolve, or `Config::load` rejects the table; set once here
/// and confirmed to exist, with a value no test ever sends anywhere.
const RELOAD_KEY_ENV: &str = "SCS_RELOAD_TEST_KEY";

/// The fingerprint with the reviewer on must differ from the same config\n/// with it off. Turning the reviewer on is a policy change, stored clean\n/// verdicts must not survive it, and the reload is what delivers that.
#[tokio::test]
async fn a_reload_can_turn_the_reviewer_on() {
    // The named key variable must resolve for the [ai_review] table to\n    // validate. A parallel test could have set it already; setting it\n    // again with the same value changes nothing for that test.
    std::env::set_var(RELOAD_KEY_ENV, "set-by-a_reload_can_turn_the_reviewer_on");

    let server = MockServer::start().await;
    let _ = mount_artifact(&server).await;

    let harness = Harness::new(
        &server,
        &ConfigFile::new(),
        FakeSandbox::new::<_, PathBuf>([]),
    );
    let fingerprint_before = harness.scanner.fingerprint();

    let mut with_reviewer = ConfigFile::new();
    with_reviewer.ai_review = Some({
        let mut table = ai_review_table();
        // The table body carries no api_key_env line by default; add one
        // naming the variable set above so the built provider matches
        // production shape. (A table without one is equally valid.)
        table.push_str(&format!("api_key_env = \"{RELOAD_KEY_ENV}\"\n"));
        table
    });
    harness.rewrite(&with_reviewer);

    let summary = harness
        .reload_summary()
        .expect("the reload itself must succeed");
    assert_ne!(
        summary.new_fingerprint, fingerprint_before,
        "turning the reviewer on must change the policy fingerprint"
    );
    assert_eq!(
        harness.scanner.fingerprint(),
        summary.new_fingerprint,
        "the scanner must run under the reloaded fingerprint"
    );
    assert!(
        harness.config.current().ai_review.is_some(),
        "the reloaded config snapshot must carry the ai_review table"
    );
}

/// Turning the reviewer off is the same contract in reverse: the
/// fingerprint returns to the reviewer-less digest, so artifacts scanned
/// under the reviewing policy are rescanned rather than served from a
/// verdict a review produced.
#[tokio::test]
async fn a_reload_can_turn_the_reviewer_off() {
    std::env::set_var(RELOAD_KEY_ENV, "set-by-a_reload_can_turn_the_reviewer_off");

    let server = MockServer::start().await;
    let _ = mount_artifact(&server).await;

    let mut initial = ConfigFile::new();
    initial.ai_review = Some(ai_review_table());
    let harness = Harness::new(&server, &initial, FakeSandbox::new::<_, PathBuf>([]));
    let fingerprint_with_reviewer = harness.scanner.fingerprint();

    let without = ConfigFile::new();
    harness.rewrite(&without);

    let summary = harness.reload_summary().expect("the reload must succeed");
    assert_ne!(
        summary.new_fingerprint, fingerprint_with_reviewer,
        "turning the reviewer off must change the policy fingerprint"
    );
    // And specifically back to a digest with no ai_review contribution:
    // the plain-config fingerprint this same file produces without the
    // table.
    let plain_fp = {
        let harness_plain = Harness::new(
            &server,
            &ConfigFile::new(),
            FakeSandbox::new::<_, PathBuf>([]),
        );
        harness_plain.scanner.fingerprint()
    };
    assert_eq!(
        harness.scanner.fingerprint(),
        plain_fp,
        "with the table gone the fingerprint must be exactly the one a \
         config that never had it produces"
    );
    assert!(
        harness.config.current().ai_review.is_none(),
        "the reloaded config snapshot must not carry an ai_review table"
    );
}

/// A reload whose `[ai_review]` table fails validation is rejected like a
/// missing plugin binary: the previously running config, policy and
/// reviewer all stay in force, and the reload returns `Err`.
#[tokio::test]
async fn a_reload_whose_ai_review_table_is_invalid_keeps_the_running_policy() {
    std::env::set_var(
        RELOAD_KEY_ENV,
        "set-by-a_reload_whose_ai_review_table_is_invalid",
    );

    let server = MockServer::start().await;
    let (filename, sha256) = mount_artifact(&server).await;

    let harness = Harness::new(
        &server,
        &ConfigFile::new(),
        FakeSandbox::new::<_, PathBuf>([]),
    );
    let key = key_for(&sha256, &filename);
    let entry = entry_for(&server, &filename, &sha256);

    let before = harness.scanner.decide(&key, &entry).await;
    assert!(matches!(before, Decision::Serve(_)), "{before:?}");
    let fingerprint_before = harness.scanner.fingerprint();

    let mut broken = ConfigFile::new();
    broken.ai_review = Some(invalid_ai_review_table());
    harness.rewrite(&broken);

    let err = harness
        .reload()
        .expect_err("a reload with an invalid [ai_review] table must fail");
    let message = format!("{err:#}");
    assert!(
        message.contains("coverage_threshold") || message.contains("ai_review"),
        "the rejection must name the ai_review problem, got {message}"
    );

    assert_eq!(
        harness.scanner.fingerprint(),
        fingerprint_before,
        "a rejected reload must leave the policy fingerprint untouched"
    );
    assert!(
        harness.config.current().ai_review.is_none(),
        "a rejected reload must leave the previous config in place"
    );

    let after = harness.scanner.decide(&key, &entry).await;
    assert!(
        matches!(after, Decision::Serve(_)),
        "the proxy must keep serving under the old policy after a rejected \
         reload, got {after:?}"
    );
}

/// `ai_review` is a reloadable field: adding the table must never trip the\n/// restart-only rejection, and the module's public field list must not\n/// name it there. This test exists because the two lists are hand-kept\n/// and a future field could land in the wrong one silently.
#[test]
fn ai_review_is_not_a_restart_only_field() {
    // Observed through behavior rather than a private const: a reload that\n    // adds [ai_review] must not be rejected as a restart-only change.\n    // `a_reload_can_turn_the_reviewer_on` above already proves the\n    // behavior end to end; the assertion here pins the source, which is\n    // the only place the field lists live.
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/http/mod.rs"))
        .expect("read the http module source");
    let restart_only_block = source
        .split("RESTART_ONLY_FIELDS")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .expect("the const must exist");
    assert!(
        !restart_only_block.contains("ai_review"),
        "ai_review must not appear in RESTART_ONLY_FIELDS: the reviewer is \
         rebuilt on reload, so a restart would be demanded for a change a \
         SIGHUP delivers"
    );
    let reloadable_block = source
        .split("RELOADABLE_FIELDS")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .expect("the const must exist");
    assert!(
        reloadable_block.contains("ai_review") && !reloadable_block.contains("restart_only"),
        "ai_review must appear in RELOADABLE_FIELDS so the startup log and the \
         reload log line both tell the operator the truth"
    );
}

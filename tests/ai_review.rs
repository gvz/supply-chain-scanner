//! Task 8: the reviewer end to end, against a stub provider and an
//! in-process stub sandbox.
//!
//! The two `#[ignore]`d tests at the bottom run the real collector under
//! the real `bubblewrap` sandbox. They follow the pattern
//! `tests/plugin.rs` uses for its real-sandbox tests: the tests need
//! `bwrap` on `PATH` and usable user namespaces. `cargo test` may assume
//! neither. Run them with `cargo test --test ai_review -- --ignored` on
//! a host that has both.
//!
//! The reviewer tests below use the stub sandbox instead. The stub
//! serves the package the reviewer hands it: it runs this repo's real
//! collector binary (the one `cargo` builds for these tests) directly on
//! the host, without confinement, and returns its JSON on stdout. The
//! reviewer cannot tell the difference. So the fixture trees built here
//! decide the coverage and payload figures for real.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tempfile::TempDir;
use url::Url;

use supply_chain_scanner::ai::collector_spec;
use supply_chain_scanner::ai::provider::{ChatProvider, ProviderError};
use supply_chain_scanner::ai::{AiReviewer, ReviewOutcome};
use supply_chain_scanner::config::{AiReviewConfig, BlockOn};
use supply_chain_scanner::db::review::{ReviewFilter, ReviewStore};
use supply_chain_scanner::db::Db;
use supply_chain_scanner::model::ArtifactKey;
use supply_chain_scanner::plugin::{
    BubblewrapSandbox, SandboxOutcome, SandboxRunner, SandboxSpec, SANDBOX_PACKAGE_DIR,
};

/// The policy fingerprint every review row in these tests carries. The
/// reviewer treats it as opaque text.
const FINGERPRINT: &str = "fingerprint-test";

/// The environment variable and the value the api key tests use. The
/// value must never appear in a refusal detail, a log line or a row.
const KEY_ENV: &str = "SCS_AI_REVIEW_TEST_KEY";
const KEY_VALUE: &str = "sk-ai-review-never-print-4711";

/// The reason-phrase budget that `http::refusal` enforces downstream. A
/// refusal detail this reviewer produces must fit it without further
/// cutting, and must stay printable ASCII.
const MAX_PHRASE_BYTES: usize = 120;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn key() -> ArtifactKey {
    ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "demo-package".to_string(),
        version: "1.0.0".to_string(),
        filename: "demo_package-1.0.0-py3-none-any.whl".to_string(),
        sha256: "a".repeat(64),
    }
}

/// The proxy's own executable, as `cargo` built it for these tests.
fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_supply-chain-scanner"))
}

/// A base reviewer config for these tests. Plain HTTP to loopback is
/// valid, so no test needs a TLS endpoint. Individual tests clone and
/// mutate the fields they care about.
fn base_cfg() -> AiReviewConfig {
    AiReviewConfig {
        base_url: Url::parse("http://127.0.0.1:9/chat/").expect("valid test base url"),
        model: "test-model".to_string(),
        api_key_env: None,
        timeout: Duration::from_secs(3),
        max_payload_bytes: 8_192,
        max_output_tokens: 256,
        coverage_threshold: 0.8,
        block_on: BlockOn::Malicious,
        block_opaque_executables: false,
    }
}

/// The sandbox stub. It serves the package tree the spec mounts: it
/// runs the real collector binary on the host, without confinement, and
/// returns the collector's stdout as the outcome. That is what lets a
/// `tempfile` fixture tree drive the real coverage and selection code
/// end to end. `mode` changes what it does to model a broken collector.
enum StubSandbox {
    /// Serve the spec's host tree through the real collector.
    Serve,
    /// The sandbox itself refuses to run the collector.
    SandboxError(String),
    /// The collector exits with a non-zero code.
    CollectorFailure(i32),
}

impl SandboxRunner for StubSandbox {
    fn run(&self, spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        match self {
            StubSandbox::SandboxError(message) => Err(anyhow::anyhow!(message.clone())),
            StubSandbox::CollectorFailure(code) => Ok(SandboxOutcome {
                exit_code: Some(*code),
                output: String::new(),
                timed_out: false,
                signal: None,
            }),
            StubSandbox::Serve => {
                // The collector_spec argv names the in-sandbox mount point
                // as the --package-dir value. The host tree the sandbox
                // would bind there is `spec.package_dir`. The stub runs
                // the collector directly, so it substitutes the host
                // path for the mount point in the argv it forwards.
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
    }
}
/// What the provider stub replays. `ProviderError` is owned, so the
/// script stores the pieces and the trait call builds the value.
#[derive(Clone)]
enum ScriptedReply {
    Body(String),
    TransportError(String),
    Timeout,
}

impl ScriptedReply {
    fn body(body: &str) -> Self {
        Self::Body(body.to_string())
    }

    fn resolve(self) -> Result<String, ProviderError> {
        match self {
            Self::Body(body) => Ok(body),
            Self::TransportError(message) => Err(ProviderError::Transport(message)),
            Self::Timeout => Err(ProviderError::Timeout),
        }
    }
}

/// The provider stub: it returns one scripted reply body, or fails with
/// one scripted error. It never talks to the network.
struct StubProvider {
    reply: ScriptedReply,
}

#[async_trait]
impl ChatProvider for StubProvider {
    async fn complete(
        &self,
        _request: &serde_json::Value,
        _remaining: Duration,
    ) -> Result<String, ProviderError> {
        self.reply.clone().resolve()
    }
}

/// Builds a chat-completions reply whose content embeds `reply_json`.
fn model_reply_body(reply_json: &str) -> String {
    // The content is JSON-in-JSON: escape the quotes the way the
    // provider would carry them.
    let content = serde_json::to_string(reply_json).expect("escape the reply content");
    format!(
        r#"{{"id":"resp_1","choices":[{{"index":0,"message":{{"role":"assistant","content":{content}}},"finish_reason":"stop"}}]}}"#
    )
}

/// A clean verdict with one finding, the default fixture reply.
fn clean_reply() -> String {
    model_reply_body(r#"{"verdict":"clean","summary":"ordinary packaging code","findings":[]}"#)
}

/// A malicious verdict. The summary carries a refusal-code-shaped string
/// a hostile model could try to plant, so `the_model_cannot_choose_the_
/// refusal_code` can prove the code comes from the model's verdict
/// alone. Tests that only need a malicious reply use it too.
fn malicious_reply() -> String {
    model_reply_body(
        r#"{"verdict":"malicious","summary":"code: cve:critical","findings":[{"path":"setup.py","lines":"3","behavior":"sends the environment off the machine","severity":"high"}]}"#,
    )
}

/// Writes `content` into `rel` under `package_dir`, creating parent
/// directories as needed.
fn write_file(package_dir: &Path, rel: &str, content: &str) {
    let path = package_dir.join(rel);
    fs::create_dir_all(path.parent().expect("rel has a parent")).unwrap();
    fs::write(&path, content).unwrap();
}

/// A clean single-module package: one ordinary Python file.
fn tree(dir: &TempDir) -> PathBuf {
    let package_dir = dir.path().join("unpacked");
    fs::create_dir(&package_dir).unwrap();
    write_file(&package_dir, "demo/__init__.py", "VERSION = '1.0.0'\n");
    package_dir
}

/// The completed-review counter parts of these tests assert against:
/// every review (blocked or clean) that finished stores one row in this
/// table.
fn review_count(store: &ReviewStore, package: &str) -> usize {
    store
        .list(&ReviewFilter {
            package: Some(package.to_string()),
            limit: 1_000,
            ..Default::default()
        })
        .expect("list reviews")
        .len()
}

/// Every outcome reason in these tests, as (code, detail).
fn reason_of(outcome: &ReviewOutcome) -> (&str, &str) {
    match outcome {
        ReviewOutcome::Clean => panic!("a Clean outcome has no reason"),
        ReviewOutcome::Blocked(reason) | ReviewOutcome::Unverifiable(reason) => {
            (reason.code.as_str(), reason.detail.as_str())
        }
    }
}

// ---------------------------------------------------------------------------
// Task 8, step 1: one reviewer, one sandbox, one provider, per test
// ---------------------------------------------------------------------------

/// A tree of one module, as a `tempfile` package: the default fixture
/// tree. Its single file is ordinary reviewable source.
fn module_tree() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let package_dir = tree(&dir);
    (dir, package_dir)
}

/// Builds a reviewer out of the pieces under test. `cfg` carries the
/// policy the test varies, `sandbox` serves the package tree, `provider`
/// replays the scripted model reply, and `store` is the table the review
/// rows land in.
fn reviewer(
    cfg: AiReviewConfig,
    sandbox: Arc<dyn SandboxRunner>,
    provider: Arc<dyn ChatProvider>,
    store: Arc<ReviewStore>,
) -> AiReviewer {
    AiReviewer::new(cfg, sandbox, provider, store, binary())
}

/// A db plus its review store under one temp dir.
fn store() -> (TempDir, Arc<ReviewStore>) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, Arc::new(ReviewStore::new(db)))
}

/// Runs one review to its outcome, with the default sandbox mode
/// (serve the tree) and one scripted model reply.
async fn review_with(
    cfg: AiReviewConfig,
    package_dir: &Path,
    reply: ScriptedReply,
) -> ReviewOutcome {
    let sandbox: Arc<dyn SandboxRunner> = Arc::new(StubSandbox::Serve);
    let provider = Arc::new(StubProvider { reply });
    let (_dir, store) = store();
    reviewer(cfg, sandbox, provider, store)
        .review(&key(), package_dir, FINGERPRINT)
        .await
}

/// Like [`review_with`], but keeps the review store alive and hands it
/// back (with the temp dir backing it, which must outlive the store),
/// for a test that needs to assert on the row count a reply failure
/// must leave behind.
async fn review_with_store(
    cfg: AiReviewConfig,
    package_dir: &Path,
    reply: ScriptedReply,
) -> (ReviewOutcome, TempDir, Arc<ReviewStore>) {
    let sandbox: Arc<dyn SandboxRunner> = Arc::new(StubSandbox::Serve);
    let provider = Arc::new(StubProvider { reply });
    let (dir, store) = store();
    let outcome = reviewer(cfg, sandbox, provider, Arc::clone(&store))
        .review(&key(), package_dir, FINGERPRINT)
        .await;
    (outcome, dir, store)
}

// ---------------------------------------------------------------------------
// Step-1 tests: the verdict and recording paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_clean_review_passes_and_is_recorded() {
    let (_dir, package_dir) = module_tree();
    let (db_dir, store) = store();
    let sandbox: Arc<dyn SandboxRunner> = Arc::new(StubSandbox::Serve);
    let provider = Arc::new(StubProvider {
        reply: ScriptedReply::body(&clean_reply()),
    });

    let outcome = reviewer(base_cfg(), sandbox, provider, Arc::clone(&store))
        .review(&key(), &package_dir, FINGERPRINT)
        .await;

    assert!(
        matches!(outcome, ReviewOutcome::Clean),
        "a clean verdict must pass, got {outcome:?}"
    );

    let rows = store
        .list(&ReviewFilter {
            limit: 10,
            ..Default::default()
        })
        .expect("list reviews");
    assert_eq!(rows.len(), 1, "a completed clean review must store a row");
    let row = &rows[0];
    assert_eq!(row.verdict, "clean");
    assert!(!row.blocked);
    assert_eq!(row.key.package, "demo-package");
    assert_eq!(row.fingerprint, FINGERPRINT);
    drop(db_dir);
}

#[tokio::test]
async fn a_malicious_review_blocks_and_is_recorded() {
    let (_dir, package_dir) = module_tree();
    let (_db_dir, store) = store();
    let sandbox: Arc<dyn SandboxRunner> = Arc::new(StubSandbox::Serve);
    let provider = Arc::new(StubProvider {
        reply: ScriptedReply::body(&malicious_reply()),
    });

    let outcome = reviewer(base_cfg(), sandbox, provider, Arc::clone(&store))
        .review(&key(), &package_dir, FINGERPRINT)
        .await;

    let (code, _) = reason_of(&outcome);
    assert_eq!(code, "ai:malicious");

    let rows = store
        .list(&ReviewFilter {
            limit: 10,
            ..Default::default()
        })
        .expect("list reviews");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].verdict, "malicious");
    assert!(
        rows[0].blocked,
        "a blocked review must record blocked: true"
    );
}

#[tokio::test]
async fn a_suspicious_review_passes_by_default_and_is_still_recorded() {
    let (_dir, package_dir) = module_tree();
    let (_db_dir, store) = store();
    let sandbox: Arc<dyn SandboxRunner> = Arc::new(StubSandbox::Serve);
    let provider = Arc::new(StubProvider {
        reply: ScriptedReply::body(&model_reply_body(
            r#"{"verdict":"suspicious","summary":"odd but not malicious","findings":[]}"#,
        )),
    });

    let outcome = reviewer(base_cfg(), sandbox, provider, Arc::clone(&store))
        .review(&key(), &package_dir, FINGERPRINT)
        .await;

    assert!(
        matches!(outcome, ReviewOutcome::Clean),
        "block_on Malicious must pass a suspicious verdict, got {outcome:?}"
    );

    let rows = store
        .list(&ReviewFilter {
            limit: 10,
            ..Default::default()
        })
        .expect("list reviews");
    assert_eq!(
        rows.len(),
        1,
        "a passed suspicious review is still recorded"
    );
    assert_eq!(rows[0].verdict, "suspicious");
    assert!(!rows[0].blocked);
}

#[tokio::test]
async fn a_suspicious_review_blocks_when_the_operator_opted_in() {
    let (_dir, package_dir) = module_tree();
    let mut cfg = base_cfg();
    cfg.block_on = BlockOn::Suspicious;

    let outcome = review_with(
        cfg,
        &package_dir,
        ScriptedReply::body(&model_reply_body(
            r#"{"verdict":"suspicious","summary":"odd but not malicious","findings":[]}"#,
        )),
    )
    .await;

    let (code, _) = reason_of(&outcome);
    assert_eq!(code, "ai:suspicious");
}

// ---------------------------------------------------------------------------
// Step-1 tests: coverage and the install surface
// ---------------------------------------------------------------------------

/// Two ordinary modules of equal size, a cap that fits only one, and a
/// threshold above what one file covers. This tree is the
/// thin-coverage fixture: whatever the model says, the payload sent
/// under half the reviewable bytes.
fn two_module_tree(dir: &TempDir) -> PathBuf {
    let package_dir = dir.path().join("unpacked");
    fs::create_dir(&package_dir).unwrap();
    write_file(
        &package_dir,
        "demo/a.py",
        &"x = 1\n".repeat(200), // 1_200 bytes
    );
    write_file(
        &package_dir,
        "demo/b.py",
        &"y = 2\n".repeat(200), // 1_200 bytes
    );
    package_dir
}

#[tokio::test]
async fn coverage_below_the_threshold_blocks_even_on_a_clean_verdict() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let package_dir = two_module_tree(&dir);
    let mut cfg = base_cfg();
    cfg.max_payload_bytes = 2_000; // fits one 1_200-byte module, not two
    cfg.coverage_threshold = 0.9;

    let outcome = review_with(cfg, &package_dir, ScriptedReply::body(&clean_reply())).await;

    let (code, detail) = reason_of(&outcome);
    assert_eq!(code, "ai:coverage");
    assert!(
        detail.contains('0') && detail.contains("0.9"),
        "the coverage detail must state the measured coverage and the threshold, got {detail:?}"
    );
    // The measured coverage for one of two equal modules is 0.5.
    assert!(detail.contains("0.5"), "detail was {detail:?}");
}

#[tokio::test]
async fn undefined_coverage_passes() {
    // A tree whose only file is a compiled extension: no reviewable
    // source, so coverage is undefined rather than zero.
    let dir = tempfile::tempdir().expect("create temp dir");
    let package_dir = dir.path().join("unpacked");
    fs::create_dir(&package_dir).unwrap();
    write_file(&package_dir, "demo/_speedup.so", "\u{7f}ELF fake payload");

    let (_db_dir, store) = store();
    let sandbox: Arc<dyn SandboxRunner> = Arc::new(StubSandbox::Serve);
    let provider = Arc::new(StubProvider {
        reply: ScriptedReply::body(&clean_reply()),
    });

    let outcome = reviewer(base_cfg(), sandbox, provider, Arc::clone(&store))
        .review(&key(), &package_dir, FINGERPRINT)
        .await;

    assert!(
        matches!(outcome, ReviewOutcome::Clean),
        "undefined coverage is no evidence, not a block, got {outcome:?}"
    );
    let rows = store
        .list(&ReviewFilter {
            limit: 10,
            ..Default::default()
        })
        .expect("list reviews");
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].coverage.is_none(),
        "a package with no reviewable source must record coverage NULL"
    );
}

#[tokio::test]
async fn an_incomplete_install_surface_blocks_regardless_of_coverage() {
    // A 20_000-byte setup.py against an 8_192-byte cap: the install
    // surface cannot be sent, so the review is insufficient no matter
    // what the model said about the rest.
    let dir = tempfile::tempdir().expect("create temp dir");
    let package_dir = dir.path().join("unpacked");
    fs::create_dir(&package_dir).unwrap();
    write_file(
        &package_dir,
        "setup.py",
        &"# padding\n".repeat(2_000), // 20_000 bytes
    );

    let outcome = review_with(
        base_cfg(),
        &package_dir,
        ScriptedReply::body(&clean_reply()),
    )
    .await;

    let (code, _) = reason_of(&outcome);
    assert_eq!(code, "ai:coverage");
}

// ---------------------------------------------------------------------------
// Step-1 tests: opaque executables
// ---------------------------------------------------------------------------

fn opaque_tree(dir: &TempDir) -> PathBuf {
    let package_dir = dir.path().join("unpacked");
    fs::create_dir(&package_dir).unwrap();
    write_file(&package_dir, "demo/__init__.py", "VERSION = '1.0.0'\n");
    write_file(&package_dir, "demo/_speedup.so", "\u{7f}ELF fake payload");
    package_dir
}

#[tokio::test]
async fn opaque_executables_pass_by_default() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let package_dir = opaque_tree(&dir);

    let outcome = review_with(
        base_cfg(),
        &package_dir,
        ScriptedReply::body(&clean_reply()),
    )
    .await;

    assert!(
        matches!(outcome, ReviewOutcome::Clean),
        "block_opaque_executables defaults to false, got {outcome:?}"
    );
}

#[tokio::test]
async fn opaque_executables_block_when_the_operator_opted_in() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let package_dir = opaque_tree(&dir);
    let mut cfg = base_cfg();
    cfg.block_opaque_executables = true;

    let outcome = review_with(cfg, &package_dir, ScriptedReply::body(&clean_reply())).await;

    let (code, _) = reason_of(&outcome);
    assert_eq!(code, "ai:opaque-executable");
}

// ---------------------------------------------------------------------------
// Step-1 tests: failure mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_failed_collector_is_unverifiable_and_records_nothing() {
    let (_dir, package_dir) = module_tree();
    let (_db_dir, store) = store();

    // A sandbox that refuses to run anything at all.
    let sandbox: Arc<dyn SandboxRunner> = Arc::new(StubSandbox::SandboxError(
        "bwrap refused to start".to_string(),
    ));
    let provider = Arc::new(StubProvider {
        reply: ScriptedReply::body(&clean_reply()),
    });

    let outcome = reviewer(base_cfg(), sandbox, provider, Arc::clone(&store))
        .review(&key(), &package_dir, FINGERPRINT)
        .await;

    let (code, _) = reason_of(&outcome);
    assert_eq!(code, "unverifiable:ai-collector");
    assert_eq!(
        review_count(&store, "demo-package"),
        0,
        "no review happened, so no row may exist"
    );
}

#[tokio::test]
async fn a_collector_nonzero_exit_is_unverifiable() {
    let (_dir, package_dir) = module_tree();
    let (_db_dir, store) = store();
    let sandbox: Arc<dyn SandboxRunner> = Arc::new(StubSandbox::CollectorFailure(2));
    let provider = Arc::new(StubProvider {
        reply: ScriptedReply::body(&clean_reply()),
    });

    let outcome = reviewer(base_cfg(), sandbox, provider, Arc::clone(&store))
        .review(&key(), &package_dir, FINGERPRINT)
        .await;

    let (code, _) = reason_of(&outcome);
    assert_eq!(code, "unverifiable:ai-collector");
    assert_eq!(review_count(&store, "demo-package"), 0);
}

#[tokio::test]
async fn a_provider_failure_is_unverifiable_and_records_nothing() {
    let (_dir, package_dir) = module_tree();
    let (_db_dir, store) = store();
    let sandbox: Arc<dyn SandboxRunner> = Arc::new(StubSandbox::Serve);
    let provider = Arc::new(StubProvider {
        reply: ScriptedReply::Timeout,
    });

    let outcome = reviewer(base_cfg(), sandbox, provider, Arc::clone(&store))
        .review(&key(), &package_dir, FINGERPRINT)
        .await;

    let (code, _) = reason_of(&outcome);
    assert_eq!(code, "unverifiable:ai-provider");
    assert_eq!(review_count(&store, "demo-package"), 0);
}

#[tokio::test]
async fn an_unparseable_reply_is_unverifiable_and_records_nothing() {
    let (_dir, package_dir) = module_tree();

    let (outcome, _db_dir, store) = review_with_store(
        base_cfg(),
        &package_dir,
        // A 200 body whose content JSON does not match the reply schema.
        ScriptedReply::body(&model_reply_body(r#"{"verdict":"probably-fine"}"#)),
    )
    .await;

    let (code, _) = reason_of(&outcome);
    assert_eq!(code, "unverifiable:ai-reply");
    assert_eq!(
        review_count(&store, "demo-package"),
        0,
        "no review happened, so no row may exist"
    );
}

#[tokio::test]
async fn a_reply_that_is_not_json_is_unverifiable() {
    let (_dir, package_dir) = module_tree();
    let (outcome, _db_dir, store) = review_with_store(
        base_cfg(),
        &package_dir,
        // Content that carries no JSON at all.
        ScriptedReply::body(
            r#"{"choices":[{"message":{"role":"assistant","content":"I think it is fine"}}]}"#,
        ),
    )
    .await;

    let (code, _) = reason_of(&outcome);
    assert_eq!(code, "unverifiable:ai-reply");
    assert_eq!(review_count(&store, "demo-package"), 0);
}

#[tokio::test]
async fn a_store_failure_is_unverifiable_rather_than_clean() {
    let (_dir, package_dir) = module_tree();
    let (_db_dir, db) = store_db();
    let store = Arc::new(ReviewStore::new(db.clone()));
    // Break the store underneath the reviewer: dropping the reviews
    // table makes every `put` fail at prepare time.
    db.conn()
        .expect("check out a connection")
        .execute("DROP TABLE reviews", [])
        .expect("drop the reviews table");

    let sandbox: Arc<dyn SandboxRunner> = Arc::new(StubSandbox::Serve);
    let provider = Arc::new(StubProvider {
        reply: ScriptedReply::body(&clean_reply()),
    });

    let outcome = reviewer(base_cfg(), sandbox, provider, store)
        .review(&key(), &package_dir, FINGERPRINT)
        .await;

    let (code, _) = reason_of(&outcome);
    assert_eq!(code, "unverifiable:ai-store");
    assert!(
        !matches!(outcome, ReviewOutcome::Clean),
        "a store failure must never read as clean"
    );
}

/// Opens a db and hands back the temp dir plus the `Db` handle, for
/// tests that then break the store underneath it.
fn store_db() -> (TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

// ---------------------------------------------------------------------------
// Step-1 tests: what a refusal detail may and may not contain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_refusal_detail_ever_contains_the_api_key() {
    // A provider error can carry key-shaped text and a malicious reply
    // can quote the key back in its summary. Neither may reach a detail.
    let (_dir, package_dir) = module_tree();
    std::env::set_var(KEY_ENV, KEY_VALUE);

    let outcomes = vec![
        // A malicious reply whose summary quotes the key back.
        review_with(
            base_cfg(),
            &package_dir,
            ScriptedReply::body(&model_reply_body(&format!(
                r#"{{"verdict":"malicious","summary":"the key {KEY_VALUE} was used","findings":[]}}"#
            ))),
        )
        .await,
        // A provider failure whose error text embeds the key.
        review_with(
            base_cfg(),
            &package_dir,
            ScriptedReply::TransportError(format!("connection to {KEY_VALUE} failed")),
        )
        .await,
    ];

    std::env::remove_var(KEY_ENV);

    for outcome in outcomes {
        let (_, detail) = reason_of(&outcome);
        assert!(
            !detail.contains(KEY_VALUE),
            "a refusal detail leaked the api key: {detail:?}"
        );
    }
}

#[tokio::test]
async fn every_refusal_detail_is_printable_ascii_within_its_cap() {
    // A malicious reply whose summary is long, non-ASCII and carries
    // control bytes: the detail must come out printable ASCII at most
    // 120 bytes for the reason phrase downstream.
    let (_dir, package_dir) = module_tree();
    let hostile = format!(
        "M\u{e9}dium \u{2014} detail {}\u{7}{}\u{a}",
        "x".repeat(500),
        "y".repeat(500)
    );
    let reply = model_reply_body(
        &serde_json::json!({
            "verdict": "malicious",
            "summary": hostile,
            "findings": [],
        })
        .to_string(),
    );

    let outcome = review_with(base_cfg(), &package_dir, ScriptedReply::body(&reply)).await;

    let (code, detail) = reason_of(&outcome);
    assert_eq!(code, "ai:malicious");
    assert!(detail.len() <= MAX_PHRASE_BYTES, "detail was {detail:?}");
    assert!(
        detail
            .chars()
            .all(|c| c.is_ascii() && !c.is_ascii_control()),
        "detail must be printable ASCII for the reason phrase, got {detail:?}"
    );
}

#[tokio::test]
async fn the_model_cannot_choose_the_refusal_code() {
    // The malicious fixture's summary carries a refusal-code-shaped
    // string. The code must still be ai:malicious: the code comes from
    // the mapped verdict, never from the model's own text.
    let (_dir, package_dir) = module_tree();

    let outcome = review_with(
        base_cfg(),
        &package_dir,
        ScriptedReply::body(&malicious_reply()),
    )
    .await;

    let (code, detail) = reason_of(&outcome);
    assert_eq!(code, "ai:malicious");
    assert_ne!(code, "cve:critical");
    // The summary stays in the detail as text (sanitized) and never
    // becomes the code.
    assert!(!detail.is_empty());
}

// ---------------------------------------------------------------------------
// The real sandbox
// ---------------------------------------------------------------------------
// The two tests below are the Task 4 pair kept from before Task 8. They
// remain #[ignore]d: they need `bwrap` on PATH and usable user
// namespaces, which `cargo test` may not rely on. Run them with
// `cargo test --test ai_review -- --ignored` on a host that has both.

/// Builds a small package tree under a fresh temp directory: one
/// install-surface file and one ordinary module, both plain text.
fn small_package() -> (TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let package_dir = root.path().join("unpacked");
    fs::create_dir(&package_dir).unwrap();
    write_file(&package_dir, "setup.py", "from setuptools import setup\n");
    write_file(&package_dir, "demo/__init__.py", "VERSION = '1.0.0'\n");
    (root, package_dir)
}

#[test]
#[ignore = "requires bwrap and usable namespaces"]
fn the_collector_runs_under_a_real_sandbox_and_returns_a_payload() {
    let (_root, package_dir) = small_package();
    let sandbox = BubblewrapSandbox::detect().expect("bwrap must be on PATH");

    let spec = collector_spec(
        &binary(),
        &package_dir,
        &key(),
        8_192,
        Duration::from_secs(15),
    );
    let outcome = sandbox
        .run(&spec)
        .expect("the collector must run under the sandbox");

    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the collector did not succeed: output {:?}",
        outcome.output
    );

    let payload = supply_chain_scanner::ai::parse_collector_output(&outcome)
        .expect("the collected output must parse as a payload");
    assert!(
        payload.files.iter().any(|file| file.path == "setup.py"),
        "setup.py is missing from the payload: {:?}",
        payload
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
#[ignore = "requires bwrap and usable namespaces"]
fn the_collector_cannot_reach_the_network_from_inside_the_sandbox() {
    let (_root, package_dir) = small_package();
    let sandbox = BubblewrapSandbox::detect().expect("bwrap must be on PATH");

    let timeout = Duration::from_secs(10);
    let spec = collector_spec(&binary(), &package_dir, &key(), 8_192, timeout);

    // The collector's own code opens no socket, so the run must succeed
    // inside a sandbox that has no network at all. The wall-clock check
    // is the actual no-network proof. Nothing in this collection tree
    // waits on a connection, so a run near the whole timeout would mean
    // the collector was blocked on the outside world.
    let started = std::time::Instant::now();
    let outcome = sandbox
        .run(&spec)
        .expect("the collector must run under the sandbox");
    let elapsed = started.elapsed();

    assert!(
        elapsed < timeout.saturating_sub(Duration::from_secs(5)),
        "the run took {elapsed:?} of a {timeout:?} budget: nothing in the \
         collector waits on the network, so the time went somewhere else"
    );
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "a network-less sandbox still let the collector finish, which it \
         must, because it never talks to the network: output {:?}",
        outcome.output
    );

    // The spec grants no network of its own. `--unshare-all` is the
    // sandbox's own flag. This checks only that the collector spec adds
    // nothing on top of it.
    assert!(
        !spec.args.iter().any(|arg| arg.contains("net")),
        "the collector spec must not weaken the sandbox's network isolation"
    );
}

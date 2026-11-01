//! End-to-end integration tests for
//! `supply_chain_scanner::http::cargo_bootstrap`: the fail-closed startup
//! sequence of a cargo/crates.io deployment.
//!
//! These are the tests that prove the pieces of the cargo plan actually
//! compose into a working deployment, not just that each works alone. Each
//! one calls the real `bootstrap_cargo`, serves the router it returns on an
//! ephemeral loopback port, and drives it with a real HTTP client in front
//! of a `wiremock` stand-in for the crates.io sparse index, the `.crate`
//! `dl` endpoint, the OSV feed, the cargo-vet audit source and the model
//! provider.
//!
//! # The sandbox seam
//!
//! `bootstrap_cargo` builds its sandbox with `default_sandbox_factory`,
//! which fails closed when `bwrap` is missing and, on a host where it is
//! present but unusable (as in many CI containers), would fail at run
//! time. These tests therefore call
//! `bootstrap_cargo_with_sandbox_factory` with a stub `SandboxRunner`,
//! exactly as `tests/plugin.rs` and `tests/ai_review.rs` do for their own
//! seams. Everything else — the database, the policy, the two cargo
//! upstream clients, the OSV sync, the cargo-vet sync, the scanner, the
//! router — is the production wiring, unchanged.
//!
//! The one stub does double duty. A plugin invocation is recognized by its
//! binary path (the fake plugin file this test writes); everything else is
//! the AI reviewer's collector, which the stub forwards to this repo's
//! real `collect` subcommand so the reviewer's coverage figures come from a
//! real walk of the unpacked crate.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zip::ZipWriter;

use supply_chain_scanner::config::{
    AiReviewConfig, AuditConfig, AuditRotation, BlockOn, CargoRegistryConfig, CargoVetSource,
    Config, CveLine, PluginConfig, UnknownSeverity,
};
use supply_chain_scanner::db::cargo_vet::CargoVetStore;
use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::ecosystem::cargo::index::index_path_for;
use supply_chain_scanner::http::cargo_bootstrap::{
    bootstrap_cargo, bootstrap_cargo_with_sandbox_factory, CargoWired,
};
use supply_chain_scanner::model::{ArtifactKey, RefusalReason, Verdict};
use supply_chain_scanner::plugin::{
    SandboxOutcome, SandboxRunner, SandboxSpec, SANDBOX_PACKAGE_DIR,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A `.crate`'s bytes: a gzipped tar of a small, ordinary Rust crate,
/// wrapped in the `<name>-<version>/` directory cargo publishes.
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
            builder
                .append_data(&mut header, format!("{root}/{rel}"), &body[..])
                .expect("append crate entry");
        }
        builder.finish().expect("finish crate fixture");
    }
    buf
}

/// An empty OSV feed zip: enough for the initial advisory sync to succeed
/// with nothing to ingest, so no test touches the real network.
fn empty_osv_zip() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let writer = ZipWriter::new(cursor);
        writer.finish().expect("finish empty zip");
    }
    buf
}

/// The chat-completions reply carrying a clean model verdict, shaped the
/// way `tests/ai_review.rs` builds its own fixtures.
fn clean_model_reply() -> String {
    let verdict = serde_json::json!({
        "verdict": "clean",
        "summary": "ordinary crate sources",
        "findings": [],
    })
    .to_string();
    let content = serde_json::to_string(&verdict).expect("escape the verdict");
    format!(
        r#"{{"id":"resp_1","choices":[{{"index":0,"message":{{"role":"assistant","content":{content}}},"finish_reason":"stop"}}]}}"#
    )
}

/// Mounts the sparse index's `config.json`, one crate's index file, and one
/// download for `vers`, all pointing back at `server`. Mirrors
/// `tests/http_cargo_download.rs`'s `mount` helper.
async fn mount_registry(server: &MockServer, name: &str, vers: &str, bytes: &[u8]) {
    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{{\"dl\":\"{}/crates/{{crate}}/{{version}}/download\"}}",
            server.uri()
        )))
        .mount(server)
        .await;

    let cksum = sha256_hex(bytes);
    Mock::given(method("GET"))
        .and(path(format!("/{}", index_path_for(name))))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{{\"name\":\"{name}\",\"vers\":\"{vers}\",\"cksum\":\"{cksum}\",\"yanked\":false,\"deps\":[]}}\n"
        )))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/crates/{name}/{vers}/download")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
        .mount(server)
        .await;
}

async fn mount_empty_osv_feed(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(empty_osv_zip()))
        .mount(server)
        .await;
}

async fn mount_clean_model(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_string(clean_model_reply()))
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// The sandbox stub
// ---------------------------------------------------------------------------

/// A `SandboxRunner` that never invokes `bwrap`.
///
/// A plugin run is recognized by `spec.binary` equalling the fake plugin
/// path, and answers with a clean exit. Any other spec is the AI reviewer's
/// collector: the stub runs this repo's real collector binary on the host,
/// substituting the sandbox mount point for the host package tree, exactly
/// as `tests/ai_review.rs`'s `StubSandbox::Serve` does. That keeps the
/// reviewer's coverage figures real without confinement.
struct StubSandbox {
    plugin_binary: PathBuf,
    plugin_runs: AtomicUsize,
}

impl StubSandbox {
    fn new(plugin_binary: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            plugin_binary,
            plugin_runs: AtomicUsize::new(0),
        })
    }

    fn plugin_runs(&self) -> usize {
        self.plugin_runs.load(Ordering::SeqCst)
    }
}

impl SandboxRunner for StubSandbox {
    fn run(&self, spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        if spec.binary == self.plugin_binary {
            self.plugin_runs.fetch_add(1, Ordering::SeqCst);
            return Ok(SandboxOutcome {
                exit_code: Some(0),
                output: String::new(),
                timed_out: false,
                signal: None,
            });
        }

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
        let output =
            std::process::Command::new(PathBuf::from(env!("CARGO_BIN_EXE_supply-chain-scanner")))
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
// Config and server wiring
// ---------------------------------------------------------------------------

/// A minimal, fully valid `Config` for a cargo deployment pointed at
/// `server` for everything: the sparse index, the `.crate` download, the
/// OSV feed, and (when enabled) the model provider.
///
/// `upstream_url` is required on `Config` whether or not `[cargo_registry]`
/// is present, and a cargo deployment never reads it; it is set to the same
/// stand-in so nothing in this file can reach the real PyPI.
fn cargo_config(
    server: &MockServer,
    public_url: Url,
    db_path: PathBuf,
    cache_dir: PathBuf,
) -> Config {
    let base = Url::parse(&format!("{}/", server.uri())).expect("valid upstream index url");
    // `bootstrap_cargo` now opens the audit log for real (this task), so
    // this can no longer be `AuditConfig::default()`'s bare "audit.jsonl":
    // that resolves relative to the test binary's current directory,
    // which is the repo's working directory, and every test in this file
    // would leave a real file behind there. Co-locating it next to this
    // test's own `db_path` keeps it inside that test's tempdir, which is
    // removed automatically when the `TempDir` guard drops. See
    // `tests/e2e.rs`'s own `base_config` for the PyPI path's identical fix.
    let audit_path = db_path
        .parent()
        .expect("db_path has a parent directory")
        .join("audit.jsonl");
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        db_path,
        cache_dir,
        upstream_url: Url::parse(&server.uri()).expect("valid upstream url"),
        public_url,
        scan_budget: Duration::from_secs(10),
        cache_ttl: Duration::from_secs(60 * 60),
        advisory_sync_interval: Duration::from_secs(60 * 60),
        advisory_source_url: Url::parse(&format!("{}/all.zip", server.uri()))
            .expect("valid advisory url"),
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
            upstream_index_url: base,
            cargo_vet_sync_interval: Duration::from_secs(60 * 60),
            cargo_vet_sources: Vec::new(),
            required_criterion: "safe-to-deploy".to_string(),
            trusted_reviewers: Vec::new(),
            min_release_age_days: None,
        }),
        npm_registry: None,
        audit: AuditConfig {
            path: audit_path,
            rotation: AuditRotation::Daily,
            max_files: 14,
        },
    }
}

fn plugin_config(binary: PathBuf) -> PluginConfig {
    PluginConfig {
        name: "yara".to_string(),
        binary,
        timeout: Duration::from_secs(5),
    }
}

fn ai_review_config(server: &MockServer) -> AiReviewConfig {
    let mut base = Url::parse(&server.uri()).expect("valid provider url");
    base.set_path("/v1/");
    AiReviewConfig {
        enabled: true,
        base_url: base,
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

/// Writes a fake plugin binary into `dir` and returns its path. It is never
/// executed: the stub sandbox answers for it. `Policy::build` only hashes
/// the file, so its contents are irrelevant.
fn fake_plugin_binary(dir: &Path) -> PathBuf {
    let binary = dir.join("yara");
    std::fs::write(&binary, b"pretend plugin binary").expect("write plugin binary");
    binary
}

struct Served {
    _db_dir: tempfile::TempDir,
    _cache_dir: tempfile::TempDir,
    _plugin_dir: tempfile::TempDir,
    base_url: Url,
    wired: CargoWired,
    sandbox: Arc<StubSandbox>,
    _server: tokio::task::JoinHandle<()>,
}

/// Binds an ephemeral listener, builds the config against it (so
/// `public_url` matches the port actually served), runs the real
/// `bootstrap_cargo_with_sandbox_factory`, and spawns the router.
async fn start(
    server: &MockServer,
    configure: impl FnOnce(&mut Config, PathBuf),
) -> anyhow::Result<Served> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;
    let base_url = Url::parse(&format!("http://127.0.0.1:{}/", addr.port()))?;

    let db_dir = tempfile::tempdir().expect("create db temp dir");
    let cache_dir = tempfile::tempdir().expect("create cache temp dir");
    let plugin_dir = tempfile::tempdir().expect("create plugin temp dir");
    let plugin_binary = fake_plugin_binary(plugin_dir.path());

    let mut cfg = cargo_config(
        server,
        base_url.clone(),
        db_dir.path().join("scanner.db"),
        cache_dir.path().join("cache"),
    );
    configure(&mut cfg, plugin_binary.clone());

    let sandbox = StubSandbox::new(plugin_binary);
    let factory: supply_chain_scanner::http::SandboxFactory = {
        let sandbox = Arc::clone(&sandbox);
        Arc::new(move |_: &Config| Ok(sandbox.clone() as Arc<dyn SandboxRunner>))
    };

    let wired = bootstrap_cargo_with_sandbox_factory(cfg, factory).await?;
    let router = wired.router.clone();
    let served = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });

    Ok(Served {
        _db_dir: db_dir,
        _cache_dir: cache_dir,
        _plugin_dir: plugin_dir,
        base_url,
        wired,
        sandbox,
        _server: served,
    })
}

// ---------------------------------------------------------------------------
// The plan's two tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_cargo_serves_a_crate_through_the_full_cascade() {
    let server = MockServer::start().await;
    let bytes = crate_bytes("demo-crate", "1.0.0");
    mount_registry(&server, "demo-crate", "1.0.0", &bytes).await;
    mount_empty_osv_feed(&server).await;
    mount_clean_model(&server).await;

    let served = start(&server, |cfg, plugin_binary| {
        // A plugin that exits 0, and a reviewer that replies clean: the
        // two checks a never-seen version must pass before it is
        // forwarded.
        cfg.plugins = vec![plugin_config(plugin_binary)];
        cfg.ai_review = Some(ai_review_config(&server));
    })
    .await
    .expect("bootstrap a cargo deployment");

    // 1. The index gate. A never-seen crate is downloaded, verified,
    //    unpacked, reviewed clean, and then forwarded.
    let index_url = format!("{}{}", served.base_url, index_path_for("demo-crate"));
    let index_response = reqwest::get(&index_url)
        .await
        .expect("GET the crate's index file");
    assert_eq!(
        index_response.status(),
        reqwest::StatusCode::OK,
        "the cascade must forward a crate whose only version reviewed clean"
    );
    let index_body = index_response.text().await.expect("read the index body");
    assert!(
        index_body.contains("\"vers\":\"1.0.0\""),
        "the forwarded version must appear in the served index file: {index_body}"
    );
    let model_calls = server
        .received_requests()
        .await
        .expect("read the stand-in's request log")
        .iter()
        .filter(|request| request.url.path() == "/v1/chat/completions")
        .count();
    assert_eq!(
        model_calls, 1,
        "the version had no stored verdict, so the cascade must have asked the \
         reviewer exactly once before forwarding it"
    );

    // 2. The download gate. The index-side review stored a clean verdict,
    //    but not a plugin-checked one, so the plugins run here — once.
    let download_url = format!("{}crates/demo-crate/1.0.0/download", served.base_url);
    let download_response = reqwest::get(&download_url)
        .await
        .expect("GET the .crate download");
    assert_eq!(
        download_response.status(),
        reqwest::StatusCode::OK,
        "a clean, plugin-passing artifact must be served"
    );
    let served_bytes = download_response
        .bytes()
        .await
        .expect("read the crate bytes");
    assert_eq!(
        served_bytes.as_ref(),
        bytes.as_slice(),
        "the bytes served must be the verified upstream bytes"
    );
    assert_eq!(
        served.sandbox.plugin_runs(),
        1,
        "the plugin gate must run exactly once for this artifact"
    );
}

#[tokio::test]
async fn bootstrap_cargo_runs_the_cargo_vet_sync_before_serving_anything() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    const AUDITS_TOML: &str = r#"
[[audits.demo-crate]]
version = "1.0.0"
who = "Jane Auditor <jane@example.com>"
criteria = "safe-to-deploy"
"#;
    Mock::given(method("GET"))
        .and(path("/audits.toml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(AUDITS_TOML))
        .mount(&server)
        .await;

    let audits_url =
        Url::parse(&format!("{}/audits.toml", server.uri())).expect("valid audits url");

    let served = start(&server, |cfg, _plugin_binary| {
        if let Some(cargo) = cfg.cargo_registry.as_mut() {
            cargo.cargo_vet_sources = vec![CargoVetSource {
                name: "test-audits".to_string(),
                url: audits_url,
            }];
        }
    })
    .await
    .expect("bootstrap a cargo deployment");

    // The observable state, not an internal counter: startup synced the
    // configured source into the store before returning, so the fast path
    // already has a proof to consult for this exact crate and version.
    let store = CargoVetStore::new(served.wired.db.clone());
    assert!(
        !store.is_empty().expect("read the cargo-vet store"),
        "the initial cargo-vet sync must have stored at least one audit"
    );
    assert!(
        store
            .covers("demo-crate", "1.0.0", "safe-to-deploy", &[])
            .expect("query cargo-vet coverage"),
        "the synced audit must cover the version and criterion it names"
    );

    // And it happened exactly once during startup, from the configured
    // source: no ticker is running in this test.
    let hits = served
        .wired
        .db
        .clone()
        .conn()
        .and_then(|conn| {
            conn.query_row("SELECT COUNT(*) FROM cargo_vet_audits", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(anyhow::Error::from)
        })
        .expect("count stored audits");
    assert_eq!(hits, 1, "exactly one full audit must be stored");
    let requested = server
        .received_requests()
        .await
        .expect("read the stand-in's request log")
        .iter()
        .filter(|request| request.url.path() == "/audits.toml")
        .count();
    assert_eq!(
        requested, 1,
        "the audit source must be fetched exactly once"
    );
}

// ---------------------------------------------------------------------------
// The shared /refusals page on the cargo router
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_cargo_router_serves_refusals_from_its_own_state() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    let served = start(&server, |_cfg, _plugin_binary| {})
        .await
        .expect("bootstrap a cargo deployment");

    // Plant a blocked verdict the way the download gate would store one.
    let verdicts = VerdictStore::new(served.wired.db.clone());
    verdicts
        .put(
            &ArtifactKey {
                ecosystem: "cargo".to_string(),
                package: "demo-crate".to_string(),
                version: "1.0.0".to_string(),
                filename: "demo-crate-1.0.0.crate".to_string(),
                sha256: "a".repeat(64),
            },
            &Verdict::Blocked(RefusalReason {
                code: "plugin:fail".to_string(),
                detail: "the plugin refused the crate".to_string(),
            }),
            &served.wired.state.cargo_scanner.fingerprint(),
        )
        .expect("store a blocked verdict");

    let response = reqwest::get(format!("{}refusals", served.base_url))
        .await
        .expect("GET /refusals");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.expect("read the refusals body");
    assert!(
        body.contains("demo-crate"),
        "the blocked crate must be listed: {body}"
    );
    assert!(
        body.contains("/why/"),
        "each row must link to its explanation: {body}"
    );
}

// ---------------------------------------------------------------------------
// The dispatch rule's own guard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_cargo_refuses_a_config_with_no_cargo_registry_table() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().expect("create temp dir");
    let mut cfg = cargo_config(
        &server,
        Url::parse("http://127.0.0.1:9/").expect("valid url"),
        dir.path().join("scanner.db"),
        dir.path().join("cache"),
    );
    cfg.cargo_registry = None;

    let err = bootstrap_cargo(cfg)
        .await
        .err()
        .expect("a config with no [cargo_registry] must not boot a cargo deployment");
    assert!(
        err.to_string().contains("[cargo_registry]"),
        "the error must name the missing table: {err:#}"
    );
}

// ---------------------------------------------------------------------------
// The routes a cargo deployment shares with the PyPI path
// ---------------------------------------------------------------------------

/// `/healthz` must answer on a cargo deployment. An operator's liveness
/// probe does not know which ecosystem it is watching, and a probe that
/// 404s reads as a dead process.
#[tokio::test]
async fn a_cargo_deployment_answers_healthz() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;
    let served = start(&server, |_, _| {}).await.expect("bootstrap");

    let response = reqwest::get(format!("{}healthz", served.base_url))
        .await
        .expect("GET healthz");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

/// `/why/<id>` must resolve on a cargo deployment. A plugin refusal
/// arrives as a real 403 whose reason phrase carries a `/why/<id>` link,
/// so without this route the proxy hands a developer a link to a 404.
#[tokio::test]
async fn a_cargo_plugin_refusal_why_link_resolves() {
    let server = MockServer::start().await;
    let bytes = crate_bytes("demo-crate", "1.0.0");
    mount_registry(&server, "demo-crate", "1.0.0", &bytes).await;
    mount_empty_osv_feed(&server).await;
    mount_clean_model(&server).await;

    let served = start(&server, |cfg, plugin_binary| {
        cfg.plugins = vec![plugin_config(plugin_binary)];
        cfg.ai_review = Some(ai_review_config(&server));
    })
    .await
    .expect("bootstrap");

    // Get the version admitted to the index first, then download it.
    let index_url = format!("{}{}", served.base_url, index_path_for("demo-crate"));
    let _ = reqwest::get(&index_url).await.expect("prime the cascade");
    let download_url = format!("{}crates/demo-crate/1.0.0/download", served.base_url);
    let download = reqwest::get(&download_url).await.expect("download");
    assert_eq!(download.status(), reqwest::StatusCode::OK);

    // A stored verdict exists for the artifact, so its why-id resolves.
    let key = ArtifactKey {
        ecosystem: "cargo".to_string(),
        package: "demo-crate".to_string(),
        version: "1.0.0".to_string(),
        filename: "demo-crate-1.0.0.crate".to_string(),
        sha256: sha256_hex(&bytes),
    };
    let stored = served
        .wired
        .state
        .verdicts
        .get(&key, &served.wired.state.cargo_scanner.fingerprint())
        .expect("query the stored verdict")
        .expect("a downloaded artifact must have a stored verdict");

    let why_url = format!("{}why/{}", served.base_url, stored.why_id);
    let why = reqwest::get(&why_url).await.expect("GET the why page");
    assert_eq!(
        why.status(),
        reqwest::StatusCode::OK,
        "a cargo deployment's /why/<id> must not be a 404"
    );
    let body = why.text().await.expect("read the why body");
    assert!(
        body.contains("demo-crate"),
        "the page must explain this artifact: {body}"
    );
}

/// `/api/reviews` must exist on a cargo deployment, behind the same
/// `[ai_review]` gate it has on the PyPI path: a 404 when the table is
/// absent, a JSON listing when it is present.
#[tokio::test]
async fn a_cargo_deployment_serves_api_reviews_behind_the_ai_gate() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    // No [ai_review]: the gate must answer 404, exactly as on PyPI.
    let without = start(&server, |_, _| {}).await.expect("bootstrap");
    let gated = reqwest::get(format!("{}api/reviews", without.base_url))
        .await
        .expect("GET api/reviews");
    assert_eq!(
        gated.status(),
        reqwest::StatusCode::NOT_FOUND,
        "an unconfigured deployment must hide /api/reviews"
    );

    // With [ai_review]: the listing answers 200 JSON.
    let configured = start(&server, |cfg, _| {
        cfg.ai_review = Some(ai_review_config(&server));
    })
    .await
    .expect("bootstrap");
    let listed = reqwest::get(format!("{}api/reviews", configured.base_url))
        .await
        .expect("GET api/reviews");
    assert_eq!(listed.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = listed.json().await.expect("api/reviews is JSON");
    assert!(
        body["reviews"].is_array(),
        "the listing must carry a reviews array: {body}"
    );
}

/// `[ai_review]` with `enabled = false` must behave exactly like an
/// absent table: the gate hides `/api/reviews`, the provider is never
/// called, and a never-seen crate (which can only pass through a review)
/// is forwarded empty rather than served.
#[tokio::test]
async fn a_disabled_reviewer_behaves_like_no_reviewer_at_all() {
    let server = MockServer::start().await;
    let bytes = crate_bytes("demo-crate", "1.0.0");
    mount_registry(&server, "demo-crate", "1.0.0", &bytes).await;
    mount_empty_osv_feed(&server).await;
    mount_clean_model(&server).await;

    let served = start(&server, |cfg, _| {
        let mut ai = ai_review_config(&server);
        ai.enabled = false;
        cfg.ai_review = Some(ai);
    })
    .await
    .expect("bootstrap a cargo deployment with the reviewer disabled");

    let gated = reqwest::get(format!("{}api/reviews", served.base_url))
        .await
        .expect("GET api/reviews");
    assert_eq!(
        gated.status(),
        reqwest::StatusCode::NOT_FOUND,
        "a disabled [ai_review] table must hide /api/reviews, same as an absent one"
    );

    let index_url = format!("{}{}", served.base_url, index_path_for("demo-crate"));
    let index_response = reqwest::get(&index_url)
        .await
        .expect("GET the crate's index file");
    assert_eq!(
        index_response.status(),
        reqwest::StatusCode::OK,
        "a crate with no usable version renders like an ordinary index, not an error"
    );
    let index_body = index_response.text().await.expect("read the index body");
    assert!(
        !index_body.contains("\"vers\":\"1.0.0\""),
        "with no reviewer to pass, the only version must not be forwarded: {index_body}"
    );

    let model_calls = server
        .received_requests()
        .await
        .expect("read the stand-in's request log")
        .iter()
        .filter(|request| request.url.path() == "/v1/chat/completions")
        .count();
    assert_eq!(
        model_calls, 0,
        "a disabled reviewer must never be called, even though the table is present"
    );
}

// ---------------------------------------------------------------------------
// The allowlist, and CVE filtering, on the cargo path
// ---------------------------------------------------------------------------

/// An allowlist entry must let a version through the index gate with no
/// AI review and no cargo-vet audit. This is the documented workaround
/// for a version the newest-first walk cannot reach, so it has to work.
#[tokio::test]
async fn an_allowlisted_version_is_forwarded_without_any_review() {
    let server = MockServer::start().await;
    let bytes = crate_bytes("demo-crate", "1.0.0");
    mount_registry(&server, "demo-crate", "1.0.0", &bytes).await;
    mount_empty_osv_feed(&server).await;

    // No reviewer configured: without the allowlist nothing could ever
    // pass. With it, the version is forwarded.
    let served = start(&server, |cfg, _| {
        cfg.allowlist = vec![supply_chain_scanner::config::AllowEntry {
            package: "demo-crate".to_string(),
            version: "1.0.0".to_string(),
        }];
    })
    .await
    .expect("bootstrap");

    let index_url = format!("{}{}", served.base_url, index_path_for("demo-crate"));
    let body = reqwest::get(&index_url)
        .await
        .expect("GET the index file")
        .text()
        .await
        .expect("read the body");
    assert!(
        body.contains("\"vers\":\"1.0.0\""),
        "an allowlisted version must be forwarded: {body:?}"
    );
}

/// An allowlist entry must also override a stored `Blocked` verdict at the
/// download gate, the same precedence the PyPI path gives it. Without
/// this, a version allowlisted after a plugin blocked it would stay
/// refused forever.
#[tokio::test]
async fn an_allowlisted_version_overrides_a_stored_plugin_block() {
    let server = MockServer::start().await;
    let bytes = crate_bytes("demo-crate", "1.0.0");
    mount_registry(&server, "demo-crate", "1.0.0", &bytes).await;
    mount_empty_osv_feed(&server).await;
    mount_clean_model(&server).await;

    let served = start(&server, |cfg, plugin_binary| {
        cfg.plugins = vec![plugin_config(plugin_binary)];
        cfg.ai_review = Some(ai_review_config(&server));
    })
    .await
    .expect("bootstrap");

    // Store a block for this artifact, as a plugin refusal would.
    let key = ArtifactKey {
        ecosystem: "cargo".to_string(),
        package: "demo-crate".to_string(),
        version: "1.0.0".to_string(),
        filename: "demo-crate-1.0.0.crate".to_string(),
        sha256: sha256_hex(&bytes),
    };
    let fingerprint = served.wired.state.cargo_scanner.fingerprint();
    served
        .wired
        .state
        .verdicts
        .put(
            &key,
            &Verdict::Blocked(RefusalReason {
                code: "plugin:yara".to_string(),
                detail: "blocked by a plugin".to_string(),
            }),
            &fingerprint,
        )
        .expect("store a blocked verdict");

    let download_url = format!("{}crates/demo-crate/1.0.0/download", served.base_url);

    // Without an allowlist, the stored block refuses the download.
    let refused = reqwest::get(&download_url).await.expect("download");
    assert_eq!(
        refused.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a stored block must refuse a non-allowlisted artifact"
    );

    // The allowlist lives in the config snapshot `bootstrap_cargo` took,
    // so assert the gate's decision directly through the same helper the
    // handler uses. A fresh deployment with the entry set proves the
    // override; mutating a running one is what SIGHUP would do, and the
    // cargo path has no reloader.
    let dirs = tempfile::tempdir().expect("create temp dir");
    let _ = dirs;
    let allowed = start(&server, |cfg, plugin_binary| {
        cfg.plugins = vec![plugin_config(plugin_binary)];
        cfg.ai_review = Some(ai_review_config(&server));
        cfg.allowlist = vec![supply_chain_scanner::config::AllowEntry {
            package: "demo-crate".to_string(),
            version: "1.0.0".to_string(),
        }];
    })
    .await
    .expect("bootstrap");

    let allowed_key = ArtifactKey {
        ecosystem: "cargo".to_string(),
        package: "demo-crate".to_string(),
        version: "1.0.0".to_string(),
        filename: "demo-crate-1.0.0.crate".to_string(),
        sha256: sha256_hex(&bytes),
    };
    allowed
        .wired
        .state
        .verdicts
        .put(
            &allowed_key,
            &Verdict::Blocked(RefusalReason {
                code: "plugin:yara".to_string(),
                detail: "blocked by a plugin".to_string(),
            }),
            &allowed.wired.state.cargo_scanner.fingerprint(),
        )
        .expect("store a blocked verdict");

    let served_bytes = reqwest::get(format!(
        "{}crates/demo-crate/1.0.0/download",
        allowed.base_url
    ))
    .await
    .expect("download");
    assert_eq!(
        served_bytes.status(),
        reqwest::StatusCode::OK,
        "an allowlisted artifact must be served despite its stored block"
    );
}

/// The CVE half of the cascade: a version matching a blocking advisory
/// must be absent from the forwarded index. This is the check that runs
/// against every published version on every request, and nothing on the
/// cargo path tested it before.
#[tokio::test]
async fn a_cve_blocked_version_is_absent_from_the_forwarded_index() {
    let server = MockServer::start().await;
    let bytes = crate_bytes("demo-crate", "1.0.0");
    mount_registry(&server, "demo-crate", "1.0.0", &bytes).await;
    mount_empty_osv_feed(&server).await;
    mount_clean_model(&server).await;

    let served = start(&server, |cfg, _| {
        cfg.ai_review = Some(ai_review_config(&server));
        // Block every advisory scoring at least 7.0, which the seeded
        // advisory below does.
        cfg.cve.min_severity = 7.0;
    })
    .await
    .expect("bootstrap");

    // Seed the mirror after startup, so the initial (empty) OSV sync is
    // not what decides this test.
    supply_chain_scanner::db::advisory::AdvisoryStore::new(served.wired.db.clone())
        .replace_all(
            "crates.io",
            &[supply_chain_scanner::advisory::Advisory {
                id: "RUSTSEC-TEST".to_string(),
                package: "demo-crate".to_string(),
                summary: "a test advisory".to_string(),
                severity: Some(9.8),
                versions: vec!["1.0.0".to_string()],
                ranges: Vec::new(),
                fixed_versions: Vec::new(),
            }],
        )
        .expect("seed the advisory mirror");

    let index_url = format!("{}{}", served.base_url, index_path_for("demo-crate"));
    let response = reqwest::get(&index_url).await.expect("GET the index file");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "a crate whose every version is advisory-blocked must still answer 200"
    );
    let body = response.text().await.expect("read the body");
    assert!(
        !body.contains("1.0.0"),
        "a CVE-blocked version must not be forwarded: {body:?}"
    );
    assert!(
        body.trim().is_empty(),
        "the whole version list is blocked, so the body must be empty: {body:?}"
    );
}

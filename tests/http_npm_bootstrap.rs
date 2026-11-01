//! End-to-end integration tests for
//! `supply_chain_scanner::http::npm_bootstrap`: the fail-closed startup
//! sequence of an npm registry deployment.
//!
//! These are the tests that prove the npm pieces compose into a working
//! deployment, not just that each works alone. Each one calls the real
//! `bootstrap_npm`, serves the router it returns on an ephemeral loopback
//! port, and drives it with a real HTTP client in front of a `wiremock`
//! stand-in for the npm registry, the OSV feed and the model provider.
//!
//! # The sandbox seam
//!
//! `bootstrap_npm` builds its sandbox with `default_sandbox_factory`,
//! which fails closed when `bwrap` is missing and, on a host where it is
//! present but unusable (as in many CI containers), would fail at run
//! time. These tests therefore call `bootstrap_npm_with_sandbox_factory`
//! with a stub `SandboxRunner`, exactly as `tests/http_cargo_bootstrap.rs`
//! does for its own seam. Everything else — the database, the policy, the
//! two npm upstream clients, the OSV sync, the scanner, the router — is
//! the production wiring, unchanged.
//!
//! The one stub does double duty. A plugin invocation is recognized by its
//! binary path (the fake plugin file this test writes); everything else is
//! the AI reviewer's collector, which the stub forwards to this repo's
//! real `collect` subcommand so the reviewer's coverage figures come from a
//! real walk of the unpacked package.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use flate2::write::GzEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};
use tokio::net::TcpListener;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zip::ZipWriter;

use supply_chain_scanner::config::{
    AiReviewConfig, AuditConfig, BlockOn, Config, CveLine, NpmRegistryConfig, PluginConfig,
    UnknownSeverity,
};
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::ecosystem::npm::packument_path;
use supply_chain_scanner::http::npm_bootstrap::{
    bootstrap_npm, bootstrap_npm_with_sandbox_factory, NpmWired,
};
use supply_chain_scanner::plugin::{
    SandboxOutcome, SandboxRunner, SandboxSpec, SANDBOX_PACKAGE_DIR,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn sha1_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// One published version's tarball bytes: a gzipped tar holding a minimal
/// `package/package.json` and one ordinary JS module, wrapped the way npm
/// itself wraps a published tarball.
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

/// A published version of a test package: its bytes and the sha1 shasum
/// the packument's `dist` object declares for them, which is also the
/// artifact key's digest.
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
/// sends.
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
        "summary": "ordinary package sources",
        "findings": [],
    })
    .to_string();
    let content = serde_json::to_string(&verdict).expect("escape the verdict");
    format!(
        r#"{{"id":"resp_1","choices":[{{"index":0,"message":{{"role":"assistant","content":{content}}},"finish_reason":"stop"}}]}}"#
    )
}

async fn mount_empty_osv_feed(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/npm/all.zip"))
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
/// as `tests/http_cargo_bootstrap.rs`'s `StubSandbox` does.
struct StubSandbox {
    plugin_binary: PathBuf,
    plugin_runs: AtomicUsize,
    /// The exit code every plugin invocation answers with. Zero is the
    /// clean case; a non-zero code is a check failure, which the download
    /// gate refuses.
    plugin_exit_code: i32,
}

impl StubSandbox {
    fn new(plugin_binary: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            plugin_binary,
            plugin_runs: AtomicUsize::new(0),
            plugin_exit_code: 0,
        })
    }

    /// Builds a stub whose plugin invocation fails, so the artifact is
    /// refused and the refusal carries a `/why/<id>` link.
    fn refusing(plugin_binary: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            plugin_binary,
            plugin_runs: AtomicUsize::new(0),
            plugin_exit_code: 1,
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
                exit_code: Some(self.plugin_exit_code),
                output: if self.plugin_exit_code == 0 {
                    String::new()
                } else {
                    "the plugin refused this package".to_string()
                },
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

/// A minimal, fully valid `Config` for an npm deployment pointed at
/// `server` for everything: the registry, the OSV feed, and (when enabled)
/// the model provider.
///
/// `upstream_url` is required on `Config` whether or not `[npm_registry]`
/// is present, and an npm deployment never reads it; it is set to the same
/// stand-in so nothing in this file can reach the real PyPI.
fn npm_config(
    server: &MockServer,
    public_url: Url,
    db_path: PathBuf,
    cache_dir: PathBuf,
) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        db_path,
        cache_dir,
        upstream_url: Url::parse(&server.uri()).expect("valid upstream url"),
        public_url,
        scan_budget: Duration::from_secs(10),
        cache_ttl: Duration::from_secs(60 * 60),
        advisory_sync_interval: Duration::from_secs(60 * 60),
        advisory_source_url: Url::parse(&format!("{}/npm/all.zip", server.uri()))
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
        cargo_registry: None,
        npm_registry: Some(NpmRegistryConfig {
            upstream_registry_url: Url::parse(&format!("{}/", server.uri()))
                .expect("valid registry url"),
            scan_budget: Duration::from_secs(10),
            max_packument_bytes: 67_108_864,
            min_release_age_days: None,
        }),
        audit: AuditConfig::default(),
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
    wired: NpmWired,
    sandbox: Arc<StubSandbox>,
    _server: tokio::task::JoinHandle<()>,
}

/// Binds an ephemeral listener, builds the config against it (so
/// `public_url` matches the port actually served), runs the real
/// `bootstrap_npm_with_sandbox_factory`, and spawns the router.
async fn start(
    server: &MockServer,
    configure: impl FnOnce(&mut Config, PathBuf),
) -> anyhow::Result<Served> {
    start_with_sandbox(server, StubSandbox::new, configure).await
}

/// [`start`] with the sandbox stub chosen by the caller, so a test can
/// make the plugin gate refuse.
async fn start_with_sandbox(
    server: &MockServer,
    make_sandbox: fn(PathBuf) -> Arc<StubSandbox>,
    configure: impl FnOnce(&mut Config, PathBuf),
) -> anyhow::Result<Served> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;
    let base_url = Url::parse(&format!("http://127.0.0.1:{}/", addr.port()))?;

    let db_dir = tempfile::tempdir().expect("create db temp dir");
    let cache_dir = tempfile::tempdir().expect("create cache temp dir");
    let plugin_dir = tempfile::tempdir().expect("create plugin temp dir");
    let plugin_binary = fake_plugin_binary(plugin_dir.path());

    let mut cfg = npm_config(
        server,
        base_url.clone(),
        db_dir.path().join("scanner.db"),
        cache_dir.path().join("cache"),
    );
    configure(&mut cfg, plugin_binary.clone());

    let sandbox = make_sandbox(plugin_binary);
    let factory: supply_chain_scanner::http::SandboxFactory = {
        let sandbox = Arc::clone(&sandbox);
        Arc::new(move |_: &Config| Ok(sandbox.clone() as Arc<dyn SandboxRunner>))
    };

    let wired = bootstrap_npm_with_sandbox_factory(cfg, factory).await?;
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
// The full cascade
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_npm_serves_a_package_through_the_full_cascade() {
    let server = MockServer::start().await;
    let v = version("demo-pkg", "1.0.0");
    mount_packument(&server, "demo-pkg", std::slice::from_ref(&v)).await;
    mount_tarball(&server, "demo-pkg", &v).await;
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
    .expect("bootstrap an npm deployment");

    // 1. The packument gate. A never-seen version is downloaded, verified,
    //    unpacked, reviewed clean, and then forwarded with its tarball
    //    repointed at this proxy.
    let packument_url = format!("{}{}", served.base_url, packument_path("demo-pkg"));
    let packument_response = reqwest::get(&packument_url)
        .await
        .expect("GET the package's packument");
    assert_eq!(
        packument_response.status(),
        reqwest::StatusCode::OK,
        "the cascade must forward a package whose only version reviewed clean"
    );
    let packument_body = packument_response
        .text()
        .await
        .expect("read the packument body");
    assert!(
        packument_body.contains("\"1.0.0\""),
        "the forwarded version must appear in the served packument: {packument_body}"
    );
    assert!(
        !packument_body.contains(&server.uri()),
        "every forwarded tarball URL must point at this proxy, never upstream: {packument_body}"
    );
    assert!(
        packument_body.contains(&served.base_url.to_string()),
        "the rewritten tarball URL must carry the configured public_url: {packument_body}"
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

    // 2. The tarball gate. The packument-side review stored a clean
    //    verdict, but not a plugin-checked one, so the plugins run here —
    //    once.
    let tarball_url = format!("{}demo-pkg/-/demo-pkg-1.0.0.tgz", served.base_url);
    let tarball_response = reqwest::get(&tarball_url).await.expect("GET the tarball");
    assert_eq!(
        tarball_response.status(),
        reqwest::StatusCode::OK,
        "a clean, plugin-passing artifact must be served"
    );
    let served_bytes = tarball_response.bytes().await.expect("read the tarball");
    assert_eq!(
        served_bytes.as_ref(),
        v.bytes.as_slice(),
        "the bytes served must be the verified upstream bytes"
    );
    assert_eq!(
        served.sandbox.plugin_runs(),
        1,
        "the plugin gate must run exactly once for this artifact"
    );
}

// ---------------------------------------------------------------------------
// The initial advisory sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_npm_syncs_the_advisory_mirror_before_serving() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;

    let served = start(&server, |cfg, _plugin_binary| {
        cfg.ai_review = Some(ai_review_config(&server));
    })
    .await
    .expect("bootstrap an npm deployment");

    // The observable state, not an internal counter: startup synced the
    // feed into the store before returning, so the mirror exists and is
    // empty rather than never having been populated.
    let store = AdvisoryStore::new(served.wired.db.clone());
    assert!(
        store.is_empty("npm").expect("read the npm advisory mirror"),
        "an empty feed must leave an empty npm mirror behind"
    );
    let requested = server
        .received_requests()
        .await
        .expect("read the stand-in's request log")
        .iter()
        .filter(|request| request.url.path() == "/npm/all.zip")
        .count();
    assert_eq!(
        requested, 1,
        "the npm advisory feed must be fetched exactly once during startup"
    );
}

// ---------------------------------------------------------------------------
// The dispatch rule's own guards
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_npm_refuses_a_config_with_no_npm_registry_table() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().expect("create temp dir");
    let mut cfg = npm_config(
        &server,
        Url::parse("http://127.0.0.1:9/").expect("valid url"),
        dir.path().join("scanner.db"),
        dir.path().join("cache"),
    );
    cfg.npm_registry = None;

    let err = bootstrap_npm(cfg)
        .await
        .err()
        .expect("a config with no [npm_registry] must not boot an npm deployment");
    assert!(
        err.to_string().contains("[npm_registry]"),
        "the error must name the missing table: {err:#}"
    );
}

#[tokio::test]
async fn bootstrap_npm_refuses_a_config_with_no_ai_review_configured() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().expect("create temp dir");
    let cfg = npm_config(
        &server,
        Url::parse("http://127.0.0.1:9/").expect("valid url"),
        dir.path().join("scanner.db"),
        dir.path().join("cache"),
    );
    assert!(
        cfg.ai_review.is_none(),
        "this fixture carries no [ai_review]"
    );

    let err = bootstrap_npm(cfg)
        .await
        .err()
        .expect("an npm deployment without a reviewer must refuse to start");
    let message = format!("{err:#}");
    assert!(
        message.contains("nothing could be forwarded"),
        "the error must name that nothing could be forwarded without a reviewer: {message}"
    );
    assert!(
        message.contains("[ai_review]"),
        "the error must name the missing table: {message}"
    );

    // A table that is present but disabled cannot review either, so it is
    // refused exactly like an absent one.
    let dir = tempfile::tempdir().expect("create temp dir");
    let mut cfg = npm_config(
        &server,
        Url::parse("http://127.0.0.1:9/").expect("valid url"),
        dir.path().join("scanner.db"),
        dir.path().join("cache"),
    );
    let mut ai = ai_review_config(&server);
    ai.enabled = false;
    cfg.ai_review = Some(ai);
    let err = bootstrap_npm(cfg)
        .await
        .err()
        .expect("a disabled reviewer must refuse to start an npm deployment");
    assert!(
        format!("{err:#}").contains("[ai_review]"),
        "the error must name the missing table: {err:#}"
    );
}

// ---------------------------------------------------------------------------
// The routes an npm deployment shares with the other paths
// ---------------------------------------------------------------------------

/// `/healthz` must answer on an npm deployment. An operator's liveness
/// probe does not know which ecosystem it is watching, and a probe that
/// 404s reads as a dead process.
#[tokio::test]
async fn an_npm_deployment_answers_healthz() {
    let server = MockServer::start().await;
    mount_empty_osv_feed(&server).await;
    let served = start(&server, |cfg, _| {
        cfg.ai_review = Some(ai_review_config(&server));
    })
    .await
    .expect("bootstrap");

    let response = reqwest::get(format!("{}healthz", served.base_url))
        .await
        .expect("GET healthz");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

/// `/api/reviews` must exist on an npm deployment, behind the same
/// `[ai_review]` gate it has on the PyPI path: a JSON listing once the
/// reviewer has run. An npm deployment cannot boot without a reviewer at
/// all, so only the configured case is reachable here.
#[tokio::test]
async fn an_npm_deployment_serves_api_reviews_behind_the_ai_gate() {
    let server = MockServer::start().await;
    let v = version("demo-pkg", "1.0.0");
    mount_packument(&server, "demo-pkg", std::slice::from_ref(&v)).await;
    mount_tarball(&server, "demo-pkg", &v).await;
    mount_empty_osv_feed(&server).await;
    mount_clean_model(&server).await;

    let served = start(&server, |cfg, _| {
        cfg.ai_review = Some(ai_review_config(&server));
    })
    .await
    .expect("bootstrap");

    // Drive one review so the listing has a row to show.
    let packument_url = format!("{}{}", served.base_url, packument_path("demo-pkg"));
    let primed = reqwest::get(&packument_url)
        .await
        .expect("prime the cascade");
    assert_eq!(primed.status(), reqwest::StatusCode::OK);

    let listed = reqwest::get(format!("{}api/reviews", served.base_url))
        .await
        .expect("GET api/reviews");
    assert_eq!(listed.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = listed.json().await.expect("api/reviews is JSON");
    let reviews = body["reviews"]
        .as_array()
        .expect("the listing must carry a reviews array");
    assert!(
        !reviews.is_empty(),
        "the review the cascade just ran must be listed: {body}"
    );
}

/// `/why/<id>` must resolve on an npm deployment. A plugin refusal
/// arrives as a real 403 whose reason phrase carries a `/why/<id>` link,
/// so without this route the proxy hands a developer a link to a 404.
#[tokio::test]
async fn a_plugin_refusal_why_link_resolves() {
    let server = MockServer::start().await;
    let v = version("demo-pkg", "1.0.0");
    mount_packument(&server, "demo-pkg", std::slice::from_ref(&v)).await;
    mount_tarball(&server, "demo-pkg", &v).await;
    mount_empty_osv_feed(&server).await;
    mount_clean_model(&server).await;

    let served = start_with_sandbox(&server, StubSandbox::refusing, |cfg, plugin_binary| {
        // The reviewer passes the version, so the packument forwards
        // it; the plugin then refuses the artifact at download time.
        cfg.plugins = vec![plugin_config(plugin_binary)];
        cfg.ai_review = Some(ai_review_config(&server));
    })
    .await
    .expect("bootstrap");

    // Get the version admitted to the packument first, then download it.
    let packument_url = format!("{}{}", served.base_url, packument_path("demo-pkg"));
    let primed = reqwest::get(&packument_url)
        .await
        .expect("prime the cascade");
    assert_eq!(primed.status(), reqwest::StatusCode::OK);

    let tarball_url = format!("{}demo-pkg/-/demo-pkg-1.0.0.tgz", served.base_url);
    let tarball = reqwest::get(&tarball_url).await.expect("download");
    assert_eq!(
        tarball.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a plugin refusal must not serve the artifact"
    );
    let refusal = tarball.text().await.expect("read the refusal body");
    assert!(
        refusal.contains("/why/"),
        "the refusal must link to its explanation: {refusal}"
    );

    // Follow the link the refusal handed the developer.
    let why_id = sqlite_why_id(served.wired.db.clone());
    let why = reqwest::get(format!("{}why/{}", served.base_url, why_id))
        .await
        .expect("GET the why page");
    assert_eq!(
        why.status(),
        reqwest::StatusCode::OK,
        "an npm deployment's /why/<id> must not be a 404"
    );
    let page = why.text().await.expect("read the why body");
    assert!(
        page.contains("demo-pkg"),
        "the page must explain this artifact: {page}"
    );
}

/// Reads the newest stored verdict's `why_id` out of the database.
///
/// `/refusals` and every refusal response link to it, and this is the same
/// column they read.
fn sqlite_why_id(db: supply_chain_scanner::db::Db) -> String {
    db.conn()
        .and_then(|conn| {
            conn.query_row(
                "SELECT why_id FROM verdicts ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(anyhow::Error::from)
        })
        .expect("a stored verdict must exist for a served version")
}

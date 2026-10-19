//! Integration tests for `supply_chain_scanner::ecosystem::cargo::upstream`
//! (the sparse-index and `.crate` download client) with `wiremock` as a
//! stand-in cargo registry.
//!
//! The stall-timeout test uses a raw TCP server, not `wiremock`, because it
//! has to stop sending bytes partway through a declared body. That is the
//! same approach `tests/upstream.rs` uses for the PyPI client.

use std::time::Duration;

use supply_chain_scanner::config::DownloadLimits;
use supply_chain_scanner::ecosystem::cargo::upstream::{CargoUpstream, UpstreamError};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The two-line index fixture from the `parse_index_lines` unit test, in
/// the exact shape the sparse index serves it.
fn index_body() -> String {
    "{\"name\":\"cargo\",\"vers\":\"1.0.0\",\"cksum\":\"deadbeef\",\"yanked\":false,\"deps\":[]}\n\
     {\"name\":\"cargo\",\"vers\":\"1.1.0\",\"cksum\":\"abc123\",\"yanked\":true,\"deps\":[]}\n"
        .to_string()
}

fn with_default_limits(index_base: Url) -> CargoUpstream {
    CargoUpstream::with_limits(index_base, &DownloadLimits::default())
        .expect("construct cargo upstream")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn index_entries_fetches_and_parses_the_per_crate_index_file() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ca/rg/cargo"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index_body()))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid index base url");
    let upstream = with_default_limits(base);

    let entries = upstream
        .index_entries("cargo")
        .await
        .expect("index_entries should succeed");

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].vers, "1.0.0");
    assert_eq!(entries[0].cksum, "deadbeef");
    assert!(!entries[0].yanked);
    assert_eq!(entries[1].vers, "1.1.0");
    assert!(entries[1].yanked);
}

#[tokio::test]
async fn index_entries_maps_a_404_to_upstream_error_not_found() {
    let server = MockServer::start().await;
    // No mock is mounted for this path, so `wiremock` answers 404.
    let base = Url::parse(&format!("{}/", server.uri())).expect("valid index base url");
    let upstream = with_default_limits(base);

    let result = upstream.index_entries("missing").await;

    assert!(
        matches!(result, Err(UpstreamError::NotFound)),
        "a 404 from upstream must map to NotFound, not to an outage"
    );
}

#[tokio::test]
async fn index_entries_normalizes_the_requested_name() {
    let server = MockServer::start().await;
    // `serde_json` normalizes to `serde-json`, whose index path is
    // `se/rd/serde-json`.
    Mock::given(method("GET"))
        .and(path("/se/rd/serde-json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "{\"name\":\"serde_json\",\"vers\":\"1.0.0\",\"cksum\":\"aa\",\"yanked\":false}\n",
        ))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid index base url");
    let upstream = with_default_limits(base);

    let entries = upstream
        .index_entries("Serde_JSON")
        .await
        .expect("index_entries should use the normalized name");

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].vers, "1.0.0");
}

#[tokio::test]
async fn download_crate_writes_the_expanded_dl_template_and_returns_its_sha256() {
    let server = MockServer::start().await;
    let body = b"the crate bytes".to_vec();
    let expected = sha256_hex(&body);

    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{{\"dl\":\"{}/crates/{{crate}}/{{version}}/download\",\"api\":\"{}\"}}",
            server.uri(),
            server.uri()
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/crates/demo/1.0.0/download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid index base url");
    let upstream = with_default_limits(base);

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("demo-1.0.0.crate");

    let digest = upstream
        .download_crate("demo", "1.0.0", &dest)
        .await
        .expect("download_crate should succeed");

    assert_eq!(digest, expected, "the returned digest must be the body's");
    assert_eq!(
        std::fs::read(&dest).expect("read downloaded file"),
        body,
        "every byte of the body must reach dest"
    );
    let leftovers: Vec<_> = std::fs::read_dir(dest_dir.path())
        .expect("read dest dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    assert_eq!(
        leftovers.len(),
        1,
        "a successful download must leave only dest behind: {leftovers:?}"
    );
}

/// The `{prefix}` marker uses the same segments as
/// `index::index_path_for`, without the crate name: `cargo` becomes
/// `ca/rg`.
#[tokio::test]
async fn download_crate_expands_the_prefix_marker() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{{\"dl\":\"{}/crates/{{prefix}}/{{crate}}/{{version}}/download\"}}",
            server.uri()
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/crates/ca/rg/cargo/1.0.0/download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid index base url");
    let upstream = with_default_limits(base);

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("cargo-1.0.0.crate");

    upstream
        .download_crate("cargo", "1.0.0", &dest)
        .await
        .expect("download_crate should expand {prefix} to ca/rg");
}

/// The `config.json` body is fetched once and reused, so a second download
/// does not pay for it again. A failed first fetch must not be cached as a
/// success: the next call must retry.
#[tokio::test]
async fn a_failed_config_fetch_is_not_cached_as_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{{\"dl\":\"{}/crates/{{crate}}/{{version}}/download\"}}",
            server.uri()
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/crates/demo/1.0.0/download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"bytes".to_vec()))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid index base url");
    let upstream = with_default_limits(base);

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let first = upstream
        .download_crate("demo", "1.0.0", &dest_dir.path().join("first.crate"))
        .await;
    assert!(
        first.is_err(),
        "a failing config.json fetch must fail the download"
    );

    let second = upstream
        .download_crate("demo", "1.0.0", &dest_dir.path().join("second.crate"))
        .await;
    assert!(
        second.is_ok(),
        "a failed config.json fetch must not be cached; the next call retries"
    );
}

#[tokio::test]
async fn download_crate_maps_a_404_to_upstream_error_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{{\"dl\":\"{}/crates/{{crate}}/{{version}}/download\"}}",
            server.uri()
        )))
        .mount(&server)
        .await;
    // No mock for the download path, so `wiremock` answers 404.

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid index base url");
    let upstream = with_default_limits(base);

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("missing-1.0.0.crate");

    let result = upstream.download_crate("missing", "1.0.0", &dest).await;

    assert!(
        matches!(result, Err(UpstreamError::NotFound)),
        "a 404 on the .crate file must map to NotFound"
    );
    assert!(
        !dest.exists(),
        "a failed download must leave nothing at dest"
    );
}

/// Serves one HTTP/1.1 response that promises `promised` bytes, writes
/// `prefix`, and then sends nothing more while holding the connection open.
/// This is a stalled transfer, not a slow one.
async fn spawn_stalling_server(prefix: Vec<u8>, promised: usize) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalling server");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut scratch = [0u8; 4096];
        let _ = stream.read(&mut scratch).await;

        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
             Content-Length: {promised}\r\n\r\n"
        );
        if stream.write_all(header.as_bytes()).await.is_err() {
            return;
        }
        if stream.write_all(&prefix).await.is_err() {
            return;
        }
        let _ = stream.flush().await;
        // Hold the connection open, writing nothing, until the test ends.
        tokio::time::sleep(Duration::from_secs(600)).await;
    });

    addr
}

/// A body that stops mid-stream must be abandoned after the configured
/// stall timeout, not left to hang, and it must leave no file behind.
#[tokio::test]
async fn download_crate_respects_the_configured_stall_timeout() {
    let download_addr = spawn_stalling_server(b"the first few bytes".to_vec(), 1024 * 1024).await;

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{{\"dl\":\"http://{download_addr}/crates/{{crate}}/{{version}}/download\"}}"
        )))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid index base url");
    let limits = DownloadLimits {
        stall_timeout: Duration::from_millis(300),
        max_duration: Duration::from_secs(60),
        ..Default::default()
    };
    let upstream = CargoUpstream::with_limits(base, &limits).expect("construct cargo upstream");

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("stalled-1.0.0.crate");

    let started = std::time::Instant::now();
    let result = upstream.download_crate("stalled", "1.0.0", &dest).await;
    let elapsed = started.elapsed();

    assert!(
        result.is_err(),
        "a stalled transfer must fail rather than hang or half-succeed"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the 300ms stall timeout must be what caught this, but it took {elapsed:?}"
    );
    assert!(
        !dest.exists(),
        "a failed download must leave nothing at dest"
    );
    let leftovers: Vec<_> = std::fs::read_dir(dest_dir.path())
        .expect("read dest dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "a failed download must not leave its temp file behind: {leftovers:?}"
    );
}

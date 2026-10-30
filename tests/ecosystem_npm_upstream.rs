//! Integration tests for `supply_chain_scanner::ecosystem::npm::upstream`
//! (the npm registry packument and tarball client) with `wiremock` as a
//! stand-in registry.
//!
//! Two tests use a raw TCP server instead of `wiremock`, because they have
//! to control framing precisely: one streams a body with no declared
//! length past the size cap, and one closes the connection mid-transfer.
//! This is the same approach `tests/ecosystem_cargo_upstream.rs` uses for
//! its stall-timeout test.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use supply_chain_scanner::config::DownloadLimits;
use supply_chain_scanner::ecosystem::npm::packument::Dist;
use supply_chain_scanner::ecosystem::npm::upstream::{NpmUpstream, UpstreamError};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn with_default_limits(registry_base: Url) -> NpmUpstream {
    NpmUpstream::with_limits(registry_base, 64 * 1024 * 1024, &DownloadLimits::default())
        .expect("construct npm upstream")
}

fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn sha512_integrity(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    format!("sha512-{}", BASE64.encode(hasher.finalize()))
}

/// A minimal but valid packument body for `name`, with one version
/// `1.0.0` whose `dist` carries `tarball_url` and the given digests.
fn packument_body(name: &str, tarball_url: &str, shasum: Option<&str>) -> String {
    let dist = match shasum {
        Some(sum) => format!(r#"{{"tarball":"{tarball_url}","shasum":"{sum}"}}"#),
        None => format!(r#"{{"tarball":"{tarball_url}"}}"#),
    };
    format!(
        r#"{{"name":"{name}","versions":{{"1.0.0":{{"version":"1.0.0","dist":{dist}}}}},
           "dist-tags":{{"latest":"1.0.0"}},
           "time":{{"created":"2024-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","1.0.0":"2024-01-01T00:00:00.000Z"}}}}"#
    )
}

#[tokio::test]
async fn packument_fetches_and_parses_the_full_document() {
    let server = MockServer::start().await;
    let body = packument_body(
        "demo",
        &format!("{}/demo/-/demo-1.0.0.tgz", server.uri()),
        Some("a"),
    );
    Mock::given(method("GET"))
        .and(path("/demo"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
    let upstream = with_default_limits(base);

    let packument = upstream
        .packument("demo")
        .await
        .expect("packument should succeed");

    assert_eq!(packument.name, "demo");
    assert!(packument.versions.contains_key("1.0.0"));
    assert_eq!(
        packument.dist_tags.get("latest").map(String::as_str),
        Some("1.0.0")
    );
    assert!(
        packument.time.contains_key("1.0.0"),
        "the full document must carry the time map, which the release-age gate needs"
    );
}

#[tokio::test]
async fn packument_requests_the_full_form_not_the_abbreviated_one() {
    let server = MockServer::start().await;
    let body = packument_body(
        "demo",
        &format!("{}/demo/-/demo-1.0.0.tgz", server.uri()),
        Some("a"),
    );
    Mock::given(method("GET"))
        .and(path("/demo"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
    let upstream = with_default_limits(base);

    upstream
        .packument("demo")
        .await
        .expect("packument should succeed");

    let requests = server.received_requests().await.expect("collect requests");
    assert_eq!(requests.len(), 1, "exactly one request must arrive");
    let accept = requests[0]
        .headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        !accept.contains("vnd.npm.install-v1+json"),
        "the request must ask for the full document, not npm's abbreviated form: \
         Accept was {accept:?}"
    );
}

#[tokio::test]
async fn packument_encodes_a_scoped_name_in_its_path() {
    let server = MockServer::start().await;
    let body = packument_body(
        "@babel/core",
        &format!("{}/@babel/core/-/core-1.0.0.tgz", server.uri()),
        Some("a"),
    );
    Mock::given(method("GET"))
        .and(path("/@babel%2fcore"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
    let upstream = with_default_limits(base);

    let packument = upstream
        .packument("@babel/core")
        .await
        .expect("a scoped name must be percent-encoded in the request path");

    assert_eq!(packument.name, "@babel/core");
}

#[tokio::test]
async fn packument_maps_a_404_to_not_found() {
    let server = MockServer::start().await;
    // No mock is mounted for this path, so `wiremock` answers 404.
    let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
    let upstream = with_default_limits(base);

    let result = upstream.packument("missing").await;

    assert!(
        matches!(result, Err(UpstreamError::NotFound)),
        "a 404 from upstream must map to NotFound, not to an outage"
    );
}

#[tokio::test]
async fn packument_maps_a_500_to_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/demo"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
    let upstream = with_default_limits(base);

    let result = upstream.packument("demo").await;

    assert!(
        matches!(result, Err(UpstreamError::Unavailable(_))),
        "a 500 from upstream must map to Unavailable, got: {result:?}"
    );
}

#[tokio::test]
async fn packument_sends_if_none_match_on_a_second_fetch_and_reuses_the_cached_body_on_304() {
    let server = MockServer::start().await;
    let body = packument_body(
        "demo",
        &format!("{}/demo/-/demo-1.0.0.tgz", server.uri()),
        Some("a"),
    );
    Mock::given(method("GET"))
        .and(path("/demo"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("ETag", "\"v1\"")
                .set_body_string(body),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/demo"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
    let upstream = with_default_limits(base);

    let first = upstream
        .packument("demo")
        .await
        .expect("first fetch should succeed");
    let second = upstream
        .packument("demo")
        .await
        .expect("second fetch should reuse the cached body on a 304");

    assert_eq!(first.name, second.name);
    assert_eq!(
        first.versions.keys().collect::<Vec<_>>(),
        second.versions.keys().collect::<Vec<_>>()
    );

    let requests = server.received_requests().await.expect("collect requests");
    assert_eq!(
        requests.len(),
        2,
        "exactly two upstream hits must have happened"
    );
    let second_request = &requests[1];
    assert_eq!(
        second_request
            .headers
            .get("if-none-match")
            .and_then(|v| v.to_str().ok()),
        Some("\"v1\""),
        "the second fetch must send If-None-Match with the first fetch's ETag"
    );
}

#[tokio::test]
async fn a_packument_over_the_size_cap_is_refused_and_nothing_is_parsed() {
    let server = MockServer::start().await;
    let huge_body = format!(
        r#"{{"name":"demo","versions":{{}},"dist-tags":{{}},"time":{{}},"padding":"{}"}}"#,
        "x".repeat(200)
    );
    Mock::given(method("GET"))
        .and(path("/demo"))
        .respond_with(ResponseTemplate::new(200).set_body_string(huge_body))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
    let upstream = NpmUpstream::with_limits(base, 50, &DownloadLimits::default())
        .expect("construct npm upstream with a tiny cap");

    let result = upstream.packument("demo").await;

    assert!(
        matches!(result, Err(UpstreamError::Unavailable(_))),
        "an honest Content-Length over the cap must be refused before parsing, got: {result:?}"
    );
}

/// Serves one HTTP/1.1 response with no `Content-Length` header (so
/// upstream's declared length is unknown, not merely absent-but-small),
/// streams `total_bytes` of body, and then holds the connection open
/// without ever signalling the end of the body. The running byte-count
/// check inside the client must trip before that point is ever reached.
async fn spawn_lengthless_oversized_server(total_bytes: usize) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind lengthless server");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut scratch = [0u8; 4096];
        let _ = stream.read(&mut scratch).await;

        let header =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n";
        if stream.write_all(header.as_bytes()).await.is_err() {
            return;
        }
        let payload = vec![b'x'; total_bytes];
        if stream.write_all(&payload).await.is_err() {
            return;
        }
        let _ = stream.flush().await;
        // Hold the connection open rather than closing it, so a client
        // that failed to stop reading at the cap would otherwise keep
        // waiting rather than succeeding with a short body.
        tokio::time::sleep(Duration::from_secs(600)).await;
    });

    addr
}

#[tokio::test]
async fn a_packument_lying_about_its_length_is_still_caught_while_streaming() {
    let addr = spawn_lengthless_oversized_server(10_000).await;
    let base = Url::parse(&format!("http://{addr}/")).expect("valid registry base url");
    let upstream = NpmUpstream::with_limits(base, 50, &DownloadLimits::default())
        .expect("construct npm upstream with a tiny cap");

    let started = std::time::Instant::now();
    let result = upstream.packument("demo").await;
    let elapsed = started.elapsed();

    assert!(
        matches!(result, Err(UpstreamError::Other(_))),
        "a body with no declared length that exceeds the cap must still be refused, \
         got: {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the running byte-count check must trip quickly, not wait for the connection \
         to close or time out; took {elapsed:?}"
    );
}

#[tokio::test]
async fn download_tarball_verifies_a_sha512_integrity_and_returns_its_digest() {
    let server = MockServer::start().await;
    let body = b"the tarball bytes, sha512 verified".to_vec();
    let integrity = sha512_integrity(&body);
    Mock::given(method("GET"))
        .and(path("/demo/-/demo-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
    let upstream = with_default_limits(base);
    let dist = Dist {
        tarball: format!("{}/demo/-/demo-1.0.0.tgz", server.uri()),
        integrity: Some(integrity),
        shasum: None,
    };

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("demo-1.0.0.tgz");

    let digest = upstream
        .download_tarball("demo", "1.0.0", &dist, &dest)
        .await
        .expect("download_tarball should succeed");

    assert_eq!(
        digest.algorithm,
        supply_chain_scanner::ecosystem::npm::packument::DigestAlgorithm::Sha512
    );
    assert_eq!(
        std::fs::read(&dest).expect("read downloaded file"),
        body,
        "every byte of the body must reach dest"
    );
}

#[tokio::test]
async fn download_tarball_falls_back_to_shasum_when_integrity_is_absent() {
    let server = MockServer::start().await;
    let body = b"the tarball bytes, sha1 verified".to_vec();
    let expected = sha1_hex(&body);
    Mock::given(method("GET"))
        .and(path("/demo/-/demo-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
    let upstream = with_default_limits(base);
    let dist = Dist {
        tarball: format!("{}/demo/-/demo-1.0.0.tgz", server.uri()),
        integrity: None,
        shasum: Some(expected.clone()),
    };

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("demo-1.0.0.tgz");

    let digest = upstream
        .download_tarball("demo", "1.0.0", &dist, &dest)
        .await
        .expect("download_tarball should fall back to shasum");

    assert_eq!(digest.hex, expected);
    assert_eq!(
        digest.algorithm,
        supply_chain_scanner::ecosystem::npm::packument::DigestAlgorithm::Sha1
    );
}

#[tokio::test]
async fn download_tarball_refuses_an_unverifiable_integrity_algorithm_without_requesting_anything()
{
    let server = MockServer::start().await;
    // No mock is mounted at all: a request here would 404 (or hang, since
    // wiremock has no matching stub), so zero hits is the only way this
    // test can pass if the digest check runs before any request.
    let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
    let upstream = with_default_limits(base);
    let dist = Dist {
        tarball: format!("{}/demo/-/demo-1.0.0.tgz", server.uri()),
        integrity: Some("sha384-not-a-supported-algorithm".to_string()),
        shasum: Some(sha1_hex(b"irrelevant, must not be used as a fallback")),
    };

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("demo-1.0.0.tgz");

    let result = upstream
        .download_tarball("demo", "1.0.0", &dist, &dest)
        .await;

    assert!(
        matches!(result, Err(UpstreamError::Other(_))),
        "an unverifiable integrity algorithm must be refused before any request, \
         got: {result:?}"
    );
    assert!(
        !dest.exists(),
        "nothing must be written for a refused download"
    );

    let requests = server.received_requests().await.expect("collect requests");
    assert_eq!(
        requests.len(),
        0,
        "no request should have been made for an unverifiable digest"
    );
}

#[tokio::test]
async fn download_tarball_rejects_a_digest_mismatch_and_leaves_no_file() {
    let server = MockServer::start().await;
    let body = b"the actual tarball bytes".to_vec();
    Mock::given(method("GET"))
        .and(path("/demo/-/demo-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/", server.uri())).expect("valid registry base url");
    let upstream = with_default_limits(base);
    let dist = Dist {
        tarball: format!("{}/demo/-/demo-1.0.0.tgz", server.uri()),
        integrity: None,
        shasum: Some("0000000000000000000000000000000000000000".to_string()),
    };

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("demo-1.0.0.tgz");

    let result = upstream
        .download_tarball("demo", "1.0.0", &dist, &dest)
        .await;

    assert!(
        matches!(result, Err(UpstreamError::Other(_))),
        "a digest mismatch must be refused, got: {result:?}"
    );
    assert!(
        !dest.exists(),
        "a digest mismatch must leave nothing at dest"
    );
    let leftovers: Vec<_> = std::fs::read_dir(dest_dir.path())
        .expect("read dest dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "a digest mismatch must not leave its temp file behind: {leftovers:?}"
    );
}

/// Serves one HTTP/1.1 response that promises `promised` bytes via
/// `Content-Length`, writes only `prefix`, and then closes the connection
/// immediately — a truncated transfer, distinct from a stalled one.
async fn spawn_truncating_server(prefix: Vec<u8>, promised: usize) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind truncating server");
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
        let _ = stream.write_all(&prefix).await;
        let _ = stream.flush().await;
        // Close the connection immediately, well short of the promised
        // length, instead of stalling.
    });

    addr
}

#[tokio::test]
async fn download_tarball_of_a_truncated_body_errors_rather_than_leaving_a_partial_file() {
    let addr = spawn_truncating_server(b"only a few bytes".to_vec(), 10_000).await;

    let base = Url::parse("http://example.invalid/").expect("valid registry base url");
    let upstream = with_default_limits(base);
    let dist = Dist {
        tarball: format!("http://{addr}/demo/-/demo-1.0.0.tgz"),
        integrity: None,
        shasum: Some(sha1_hex(b"whatever the complete body would have been")),
    };

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("demo-1.0.0.tgz");

    let result = upstream
        .download_tarball("demo", "1.0.0", &dist, &dest)
        .await;

    assert!(
        result.is_err(),
        "a truncated transfer must error rather than succeed with a partial body"
    );
    assert!(
        !dest.exists(),
        "a truncated download must leave nothing at dest"
    );
    let leftovers: Vec<_> = std::fs::read_dir(dest_dir.path())
        .expect("read dest dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "a truncated download must not leave its temp file behind: {leftovers:?}"
    );
}

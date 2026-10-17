//! Integration tests for `supply_chain_scanner::ecosystem::pypi::upstream`
//! (the HTTP client that talks to upstream PyPI, backed by a stale-tolerant
//! index cache) using `wiremock` as a stand-in upstream.

use supply_chain_scanner::db::index_cache::IndexCache;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::pypi::upstream::{Upstream, UpstreamError};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

fn simple_page_html() -> String {
    r#"<!DOCTYPE html>
<html><body>
<a href="https://files.pythonhosted.org/packages/example/example_package-1.2.3-py3-none-any.whl#sha256=abc123">example_package-1.2.3-py3-none-any.whl</a>
</body></html>
"#
    .to_string()
}

#[tokio::test]
async fn simple_page_returns_entries_and_caches_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/simple/example-package/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(simple_page_html()))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let cache = IndexCache::new(db);
    let base = Url::parse(&format!("{}/simple/", server.uri())).expect("valid base url");
    let upstream = Upstream::new(base, cache.clone()).expect("construct upstream");

    let fetched = upstream
        .simple_page("example-package")
        .await
        .expect("simple_page should succeed");

    assert!(!fetched.stale, "a live upstream fetch must not be stale");
    assert_eq!(fetched.value.len(), 1);
    assert_eq!(
        fetched.value[0].filename,
        "example_package-1.2.3-py3-none-any.whl"
    );

    let cached = cache
        .get("example-package")
        .expect("cache lookup should succeed")
        .expect("a successful fetch must populate the cache");
    assert!(cached.0.contains("example_package-1.2.3-py3-none-any.whl"));
}

#[tokio::test]
async fn simple_page_falls_back_to_cache_when_upstream_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/simple/example-package/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(simple_page_html()))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/simple/example-package/"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let cache = IndexCache::new(db);
    let base = Url::parse(&format!("{}/simple/", server.uri())).expect("valid base url");
    let upstream = Upstream::new(base, cache).expect("construct upstream");

    // First call succeeds and populates the cache.
    let first = upstream
        .simple_page("example-package")
        .await
        .expect("first call should succeed");
    assert!(!first.stale);

    // Second call: upstream now fails (503), must fall back to the cache.
    let second = upstream
        .simple_page("example-package")
        .await
        .expect("second call should fall back to cache rather than error");

    assert!(
        second.stale,
        "data served from the fallback path must be marked stale"
    );
    assert_eq!(second.value.len(), 1);
    assert_eq!(
        second.value[0].filename,
        "example_package-1.2.3-py3-none-any.whl"
    );
}

#[tokio::test]
async fn simple_page_without_cache_and_dead_upstream_is_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/simple/example-package/"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let cache = IndexCache::new(db);
    let base = Url::parse(&format!("{}/simple/", server.uri())).expect("valid base url");
    let upstream = Upstream::new(base, cache).expect("construct upstream");

    let result = upstream.simple_page("example-package").await;

    match result {
        Err(UpstreamError::Unavailable(_)) => {}
        Err(other) => panic!("expected Unavailable, got {other:?}"),
        Ok(fetched) => panic!(
            "expected an error with no cache to fall back to, got Ok with stale={}",
            fetched.stale
        ),
    }
}

#[tokio::test]
async fn simple_page_404_is_not_found_and_does_not_poison_cache() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/simple/example-package/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(simple_page_html()))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/simple/example-package/"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let cache = IndexCache::new(db);
    let base = Url::parse(&format!("{}/simple/", server.uri())).expect("valid base url");
    let upstream = Upstream::new(base, cache.clone()).expect("construct upstream");

    // First call succeeds and populates the cache with a good entry.
    upstream
        .simple_page("example-package")
        .await
        .expect("first call should succeed");

    // Second call: upstream now says 404.
    let result = upstream.simple_page("example-package").await;
    match result {
        Err(UpstreamError::NotFound) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }

    // The good cache entry from the first call must survive untouched.
    let cached = cache
        .get("example-package")
        .expect("cache lookup should succeed")
        .expect("a 404 must not delete a previously good cache entry");
    assert!(cached.0.contains("example_package-1.2.3-py3-none-any.whl"));
}

#[tokio::test]
async fn download_streams_to_file_and_returns_sha256() {
    let server = MockServer::start().await;
    let body = b"the quick brown fox jumps over the lazy dog".to_vec();
    Mock::given(method("GET"))
        .and(path("/packages/example_package-1.2.3-py3-none-any.whl"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let cache = IndexCache::new(db);
    let base = Url::parse(&format!("{}/simple/", server.uri())).expect("valid base url");
    let upstream = Upstream::new(base, cache).expect("construct upstream");

    let entry_url = Url::parse(&format!(
        "{}/packages/example_package-1.2.3-py3-none-any.whl",
        server.uri()
    ))
    .expect("valid artifact url");
    let entry = supply_chain_scanner::ecosystem::pypi::index::IndexEntry {
        filename: "example_package-1.2.3-py3-none-any.whl".to_string(),
        url: entry_url,
        sha256: None,
        requires_python: None,
        metadata_hash: None,
        yanked: None,
    };

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir
        .path()
        .join("example_package-1.2.3-py3-none-any.whl");

    let sha256 = upstream
        .download(&entry, &dest)
        .await
        .expect("download should succeed");

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let expected: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    assert_eq!(
        sha256, expected,
        "returned hash must be lowercase hex sha256"
    );
    assert_eq!(sha256.to_lowercase(), sha256, "hash must be lowercase");

    let on_disk = std::fs::read(&dest).expect("downloaded file must exist");
    assert_eq!(on_disk, body);

    // No temp/partial files should be left lying around beside dest.
    let leftovers: Vec<_> = std::fs::read_dir(dest_dir.path())
        .expect("read dest dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path() != dest)
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temp files should remain after a successful download: {leftovers:?}"
    );
}

#[tokio::test]
async fn download_cleans_up_temp_file_when_rename_fails() {
    let server = MockServer::start().await;
    let body = b"rename failure body".to_vec();
    Mock::given(method("GET"))
        .and(path("/packages/rename-fail-1.0.0.tar.gz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let cache = IndexCache::new(db);
    let base = Url::parse(&format!("{}/simple/", server.uri())).expect("valid base url");
    let upstream = Upstream::new(base, cache).expect("construct upstream");

    let entry_url = Url::parse(&format!(
        "{}/packages/rename-fail-1.0.0.tar.gz",
        server.uri()
    ))
    .expect("valid artifact url");
    let entry = supply_chain_scanner::ecosystem::pypi::index::IndexEntry {
        filename: "rename-fail-1.0.0.tar.gz".to_string(),
        url: entry_url,
        sha256: None,
        requires_python: None,
        metadata_hash: None,
        yanked: None,
    };

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    // `dest` is itself a non-empty directory, so renaming the fully
    // streamed temp file onto it fails on Linux (EISDIR/ENOTEMPTY). This
    // deterministically exercises the rename-failure branch in
    // `download`, distinct from the stream-failure branch exercised by
    // the truncated-download test above.
    let dest = dest_dir.path().join("rename-fail-1.0.0.tar.gz");
    std::fs::create_dir(&dest).expect("create dest as a directory");
    std::fs::write(dest.join("occupant"), b"occupying file").expect("populate dest directory");

    let result = upstream.download(&entry, &dest).await;
    assert!(
        result.is_err(),
        "a failed rename must surface as an error, not a silent success"
    );

    assert!(
        dest.is_dir(),
        "the pre-existing dest directory must be left untouched by the failed rename"
    );

    let leftovers: Vec<_> = std::fs::read_dir(dest_dir.path())
        .expect("read dest dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path() != dest)
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temp file must survive a failed rename: {leftovers:?}"
    );
}

#[tokio::test]
async fn download_of_truncated_body_errors_rather_than_leaving_partial_file() {
    let server = MockServer::start().await;
    // Declare a Content-Length larger than the actual body, which causes
    // the HTTP client to observe a truncated/incomplete body and error out
    // mid-stream, simulating a connection that drops partway through.
    Mock::given(method("GET"))
        .and(path("/packages/truncated-1.0.0.tar.gz"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(b"short".to_vec())
                .append_header("content-length", "1000"),
        )
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let cache = IndexCache::new(db);
    let base = Url::parse(&format!("{}/simple/", server.uri())).expect("valid base url");
    let upstream = Upstream::new(base, cache).expect("construct upstream");

    let entry_url = Url::parse(&format!("{}/packages/truncated-1.0.0.tar.gz", server.uri()))
        .expect("valid artifact url");
    let entry = supply_chain_scanner::ecosystem::pypi::index::IndexEntry {
        filename: "truncated-1.0.0.tar.gz".to_string(),
        url: entry_url,
        sha256: None,
        requires_python: None,
        metadata_hash: None,
        yanked: None,
    };

    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("truncated-1.0.0.tar.gz");

    let result = upstream.download(&entry, &dest).await;
    assert!(
        result.is_err(),
        "a truncated download must surface as an error, not a short success"
    );

    assert!(
        !dest.exists(),
        "the destination file must not exist after a failed download"
    );

    let leftovers: Vec<_> = std::fs::read_dir(dest_dir.path())
        .expect("read dest dir")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        leftovers.is_empty(),
        "no partial/temp file must survive a failed download: {leftovers:?}"
    );
}

#[tokio::test]
async fn metadata_sidecar_fetches_the_dot_metadata_url() {
    let server = MockServer::start().await;
    let metadata_body = b"Metadata-Version: 2.1\nName: example-package\n".to_vec();
    Mock::given(method("GET"))
        .and(path(
            "/packages/example_package-1.2.3-py3-none-any.whl.metadata",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(metadata_body.clone()))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let cache = IndexCache::new(db);
    let base = Url::parse(&format!("{}/simple/", server.uri())).expect("valid base url");
    let upstream = Upstream::new(base, cache).expect("construct upstream");

    let entry_url = Url::parse(&format!(
        "{}/packages/example_package-1.2.3-py3-none-any.whl",
        server.uri()
    ))
    .expect("valid artifact url");
    let entry = supply_chain_scanner::ecosystem::pypi::index::IndexEntry {
        filename: "example_package-1.2.3-py3-none-any.whl".to_string(),
        url: entry_url,
        sha256: None,
        requires_python: None,
        metadata_hash: Some("true".to_string()),
        yanked: None,
    };

    let bytes = upstream
        .metadata_sidecar(&entry)
        .await
        .expect("metadata_sidecar should succeed");

    assert_eq!(bytes.as_ref(), metadata_body.as_slice());
}

// ---------------------------------------------------------------------------
// Download timeout semantics
//
// `reqwest`'s `ClientBuilder::timeout` is a *total* deadline: connect
// through end-of-body. A 10s total deadline capped every servable artifact
// at 10s x sustained throughput — a 300 MB wheel needed 30 MB/s held for
// the whole transfer and a 900 MB `torch` wheel needed 90 MB/s, so every
// large ML/CUDA wheel was permanently unservable as a 503 that pip retries
// five times and then reports as an upstream problem. The download path
// now uses stall detection (`read_timeout`) plus a generous absolute cap
// instead; the index-page path keeps its total deadline, because it
// fetches small documents and sits in front of the scan budget.
// ---------------------------------------------------------------------------

/// Serves exactly one HTTP/1.1 response on a fresh ephemeral port,
/// trickling `body` out in `chunks` pieces with `gap` between them, so the
/// transfer takes roughly `chunks * gap` without ever stalling for longer
/// than `gap`. The returned task owns the listener and ends after the one
/// response.
async fn spawn_trickling_server(
    body: Vec<u8>,
    chunks: usize,
    gap: std::time::Duration,
) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind trickling server");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        // Drain the request headers; we serve the same body regardless.
        let mut scratch = [0u8; 4096];
        let _ = stream.read(&mut scratch).await;

        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        if stream.write_all(header.as_bytes()).await.is_err() {
            return;
        }
        let chunk_size = body.len().div_ceil(chunks);
        for piece in body.chunks(chunk_size) {
            tokio::time::sleep(gap).await;
            if stream.write_all(piece).await.is_err() {
                return;
            }
            if stream.flush().await.is_err() {
                return;
            }
        }
        let _ = stream.shutdown().await;
    });

    addr
}

/// Serves one HTTP/1.1 response that promises `promised` bytes, writes
/// `prefix`, and then never writes another byte while holding the
/// connection open — a genuinely stalled transfer, as distinct from a slow
/// one.
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
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
    });

    addr
}

fn entry_at(url: &str, filename: &str) -> supply_chain_scanner::ecosystem::pypi::index::IndexEntry {
    supply_chain_scanner::ecosystem::pypi::index::IndexEntry {
        filename: filename.to_string(),
        url: Url::parse(url).expect("valid artifact url"),
        sha256: None,
        requires_python: None,
        metadata_hash: None,
        yanked: None,
    }
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

/// A body that trickles for longer than the old 10s *total* deadline but
/// never stalls must now complete. Under the previous
/// `ClientBuilder::timeout(10s)` this failed at the 10 second mark no
/// matter how healthy the connection was, which is the whole of B2.
///
/// Deliberately a slow test (~12s): a shorter one cannot distinguish "the
/// total deadline is gone" from "the total deadline was not reached".
#[tokio::test]
async fn a_body_trickling_past_the_old_total_deadline_now_completes() {
    let body: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 251) as u8).collect();
    let expected = sha256_hex(&body);
    // 24 chunks x 500ms = ~12s, comfortably past the retired 10s total
    // deadline, with no single gap anywhere near the 30s default stall
    // timeout.
    let addr =
        spawn_trickling_server(body.clone(), 24, std::time::Duration::from_millis(500)).await;

    let (_dir, db) = open_db();
    let cache = IndexCache::new(db);
    let base = Url::parse("http://127.0.0.1/simple/").expect("valid base url");
    // Default download limits on purpose: the fix has to hold for an
    // operator who configures nothing.
    let upstream = Upstream::new(base, cache).expect("construct upstream");

    let entry = entry_at(
        &format!("http://{addr}/packages/big-1.0.0-py3-none-any.whl"),
        "big-1.0.0-py3-none-any.whl",
    );
    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("big-1.0.0-py3-none-any.whl");

    let started = std::time::Instant::now();
    let digest = upstream
        .download(&entry, &dest)
        .await
        .expect("a slow but healthy transfer must complete, not time out");
    let elapsed = started.elapsed();

    assert_eq!(digest, expected, "every byte must have been hashed");
    assert_eq!(
        std::fs::metadata(&dest).expect("stat dest").len() as usize,
        body.len()
    );
    assert!(
        elapsed > std::time::Duration::from_secs(10),
        "the fixture must actually have run past the old 10s deadline to \
         prove anything; it took {elapsed:?}"
    );
}

/// A genuinely stalled body — no bytes at all for longer than the
/// configured stall timeout — must still fail, and fail closed: no
/// partial file left where a caller might find it.
#[tokio::test]
async fn a_stalled_body_still_fails_closed() {
    let addr = spawn_stalling_server(b"the first few bytes".to_vec(), 1024 * 1024).await;

    let (_dir, db) = open_db();
    let cache = IndexCache::new(db);
    let base = Url::parse("http://127.0.0.1/simple/").expect("valid base url");
    let limits = supply_chain_scanner::config::DownloadLimits {
        stall_timeout: std::time::Duration::from_millis(300),
        max_duration: std::time::Duration::from_secs(60),
    };
    let upstream = Upstream::with_limits(base, cache, &limits).expect("construct upstream");

    let entry = entry_at(
        &format!("http://{addr}/packages/stalled-1.0.0.tar.gz"),
        "stalled-1.0.0.tar.gz",
    );
    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("stalled-1.0.0.tar.gz");

    let started = std::time::Instant::now();
    let result = upstream.download(&entry, &dest).await;
    let elapsed = started.elapsed();
    assert!(
        result.is_err(),
        "a stalled transfer must fail rather than hang or half-succeed"
    );
    // Well under both the retired 10s total deadline and the 60s absolute
    // cap, so the only thing that could have caught this is the 300ms
    // stall timeout — which is the point: stall detection, not duration.
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "the stall timeout must be what caught this, but it took {elapsed:?}"
    );
    assert!(
        !dest.exists(),
        "a failed download must leave nothing at dest"
    );
    let leftovers: Vec<_> = std::fs::read_dir(dest_dir.path())
        .expect("read dest dir")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        leftovers.is_empty(),
        "a failed download must not leave its temp file behind: {leftovers:?}"
    );
}

/// The absolute cap is the backstop behind stall detection: a transfer
/// that keeps dribbling bytes forever cannot run unbounded.
#[tokio::test]
async fn the_absolute_download_cap_still_bounds_an_endlessly_slow_transfer() {
    let body: Vec<u8> = vec![7u8; 8 * 1024];
    // 32 chunks x 200ms = ~6.4s of trickling, against a 1s cap.
    let addr = spawn_trickling_server(body, 32, std::time::Duration::from_millis(200)).await;

    let (_dir, db) = open_db();
    let cache = IndexCache::new(db);
    let base = Url::parse("http://127.0.0.1/simple/").expect("valid base url");
    let limits = supply_chain_scanner::config::DownloadLimits {
        // Never trips: each gap is 200ms.
        stall_timeout: std::time::Duration::from_secs(30),
        max_duration: std::time::Duration::from_secs(1),
    };
    let upstream = Upstream::with_limits(base, cache, &limits).expect("construct upstream");

    let entry = entry_at(
        &format!("http://{addr}/packages/endless-1.0.0.tar.gz"),
        "endless-1.0.0.tar.gz",
    );
    let dest_dir = tempfile::tempdir().expect("create dest dir");
    let dest = dest_dir.path().join("endless-1.0.0.tar.gz");

    let result = upstream.download(&entry, &dest).await;
    assert!(
        result.is_err(),
        "a transfer past the absolute cap must fail, not run forever"
    );
    assert!(!dest.exists(), "nothing may be left at dest");
}

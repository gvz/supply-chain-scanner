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

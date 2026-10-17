//! Integration tests for `supply_chain_scanner::artifact_cache` (the
//! content-addressed, sliding-TTL on-disk cache of scanned artifact
//! bytes).
//!
//! The cache is a performance feature only: the verdict database (not
//! exercised here) is the durable record of whether an artifact may be
//! served. These tests manipulate `last_access` directly through raw SQL
//! against the same database the cache uses, rather than sleeping, so the
//! sliding-TTL behavior is proven deterministically and fast.

use std::io::Write;
use std::time::Duration;

use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::model::ArtifactKey;

/// Opens a fresh database and cache root in their own temp directories.
/// Both temp dirs must stay alive for the duration of the test (hence
/// returning them), or they're deleted as soon as this function returns.
fn open_cache() -> (tempfile::TempDir, tempfile::TempDir, Db, ArtifactCache) {
    let db_dir = tempfile::tempdir().expect("create db temp dir");
    let cache_dir = tempfile::tempdir().expect("create cache temp dir");
    let db = Db::open(&db_dir.path().join("scanner.db")).expect("open db");
    let cache = ArtifactCache::new(db.clone(), cache_dir.path().join("artifacts"))
        .expect("create artifact cache");
    (db_dir, cache_dir, db, cache)
}

fn key(sha256: &str) -> ArtifactKey {
    ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "example-package".to_string(),
        version: "1.2.3".to_string(),
        filename: "example_package-1.2.3-py3-none-any.whl".to_string(),
        sha256: sha256.to_string(),
    }
}

/// Writes `content` to a fresh temp file and returns it (the temp dir
/// guard must be kept alive by the caller until the file is consumed).
fn temp_source_file(dir: &tempfile::TempDir, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create source file");
    f.write_all(content).expect("write source file");
    path
}

/// Directly rewrites the `last_access` column for `sha256` to `seconds_ago`
/// seconds before now, bypassing the cache's own API. This is how these
/// tests move time without sleeping: it simulates "this entry was last
/// touched a while ago" exactly as it would look after real time passed.
fn backdate_last_access(db: &Db, sha256: &str, seconds_ago: i64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let conn = db.conn().expect("get connection");
    conn.execute(
        "UPDATE artifact_cache SET last_access = ?1 WHERE sha256 = ?2",
        rusqlite::params![now - seconds_ago, sha256],
    )
    .expect("backdate last_access");
}

fn last_access_of(db: &Db, sha256: &str) -> i64 {
    let conn = db.conn().expect("get connection");
    conn.query_row(
        "SELECT last_access FROM artifact_cache WHERE sha256 = ?1",
        [sha256],
        |row| row.get(0),
    )
    .expect("read last_access")
}

fn row_exists(db: &Db, sha256: &str) -> bool {
    let conn = db.conn().expect("get connection");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM artifact_cache WHERE sha256 = ?1",
            [sha256],
            |row| row.get(0),
        )
        .expect("count rows");
    count > 0
}

#[test]
fn insert_then_get_returns_the_stored_path() {
    let (src_dir, _cache_dir, _db, cache) = open_cache();
    let sha256 = "a".repeat(64);
    let k = key(&sha256);
    let source = temp_source_file(&src_dir, "artifact.whl", b"hello artifact bytes");

    let stored_path = cache.insert(&k, &source).expect("insert should succeed");
    assert!(stored_path.is_file(), "insert must leave a file in place");
    assert_eq!(
        std::fs::read(&stored_path).expect("read stored file"),
        b"hello artifact bytes"
    );

    let fetched = cache
        .get(&k)
        .expect("get should succeed")
        .expect("entry must be present after insert");
    assert_eq!(fetched, stored_path);
}

#[test]
fn get_refreshes_last_access() {
    let (src_dir, _cache_dir, db, cache) = open_cache();
    let sha256 = "b".repeat(64);
    let k = key(&sha256);
    let source = temp_source_file(&src_dir, "artifact.whl", b"payload");
    cache.insert(&k, &source).expect("insert should succeed");

    // Simulate time having passed since the last touch.
    backdate_last_access(&db, &sha256, 10_000);
    let backdated = last_access_of(&db, &sha256);

    cache.get(&k).expect("get should succeed");

    let refreshed = last_access_of(&db, &sha256);
    assert!(
        refreshed > backdated + 1000,
        "get() must move last_access forward to roughly now \
         (backdated={backdated}, refreshed={refreshed})"
    );
}

#[test]
fn evict_removes_untouched_entries_past_ttl() {
    let (src_dir, _cache_dir, db, cache) = open_cache();
    let sha256 = "c".repeat(64);
    let k = key(&sha256);
    let source = temp_source_file(&src_dir, "artifact.whl", b"payload");
    let stored_path = cache.insert(&k, &source).expect("insert should succeed");

    // Older than the TTL we're about to sweep with, and never touched
    // again after insert.
    backdate_last_access(&db, &sha256, 3600);

    let removed = cache
        .evict_expired(Duration::from_secs(60))
        .expect("evict_expired should succeed");

    assert_eq!(removed, 1, "exactly the one expired entry must be removed");
    assert!(
        !stored_path.exists(),
        "the backing file must be deleted, not just the row"
    );
    assert!(
        !row_exists(&db, &sha256),
        "the metadata row must be deleted"
    );
}

#[test]
fn evict_keeps_entries_touched_within_ttl() {
    let (src_dir, _cache_dir, db, cache) = open_cache();
    let sha256 = "d".repeat(64);
    let k = key(&sha256);
    let source = temp_source_file(&src_dir, "artifact.whl", b"payload");
    let stored_path = cache.insert(&k, &source).expect("insert should succeed");
    // Freshly inserted: last_access is "now", well within any reasonable TTL.

    let removed = cache
        .evict_expired(Duration::from_secs(3600))
        .expect("evict_expired should succeed");

    assert_eq!(removed, 0, "a recently touched entry must not be swept");
    assert!(stored_path.exists(), "the backing file must survive");
    assert!(row_exists(&db, &sha256), "the metadata row must survive");
}

#[test]
fn repeatedly_requested_entry_survives_many_evictions() {
    let (src_dir, _cache_dir, db, cache) = open_cache();
    let ttl = Duration::from_secs(5);

    let hot_sha = "e".repeat(64);
    let hot_key = key(&hot_sha);
    let hot_source = temp_source_file(&src_dir, "hot.whl", b"hot payload");
    cache
        .insert(&hot_key, &hot_source)
        .expect("insert hot entry");

    let cold_sha = "f".repeat(64);
    let cold_key = key(&cold_sha);
    let cold_source = temp_source_file(&src_dir, "cold.whl", b"cold payload");
    cache
        .insert(&cold_key, &cold_source)
        .expect("insert cold entry");
    // The cold entry is never requested again, so push it past the TTL
    // once, up front, and leave it there for every sweep below.
    backdate_last_access(&db, &cold_sha, 3600);

    for sweep in 0..5 {
        // Simulate enough wall-clock time passing, between requests, that
        // without a fresh touch the hot entry would also be past TTL.
        backdate_last_access(&db, &hot_sha, ttl.as_secs() as i64 + 1);

        // A "repeated request": this must reset the hot entry's clock.
        let fetched = cache
            .get(&hot_key)
            .expect("get should succeed")
            .expect("hot entry must still be present before this sweep");
        assert!(fetched.is_file(), "sweep {sweep}: hot file must exist");

        cache
            .evict_expired(ttl)
            .expect("evict_expired should succeed");

        assert!(
            cache.get(&hot_key).expect("get should succeed").is_some(),
            "sweep {sweep}: hot entry must survive because it was just requested"
        );
        assert!(
            !row_exists(&db, &cold_sha),
            "sweep {sweep}: cold entry must stay evicted"
        );
    }
}

#[test]
fn get_returns_none_when_the_file_vanished_from_disk() {
    let (src_dir, _cache_dir, db, cache) = open_cache();
    let sha256 = "0".repeat(64);
    let k = key(&sha256);
    let source = temp_source_file(&src_dir, "artifact.whl", b"payload");
    let stored_path = cache.insert(&k, &source).expect("insert should succeed");

    // Someone pruned the cache directory by hand.
    std::fs::remove_file(&stored_path).expect("remove backing file out from under the cache");

    let fetched = cache.get(&k).expect("get should not error");
    assert!(
        fetched.is_none(),
        "get must return None when the file is gone"
    );
    assert!(
        !row_exists(&db, &sha256),
        "the stale row must be cleaned up, not left for a future (now-wrong) hit"
    );
}

#[test]
fn stored_path_is_derived_from_sha256() {
    let (src_dir, cache_dir, _db, cache) = open_cache();
    let sha256 = "0123456789abcdef".repeat(4); // 64 lowercase hex chars
    assert_eq!(sha256.len(), 64);
    let k = key(&sha256);
    let source = temp_source_file(&src_dir, "artifact.whl", b"payload");

    let stored_path = cache.insert(&k, &source).expect("insert should succeed");

    let expected = cache_dir
        .path()
        .join("artifacts")
        .join(&sha256[0..2])
        .join(&sha256);
    assert_eq!(stored_path, expected);
}

#[test]
fn rejects_sha256_that_is_not_lowercase_hex() {
    let (src_dir, _cache_dir, _db, cache) = open_cache();
    let source = temp_source_file(&src_dir, "artifact.whl", b"payload");

    // Uppercase hex, a path traversal attempt, and a too-short string must
    // all be rejected before they ever reach the filesystem.
    for bad_sha256 in [
        "A".repeat(64),
        format!("../../etc/passwd{}", "0".repeat(49)),
        "abc".to_string(),
    ] {
        let k = key(&bad_sha256);
        assert!(
            cache.insert(&k, &source).is_err(),
            "insert must reject non-hex sha256: {bad_sha256:?}"
        );
        assert!(
            cache.get(&k).is_err(),
            "get must reject non-hex sha256: {bad_sha256:?}"
        );
    }
}

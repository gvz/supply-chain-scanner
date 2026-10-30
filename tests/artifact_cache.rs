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
fn evict_retries_an_entry_whose_file_cannot_be_deleted() {
    let (src_dir, _cache_dir, db, cache) = open_cache();
    let sha256 = "9".repeat(64);
    let k = key(&sha256);
    let source = temp_source_file(&src_dir, "artifact.whl", b"payload");
    let stored_path = cache.insert(&k, &source).expect("insert should succeed");

    // Simulate the backing file becoming undeletable without needing any
    // privilege games: replace it with a directory at the same path. On
    // Linux, `remove_file` on a directory fails with `EISDIR`, not
    // `NotFound` — a different failure from the "pruned by hand" case
    // `get_returns_none_when_the_file_vanished_from_disk` covers.
    std::fs::remove_file(&stored_path).expect("remove the real file first");
    std::fs::create_dir(&stored_path).expect("replace it with a directory");

    backdate_last_access(&db, &sha256, 3600);

    let removed = cache
        .evict_expired(Duration::from_secs(60))
        .expect("evict_expired must not error just because one file failed to delete");

    assert_eq!(
        removed, 0,
        "an entry whose file could not be deleted must not be counted as removed"
    );
    assert!(
        row_exists(&db, &sha256),
        "its row must be kept, not dropped, so the bytes are never silently orphaned"
    );

    // Clear the obstruction and sweep again. The row must still be a
    // candidate for eviction rather than permanently stuck because an
    // earlier attempt failed: this time deletion can succeed, and it
    // must actually happen.
    std::fs::remove_dir(&stored_path).expect("clear the obstruction");

    let removed_on_retry = cache
        .evict_expired(Duration::from_secs(60))
        .expect("evict_expired should succeed once the obstruction is gone");

    assert_eq!(
        removed_on_retry, 1,
        "a later sweep must retry the entry, not leave it stuck forever"
    );
    assert!(
        !row_exists(&db, &sha256),
        "once the obstruction is gone, the retried sweep must finish the job"
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

// ---------------------------------------------------------------------------
// Integrity: the cache must never hand back bytes it cannot vouch for
// ---------------------------------------------------------------------------

/// `evict_expired` read `sha256` straight out of the database and handed it
/// to `path_for`, which slices `&sha256[0..2]`. `validated_sha256` guarded
/// `get` and `insert` but not this path, so any short or non-hex value that
/// ever reached the table — a schema change, a hand-edited row, a future
/// caller that skipped the guard — panicked the eviction ticker instead of
/// skipping the row.
#[test]
fn evict_expired_deletes_a_malformed_sha256_row_instead_of_leaving_it_forever() {
    let (_db_dir, _cache_dir, db, cache) = open_cache();
    let source_dir = tempfile::tempdir().expect("create source temp dir");

    // One good, expired entry alongside the bad row, so the sweep has to
    // survive the bad one *and* still do its job.
    let good = "c".repeat(64);
    let file = temp_source_file(&source_dir, "good.whl", b"good bytes");
    cache.insert(&key(&good), &file).expect("insert good entry");
    backdate_last_access(&db, &good, 10_000);

    // A row `path_for` would panic on: shorter than the two characters it
    // slices.
    {
        let conn = db.conn().expect("get connection");
        conn.execute(
            "INSERT INTO artifact_cache
                 (sha256, ecosystem, package, version, filename, bytes, last_access)
             VALUES ('x', 'pypi', 'p', '1', 'f.whl', 1, 0)",
            [],
        )
        .expect("insert malformed row");
    }

    // N5: a malformed row must not merely be skipped-and-kept — that
    // logs the same warning and reclaims nothing on every future sweep,
    // forever. It must be deleted, same as a row whose file has already
    // gone missing.
    let removed = cache
        .evict_expired(Duration::from_secs(60))
        .expect("the sweep must not fail because of one bad row");
    assert_eq!(
        removed, 2,
        "both the good expired entry and the malformed row must be removed"
    );

    let remaining: i64 = db
        .conn()
        .expect("get connection")
        .query_row(
            "SELECT COUNT(*) FROM artifact_cache WHERE sha256 = 'x'",
            [],
            |row| row.get(0),
        )
        .expect("query malformed row");
    assert_eq!(
        remaining, 0,
        "the malformed row must actually be deleted, not merely skipped"
    );

    // A second sweep must find nothing left to do (and, crucially, must
    // not panic or re-log the same malformed row again).
    let removed_again = cache
        .evict_expired(Duration::from_secs(60))
        .expect("a second sweep over an already-clean table must not fail");
    assert_eq!(
        removed_again, 0,
        "the malformed row must not still be there to be \"removed\" again"
    );
}

/// `get` checked only `path.is_file()`, never the recorded length. A crash
/// mid-write leaves a truncated file whose row says it is complete, and the
/// scanner then serves those bytes as `Clean` forever — the artifact was
/// hash-verified once, so nothing downstream re-checks it.
#[test]
fn get_treats_a_truncated_backing_file_as_a_miss_and_cleans_the_row() {
    let (_db_dir, _cache_dir, db, cache) = open_cache();
    let source_dir = tempfile::tempdir().expect("create source temp dir");

    let sha = "d".repeat(64);
    let file = temp_source_file(&source_dir, "full.whl", b"the complete artifact bytes");
    let cached = cache.insert(&key(&sha), &file).expect("insert");
    assert!(cache.get(&key(&sha)).expect("get").is_some());

    // Simulate the crash: the file on disk is now shorter than its row.
    std::fs::write(&cached, b"trunc").expect("truncate the cached file");

    assert!(
        cache.get(&key(&sha)).expect("get").is_none(),
        "a file whose length disagrees with its row must be a miss, never \
         served as verified bytes"
    );
    let conn = db.conn().expect("get connection");
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM artifact_cache WHERE sha256 = ?1",
            [&sha],
            |row| row.get(0),
        )
        .expect("count rows");
    assert_eq!(rows, 0, "the stale row must be cleaned up");
    assert!(
        !cached.exists(),
        "the untrustworthy file must be removed, not left for the next caller"
    );
}

/// `insert` trusted any pre-existing file at the content-addressed path and
/// deleted the incoming copy. After a crash left a truncated file there,
/// the next request re-downloaded, verified, called `insert`, saw the file,
/// deleted the *good* bytes, and wrote a row pointing at the truncated one.
#[test]
fn insert_replaces_a_pre_existing_file_whose_length_is_wrong() {
    let (_db_dir, _cache_dir, _db, cache) = open_cache();
    let source_dir = tempfile::tempdir().expect("create source temp dir");

    let sha = "e".repeat(64);
    let full = b"the complete artifact bytes".to_vec();

    // Plant a truncated file at the content-addressed path with no row,
    // exactly what a crash mid-copy leaves behind.
    let file = temp_source_file(&source_dir, "probe.whl", &full);
    let dest = cache
        .insert(&key(&sha), &file)
        .expect("insert to learn dest");
    {
        let conn = _db.conn().expect("get connection");
        conn.execute("DELETE FROM artifact_cache", []).unwrap();
    }
    std::fs::write(&dest, b"trunc").expect("plant a truncated file");

    // Now a fresh, hash-verified download arrives.
    let good = temp_source_file(&source_dir, "good.whl", &full);
    let path = cache.insert(&key(&sha), &good).expect("insert good bytes");

    assert_eq!(
        std::fs::read(&path).expect("read cached file"),
        full,
        "insert must not keep a pre-existing file whose length disagrees \
         with the bytes it was handed"
    );
    assert!(
        cache.get(&key(&sha)).expect("get").is_some(),
        "the entry must now be a hit"
    );
}

/// `insert` keeps a pre-existing file whose length *does* match, and
/// removes the redundant incoming copy — the hit path, previously
/// untested, which is where the bug above hid.
#[test]
fn insert_keeps_a_matching_pre_existing_file_and_drops_the_redundant_copy() {
    let (_db_dir, _cache_dir, _db, cache) = open_cache();
    let source_dir = tempfile::tempdir().expect("create source temp dir");

    let sha = "f".repeat(64);
    let content = b"identical bytes shipped twice".to_vec();

    let first = temp_source_file(&source_dir, "first.whl", &content);
    let dest = cache.insert(&key(&sha), &first).expect("first insert");

    let second = temp_source_file(&source_dir, "second.whl", &content);
    let again = cache.insert(&key(&sha), &second).expect("second insert");

    assert_eq!(dest, again, "the same content must land at the same path");
    assert!(
        !second.exists(),
        "the redundant incoming copy must be removed"
    );
    assert_eq!(std::fs::read(&dest).expect("read cached file"), content);
}

#[test]
fn insert_and_get_round_trip_a_sha512_digest() {
    let (src_dir, _cache_dir, _db, cache) = open_cache();
    let sha512 = "a".repeat(128); // 128 lowercase hex chars (sha512)
    let k = key(&sha512);
    let source = temp_source_file(&src_dir, "artifact.tar.gz", b"npm package bytes");

    let stored_path = cache
        .insert(&k, &source)
        .expect("insert sha512 should succeed");
    assert!(stored_path.is_file(), "insert must leave a file in place");
    assert_eq!(
        std::fs::read(&stored_path).expect("read stored file"),
        b"npm package bytes"
    );

    let fetched = cache
        .get(&k)
        .expect("get should succeed")
        .expect("sha512 entry must be present after insert");
    assert_eq!(fetched, stored_path);
}

#[test]
fn insert_and_get_round_trip_a_sha1_digest() {
    let (src_dir, _cache_dir, _db, cache) = open_cache();
    let sha1 = "b".repeat(40); // 40 lowercase hex chars (sha1)
    let k = key(&sha1);
    let source = temp_source_file(&src_dir, "artifact.tar.gz", b"old npm package");

    let stored_path = cache
        .insert(&k, &source)
        .expect("insert sha1 should succeed");
    assert!(stored_path.is_file(), "insert must leave a file in place");
    assert_eq!(
        std::fs::read(&stored_path).expect("read stored file"),
        b"old npm package"
    );

    let fetched = cache
        .get(&k)
        .expect("get should succeed")
        .expect("sha1 entry must be present after insert");
    assert_eq!(fetched, stored_path);
}

#[test]
fn a_digest_of_an_unsupported_length_is_still_rejected() {
    let (src_dir, _cache_dir, _db, cache) = open_cache();
    let source = temp_source_file(&src_dir, "artifact.tar.gz", b"payload");

    // 63 and 100 hex chars (neither 40, 64, nor 128) must be rejected
    for bad_digest in ["c".repeat(63), "d".repeat(100)] {
        let k = key(&bad_digest);
        assert!(
            cache.insert(&k, &source).is_err(),
            "insert must reject digest of unsupported length: {bad_digest:?}"
        );
        assert!(
            cache.get(&k).is_err(),
            "get must reject digest of unsupported length: {bad_digest:?}"
        );
    }
}

#[test]
fn an_uppercase_or_non_hex_digest_is_still_rejected() {
    let (src_dir, _cache_dir, _db, cache) = open_cache();
    let source = temp_source_file(&src_dir, "artifact.tar.gz", b"payload");

    // Uppercase and non-hex characters must still be rejected at all lengths
    for bad_digest in ["A".repeat(64), "z".repeat(64)] {
        let k = key(&bad_digest);
        assert!(
            cache.insert(&k, &source).is_err(),
            "insert must reject non-lowercase-hex digest: {bad_digest:?}"
        );
        assert!(
            cache.get(&k).is_err(),
            "get must reject non-lowercase-hex digest: {bad_digest:?}"
        );
    }
}

/// `move_into_place`'s `EXDEV` fallback used to `fs::copy` straight to the
/// final path, so a crash mid-copy left a truncated file at a
/// content-addressed path with no row behind it. It now copies to a temp
/// name beside the destination and renames. Exercised here by pointing the
/// cache root at a `tmpfs` mount when one is available — the real
/// cross-device case — and otherwise by checking the same code path's
/// observable contract on one filesystem.
#[test]
fn insert_across_a_device_boundary_lands_complete_bytes() {
    let db_dir = tempfile::tempdir().expect("create db temp dir");
    let db = Db::open(&db_dir.path().join("scanner.db")).expect("open db");

    // `/dev/shm` is a tmpfs on Linux and therefore a different device
    // from the usual `/tmp` backing store, which is what makes
    // `fs::rename` return EXDEV.
    let shm = std::path::Path::new("/dev/shm");
    let (cache_root, _guard) = if shm.is_dir() {
        let dir = tempfile::tempdir_in(shm).expect("create tmpfs temp dir");
        (dir.path().join("artifacts"), Some(dir))
    } else {
        let dir = tempfile::tempdir().expect("create cache temp dir");
        (dir.path().join("artifacts"), Some(dir))
    };
    let cache = ArtifactCache::new(db, cache_root).expect("create artifact cache");

    // The source lives under the default temp dir, i.e. (usually) a
    // different device from `/dev/shm`.
    let source_dir = tempfile::tempdir().expect("create source temp dir");
    let sha = "a".repeat(64);
    let content: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 251) as u8).collect();
    let file = temp_source_file(&source_dir, "big.whl", &content);

    let dest = cache.insert(&key(&sha), &file).expect("insert");
    assert_eq!(
        std::fs::read(&dest).expect("read cached file"),
        content,
        "every byte must survive the move, cross-device or not"
    );
    assert!(!file.exists(), "the source must have been consumed");
    assert!(
        cache.get(&key(&sha)).expect("get").is_some(),
        "the entry must be a hit, i.e. the recorded length must match disk"
    );

    // No `.part` leftovers from the copy-then-rename fallback.
    let shard = dest.parent().expect("shard dir");
    let leftovers: Vec<_> = std::fs::read_dir(shard)
        .expect("read shard dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path() != dest)
        .map(|e| e.file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "the cross-device fallback must not leave temp files: {leftovers:?}"
    );
}

//! Integration tests for `supply_chain_scanner::db` (SQLite store, migrations,
//! per-artifact verdict store).

use supply_chain_scanner::db::verdict::VerdictStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::model::{ArtifactKey, RefusalReason, Verdict};

const FINGERPRINT_A: &str = "fingerprint-a";
const FINGERPRINT_B: &str = "fingerprint-b";

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

fn key(filename: &str, sha256: &str) -> ArtifactKey {
    ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "example-package".to_string(),
        version: "1.2.3".to_string(),
        filename: filename.to_string(),
        sha256: sha256.to_string(),
    }
}

#[test]
fn put_then_get_roundtrips_clean_verdict() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db);
    let k = key(
        "example_package-1.2.3-py3-none-any.whl",
        "a".repeat(64).as_str(),
    );

    store
        .put(&k, &Verdict::Clean, FINGERPRINT_A)
        .expect("put clean verdict");

    let stored = store
        .get(&k, FINGERPRINT_A)
        .expect("get should succeed")
        .expect("verdict must be present");

    assert_eq!(stored.verdict, Verdict::Clean);
}

#[test]
fn put_then_get_roundtrips_blocked_verdict_with_reason() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db);
    let k = key("example_package-1.2.3.tar.gz", "b".repeat(64).as_str());
    let reason = RefusalReason {
        code: "cve:high".to_string(),
        detail: "CVE-2024-0001 (CVSS 9.1), no fix available".to_string(),
    };

    store
        .put(&k, &Verdict::Blocked(reason.clone()), FINGERPRINT_A)
        .expect("put blocked verdict");

    let stored = store
        .get(&k, FINGERPRINT_A)
        .expect("get should succeed")
        .expect("verdict must be present");

    match stored.verdict {
        Verdict::Blocked(stored_reason) => {
            assert_eq!(stored_reason.code, reason.code);
            assert_eq!(stored_reason.detail, reason.detail);
        }
        Verdict::Clean => panic!("expected a blocked verdict"),
    }
}

#[test]
fn get_with_different_fingerprint_returns_none() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db);
    let k = key(
        "example_package-1.2.3-py3-none-any.whl",
        "c".repeat(64).as_str(),
    );

    store
        .put(&k, &Verdict::Clean, FINGERPRINT_A)
        .expect("put clean verdict");

    let stored = store
        .get(&k, FINGERPRINT_B)
        .expect("get should succeed, just with no match");

    assert!(
        stored.is_none(),
        "a stale fingerprint must not return a stored verdict"
    );
}

#[test]
fn put_twice_updates_in_place_and_keeps_one_row() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db.clone());
    let k = key(
        "example_package-1.2.3-py3-none-any.whl",
        "d".repeat(64).as_str(),
    );

    let why_id_1 = store
        .put(&k, &Verdict::Clean, FINGERPRINT_A)
        .expect("first put");

    let reason = RefusalReason {
        code: "plugin:yara".to_string(),
        detail: "matched malware signature".to_string(),
    };
    let why_id_2 = store
        .put(&k, &Verdict::Blocked(reason), FINGERPRINT_B)
        .expect("second put (re-scan under a new policy)");

    assert_eq!(
        why_id_1, why_id_2,
        "upserting the same artifact must reuse the existing why_id"
    );

    let stored = store
        .get(&k, FINGERPRINT_B)
        .expect("get should succeed")
        .expect("verdict must be present after update");
    assert!(matches!(stored.verdict, Verdict::Blocked(_)));

    let conn = db.conn().expect("get pooled connection");
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM verdicts", [], |row| row.get(0))
        .expect("count rows");
    assert_eq!(count, 1, "there must be exactly one row for this artifact");
}

#[test]
fn why_id_is_url_safe_and_resolves_to_the_verdict() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db);
    let k = key(
        "example_package-1.2.3-py3-none-any.whl",
        "e".repeat(64).as_str(),
    );

    let why_id = store
        .put(&k, &Verdict::Clean, FINGERPRINT_A)
        .expect("put clean verdict");

    assert!(
        why_id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "why_id must be URL-safe (lowercase alphanumeric only): {why_id:?}"
    );
    assert_eq!(why_id.len(), 16, "why_id must be 16 characters long");

    let (resolved_key, stored) = store
        .get_by_why_id(&why_id)
        .expect("get_by_why_id should succeed")
        .expect("why_id must resolve to a verdict");

    assert_eq!(resolved_key, k);
    assert_eq!(stored.verdict, Verdict::Clean);
    assert_eq!(stored.why_id, why_id);
}

#[test]
fn two_artifacts_of_same_version_are_stored_separately() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db.clone());
    let wheel = key(
        "example_package-1.2.3-py3-none-any.whl",
        "f".repeat(64).as_str(),
    );
    let sdist = key("example_package-1.2.3.tar.gz", "0".repeat(64).as_str());

    store
        .put(&sdist, &Verdict::Clean, FINGERPRINT_A)
        .expect("put clean sdist verdict");

    let reason = RefusalReason {
        code: "cve:high".to_string(),
        detail: "unscanned wheel must not ride on the sdist's clean verdict".to_string(),
    };
    store
        .put(&wheel, &Verdict::Blocked(reason), FINGERPRINT_A)
        .expect("put blocked wheel verdict");

    let sdist_stored = store
        .get(&sdist, FINGERPRINT_A)
        .expect("get sdist")
        .expect("sdist verdict must be present");
    assert_eq!(sdist_stored.verdict, Verdict::Clean);

    let wheel_stored = store
        .get(&wheel, FINGERPRINT_A)
        .expect("get wheel")
        .expect("wheel verdict must be present");
    assert!(matches!(wheel_stored.verdict, Verdict::Blocked(_)));

    let conn = db.conn().expect("get pooled connection");
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM verdicts", [], |row| row.get(0))
        .expect("count rows");
    assert_eq!(
        count, 2,
        "the sdist and the wheel must be stored as separate rows"
    );
}

#[test]
fn open_is_idempotent_and_migrations_rerun_cleanly() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("scanner.db");

    let db1 = Db::open(&path).expect("first open runs migrations");
    let store1 = VerdictStore::new(db1);
    let k = key(
        "example_package-1.2.3-py3-none-any.whl",
        "4".repeat(64).as_str(),
    );
    store1
        .put(&k, &Verdict::Clean, FINGERPRINT_A)
        .expect("put survives across opens");

    // Re-opening the same database file must not fail and must not disturb
    // existing data, even though migrations have already been applied.
    let db2 = Db::open(&path).expect("second open is idempotent");
    let store2 = VerdictStore::new(db2);

    let stored = store2
        .get(&k, FINGERPRINT_A)
        .expect("get should succeed")
        .expect("verdict written before reopening must survive");
    assert_eq!(stored.verdict, Verdict::Clean);
}

#[test]
fn a_freshly_stored_clean_verdict_is_not_yet_plugin_checked() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db);
    let k = key(
        "example_package-1.2.3-py3-none-any.whl",
        "5".repeat(64).as_str(),
    );

    store
        .put(&k, &Verdict::Clean, FINGERPRINT_A)
        .expect("put clean verdict");

    assert!(!store
        .is_plugin_checked(&k, FINGERPRINT_A)
        .expect("is_plugin_checked should succeed"));
}

#[test]
fn mark_plugin_checked_flips_it_true() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db);
    let k = key(
        "example_package-1.2.3-py3-none-any.whl",
        "6".repeat(64).as_str(),
    );

    store
        .put(&k, &Verdict::Clean, FINGERPRINT_A)
        .expect("put clean verdict");
    store
        .mark_plugin_checked(&k, FINGERPRINT_A)
        .expect("mark plugin checked");

    assert!(store
        .is_plugin_checked(&k, FINGERPRINT_A)
        .expect("is_plugin_checked should succeed"));
}

#[test]
fn is_plugin_checked_is_false_for_a_fingerprint_with_no_stored_verdict_at_all() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db);
    let k = key(
        "example_package-1.2.3-py3-none-any.whl",
        "7".repeat(64).as_str(),
    );

    assert!(!store
        .is_plugin_checked(&k, "never-scanned-fp")
        .expect("is_plugin_checked should succeed"));
}

#[test]
fn is_plugin_checked_is_false_under_a_fingerprint_the_artifact_was_not_marked_under() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db);
    let k = key(
        "example_package-1.2.3-py3-none-any.whl",
        "8".repeat(64).as_str(),
    );

    store
        .put(&k, &Verdict::Clean, FINGERPRINT_A)
        .expect("put clean verdict");
    store
        .mark_plugin_checked(&k, FINGERPRINT_A)
        .expect("mark plugin checked");

    assert!(
        !store
            .is_plugin_checked(&k, FINGERPRINT_B)
            .expect("is_plugin_checked should succeed"),
        "a plugin-checked mark must not carry over to a different policy fingerprint"
    );
}

#[test]
fn put_resets_plugin_checked_so_a_rewritten_verdict_re_runs_the_plugin_gate() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db);
    let k = key(
        "example_package-1.2.3-py3-none-any.whl",
        "9".repeat(64).as_str(),
    );

    store
        .put(&k, &Verdict::Clean, FINGERPRINT_A)
        .expect("put clean verdict");
    store
        .mark_plugin_checked(&k, FINGERPRINT_A)
        .expect("mark plugin checked");
    assert!(store
        .is_plugin_checked(&k, FINGERPRINT_A)
        .expect("is_plugin_checked should succeed"));

    // Rewriting the verdict in place must clear the plugin-checked mark:
    // the plugins that passed before have not passed for this new verdict.
    store
        .put(&k, &Verdict::Clean, FINGERPRINT_A)
        .expect("rewrite clean verdict");

    assert!(
        !store
            .is_plugin_checked(&k, FINGERPRINT_A)
            .expect("is_plugin_checked should succeed"),
        "put must reset plugin_checked to 0 so the plugin gate runs again"
    );
}

#[test]
fn file_verdicts_returns_clean_and_blocked_rows_with_their_reasons() {
    let (_dir, db) = open_db();
    let store = VerdictStore::new(db);

    let clean_wheel = key(
        "example_package-1.2.3-py3-none-any.whl",
        "1".repeat(64).as_str(),
    );
    let blocked_sdist = key("example_package-1.2.3.tar.gz", "2".repeat(64).as_str());
    let stale = key(
        "example_package-1.2.3-cp311-cp311-linux_x86_64.whl",
        "3".repeat(64).as_str(),
    );

    store
        .put(&clean_wheel, &Verdict::Clean, FINGERPRINT_A)
        .expect("put clean wheel");

    let reason = RefusalReason {
        code: "plugin:yara".to_string(),
        detail: "matched malware signature".to_string(),
    };
    store
        .put(&blocked_sdist, &Verdict::Blocked(reason), FINGERPRINT_A)
        .expect("put blocked sdist");

    // Stored under a different fingerprint: must not show up when
    // querying under FINGERPRINT_A.
    store
        .put(&stale, &Verdict::Clean, FINGERPRINT_B)
        .expect("put stale clean artifact");

    let rows = store
        .file_verdicts("pypi", "example-package", FINGERPRINT_A)
        .expect("file_verdicts should succeed");

    assert_eq!(rows.len(), 2);

    let clean = rows
        .iter()
        .find(|row| row.filename == "example_package-1.2.3-py3-none-any.whl")
        .expect("clean row must be present");
    let blocked = rows
        .iter()
        .find(|row| row.filename == "example_package-1.2.3.tar.gz")
        .expect("blocked row must be present");

    assert!(!clean.blocked);
    assert_eq!(clean.version, "1.2.3");
    assert!(!clean.why_id.is_empty());

    assert!(blocked.blocked);
    assert_eq!(blocked.version, "1.2.3");
    assert_eq!(blocked.reason_code, "plugin:yara");
    assert_eq!(blocked.reason_detail, "matched malware signature");
    assert!(!blocked.why_id.is_empty());
}

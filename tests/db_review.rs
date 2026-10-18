//! Integration tests for `supply_chain_scanner::db::review` — the
//! append-only store of every completed AI review.

use supply_chain_scanner::db::review::{NewReview, ReviewFilter, ReviewStore};
use supply_chain_scanner::db::Db;
use supply_chain_scanner::model::ArtifactKey;

const FINGERPRINT_A: &str = "fingerprint-a";
const FINGERPRINT_B: &str = "fingerprint-b";

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

fn key(package: &str) -> ArtifactKey {
    ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: package.to_string(),
        version: "1.2.3".to_string(),
        filename: format!("{package}-1.2.3-py3-none-any.whl"),
        sha256: format!("{package}-sha256"),
    }
}

fn review(package: &str, fingerprint: &str, verdict: &'static str) -> NewReview {
    NewReview {
        key: key(package),
        fingerprint: fingerprint.to_string(),
        verdict,
        blocked: verdict != "clean",
        summary: format!("summary for {package} under {fingerprint}"),
        findings_json: r#"[{"path":"evil.py","behavior":"reads env"}]"#.to_string(),
        coverage: Some(0.75),
        reviewable_bytes_total: 10_000,
        reviewable_bytes_sent: 7_500,
        opaque_json: r#"{"opaque_data_bytes":0}"#.to_string(),
        reviewed_paths_json: r#"["setup.py","evil.py"]"#.to_string(),
        model: "test-model".to_string(),
        prompt_version: "1",
        collector_version: "1".to_string(),
    }
}

fn all() -> ReviewFilter {
    ReviewFilter {
        limit: 100,
        ..Default::default()
    }
}

#[test]
fn a_stored_review_reads_back_field_for_field() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before the epoch")
        .as_secs() as i64;
    let new = review("example-package", FINGERPRINT_A, "suspicious");

    store.put(&new).expect("put review");

    let stored = store
        .newest_for_artifact(&new.key, FINGERPRINT_A)
        .expect("newest_for_artifact should succeed")
        .expect("review must be present");

    assert_eq!(stored.key, new.key);
    assert_eq!(stored.fingerprint, new.fingerprint);
    assert_eq!(stored.verdict, "suspicious");
    assert!(stored.blocked);
    assert_eq!(stored.summary, new.summary);
    assert_eq!(stored.findings_json, new.findings_json);
    assert_eq!(stored.coverage, Some(0.75));
    assert_eq!(stored.reviewable_bytes_total, new.reviewable_bytes_total);
    assert_eq!(stored.reviewable_bytes_sent, new.reviewable_bytes_sent);
    assert_eq!(stored.opaque_json, new.opaque_json);
    assert_eq!(stored.reviewed_paths_json, new.reviewed_paths_json);
    assert_eq!(stored.model, new.model);
    assert_eq!(stored.prompt_version, "1");
    assert_eq!(stored.collector_version, new.collector_version);
    assert!(stored.id > 0);
    assert!(
        (before..=before + 120).contains(&stored.reviewed_at),
        "reviewed_at {} should sit between {} and {}",
        stored.reviewed_at,
        before,
        before + 120
    );
}

#[test]
fn put_returns_a_fresh_id_for_each_review() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    let mut new = review("example-package", FINGERPRINT_A, "clean");

    let first = store.put(&new).expect("first put");
    new.summary = "second pass".to_string();
    let second = store.put(&new).expect("second put");

    assert_ne!(first, second);
}

#[test]
fn a_second_review_of_the_same_artifact_does_not_overwrite_the_first() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    let mut new = review("example-package", FINGERPRINT_A, "clean");

    store.put(&new).expect("first put");
    new.summary = "second pass disagrees".to_string();
    new.verdict = "malicious";
    new.blocked = true;
    store.put(&new).expect("second put");

    let rows = store.list(&all()).expect("list reviews");
    assert_eq!(rows.len(), 2, "a repeat review appends, it never replaces");
}

#[test]
fn newest_for_artifact_returns_the_latest_row() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    let mut new = review("example-package", FINGERPRINT_A, "clean");

    store.put(&new).expect("first put");
    new.summary = "the second review".to_string();
    store.put(&new).expect("second put");

    let stored = store
        .newest_for_artifact(&new.key, FINGERPRINT_A)
        .expect("newest_for_artifact should succeed")
        .expect("review must be present");
    assert_eq!(stored.summary, "the second review");
}

#[test]
fn newest_for_artifact_ignores_another_fingerprint() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    store
        .put(&review("example-package", FINGERPRINT_A, "clean"))
        .expect("put under fingerprint A");
    store
        .put(&review("example-package", FINGERPRINT_B, "malicious"))
        .expect("put under fingerprint B");

    let stored = store
        .newest_for_artifact(&key("example-package"), FINGERPRINT_A)
        .expect("newest_for_artifact should succeed")
        .expect("review must be present");
    assert_eq!(stored.verdict, "clean");
}

#[test]
fn newest_for_artifact_returns_none_for_an_unreviewed_artifact() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    store
        .put(&review("example-package", FINGERPRINT_A, "clean"))
        .expect("put unrelated review");

    let stored = store
        .newest_for_artifact(&key("other-package"), FINGERPRINT_A)
        .expect("newest_for_artifact should succeed");
    assert!(stored.is_none());
}

#[test]
fn list_returns_newest_first() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    let mut new = review("example-package", FINGERPRINT_A, "clean");
    store.put(&new).expect("put 1");
    new.summary = "second".to_string();
    store.put(&new).expect("put 2");
    new.summary = "third".to_string();
    store.put(&new).expect("put 3");

    let rows = store.list(&all()).expect("list reviews");
    let summaries: Vec<&str> = rows.iter().map(|r| r.summary.as_str()).collect();
    assert_eq!(
        summaries,
        vec![
            "third",
            "second",
            "summary for example-package under fingerprint-a"
        ]
    );
}

#[test]
fn list_filters_by_verdict() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    store
        .put(&review("pkg-one", FINGERPRINT_A, "clean"))
        .expect("put clean");
    store
        .put(&review("pkg-two", FINGERPRINT_A, "malicious"))
        .expect("put malicious");

    let filter = ReviewFilter {
        verdict: Some("malicious".to_string()),
        ..all()
    };
    let rows = store.list(&filter).expect("list reviews");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].verdict, "malicious");
}

#[test]
fn list_filters_by_package() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    store
        .put(&review("pkg-one", FINGERPRINT_A, "clean"))
        .expect("put pkg-one");
    store
        .put(&review("pkg-two", FINGERPRINT_A, "clean"))
        .expect("put pkg-two");

    let filter = ReviewFilter {
        package: Some("pkg-two".to_string()),
        ..all()
    };
    let rows = store.list(&filter).expect("list reviews");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key.package, "pkg-two");
}

#[test]
fn list_filters_by_since() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    store
        .put(&review("pkg-one", FINGERPRINT_A, "clean"))
        .expect("put review");

    // Every row was written after the epoch counts.
    let from_epoch = ReviewFilter {
        since: Some(0),
        ..all()
    };
    assert_eq!(store.list(&from_epoch).expect("list reviews").len(), 1);

    // A cutoff far in the future matches nothing.
    let from_future = ReviewFilter {
        since: Some(2_000_000_000_000),
        ..all()
    };
    assert!(store.list(&from_future).expect("list reviews").is_empty());
}

#[test]
fn list_paginates_with_before_id() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    let mut new = review("example-package", FINGERPRINT_A, "clean");
    let id_oldest = store.put(&new).expect("put 1");
    new.summary = "second".to_string();
    let id_middle = store.put(&new).expect("put 2");
    new.summary = "third".to_string();
    let id_newest = store.put(&new).expect("put 3");

    let filter = ReviewFilter {
        before_id: Some(id_middle),
        ..all()
    };
    let rows = store.list(&filter).expect("list reviews");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, id_oldest);

    let before_everything = ReviewFilter {
        before_id: Some(id_newest + 1),
        ..all()
    };
    assert_eq!(
        store.list(&before_everything).expect("list reviews").len(),
        3
    );
}

#[test]
fn list_honours_its_limit() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    let mut new = review("example-package", FINGERPRINT_A, "clean");
    store.put(&new).expect("put 1");
    new.summary = "second".to_string();
    store.put(&new).expect("put 2");
    new.summary = "third".to_string();
    store.put(&new).expect("put 3");

    let filter = ReviewFilter {
        limit: 2,
        ..Default::default()
    };
    let rows = store.list(&filter).expect("list reviews");
    // The limit keeps the newest rows, not the oldest.
    let summaries: Vec<&str> = rows.iter().map(|r| r.summary.as_str()).collect();
    assert_eq!(summaries, vec!["third", "second"]);
}

#[test]
fn coverage_round_trips_as_null_when_undefined() {
    let (_dir, db) = open_db();
    let store = ReviewStore::new(db);
    let mut new = review("example-package", FINGERPRINT_A, "clean");
    let coverage = new.coverage;
    new.coverage = None;

    store.put(&new).expect("put review");

    let stored = store
        .newest_for_artifact(&new.key, FINGERPRINT_A)
        .expect("newest_for_artifact should succeed")
        .expect("review must be present");
    assert_eq!(stored.coverage, None);
    // Sanity: the fixture really did carry a defined value before.
    assert!(coverage.is_some());
}

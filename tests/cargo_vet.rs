//! Integration tests for the cargo-vet fast path. They cover three parts:
//! the `audits.toml` parser (`supply_chain_scanner::cargovet::parse`), the
//! audit store (`supply_chain_scanner::db::cargo_vet`), and the
//! multi-source sync (`supply_chain_scanner::cargovet::CargoVetSync`).
//! `wiremock` stands in for the upstream audit sets.

use std::sync::Arc;

use supply_chain_scanner::cargovet::parse::{parse_audits_toml, AuditEntry};
use supply_chain_scanner::cargovet::CargoVetSync;
use supply_chain_scanner::config::CargoVetSource;
use supply_chain_scanner::db::cargo_vet::CargoVetStore;
use supply_chain_scanner::db::Db;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A minimal but realistic `audits.toml`: one full audit and one delta
/// audit for the same crate, in cargo-vet's own on-disk shape.
const SAMPLE_AUDITS_TOML: &str = r#"
[[audits.demo-crate]]
version = "1.2.3"
who = "Jane Auditor <jane@example.com>"
criteria = "safe-to-deploy"

[[audits.demo-crate]]
delta = "1.2.3 -> 1.3.0"
who = "Jane Auditor <jane@example.com>"
criteria = "safe-to-run"
"#;

/// A file whose `who` and `criteria` are arrays rather than single
/// strings. cargo-vet's format allows both forms.
const ARRAY_VALUED_AUDITS_TOML: &str = r#"
[[audits.array-crate]]
version = "2.0.0"
who = ["Jane Auditor <jane@example.com>", "John Auditor <john@example.com>"]
criteria = ["safe-to-run", "safe-to-deploy"]
"#;

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

fn fresh_store() -> (tempfile::TempDir, CargoVetStore) {
    let (dir, db) = open_db();
    (dir, CargoVetStore::new(db))
}

fn full(package: &str, version: &str, who: &str, criterion: &str, source: &str) -> AuditEntry {
    AuditEntry::Full {
        package: package.to_string(),
        version: version.to_string(),
        who: vec![who.to_string()],
        criteria: vec![criterion.to_string()],
        source: source.to_string(),
    }
}

fn delta(package: &str, from: &str, to: &str, criterion: &str, source: &str) -> AuditEntry {
    AuditEntry::Delta {
        package: package.to_string(),
        from: from.to_string(),
        to: to.to_string(),
        who: vec!["Jane Auditor <jane@example.com>".to_string()],
        criteria: vec![criterion.to_string()],
        source: source.to_string(),
    }
}

// ---- parse_audits_toml ----

#[test]
fn parses_a_full_audit_entry() {
    let entries = parse_audits_toml(SAMPLE_AUDITS_TOML, "mozilla").expect("parse audits.toml");

    let full = entries
        .iter()
        .find_map(|entry| match entry {
            AuditEntry::Full {
                package,
                version,
                who,
                criteria,
                source,
            } => Some((package, version, who, criteria, source)),
            AuditEntry::Delta { .. } => None,
        })
        .expect("a Full entry must be present");

    assert_eq!(full.0, "demo-crate");
    assert_eq!(full.1, "1.2.3");
    assert_eq!(full.2, &vec!["Jane Auditor <jane@example.com>".to_string()]);
    assert_eq!(full.3, &vec!["safe-to-deploy".to_string()]);
    assert_eq!(full.4, "mozilla");
}

#[test]
fn parses_a_delta_audit_entry_without_treating_it_as_full() {
    let entries = parse_audits_toml(SAMPLE_AUDITS_TOML, "mozilla").expect("parse audits.toml");

    let delta = entries
        .iter()
        .find_map(|entry| match entry {
            AuditEntry::Delta {
                package, from, to, ..
            } => Some((package, from, to)),
            AuditEntry::Full { .. } => None,
        })
        .expect("a Delta entry must be present");

    assert_eq!(
        delta,
        (
            &"demo-crate".to_string(),
            &"1.2.3".to_string(),
            &"1.3.0".to_string()
        )
    );
    assert_eq!(
        entries.len(),
        2,
        "the sample file holds exactly one full and one delta entry"
    );
}

#[test]
fn parses_string_or_array_valued_who_and_criteria() {
    let entries = parse_audits_toml(ARRAY_VALUED_AUDITS_TOML, "google").expect("parse audits.toml");

    assert_eq!(entries.len(), 1);
    match &entries[0] {
        AuditEntry::Full { who, criteria, .. } => {
            assert_eq!(
                who,
                &vec![
                    "Jane Auditor <jane@example.com>".to_string(),
                    "John Auditor <john@example.com>".to_string(),
                ]
            );
            assert_eq!(
                criteria,
                &vec!["safe-to-run".to_string(), "safe-to-deploy".to_string()]
            );
        }
        other => panic!("expected a Full entry, got {other:?}"),
    }
}

// ---- CargoVetStore ----

#[test]
fn covers_is_true_for_a_full_audit_meeting_the_criterion_from_a_trusted_source() {
    let (_dir, store) = fresh_store();
    store
        .replace_source(
            "mozilla",
            &[full(
                "demo-crate",
                "1.2.3",
                "Jane Auditor <jane@example.com>",
                "safe-to-deploy",
                "mozilla",
            )],
        )
        .expect("replace_source");

    assert!(store
        .covers("demo-crate", "1.2.3", "safe-to-deploy", &[])
        .expect("covers"));
}

#[test]
fn covers_is_false_when_the_criterion_is_not_met() {
    let (_dir, store) = fresh_store();
    store
        .replace_source(
            "mozilla",
            &[full(
                "demo-crate",
                "1.2.3",
                "Jane Auditor <jane@example.com>",
                "safe-to-run",
                "mozilla",
            )],
        )
        .expect("replace_source");

    assert!(
        !store
            .covers("demo-crate", "1.2.3", "safe-to-deploy", &[])
            .expect("covers"),
        "an entry certifying only safe-to-run must not cover safe-to-deploy"
    );
    assert!(
        store
            .covers("demo-crate", "1.2.3", "safe-to-run", &[])
            .expect("covers"),
        "the same entry does cover the criterion it names"
    );
}

#[test]
fn covers_respects_a_non_empty_trusted_reviewers_allowlist() {
    let (_dir, store) = fresh_store();
    store
        .replace_source(
            "mozilla",
            &[full(
                "demo-crate",
                "1.2.3",
                "Jane Auditor <jane@example.com>",
                "safe-to-deploy",
                "mozilla",
            )],
        )
        .expect("replace_source");

    assert!(store
        .covers("demo-crate", "1.2.3", "safe-to-deploy", &[])
        .expect("covers"));

    let mismatched = vec!["Someone Else <else@example.com>".to_string()];
    assert!(
        !store
            .covers("demo-crate", "1.2.3", "safe-to-deploy", &mismatched)
            .expect("covers"),
        "a non-empty allowlist that names another reviewer must not cover"
    );

    let matched = vec!["Jane Auditor <jane@example.com>".to_string()];
    assert!(
        store
            .covers("demo-crate", "1.2.3", "safe-to-deploy", &matched)
            .expect("covers"),
        "an allowlist naming the entry's who must cover"
    );
}

#[test]
fn covers_normalizes_the_package_name() {
    let (_dir, store) = fresh_store();
    store
        .replace_source(
            "mozilla",
            &[full(
                "demo-crate",
                "1.2.3",
                "Jane Auditor <jane@example.com>",
                "safe-to-deploy",
                "mozilla",
            )],
        )
        .expect("replace_source");

    assert!(
        store
            .covers("Demo_Crate", "1.2.3", "safe-to-deploy", &[])
            .expect("covers"),
        "crates.io treats Demo_Crate and demo-crate as the same crate"
    );
}

#[test]
fn a_delta_only_entry_never_satisfies_covers() {
    let (_dir, store) = fresh_store();
    store
        .replace_source(
            "mozilla",
            &[delta(
                "demo-crate",
                "1.2.3",
                "1.3.0",
                "safe-to-deploy",
                "mozilla",
            )],
        )
        .expect("replace_source");

    assert!(
        !store
            .covers("demo-crate", "1.3.0", "safe-to-deploy", &[])
            .expect("covers"),
        "a delta entry is never sufficient on its own"
    );
}

#[test]
fn replace_source_is_scoped_to_its_own_source_and_does_not_touch_others() {
    let (_dir, store) = fresh_store();
    store
        .replace_source(
            "mozilla",
            &[full(
                "demo-crate",
                "1.2.3",
                "Jane Auditor <jane@example.com>",
                "safe-to-deploy",
                "mozilla",
            )],
        )
        .expect("replace_source mozilla");
    store
        .replace_source(
            "google",
            &[full(
                "other-crate",
                "4.5.6",
                "John Auditor <john@example.com>",
                "safe-to-deploy",
                "google",
            )],
        )
        .expect("replace_source google");

    assert!(store
        .covers("demo-crate", "1.2.3", "safe-to-deploy", &[])
        .expect("covers"));
    assert!(store
        .covers("other-crate", "4.5.6", "safe-to-deploy", &[])
        .expect("covers"));

    let replaced = store
        .replace_source("mozilla", &[])
        .expect("replace_source mozilla with nothing");
    assert_eq!(replaced, 0);

    assert!(
        !store
            .covers("demo-crate", "1.2.3", "safe-to-deploy", &[])
            .expect("covers"),
        "clearing mozilla must remove mozilla's rows"
    );
    assert!(
        store
            .covers("other-crate", "4.5.6", "safe-to-deploy", &[])
            .expect("covers"),
        "clearing mozilla must not touch google's rows"
    );
}

// ---- CargoVetSync ----

#[tokio::test]
async fn sync_all_updates_every_reachable_source_and_skips_a_failing_one() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/mozilla/audits.toml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SAMPLE_AUDITS_TOML))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/org/audits.toml"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let store = Arc::new(CargoVetStore::new(db));
    let sources = vec![
        CargoVetSource {
            name: "mozilla".to_string(),
            url: Url::parse(&format!("{}/mozilla/audits.toml", server.uri())).expect("valid url"),
        },
        CargoVetSource {
            name: "org".to_string(),
            url: Url::parse(&format!("{}/org/audits.toml", server.uri())).expect("valid url"),
        },
    ];

    let sync = CargoVetSync::new(store.clone(), sources).expect("build sync");
    let count = sync.sync_all().await.expect("sync_all");

    assert_eq!(
        count, 1,
        "only the reachable source's full audit is stored, and a delta entry is not"
    );
    assert!(
        store
            .covers("demo-crate", "1.2.3", "safe-to-deploy", &[])
            .expect("covers"),
        "the reachable source's audit must be stored despite the other source's 500"
    );
}

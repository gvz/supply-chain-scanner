//! Integration tests for `supply_chain_scanner::advisory` (OSV document
//! parsing and CVSS scoring) and `supply_chain_scanner::db::advisory` (the
//! local advisory mirror and its atomic sync), using `wiremock` as a
//! stand-in for the upstream OSV feed.

use std::io::Write as _;

use supply_chain_scanner::advisory::osv::{parse_osv, severity_score, OsvSync};
use supply_chain_scanner::advisory::VersionRange;
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::Db;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Db::open(&dir.path().join("scanner.db")).expect("open db");
    (dir, db)
}

/// Reads a fixture JSON document from `tests/fixtures/osv/`.
fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/osv/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading fixture {path}: {err}"))
}

/// Builds an in-memory zip (uncompressed, so no compression feature is
/// needed to write it) containing one entry per document in `docs`.
fn zip_of(docs: &[&str]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut writer = ZipWriter::new(cursor);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (index, doc) in docs.iter().enumerate() {
            writer
                .start_file(format!("advisory-{index}.json"), options)
                .expect("start zip entry");
            writer.write_all(doc.as_bytes()).expect("write zip entry");
        }
        writer.finish().expect("finish zip");
    }
    buf
}

// ---- parse_osv ----

#[test]
fn parse_osv_extracts_id_package_and_enumerated_versions() {
    let advisories = parse_osv(&fixture("basic.json")).expect("parse basic fixture");
    assert_eq!(advisories.len(), 1);
    let adv = &advisories[0];
    assert_eq!(adv.id, "PYSEC-2024-1");
    assert_eq!(
        adv.package, "example-package",
        "package name must be PEP 503 normalized"
    );
    assert_eq!(adv.versions, vec!["1.0.0", "1.1.0", "1.2.0"]);
}

#[test]
fn parse_osv_extracts_introduced_and_fixed_ranges() {
    let advisories = parse_osv(&fixture("ranges.json")).expect("parse ranges fixture");
    assert_eq!(advisories.len(), 1);
    let adv = &advisories[0];
    assert_eq!(adv.ranges.len(), 1);
    assert_eq!(adv.ranges[0].introduced, Some("0".to_string()));
    assert_eq!(adv.ranges[0].fixed, Some("2.0.0".to_string()));
    assert_eq!(
        adv.fixed_versions,
        vec!["2.0.0".to_string()],
        "fixed_versions must be derived from the ranges' fixed events"
    );
}

#[test]
fn parse_osv_entry_without_severity_yields_none() {
    let advisories = parse_osv(&fixture("no_severity.json")).expect("parse no_severity fixture");
    assert_eq!(advisories.len(), 1);
    assert_eq!(
        advisories[0].severity, None,
        "a document with no severity[] entries must yield None, not a default score"
    );
}

#[test]
fn parse_osv_entry_with_multiple_affected_packages_yields_one_advisory_each() {
    let advisories =
        parse_osv(&fixture("multi_affected.json")).expect("parse multi_affected fixture");
    assert_eq!(advisories.len(), 2);
    assert_eq!(advisories[0].package, "package-one");
    assert_eq!(advisories[1].package, "package-two");
    assert_eq!(advisories[0].id, "PYSEC-2024-4");
    assert_eq!(advisories[1].id, "PYSEC-2024-4");
}

/// Regression test for the defect this task fixes: `repeated_package.json`
/// is modeled on the real OSV document `GHSA-22jm-4hxw-35jf`, which lists
/// `PyPI/nova` three times in `affected[]` with disjoint version sets and
/// disjoint ranges. `parse_osv` must merge same-package entries within one
/// document into a single `Advisory`, unioning `versions` and `ranges`,
/// rather than emitting one row per `affected[]` entry (which collides on
/// the `(ecosystem, id, package)` primary key once stored).
#[test]
fn parse_osv_merges_repeated_affected_entries_for_the_same_package() {
    let advisories =
        parse_osv(&fixture("repeated_package.json")).expect("parse repeated_package fixture");

    assert_eq!(
        advisories.len(),
        1,
        "three affected[] entries for the same package must merge into one Advisory"
    );
    let adv = &advisories[0];
    assert_eq!(adv.id, "PYSEC-2024-5");
    assert_eq!(adv.package, "repeated-package");

    assert_eq!(
        adv.versions,
        vec![
            "0.9.0".to_string(),
            "1.5.0".to_string(),
            "2.5.0".to_string()
        ],
        "versions must be the union of all three entries' enumerated versions"
    );

    assert_eq!(
        adv.ranges.len(),
        3,
        "ranges must be the union of all three entries' ranges"
    );
    assert!(adv.ranges.contains(&VersionRange {
        introduced: Some("0".to_string()),
        fixed: Some("1.0.0".to_string()),
    }));
    assert!(adv.ranges.contains(&VersionRange {
        introduced: Some("1.1.0".to_string()),
        fixed: Some("1.6.0".to_string()),
    }));
    assert!(adv.ranges.contains(&VersionRange {
        introduced: Some("2.0.0".to_string()),
        fixed: Some("2.6.0".to_string()),
    }));

    assert_eq!(
        adv.fixed_versions,
        vec![
            "1.0.0".to_string(),
            "1.6.0".to_string(),
            "2.6.0".to_string()
        ],
        "fixed_versions must be the union of all three entries' fixed events"
    );
}

/// Regression test for the live false positive this task fixes:
/// `pip download torch==2.5.1` through the proxy was refused with
/// `BLOCKED cve:GHSA-4vmg-rw8f-92f9`, whose `/why` page read "Withdrawn
/// Advisory: PyTorch deserialization vulnerability" — the OSV feed keeps
/// shipping documents carrying a `withdrawn` timestamp rather than
/// deleting them, and the mirror was ingesting them, blocking a top-20
/// package on a finding its own publisher had retracted. `fixture`
/// `withdrawn_advisory.json` reproduces that exact document (same id,
/// same package, same summary) with a `withdrawn` timestamp present.
#[test]
fn parse_osv_drops_a_withdrawn_advisory() {
    let advisories =
        parse_osv(&fixture("withdrawn_advisory.json")).expect("parse withdrawn_advisory fixture");
    assert!(
        advisories.is_empty(),
        "a document carrying a `withdrawn` timestamp must yield no advisories"
    );
}

/// Control for the test above: `withdrawn_advisory_active.json` is the
/// identical document with the `withdrawn` field removed. Without this
/// test, `parse_osv_drops_a_withdrawn_advisory` could pass for the wrong
/// reason — e.g. a parser that drops every document, or one that fails to
/// parse this fixture's shape at all — rather than because it specifically
/// recognizes `withdrawn`.
#[test]
fn parse_osv_keeps_the_same_advisory_when_not_withdrawn() {
    let advisories = parse_osv(&fixture("withdrawn_advisory_active.json"))
        .expect("parse withdrawn_advisory_active fixture");
    assert_eq!(
        advisories.len(),
        1,
        "the same document without `withdrawn` must yield its advisory"
    );
    assert_eq!(advisories[0].id, "GHSA-4vmg-rw8f-92f9");
    assert_eq!(advisories[0].package, "torch");
}

// ---- severity_score ----

#[test]
fn severity_score_parses_cvss_v3_vector() {
    let score = severity_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        .expect("a well-formed CVSS v3.1 vector must parse");
    assert!((score - 9.8).abs() < 0.05, "expected ~9.8, got {score}");
}

#[test]
fn severity_score_parses_bare_numeric_score() {
    let score = severity_score("7.5").expect("a bare numeric score must parse");
    assert!((score - 7.5).abs() < f32::EPSILON);
}

#[test]
fn severity_score_rejects_garbage() {
    assert_eq!(
        severity_score("not a vector or a number"),
        None,
        "garbage input must yield None, not 0.0"
    );
    assert_eq!(severity_score(""), None, "empty input must yield None");
    assert_eq!(
        severity_score("nan"),
        None,
        "the literal \"nan\" must never surface as Some(NaN)"
    );
}

// ---- AdvisoryStore ----

#[test]
fn for_package_normalizes_the_lookup_name() {
    let (_dir, db) = open_db();
    let store = AdvisoryStore::new(db);
    let advisories = parse_osv(&fixture("basic.json")).expect("parse basic fixture");
    store
        .replace_all("pypi", &advisories)
        .expect("replace_all should succeed");

    // The fixture's package is "Example-Package"; stored (and looked up)
    // under its PEP 503 normalized form, "example-package".
    let found = store
        .for_package("pypi", "Example_Package")
        .expect("lookup should succeed");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, "PYSEC-2024-1");
}

/// Regression test: `multi_affected.json` parses into two `Advisory` rows
/// that share one OSV id but name different packages with different
/// version lists. The store must accept both (no primary-key collision
/// on the shared id) and must never let one package's versions leak into
/// the other's lookup.
#[test]
fn replace_all_keeps_shared_advisory_id_rows_isolated_per_package() {
    let (_dir, db) = open_db();
    let store = AdvisoryStore::new(db);
    let advisories =
        parse_osv(&fixture("multi_affected.json")).expect("parse multi_affected fixture");
    store
        .replace_all("pypi", &advisories)
        .expect("replace_all must accept two rows sharing one advisory id");

    let package_one = store
        .for_package("pypi", "package-one")
        .expect("lookup should succeed");
    assert_eq!(package_one.len(), 1);
    assert_eq!(package_one[0].id, "PYSEC-2024-4");
    assert_eq!(package_one[0].versions, vec!["1.0.0".to_string()]);

    let package_two = store
        .for_package("pypi", "package-two")
        .expect("lookup should succeed");
    assert_eq!(package_two.len(), 1);
    assert_eq!(package_two[0].id, "PYSEC-2024-4");
    assert_eq!(
        package_two[0].versions,
        vec!["2.0.0".to_string()],
        "package-two must not see package-one's versions despite sharing an advisory id"
    );
}

/// Regression test for the defect this task fixes: before the fix,
/// `parse_osv` emitted one `Advisory` row per `affected[]` entry, so a
/// document repeating the same package (like `repeated_package.json`,
/// modeled on the real `GHSA-22jm-4hxw-35jf`) produced three rows that all
/// shared the `(ecosystem, id, package)` primary key, and `replace_all`
/// failed with a primary-key violation inside its transaction — which is
/// exactly the failure the live OSV feed hit at startup (1156 of 26370
/// real documents repeat a package). After the fix, `parse_osv` merges
/// those entries into one row before `replace_all` ever sees them, so the
/// insert succeeds and the merged row round-trips through `for_package`
/// with the union of versions and ranges intact.
#[test]
fn replace_all_accepts_merged_rows_for_a_repeated_package() {
    let (_dir, db) = open_db();
    let store = AdvisoryStore::new(db);
    let advisories =
        parse_osv(&fixture("repeated_package.json")).expect("parse repeated_package fixture");

    store
        .replace_all("pypi", &advisories)
        .expect("replace_all must accept the merged row without a primary-key violation");

    let found = store
        .for_package("pypi", "Repeated-Package")
        .expect("lookup should succeed");
    assert_eq!(
        found.len(),
        1,
        "exactly one merged advisory must round-trip"
    );
    assert_eq!(found[0].id, "PYSEC-2024-5");
    assert_eq!(
        found[0].versions,
        vec![
            "0.9.0".to_string(),
            "1.5.0".to_string(),
            "2.5.0".to_string()
        ]
    );
    assert_eq!(
        found[0].ranges.len(),
        3,
        "all three merged ranges must round-trip"
    );
    assert!(found[0].ranges.contains(&VersionRange {
        introduced: Some("2.0.0".to_string()),
        fixed: Some("2.6.0".to_string()),
    }));
}

/// Store-level companion to `parse_osv_drops_a_withdrawn_advisory`: even
/// handed a `replace_all` call, a withdrawn advisory must never be
/// reachable through `for_package`. `parse_osv` already returns nothing
/// for `withdrawn_advisory.json`, so this asserts the empty `Vec` round-trips
/// through storage as "nothing to find" rather than, say, a row that
/// `replace_all` or `for_package` resurrects some other way.
#[test]
fn for_package_never_returns_a_withdrawn_advisory() {
    let (_dir, db) = open_db();
    let store = AdvisoryStore::new(db);
    let advisories =
        parse_osv(&fixture("withdrawn_advisory.json")).expect("parse withdrawn_advisory fixture");
    store
        .replace_all("pypi", &advisories)
        .expect("replace_all should succeed even with nothing to insert");

    let found = store
        .for_package("pypi", "torch")
        .expect("lookup should succeed");
    assert!(
        found.is_empty(),
        "a withdrawn advisory must never reach for_package"
    );
}

// ---- OsvSync ----

#[tokio::test]
async fn sync_pypi_ingests_a_zip_of_osv_docs() {
    let server = MockServer::start().await;
    let zip_bytes = zip_of(&[&fixture("basic.json"), &fixture("ranges.json")]);
    Mock::given(method("GET"))
        .and(path("/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let store = AdvisoryStore::new(db);
    let url = Url::parse(&format!("{}/all.zip", server.uri())).expect("valid url");
    let sync = OsvSync::new(store, reqwest::Client::new(), url);

    let count = sync.sync_pypi().await.expect("sync should succeed");
    assert_eq!(count, 2);
}

#[tokio::test]
async fn sync_pypi_replaces_previous_rows_atomically() {
    let server = MockServer::start().await;
    let first_zip = zip_of(&[&fixture("basic.json"), &fixture("withdrawn.json")]);
    let second_zip = zip_of(&[&fixture("basic.json")]);

    Mock::given(method("GET"))
        .and(path("/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(first_zip))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(second_zip))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let sync_store = AdvisoryStore::new(db.clone());
    let url = Url::parse(&format!("{}/all.zip", server.uri())).expect("valid url");
    let sync = OsvSync::new(sync_store, reqwest::Client::new(), url);

    sync.sync_pypi().await.expect("first sync should succeed");

    let query_store = AdvisoryStore::new(db);
    let withdrawn_before = query_store
        .for_package("pypi", "withdrawn-package")
        .expect("lookup should succeed");
    assert_eq!(
        withdrawn_before.len(),
        1,
        "withdrawn-package must be present after the first sync"
    );

    sync.sync_pypi().await.expect("second sync should succeed");

    let withdrawn_after = query_store
        .for_package("pypi", "withdrawn-package")
        .expect("lookup should succeed");
    assert!(
        withdrawn_after.is_empty(),
        "withdrawn-package must disappear once the second sync's set no longer includes it"
    );

    let still_present = query_store
        .for_package("pypi", "example-package")
        .expect("lookup should succeed");
    assert_eq!(
        still_present.len(),
        1,
        "example-package must still be present after the second sync"
    );
}

#[tokio::test]
async fn sync_pypi_failure_leaves_existing_advisories_intact() {
    let server = MockServer::start().await;
    let good_zip = zip_of(&[&fixture("basic.json")]);

    Mock::given(method("GET"))
        .and(path("/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(good_zip))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/all.zip"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let sync_store = AdvisoryStore::new(db.clone());
    let url = Url::parse(&format!("{}/all.zip", server.uri())).expect("valid url");
    let sync = OsvSync::new(sync_store, reqwest::Client::new(), url);

    sync.sync_pypi().await.expect("first sync should succeed");

    let result = sync.sync_pypi().await;
    assert!(
        result.is_err(),
        "a failed download must surface as an error, not an empty success"
    );

    let query_store = AdvisoryStore::new(db);
    let advisories = query_store
        .for_package("pypi", "example-package")
        .expect("lookup should succeed");
    assert_eq!(
        advisories.len(),
        1,
        "a failed sync must leave the previous advisories intact"
    );
}

//! Integration tests for the ecosystem-pluggable `OsvSync::sync` entry
//! point, exercised against crates.io. Mirrors `tests/advisory_sync.rs`'s
//! `OsvSync` tests (a wiremock server serving an in-memory zip, asserting
//! the store ends up populated), but calls the general
//! `sync(ecosystem, normalize)` form with the cargo normalizer.

use std::io::Write as _;

use supply_chain_scanner::advisory::osv::OsvSync;
use supply_chain_scanner::db::advisory::AdvisoryStore;
use supply_chain_scanner::db::Db;
use supply_chain_scanner::ecosystem::cargo::normalize_name;
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

/// One OSV document naming package `Serde_JSON`, which the cargo normalizer
/// must key as `serde-json`.
const CARGO_OSV_DOC: &str = r#"{
  "id": "RUSTSEC-2024-0001",
  "summary": "a demo crate vulnerability",
  "affected": [
    {
      "package": { "ecosystem": "crates.io", "name": "Serde_JSON" },
      "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "0" }, { "fixed": "1.0.200" } ] } ]
    }
  ]
}"#;

#[tokio::test]
async fn sync_populates_the_crates_io_ecosystem_under_its_own_normalizer() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_of(&[CARGO_OSV_DOC])))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let sync_store = AdvisoryStore::new(db.clone());
    let url = Url::parse(&format!("{}/all.zip", server.uri())).expect("valid url");
    let sync = OsvSync::new(sync_store, reqwest::Client::new(), url);

    let count = sync.sync("crates.io", normalize_name).await.unwrap();
    assert_eq!(count, 1);

    let store = AdvisoryStore::new(db);
    let stored = store.for_package("crates.io", "serde-json").unwrap();
    assert_eq!(
        stored.len(),
        1,
        "the normalized name must be the lookup key"
    );
    assert_eq!(stored[0].id, "RUSTSEC-2024-0001");
    assert_eq!(stored[0].package, "serde-json");
}

#[tokio::test]
async fn sync_keeps_ecosystems_isolated() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_of(&[CARGO_OSV_DOC])))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let sync_store = AdvisoryStore::new(db.clone());
    let url = Url::parse(&format!("{}/all.zip", server.uri())).expect("valid url");
    let sync = OsvSync::new(sync_store, reqwest::Client::new(), url);

    sync.sync("crates.io", normalize_name)
        .await
        .expect("sync should succeed");

    let store = AdvisoryStore::new(db);
    assert!(
        store
            .for_package("pypi", "serde-json")
            .expect("lookup should succeed")
            .is_empty(),
        "a crates.io sync must not populate the pypi ecosystem"
    );
}

#[tokio::test]
async fn a_failed_download_surfaces_an_error_and_leaves_the_mirror_intact() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/all.zip"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let (_dir, db) = open_db();
    let sync_store = AdvisoryStore::new(db.clone());
    let url = Url::parse(&format!("{}/all.zip", server.uri())).expect("valid url");
    let sync = OsvSync::new(sync_store, reqwest::Client::new(), url);

    let result = sync.sync("crates.io", normalize_name).await;
    assert!(
        result.is_err(),
        "a failed download must surface an error, not an empty success"
    );
    let store = AdvisoryStore::new(db);
    assert!(store
        .for_package("crates.io", "serde-json")
        .expect("lookup should succeed")
        .is_empty());
}

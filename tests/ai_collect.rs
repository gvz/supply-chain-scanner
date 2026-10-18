//! Integration tests for the payload collector in
//! `supply_chain_scanner::ai::collect`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use supply_chain_scanner::ai::collect::{collect, CollectedPayload, FileSize};
use supply_chain_scanner::ecosystem::install_surface::PyPiInstallSurface;

/// The install surface the collector runs with in these tests.
const PYPI: PyPiInstallSurface = PyPiInstallSurface;

/// Writes `content` to `root/rel` and creates the parent directories.
fn write_bytes(root: &Path, rel: &str, content: &[u8]) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, content).unwrap();
}

/// Writes text to `root/rel` and creates the parent directories.
fn write_file(root: &Path, rel: &str, content: &str) {
    write_bytes(root, rel, content.as_bytes());
}

/// Text of exactly `len` bytes with no suspicion signal in it.
fn plain(len: usize) -> String {
    let mut text = String::new();
    while text.len() < len {
        text.push_str("value = 0\n");
    }
    text.truncate(len);
    text
}

/// Builds a fixed mixed tree: install-surface files, plain modules of
/// different sizes, one suspicious module, one oversize module, and one
/// native library.
fn build_identical_tree(root: &Path) {
    write_file(root, "setup.py", &plain(80));
    write_file(root, "pkg/__init__.py", &plain(40));
    write_file(root, "pkg/evil.py", "exec(base64.b64decode(payload))\n");
    write_file(root, "pkg/dull.py", &plain(120));
    write_file(root, "pkg/tiny.py", &plain(30));
    write_file(root, "pkg/oversize.py", &plain(9_000));
    write_bytes(root, "pkg/_native.so", b"\x7fELF\x02\x01\x01\x00 native");
}

#[test]
fn install_surface_files_come_first_and_whole() {
    let root = tempfile::tempdir().unwrap();
    let mut expected = BTreeMap::new();
    for (rel, len) in [("setup.py", 64), ("setup.cfg", 64), ("pkg/__init__.py", 64)] {
        write_file(root.path(), rel, &plain(len));
        expected.insert(rel.to_string(), plain(len));
    }
    for index in 0..20 {
        let rel = format!("pkg/mod_{index:02}.py");
        let content = plain(64 + index);
        write_file(root.path(), &rel, &content);
        expected.insert(rel, content);
    }

    let payload = collect(root.path(), &PYPI, 100_000).unwrap();

    assert_eq!(payload.files.len(), 23);
    let head: Vec<&str> = payload
        .files
        .iter()
        .take(3)
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(head, vec!["pkg/__init__.py", "setup.cfg", "setup.py"]);
    for (index, file) in payload.files.iter().enumerate() {
        assert!(file.install_surface == (index < 3), "{}", file.path);
        assert_eq!(file.content, expected[&file.path], "{}", file.path);
    }
    assert!(payload.skipped_reviewable.is_empty());
    assert!(payload.install_surface_complete);
}

#[test]
fn a_suspicious_module_outranks_an_innocent_one() {
    let root = tempfile::tempdir().unwrap();
    let evil = "exec(base64.b64decode(payload))\n";
    write_file(root.path(), "pkg/evil.py", evil);
    write_file(root.path(), "pkg/plain.py", &plain(evil.len()));

    // The cap fits the content of exactly one of the two files.
    let payload = collect(root.path(), &PYPI, evil.len()).unwrap();

    assert_eq!(payload.files.len(), 1);
    assert_eq!(payload.files[0].path, "pkg/evil.py");
    assert_eq!(
        payload.skipped_reviewable,
        vec![FileSize {
            path: "pkg/plain.py".to_string(),
            bytes: evil.len() as u64,
        }]
    );
}

#[test]
fn files_are_sent_whole_or_not_at_all() {
    let root = tempfile::tempdir().unwrap();
    write_file(root.path(), "pkg/mod.py", &plain(10_000));

    let payload = collect(root.path(), &PYPI, 8_192).unwrap();

    assert!(payload.files.is_empty());
    assert_eq!(payload.reviewable_bytes_sent, 0);
    assert_eq!(
        payload.skipped_reviewable,
        vec![FileSize {
            path: "pkg/mod.py".to_string(),
            bytes: 10_000,
        }]
    );
}

#[test]
fn a_file_larger_than_the_whole_cap_is_skipped_without_being_read() {
    let root = tempfile::tempdir().unwrap();
    write_file(root.path(), "pkg/huge.py", &plain(2 * 1024 * 1024));

    let payload = collect(root.path(), &PYPI, 8_192).unwrap();

    assert!(payload.files.is_empty());
    assert_eq!(payload.reviewable_bytes_sent, 0);
    assert_eq!(
        payload.skipped_reviewable,
        vec![FileSize {
            path: "pkg/huge.py".to_string(),
            bytes: 2 * 1024 * 1024,
        }]
    );
}

#[test]
fn coverage_is_the_sent_fraction_of_reviewable_bytes() {
    let root = tempfile::tempdir().unwrap();
    write_file(root.path(), "pkg/a.py", &plain(1_000));
    write_file(root.path(), "pkg/b.py", &plain(1_000));

    // The cap fits the content of exactly one of the two files.
    let payload = collect(root.path(), &PYPI, 1_000).unwrap();

    assert_eq!(payload.files.len(), 1);
    assert_eq!(payload.files[0].path, "pkg/a.py");
    let coverage = payload.coverage().expect("coverage was undefined");
    assert!((coverage - 0.5).abs() < 0.01, "coverage was {coverage}");
}

#[test]
fn coverage_is_none_when_nothing_is_reviewable() {
    let root = tempfile::tempdir().unwrap();
    write_bytes(
        root.path(),
        "pkg/_speedup.so",
        b"\x7fELF\x02\x01\x01\x00 native",
    );
    write_bytes(
        root.path(),
        "docs/logo.png",
        &[0x89, b'P', b'N', b'G', 0, 1, 2, 3],
    );

    let payload = collect(root.path(), &PYPI, 100_000).unwrap();

    assert_eq!(payload.coverage(), None);
    assert_eq!(payload.reviewable_bytes_total, 0);
    assert!(payload.files.is_empty());

    // The payload still validates as the wire type.
    let json = serde_json::to_string(&payload).unwrap();
    let round: CollectedPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(round, payload);
}

#[test]
fn opaque_executables_are_listed_with_their_sizes_and_excluded_from_coverage() {
    let root = tempfile::tempdir().unwrap();
    write_file(root.path(), "pkg/mod.py", &plain(1_000));
    write_bytes(root.path(), "pkg/_speedup.so", &vec![b'x'; 5_000]);

    let payload = collect(root.path(), &PYPI, 100_000).unwrap();

    let coverage = payload.coverage().expect("coverage was undefined");
    assert!(
        (coverage - 1.0).abs() < f32::EPSILON,
        "coverage was {coverage}"
    );
    assert_eq!(payload.files.len(), 1);
    assert_eq!(
        payload.opaque_executables,
        vec![FileSize {
            path: "pkg/_speedup.so".to_string(),
            bytes: 5_000,
        }]
    );
}

#[test]
fn install_surface_complete_is_false_when_an_install_file_does_not_fit() {
    let root = tempfile::tempdir().unwrap();
    write_file(root.path(), "setup.py", &plain(20_000));
    write_file(root.path(), "pkg/mod.py", &plain(100));

    let payload = collect(root.path(), &PYPI, 8_192).unwrap();

    assert!(!payload.install_surface_complete);
    assert_eq!(
        payload.skipped_reviewable,
        vec![FileSize {
            path: "setup.py".to_string(),
            bytes: 20_000,
        }]
    );
}

#[test]
fn install_surface_complete_is_true_when_there_is_no_install_surface() {
    let root = tempfile::tempdir().unwrap();
    write_file(root.path(), "pkg/mod.py", &plain(100));
    write_file(root.path(), "pkg/other.py", &plain(100));

    let payload = collect(root.path(), &PYPI, 100_000).unwrap();

    assert!(payload.install_surface_complete);
    assert_eq!(payload.files.len(), 2);
    assert!(payload.skipped_reviewable.is_empty());
}

#[test]
fn a_non_utf8_install_surface_file_counts_against_coverage_instead_of_vanishing() {
    let root = tempfile::tempdir().unwrap();
    // A `setup.py` with a PEP 263 coding declaration and one non-UTF-8
    // byte: real, executable Python that `fs::read_to_string` cannot
    // decode. This must stay in `reviewable_bytes_total` and must mark
    // the install surface incomplete, not disappear into the opaque
    // pile and report 100% coverage over a package no one actually saw.
    write_bytes(
        root.path(),
        "setup.py",
        b"# -*- coding: latin-1 -*-\nvalue = 0\n\xe9\n",
    );
    write_file(root.path(), "pkg/__init__.py", &plain(100));

    let payload = collect(root.path(), &PYPI, 100_000).unwrap();

    assert!(
        !payload.install_surface_complete,
        "an unreadable install-surface file must not read as complete"
    );
    assert_eq!(
        payload.skipped_reviewable,
        vec![FileSize {
            path: "setup.py".to_string(),
            bytes: payload.skipped_reviewable[0].bytes,
        }]
    );
    assert!(
        payload.coverage().unwrap() < 1.0,
        "coverage must fall, not read as complete, when a reviewable file could not be decoded"
    );
    assert!(
        payload.files.iter().all(|f| f.path != "setup.py"),
        "an unreadable file must never be sent to the model as content"
    );
}

#[test]
fn a_non_utf8_ordinary_module_also_counts_against_coverage() {
    let root = tempfile::tempdir().unwrap();
    write_bytes(root.path(), "pkg/mod.py", b"value = 0\n\xe9\n");
    write_file(root.path(), "pkg/other.py", &plain(100));

    let payload = collect(root.path(), &PYPI, 100_000).unwrap();

    assert!(payload
        .skipped_reviewable
        .iter()
        .any(|f| f.path == "pkg/mod.py"));
    assert!(payload.coverage().unwrap() < 1.0);
}

#[test]
fn selection_is_deterministic_for_identical_trees() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    build_identical_tree(first.path());
    build_identical_tree(second.path());

    let a = collect(first.path(), &PYPI, 4_000).unwrap();
    let b = collect(second.path(), &PYPI, 4_000).unwrap();

    let paths_a: Vec<&str> = a.files.iter().map(|f| f.path.as_str()).collect();
    let paths_b: Vec<&str> = b.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths_a, paths_b);
    assert_eq!(a, b);
}

#[test]
fn directories_and_irregular_entries_are_walked_without_error() {
    let root = tempfile::tempdir().unwrap();
    write_file(root.path(), "pkg/mod.py", &plain(32));
    write_file(root.path(), "pkg/sub/deep.py", &plain(32));
    fs::create_dir_all(root.path().join("pkg/empty")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("mod.py", root.path().join("pkg/link.py")).unwrap();

    let payload = collect(root.path(), &PYPI, 100_000).unwrap();

    let paths: Vec<&str> = payload.files.iter().map(|f| f.path.as_str()).collect();
    assert!(paths.contains(&"pkg/mod.py"), "paths were {paths:?}");
    assert!(paths.contains(&"pkg/sub/deep.py"), "paths were {paths:?}");
    #[cfg(unix)]
    assert!(!paths.contains(&"pkg/link.py"), "paths were {paths:?}");
}

#[test]
fn the_payload_round_trips_through_json() {
    let root = tempfile::tempdir().unwrap();
    build_identical_tree(root.path());

    let payload = collect(root.path(), &PYPI, 4_000).unwrap();

    let json = serde_json::to_string(&payload).unwrap();
    let round: CollectedPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(round, payload);
}

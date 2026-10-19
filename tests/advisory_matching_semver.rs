//! Integration tests for `supply_chain_scanner::advisory::matching_semver`.
//!
//! Mirrors `tests/advisory_match.rs`, but for the SemVer matcher: the same
//! `Advisory`/`VersionRange` fixtures and the same fail-closed rules,
//! compared with `semver::Version` instead of `pep440_rs::Version`.

use supply_chain_scanner::advisory::matching_semver::affects;
use supply_chain_scanner::advisory::{Advisory, VersionRange};

/// A minimal advisory with no enumerated versions and no ranges. Tests
/// override the fields they care about with struct-update syntax.
fn advisory(id: &str) -> Advisory {
    Advisory {
        id: id.to_string(),
        package: "demo-crate".to_string(),
        summary: "a demo vulnerability".to_string(),
        severity: Some(9.0),
        versions: Vec::new(),
        ranges: Vec::new(),
        fixed_versions: Vec::new(),
    }
}

/// An advisory carrying exactly one `[introduced, fixed)` range.
fn advisory_with_range(introduced: Option<&str>, fixed: Option<&str>) -> Advisory {
    Advisory {
        ranges: vec![VersionRange {
            introduced: introduced.map(str::to_string),
            fixed: fixed.map(str::to_string),
        }],
        ..advisory("RUSTSEC-range")
    }
}

/// An advisory carrying exactly the given enumerated version list.
fn advisory_with_versions(versions: Vec<String>) -> Advisory {
    Advisory {
        versions,
        ..advisory("RUSTSEC-enumerated")
    }
}

#[test]
fn a_prerelease_sorts_below_its_final_release() {
    // semver: 2.0.0-rc.1 < 2.0.0, same ordering direction PEP 440 uses,
    // but via different parsing — this pins that the SemVer path is
    // actually exercised, not accidentally delegating to pep440_rs.
    //
    // `2.0.0-rc.1` is below the range's `fixed` bound `2.0.0`, so it is
    // still inside `[1.0.0, 2.0.0)` and must report as affected.
    let adv = advisory_with_range(Some("1.0.0"), Some("2.0.0"));
    assert!(affects(&adv, "1.5.0"));
    assert!(affects(&adv, "2.0.0-rc.1"));
}

#[test]
fn an_unparseable_version_fails_closed_against_a_range() {
    let adv = advisory_with_range(Some("1.0.0"), None);
    assert!(affects(&adv, "not-a-version"));
}

#[test]
fn an_enumerated_version_falls_back_to_a_trimmed_case_insensitive_string_compare_when_unparseable()
{
    let adv = advisory_with_versions(vec!["Weird Build".to_string()]);
    assert!(affects(&adv, "weird build"));
}

#[test]
fn exact_version_in_enumerated_list_affects() {
    let adv = advisory_with_versions(vec!["1.2.3".to_string()]);
    assert!(affects(&adv, "1.2.3"));
}

#[test]
fn version_outside_enumerated_list_does_not_affect() {
    let adv = advisory_with_versions(vec!["1.2.3".to_string()]);
    assert!(!affects(&adv, "1.2.4"));
}

#[test]
fn version_at_fixed_boundary_does_not_affect() {
    let adv = advisory_with_range(Some("1.0.0"), Some("2.0.0"));
    assert!(
        !affects(&adv, "2.0.0"),
        "the range is half-open [introduced, fixed); the version equal to fixed must not affect"
    );
    assert!(
        affects(&adv, "1.0.0"),
        "sanity: the version equal to introduced must affect"
    );
}

#[test]
fn open_ended_range_affects_everything_above_introduced() {
    let adv = advisory_with_range(Some("1.0.0"), None);
    assert!(affects(&adv, "1.0.0"));
    assert!(affects(&adv, "999.0.0"));
    assert!(!affects(&adv, "0.9.0"));
}

#[test]
fn build_metadata_does_not_change_the_comparison() {
    let adv = advisory_with_range(Some("1.0.0"), Some("2.0.0"));
    assert!(
        affects(&adv, "1.5.0+build.7"),
        "SemVer build metadata is ignored for ordering, so this is still in range"
    );
}

#[test]
fn an_unparseable_range_bound_does_not_disprove_the_match() {
    let adv = advisory_with_range(Some("not-a-version"), None);
    assert!(
        affects(&adv, "1.0.0"),
        "an unparseable introduced bound must be treated as satisfied"
    );
}

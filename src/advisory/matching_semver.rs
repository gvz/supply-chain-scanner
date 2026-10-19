//! Matching advisories against a specific crate version, with SemVer
//! semantics.
//!
//! This is a structural mirror of [`crate::advisory::matching`]: the same
//! [`affects`] semantics and the same fail-closed rules, but versions are
//! compared with [`semver::Version`] instead of `pep440_rs::Version`,
//! because crates.io versions are SemVer rather than PEP 440. The two
//! grammars overlap enough that one module could not serve both: `2.0.0-rc.1`
//! is a valid SemVer prerelease and `2.0.0rc1` is a valid PEP 440
//! prerelease, but neither parses under the other's grammar.
//!
//! Versions are compared semantically rather than lexically: `1.10 > 1.9`,
//! and a prerelease such as `2.0.0-rc.1` sorts below its final release
//! `2.0.0`. A version that fails to parse is never treated as "not
//! affected" when the advisory carries ranges — this scanner's rule is
//! that an error in a check is never a clean verdict, so an unparseable
//! version fails closed as affected instead.

use std::str::FromStr;

use semver::Version;

use crate::advisory::{Advisory, VersionRange};

/// Whether `adv` affects `version`.
///
/// Checks the enumerated `versions` list first, by SemVer equality, then
/// falls back to `ranges`. If `version` cannot be parsed as SemVer and
/// `adv` carries any ranges, the version is treated as affected: there is
/// no way to prove it falls outside every range, and failing open here
/// would let an unparseable version slip through unscanned.
///
/// An enumerated entry that itself fails to parse as SemVer falls back to
/// a raw, trimmed, case-insensitive string comparison against `version`,
/// rather than silently never matching (fail open) or, the other extreme,
/// blocking every version of the crate just because one entry in the list
/// is malformed (over-block). This only affects that one entry's
/// comparison; it never substitutes for the SemVer comparison when the
/// entry does parse.
pub fn affects(adv: &Advisory, version: &str) -> bool {
    let parsed_version = Version::from_str(version).ok();

    let in_enumerated_list =
        adv.versions
            .iter()
            .any(|enumerated| match Version::from_str(enumerated) {
                Ok(ev) => parsed_version.as_ref().is_some_and(|v| ev == *v),
                Err(_) => enumerated.trim().eq_ignore_ascii_case(version.trim()),
            });
    if in_enumerated_list {
        return true;
    }

    if adv.ranges.is_empty() {
        return false;
    }

    match &parsed_version {
        Some(v) => adv.ranges.iter().any(|range| range_affects(range, v)),
        // Fail closed: `adv` has ranges, but `version` could not be
        // parsed, so it cannot be shown to fall outside any of them.
        None => true,
    }
}

/// Whether `version` falls inside `range`'s half-open `[introduced, fixed)`
/// interval.
///
/// A bound that fails to parse is treated as satisfied rather than as
/// disproving the match: an unparseable `introduced`/`fixed` string in
/// advisory data must never be the reason a genuinely affected version
/// slips through as "not affected".
fn range_affects(range: &VersionRange, version: &Version) -> bool {
    let at_or_above_introduced = match &range.introduced {
        Some(introduced) => match Version::from_str(introduced) {
            Ok(lower) => *version >= lower,
            Err(_) => true,
        },
        None => true,
    };
    if !at_or_above_introduced {
        return false;
    }

    match &range.fixed {
        Some(fixed) => match Version::from_str(fixed) {
            Ok(upper) => *version < upper,
            Err(_) => true,
        },
        None => true,
    }
}

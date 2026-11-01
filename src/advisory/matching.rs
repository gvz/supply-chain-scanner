//! Matching advisories against a specific package version.
//!
//! Every function here is pure — an `&[Advisory]`, a version string, and a
//! [`Policy`] in; a decision out. No database and no I/O: task 10 is the
//! one that calls [`crate::db::advisory::AdvisoryStore::for_package`] and
//! hands this module the result, both on a first-time scan and, because an
//! advisory may have been filed since an artifact was scanned, on every
//! later request for an artifact already known clean. That makes
//! [`first_blocking`] some of the hottest policy code in the system, so it
//! stops at the first match rather than scanning the whole slice to find
//! "the worst" one.
//!
//! Versions are compared with PEP 440 semantics (`pep440_rs::Version`), not
//! lexically: `1.10 > 1.9`, and a prerelease such as `2.0.0rc1` sorts below
//! its final release `2.0.0`. A version that fails to parse is never
//! treated as "not affected" when the advisory carries ranges — this
//! scanner's rule is that an error in a check is never a clean verdict, so
//! an unparseable version fails closed as affected instead.

use std::str::FromStr;

use pep440_rs::Version;

use crate::advisory::{Advisory, VersionRange};
use crate::model::RefusalReason;
use crate::policy::{AdvisoryVerdictInput, Policy};

/// Whether `adv` affects `version`.
///
/// Checks the enumerated `versions` list first, by normalized PEP 440
/// equality — this is what OSV's PyPI entries almost always carry — then
/// falls back to `ranges`. If `version` cannot be parsed as PEP 440 and
/// `adv` carries any ranges, the version is treated as affected: there is
/// no way to prove it falls outside every range, and failing open here
/// would let an unparseable version slip through unscanned.
///
/// An enumerated entry that itself fails to parse as PEP 440 falls back to
/// a raw, trimmed, case-insensitive string comparison against `version`,
/// rather than silently never matching (fail open) or, the other extreme,
/// blocking every version of the package just because one entry in the
/// list is malformed (over-block). This only affects that one entry's
/// comparison; it never substitutes for the PEP 440 comparison when the
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

/// Returns the [`RefusalReason`] for the first advisory in `advs` that both
/// [`affects`] `version` and [`Policy::blocks_advisory`] under `policy`, or
/// `None` if no advisory blocks.
///
/// Returns the *first* blocking advisory in `advs`'s given order, not the
/// most severe one: the caller refuses on the first block and stops, so
/// sorting or picking "the worst" would do unnecessary work on the hottest
/// policy path in the system for no behavioral benefit.
pub fn first_blocking(advs: &[Advisory], version: &str, policy: &Policy) -> Option<RefusalReason> {
    advs.iter().find_map(|adv| {
        if !affects(adv, version) {
            return None;
        }

        let input = AdvisoryVerdictInput {
            severity: adv.severity,
            has_fix: !adv.fixed_versions.is_empty(),
        };
        if !policy.blocks_advisory(&input) {
            return None;
        }

        Some(refusal_reason(adv))
    })
}

/// Builds the [`RefusalReason`] for one blocking advisory.
///
/// `code` is `cve:<advisory-id>`. `detail` carries the advisory's summary
/// and severity, pre-sanitized to ASCII with no newlines: task 11 sanitizes
/// again before putting a form of this text into an HTTP reason phrase, but
/// this function does not rely on that downstream step to keep the value
/// safe.
fn refusal_reason(adv: &Advisory) -> RefusalReason {
    let severity = match adv.severity {
        Some(score) => format!("{score}"),
        None => "unknown".to_string(),
    };
    let summary = sanitize_detail_text(&adv.summary);

    RefusalReason {
        code: format!("cve:{}", adv.id),
        detail: format!("{summary} (severity {severity})"),
    }
}

/// The cap, in characters, on the sanitized summary portion of `detail`.
/// `adv.summary` comes from upstream OSV data with no length guarantee;
/// task 11 caps the whole HTTP reason phrase at 120 bytes, so 200
/// characters of summary is already more than that budget allows and
/// anything past it would be dead weight even before task 11's own
/// truncation. Capping here keeps `detail` itself bounded rather than
/// relying on that downstream step.
const SUMMARY_MAX_CHARS: usize = 200;

/// Strips anything that could make `text` dangerous or malformed inside an
/// HTTP reason phrase later: ASCII control characters (including CR/LF, the
/// bytes a response-splitting attack needs) and non-ASCII characters, then
/// truncates to [`SUMMARY_MAX_CHARS`]. Everything else passes through
/// unchanged.
///
/// `pub(crate)` so [`crate::scan::npm`]'s own `cve:<advisory-id>` listing
/// line can sanitize and cap an advisory summary the same way, rather than
/// writing unbounded, unsanitized OSV text into a log whose volume the
/// fetch-audit-log design already flags as a concern. There is one
/// sanitizer for this text, not a second copy drifting out of sync with
/// this one.
pub(crate) fn sanitize_detail_text(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .take(SUMMARY_MAX_CHARS)
        .collect()
}

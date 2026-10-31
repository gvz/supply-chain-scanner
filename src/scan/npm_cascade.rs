//! The npm cascade decision core: pure logic, no I/O.
//!
//! npm resolves a whole dependency tree, and every dependency carries a
//! version range. Two dependents needing different majors of the same
//! package is the ordinary state of a real `node_modules`, not an edge
//! case — so unlike [`crate::scan::cargo_cascade::plan_cascade`], which
//! forwards essentially one version per crate, this cascade can forward
//! one *passing* version per major line. A packument that carried only
//! the single newest reviewed version would make any dependent pinned to
//! an older major find nothing satisfying its range, and that failure is
//! not local — it fails the entire `npm install`, not one package.
//!
//! The decision order for one package:
//!
//! 1. Drop every entry in `cve_blocked` or `too_new` that is not in
//!    `allowlisted`. An unparseable version is dropped too: it has no
//!    major line to belong to, so — unlike
//!    `cargo_cascade::sort_newest_first`, which sorts such a version last
//!    and keeps it — it cannot be grouped and is excluded from the
//!    survivor set entirely.
//! 2. Group survivors by semver major, except npm's caret operator does
//!    not treat every version this way, so neither does this grouping:
//!    - `major > 0`: group by major. `^1.2.3` means `>=1.2.3 <2.0.0`, so
//!      every `1.x` version belongs together.
//!    - `major == 0, minor > 0`: group by minor instead. `^0.2.3` means
//!      `>=0.2.3 <0.3.0` — it spans patches within a minor but not across
//!      one — so `0.2.0` and `0.1.0` are effectively different "major"
//!      lines.
//!    - `major == 0, minor == 0`: group by patch. `^0.0.3` means
//!      `>=0.0.3 <0.0.4` — it accepts *only* `0.0.3`, nothing else — so
//!      every `0.0.x` version is its own line; grouping these by minor
//!      (i.e. all lumped into one `0.0` line) would let a newer `0.0.x`
//!      patch silently shadow an older one that some dependent's
//!      `^0.0.x` range needs and nothing else on the registry satisfies.
//! 3. A survivor is *forwardable* if an operator allowlisted it or AI
//!    review passed it. The allowlist is consulted first, the same
//!    precedence the PyPI and cargo paths give a human sign-off: it
//!    overrides both the CVE gate and the release-age gate.
//! 4. Visit major lines newest-first. Within a line, newest-first, the
//!    first survivor that is neither forwardable nor already
//!    review-failed is the review candidate — the search continues past
//!    a failed entry to an older one in the same line before moving to
//!    the next line down.
//! 5. If no line has a candidate, forward every forwardable survivor —
//!    at most the newest forwardable version per major line, newest line
//!    first. That list can be empty.
//!
//! Nothing here excludes a version for being deprecated. cargo's cascade
//! excludes `yanked` versions because cargo itself discounts them for
//! fresh resolution, but npm's `deprecated` field is not equivalent — npm
//! installs deprecated versions routinely, with only a warning, and a
//! great many widely-depended-on versions carry one. Excluding them would
//! break ordinary resolution, which is why `NpmCascadeInput` has no
//! `deprecated` field at all.
//!
//! This module never panics and never returns an error. A package with no
//! usable version yields [`NpmNextStep::Forward`] with an empty list, so
//! the caller renders it the way it renders a package that has none.

use std::collections::{HashMap, HashSet};

use semver::Version;

use crate::scan::cargo_cascade::ReviewStatus;

/// Everything [`plan_npm_cascade`] needs to decide one package's next
/// step.
pub struct NpmCascadeInput {
    /// Every published version string, in any order.
    pub versions: Vec<String>,
    /// Versions that CVE filtering removed.
    pub cve_blocked: HashSet<String>,
    /// Versions the release-age gate removed.
    pub too_new: HashSet<String>,
    /// The AI-review cache, keyed by version.
    pub review_status: HashMap<String, ReviewStatus>,
    /// Versions an operator has allowlisted for this package.
    ///
    /// Consulted before the CVE and release-age gates, the same
    /// precedence [`crate::scan::Scanner::decide_inner`] gives the
    /// allowlist on the PyPI path: a human sign-off overrides both
    /// judgement checks.
    pub allowlisted: HashSet<String>,
}

/// What the cascade wants the caller to do next.
#[derive(Debug, PartialEq)]
pub enum NpmNextStep {
    /// The final list of versions this proxy can serve, at most one per
    /// major line, newest line first. The list can be empty.
    Forward(Vec<String>),
    /// Fetch this version and run AI review on it next.
    NeedsReview(String),
}

/// A major-version grouping key, matching npm's three-tier caret
/// semantics (see the module docs, rule 2): non-zero majors group by
/// major, `0.y` (`y > 0`) lines group by minor, and `0.0.z` lines group
/// by patch — because `^0.0.z` accepts only that exact patch, so without
/// this third tier every `0.0.x` version would wrongly share one line.
///
/// Each variant's payload is always drawn directly from the matching
/// version's own major, minor, or patch field, and the three variants
/// correspond to disjoint `(major, minor)` conditions. That is what keeps
/// group ordering deterministic: two distinct keys can never describe
/// groups whose newest members compare equal under [`Version::cmp`] (see
/// [`plan_npm_cascade`]'s ordering comment for the full argument), so
/// sorting lines by their newest member is a strict total order.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum MajorLine {
    Major(u64),
    ZeroMinor(u64),
    ZeroPatch(u64),
}

fn major_line(version: &Version) -> MajorLine {
    if version.major != 0 {
        MajorLine::Major(version.major)
    } else if version.minor != 0 {
        MajorLine::ZeroMinor(version.minor)
    } else {
        MajorLine::ZeroPatch(version.patch)
    }
}

/// Decides the next cascade step for one package (see the module docs for
/// the rules).
pub fn plan_npm_cascade(input: &NpmCascadeInput) -> NpmNextStep {
    // Group survivors by major line, newest-first within each line. An
    // unparseable version has no major line to join, so it is dropped
    // here rather than kept and sorted last.
    let mut lines: HashMap<MajorLine, Vec<(Version, String)>> = HashMap::new();
    for raw in &input.versions {
        let blocked = (input.cve_blocked.contains(raw) || input.too_new.contains(raw))
            && !input.allowlisted.contains(raw);
        if blocked {
            continue;
        }
        let Ok(parsed) = Version::parse(raw) else {
            continue;
        };
        lines
            .entry(major_line(&parsed))
            .or_default()
            .push((parsed, raw.clone()));
    }

    for entries in lines.values_mut() {
        entries.sort_by(|a, b| b.0.cmp(&a.0));
    }

    // Visit major lines newest-first. Ordering by each line's own newest
    // member is deterministic even with three `MajorLine` variants in
    // play: every member of a line was *assigned* to that line because
    // its own major/minor/patch matched the key, so the line's newest
    // member always carries the key's defining field(s) verbatim. Two
    // distinct keys therefore always disagree on some field that
    // `Version::cmp` consults before any field they might share —
    // `Major(m)` vs `Major(m')` disagree on major; a `Major(m)` with
    // `m > 0` outranks every zero-major key on major alone; `ZeroMinor`
    // keys disagree on minor (and that minor is always non-zero, so it
    // can never match a `ZeroPatch` line's minor of zero); `ZeroPatch`
    // keys share major 0 and minor 0 but disagree on patch. So no two
    // distinct lines can ever produce newest-member values that compare
    // equal, which makes this sort a strict total order that never
    // depends on `HashMap` iteration order.
    let mut ordered_lines: Vec<&Vec<(Version, String)>> = lines.values().collect();
    ordered_lines.sort_by(|a, b| b[0].0.cmp(&a[0].0));

    let forwardable = |vers: &str| {
        input.allowlisted.contains(vers)
            || matches!(input.review_status.get(vers), Some(ReviewStatus::Passed))
    };
    let review_failed =
        |vers: &str| matches!(input.review_status.get(vers), Some(ReviewStatus::Failed));

    // Within a line, walk newest-first and stop at the first forwardable
    // entry — do not skip past it to an older one. A line whose newest
    // survivor already passed (or was allowlisted) has nothing left to
    // review in that line at all; only a line whose newest survivors are
    // all review-failed falls through to an older, still-unreviewed entry.
    // Without the `break`, a line of several unreviewed versions would
    // offer every one of them as a candidate in turn, one iteration (one
    // AI review and one tarball download) per version, instead of
    // stopping the moment the newest one passes.
    for entries in &ordered_lines {
        for (_, vers) in entries.iter() {
            if forwardable(vers) {
                break;
            }
            if !review_failed(vers) {
                return NpmNextStep::NeedsReview(vers.clone());
            }
            // Already review-failed: try the next-older entry in this
            // same line.
        }
    }

    let mut forwarded = Vec::new();
    for entries in &ordered_lines {
        if let Some((_, vers)) = entries.iter().find(|(_, vers)| forwardable(vers)) {
            forwarded.push(vers.clone());
        }
    }
    NpmNextStep::Forward(forwarded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(versions: &[&str]) -> NpmCascadeInput {
        NpmCascadeInput {
            versions: versions.iter().map(|v| v.to_string()).collect(),
            cve_blocked: HashSet::new(),
            too_new: HashSet::new(),
            review_status: HashMap::new(),
            allowlisted: HashSet::new(),
        }
    }

    #[test]
    fn the_newest_version_of_the_newest_major_is_the_first_candidate() {
        let input = input(&["1.0.0", "2.0.0", "0.9.0"]);
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::NeedsReview("2.0.0".to_string())
        );
    }

    #[test]
    fn a_passing_version_in_each_major_line_is_forwarded_together() {
        let input = NpmCascadeInput {
            versions: vec![
                "3.1.0".to_string(),
                "2.4.0".to_string(),
                "1.9.0".to_string(),
            ],
            cve_blocked: HashSet::new(),
            too_new: HashSet::new(),
            review_status: HashMap::from([
                ("3.1.0".to_string(), ReviewStatus::Passed),
                ("2.4.0".to_string(), ReviewStatus::Passed),
                ("1.9.0".to_string(), ReviewStatus::Passed),
            ]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::Forward(vec![
                "3.1.0".to_string(),
                "2.4.0".to_string(),
                "1.9.0".to_string(),
            ])
        );
    }

    #[test]
    fn only_the_newest_passing_version_of_a_major_line_is_forwarded() {
        let input = NpmCascadeInput {
            versions: vec!["2.4.0".to_string(), "2.3.0".to_string()],
            cve_blocked: HashSet::new(),
            too_new: HashSet::new(),
            review_status: HashMap::from([
                ("2.4.0".to_string(), ReviewStatus::Passed),
                ("2.3.0".to_string(), ReviewStatus::Passed),
            ]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::Forward(vec!["2.4.0".to_string()]),
            "a major line forwards at most its newest passing version"
        );
    }

    #[test]
    fn a_failed_newest_version_cascades_within_its_own_major_line() {
        let input = NpmCascadeInput {
            versions: vec![
                "3.2.0".to_string(),
                "3.1.0".to_string(),
                "2.9.0".to_string(),
            ],
            cve_blocked: HashSet::new(),
            too_new: HashSet::new(),
            review_status: HashMap::from([("3.2.0".to_string(), ReviewStatus::Failed)]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::NeedsReview("3.1.0".to_string()),
            "the cascade must stay within the 3.x line rather than jump to 2.x"
        );
    }

    #[test]
    fn an_exhausted_major_line_moves_to_the_next_line_down() {
        let input = NpmCascadeInput {
            versions: vec![
                "3.2.0".to_string(),
                "3.1.0".to_string(),
                "2.9.0".to_string(),
            ],
            cve_blocked: HashSet::new(),
            too_new: HashSet::new(),
            review_status: HashMap::from([
                ("3.2.0".to_string(), ReviewStatus::Failed),
                ("3.1.0".to_string(), ReviewStatus::Failed),
            ]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::NeedsReview("2.9.0".to_string()),
            "every 3.x candidate already failed, so the cascade moves to 2.x"
        );
    }

    #[test]
    fn a_cve_blocked_version_is_never_a_candidate() {
        let input = NpmCascadeInput {
            versions: vec!["1.0.0".to_string(), "0.9.0".to_string()],
            cve_blocked: HashSet::from(["1.0.0".to_string()]),
            too_new: HashSet::new(),
            review_status: HashMap::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::NeedsReview("0.9.0".to_string())
        );
    }

    #[test]
    fn a_too_new_version_is_never_a_candidate() {
        let input = NpmCascadeInput {
            versions: vec!["1.0.0".to_string(), "0.9.0".to_string()],
            cve_blocked: HashSet::new(),
            too_new: HashSet::from(["1.0.0".to_string()]),
            review_status: HashMap::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::NeedsReview("0.9.0".to_string())
        );
    }

    #[test]
    fn an_allowlisted_version_is_forwarded_despite_cve_and_age_blocks() {
        let input = NpmCascadeInput {
            versions: vec!["1.0.0".to_string()],
            cve_blocked: HashSet::from(["1.0.0".to_string()]),
            too_new: HashSet::from(["1.0.0".to_string()]),
            review_status: HashMap::new(),
            allowlisted: HashSet::from(["1.0.0".to_string()]),
        };
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::Forward(vec!["1.0.0".to_string()]),
            "an operator sign-off overrides both the CVE gate and the release-age gate"
        );
    }

    #[test]
    fn a_deprecated_version_is_still_a_candidate() {
        // NpmCascadeInput has no `deprecated` field at all: this test
        // documents that decision by showing nothing excludes such a
        // version — a plain, unreviewed version is still offered for
        // review exactly like any other.
        let input = input(&["1.0.0"]);
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::NeedsReview("1.0.0".to_string())
        );
    }

    #[test]
    fn every_version_failing_forwards_an_empty_list_rather_than_erroring() {
        let input = NpmCascadeInput {
            versions: vec!["1.0.0".to_string(), "0.9.0".to_string()],
            cve_blocked: HashSet::new(),
            too_new: HashSet::new(),
            review_status: HashMap::from([
                ("1.0.0".to_string(), ReviewStatus::Failed),
                ("0.9.0".to_string(), ReviewStatus::Failed),
            ]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(plan_npm_cascade(&input), NpmNextStep::Forward(Vec::new()));
    }

    #[test]
    fn a_zero_minor_line_is_its_own_group() {
        // 0.2.0 and 0.1.0 are different "majors" for npm's caret
        // semantics, so each gets its own forwarded slot rather than
        // being merged into one "0.x" group that would forward only the
        // newest of the two.
        let input = NpmCascadeInput {
            versions: vec!["0.2.0".to_string(), "0.1.0".to_string()],
            cve_blocked: HashSet::new(),
            too_new: HashSet::new(),
            review_status: HashMap::from([
                ("0.2.0".to_string(), ReviewStatus::Passed),
                ("0.1.0".to_string(), ReviewStatus::Passed),
            ]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::Forward(vec!["0.2.0".to_string(), "0.1.0".to_string()]),
            "0.2.0 and 0.1.0 must both be forwarded as separate minor-keyed lines"
        );
    }

    #[test]
    fn a_zero_zero_patch_line_is_its_own_group() {
        // ^0.0.3 means >=0.0.3 <0.0.4 — it accepts *only* 0.0.3. If
        // 0.0.3 and 0.0.4 shared one "0.0" line the way 0.2.x shares one
        // minor line, only 0.0.4 (the newest) would ever be forwarded,
        // and a dependent on ^0.0.3 would find nothing — the exact
        // whole-install failure this cascade exists to avoid. Grouping
        // by patch for a zero major and zero minor keeps them separate.
        let input = NpmCascadeInput {
            versions: vec!["0.0.4".to_string(), "0.0.3".to_string()],
            cve_blocked: HashSet::new(),
            too_new: HashSet::new(),
            review_status: HashMap::from([
                ("0.0.4".to_string(), ReviewStatus::Passed),
                ("0.0.3".to_string(), ReviewStatus::Passed),
            ]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::Forward(vec!["0.0.4".to_string(), "0.0.3".to_string()]),
            "0.0.3 and 0.0.4 must both be forwarded as separate patch-keyed lines"
        );
    }

    #[test]
    fn a_prerelease_version_can_be_the_review_candidate() {
        // A genuine prerelease tag (not just a low patch number) is not
        // excluded from candidacy: with no release in its line at all,
        // it is offered for review like any other unreviewed survivor.
        let input = input(&["2.0.0-beta.1"]);
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::NeedsReview("2.0.0-beta.1".to_string())
        );
    }

    #[test]
    fn a_prerelease_shares_its_release_line_and_is_tried_after_it_fails_review() {
        // 2.0.0-beta.1 and 2.0.0 share one major line (both major 2).
        // semver orders the final release above its prerelease, so once
        // 2.0.0 fails review the cascade falls through to the
        // prerelease next, within the same line, rather than reporting
        // the line exhausted.
        let input = NpmCascadeInput {
            versions: vec!["2.0.0".to_string(), "2.0.0-beta.1".to_string()],
            cve_blocked: HashSet::new(),
            too_new: HashSet::new(),
            review_status: HashMap::from([("2.0.0".to_string(), ReviewStatus::Failed)]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::NeedsReview("2.0.0-beta.1".to_string()),
            "a prerelease must share its release's major line and be tried next within it"
        );
    }

    #[test]
    fn a_prerelease_version_can_be_forwarded_when_it_passes_review() {
        // A prerelease is not barred from forwarding either: as the
        // newest (and only) forwardable survivor in its line, it is
        // forwarded exactly like a final release would be.
        let input = NpmCascadeInput {
            versions: vec!["2.0.0-beta.1".to_string()],
            cve_blocked: HashSet::new(),
            too_new: HashSet::new(),
            review_status: HashMap::from([("2.0.0-beta.1".to_string(), ReviewStatus::Passed)]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::Forward(vec!["2.0.0-beta.1".to_string()])
        );
    }

    #[test]
    fn a_line_stops_at_the_first_forwardable_entry_rather_than_skipping_past_it() {
        // Regression for I1: `find` used to scan past a forwardable entry
        // to an older, still-unreviewed one in the same line instead of
        // stopping. For a line of several unreviewed versions that meant
        // one candidate (one AI review, one tarball download) per version
        // in the line, rather than stopping the moment the newest one
        // passes.
        let input = NpmCascadeInput {
            versions: vec!["2.4.0".to_string(), "2.3.0".to_string()],
            cve_blocked: HashSet::new(),
            too_new: HashSet::new(),
            review_status: HashMap::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_npm_cascade(&input),
            NpmNextStep::NeedsReview("2.4.0".to_string()),
            "the newest unreviewed version in the line is the only candidate"
        );

        // 2.4.0 passes review. The cascade must stop at that forwardable
        // entry and never ask to review 2.3.0 too.
        let mut passed = input;
        passed
            .review_status
            .insert("2.4.0".to_string(), ReviewStatus::Passed);
        assert_eq!(
            plan_npm_cascade(&passed),
            NpmNextStep::Forward(vec!["2.4.0".to_string()]),
            "once the newest version in a line passes, the cascade must forward it \
             without ever asking to review an older version in the same line"
        );
    }

    #[test]
    fn an_unparseable_version_is_excluded_deterministically_and_never_panics() {
        let input = input(&["not-a-version", "1.x", "1.0.0", "0.9.0"]);
        for _ in 0..5 {
            assert_eq!(
                plan_npm_cascade(&input),
                NpmNextStep::NeedsReview("1.0.0".to_string()),
                "unparseable versions must be dropped, never panic, and never flip outcomes across runs"
            );
        }
    }
}

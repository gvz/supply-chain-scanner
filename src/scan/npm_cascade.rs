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
//! 2. Group survivors by semver major. `0.x` versions group by minor
//!    instead, matching npm's caret semantics: `^0.2.0` does not accept
//!    `0.3.0`, so `0.2.0` and `0.1.0` are effectively different "major"
//!    lines.
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

/// A major-version grouping key. `0.x` lines group by minor instead of
/// major, matching npm's caret semantics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum MajorLine {
    Major(u64),
    ZeroMinor(u64),
}

fn major_line(version: &Version) -> MajorLine {
    if version.major == 0 {
        MajorLine::ZeroMinor(version.minor)
    } else {
        MajorLine::Major(version.major)
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
    // member is deterministic: two distinct lines can never share the
    // same newest semver value, since that value's major (and, for a
    // zero major, its minor) is exactly what makes the lines distinct in
    // the first place — so this never depends on hash iteration order.
    let mut ordered_lines: Vec<&Vec<(Version, String)>> = lines.values().collect();
    ordered_lines.sort_by(|a, b| b[0].0.cmp(&a[0].0));

    let forwardable = |vers: &str| {
        input.allowlisted.contains(vers)
            || matches!(input.review_status.get(vers), Some(ReviewStatus::Passed))
    };
    let review_failed =
        |vers: &str| matches!(input.review_status.get(vers), Some(ReviewStatus::Failed));

    for entries in &ordered_lines {
        if let Some((_, vers)) = entries
            .iter()
            .find(|(_, vers)| !forwardable(vers) && !review_failed(vers))
        {
            return NpmNextStep::NeedsReview(vers.clone());
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
    fn a_zero_major_prerelease_line_is_its_own_group() {
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

//! The cargo cascade decision core: pure logic, no I/O.
//!
//! The cascade answers one question for one crate: which of its published
//! versions can this proxy forward, and if none can be forwarded yet,
//! which single version should go to AI review next?
//!
//! [`plan_cascade`] reads only the data its caller hands it. Task 5's
//! orchestration fetches that data and runs the review. This module stays
//! pure so every decision rule is unit-testable without a network or a
//! database.
//!
//! The decision order for one crate:
//!
//! 1. Drop every yanked entry, and every entry in `cve_blocked` that is
//!    not in `allowlisted`. A yanked version is never a candidate, even
//!    when it is the newest one, and an allowlist entry does not revive a
//!    yanked version either.
//! 2. A surviving version is *forwardable* if an operator allowlisted it,
//!    or a cargo-vet audit covers it, or AI review passed it. The
//!    allowlist comes first, matching the PyPI path's precedence: a human
//!    sign-off overrides both judgement checks.
//! 3. If every survivor is forwardable, forward them all.
//! 4. Otherwise review the newest survivor that is neither forwardable nor
//!    already review-failed.
//! 5. If every non-forwardable survivor already failed review, forward the
//!    forwardable ones and stop. That list can be empty.
//!
//! This module never panics and never returns an error. A crate with no
//! usable version yields [`NextStep::Forward`] with an empty list, so the
//! caller reports it the way it reports a crate that does not exist.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use semver::Version;

use crate::ecosystem::cargo::index::CargoIndexEntry;

/// Everything [`plan_cascade`] needs to decide one crate's next step.
pub struct CascadeInput {
    /// The crate's index entries, in any order.
    pub entries: Vec<CargoIndexEntry>,
    /// Versions that CVE filtering removed.
    pub cve_blocked: HashSet<String>,
    /// The AI-review cache, keyed by version.
    pub review_status: HashMap<String, ReviewStatus>,
    /// Versions that a qualifying cargo-vet audit covers.
    pub vet_covered: HashSet<String>,
    /// Versions an operator has allowlisted for this crate.
    ///
    /// An allowlist entry is a human sign-off, so it has the same force
    /// here that [`crate::scan::Scanner::decide_inner`] gives it on the
    /// PyPI path: it is consulted *before* any stored verdict, so it
    /// overrides a CVE block and an AI-review failure alike. The one
    /// check it never overrides is the artifact's hash, which
    /// [`crate::http::cargo_download`] still verifies against the index
    /// `cksum`.
    pub allowlisted: HashSet<String>,
}

/// The AI-review result for one version.
///
/// A version with no entry has never been reviewed.
pub enum ReviewStatus {
    Passed,
    Failed,
}

/// What the cascade wants the caller to do next.
#[derive(Debug, PartialEq)]
pub enum NextStep {
    /// The final list of versions this proxy can serve, newest first.
    /// The list can be empty.
    Forward(Vec<String>),
    /// Fetch this version and run AI review on it next.
    NeedsReview(String),
}

/// Decides the next cascade step for one crate (see the module docs for
/// the rules).
pub fn plan_cascade(input: &CascadeInput) -> NextStep {
    let mut survivors: Vec<String> = Vec::new();
    for entry in &input.entries {
        if entry.yanked {
            continue;
        }
        // The allowlist is consulted before the CVE block, matching the
        // PyPI path's precedence: an operator who allowlisted this exact
        // version has overridden every judgement check, not just the
        // reviewed ones.
        if input.cve_blocked.contains(&entry.vers) && !input.allowlisted.contains(&entry.vers) {
            continue;
        }
        if !survivors.contains(&entry.vers) {
            survivors.push(entry.vers.clone());
        }
    }
    sort_newest_first(&mut survivors);

    let forwardable = |vers: &String| {
        input.allowlisted.contains(vers)
            || input.vet_covered.contains(vers)
            || matches!(input.review_status.get(vers), Some(ReviewStatus::Passed))
    };

    if survivors.iter().all(forwardable) {
        return NextStep::Forward(survivors);
    }

    if let Some(candidate) = survivors.iter().find(|vers| {
        !forwardable(vers) && !matches!(input.review_status.get(*vers), Some(ReviewStatus::Failed))
    }) {
        return NextStep::NeedsReview(candidate.clone());
    }

    let left: Vec<String> = survivors.into_iter().filter(forwardable).collect();
    NextStep::Forward(left)
}

/// Sorts versions newest-first with `semver` ordering. A version that
/// does not parse as semver sorts last, by descending string order, so
/// the result is deterministic and never panics.
fn sort_newest_first(versions: &mut [String]) {
    versions.sort_by(|a, b| match (Version::parse(a), Version::parse(b)) {
        (Ok(left), Ok(right)) => right.cmp(&left),
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => b.cmp(a),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(vers: &str, yanked: bool) -> CargoIndexEntry {
        CargoIndexEntry {
            name: "demo".to_string(),
            vers: vers.to_string(),
            cksum: format!("cksum-{vers}"),
            yanked,
        }
    }

    #[test]
    fn with_nothing_cached_the_newest_non_yanked_cve_clean_version_needs_review() {
        let input = CascadeInput {
            entries: vec![entry("1.0.0", false), entry("0.9.0", false)],
            cve_blocked: HashSet::new(),
            review_status: HashMap::new(),
            vet_covered: HashSet::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_cascade(&input),
            NextStep::NeedsReview("1.0.0".to_string())
        );
    }

    #[test]
    fn a_cargo_vet_covered_version_is_forwarded_without_ever_needing_review() {
        let input = CascadeInput {
            entries: vec![entry("1.0.0", false), entry("0.9.0", false)],
            cve_blocked: HashSet::new(),
            review_status: HashMap::new(),
            vet_covered: HashSet::from(["1.0.0".to_string(), "0.9.0".to_string()]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_cascade(&input),
            NextStep::Forward(vec!["1.0.0".to_string(), "0.9.0".to_string()]),
            "a vet-covered version is forwardable with no AI review"
        );
    }

    #[test]
    fn a_cve_blocked_newest_version_is_skipped_in_favor_of_an_older_clean_one() {
        let input = CascadeInput {
            entries: vec![entry("1.0.0", false), entry("0.9.0", false)],
            cve_blocked: HashSet::from(["1.0.0".to_string()]),
            review_status: HashMap::new(),
            vet_covered: HashSet::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_cascade(&input),
            NextStep::NeedsReview("0.9.0".to_string())
        );
    }

    #[test]
    fn a_yanked_newest_version_is_never_selected_as_a_review_candidate() {
        let input = CascadeInput {
            entries: vec![entry("1.1.0", true), entry("1.0.0", false)],
            cve_blocked: HashSet::new(),
            review_status: HashMap::new(),
            vet_covered: HashSet::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_cascade(&input),
            NextStep::NeedsReview("1.0.0".to_string()),
            "a yanked version must never be chosen, even when it is newest and CVE-clean"
        );
    }

    #[test]
    fn a_yanked_newest_version_with_only_a_failed_older_version_forwards_nothing_forwardable() {
        let input = CascadeInput {
            entries: vec![entry("1.1.0", true), entry("1.0.0", false)],
            cve_blocked: HashSet::new(),
            review_status: HashMap::from([("1.0.0".to_string(), ReviewStatus::Failed)]),
            vet_covered: HashSet::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_cascade(&input),
            NextStep::Forward(Vec::new()),
            "the cascade must not loop back to the yanked version"
        );
    }

    #[test]
    fn after_the_newest_candidate_fails_review_the_cascade_moves_to_the_next_newest() {
        let mut review_status = HashMap::new();
        review_status.insert("1.0.0".to_string(), ReviewStatus::Failed);
        let input = CascadeInput {
            entries: vec![entry("1.0.0", false), entry("0.9.0", false)],
            cve_blocked: HashSet::new(),
            review_status,
            vet_covered: HashSet::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_cascade(&input),
            NextStep::NeedsReview("0.9.0".to_string())
        );
    }

    #[test]
    fn when_every_candidate_has_failed_review_the_forwardable_list_is_whatever_is_left_even_if_empty(
    ) {
        let input = CascadeInput {
            entries: vec![entry("1.0.0", false), entry("0.9.0", false)],
            cve_blocked: HashSet::new(),
            review_status: HashMap::from([
                ("1.0.0".to_string(), ReviewStatus::Failed),
                ("0.9.0".to_string(), ReviewStatus::Failed),
            ]),
            vet_covered: HashSet::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(plan_cascade(&input), NextStep::Forward(Vec::new()));
    }

    #[test]
    fn a_failed_candidate_leaves_the_already_passed_version_in_the_forwardable_list() {
        let input = CascadeInput {
            entries: vec![entry("1.0.0", false), entry("0.9.0", false)],
            cve_blocked: HashSet::new(),
            review_status: HashMap::from([
                ("1.0.0".to_string(), ReviewStatus::Failed),
                ("0.9.0".to_string(), ReviewStatus::Passed),
            ]),
            vet_covered: HashSet::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_cascade(&input),
            NextStep::Forward(vec!["0.9.0".to_string()]),
            "a passed version stays forwardable while a newer one has failed"
        );
    }

    #[test]
    fn a_crate_with_no_cve_clean_versions_at_all_forwards_an_empty_list_not_an_error() {
        let input = CascadeInput {
            entries: vec![entry("1.0.0", false), entry("0.9.0", false)],
            cve_blocked: HashSet::from(["1.0.0".to_string(), "0.9.0".to_string()]),
            review_status: HashMap::new(),
            vet_covered: HashSet::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(plan_cascade(&input), NextStep::Forward(Vec::new()));
    }

    #[test]
    fn a_crate_with_no_versions_at_all_forwards_an_empty_list() {
        let input = CascadeInput {
            entries: Vec::new(),
            cve_blocked: HashSet::new(),
            review_status: HashMap::new(),
            vet_covered: HashSet::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(plan_cascade(&input), NextStep::Forward(Vec::new()));
    }

    #[test]
    fn forward_output_is_sorted_newest_first_not_in_index_order() {
        let input = CascadeInput {
            entries: vec![
                entry("0.9.0", false),
                entry("0.10.0", false),
                entry("0.2.0", false),
            ],
            cve_blocked: HashSet::new(),
            review_status: HashMap::new(),
            vet_covered: HashSet::from([
                "0.9.0".to_string(),
                "0.10.0".to_string(),
                "0.2.0".to_string(),
            ]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_cascade(&input),
            NextStep::Forward(vec![
                "0.10.0".to_string(),
                "0.9.0".to_string(),
                "0.2.0".to_string(),
            ])
        );
    }

    #[test]
    fn a_prerelease_sorts_below_its_final_release() {
        let input = CascadeInput {
            entries: vec![entry("2.0.0-rc.1", false), entry("2.0.0", false)],
            cve_blocked: HashSet::new(),
            review_status: HashMap::new(),
            vet_covered: HashSet::from(["2.0.0-rc.1".to_string(), "2.0.0".to_string()]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_cascade(&input),
            NextStep::Forward(vec!["2.0.0".to_string(), "2.0.0-rc.1".to_string()]),
            "semver ordering puts a prerelease below its final release"
        );
    }

    #[test]
    fn a_version_that_is_not_semver_sorts_last_instead_of_panicking() {
        // A malformed index line must never panic the decision core, and
        // the result must be stable, so the unparseable version lands at
        // the end of the forwardable list.
        let input = CascadeInput {
            entries: vec![
                entry("not-a-version", false),
                entry("1.0.0", false),
                entry("zzz", false),
            ],
            cve_blocked: HashSet::new(),
            review_status: HashMap::new(),
            vet_covered: HashSet::from([
                "not-a-version".to_string(),
                "1.0.0".to_string(),
                "zzz".to_string(),
            ]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_cascade(&input),
            NextStep::Forward(vec![
                "1.0.0".to_string(),
                "zzz".to_string(),
                "not-a-version".to_string(),
            ]),
            "unparseable versions sort last, by descending string order, with no panic"
        );
    }

    #[test]
    fn an_unparseable_version_is_still_offered_for_review_when_it_is_the_only_candidate() {
        let input = CascadeInput {
            entries: vec![entry("not-a-version", false)],
            cve_blocked: HashSet::new(),
            review_status: HashMap::new(),
            vet_covered: HashSet::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_cascade(&input),
            NextStep::NeedsReview("not-a-version".to_string())
        );
    }

    #[test]
    fn a_duplicated_index_line_yields_one_forwarded_version_not_two() {
        let input = CascadeInput {
            entries: vec![entry("1.0.0", false), entry("1.0.0", false)],
            cve_blocked: HashSet::new(),
            review_status: HashMap::new(),
            vet_covered: HashSet::from(["1.0.0".to_string()]),
            allowlisted: HashSet::new(),
        };
        assert_eq!(
            plan_cascade(&input),
            NextStep::Forward(vec!["1.0.0".to_string()])
        );
    }

    #[test]
    fn a_duplicate_of_a_cve_blocked_version_stays_out_of_the_survivors() {
        let input = CascadeInput {
            entries: vec![entry("1.0.0", false), entry("1.0.0", false)],
            cve_blocked: HashSet::from(["1.0.0".to_string()]),
            review_status: HashMap::new(),
            vet_covered: HashSet::new(),
            allowlisted: HashSet::new(),
        };
        assert_eq!(plan_cascade(&input), NextStep::Forward(Vec::new()));
    }
}

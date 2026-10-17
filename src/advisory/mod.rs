//! The local mirror of OSV security advisories: what this task downloads,
//! parses, and stores, and what task 7 will match against a specific
//! package version.
//!
//! [`osv`] does the parsing (one OSV JSON document becomes one [`Advisory`]
//! per affected package) and the periodic sync from the upstream OSV feed.
//! Storage lives in [`crate::db::advisory`], alongside every other store,
//! so this module stays about the advisory *data* rather than how it is
//! persisted.

pub mod matching;
pub mod osv;

/// One advisory as it applies to a single affected package: everything
/// [`crate::db::advisory::AdvisoryStore`] persists and task 7's
/// version-matching logic needs to decide whether it blocks a specific
/// version.
///
/// `versions` is OSV's `affected[].versions` enumeration and `ranges` is
/// `affected[].ranges` collapsed to `(introduced, fixed)` pairs — both
/// stored exactly as OSV gave them, uninterpreted; task 7 does the PEP 440
/// comparison. `severity` is `None` whenever OSV gave no severity or gave
/// one this crate could not parse — never a sentinel number — so
/// [`crate::policy::Policy::blocks_advisory`]'s explicit unknown-severity
/// rule governs it instead of a value that would compare false against
/// every threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct Advisory {
    pub id: String,
    pub package: String,
    pub summary: String,
    pub severity: Option<f32>,
    pub versions: Vec<String>,
    pub ranges: Vec<VersionRange>,
    pub fixed_versions: Vec<String>,
}

/// One `(introduced, fixed)` pair taken from an OSV affected range, stored
/// exactly as given — no version comparison happens here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRange {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

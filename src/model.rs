//! Core domain types shared across the scanner: the identity of a scanned
//! artifact and the verdict recorded for it.

/// Identifies one scanned artifact file.
///
/// Verdicts are stored per artifact, not per version: a wheel and an sdist
/// for the same version have different contents and are scanned and
/// verdicted independently.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactKey {
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub filename: String,
    pub sha256: String,
}

/// Why an artifact was blocked.
///
/// `code` is a short, machine-readable identifier (e.g. `"cve:high"`,
/// `"plugin:yara"`, `"hash-mismatch"`); `detail` is a human-readable
/// explanation intended for the `/why/<id>` page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalReason {
    pub code: String,
    pub detail: String,
}

/// The outcome of scanning one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Blocked(RefusalReason),
}

//! The org's policy: a plugin-aware fingerprint identifying exactly which
//! rules produced a scan verdict, an allowlist override, and the CVE
//! severity line.
//!
//! [`Policy::build`] reads every configured plugin binary from disk to
//! fold its contents into the fingerprint, so it fails when a binary is
//! missing or unreadable. That is deliberate fail-closed behavior at
//! startup: the proxy must refuse to boot under a broken plugin list
//! rather than silently scan with fewer checks than the org configured.
//!
//! The allowlist is deliberately excluded from the fingerprint. It is an
//! override applied at request time, not an input that changes what a
//! scan examines, so adding an allowlist entry must never invalidate
//! verdicts already stored under the current policy. The same reasoning
//! excludes `bind` and `cache_ttl`: they are operational knobs, not scan
//! inputs.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use sha2::{Digest, Sha256};

use crate::config::{Config, CveLine, UnknownSeverity};
use crate::ecosystem::pypi::index::normalize_name;

/// Separates each hashed field so that, e.g., a plugin named `"ab"` with
/// binary hash `"cd..."` can never hash identically to a plugin named
/// `"a"` with binary hash `"bcd..."`.
const FIELD_SEP: &[u8] = &[0u8];

/// Computes the policy fingerprint for `cfg`: a lowercase hex SHA-256
/// digest over the serialized [`CveLine`], then — in config list order —
/// each plugin's name and the SHA-256 of its binary's current file
/// contents.
///
/// Reorder-sensitive by construction: swapping two plugins' positions in
/// `cfg.plugins` changes the byte sequence fed to the hasher even though
/// the set of plugins is unchanged.
pub fn policy_fingerprint(cfg: &Config) -> anyhow::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(serialize_cve_line(&cfg.cve).as_bytes());

    for plugin in &cfg.plugins {
        hasher.update(FIELD_SEP);
        hasher.update(plugin.name.as_bytes());
        hasher.update(FIELD_SEP);

        let binary_hash = hash_file(&plugin.binary).with_context(|| {
            format!(
                "hashing plugin {:?} binary at {}",
                plugin.name,
                plugin.binary.display()
            )
        })?;
        hasher.update(binary_hash.as_bytes());
    }

    Ok(hex::encode(hasher.finalize()))
}

/// A deterministic, field-order-stable text representation of a
/// [`CveLine`], sufficient to hash (every field is covered by `Debug` and
/// the field order is fixed by the struct's declaration) but not intended
/// for display.
fn serialize_cve_line(cve: &CveLine) -> String {
    format!("{cve:?}")
}

/// Reads `path` in full and returns the lowercase hex SHA-256 of its
/// contents.
fn hash_file(path: &Path) -> anyhow::Result<String> {
    let contents =
        std::fs::read(path).with_context(|| format!("reading plugin binary {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&contents);
    Ok(hex::encode(hasher.finalize()))
}

/// The organization's compiled rules for one running configuration: a
/// fingerprint identifying which rules produced a verdict, an allowlist
/// override, and the CVE severity line.
///
/// Built from `Arc<Config>` and kept immutable: a config reload produces a
/// brand new `Policy` rather than mutating this one in place, so an
/// in-flight scan always finishes under the policy it started with.
pub struct Policy {
    cfg: Arc<Config>,
    fingerprint: String,
}

impl Policy {
    /// Builds a `Policy` from `cfg`, computing and storing its fingerprint
    /// up front. Reads every configured plugin binary from disk to do so
    /// (see the module docs for why a missing binary is an error here).
    pub fn build(cfg: Arc<Config>) -> anyhow::Result<Policy> {
        let fingerprint = policy_fingerprint(&cfg)?;
        Ok(Policy { cfg, fingerprint })
    }

    /// The policy fingerprint stored alongside every verdict scanned under
    /// this policy.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Whether `package`@`version` is explicitly allowlisted by the org,
    /// overriding any stored verdict. Package names are compared after PEP
    /// 503 normalization, so `Flask_X` in config matches a request for
    /// `flask-x`; versions are compared verbatim.
    pub fn allows(&self, package: &str, version: &str) -> bool {
        let normalized = normalize_name(package);
        self.cfg
            .allowlist
            .iter()
            .any(|entry| normalize_name(&entry.package) == normalized && entry.version == version)
    }

    /// Whether a matched advisory blocks the artifact under the org's CVE
    /// line.
    ///
    /// An advisory with known severity blocks when that severity is at or
    /// above `min_severity`. An advisory with unknown severity (`None`)
    /// blocks only if `unknown_severity` is `Block`; it defaults to
    /// `Allow`, since treating unknown severity as blocking would refuse a
    /// large share of ordinary packages on day one. Either way, if
    /// `require_fix_available` is set, an advisory with no known fix never
    /// blocks, regardless of severity.
    pub fn blocks_advisory(&self, m: &AdvisoryVerdictInput) -> bool {
        let cve = &self.cfg.cve;

        let severity_blocks = match m.severity {
            Some(severity) => severity >= cve.min_severity,
            None => cve.unknown_severity == UnknownSeverity::Block,
        };
        if !severity_blocks {
            return false;
        }

        if cve.require_fix_available && !m.has_fix {
            return false;
        }

        true
    }
}

/// What's known about one advisory matched against a scanned artifact, as
/// handed to [`Policy::blocks_advisory`].
///
/// Task 7 builds this from an `Advisory`'s `severity: Option<f32>` and
/// `fixed_versions: Vec<String>` (`has_fix = !fixed_versions.is_empty()`).
pub struct AdvisoryVerdictInput {
    pub severity: Option<f32>,
    pub has_fix: bool,
}

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
//! verdicts already stored under the current policy. `[cargo_registry]`'s
//! `trusted_reviewers` is excluded for the same reason: it narrows who is
//! trusted, not what is checked. The same reasoning excludes `bind` and
//! `cache_ttl`: they are operational knobs, not scan inputs. The one
//! implementation of that request-time override is
//! [`crate::scan::is_allowlisted`], which reads the live config snapshot;
//! this module deliberately offers no second copy of that comparison.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use sha2::{Digest, Sha256};

use crate::ai::collect;
use crate::ai::prompt;
use crate::config::{Config, CveLine, UnknownSeverity};

/// Separates each hashed field so that, e.g., a plugin named `"ab"` with
/// binary hash `"cd..."` can never hash identically to a plugin named
/// `"a"` with binary hash `"bcd..."`.
const FIELD_SEP: &[u8] = &[0u8];

/// Computes the policy fingerprint for `cfg`: a lowercase hex SHA-256
/// digest over the serialized [`CveLine`], then, when set,
/// `min_release_age_days` (the gate changes what a scan admits, so
/// tightening or loosening it must invalidate stored verdicts the same
/// way editing `cve` does), then — in config list order —
/// each plugin's name and the SHA-256 of its binary's current file
/// contents, then, when `[ai_review]` is present, the reviewer's
/// identity (see below).
///
/// Reorder-sensitive by construction: swapping two plugins' positions in
/// `cfg.plugins` changes the byte sequence fed to the hasher even though
/// the set of plugins is unchanged.
///
/// The reviewer contributes the model, the prompt version, the collector
/// version, the coverage threshold, `block_on` and
/// `block_opaque_executables`: everything that changes which checks a
/// review runs or how it blocks. `base_url` and `api_key_env` stay out:
/// they are operational knobs, like `bind`, and moving a deployment to a
/// different provider host must not invalidate every stored verdict.
///
/// A config with no `[ai_review]` table appends nothing at all, so an
/// unconfigured deployment produces a byte-identical digest to the same
/// config on a binary built before the reviewer existed. Upgrading this
/// proxy never invalidates a stored verdict by the mere presence of the
/// new code.
///
/// A config with `[cargo_registry]` set appends, in order: the marker
/// `cargo_registry`, the required cargo-vet criterion, then — in config
/// list order — each cargo-vet source's name and URL. The criterion and
/// the source list decide what a cargo deployment accepts as proof that a
/// version is safe, so both change what gets checked. `trusted_reviewers`
/// stays out for the same reason the allowlist does: narrowing or
/// widening who is trusted is an operational judgment call applied at
/// request time, not a change to what is examined, so editing that list
/// must never invalidate a verdict already stored. A config with no
/// `[cargo_registry]` table appends nothing, by the same reasoning as
/// `[ai_review]` above.
pub fn policy_fingerprint(cfg: &Config) -> anyhow::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(serialize_cve_line(&cfg.cve).as_bytes());

    if let Some(days) = cfg.min_release_age_days {
        hasher.update(FIELD_SEP);
        hasher.update(b"min_release_age_days");
        hasher.update(FIELD_SEP);
        hasher.update(days.to_string().as_bytes());
    }

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

    if let Some(ai) = cfg.ai_review.as_ref() {
        hasher.update(FIELD_SEP);
        hasher.update(b"ai_review");
        hasher.update(FIELD_SEP);
        hasher.update(ai.model.as_bytes());
        hasher.update(FIELD_SEP);
        hasher.update(prompt::PROMPT_VERSION.as_bytes());
        hasher.update(FIELD_SEP);
        hasher.update(collect::COLLECTOR_VERSION.as_bytes());
        hasher.update(FIELD_SEP);
        // `{}` renders every `f32` bit pattern, including integral values
        // as `1` rather than `1.0`, and unlike `{:?}` it cannot be
        // confused with a numeric string that carries different bytes.
        // Two thresholds with different bits never serialize alike here
        // because the whole float is printed.
        hasher.update(format!("{}", ai.coverage_threshold).as_bytes());
        hasher.update(FIELD_SEP);
        hasher.update(match ai.block_on {
            crate::config::BlockOn::Malicious => b"malicious".as_slice(),
            crate::config::BlockOn::Suspicious => b"suspicious".as_slice(),
        });
        hasher.update(FIELD_SEP);
        hasher.update(if ai.block_opaque_executables {
            b"true".as_slice()
        } else {
            b"false".as_slice()
        });
    }

    if let Some(registry) = cfg.cargo_registry.as_ref() {
        hasher.update(FIELD_SEP);
        hasher.update(b"cargo_registry");
        hasher.update(FIELD_SEP);
        hasher.update(registry.required_criterion.as_bytes());

        if let Some(days) = registry.min_release_age_days {
            hasher.update(FIELD_SEP);
            hasher.update(b"min_release_age_days");
            hasher.update(FIELD_SEP);
            hasher.update(days.to_string().as_bytes());
        }

        // `trusted_reviewers` is deliberately absent: see this function's
        // doc comment.
        for source in &registry.cargo_vet_sources {
            hasher.update(FIELD_SEP);
            hasher.update(source.name.as_bytes());
            hasher.update(FIELD_SEP);
            hasher.update(source.url.as_str().as_bytes());
        }
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
/// Built from `Arc<Config>` and kept immutable: a config reload builds a
/// brand new `Policy` and swaps it in behind
/// [`crate::scan::Scanner`]'s `ArcSwap` rather than mutating this one in
/// place. [`crate::scan::Scanner::decide`] loads one snapshot at its entry
/// point and uses it for the whole decision, so an in-flight scan always
/// finishes under the policy it started with *and* a reload is not inert.
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

    /// The PyPI deployment's minimum release age, in days. `None` means
    /// the gate is off. See [`Config::min_release_age_days`]'s doc
    /// comment for the cargo deployment's independent equivalent.
    pub fn min_release_age_days(&self) -> Option<u64> {
        self.cfg.min_release_age_days
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

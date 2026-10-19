//! The `audits.toml` parser. It turns one cargo-vet audit set, as published
//! by a trusted source, into a flat list of [`AuditEntry`] values.
//!
//! This module is pure. It does no I/O, so tests call it directly against
//! fixture TOML. Only *full* audits are actionable in this plan. A full
//! audit names a `version` directly. The parser builds [`AuditEntry::Delta`]
//! for delta audits so it does not silently drop them. Nothing downstream
//! treats a delta entry as sufficient on its own, because walking a delta
//! chain back to a full audit is out of scope. A crate that only a delta
//! chain covers therefore falls through to AI review, the same way a crate
//! with no audit does.

use anyhow::Context;
use serde::Deserialize;

/// One parsed audit from an `audits.toml` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEntry {
    /// A full audit. The auditor `who` reviewed the named `version` against
    /// `criteria`. Only this form can satisfy a coverage query.
    Full {
        package: String,
        version: String,
        who: Vec<String>,
        criteria: Vec<String>,
        source: String,
    },
    /// A delta audit. The auditor reviewed the step from `from` to `to`.
    /// The parser keeps it so the file's contents are not silently lost.
    /// The store never persists it, and it is never sufficient for
    /// coverage on its own.
    Delta {
        package: String,
        from: String,
        to: String,
        who: Vec<String>,
        criteria: Vec<String>,
        source: String,
    },
}

/// Either a single TOML string or an array of strings.
///
/// cargo-vet's own format allows both forms for `who` and `criteria`. The
/// parser must accept both forms and normalize each one to `Vec<String>`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum StringOrVec {
    One(String),
    Many(Vec<String>),
}

impl StringOrVec {
    fn into_vec(self) -> Vec<String> {
        match self {
            StringOrVec::One(one) => vec![one],
            StringOrVec::Many(many) => many,
        }
    }
}

/// The top-level shape of an `audits.toml` file. `audits` is a map from
/// crate name to that crate's list of audits. The `[[audits.<crate>]]`
/// tables in the file produce exactly that map.
#[derive(Debug, Deserialize)]
struct AuditsToml {
    #[serde(default)]
    audits: std::collections::BTreeMap<String, Vec<RawAudit>>,
}

#[derive(Debug, Deserialize)]
struct RawAudit {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    delta: Option<String>,
    #[serde(default)]
    who: Option<StringOrVec>,
    #[serde(default)]
    criteria: Option<StringOrVec>,
}

/// Parses one `audits.toml` document into its entries. It tags every entry
/// with `source`, the configured name of the audit set that holds it.
///
/// A file that is not valid TOML is an error. A file whose shape does not
/// match [`AuditsToml`] is an error too, never a silently partial result.
/// An entry that names neither `version` nor `delta` is also an error. Such
/// an entry is neither form this parser can act on, and skipping it would
/// hide a format change.
pub fn parse_audits_toml(toml: &str, source: &str) -> anyhow::Result<Vec<AuditEntry>> {
    let parsed: AuditsToml = toml::from_str(toml).context("parsing audits.toml")?;

    let mut entries = Vec::new();
    for (package, audits) in parsed.audits {
        for audit in audits {
            let who = audit.who.map(StringOrVec::into_vec).unwrap_or_default();
            let criteria = audit
                .criteria
                .map(StringOrVec::into_vec)
                .unwrap_or_default();

            let entry = match (audit.version, audit.delta) {
                (Some(version), _) => AuditEntry::Full {
                    package: package.clone(),
                    version,
                    who,
                    criteria,
                    source: source.to_string(),
                },
                (None, Some(delta)) => {
                    let (from, to) = parse_delta(&delta).with_context(|| {
                        format!("parsing delta {delta:?} for package {package:?}")
                    })?;
                    AuditEntry::Delta {
                        package: package.clone(),
                        from,
                        to,
                        who,
                        criteria,
                        source: source.to_string(),
                    }
                }
                (None, None) => anyhow::bail!(
                    "audit for package {package:?} in source {source:?} names neither a version nor a delta"
                ),
            };
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Splits cargo-vet's `"<from> -> <to>"` delta notation into its two
/// versions. Each half must be non-empty, and anything else is an error.
fn parse_delta(delta: &str) -> anyhow::Result<(String, String)> {
    let (from, to) = delta
        .split_once("->")
        .with_context(|| format!("delta {delta:?} has no `->` separator"))?;
    let from = from.trim();
    let to = to.trim();
    if from.is_empty() || to.is_empty() {
        anyhow::bail!("delta {delta:?} has an empty version on one side");
    }
    Ok((from.to_string(), to.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{parse_audits_toml, AuditEntry};

    #[test]
    fn a_delta_without_a_separator_is_an_error() {
        let toml = r#"
[[audits.demo-crate]]
delta = "1.2.3"
who = "Jane Auditor <jane@example.com>"
criteria = "safe-to-deploy"
"#;
        assert!(parse_audits_toml(toml, "mozilla").is_err());
    }

    #[test]
    fn an_entry_with_neither_version_nor_delta_is_an_error() {
        let toml = r#"
[[audits.demo-crate]]
who = "Jane Auditor <jane@example.com>"
criteria = "safe-to-deploy"
"#;
        assert!(parse_audits_toml(toml, "mozilla").is_err());
    }

    #[test]
    fn an_empty_file_parses_to_no_entries() {
        let entries = parse_audits_toml("", "mozilla").expect("parse empty file");
        assert!(entries.is_empty());
        assert_eq!(
            entries
                .iter()
                .filter(|e| matches!(e, AuditEntry::Full { .. }))
                .count(),
            0
        );
    }
}

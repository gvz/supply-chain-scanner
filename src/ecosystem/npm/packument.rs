//! Parsing, digest selection, and filtering for npm packuments.
//!
//! This module is pure. It has no I/O, no network, and no database. A
//! packument is the single JSON document the npm registry serves for one
//! package: it lists every published version under `versions`, points
//! `dist-tags` (such as `latest`) at specific versions, and records
//! publish timestamps under `time`.
//!
//! The proxy fetches a packument, decides which versions pass its gates,
//! and must serve back a document that forwards only the survivors — npm
//! itself resolves installs from whatever this proxy returns, so a
//! version removed here can never be installed, however it got filtered.
//!
//! [`parse_packument`] keeps the original parsed JSON in
//! [`Packument::raw`]. Upstream packuments carry fields this module does
//! not model (`readme`, `maintainers`, `users`, and more), and npm's
//! client may depend on some of them. [`filter_packument`] edits a clone
//! of that raw document rather than reconstructing one from the typed
//! fields, so anything this module does not know about survives the
//! round trip untouched.

use std::collections::{BTreeMap, HashSet};

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use semver::Version;
use serde::Deserialize;
use serde_json::Value;

use super::tarball_path;

/// One package's full registry metadata document.
#[derive(Debug, Clone)]
pub struct Packument {
    pub name: String,
    pub versions: BTreeMap<String, PackumentVersion>,
    pub dist_tags: BTreeMap<String, String>,
    pub time: BTreeMap<String, DateTime<Utc>>,
    /// The parsed document exactly as upstream sent it. [`filter_packument`]
    /// edits a clone of this rather than rebuilding a document from the
    /// typed fields above, so fields this struct does not model still
    /// reach npm for any version that survives filtering.
    pub raw: Value,
}

/// One published version's metadata, as declared in `versions.<version>`.
///
/// Only the fields this proxy acts on are declared here. Serde ignores
/// unknown fields, so an upstream addition does not break this parser —
/// see [`Packument::raw`] for how those fields still reach npm.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PackumentVersion {
    pub version: String,
    pub dist: Dist,
    #[serde(default)]
    pub deprecated: Option<String>,
    #[serde(default)]
    pub scripts: BTreeMap<String, String>,
}

/// The `dist` object of one published version: where its tarball lives
/// and the digests upstream declared for it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Dist {
    pub tarball: String,
    #[serde(default)]
    pub integrity: Option<String>,
    #[serde(default)]
    pub shasum: Option<String>,
}

/// The digest algorithm a [`DeclaredDigest`] was computed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha1,
    Sha512,
}

/// The digest this proxy will verify a downloaded tarball against,
/// selected from a [`Dist`] by [`declared_digest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredDigest {
    pub algorithm: DigestAlgorithm,
    /// Lowercase hex, regardless of whether it came from `integrity`
    /// (base64-decoded) or `shasum` (already hex, merely lowercased).
    pub hex: String,
}

/// The typed subset of a packument's top-level fields, deserialized
/// separately from [`Packument::raw`] so [`parse_packument`] can keep
/// both the typed view and the original document.
#[derive(Debug, Deserialize)]
struct PackumentFields {
    name: String,
    #[serde(default)]
    versions: BTreeMap<String, PackumentVersion>,
    #[serde(rename = "dist-tags", default)]
    dist_tags: BTreeMap<String, String>,
    #[serde(default)]
    time: BTreeMap<String, DateTime<Utc>>,
}

/// Parses a packument's JSON body.
///
/// Returns an error if the body is not valid JSON, or if it does not
/// have at least a `name`. A missing `versions`, `dist-tags`, or `time`
/// is not an error: each defaults to empty, which upstream's own
/// abbreviated-metadata responses sometimes do (no `time` map) and a
/// brand-new or fully-unpublished package always does (no `versions`).
///
/// This never drops versions silently: if upstream's `versions` entries
/// do not match this module's [`PackumentVersion`] shape, parsing fails
/// outright rather than producing a document with some versions quietly
/// missing, which would look identical to this proxy's own gate having
/// removed them.
pub fn parse_packument(body: &str) -> Result<Packument> {
    let raw: Value = serde_json::from_str(body).context("parsing npm packument JSON")?;
    let fields: PackumentFields =
        serde_json::from_value(raw.clone()).context("parsing npm packument fields")?;
    Ok(Packument {
        name: fields.name,
        versions: fields.versions,
        dist_tags: fields.dist_tags,
        time: fields.time,
        raw,
    })
}

/// Selects the digest this proxy should verify a tarball against,
/// preferring `dist.integrity` over `dist.shasum`.
///
/// `integrity` is a Subresource Integrity string (`sha512-<base64>`, or
/// occasionally `sha1-<base64>`). `shasum` is a plain hex SHA-1.
///
/// When `integrity` is present but its algorithm prefix is neither
/// `sha1-` nor `sha512-` (for example `sha384-`), its base64 payload
/// does not decode, or the decoded payload is not that algorithm's
/// exact digest length (20 bytes for SHA-1, 64 for SHA-512), this
/// returns `None` — even when a usable `shasum` is also present.
/// Falling back to `shasum` in that case would silently verify the
/// tarball against a weaker digest than the one upstream actually
/// declared, which is worse than refusing outright.
pub fn declared_digest(dist: &Dist) -> Option<DeclaredDigest> {
    if let Some(integrity) = &dist.integrity {
        let (algorithm, encoded) = if let Some(rest) = integrity.strip_prefix("sha512-") {
            (DigestAlgorithm::Sha512, rest)
        } else if let Some(rest) = integrity.strip_prefix("sha1-") {
            (DigestAlgorithm::Sha1, rest)
        } else {
            // An algorithm this proxy cannot (or should not) verify
            // against. Never fall back to `shasum` here: that would be a
            // silent downgrade from whatever upstream actually declared.
            return None;
        };
        let bytes = BASE64.decode(encoded).ok()?;
        let expected_len = match algorithm {
            DigestAlgorithm::Sha1 => 20,
            DigestAlgorithm::Sha512 => 64,
        };
        if bytes.len() != expected_len {
            // Valid base64 that decodes to the wrong length (a truncated
            // or otherwise corrupted integrity string) is just as
            // unverifiable as an unknown algorithm. Catch it here, at the
            // layer that knows which algorithm was declared, rather than
            // letting a downstream hash comparison fail for an unrelated
            // reason.
            return None;
        }
        return Some(DeclaredDigest {
            algorithm,
            hex: hex::encode(bytes),
        });
    }

    let shasum = dist.shasum.as_ref()?;
    Some(DeclaredDigest {
        algorithm: DigestAlgorithm::Sha1,
        hex: shasum.to_lowercase(),
    })
}

/// Returns the semver-newest of `versions`, or `None` if it is empty.
///
/// A version that fails to parse as semver sorts below every version
/// that does, so a malformed survivor is never preferred over a valid
/// one — mirrors `sort_newest_first` in
/// [`crate::scan::cargo_cascade`].
fn semver_newest(versions: &[String]) -> Option<String> {
    versions
        .iter()
        .max_by(|a, b| match (Version::parse(a), Version::parse(b)) {
            (Ok(left), Ok(right)) => left.cmp(&right),
            (Ok(_), Err(_)) => std::cmp::Ordering::Greater,
            (Err(_), Ok(_)) => std::cmp::Ordering::Less,
            (Err(_), Err(_)) => a.cmp(b),
        })
        .cloned()
}

/// Builds the packument this proxy serves back to npm: only `keep`'s
/// versions survive, each survivor's tarball points at this proxy
/// instead of upstream, and `dist-tags` is rebuilt to never dangle.
///
/// This edits a clone of `source.raw` (see [`Packument::raw`]) rather
/// than reconstructing a document from the typed fields, so any upstream
/// field this module does not model (on a surviving version, including
/// `deprecated`) passes through untouched.
///
/// `dist-tags` rules:
/// - a tag whose target survived is kept unchanged;
/// - `latest`, if its original target did not survive, is repointed to
///   the semver-newest survivor (or dropped if there are no survivors
///   at all);
/// - any other tag whose target did not survive is dropped.
///
/// With no survivors, this still returns a well-formed document with
/// empty `versions` and empty `dist-tags` — never an error. A upstream
/// document with no `versions` object at all (for example a bare
/// `{"name":"x"}`) is treated exactly like one with zero survivors.
pub fn filter_packument(source: &Packument, keep: &[String], public_base: &str) -> Value {
    let mut doc = source.raw.clone();
    let obj = doc
        .as_object_mut()
        .expect("a packument produced by parse_packument is always a JSON object");

    let keep_set: HashSet<&str> = keep.iter().map(String::as_str).collect();

    let mut survivors: Vec<String> = Vec::new();
    let versions_slot = obj
        .entry("versions".to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));

    // `parse_packument`'s all-or-nothing deserialization guarantees that
    // any `Packument` it produced has a `raw["versions"]` that is a JSON
    // object whose every entry has a JSON object `dist`. `Packument`'s
    // fields are all `pub`, so nothing stops a caller outside this module
    // from constructing one with a `raw` that violates that — and if that
    // ever happens, failing loudly here is the only acceptable response.
    // Silently treating "not an object" as "zero versions" would drop
    // versions exactly the way this proxy's own gate does, making a bug
    // indistinguishable from a refusal; silently skipping a tarball
    // rewrite would be worse, forwarding a survivor whose `dist.tarball`
    // still points at the real upstream registry instead of this proxy.
    let versions_map = versions_slot
        .as_object_mut()
        .expect("invariant violated: Packument.raw[\"versions\"] must be a JSON object");
    versions_map.retain(|version, _| keep_set.contains(version.as_str()));
    for (version, entry) in versions_map.iter_mut() {
        survivors.push(version.clone());
        let dist = entry.get_mut("dist").and_then(Value::as_object_mut).expect(
            "invariant violated: every Packument.raw[\"versions\"] entry must have an object \"dist\"",
        );
        let tarball_url = format!("{public_base}/{}", tarball_path(&source.name, version));
        dist.insert("tarball".to_string(), Value::String(tarball_url));
    }

    let newest_survivor = semver_newest(&survivors);
    let mut new_dist_tags = serde_json::Map::new();
    for (tag, target) in &source.dist_tags {
        if survivors.contains(target) {
            new_dist_tags.insert(tag.clone(), Value::String(target.clone()));
        } else if tag == "latest" {
            if let Some(newest) = &newest_survivor {
                new_dist_tags.insert(tag.clone(), Value::String(newest.clone()));
            }
            // No survivors at all: drop `latest` rather than point it
            // at nothing.
        }
        // Any other tag whose target did not survive is dropped.
    }
    obj.insert("dist-tags".to_string(), Value::Object(new_dist_tags));

    doc
}

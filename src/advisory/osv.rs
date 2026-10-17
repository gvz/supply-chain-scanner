//! OSV document parsing, CVSS scoring, and the periodic sync that mirrors
//! the OSV PyPI advisory feed into the local database.
//!
//! [`parse_osv`] and [`severity_score`] are pure — no I/O — so they can be
//! unit-tested directly against fixture JSON. [`OsvSync`] is the only part
//! of this module that touches the network: it downloads the upstream
//! `all.zip`, parses every entry, and only then calls
//! [`crate::db::advisory::AdvisoryStore::replace_all`], so a download
//! failure or a single malformed document never reaches the store and
//! never disturbs the advisories already on disk — parsing happens
//! entirely in memory before anything is written.

use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context};
use futures_util::StreamExt;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use url::Url;

use super::{Advisory, VersionRange};
use crate::db::advisory::AdvisoryStore;
use crate::ecosystem::pypi::index::normalize_name;

/// The ecosystem name OSV-mirrored PyPI advisories are stored under,
/// matching what [`crate::db::advisory::AdvisoryStore`] keys rows by.
const PYPI_ECOSYSTEM: &str = "pypi";

/// One raw OSV vulnerability document, as published at
/// `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip` (one
/// JSON document per zip entry). Only the fields this scanner uses are
/// modeled; unrecognized fields are ignored by `serde`'s default
/// deserialization behavior.
#[derive(Debug, Deserialize)]
struct OsvDoc {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    name: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
}

/// Parses one OSV JSON document into one [`Advisory`] per entry in its
/// `affected` array (one advisory can name several affected packages,
/// e.g. across a project's sibling distributions).
///
/// Severity is computed once for the whole document — OSV's `severity`
/// array is document-level, not per affected package — and shared by
/// every advisory produced from it: the highest score among `severity[]`
/// that [`severity_score`] can parse, or `None` if the array is empty or
/// every entry is unparseable.
pub fn parse_osv(json: &str) -> anyhow::Result<Vec<Advisory>> {
    let doc: OsvDoc = serde_json::from_str(json).context("parsing OSV JSON document")?;
    let severity = highest_severity(&doc.severity);

    let advisories = doc
        .affected
        .iter()
        .map(|affected| {
            let ranges: Vec<VersionRange> = affected
                .ranges
                .iter()
                .flat_map(|range| ranges_from_events(&range.events))
                .collect();
            let fixed_versions: Vec<String> =
                ranges.iter().filter_map(|r| r.fixed.clone()).collect();

            Advisory {
                id: doc.id.clone(),
                package: normalize_name(&affected.package.name),
                summary: doc.summary.clone(),
                severity,
                versions: affected.versions.clone(),
                ranges,
                fixed_versions,
            }
        })
        .collect();

    Ok(advisories)
}

/// The highest score among `entries` that [`severity_score`] can parse, or
/// `None` if none can be (including an empty list) — never a default
/// number standing in for "unknown."
fn highest_severity(entries: &[OsvSeverity]) -> Option<f32> {
    entries
        .iter()
        .filter_map(|entry| severity_score(&entry.score))
        .fold(None, |best, score| match best {
            Some(current) if current >= score => Some(current),
            _ => Some(score),
        })
}

/// Collapses one OSV range's event list into `(introduced, fixed)` pairs,
/// stored exactly as given. OSV's event list is a flat sequence (e.g.
/// `[{introduced: "0"}, {fixed: "1.2.3"}]`, possibly repeated for several
/// sub-ranges): an `introduced` event starts a new pending range, and a
/// `fixed` event closes whichever range is open, or stands alone if none
/// is. `last_affected`/`limit` events are not modeled — this task stores
/// only `introduced`/`fixed`, per its scope.
fn ranges_from_events(events: &[OsvEvent]) -> Vec<VersionRange> {
    let mut ranges = Vec::new();
    let mut open: Option<VersionRange> = None;

    for event in events {
        if let Some(introduced) = &event.introduced {
            if let Some(range) = open.take() {
                ranges.push(range);
            }
            open = Some(VersionRange {
                introduced: Some(introduced.clone()),
                fixed: None,
            });
        }
        if let Some(fixed) = &event.fixed {
            match open.take() {
                Some(mut range) => {
                    range.fixed = Some(fixed.clone());
                    ranges.push(range);
                }
                None => ranges.push(VersionRange {
                    introduced: None,
                    fixed: Some(fixed.clone()),
                }),
            }
        }
    }

    if let Some(range) = open.take() {
        ranges.push(range);
    }

    ranges
}

/// Scores a CVSS v2, v3, or v4 vector string, or accepts a bare numeric
/// string as-is (some OSV sources report a raw database-specific score
/// instead of a vector). Returns `None` — never `0.0`, never `NaN` — for
/// anything that parses as neither, so a garbage or missing severity reads
/// as "unknown" to the policy engine rather than as a score that would
/// compare false against every threshold.
pub fn severity_score(vector_or_score: &str) -> Option<f32> {
    let trimmed = vector_or_score.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(score) = trimmed.parse::<f32>() {
        return score.is_finite().then_some(score);
    }

    trimmed
        .parse::<cvss::Cvss>()
        .ok()
        .map(|vector| vector.score() as f32)
        .filter(|score| score.is_finite())
}

/// Downloads the OSV PyPI advisory feed and refreshes the local mirror.
///
/// Built from an [`AdvisoryStore`] and an HTTP client (task 4's
/// rustls-backed `reqwest::Client`, reused here rather than standing up a
/// second HTTP stack) pointed at a source URL — normally
/// `Config::advisory_source_url`, overridden to a wiremock server in this
/// module's own tests.
pub struct OsvSync {
    store: AdvisoryStore,
    http: reqwest::Client,
    source_url: Url,
}

impl OsvSync {
    pub fn new(store: AdvisoryStore, http: reqwest::Client, source_url: Url) -> Self {
        Self {
            store,
            http,
            source_url,
        }
    }

    /// Downloads `source_url` (OSV's PyPI `all.zip`), parses every entry,
    /// and atomically replaces the `"pypi"` ecosystem's advisories with
    /// the freshly parsed set.
    ///
    /// Download and parsing happen entirely before
    /// [`AdvisoryStore::replace_all`] is called: a network failure, a
    /// corrupt zip, or one unparseable document aborts here and returns
    /// `Err` without ever touching the store, so the previous mirror is
    /// left exactly as it was.
    pub async fn sync_pypi(&self) -> anyhow::Result<usize> {
        let download = download_to_temp_file(&self.http, &self.source_url)
            .await
            .context("downloading OSV advisory feed")?;

        let advisories = parse_zip_advisories(download.path())
            .context("parsing downloaded OSV advisory feed")?;

        self.store
            .replace_all(PYPI_ECOSYSTEM, &advisories)
            .context("replacing the PyPI advisory mirror")
    }
}

/// Downloads `url`'s body in full, streaming it into a fresh temp file,
/// and returns the handle (the file is removed automatically when it is
/// dropped). Any non-success status or I/O error during the stream is an
/// error; nothing is returned for a partial download.
async fn download_to_temp_file(
    http: &reqwest::Client,
    url: &Url,
) -> anyhow::Result<tempfile::NamedTempFile> {
    let response = http
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("requesting advisory feed from {url}"))?;

    if !response.status().is_success() {
        bail!(
            "advisory feed request to {url} returned status {}",
            response.status()
        );
    }

    let temp = tempfile::NamedTempFile::new().context("creating temp file for advisory feed")?;
    let mut file = tokio::fs::File::create(temp.path())
        .await
        .with_context(|| format!("opening temp file {} for writing", temp.path().display()))?;

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading advisory feed response chunk")?;
        file.write_all(&chunk)
            .await
            .context("writing advisory feed chunk to temp file")?;
    }
    file.flush()
        .await
        .context("flushing advisory feed temp file")?;

    Ok(temp)
}

/// Reads every entry of the zip at `path` as a UTF-8 OSV JSON document and
/// parses it with [`parse_osv`], collecting every advisory produced. A zip
/// that fails to open, or any entry that fails to read or parse, is an
/// error — never a silently partial result.
fn parse_zip_advisories(path: &Path) -> anyhow::Result<Vec<Advisory>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening downloaded advisory feed at {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("reading advisory feed as a zip")?;

    let mut advisories = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("reading zip entry {index}"))?;
        if entry.is_dir() {
            continue;
        }
        let name = entry
            .name()
            .with_context(|| format!("reading file name of zip entry {index}"))?
            .into_owned();

        let mut contents = String::new();
        entry
            .read_to_string(&mut contents)
            .with_context(|| format!("reading contents of zip entry {name:?}"))?;

        let parsed = parse_osv(&contents)
            .with_context(|| format!("parsing OSV document in zip entry {name:?}"))?;
        advisories.extend(parsed);
    }

    Ok(advisories)
}

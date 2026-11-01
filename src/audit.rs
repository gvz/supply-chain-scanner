//! The fetch audit log: a fail-closed, JSON Lines record of which client IP
//! fetched which package version, and which *evaluated* versions were
//! withheld from which client and why.
//!
//! See `docs/superpowers/specs/2026-11-01-fetch-audit-log-design.md` for the
//! full design. The two decisions that shape everything in this module:
//!
//! **This is not a `tracing` layer.** `tracing`'s macros (`info!`, `warn!`,
//! ...) return `()`: a subscriber can drop, buffer, or fail to write an
//! event and the call site never finds out. The design's non-negotiable is
//! that an un-logged fetch must never happen — if the record can't be
//! written, the request has to fail with a 500 instead of serving package
//! bytes. That requires a call that returns a `Result` a handler can act on,
//! which a `tracing` subscriber cannot give. So [`AuditLog`] is a plain
//! fallible component: [`AuditLog::write`] returns `anyhow::Result<()>`,
//! and nothing here is wired into the `tracing` subscriber graph.
//!
//! **The non-blocking appender is not used either**, for the same reason
//! one layer down: `tracing_appender::non_blocking` hands writes to a
//! bounded channel and a background worker thread, and is documented to
//! *drop* events rather than block when that channel is full or the
//! worker has gone away. A dropped record is exactly the "silent hole"
//! the design calls out — the log would look healthy while quietly
//! missing fetches. [`AuditLog::write`] instead writes and flushes
//! synchronously, on the calling thread, under a lock, so a failure is
//! visible to the caller at the point of the fetch it describes.
//!
//! **Rotation is hand-rolled, not `tracing-appender`.** Task 2's brief asked
//! for `tracing-appender`'s blocking `RollingFileAppender` to be evaluated
//! for three properties: daily/hourly rotation, a `max_log_files` bound, and
//! an `io::Write` that returns errors rather than swallowing them. Reading
//! `tracing-appender` 0.2.5's `src/rolling.rs`: the first two hold
//! (`Rotation::{DAILY,HOURLY}`, `Builder::max_log_files`), but the third
//! does not. Its `write()` rolls over by calling `Inner::refresh_writer`,
//! which on a failure to open the new period's file (permission denied,
//! disk full, ...) does `eprintln!("Couldn't create writer for logs: {}",
//! err)` and keeps writing into the *previous* period's file handle — the
//! `io::Write::write` call that follows then reports success. That is
//! worse than a swallowed error: it is a record silently misattributed to
//! the wrong file while the caller is told nothing went wrong, which is
//! precisely the kind of quiet gap fail-closed exists to prevent. So this
//! module does not depend on `tracing-appender` at all; [`RotatingFile`]
//! below is a small hand-rolled replacement, built directly on
//! `std::fs::OpenOptions::append`, whose `write()` returns any `io::Error`
//! it hits while rolling over instead of falling back to a stale file.

use std::fs;
use std::io::{self, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, Context};
use chrono::Utc;
use rand::Rng as _;
use serde::Serialize;

use crate::config::{AuditConfig, AuditRotation};
use crate::model::RefusalReason;

/// RFC 3339, UTC, millisecond precision — the `ts` field on every record.
fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// 16 lowercase hex characters from 8 random bytes — enough entropy that
/// two concurrent requests never collide in practice, short enough to grep
/// comfortably in a shipped log.
fn generate_request_id() -> String {
    let mut bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The closed set of lines this log ever writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditEvent {
    Listing,
    Listed,
    Served,
    Refused,
}

/// Whether one evaluated version was let through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allowed,
    Denied,
}

/// One line of the audit log.
///
/// Always present: `ts`, `event`, `ecosystem`, `client_ip`, `client_port`,
/// `request_id`, `package`. Every other field is only ever set by one of
/// the four constructors below, matching the event it belongs to, and is
/// omitted from the JSON entirely (not written as `null`) when absent.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    pub ts: String,
    pub event: AuditEvent,
    pub ecosystem: String,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub request_id: String,
    pub package: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions_upstream: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions_evaluated: Option<usize>,
}

impl AuditRecord {
    fn blank(ctx: &AuditContext, event: AuditEvent, package: &str) -> Self {
        Self {
            ts: now_rfc3339(),
            event,
            ecosystem: ctx.ecosystem.clone(),
            client_ip: ctx.client_ip,
            client_port: ctx.client_port,
            request_id: ctx.request_id.clone(),
            package: package.to_string(),
            version: None,
            filename: None,
            sha256: None,
            decision: None,
            reason_code: None,
            reason_detail: None,
            why_id: None,
            versions_upstream: None,
            versions_evaluated: None,
        }
    }

    /// One line per listing request, written before that request's
    /// `listed` lines.
    pub fn listing(
        ctx: &AuditContext,
        package: &str,
        versions_upstream: usize,
        versions_evaluated: usize,
    ) -> Self {
        Self {
            versions_upstream: Some(versions_upstream),
            versions_evaluated: Some(versions_evaluated),
            ..Self::blank(ctx, AuditEvent::Listing, package)
        }
    }

    /// One line per evaluated version in a listing response.
    pub fn listed(ctx: &AuditContext, package: &str, decision: &VersionDecision) -> Self {
        Self {
            version: Some(decision.version.clone()),
            filename: decision.filename.clone(),
            decision: Some(if decision.allowed {
                Decision::Allowed
            } else {
                Decision::Denied
            }),
            reason_code: decision.reason_code.clone(),
            reason_detail: decision.reason_detail.clone(),
            why_id: decision.why_id.clone(),
            ..Self::blank(ctx, AuditEvent::Listed, package)
        }
    }

    /// A download that delivered bytes.
    pub fn served(
        ctx: &AuditContext,
        package: &str,
        version: &str,
        filename: &str,
        sha256: &str,
    ) -> Self {
        Self {
            version: Some(version.to_string()),
            filename: Some(filename.to_string()),
            sha256: Some(sha256.to_string()),
            ..Self::blank(ctx, AuditEvent::Served, package)
        }
    }

    /// A download that got a refusal response.
    pub fn refused(
        ctx: &AuditContext,
        package: &str,
        version: &str,
        filename: Option<&str>,
        reason: &RefusalReason,
        why_id: Option<&str>,
    ) -> Self {
        Self {
            version: Some(version.to_string()),
            filename: filename.map(str::to_string),
            reason_code: Some(reason.code.clone()),
            reason_detail: Some(reason.detail.clone()),
            why_id: why_id.map(str::to_string),
            ..Self::blank(ctx, AuditEvent::Refused, package)
        }
    }
}

/// Per-request identity, built once per HTTP request and threaded through
/// to every audit record that request produces.
pub struct AuditContext {
    pub ecosystem: String,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub request_id: String,
}

impl AuditContext {
    /// `request_id` is freshly generated: 16 lowercase hex characters.
    pub fn new(ecosystem: &str, client: SocketAddr) -> Self {
        Self {
            ecosystem: ecosystem.to_string(),
            client_ip: client.ip(),
            client_port: client.port(),
            request_id: generate_request_id(),
        }
    }
}

/// One decision about one evaluated version. `filename` is `Some` only
/// where the ecosystem decides per file (PyPI), `None` for cargo and npm,
/// which decide per version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionDecision {
    pub version: String,
    pub filename: Option<String>,
    pub allowed: bool,
    pub reason_code: Option<String>,
    pub reason_detail: Option<String>,
    pub why_id: Option<String>,
}

/// Everything one listing response needs to report: how many versions
/// upstream carried, and the cascade's decision for each one it actually
/// evaluated. Versions the cascade never looked at (see the module-level
/// design doc for why most of a packument is never evaluated) are not
/// represented here at all.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListingAudit {
    pub versions_upstream: usize,
    pub decisions: Vec<VersionDecision>,
}

impl ListingAudit {
    /// How many versions the cascade evaluated — i.e. how many of
    /// `versions_upstream` have a line in `decisions`.
    pub fn versions_evaluated(&self) -> usize {
        self.decisions.len()
    }

    /// The `listing` line for this response, followed by one `listed` line
    /// per evaluated version, in the order they were decided.
    pub fn records(&self, ctx: &AuditContext, package: &str) -> Vec<AuditRecord> {
        let mut records = Vec::with_capacity(1 + self.decisions.len());
        records.push(AuditRecord::listing(
            ctx,
            package,
            self.versions_upstream,
            self.versions_evaluated(),
        ));
        records.extend(
            self.decisions
                .iter()
                .map(|decision| AuditRecord::listed(ctx, package, decision)),
        );
        records
    }
}

/// Splits a configured audit path (a filename *prefix*; see
/// [`AuditConfig::path`]) into the directory it lives in and the prefix
/// itself, defaulting an empty directory component to the current
/// directory so a bare `"audit.jsonl"` behaves the way a relative path
/// normally does.
fn directory_and_prefix(path: &Path) -> anyhow::Result<(PathBuf, String)> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let prefix = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("audit path {} has no file name", path.display()))?
        .to_string();
    Ok((directory, prefix))
}

/// The date-suffixed name a rotating audit file has at a given instant,
/// e.g. `audit.jsonl.2026-11-01` (daily) or `audit.jsonl.2026-11-01-14`
/// (hourly).
fn rotated_path(
    directory: &Path,
    prefix: &str,
    rotation: AuditRotation,
    now: chrono::DateTime<Utc>,
) -> PathBuf {
    let suffix = match rotation {
        AuditRotation::Daily => now.format("%Y-%m-%d").to_string(),
        AuditRotation::Hourly => now.format("%Y-%m-%d-%H").to_string(),
    };
    directory.join(format!("{prefix}.{suffix}"))
}

/// A `std::io::Write` over a `std::fs::File` that rolls over to a new
/// dated file as the configured period advances, pruning the oldest files
/// past `max_files` on each rotation.
///
/// Every fallible step — opening the new period's file, flushing and
/// swapping in the old one — returns its `io::Error` straight out of
/// `write()` rather than falling back silently, which is the property
/// `tracing_appender::rolling::RollingFileAppender` does not have (see the
/// module docs above). Pruning old files is best-effort: a failure to
/// delete a stale file does not stop the record that triggered rotation
/// from being written, since that record already landed safely in the new
/// file by the time pruning runs.
struct RotatingFile {
    directory: PathBuf,
    prefix: String,
    rotation: AuditRotation,
    max_files: usize,
    current_path: PathBuf,
    file: fs::File,
}

impl RotatingFile {
    fn open(config: &AuditConfig) -> anyhow::Result<Self> {
        let (directory, prefix) = directory_and_prefix(&config.path)?;
        fs::create_dir_all(&directory).with_context(|| {
            format!(
                "failed to create the directory for audit log {}",
                config.path.display()
            )
        })?;

        let current_path = rotated_path(&directory, &prefix, config.rotation, Utc::now());
        let file = open_append(&current_path)
            .with_context(|| format!("failed to open audit log at {}", config.path.display()))?;

        let rotating = Self {
            directory,
            prefix,
            rotation: config.rotation,
            max_files: config.max_files,
            current_path,
            file,
        };
        rotating.prune_old_files();
        Ok(rotating)
    }

    /// Deletes the oldest sibling audit files past `max_files`, keeping
    /// the current one. File names of the same rotation granularity sort
    /// lexicographically in chronological order (the date suffix is
    /// zero-padded, most-significant component first), so a plain name
    /// sort is enough to find the oldest ones.
    fn prune_old_files(&self) {
        if self.max_files == 0 {
            return;
        }
        let Ok(entries) = fs::read_dir(&self.directory) else {
            return;
        };
        let dotted_prefix = format!("{}.", self.prefix);
        let mut siblings: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&dotted_prefix))
            })
            .collect();
        siblings.sort();

        if siblings.len() <= self.max_files {
            return;
        }
        for stale in &siblings[..siblings.len() - self.max_files] {
            if let Err(err) = fs::remove_file(stale) {
                tracing::warn!(path = %stale.display(), %err, "failed to prune old audit log file");
            }
        }
    }
}

impl io::Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let wanted_path = rotated_path(&self.directory, &self.prefix, self.rotation, Utc::now());
        if wanted_path != self.current_path {
            let mut new_file = open_append(&wanted_path)?;
            self.file.flush()?;
            std::mem::swap(&mut self.file, &mut new_file);
            self.current_path = wanted_path;
            self.prune_old_files();
        }
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn open_append(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new().create(true).append(true).open(path)
}

/// The audit log's write side: one fallible, lockable `Write` behind a
/// uniform interface, whether that's a real rotating file
/// ([`AuditLog::open`]) or an arbitrary writer a test wants to probe
/// ([`AuditLog::with_writer`]).
pub struct AuditLog {
    inner: Mutex<Box<dyn io::Write + Send>>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog").finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Opens the configured audit log, creating parent directories as
    /// needed, and proves the sink writable by actually opening today's
    /// (or this hour's) file. Any failure's error text names the
    /// configured path.
    pub fn open(config: &AuditConfig) -> anyhow::Result<Self> {
        let rotating = RotatingFile::open(config)?;
        Ok(Self::with_writer(rotating))
    }

    /// For tests: wraps any writer, including one that always errors.
    pub fn with_writer<W: io::Write + Send + 'static>(writer: W) -> Self {
        Self {
            inner: Mutex::new(Box::new(writer)),
        }
    }

    /// Serializes each record as one JSON line, under a single lock held
    /// for the whole slice, and flushes once at the end. Any error —
    /// serialization, the write itself, the flush, or a poisoned lock
    /// from an earlier panic — is returned, never swallowed.
    pub fn write(&self, records: &[AuditRecord]) -> anyhow::Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| anyhow!("audit log lock was poisoned by an earlier panic"))?;

        for record in records {
            serde_json::to_writer(&mut *guard, record)
                .context("failed to serialize an audit record")?;
            guard
                .write_all(b"\n")
                .context("failed to write an audit record")?;
        }
        guard.flush().context("failed to flush the audit log")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `directory_and_prefix` must not be fooled by a bare filename with
    /// no directory component into trying to create an empty directory.
    #[test]
    fn a_bare_filename_prefix_resolves_to_the_current_directory() {
        let (directory, prefix) = directory_and_prefix(Path::new("audit.jsonl")).expect("resolves");
        assert_eq!(directory, PathBuf::from("."));
        assert_eq!(prefix, "audit.jsonl");
    }

    #[test]
    fn an_empty_path_has_no_file_name_and_is_rejected() {
        directory_and_prefix(Path::new("")).expect_err("empty path has no file name");
    }

    /// Guards against a future edit accidentally reordering the
    /// struct-update shorthand in `blank`'s callers in a way that leaves
    /// `event` wrong for its own constructor.
    #[test]
    fn each_constructor_stamps_its_own_event() {
        let ctx = AuditContext::new("pypi", "127.0.0.1:1".parse().unwrap());
        assert_eq!(
            AuditRecord::listing(&ctx, "p", 1, 1).event,
            AuditEvent::Listing
        );
        let decision = VersionDecision {
            version: "1.0.0".to_string(),
            filename: None,
            allowed: true,
            reason_code: None,
            reason_detail: None,
            why_id: None,
        };
        assert_eq!(
            AuditRecord::listed(&ctx, "p", &decision).event,
            AuditEvent::Listed
        );
        assert_eq!(
            AuditRecord::served(&ctx, "p", "1.0.0", "f", "sha").event,
            AuditEvent::Served
        );
        let reason = RefusalReason {
            code: "c".to_string(),
            detail: "d".to_string(),
        };
        assert_eq!(
            AuditRecord::refused(&ctx, "p", "1.0.0", None, &reason, None).event,
            AuditEvent::Refused
        );
    }
}

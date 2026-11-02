//! The fetch audit log: a fail-closed, JSON Lines record of which client IP
//! fetched which package version, and which *evaluated* versions were
//! withheld from which client and why.
//!
//! See `docs/superpowers/specs/2026-11-01-fetch-audit-log-design.md` for the
//! full design. The decisions that shape everything in this module:
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
//! `std::fs::OpenOptions::append`, whose rotation returns any `io::Error`
//! it hits instead of falling back to a stale file.
//!
//! **The rotation decision is made once per record, never once per token
//! the JSON serializer happens to flush.** `serde_json::to_writer` drives
//! a formatter that issues many small `write_all` calls per object — one
//! for `{`, one per field name, one per value, and so on. A rotation
//! check living inside a plain `io::Write::write` would be re-evaluated on
//! every one of those calls, and could swap the underlying file *midway
//! through serializing a single record* if the clock happened to cross a
//! period boundary in between — splitting one record's bytes across two
//! files, neither half parsing, with [`AuditLog::write`] still returning
//! `Ok`. [`AuditLog::write`] avoids this by never streaming
//! `serde_json::to_writer` straight into the locked writer: it serializes
//! each record into a reused in-memory buffer first, appends the trailing
//! `\n`, and hands the writer exactly one complete `<record>\n` buffer via
//! a single `write_all` call. [`RotatingFile`] overrides `write_all`
//! (rather than inheriting `Write`'s default implementation, which loops
//! over `write`) specifically so that override is the only place the
//! clock gets consulted — once per call, which this discipline makes once
//! per record.
//!
//! **Pruning never touches the live file, and a vanished live file gets
//! recreated.** [`RotatingFile::prune_old_files`] only ever considers a
//! regular file named `"<prefix>.<suffix>"` whose `<suffix>` actually
//! parses under the configured rotation — not a `.bak`, a `.gz`, a
//! directory, or another deployment's differently-shaped log sharing the
//! same prefix on disk — and it explicitly skips the file currently open
//! no matter where it sorts (name order tracks chronological order only
//! while the rotation granularity stays fixed; a reconfigured granularity
//! or a clock stepping backward can break that). Separately, every write
//! also checks whether the current file still exists on disk at all: an
//! operator, `logrotate`, or a bug unlinking it would otherwise leave
//! writes succeeding silently into a doomed, directory-entry-less inode
//! (POSIX keeps it alive only until the descriptor closes) — so a missing
//! file is treated exactly like a rotation and reopened before the write
//! proceeds.

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
#[derive(Debug, Clone)]
pub struct AuditContext {
    pub ecosystem: String,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub request_id: String,
}

impl AuditContext {
    /// `request_id` is freshly generated: 16 lowercase hex characters.
    ///
    /// `client_ip` is canonicalized (`to_canonical`) rather than recorded
    /// verbatim: a dual-stack bind (e.g. `[::]:8080`, a plausible choice
    /// for an org-wide deployment) delivers IPv4 peers to this process as
    /// IPv4-mapped IPv6 addresses. Left unnormalized, the audit file would
    /// read `::ffff:10.1.2.3` for a machine the security team's own
    /// inventory knows as `10.1.2.3` — the one query this log exists to
    /// answer, "who fetched this", would silently miss it. Genuine IPv6
    /// addresses pass through unchanged.
    pub fn new(ecosystem: &str, client: SocketAddr) -> Self {
        Self {
            ecosystem: ecosystem.to_string(),
            client_ip: client.ip().to_canonical(),
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
    directory.join(format!("{prefix}.{}", date_suffix(rotation, now)))
}

fn date_suffix(rotation: AuditRotation, now: chrono::DateTime<Utc>) -> String {
    match rotation {
        AuditRotation::Daily => now.format("%Y-%m-%d").to_string(),
        AuditRotation::Hourly => now.format("%Y-%m-%d-%H").to_string(),
    }
}

/// Whether `suffix` (the part of a sibling file's name after
/// `"<prefix>."`) is a well-formed date suffix this writer could actually
/// have produced under `rotation` — as opposed to a `.bak`, a `.gz`, an
/// operator's manual copy, or another deployment's differently-shaped log
/// sharing the same prefix on disk. Only files that pass this are ever
/// candidates for [`RotatingFile::prune_old_files`].
fn suffix_is_valid(rotation: AuditRotation, suffix: &str) -> bool {
    match rotation {
        AuditRotation::Daily => chrono::NaiveDate::parse_from_str(suffix, "%Y-%m-%d").is_ok(),
        AuditRotation::Hourly => match suffix.rsplit_once('-') {
            Some((date_part, hour_part)) => {
                chrono::NaiveDate::parse_from_str(date_part, "%Y-%m-%d").is_ok()
                    && hour_part.len() == 2
                    && hour_part.chars().all(|c| c.is_ascii_digit())
                    && hour_part.parse::<u32>().is_ok_and(|hour| hour < 24)
            }
            None => false,
        },
    }
}

fn open_append(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new().create(true).append(true).open(path)
}

/// An injectable source of "now", so [`RotatingFile`]'s own tests can
/// simulate crossing a rotation boundary (or a clock stepping backward)
/// without sleeping across a real one. Production code only ever uses
/// [`RotatingFile::open`], which wires up `Utc::now`.
type ClockFn = Box<dyn Fn() -> chrono::DateTime<Utc> + Send>;

/// A `std::io::Write` over a `std::fs::File` that rolls over to a new
/// dated file as the configured period advances, recreates that file if
/// it vanishes underneath the writer, and prunes the oldest files past
/// `max_files` on each rotation. See the module docs above for why each
/// of these matters and what went wrong before each was true.
///
/// Every fallible step — opening the new period's file, flushing the old
/// one before the swap — returns its `io::Error` straight out of the call
/// rather than falling back silently, which is the property
/// `tracing_appender::rolling::RollingFileAppender` does not have. That
/// property only holds if the rotation decision itself happens at most
/// once per logical write, which is why `write_all` is overridden below
/// rather than left to `Write`'s default implementation (which loops over
/// `write` once per internal token a caller happens to flush).
struct RotatingFile {
    directory: PathBuf,
    prefix: String,
    rotation: AuditRotation,
    max_files: usize,
    current_path: PathBuf,
    file: fs::File,
    now: ClockFn,
}

impl RotatingFile {
    fn open(config: &AuditConfig) -> anyhow::Result<Self> {
        Self::open_with_clock(config, Box::new(Utc::now))
    }

    /// Same as [`RotatingFile::open`], but with an injectable clock. Only
    /// this module's own tests call this directly.
    fn open_with_clock(config: &AuditConfig, now: ClockFn) -> anyhow::Result<Self> {
        let (directory, prefix) = directory_and_prefix(&config.path)?;
        fs::create_dir_all(&directory).with_context(|| {
            format!(
                "failed to create the directory for audit log {}",
                config.path.display()
            )
        })?;

        let current_path = rotated_path(&directory, &prefix, config.rotation, now());
        let file = open_append(&current_path)
            .with_context(|| format!("failed to open audit log at {}", config.path.display()))?;

        let rotating = Self {
            directory,
            prefix,
            rotation: config.rotation,
            max_files: config.max_files,
            current_path,
            file,
            now,
        };
        rotating.prune_old_files();
        Ok(rotating)
    }

    /// Rotates to the current period's file if the clock has moved past
    /// it, or if the file this writer was using has vanished underneath
    /// it (an operator, `logrotate`, or a bug removed it). Either way the
    /// next write must land somewhere a reader can actually find it, not
    /// invisibly into an orphaned inode. The existence check runs on
    /// every call, not just when the computed path changes, so a deleted
    /// file is caught even mid-period.
    fn rotate_if_needed(&mut self) -> io::Result<()> {
        let wanted_path = rotated_path(&self.directory, &self.prefix, self.rotation, (self.now)());
        let current_is_missing = fs::metadata(&self.current_path).is_err();
        if wanted_path != self.current_path || current_is_missing {
            let mut new_file = open_append(&wanted_path)?;
            self.file.flush()?;
            std::mem::swap(&mut self.file, &mut new_file);
            self.current_path = wanted_path;
            self.prune_old_files();
        }
        Ok(())
    }

    /// Deletes the oldest sibling audit files past `max_files`, among
    /// only the files this writer could itself have produced: a regular
    /// file directly inside the configured directory, named
    /// `"<prefix>.<date-suffix>"` where the suffix actually parses under
    /// the configured rotation (see [`suffix_is_valid`]). That excludes
    /// an ops-side `.bak`/`.gz` copy, another deployment's differently
    /// prefixed log, and any directory — none of those are ours to
    /// delete, and matching on the prefix alone would otherwise let any
    /// of them consume a slot in `max_files` and crowd out real audit
    /// history.
    ///
    /// The file currently open (`self.current_path`) is never deleted,
    /// regardless of where it sorts: name order tracks chronological
    /// order only while the rotation granularity stays the same, so a
    /// reconfigured granularity (or a clock that stepped backward) can
    /// put a leftover ahead of the live file in sorted order. Skipping it
    /// explicitly, rather than relying on it to sort last, is what keeps
    /// that true under either kind of surprise — at the cost of
    /// `max_files` being a best-effort cap rather than a hard one in that
    /// pathological case: the live file is always kept even if that means
    /// one file over the configured limit until it ages out naturally.
    fn prune_old_files(&self) {
        if self.max_files == 0 {
            return;
        }
        let Ok(entries) = fs::read_dir(&self.directory) else {
            return;
        };
        let dotted_prefix = format!("{}.", self.prefix);
        let rotation = self.rotation;
        let mut siblings: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_file()))
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_prefix(&dotted_prefix))
                    .is_some_and(|suffix| suffix_is_valid(rotation, suffix))
            })
            .collect();
        siblings.sort();

        if siblings.len() <= self.max_files {
            return;
        }
        for stale in &siblings[..siblings.len() - self.max_files] {
            if *stale == self.current_path {
                continue;
            }
            if let Err(err) = fs::remove_file(stale) {
                tracing::warn!(path = %stale.display(), %err, "failed to prune old audit log file");
            }
        }
    }
}

impl io::Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.rotate_if_needed()?;
        self.file.write(buf)
    }

    /// Overridden (rather than inheriting `Write`'s default, which loops
    /// over `write`) so that one call is exactly one rotation decision.
    /// [`AuditLog::write`] relies on this: it hands over one
    /// fully-assembled `<record>\n` buffer per record in a single
    /// `write_all` call, so the clock is consulted once per record, never
    /// once per token the JSON serializer happens to flush.
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.rotate_if_needed()?;
        self.file.write_all(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
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

    /// Serializes each record into a reused buffer first, under a single
    /// lock held for the whole slice, and hands the writer one complete
    /// `<record>\n` buffer per record via a single `write_all` call —
    /// never `serde_json::to_writer` streamed straight into the locked
    /// writer, which is what let a rotation decision land mid-record (see
    /// the module docs). Flushes once at the end. Any error —
    /// serialization, the write itself, the flush, or a poisoned lock
    /// from an earlier panic — is returned, never swallowed.
    pub fn write(&self, records: &[AuditRecord]) -> anyhow::Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| anyhow!("audit log lock was poisoned by an earlier panic"))?;

        let mut line = Vec::new();
        for record in records {
            line.clear();
            serde_json::to_writer(&mut line, record)
                .context("failed to serialize an audit record")?;
            line.push(b'\n');
            guard
                .write_all(&line)
                .context("failed to write an audit record")?;
        }
        guard.flush().context("failed to flush the audit log")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::Arc;

    /// A clock whose value the test can move forward (or backward)
    /// between calls, without sleeping across a real rotation boundary.
    fn shared_clock(
        initial: chrono::DateTime<Utc>,
    ) -> (Arc<Mutex<chrono::DateTime<Utc>>>, ClockFn) {
        let cell = Arc::new(Mutex::new(initial));
        let reader = Arc::clone(&cell);
        let clock: ClockFn = Box::new(move || *reader.lock().expect("clock mutex"));
        (cell, clock)
    }

    /// A clock that jumps one day further *every single time it is read*,
    /// starting from `start`. Used by
    /// `audit_log_write_keeps_one_complete_record_per_file_under_a_clock_that_advances_every_read`
    /// below to make a rotation-per-token bug impossible to survive: if
    /// anything in the write path consults this clock more than once per
    /// record, that record's bytes land in more than one file.
    fn advancing_clock(start: chrono::DateTime<Utc>) -> ClockFn {
        let day = Arc::new(Mutex::new(0i64));
        Box::new(move || {
            let mut day = day.lock().expect("clock mutex");
            let now = start + chrono::Duration::days(*day);
            *day += 1;
            now
        })
    }

    /// Regression test for the Critical fix, exercised through the actual
    /// public path (`AuditLog::write` -> `RotatingFile`), not by calling
    /// `write_all` directly with a hand-built buffer: that would also pass
    /// pre-fix, since a small buffer written in one `write_all` call issues
    /// exactly one `write` either way and proves nothing about
    /// `serde_json`'s many per-token writes.
    ///
    /// Against `advancing_clock`, which returns a *new* day on every read,
    /// the fix (buffer a whole record, then one `write_all` -> one
    /// rotation decision) must still land each record whole in exactly one
    /// file: `AuditLog::write` only ever reads the clock once per record.
    /// Reintroducing the old bug — streaming `serde_json::to_writer`
    /// straight into the locked writer — would have the formatter's many
    /// small `write_all` calls each consult this clock, rotating mid
    /// -record and scattering unparseable fragments across several files;
    /// this test fails loudly if that regression returns (verified by
    /// hand; see the task-2-report.md fix report for what the failure
    /// looked like).
    #[test]
    fn audit_log_write_keeps_one_complete_record_per_file_under_a_clock_that_advances_every_read() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let config = AuditConfig {
            path: dir.path().join("audit.jsonl"),
            rotation: AuditRotation::Daily,
            max_files: 365,
        };
        let start = Utc
            .with_ymd_and_hms(2026, 11, 1, 0, 0, 0)
            .single()
            .expect("valid datetime");
        let rotating =
            RotatingFile::open_with_clock(&config, advancing_clock(start)).expect("open succeeds");
        let log = AuditLog::with_writer(rotating);

        let client: SocketAddr = "10.1.2.3:51234".parse().expect("valid socket addr");
        let ctx = AuditContext::new("pypi", client);
        let records: Vec<AuditRecord> = (0..5)
            .map(|i| {
                AuditRecord::served(
                    &ctx,
                    "pkg",
                    "1.0.0",
                    "pkg-1.0.0.tar.gz",
                    &format!("{i:064x}"),
                )
            })
            .collect();

        log.write(&records).expect("write succeeds");

        let mut complete_records_found = 0usize;
        for entry in std::fs::read_dir(dir.path()).expect("read tempdir") {
            let entry = entry.expect("dir entry");
            if !entry.file_type().expect("file type").is_file() {
                continue;
            }
            let contents = std::fs::read_to_string(entry.path()).expect("read dated file");
            if contents.is_empty() {
                // The file created at `open`, before the first record ever
                // rotated away from it: never written to, legitimately empty.
                continue;
            }
            let lines: Vec<&str> = contents.lines().collect();
            assert_eq!(
                lines.len(),
                1,
                "{} must hold exactly one record, found {} lines: {:?}",
                entry.path().display(),
                lines.len(),
                lines
            );
            serde_json::from_str::<serde_json::Value>(lines[0]).unwrap_or_else(|err| {
                panic!(
                    "{} does not hold one complete record ({err}); a rotation-per-token \
                     regression would scatter a record's bytes across files like this: {contents:?}",
                    entry.path().display()
                )
            });
            complete_records_found += 1;
        }
        assert_eq!(
            complete_records_found,
            records.len(),
            "every record must have landed whole in exactly one file"
        );
    }

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

    // --- RotatingFile: the hand-rolled rotation this task's authorized
    // deviation made the project's own, so it carries its own tests
    // rather than relying only on the brief's ten (which predate it). ---

    #[test]
    fn a_rollover_crossing_a_boundary_writes_two_separate_terminated_files() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let config = AuditConfig {
            path: dir.path().join("audit.jsonl"),
            rotation: AuditRotation::Daily,
            max_files: 14,
        };
        let day_one = Utc
            .with_ymd_and_hms(2026, 11, 1, 23, 59, 59)
            .single()
            .expect("valid datetime");
        let (clock_cell, clock) = shared_clock(day_one);
        let mut rotating = RotatingFile::open_with_clock(&config, clock).expect("open succeeds");

        rotating
            .write_all(b"{\"a\":1}\n")
            .expect("first write succeeds");

        let day_two = Utc
            .with_ymd_and_hms(2026, 11, 2, 0, 0, 1)
            .single()
            .expect("valid datetime");
        *clock_cell.lock().expect("clock mutex") = day_two;
        rotating
            .write_all(b"{\"a\":2}\n")
            .expect("second write succeeds after rollover");

        let first = std::fs::read_to_string(dir.path().join("audit.jsonl.2026-11-01"))
            .expect("first file readable");
        let second = std::fs::read_to_string(dir.path().join("audit.jsonl.2026-11-02"))
            .expect("second file readable");
        assert_eq!(
            first, "{\"a\":1}\n",
            "the first file must hold exactly its own complete record"
        );
        assert_eq!(
            second, "{\"a\":2}\n",
            "the second file must hold exactly its own complete record, not a fragment of the first"
        );
    }

    #[test]
    fn a_rollover_whose_new_file_cannot_be_opened_returns_err_instead_of_falling_back() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let config = AuditConfig {
            path: dir.path().join("audit.jsonl"),
            rotation: AuditRotation::Daily,
            max_files: 14,
        };
        let day_one = Utc
            .with_ymd_and_hms(2026, 11, 1, 12, 0, 0)
            .single()
            .expect("valid datetime");
        let (clock_cell, clock) = shared_clock(day_one);
        let mut rotating = RotatingFile::open_with_clock(&config, clock).expect("open succeeds");
        rotating
            .write_all(b"{\"a\":1}\n")
            .expect("first write succeeds");

        let day_two = Utc
            .with_ymd_and_hms(2026, 11, 2, 0, 0, 1)
            .single()
            .expect("valid datetime");
        *clock_cell.lock().expect("clock mutex") = day_two;
        // Block the next period's path with a directory, so opening it as
        // a file fails rather than succeeding.
        std::fs::create_dir(dir.path().join("audit.jsonl.2026-11-02"))
            .expect("create blocking directory");

        rotating.write_all(b"{\"a\":2}\n").expect_err(
            "a rollover that can't open its new file must fail, not fall back silently",
        );

        let first = std::fs::read_to_string(dir.path().join("audit.jsonl.2026-11-01"))
            .expect("first file still readable");
        assert_eq!(
            first, "{\"a\":1}\n",
            "the failed rollover must not have written the second record into the old file either"
        );
    }

    #[test]
    fn a_write_after_the_current_file_is_deleted_underneath_recreates_it() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let config = AuditConfig {
            path: dir.path().join("audit.jsonl"),
            rotation: AuditRotation::Daily,
            max_files: 14,
        };
        let now = Utc
            .with_ymd_and_hms(2026, 11, 1, 12, 0, 0)
            .single()
            .expect("valid datetime");
        let (_clock_cell, clock) = shared_clock(now);
        let mut rotating = RotatingFile::open_with_clock(&config, clock).expect("open succeeds");
        rotating
            .write_all(b"{\"a\":1}\n")
            .expect("first write succeeds");

        std::fs::remove_file(dir.path().join("audit.jsonl.2026-11-01"))
            .expect("remove the live file");

        rotating
            .write_all(b"{\"a\":2}\n")
            .expect("write after the file vanished must still succeed");

        let contents = std::fs::read_to_string(dir.path().join("audit.jsonl.2026-11-01"))
            .expect("the file must be visible on disk again, not written into an orphaned inode");
        assert_eq!(contents, "{\"a\":2}\n");
    }

    #[test]
    fn pruning_only_considers_files_this_writer_could_have_produced() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let prefix = "audit.jsonl";
        std::fs::write(dir.path().join(format!("{prefix}.bak")), b"irrelevant\n")
            .expect("write sibling");
        std::fs::write(
            dir.path().join(format!("{prefix}.2026-10-31.gz")),
            b"irrelevant\n",
        )
        .expect("write sibling");
        std::fs::write(
            dir.path().join(format!("{prefix}.npm.2026-11-01")),
            b"irrelevant\n",
        )
        .expect("write sibling");
        std::fs::create_dir(dir.path().join(format!("{prefix}.2026-10-20")))
            .expect("create directory sibling");

        let config = AuditConfig {
            path: dir.path().join(prefix),
            rotation: AuditRotation::Daily,
            max_files: 1,
        };
        let now = Utc
            .with_ymd_and_hms(2026, 11, 2, 0, 0, 0)
            .single()
            .expect("valid datetime");
        let (_clock_cell, clock) = shared_clock(now);
        let _rotating = RotatingFile::open_with_clock(&config, clock).expect("open succeeds");

        // None of these lookalikes were ever valid candidates, so pruning
        // (with max_files = 1, which would otherwise be very aggressive)
        // must have left every one of them untouched.
        assert!(dir.path().join(format!("{prefix}.bak")).exists());
        assert!(dir.path().join(format!("{prefix}.2026-10-31.gz")).exists());
        assert!(dir.path().join(format!("{prefix}.npm.2026-11-01")).exists());
        assert!(dir.path().join(format!("{prefix}.2026-10-20")).exists());
    }

    #[test]
    fn pruning_deletes_the_oldest_files_past_max_files_but_keeps_the_current_one() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let prefix = "audit.jsonl";
        for day in 20..=25 {
            std::fs::write(dir.path().join(format!("{prefix}.2026-10-{day}")), b"old\n")
                .expect("write old file");
        }

        let config = AuditConfig {
            path: dir.path().join(prefix),
            rotation: AuditRotation::Daily,
            max_files: 3,
        };
        let now = Utc
            .with_ymd_and_hms(2026, 10, 27, 12, 0, 0)
            .single()
            .expect("valid datetime");
        let (_clock_cell, clock) = shared_clock(now);
        let _rotating = RotatingFile::open_with_clock(&config, clock).expect("open succeeds");

        assert!(
            dir.path().join(format!("{prefix}.2026-10-27")).exists(),
            "the current file must survive"
        );
        let old_survivors = (20..=25)
            .filter(|day| dir.path().join(format!("{prefix}.2026-10-{day}")).exists())
            .count();
        assert_eq!(
            old_survivors, 2,
            "with max_files = 3 and the current file counted as one slot, only 2 of the 6 old files should remain"
        );
    }

    #[test]
    fn the_current_file_survives_pruning_even_when_it_sorts_oldest() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let prefix = "audit.jsonl";
        std::fs::write(dir.path().join(format!("{prefix}.2026-11-05")), b"old\n")
            .expect("write sibling");
        std::fs::write(dir.path().join(format!("{prefix}.2026-11-06")), b"old\n")
            .expect("write sibling");

        let config = AuditConfig {
            path: dir.path().join(prefix),
            rotation: AuditRotation::Daily,
            max_files: 1,
        };
        // A clock behind the leftover files' dates (e.g. an NTP step
        // backward), so the live file sorts first rather than last.
        let now = Utc
            .with_ymd_and_hms(2026, 11, 1, 0, 0, 0)
            .single()
            .expect("valid datetime");
        let (_clock_cell, clock) = shared_clock(now);
        let _rotating = RotatingFile::open_with_clock(&config, clock).expect("open succeeds");

        assert!(
            dir.path().join(format!("{prefix}.2026-11-01")).exists(),
            "the live file must never be pruned, regardless of sort position"
        );
    }
}

//! Per-artifact verdict store: the durable memory of every scan outcome.
//!
//! Verdicts are keyed per artifact file — `(ecosystem, package, version,
//! filename, sha256)` — because one package version can ship several
//! wheels plus an sdist, and a clean sdist must never license an unscanned
//! wheel. Every row also carries the policy `fingerprint` that produced
//! it; [`VerdictStore::get`] only returns a verdict when the fingerprint
//! passed in matches the one stored, so a policy change forces a rescan
//! rather than silently reusing a verdict made under different rules.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use rand::Rng;
use rusqlite::OptionalExtension;

use crate::db::Db;
use crate::model::{ArtifactKey, RefusalReason, Verdict};

/// Lowercase RFC 4648 base32 alphabet, chosen so a `why_id` is safe to
/// embed directly in a URL path (`/why/<id>`) without escaping.
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Number of base32 characters produced from an 80-bit random value
/// (80 / 5 = 16, with no padding needed).
const WHY_ID_LEN: usize = 16;

/// A verdict as read back from the store, together with the identifiers
/// that let it be looked up again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredVerdict {
    pub why_id: String,
    pub verdict: Verdict,
    pub scanned_at: i64,
}

/// The durable record of every artifact this scanner has ever scanned.
pub struct VerdictStore {
    db: Db,
}

impl VerdictStore {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Returns the stored verdict for `key`, but only if it was recorded
    /// under the given policy `fingerprint`. A fingerprint mismatch means
    /// the org's rules changed since this artifact was scanned, so it is
    /// treated as if no verdict exists at all — the caller must rescan.
    pub fn get(
        &self,
        key: &ArtifactKey,
        fingerprint: &str,
    ) -> anyhow::Result<Option<StoredVerdict>> {
        let conn = self.db.conn()?;
        conn.query_row(
            "SELECT why_id, blocked, reason_code, reason_detail, scanned_at
             FROM verdicts
             WHERE ecosystem = ?1 AND package = ?2 AND version = ?3
               AND filename = ?4 AND sha256 = ?5 AND fingerprint = ?6",
            rusqlite::params![
                key.ecosystem,
                key.package,
                key.version,
                key.filename,
                key.sha256,
                fingerprint
            ],
            row_to_stored_verdict,
        )
        .optional()
        .context("querying verdict by artifact key and fingerprint")
    }

    /// Records (or updates) the verdict for `key` under the given policy
    /// `fingerprint`. If a row already exists for this artifact (under
    /// any fingerprint), it is updated in place and its original `why_id`
    /// is preserved; otherwise a fresh row is inserted with a newly
    /// generated `why_id`. Returns the `why_id` either way.
    pub fn put(
        &self,
        key: &ArtifactKey,
        verdict: &Verdict,
        fingerprint: &str,
    ) -> anyhow::Result<String> {
        let (blocked, reason_code, reason_detail) = match verdict {
            Verdict::Clean => (false, None, None),
            Verdict::Blocked(RefusalReason { code, detail }) => {
                (true, Some(code.as_str()), Some(detail.as_str()))
            }
        };
        let scanned_at = now_unix();
        let candidate_why_id = generate_why_id();

        let conn = self.db.conn()?;
        let why_id: String = conn
            .query_row(
                "INSERT INTO verdicts
                     (why_id, ecosystem, package, version, filename, sha256,
                      blocked, reason_code, reason_detail, fingerprint, scanned_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT (ecosystem, package, version, filename, sha256)
                 DO UPDATE SET
                     blocked = excluded.blocked,
                     reason_code = excluded.reason_code,
                     reason_detail = excluded.reason_detail,
                     fingerprint = excluded.fingerprint,
                     scanned_at = excluded.scanned_at
                 RETURNING why_id",
                rusqlite::params![
                    candidate_why_id,
                    key.ecosystem,
                    key.package,
                    key.version,
                    key.filename,
                    key.sha256,
                    blocked,
                    reason_code,
                    reason_detail,
                    fingerprint,
                    scanned_at,
                ],
                |row| row.get(0),
            )
            .context("upserting verdict")?;

        Ok(why_id)
    }

    /// Resolves a `why_id` (as printed in a `/why/<id>` URL) back to the
    /// artifact it was issued for and its stored verdict, regardless of
    /// whether the verdict is still current under today's policy — this
    /// is a historical lookup for a page a developer already has a link
    /// to, not a gate.
    pub fn get_by_why_id(
        &self,
        why_id: &str,
    ) -> anyhow::Result<Option<(ArtifactKey, StoredVerdict)>> {
        let conn = self.db.conn()?;
        conn.query_row(
            "SELECT ecosystem, package, version, filename, sha256,
                    why_id, blocked, reason_code, reason_detail, scanned_at
             FROM verdicts
             WHERE why_id = ?1",
            [why_id],
            |row| {
                let key = ArtifactKey {
                    ecosystem: row.get(0)?,
                    package: row.get(1)?,
                    version: row.get(2)?,
                    filename: row.get(3)?,
                    sha256: row.get(4)?,
                };
                let stored = stored_verdict_from_row(row, 5)?;
                Ok((key, stored))
            },
        )
        .optional()
        .context("querying verdict by why_id")
    }

    /// Lists the filenames currently blocked for `(ecosystem, package)`
    /// under the given policy `fingerprint`. Used to filter the package
    /// index so a developer never sees a download link for a blocked
    /// artifact in the first place.
    pub fn blocked_filenames(
        &self,
        ecosystem: &str,
        package: &str,
        fingerprint: &str,
    ) -> anyhow::Result<HashSet<String>> {
        let conn = self.db.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT filename FROM verdicts
                 WHERE ecosystem = ?1 AND package = ?2 AND fingerprint = ?3 AND blocked = 1",
            )
            .context("preparing blocked_filenames query")?;
        let rows = stmt
            .query_map(rusqlite::params![ecosystem, package, fingerprint], |row| {
                row.get::<_, String>(0)
            })
            .context("querying blocked filenames")?;

        let mut filenames = HashSet::new();
        for row in rows {
            filenames.insert(row.context("reading blocked filename row")?);
        }
        Ok(filenames)
    }
}

/// Builds a [`StoredVerdict`] from a row shaped
/// `(why_id, blocked, reason_code, reason_detail, scanned_at)`.
fn row_to_stored_verdict(row: &rusqlite::Row) -> rusqlite::Result<StoredVerdict> {
    stored_verdict_from_row(row, 0)
}

/// Builds a [`StoredVerdict`] from five consecutive columns
/// `(why_id, blocked, reason_code, reason_detail, scanned_at)` starting at
/// `offset`.
fn stored_verdict_from_row(row: &rusqlite::Row, offset: usize) -> rusqlite::Result<StoredVerdict> {
    let why_id: String = row.get(offset)?;
    let blocked: bool = row.get(offset + 1)?;
    let reason_code: Option<String> = row.get(offset + 2)?;
    let reason_detail: Option<String> = row.get(offset + 3)?;
    let scanned_at: i64 = row.get(offset + 4)?;

    let verdict = if blocked {
        Verdict::Blocked(RefusalReason {
            code: reason_code.unwrap_or_default(),
            detail: reason_detail.unwrap_or_default(),
        })
    } else {
        Verdict::Clean
    };

    Ok(StoredVerdict {
        why_id,
        verdict,
        scanned_at,
    })
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs() as i64
}

/// Generates a `why_id`: 16 lowercase base32 characters encoding a random
/// 80-bit value. URL-safe by construction (lowercase letters and digits
/// only), so it can be printed directly into a `/why/<id>` link.
fn generate_why_id() -> String {
    let mut bytes = [0u8; 10]; // 80 bits
    rand::rng().fill_bytes(&mut bytes);
    encode_base32(&bytes)
}

fn encode_base32(bytes: &[u8; 10]) -> String {
    let mut bits: u128 = 0;
    for &b in bytes {
        bits = (bits << 8) | u128::from(b);
    }

    let mut out = String::with_capacity(WHY_ID_LEN);
    for i in (0..WHY_ID_LEN).rev() {
        let shift = i * 5;
        let index = ((bits >> shift) & 0b1_1111) as usize;
        out.push(BASE32_ALPHABET[index] as char);
    }
    out
}

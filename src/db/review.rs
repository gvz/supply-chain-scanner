//! Per-artifact AI review store: the audit trail of every completed
//! review, newest answer on top.
//!
//! The `reviews` table has **no unique constraint**. Task 8's reviewer is
//! not deterministic, so two reviews of identical bytes can disagree, and
//! the design requires every completed review to survive: a repeat review
//! appends a new row beside its predecessor rather than replacing it.
//! [`ReviewStore::newest_for_artifact`] picks the latest row for a
//! caller that needs one answer, and [`ReviewStore::list`] walks the
//! whole history newest first.
//!
//! Like [`VerdictStore`](crate::db::verdict::VerdictStore), every row
//! carries the policy `fingerprint` that produced it, so a review made
//! under one set of rules never gets attributed to another.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use rusqlite::types::Value as SqlValue;
use rusqlite::OptionalExtension;

use crate::db::Db;
use crate::model::ArtifactKey;

/// A completed review as it goes in.
///
/// `verdict` is one of `"clean"`, `"suspicious"`, `"malicious"` —
/// `ModelVerdict`'s closed set, as produced by
/// [`prompt::parse_reply`](crate::ai::prompt). `coverage` is `None` when
/// the artifact had no reviewable source at all: undefined, not zero.
/// The three `*_json` fields are already-serialized JSON strings
/// (findings, opaque content, reviewed paths) stored verbatim.
#[derive(Debug, Clone)]
pub struct NewReview {
    pub key: ArtifactKey,
    pub fingerprint: String,
    pub verdict: &'static str,
    pub blocked: bool,
    pub summary: String,
    pub findings_json: String,
    pub coverage: Option<f32>,
    pub reviewable_bytes_total: i64,
    pub reviewable_bytes_sent: i64,
    pub opaque_json: String,
    pub reviewed_paths_json: String,
    pub model: String,
    pub prompt_version: &'static str,
    pub collector_version: String,
}

/// Every `NewReview` field as read back, plus its row id and timestamp.
/// Note the three that widen on the way out: `verdict`, `prompt_version`
/// and `collector_version` are owned `String`s here, not `&'static str`.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredReview {
    pub id: i64,
    pub key: ArtifactKey,
    pub fingerprint: String,
    pub verdict: String,
    pub blocked: bool,
    pub summary: String,
    pub findings_json: String,
    pub coverage: Option<f32>,
    pub reviewable_bytes_total: i64,
    pub reviewable_bytes_sent: i64,
    pub opaque_json: String,
    pub reviewed_paths_json: String,
    pub model: String,
    pub prompt_version: String,
    pub collector_version: String,
    pub reviewed_at: i64,
}

/// Which rows [`ReviewStore::list`] returns. An unset field matches
/// everything; set fields combine with AND. Results come back newest
/// first (`id` descending), so `before_id` paginates backwards through
/// the history.
#[derive(Debug, Clone, Default)]
pub struct ReviewFilter {
    pub verdict: Option<String>,
    pub package: Option<String>,
    pub since: Option<i64>,
    pub before_id: Option<i64>,
    pub limit: usize,
}

/// The append-only record of every completed AI review.
pub struct ReviewStore {
    db: Db,
}

/// Columns the `SELECT` statements below ask for, in the order
/// [`row_to_stored_review`] reads them back.
const REVIEW_COLUMNS: &str = "id, ecosystem, package, version, filename, sha256, \
     fingerprint, verdict, blocked, summary, findings_json, coverage, \
     reviewable_bytes_total, reviewable_bytes_sent, opaque_json, \
     reviewed_paths_json, model, prompt_version, collector_version, reviewed_at";

impl ReviewStore {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Appends one completed review and returns its fresh row id.
    /// Never overwrites: a repeat review of the same artifact lands in a
    /// new row beside its predecessor.
    pub fn put(&self, review: &NewReview) -> anyhow::Result<i64> {
        let conn = self.db.conn()?;
        let reviewed_at = now_unix();
        conn.execute(
            "INSERT INTO reviews
                 (ecosystem, package, version, filename, sha256, fingerprint,
                  verdict, blocked, summary, findings_json, coverage,
                  reviewable_bytes_total, reviewable_bytes_sent, opaque_json,
                  reviewed_paths_json, model, prompt_version, collector_version,
                  reviewed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                     ?15, ?16, ?17, ?18, ?19)",
            rusqlite::params![
                review.key.ecosystem,
                review.key.package,
                review.key.version,
                review.key.filename,
                review.key.sha256,
                review.fingerprint,
                review.verdict,
                review.blocked,
                review.summary,
                review.findings_json,
                review.coverage,
                review.reviewable_bytes_total,
                review.reviewable_bytes_sent,
                review.opaque_json,
                review.reviewed_paths_json,
                review.model,
                review.prompt_version,
                review.collector_version,
                reviewed_at,
            ],
        )
        .context("inserting review")?;
        Ok(conn.last_insert_rowid())
    }

    /// Newest row for this artifact under this fingerprint, or `None` if
    /// this artifact was never reviewed under that policy.
    pub fn newest_for_artifact(
        &self,
        key: &ArtifactKey,
        fingerprint: &str,
    ) -> anyhow::Result<Option<StoredReview>> {
        let conn = self.db.conn()?;
        conn.query_row(
            &format!(
                "SELECT {REVIEW_COLUMNS}
                 FROM reviews
                 WHERE ecosystem = ?1 AND package = ?2 AND version = ?3
                   AND filename = ?4 AND sha256 = ?5 AND fingerprint = ?6
                 ORDER BY id DESC
                 LIMIT 1"
            ),
            rusqlite::params![
                key.ecosystem,
                key.package,
                key.version,
                key.filename,
                key.sha256,
                fingerprint
            ],
            row_to_stored_review,
        )
        .optional()
        .context("querying newest review by artifact key and fingerprint")
    }

    /// Rows matching `filter`, newest first (`id` descending).
    pub fn list(&self, filter: &ReviewFilter) -> anyhow::Result<Vec<StoredReview>> {
        let conn = self.db.conn()?;

        let mut sql = format!("SELECT {REVIEW_COLUMNS} FROM reviews WHERE 1 = 1");
        let mut params: Vec<SqlValue> = Vec::new();

        if let Some(verdict) = &filter.verdict {
            sql.push_str(" AND verdict = ?");
            params.push(SqlValue::Text(verdict.clone()));
        }
        if let Some(package) = &filter.package {
            sql.push_str(" AND package = ?");
            params.push(SqlValue::Text(package.clone()));
        }
        if let Some(since) = filter.since {
            sql.push_str(" AND reviewed_at >= ?");
            params.push(SqlValue::Integer(since));
        }
        if let Some(before_id) = filter.before_id {
            sql.push_str(" AND id < ?");
            params.push(SqlValue::Integer(before_id));
        }

        // `LIMIT ?` would need its own bind order relative to the
        // conditional filters above, and a usize limit does not map onto
        // one SQLite value cleanly. Formatting it here is safe: the value
        // is the caller's own row cap, not remote input.
        sql.push_str(" ORDER BY id DESC LIMIT ");
        sql.push_str(&filter.limit.to_string());

        let mut stmt = conn.prepare(&sql).context("preparing review list query")?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params), row_to_stored_review)
            .context("querying reviews")?;

        let mut reviews = Vec::new();
        for row in rows {
            reviews.push(row.context("reading review row")?);
        }
        Ok(reviews)
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs() as i64
}

fn row_to_stored_review(row: &rusqlite::Row) -> rusqlite::Result<StoredReview> {
    Ok(StoredReview {
        id: row.get(0)?,
        key: ArtifactKey {
            ecosystem: row.get(1)?,
            package: row.get(2)?,
            version: row.get(3)?,
            filename: row.get(4)?,
            sha256: row.get(5)?,
        },
        fingerprint: row.get(6)?,
        verdict: row.get(7)?,
        blocked: row.get(8)?,
        summary: row.get(9)?,
        findings_json: row.get(10)?,
        coverage: row.get(11)?,
        reviewable_bytes_total: row.get(12)?,
        reviewable_bytes_sent: row.get(13)?,
        opaque_json: row.get(14)?,
        reviewed_paths_json: row.get(15)?,
        model: row.get(16)?,
        prompt_version: row.get(17)?,
        collector_version: row.get(18)?,
        reviewed_at: row.get(19)?,
    })
}

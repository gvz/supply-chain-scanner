//! Metadata store backing the on-disk artifact cache: one row per cached
//! blob, keyed by its sha256 content hash.
//!
//! This module only touches the database — [`crate::artifact_cache::ArtifactCache`]
//! owns the on-disk content-addressed layout and composes this store with
//! it to implement the sliding TTL. `last_access` is that TTL's clock:
//! every cache hit stamps it with the current time (see
//! [`CacheStore::touch`]), so a package in constant use is never evicted
//! while one-off downloads age out.
//!
//! The verdict recorded in [`crate::db::verdict::VerdictStore`] is the
//! durable record of whether an artifact may be served; this table is a
//! performance cache only and can be emptied at any time without changing
//! what the proxy would decide to serve next.

use anyhow::Context;
use rusqlite::OptionalExtension;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db::Db;
use crate::model::ArtifactKey;

/// One row of cache metadata, as read back from the store. Keyed by
/// content hash, but carries the descriptive columns (ecosystem, package,
/// version, filename) so an operator inspecting the database can see what
/// a cached blob actually is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    pub sha256: String,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub filename: String,
    pub bytes: i64,
    pub last_access: i64,
}

/// Durable metadata for the content-addressed artifact cache.
pub struct CacheStore {
    db: Db,
}

impl CacheStore {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Records (or refreshes) metadata for a cached blob, stamping the
    /// current time as `last_access`. Content is addressed by `sha256`
    /// alone, so inserting the same hash twice (e.g. two packages that
    /// happen to ship byte-identical files) just updates the descriptive
    /// columns and refreshes the clock rather than erroring.
    pub fn insert(&self, key: &ArtifactKey, bytes: u64) -> anyhow::Result<()> {
        let conn = self.db.conn()?;
        let now = now_unix();
        let bytes = i64::try_from(bytes).context("artifact size overflows i64")?;
        conn.execute(
            "INSERT INTO artifact_cache
                 (sha256, ecosystem, package, version, filename, bytes, last_access)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (sha256) DO UPDATE SET
                 ecosystem = excluded.ecosystem,
                 package = excluded.package,
                 version = excluded.version,
                 filename = excluded.filename,
                 bytes = excluded.bytes,
                 last_access = excluded.last_access",
            rusqlite::params![
                key.sha256,
                key.ecosystem,
                key.package,
                key.version,
                key.filename,
                bytes,
                now,
            ],
        )
        .context("upserting artifact cache row")?;
        Ok(())
    }

    /// Returns the metadata row for `sha256`, if any. Does not touch
    /// `last_access` — a caller that counts this lookup as a use of the
    /// cached artifact must call [`CacheStore::touch`] itself.
    pub fn get(&self, sha256: &str) -> anyhow::Result<Option<CacheEntry>> {
        let conn = self.db.conn()?;
        conn.query_row(
            "SELECT sha256, ecosystem, package, version, filename, bytes, last_access
             FROM artifact_cache WHERE sha256 = ?1",
            [sha256],
            |row| {
                Ok(CacheEntry {
                    sha256: row.get(0)?,
                    ecosystem: row.get(1)?,
                    package: row.get(2)?,
                    version: row.get(3)?,
                    filename: row.get(4)?,
                    bytes: row.get(5)?,
                    last_access: row.get(6)?,
                })
            },
        )
        .optional()
        .context("querying artifact cache row")
    }

    /// Stamps `last_access` to now for `sha256`. This is the sliding TTL
    /// in practice: every successful cache hit calls this, so a
    /// repeatedly requested artifact is never swept by
    /// [`CacheStore::expired_before`].
    pub fn touch(&self, sha256: &str) -> anyhow::Result<()> {
        let conn = self.db.conn()?;
        conn.execute(
            "UPDATE artifact_cache SET last_access = ?1 WHERE sha256 = ?2",
            rusqlite::params![now_unix(), sha256],
        )
        .context("touching artifact cache row")?;
        Ok(())
    }

    /// Deletes the row for `sha256`. Used both when a cache entry expires
    /// and when its backing file is found to have vanished from disk.
    pub fn remove(&self, sha256: &str) -> anyhow::Result<()> {
        let conn = self.db.conn()?;
        conn.execute("DELETE FROM artifact_cache WHERE sha256 = ?1", [sha256])
            .context("deleting artifact cache row")?;
        Ok(())
    }

    /// Returns the `sha256` of every row whose `last_access` is strictly
    /// before `cutoff` (Unix seconds) — i.e. entries that have gone
    /// untouched for longer than the caller's TTL.
    pub fn expired_before(&self, cutoff: i64) -> anyhow::Result<Vec<String>> {
        let conn = self.db.conn()?;
        let mut stmt = conn
            .prepare("SELECT sha256 FROM artifact_cache WHERE last_access < ?1")
            .context("preparing expired artifact cache query")?;
        let rows = stmt
            .query_map([cutoff], |row| row.get::<_, String>(0))
            .context("querying expired artifact cache rows")?;

        let mut expired = Vec::new();
        for row in rows {
            expired.push(row.context("reading expired artifact cache row")?);
        }
        Ok(expired)
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs() as i64
}

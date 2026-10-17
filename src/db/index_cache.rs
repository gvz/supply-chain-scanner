//! Cache of the last successfully fetched PEP 503 simple index page body
//! for each package, keyed by its normalized name.
//!
//! This is the proxy's fallback memory: [`crate::ecosystem::pypi::upstream::Upstream`]
//! always tries upstream PyPI first and only reads this cache when upstream
//! is unreachable. Cache freshness policy (TTLs, background refresh) is not
//! this module's concern — it stores exactly what was last fetched and
//! when, and leaves the decision of whether that's good enough to the
//! caller.

use anyhow::Context;
use rusqlite::OptionalExtension;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db::Db;

/// Durable cache of simple index page bodies, one row per normalized
/// package name.
#[derive(Clone)]
pub struct IndexCache {
    db: Db,
}

impl IndexCache {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Returns the cached `(body, fetched_at)` for `package`, if any.
    /// `package` must already be normalized (see
    /// [`crate::ecosystem::pypi::index::normalize_name`]) — this store does
    /// not normalize on the caller's behalf, so it stays the single place
    /// that decides what "the same package" means.
    pub fn get(&self, package: &str) -> anyhow::Result<Option<(String, i64)>> {
        let conn = self.db.conn()?;
        conn.query_row(
            "SELECT body, fetched_at FROM index_cache WHERE package = ?1",
            [package],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .context("querying index cache")
    }

    /// Records `body` as the latest known-good page for `package`,
    /// overwriting whatever was cached before and stamping the current
    /// time as the fetch time.
    pub fn put(&self, package: &str, body: &str) -> anyhow::Result<()> {
        let conn = self.db.conn()?;
        let fetched_at = now_unix();
        conn.execute(
            "INSERT INTO index_cache (package, body, fetched_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (package) DO UPDATE SET
                 body = excluded.body,
                 fetched_at = excluded.fetched_at",
            rusqlite::params![package, body, fetched_at],
        )
        .context("upserting index cache")?;
        Ok(())
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs() as i64
}

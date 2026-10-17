//! The single SQLite file this binary owns. Everything persistent in the
//! scanner — verdicts, the advisory mirror, the index cache, and artifact
//! cache metadata — lives in one file, opened once at startup through
//! [`Db::open`].

pub mod migrations;
pub mod verdict;

use std::path::Path;

use anyhow::Context;
use r2d2_sqlite::SqliteConnectionManager;

/// A pooled connection checked out from a [`Db`]. Borrowed connections are
/// returned to the pool when dropped.
pub type PooledConnection = r2d2::PooledConnection<SqliteConnectionManager>;

/// A handle to the scanner's single SQLite database.
///
/// Cheap to clone: it wraps an `r2d2::Pool`, so every store built on top of
/// a `Db` (the index cache, the advisory store, the artifact cache, the
/// verdict store) can hold its own clone of the same underlying pool.
#[derive(Clone)]
pub struct Db {
    pool: r2d2::Pool<SqliteConnectionManager>,
}

impl Db {
    /// Opens (creating if necessary) the SQLite database at `path`,
    /// applying every migration in [`migrations::MIGRATIONS`] that hasn't
    /// already run. Safe to call repeatedly against the same file: an
    /// already-migrated database is left untouched.
    pub fn open(path: &Path) -> anyhow::Result<Db> {
        let manager = SqliteConnectionManager::file(path).with_init(|conn| {
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA busy_timeout=5000;",
            )
        });

        let pool = r2d2::Pool::new(manager)
            .with_context(|| format!("creating connection pool for {}", path.display()))?;

        {
            let conn = pool
                .get()
                .with_context(|| format!("opening {}", path.display()))?;
            migrations::apply(&conn).context("applying database migrations")?;
        }

        Ok(Db { pool })
    }

    /// Checks out a pooled connection, blocking until one is available.
    pub fn conn(&self) -> anyhow::Result<PooledConnection> {
        self.pool
            .get()
            .context("checking out a database connection")
    }
}

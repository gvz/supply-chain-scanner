//! The ordered list of schema migrations applied to the single SQLite file
//! this binary owns.
//!
//! Every persistent table in the scanner — verdicts (this task), the
//! advisory mirror, the index cache, and artifact cache metadata (later
//! tasks) — is created here. Appending a migration is a one-line change:
//! add another `&str` to [`MIGRATIONS`]. Migrations already applied are
//! never edited or removed; a new change to an existing table is a new
//! migration appended to the end.

/// Ordered list of migrations. Each entry is run exactly once, in order,
/// inside a single transaction, the first time a database file reaches
/// that index in [`apply`].
pub const MIGRATIONS: &[&str] = &[
    // 0: verdicts — one row per scanned artifact file. Verdicts are keyed
    // per artifact (ecosystem, package, version, filename, sha256), not
    // per package version: a clean sdist must never license an unscanned
    // wheel. `fingerprint` records the policy that produced this verdict;
    // a later policy change invalidates the row without deleting it.
    r#"
    CREATE TABLE verdicts (
        why_id         TEXT PRIMARY KEY,
        ecosystem      TEXT NOT NULL,
        package        TEXT NOT NULL,
        version        TEXT NOT NULL,
        filename       TEXT NOT NULL,
        sha256         TEXT NOT NULL,
        blocked        INTEGER NOT NULL,
        reason_code    TEXT,
        reason_detail  TEXT,
        fingerprint    TEXT NOT NULL,
        scanned_at     INTEGER NOT NULL,
        UNIQUE(ecosystem, package, version, filename, sha256)
    )
    "#,
    // 1: index_cache — the raw body of the last successfully fetched PEP
    // 503 simple index page for a package, keyed by its normalized name.
    // Populated on every successful upstream fetch (task 4's `Upstream`);
    // read back only when upstream is unreachable, so a PyPI outage
    // degrades to "serve what we already know" rather than an empty page.
    r#"
    CREATE TABLE index_cache (
        package     TEXT PRIMARY KEY,
        body        TEXT NOT NULL,
        fetched_at  INTEGER NOT NULL
    )
    "#,
];

/// Applies every migration in [`MIGRATIONS`] that hasn't already run
/// against this connection, tracking progress in a `schema_version` table.
/// Running this against an already-migrated database is a no-op.
pub fn apply(conn: &rusqlite::Connection) -> anyhow::Result<()> {
    use anyhow::Context;

    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        .context("creating schema_version table")?;

    let current_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .context("reading current schema version")?;

    let current_version = usize::try_from(current_version).context("negative schema version")?;

    if current_version >= MIGRATIONS.len() {
        return Ok(());
    }

    let tx = conn
        .unchecked_transaction()
        .context("starting migration transaction")?;
    for (index, migration) in MIGRATIONS.iter().enumerate().skip(current_version) {
        tx.execute_batch(migration)
            .with_context(|| format!("applying migration {index}"))?;
        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            [index as i64 + 1],
        )
        .with_context(|| format!("recording migration {index}"))?;
    }
    tx.commit().context("committing migrations")?;

    Ok(())
}

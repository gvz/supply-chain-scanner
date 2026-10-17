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
    // 2: advisories — the local OSV mirror (task 6's `AdvisoryStore`),
    // keyed per ecosystem and PEP 503 normalized package name.
    // `replace_all` deletes every row for one ecosystem and reinserts the
    // freshly parsed set inside a single transaction; `ON DELETE CASCADE`
    // on the child tables means that one delete takes `advisory_versions`
    // and `advisory_ranges` with it, so a withdrawn advisory's enumerated
    // versions and ranges never outlive the advisory itself.
    //
    // The primary key is `(ecosystem, id, package)`, not just
    // `(ecosystem, id)`: one OSV advisory id can list several affected
    // packages (e.g. sibling distributions sharing a vulnerability), which
    // `parse_osv` turns into one `Advisory` row per package, all carrying
    // the same `id`. The child tables key on that same triple so each
    // package's own versions/ranges never mix with another package's rows
    // under a shared advisory id.
    r#"
    CREATE TABLE advisories (
        ecosystem       TEXT NOT NULL,
        id              TEXT NOT NULL,
        package         TEXT NOT NULL,
        summary         TEXT NOT NULL,
        severity        REAL,
        fixed_versions  TEXT NOT NULL,
        PRIMARY KEY (ecosystem, id, package)
    );
    CREATE INDEX idx_advisories_ecosystem_package ON advisories(ecosystem, package);

    CREATE TABLE advisory_versions (
        ecosystem    TEXT NOT NULL,
        advisory_id  TEXT NOT NULL,
        package      TEXT NOT NULL,
        version      TEXT NOT NULL,
        FOREIGN KEY (ecosystem, advisory_id, package)
            REFERENCES advisories(ecosystem, id, package) ON DELETE CASCADE
    );
    CREATE INDEX idx_advisory_versions_advisory
        ON advisory_versions(ecosystem, advisory_id, package);

    CREATE TABLE advisory_ranges (
        ecosystem    TEXT NOT NULL,
        advisory_id  TEXT NOT NULL,
        package      TEXT NOT NULL,
        introduced   TEXT,
        fixed        TEXT,
        FOREIGN KEY (ecosystem, advisory_id, package)
            REFERENCES advisories(ecosystem, id, package) ON DELETE CASCADE
    );
    CREATE INDEX idx_advisory_ranges_advisory
        ON advisory_ranges(ecosystem, advisory_id, package);
    "#,
    // 3: artifact_cache — on-disk cache of scanned artifact bytes (task 9's
    // `ArtifactCache`), keyed by `sha256` alone rather than by
    // (ecosystem, package, version, filename): the cache is content
    // addressed, so identical bytes shipped under different names are
    // stored once. The descriptive columns are kept anyway so an operator
    // inspecting the database can see what a cached blob is.
    //
    // `last_access` is the sliding TTL clock: every cache hit stamps it
    // with the current time, so a package in constant use is never
    // evicted while one-off downloads age out. This table is purely a
    // performance cache in front of the durable `verdicts` table above —
    // emptying it never changes what the proxy decides to serve, only how
    // long that takes.
    r#"
    CREATE TABLE artifact_cache (
        sha256       TEXT PRIMARY KEY,
        ecosystem    TEXT NOT NULL,
        package      TEXT NOT NULL,
        version      TEXT NOT NULL,
        filename     TEXT NOT NULL,
        bytes        INTEGER NOT NULL,
        last_access  INTEGER NOT NULL
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

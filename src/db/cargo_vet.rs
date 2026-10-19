//! The local mirror of trusted cargo-vet audit sets. The cargo path's fast
//! path reads it, which lets a qualifying audit stand in for AI review.
//!
//! [`CargoVetStore::replace_source`] is the only way this mirror is
//! written. It deletes every row for one source and reinserts that source's
//! freshly parsed set inside a single transaction. A concurrent
//! [`CargoVetStore::covers`] query therefore always sees either the
//! complete old set or the complete new one, never a half-populated mix.
//! Sources are independent: replacing one never touches another's rows,
//! because a down Mozilla endpoint must not wipe the org's own audits.
//!
//! Only full audits are stored. A delta audit names a step between two
//! versions. Resolving a chain of delta audits back to a full audit is out
//! of this plan's scope. [`CargoVetStore::replace_source`] therefore drops
//! delta entries. A crate that only a delta chain covers reads as
//! uncovered, and it falls through to AI review.

use anyhow::Context;

use crate::cargovet::parse::AuditEntry;
use crate::db::Db;
use crate::ecosystem::cargo::normalize_name;

/// The durable mirror of cargo-vet audits. It holds one row per full audit
/// per source, with the auditor and criteria lists stored as JSON arrays.
pub struct CargoVetStore {
    db: Db,
}

impl CargoVetStore {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Replaces every audit stored for `source` with the full entries in
    /// `entries`, inside one transaction. The call deletes all of
    /// `source`'s existing rows, then inserts the full entries. Either the
    /// whole replacement commits or none of it does.
    ///
    /// The call normalizes `package` with [`normalize_name`] before storage,
    /// the same way [`CargoVetStore::covers`] normalizes its lookup. It
    /// skips delta entries. Nothing queries those entries, and storing them
    /// would invite a later reader to treat one as sufficient.
    ///
    /// The call uses its `source` argument and ignores the `source` field
    /// of each entry. The argument is the caller's configured name for the
    /// audit set.
    ///
    /// The return value is the number of full entries stored.
    pub fn replace_source(&self, source: &str, entries: &[AuditEntry]) -> anyhow::Result<usize> {
        let conn = self.db.conn()?;
        let tx = conn
            .unchecked_transaction()
            .context("starting cargo-vet replace transaction")?;

        tx.execute("DELETE FROM cargo_vet_audits WHERE source = ?1", [source])
            .context("deleting previous cargo-vet audits")?;

        let mut stored = 0;
        for entry in entries {
            let AuditEntry::Full {
                package,
                version,
                who,
                criteria,
                ..
            } = entry
            else {
                continue;
            };

            let package = normalize_name(package);
            let who_json = serde_json::to_string(who).context("serializing who to JSON")?;
            let criteria_json =
                serde_json::to_string(criteria).context("serializing criteria to JSON")?;

            tx.execute(
                "INSERT OR REPLACE INTO cargo_vet_audits
                     (source, package, version, who_json, criteria_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![source, package, version, who_json, criteria_json],
            )
            .with_context(|| format!("inserting cargo-vet audit for {package} {version}"))?;

            stored += 1;
        }

        tx.commit()
            .context("committing cargo-vet replace transaction")?;
        Ok(stored)
    }

    /// Reports whether the store holds no audit row at all, across every
    /// source.
    ///
    /// [`super::advisory::AdvisoryStore::is_empty`] answers the same
    /// question per ecosystem; this mirror has no ecosystem column, so the
    /// check is over the whole table. Startup uses it to decide whether an
    /// initial sync is needed: an empty store means the cargo-vet fast path
    /// currently has no proof to consult, so the proxy syncs once before it
    /// serves anything.
    pub fn is_empty(&self) -> anyhow::Result<bool> {
        let conn = self.db.conn()?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cargo_vet_audits", [], |row| {
                row.get(0)
            })
            .context("counting cargo-vet audits")?;
        Ok(count == 0)
    }

    /// Reports whether some stored audit covers `package` at `version`
    /// against `required_criterion`.
    ///
    /// The answer is true when a row for that package and version has
    /// `required_criterion` in its criteria. The answer is also conditional
    /// on the reviewers: `trusted_reviewers` must be empty, or one of the
    /// row's `who` entries must appear in `trusted_reviewers`. An empty
    /// `trusted_reviewers` means any auditor's entry counts.
    ///
    /// The call normalizes `package` with [`normalize_name`] first, so a
    /// lookup that uses `Demo_Crate` finds a row stored as `demo-crate`.
    pub fn covers(
        &self,
        package: &str,
        version: &str,
        required_criterion: &str,
        trusted_reviewers: &[String],
    ) -> anyhow::Result<bool> {
        let normalized = normalize_name(package);
        let conn = self.db.conn()?;

        let mut stmt = conn
            .prepare(
                "SELECT who_json, criteria_json
                 FROM cargo_vet_audits
                 WHERE package = ?1 AND version = ?2",
            )
            .context("preparing cargo-vet coverage query")?;

        let rows = stmt
            .query_map(rusqlite::params![normalized, version], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .context("querying cargo-vet audits for coverage")?;

        for row in rows {
            let (who_json, criteria_json) = row.context("reading cargo-vet audit row")?;
            let who: Vec<String> = serde_json::from_str(&who_json)
                .with_context(|| format!("deserializing who for {normalized} {version}"))?;
            let criteria: Vec<String> = serde_json::from_str(&criteria_json)
                .with_context(|| format!("deserializing criteria for {normalized} {version}"))?;

            if !criteria.iter().any(|c| c == required_criterion) {
                continue;
            }
            if trusted_reviewers.is_empty() || who.iter().any(|w| trusted_reviewers.contains(w)) {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

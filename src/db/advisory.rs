//! The local mirror of OSV advisories: storage behind task 6's [`Advisory`]
//! and [`VersionRange`], keyed per ecosystem and PEP 503 normalized
//! package name.
//!
//! [`AdvisoryStore::replace_all`] is the only way this mirror is written:
//! it deletes every row for one ecosystem and reinserts the freshly
//! parsed set inside a single transaction, so a concurrent
//! [`AdvisoryStore::for_package`] lookup always sees either the complete
//! old set or the complete new one, never a half-populated mix.

use anyhow::Context;

use crate::advisory::{Advisory, VersionRange};
use crate::db::Db;
use crate::ecosystem::pypi::index::normalize_name;

/// The durable mirror of OSV advisories, one row per advisory per
/// ecosystem, with child rows for its enumerated versions and ranges.
pub struct AdvisoryStore {
    db: Db,
}

impl AdvisoryStore {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Replaces every advisory stored for `ecosystem` with `advs`, inside
    /// one transaction: all of `ecosystem`'s existing rows (and, via
    /// `ON DELETE CASCADE`, their child version/range rows) are deleted,
    /// then `advs` is inserted. Either the whole replacement commits or
    /// none of it does, so a withdrawn advisory disappears cleanly and a
    /// failure partway through never leaves a half-populated mirror.
    ///
    /// `adv.package` is normalized with [`normalize_name`] before storage,
    /// matching how [`AdvisoryStore::for_package`] normalizes its lookup.
    pub fn replace_all(&self, ecosystem: &str, advs: &[Advisory]) -> anyhow::Result<usize> {
        let conn = self.db.conn()?;
        let tx = conn
            .unchecked_transaction()
            .context("starting advisory replace transaction")?;

        tx.execute("DELETE FROM advisories WHERE ecosystem = ?1", [ecosystem])
            .context("deleting previous advisories")?;

        for adv in advs {
            let package = normalize_name(&adv.package);
            let fixed_versions_json = serde_json::to_string(&adv.fixed_versions)
                .context("serializing fixed_versions to JSON")?;

            tx.execute(
                "INSERT INTO advisories (ecosystem, id, package, summary, severity, fixed_versions)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    ecosystem,
                    adv.id,
                    package,
                    adv.summary,
                    adv.severity,
                    fixed_versions_json,
                ],
            )
            .with_context(|| format!("inserting advisory {:?}", adv.id))?;

            for version in &adv.versions {
                tx.execute(
                    "INSERT INTO advisory_versions (ecosystem, advisory_id, package, version)
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![ecosystem, adv.id, package, version],
                )
                .with_context(|| format!("inserting version for advisory {:?}", adv.id))?;
            }

            for range in &adv.ranges {
                tx.execute(
                    "INSERT INTO advisory_ranges (ecosystem, advisory_id, package, introduced, fixed)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![ecosystem, adv.id, package, range.introduced, range.fixed],
                )
                .with_context(|| format!("inserting range for advisory {:?}", adv.id))?;
            }
        }

        tx.commit()
            .context("committing advisory replace transaction")?;
        Ok(advs.len())
    }

    /// Returns every advisory stored for `ecosystem` under `package`'s PEP
    /// 503 normalized name — `package` need not already be normalized,
    /// this is the lookup-side counterpart to the normalization
    /// [`AdvisoryStore::replace_all`] applies on the way in.
    pub fn for_package(&self, ecosystem: &str, package: &str) -> anyhow::Result<Vec<Advisory>> {
        let normalized = normalize_name(package);
        let conn = self.db.conn()?;

        let mut stmt = conn
            .prepare(
                "SELECT id, package, summary, severity, fixed_versions
                 FROM advisories
                 WHERE ecosystem = ?1 AND package = ?2",
            )
            .context("preparing advisory lookup")?;

        let rows = stmt
            .query_map(rusqlite::params![ecosystem, normalized], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<f32>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .context("querying advisories by package")?;

        let mut advisories = Vec::new();
        for row in rows {
            let (id, package, summary, severity, fixed_versions_json) =
                row.context("reading advisory row")?;
            let fixed_versions: Vec<String> = serde_json::from_str(&fixed_versions_json)
                .with_context(|| format!("deserializing fixed_versions for advisory {id:?}"))?;
            let versions = self
                .versions_for(&conn, ecosystem, &id, &package)
                .with_context(|| format!("loading versions for advisory {id:?}"))?;
            let ranges = self
                .ranges_for(&conn, ecosystem, &id, &package)
                .with_context(|| format!("loading ranges for advisory {id:?}"))?;

            advisories.push(Advisory {
                id,
                package,
                summary,
                severity,
                versions,
                ranges,
                fixed_versions,
            });
        }

        Ok(advisories)
    }

    /// Whether the mirror holds no advisories at all for `ecosystem` —
    /// the hook task 12 uses to decide whether a startup sync is needed
    /// before serving any request.
    pub fn is_empty(&self, ecosystem: &str) -> anyhow::Result<bool> {
        let conn = self.db.conn()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM advisories WHERE ecosystem = ?1",
                [ecosystem],
                |row| row.get(0),
            )
            .context("counting advisories for ecosystem")?;
        Ok(count == 0)
    }

    /// Loads the enumerated versions for one `(ecosystem, advisory_id,
    /// package)` triple. `package` is part of the key, not just
    /// `advisory_id`, because one OSV advisory id can be shared by several
    /// `Advisory` rows (one per affected package); without it, two
    /// packages sharing an id would see each other's versions.
    fn versions_for(
        &self,
        conn: &rusqlite::Connection,
        ecosystem: &str,
        advisory_id: &str,
        package: &str,
    ) -> anyhow::Result<Vec<String>> {
        let mut stmt = conn
            .prepare(
                "SELECT version FROM advisory_versions
                 WHERE ecosystem = ?1 AND advisory_id = ?2 AND package = ?3
                 ORDER BY rowid",
            )
            .context("preparing version lookup")?;
        let rows = stmt
            .query_map(rusqlite::params![ecosystem, advisory_id, package], |row| {
                row.get::<_, String>(0)
            })
            .context("querying advisory versions")?;
        rows.collect::<Result<Vec<_>, _>>()
            .context("reading advisory version row")
    }

    /// Loads the introduced/fixed ranges for one `(ecosystem, advisory_id,
    /// package)` triple; see [`AdvisoryStore::versions_for`] for why
    /// `package` is part of the key.
    fn ranges_for(
        &self,
        conn: &rusqlite::Connection,
        ecosystem: &str,
        advisory_id: &str,
        package: &str,
    ) -> anyhow::Result<Vec<VersionRange>> {
        let mut stmt = conn
            .prepare(
                "SELECT introduced, fixed FROM advisory_ranges
                 WHERE ecosystem = ?1 AND advisory_id = ?2 AND package = ?3
                 ORDER BY rowid",
            )
            .context("preparing range lookup")?;
        let rows = stmt
            .query_map(rusqlite::params![ecosystem, advisory_id, package], |row| {
                Ok(VersionRange {
                    introduced: row.get(0)?,
                    fixed: row.get(1)?,
                })
            })
            .context("querying advisory ranges")?;
        rows.collect::<Result<Vec<_>, _>>()
            .context("reading advisory range row")
    }
}

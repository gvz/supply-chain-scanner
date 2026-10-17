# Advisories

`src/advisory/` — the local mirror of OSV security advisories: what gets downloaded, parsed, stored, and matched against a specific package version.

## Why a local mirror

Clean-verdict re-checks happen on **every request** for an already-scanned artifact (a CVE may have been filed since), so advisory lookups must be fast. And an upstream advisory API outage must not become a proxy outage, or worse, a reason to fail open. A local mirror, synced on a schedule, solves both.

## Sync

`OsvSync::sync_pypi` (`src/advisory/osv.rs`) downloads the upstream OSV PyPI feed (`all.zip`). It parses **every** entry in memory. Only then does it call `AdvisoryStore::replace_all`, which deletes every row for one ecosystem and reinserts the fresh set inside a single transaction.

Two consequences:

- A download failure or a single malformed document never reaches the store. The advisories already on disk are never disturbed by a bad sync.
- Replacing all rows for the ecosystem is atomic: a scan never sees a half-updated mirror.

The sync cadence comes from `advisory_sync_interval` (default 1h). The source URL is configurable for testing — the test suite points it at a wiremock server.

## Parsing

`parse_osv` turns one OSV JSON document into one `Advisory` **per affected package**. One OSV id can list several affected packages, and each package's versions and ranges stay separate.

Severity is computed once per document: the **highest score** among the document's `severity` array that parses as CVSS. The result is `None` if the array is empty or every entry is unparseable. An advisory's severity is `Option<f32>`. `None` is a real state that flows into the policy engine's `unknown_severity` rule. It is not an error.

## Matching

`src/advisory/matching.rs` — pure functions. An `&[Advisory]`, a version string, and a `Policy` go in. A decision comes out. No database, no I/O. This is the hottest policy code in the system, so `first_blocking` stops at the first match rather than scanning the whole slice for "the worst".

### PEP 440, not lexical

Versions compare with `pep440_rs::Version` semantics: `1.10 > 1.9`, and `2.0.0rc1` sorts below `2.0.0`.

### Matching order

`affects(adv, version)`:

1. **Enumerated versions first** — most OSV PyPI entries carry an explicit list. Compared by PEP 440 equality. An enumerated entry that itself fails to parse falls back to a trimmed, case-insensitive string comparison. This neither silently never matches (fail open) nor blocks every version of the package because one list entry is malformed (over-block).
2. **Ranges second** — half-open `[introduced, fixed)` intervals.

### Fail-closed corners

- The requested version fails to parse as PEP 440 **and** the advisory carries ranges → **affected**. There is no way to prove it falls outside every range, and an unparseable version must not slip through unscanned.
- A range bound that fails to parse is treated as satisfied rather than as disproving the match. A malformed `introduced`/`fixed` string in advisory data must never let a genuinely affected version through.

### The refusal reason

A blocking advisory produces `code = "cve:<advisory-id>"` and a `detail` carrying the sanitized summary and severity. The detail is pre-sanitized to ASCII with no newlines at this layer. This happens independently of the HTTP layer's own sanitizing downstream. One layer never relies on another to stay safe.

## Storage schema

The mirror lives in three tables (`src/db/migrations.rs`, migration 2). The `advisories` table is keyed by `(ecosystem, id, package)`. The `advisory_versions` and `advisory_ranges` child tables carry `ON DELETE CASCADE`. A withdrawn advisory's enumerated versions and ranges therefore never outlive the advisory itself. The triple key — not just the id — keeps one package's rows from mixing with a sibling package's rows under a shared advisory id.

The whole matching layer, and each fail-closed corner above, is pinned by `tests/advisory_match.rs` and `tests/advisory_sync.rs` with fixture OSV documents in `tests/fixtures/osv/`.
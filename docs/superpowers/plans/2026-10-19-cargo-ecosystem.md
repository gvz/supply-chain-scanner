# Cargo/crates.io Ecosystem Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gate `cargo add` the way the proxy already gates `pip install`: CVE and AI review block at the sparse-index response (before `cargo add` returns), org plugins block at the `.crate` download, and a cargo-vet audit from a trusted source can stand in for AI review.

**Architecture:** A second, independent `Ecosystem`-shaped surface — not an implementation of the existing `crate::ecosystem::Ecosystem` trait, and not routed through `Scanner::decide`/`run_full_scan`. Both of those are shaped around "one artifact, one linear check sequence, one verdict" (see `src/scan/mod.rs`), and cargo's actual requirement is "one crate, N candidate versions evaluated by a cascading rule, two checks split across two different HTTP endpoints." Cargo gets its own upstream client, its own cascade decision logic, and its own HTTP handlers, built from the same lower-level primitives the PyPI path already uses: `VerdictStore`, `AdvisoryStore`, `AiReviewer`, `PluginRunner`, `ArtifactCache`, `ReviewStore`. This is a plan-level decision, not left open: an implementer who tries to make cargo implement `Ecosystem` will fight the trait's shape the whole way through.

**Tech Stack:** Rust, `semver` crate (new dependency — SemVer, distinct from PyPI's `pep440_rs`), `toml`/`serde` (already a dependency) for parsing cargo-vet's `audits.toml`, SQLite via the existing `Db`/`r2d2` pool, axum/reqwest as already used by the PyPI path.

**Spec:** `docs/superpowers/specs/2026-10-19-cargo-ecosystem-design.md` (and its own extension of `docs/superpowers/specs/2026-10-17-supply-chain-scanner-design.md`)

## Global Constraints

- The scan path never fails open: an error anywhere in the cascade, the cargo-vet check, or the plugin gate is `Unverifiable`, never a clean result — the base design's rule, unchanged by ecosystem (base spec, "Constraints").
- The cascade's total time must stay under the deployment's configured cargo `http.timeout` (default 30s) — the cargo-side equivalent of the existing `scan_budget < pip timeout` rule (design spec, "Budget").
- A version is only ever forwarded to cargo's index response if it is CVE-clean **and** (AI-review-cached-passed **or** covered by a qualifying cargo-vet audit) (design spec, "The index response is the gate" / "A known-good fast path").
- Yanked versions are excluded from AI-review cascade candidate selection entirely (design spec, "Decided by the author").
- Org plugins gate the `.crate` download, not the index response, and run exactly once per artifact hash (design spec, "Plugins run at fetch, not at add").
- The cargo-vet fast path substitutes only for AI review — never for CVE filtering, never for the plugin gate (design spec, "Constraints").
- No `cargo` wrapper, shell alias, or shim binary anywhere in this plan (design spec, "Non-goals").
- This ships as a second deployment of the existing binary (new config fields, new bootstrap path), not a second ecosystem multiplexed into one running process (design spec, "Deployment").

## Review Focus

- **A crate with zero published versions that pass CVE filtering** (e.g. every version is advisory-blocked). The index response must still be well-formed (an empty version list, not an error), and `cargo add` must fail the way it does for a genuinely nonexistent crate, not hang or 500. Pinned to Task 4's cascade tests and Task 6's handler tests.
- **A crate whose newest version is yanked and whose only non-yanked version is also the one already cached as AI-review-failed.** The cascade must not get stuck re-selecting the yanked version as "newest" forever, and must correctly fall through to "nothing forwardable" rather than looping. Pinned to Task 4.
- **Two concurrent `cargo add` requests for the same never-before-seen crate.** Without dedup, both would independently fetch and AI-review the same candidate version, doubling AI spend and sandbox load for one real need. Pinned to Task 5 (the orchestration task), reusing the existing `ScanCoordinator` single-flight pattern `src/scan/coordinator.rs` already provides for the PyPI path.
- **A `config.json` or per-crate index fetch that 404s or times out partway through a cascade already holding cached-good versions from earlier requests.** The response must fall back to what's already known-good rather than discarding it, and must not mark previously-passed versions as newly bad. Pinned to Task 3 (upstream client error mapping) and Task 5.
- **A crate name that collides under crates.io's hyphen/underscore equivalence** (`serde_json` vs `serde-json` naming through to the advisory mirror and the cargo-vet store, both keyed by normalized name) — a lookup using the wrong form must still find the row. Pinned to Task 1 (normalization) and Task 2 (cargo-vet store lookups use the same normalizer).

---

### Task 1: SemVer advisory matching, and an ecosystem-pluggable OSV sync

**Files:**
- Create: `src/advisory/matching_semver.rs`
- Create: `src/ecosystem/cargo/mod.rs` (just `pub fn normalize_name(name: &str) -> String` for now; later tasks add to this module)
- Modify: `src/advisory/osv.rs` (generalize `parse_osv` and `OsvSync`)
- Modify: `src/advisory/mod.rs` (add `pub mod matching_semver;`)
- Modify: `Cargo.toml` (add `semver = "1"`)
- Test: `tests/advisory_matching_semver.rs`
- Test: `tests/advisory_osv_cargo.rs`

**Interfaces:**
- Consumes: `crate::advisory::{Advisory, VersionRange}` (unchanged), `crate::db::advisory::AdvisoryStore` (unchanged).
- Produces: `crate::advisory::matching_semver::affects(adv: &Advisory, version: &str) -> bool` — same signature and semantics as the existing `crate::advisory::matching::affects`, used by every later task that needs to CVE-filter a cargo version. `crate::ecosystem::cargo::normalize_name(name: &str) -> String`, used by Task 2's cargo-vet store and Task 3's upstream client. `crate::advisory::osv::OsvSync::sync(&self, ecosystem: &str, normalize: impl Fn(&str) -> String + Copy) -> anyhow::Result<usize>` — the generalized sync Task 11's cargo ticker calls directly.

- [ ] **Step 1: Write the failing tests for `normalize_name`**

```rust
// src/ecosystem/cargo/mod.rs, #[cfg(test)] mod tests
#[test]
fn normalize_name_lowercases_and_treats_underscore_as_hyphen() {
    assert_eq!(normalize_name("Serde_JSON"), "serde-json");
    assert_eq!(normalize_name("serde-json"), "serde-json");
}
```

- [ ] **Step 2: Run it to verify it fails** — `cargo test normalize_name` — FAIL, function does not exist.

- [ ] **Step 3: Implement `normalize_name`** in `src/ecosystem/cargo/mod.rs`: lowercase the input, then replace every `_` with `-`. Document (one line) that this mirrors crates.io's own name-collision rule, not PEP 503's.

- [ ] **Step 4: Run it to verify it passes.**

- [ ] **Step 5: Write the failing SemVer matching tests** in `tests/advisory_matching_semver.rs`, exercising the PEP-440-vs-SemVer divergence the design doc flags:

```rust
#[test]
fn a_prerelease_sorts_below_its_final_release() {
    // semver: 2.0.0-rc.1 < 2.0.0, same ordering direction PEP 440 uses,
    // but via different parsing — this pins that the SemVer path is
    // actually exercised, not accidentally delegating to pep440_rs.
    let adv = advisory_with_range(Some("1.0.0"), Some("2.0.0"));
    assert!(supply_chain_scanner::advisory::matching_semver::affects(&adv, "1.5.0"));
    assert!(!supply_chain_scanner::advisory::matching_semver::affects(&adv, "2.0.0-rc.1"));
}

#[test]
fn an_unparseable_version_fails_closed_against_a_range() {
    let adv = advisory_with_range(Some("1.0.0"), None);
    assert!(supply_chain_scanner::advisory::matching_semver::affects(&adv, "not-a-version"));
}

#[test]
fn an_enumerated_version_falls_back_to_a_trimmed_case_insensitive_string_compare_when_unparseable() {
    let adv = advisory_with_versions(vec!["Weird Build".to_string()]);
    assert!(supply_chain_scanner::advisory::matching_semver::affects(&adv, "weird build"));
}
```

(`advisory_with_range`/`advisory_with_versions` are small local fixture builders the implementer writes, matching the shape `tests/advisory_matching.rs`'s existing PEP 440 tests already use for `advisory::matching::affects` — same `Advisory`/`VersionRange` struct, so the fixtures are structurally identical.)

- [ ] **Step 6: Run to verify failure**, then **implement `src/advisory/matching_semver.rs`**: a direct structural mirror of `src/advisory/matching.rs`'s `affects`/`range_affects`, parsing with `semver::Version::parse` instead of `pep440_rs::Version::from_str`. Same fail-closed rules verbatim: an unparseable `version` against a `ranges`-bearing advisory is affected; an unparseable range bound is treated as satisfied, not disproving; an unparseable enumerated entry falls back to a trimmed case-insensitive string compare.

- [ ] **Step 7: Run to verify it passes.**

- [ ] **Step 8: Write the failing test for the generalized OSV sync** in `tests/advisory_osv_cargo.rs`, mirroring whatever shape `tests/advisory_osv.rs` already uses for `sync_pypi` (a wiremock server serving a zip, asserting the store ends up populated) but calling the new general entry point:

```rust
#[tokio::test]
async fn sync_populates_the_crates_io_ecosystem_under_its_own_normalizer() {
    // ... wiremock server serving a one-entry OSV zip naming package "Serde_JSON" ...
    let count = sync.sync("crates.io", supply_chain_scanner::ecosystem::cargo::normalize_name).await.unwrap();
    assert_eq!(count, 1);
    let stored = store.for_package("crates.io", "serde-json").unwrap();
    assert_eq!(stored.len(), 1, "the normalized name must be the lookup key");
}
```

- [ ] **Step 9: Run to verify failure, then generalize `src/advisory/osv.rs`.** `parse_osv` gains a `normalize: impl Fn(&str) -> String` parameter, used where it currently calls the hardcoded `crate::ecosystem::pypi::index::normalize_name`. `OsvSync` gains `pub async fn sync(&self, ecosystem: &str, normalize: impl Fn(&str) -> String + Copy) -> anyhow::Result<usize>`, replacing the hardcoded `PYPI_ECOSYSTEM`/`store.replace_all("pypi", ...)` call with the passed-in `ecosystem`/`normalize`. `sync_pypi` becomes `pub async fn sync_pypi(&self) -> anyhow::Result<usize> { self.sync("pypi", pypi_normalize).await }` where `pypi_normalize` wraps the existing `crate::ecosystem::pypi::index::normalize_name`, so every existing `sync_pypi` caller and test keeps compiling unchanged.

- [ ] **Step 10: Run every existing `advisory`/`osv` test plus the new ones; all green.**

- [ ] **Step 11: Commit**

```bash
git add Cargo.toml src/advisory/matching_semver.rs src/advisory/osv.rs src/advisory/mod.rs \
        src/ecosystem/cargo/mod.rs tests/advisory_matching_semver.rs tests/advisory_osv_cargo.rs
git commit -m "feat(advisory): add SemVer matching and a generalized, ecosystem-pluggable OSV sync"
```

---

### Task 2: The cargo-vet audit store and coverage query

**Files:**
- Create: `src/cargovet/mod.rs`
- Create: `src/cargovet/parse.rs`
- Create: `src/db/cargo_vet.rs`
- Modify: `src/db/mod.rs` (register the new store module)
- Modify: `src/db/migrations.rs` (new migration — follow the existing numbered-migration pattern this file already uses for `advisories`/`reviews`)
- Test: `tests/cargo_vet.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `crate::cargovet::parse::parse_audits_toml(toml: &str, source: &str) -> anyhow::Result<Vec<AuditEntry>>` and the `AuditEntry` struct; `crate::db::cargo_vet::CargoVetStore::{new, replace_source, covers}`; `crate::cargovet::CargoVetSync::{new, sync_all}`. Task 5's orchestration calls `CargoVetStore::covers` directly; Task 11's ticker calls `CargoVetSync::sync_all`.

**Scope note (carried from the design doc's "Left to the builder"):** this task resolves only *full* audits (an entry naming a `version` directly). Delta-audit chains (an entry naming a `delta` from one version to another, requiring a walk back to a full audit) are out of scope for this plan — `parse_audits_toml` parses delta entries into `AuditEntry::Delta` so they are not silently dropped, but `covers` never treats a delta entry as sufficient on its own. A crate covered only by a delta chain falls through to AI review, exactly like a crate with no audit at all.

- [ ] **Step 1: Write the failing parser tests**

```rust
// tests/cargo_vet.rs
const SAMPLE_AUDITS_TOML: &str = r#"
[[audits.demo-crate]]
version = "1.2.3"
who = "Jane Auditor <jane@example.com>"
criteria = "safe-to-deploy"

[[audits.demo-crate]]
delta = "1.2.3 -> 1.3.0"
who = "Jane Auditor <jane@example.com>"
criteria = "safe-to-run"
"#;

#[test]
fn parses_a_full_audit_entry() {
    let entries = supply_chain_scanner::cargovet::parse::parse_audits_toml(SAMPLE_AUDITS_TOML, "mozilla").unwrap();
    let full = entries.iter().find(|e| matches!(e, AuditEntry::Full { .. })).unwrap();
    // package "demo-crate", version "1.2.3", criteria contains "safe-to-deploy",
    // who contains "Jane Auditor <jane@example.com>", source == "mozilla"
}

#[test]
fn parses_a_delta_audit_entry_without_treating_it_as_full() {
    let entries = supply_chain_scanner::cargovet::parse::parse_audits_toml(SAMPLE_AUDITS_TOML, "mozilla").unwrap();
    assert!(entries.iter().any(|e| matches!(e, AuditEntry::Delta { .. })));
}
```

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `AuditEntry` and `parse_audits_toml`** in `src/cargovet/parse.rs`:

```rust
pub enum AuditEntry {
    Full { package: String, version: String, who: Vec<String>, criteria: Vec<String>, source: String },
    Delta { package: String, from: String, to: String, who: Vec<String>, criteria: Vec<String>, source: String },
}
pub fn parse_audits_toml(toml: &str, source: &str) -> anyhow::Result<Vec<AuditEntry>>
```

`who` and `criteria` in real `audits.toml` files are each either a single TOML string or an array of strings (cargo-vet's own format allows both); deserialize into a type that accepts either and normalizes to `Vec<String>` (a `#[serde(deserialize_with = ...)]` helper, or an untagged enum `StringOrVec`).

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Write the failing migration + store tests**

```rust
#[test]
fn covers_is_true_for_a_full_audit_meeting_the_criterion_from_a_trusted_source() {
    let store = fresh_store();
    store.replace_source("mozilla", &[AuditEntry::Full {
        package: "demo-crate".into(), version: "1.2.3".into(),
        who: vec!["Jane Auditor <jane@example.com>".into()],
        criteria: vec!["safe-to-deploy".into()], source: "mozilla".into(),
    }]).unwrap();

    assert!(store.covers("demo-crate", "1.2.3", "safe-to-deploy", &[]).unwrap());
}

#[test]
fn covers_is_false_when_the_criterion_is_not_met() {
    // an entry certifying only "safe-to-run" does not cover a "safe-to-deploy" requirement
}

#[test]
fn covers_respects_a_non_empty_trusted_reviewers_allowlist() {
    // the same entry as above: covers(...) is true with an empty allowlist,
    // false when the allowlist contains a name that does not match `who`,
    // true again when the allowlist contains the matching `who` entry
}

#[test]
fn covers_normalizes_the_package_name() {
    // stored under "demo-crate" (via replace_source), looked up as "Demo_Crate",
    // using crate::ecosystem::cargo::normalize_name — must still match
}

#[test]
fn a_delta_only_entry_never_satisfies_covers() {
    // store only an AuditEntry::Delta for a package+version; covers(...) is false
}

#[test]
fn replace_source_is_scoped_to_its_own_source_and_does_not_touch_others() {
    // replace_source("mozilla", [...]); replace_source("google", [...]);
    // re-calling replace_source("mozilla", []) must clear only mozilla's rows
}
```

- [ ] **Step 6: Run to verify failure, then add the migration.** New table `cargo_vet_audits(source TEXT, package TEXT, version TEXT, who_json TEXT, criteria_json TEXT, PRIMARY KEY (source, package, version, who_json))` — follow `src/db/migrations.rs`'s existing numbered-migration style exactly (look at how the `advisories`/`reviews` migrations are structured there and match it).

- [ ] **Step 7: Implement `CargoVetStore`** in `src/db/cargo_vet.rs`:

```rust
pub struct CargoVetStore { db: Db }
impl CargoVetStore {
    pub fn new(db: Db) -> Self;
    pub fn replace_source(&self, source: &str, entries: &[AuditEntry]) -> anyhow::Result<usize>;
    pub fn covers(&self, package: &str, version: &str, required_criterion: &str, trusted_reviewers: &[String]) -> anyhow::Result<bool>;
}
```

`replace_source` deletes every row for `source` then inserts every `Full` entry from `entries` (delta entries are parsed but not persisted, per the scope note above — nothing queries them). `covers` normalizes `package` with `crate::ecosystem::cargo::normalize_name`, looks up matching rows, and returns true if any row's `criteria` contains `required_criterion` and (`trusted_reviewers` is empty, or any of the row's `who` entries appears in `trusted_reviewers`).

- [ ] **Step 8: Run to verify it passes.**

- [ ] **Step 9: Write and implement `CargoVetSync`** in `src/cargovet/mod.rs`, mirroring `OsvSync`'s shape: fetches each configured source URL's `audits.toml` over HTTP, parses with `parse_audits_toml`, calls `store.replace_source`. `sync_all(&self) -> anyhow::Result<usize>` returns the total entries stored across every configured source; one source's fetch failure is logged and skipped rather than aborting the others (unlike `OsvSync`, where a bad feed must not touch the existing mirror — here, each source is independent, so a down Mozilla endpoint must not block Google's or the org's own from updating). Test: a wiremock server with two sources, one 500ing — `sync_all` still updates the other and returns its count.

- [ ] **Step 10: Run full `cargo_vet` test file; all green.**

- [ ] **Step 11: Commit**

```bash
git add src/cargovet src/db/cargo_vet.rs src/db/mod.rs src/db/migrations.rs tests/cargo_vet.rs
git commit -m "feat(cargovet): add the audits.toml parser, store, and multi-source sync"
```

---

### Task 3: The cargo registry upstream client

**Files:**
- Create: `src/ecosystem/cargo/upstream.rs`
- Create: `src/ecosystem/cargo/index.rs`
- Modify: `src/ecosystem/cargo/mod.rs` (wire the two new submodules, add `validate_name`)
- Test: `tests/ecosystem_cargo_upstream.rs`

**Interfaces:**
- Consumes: `crate::config::DownloadLimits` (reused verbatim for the `.crate` download's stall/duration/size caps, same struct the PyPI `Upstream` already takes).
- Produces: `crate::ecosystem::cargo::index::{CargoIndexEntry, index_path_for, InvalidName, validate_name}`; `crate::ecosystem::cargo::upstream::{CargoUpstream, UpstreamError}`. Task 4's cascade logic consumes `CargoIndexEntry`; Task 5's orchestration consumes `CargoUpstream`.

- [ ] **Step 1: Write the failing prefix-path tests**, using the Cargo Book's own documented examples:

```rust
// src/ecosystem/cargo/index.rs, #[cfg(test)] mod tests
#[test]
fn a_one_character_name_uses_the_1_prefix() {
    assert_eq!(index_path_for("a"), "1/a");
}
#[test]
fn a_two_character_name_uses_the_2_prefix() {
    assert_eq!(index_path_for("ab"), "2/ab");
}
#[test]
fn a_three_character_name_uses_the_3_prefix_plus_first_letter() {
    assert_eq!(index_path_for("abc"), "3/a/abc");
}
#[test]
fn a_longer_name_uses_the_first_four_characters_as_two_two_character_prefixes() {
    assert_eq!(index_path_for("cargo"), "ca/rg/cargo");
}
```

- [ ] **Step 2: Run to verify failure, then implement `index_path_for(name: &str) -> String`** per the rules above (names are pre-lowercased by the caller via `normalize_name` before this function runs — `index_path_for` itself does no case folding).

- [ ] **Step 3: Run to verify it passes.**

- [ ] **Step 4: Write the failing `validate_name` tests**, mirroring `crate::ecosystem::pypi::index::validate_name`'s existing shape and `InvalidName` error type but against crates.io's rules (ASCII alphanumeric, `-`, `_`; must start with an ASCII letter; non-empty; a documented max length):

```rust
#[test]
fn validate_name_accepts_an_ordinary_name() {
    assert_eq!(validate_name("serde_json").unwrap(), "serde_json");
}
#[test]
fn validate_name_rejects_a_name_with_a_disallowed_character() {
    assert!(validate_name("serde/json").is_err());
}
#[test]
fn validate_name_rejects_a_name_not_starting_with_a_letter() {
    assert!(validate_name("1crate").is_err());
}
```

- [ ] **Step 5: Run to verify failure, then implement `validate_name`/`InvalidName`.**

- [ ] **Step 6: Run to verify it passes.**

- [ ] **Step 7: Write the failing `CargoIndexEntry` JSON-lines parsing test**

```rust
#[test]
fn parses_one_json_line_per_version_ignoring_unknown_fields() {
    let body = "{\"name\":\"demo\",\"vers\":\"1.0.0\",\"cksum\":\"deadbeef\",\"yanked\":false,\"deps\":[]}\n\
                {\"name\":\"demo\",\"vers\":\"1.1.0\",\"cksum\":\"abc123\",\"yanked\":true,\"deps\":[]}\n";
    let entries = parse_index_lines(body).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].vers, "1.1.0");
    assert!(entries[1].yanked);
}
```

- [ ] **Step 8: Run to verify failure, then implement `CargoIndexEntry` (`#[derive(Deserialize)]`, fields `name: String, vers: String, cksum: String, #[serde(default)] yanked: bool`, unrecognized fields ignored by serde's default behavior) and `parse_index_lines(body: &str) -> anyhow::Result<Vec<CargoIndexEntry>>`** (split on `\n`, skip empty lines, `serde_json::from_str` each).

- [ ] **Step 9: Run to verify it passes.**

- [ ] **Step 10: Write the failing `CargoUpstream` integration tests** against a wiremock server, mirroring how `tests/ecosystem_pypi_upstream.rs` already stands up a fake PyPI for the existing `Upstream`:

```rust
#[tokio::test]
async fn index_entries_fetches_and_parses_the_per_crate_index_file() {
    // wiremock: GET /ca/rg/cargo -> the two-line body from Step 7's fixture
    // CargoUpstream::index_entries("cargo") returns the same two entries
}

#[tokio::test]
async fn index_entries_maps_a_404_to_upstream_error_not_found() {
    // GET /.../missing -> 404; index_entries returns Err(UpstreamError::NotFound)
}

#[tokio::test]
async fn download_crate_writes_the_expanded_dl_template_and_returns_its_sha256() {
    // GET /config.json -> {"dl":"<server>/crates/{crate}/{version}/download"}
    // GET /crates/demo/1.0.0/download -> fixed bytes
    // download_crate("demo", "1.0.0", dest) writes those bytes to dest and
    // returns their lowercase hex sha256
}

#[tokio::test]
async fn download_crate_respects_the_configured_stall_timeout() {
    // mirrors the existing PyPI upstream's own stall-timeout test shape —
    // a response that stops sending bytes mid-stream is abandoned, not hung
}
```

- [ ] **Step 11: Run to verify failure, then implement `CargoUpstream`**:

```rust
pub enum UpstreamError { NotFound, Http(String), Io(String) /* mirror pypi::upstream::UpstreamError's shape */ }
pub struct CargoUpstream { /* reqwest::Client, index_base: Url, download_limits: DownloadLimits */ }
impl CargoUpstream {
    pub fn with_limits(index_base: Url, download_limits: &DownloadLimits) -> anyhow::Result<Self>;
    pub async fn index_entries(&self, name: &str) -> Result<Vec<CargoIndexEntry>, UpstreamError>;
    pub async fn download_crate(&self, name: &str, version: &str, dest: &Path) -> Result<String, UpstreamError>;
}
```

`download_crate` fetches `config.json` (cached after the first successful fetch — do not refetch it on every call; a simple `OnceCell`/`tokio::sync::OnceCell` inside `CargoUpstream` is sufficient), expands its `dl` template's `{crate}`/`{version}`/`{prefix}` markers, and streams the response to `dest` applying the same stall-timeout/max-duration/max-size enforcement the existing PyPI `Upstream::download` already implements — read that function's body first and match its approach rather than re-deriving it.

- [ ] **Step 12: Run to verify it passes; run the whole `ecosystem_cargo_upstream` test file.**

- [ ] **Step 13: Commit**

```bash
git add src/ecosystem/cargo tests/ecosystem_cargo_upstream.rs
git commit -m "feat(ecosystem): add the cargo sparse-registry upstream client"
```

---

### Task 4: The cascade decision core (pure logic)

**Files:**
- Create: `src/scan/cargo_cascade.rs`
- Modify: `src/scan/mod.rs` (add `pub mod cargo_cascade;`)
- Test: inline `#[cfg(test)] mod tests` in `src/scan/cargo_cascade.rs` (pure logic, no I/O — matches this crate's existing convention of unit-testing pure decision functions inline, e.g. `src/advisory/matching.rs`'s own tests)

**Interfaces:**
- Consumes: `crate::ecosystem::cargo::index::CargoIndexEntry` (Task 3).
- Produces: `CascadeInput`, `ReviewStatus`, `NextStep`, `plan_cascade`. Task 5's orchestration is the only caller of `plan_cascade`; it owns fetching the real data this task's tests stub by hand.

- [ ] **Step 1: Write the failing test for the simplest case — nothing cached, one clean candidate**

```rust
fn entry(vers: &str, yanked: bool) -> CargoIndexEntry { /* helper */ }

#[test]
fn with_nothing_cached_the_newest_non_yanked_cve_clean_version_needs_review() {
    let input = CascadeInput {
        entries: vec![entry("1.0.0", false), entry("0.9.0", false)],
        cve_blocked: HashSet::new(),
        review_status: HashMap::new(),
        vet_covered: HashSet::new(),
    };
    assert_eq!(plan_cascade(&input), NextStep::NeedsReview("1.0.0".to_string()));
}
```

- [ ] **Step 2: Run to verify failure (types do not exist yet).**

- [ ] **Step 3: Implement the types and a first-pass `plan_cascade`**:

```rust
pub struct CascadeInput {
    pub entries: Vec<CargoIndexEntry>,
    pub cve_blocked: HashSet<String>,   // versions CVE-filtered out
    pub review_status: HashMap<String, ReviewStatus>, // AI-review cache
    pub vet_covered: HashSet<String>,   // versions covered by a qualifying cargo-vet audit
}
pub enum ReviewStatus { Passed, Failed }
#[derive(Debug, PartialEq)]
pub enum NextStep {
    Forward(Vec<String>),       // the final, forwardable version list
    NeedsReview(String),        // fetch and AI-review this version next
}
pub fn plan_cascade(input: &CascadeInput) -> NextStep
```

Algorithm: filter `entries` to non-yanked and not in `cve_blocked`; among those, a version is *forwardable* if it's in `vet_covered` or `review_status == Some(Passed)`. If every surviving version is forwardable, return `Forward` with all of them (sorted newest-first — use `semver::Version` for the sort, matching Task 1's version semantics). Otherwise, pick the single newest surviving version that is neither forwardable nor `Some(Failed)` and return `NeedsReview` for it. If every non-forwardable survivor is `Some(Failed)`, return `Forward` with just the forwardable ones (possibly empty) — there is nothing left to try.

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Write and make pass, one at a time, the remaining cascade tests** (each its own `#[test]`, implementing only what the previous ones don't already cover):

```rust
#[test]
fn a_cargo_vet_covered_version_is_forwarded_without_ever_needing_review() { /* ... */ }

#[test]
fn a_cve_blocked_newest_version_is_skipped_in_favor_of_an_older_clean_one() { /* ... */ }

#[test]
fn a_yanked_newest_version_is_never_selected_as_a_review_candidate() {
    // entries: 1.1.0 yanked, 1.0.0 not — plan_cascade must pick 1.0.0, never 1.1.0,
    // even though 1.1.0 is numerically newest and CVE-clean
}

#[test]
fn after_the_newest_candidate_fails_review_the_cascade_moves_to_the_next_newest() {
    let mut review_status = HashMap::new();
    review_status.insert("1.0.0".to_string(), ReviewStatus::Failed);
    let input = CascadeInput {
        entries: vec![entry("1.0.0", false), entry("0.9.0", false)],
        cve_blocked: HashSet::new(), review_status, vet_covered: HashSet::new(),
    };
    assert_eq!(plan_cascade(&input), NextStep::NeedsReview("0.9.0".to_string()));
}

#[test]
fn when_every_candidate_has_failed_review_the_forwardable_list_is_whatever_is_left_even_if_empty() {
    // both versions Failed, nothing vet-covered or Passed -> Forward(vec![])
}

#[test]
fn a_crate_with_no_cve_clean_versions_at_all_forwards_an_empty_list_not_an_error() {
    // Review Focus case: every version CVE-blocked -> Forward(vec![]), never a panic or Err
}
```

- [ ] **Step 6: Run the whole file; all green.**

- [ ] **Step 7: Commit**

```bash
git add src/scan/cargo_cascade.rs src/scan/mod.rs
git commit -m "feat(scan): add the pure cargo cascade decision logic"
```

---

### Task 5: Cascade orchestration — wiring the cascade against real I/O under the shared deadline

**Files:**
- Create: `src/scan/cargo.rs`
- Modify: `src/scan/mod.rs` (add `pub mod cargo;`)
- Test: `tests/scan_cargo.rs`

**Interfaces:**
- Consumes: `crate::scan::cargo_cascade::{CascadeInput, NextStep, ReviewStatus, plan_cascade}` (Task 4); `crate::ecosystem::cargo::upstream::CargoUpstream` (Task 3); `crate::advisory::matching_semver::affects` and `crate::db::advisory::AdvisoryStore` (Task 1); `crate::db::cargo_vet::CargoVetStore` (Task 2); `crate::ai::{AiReviewer, ReviewOutcome}` (existing); `crate::db::verdict::VerdictStore`/`crate::model::{ArtifactKey, Verdict}` (existing); `crate::scan::coordinator::ScanCoordinator` (existing, for the single-flight dedup the Review Focus section calls for).
- Produces: `CargoScanner` and `CargoIndexDecision`, which Task 6's HTTP handler is the sole caller of.

```rust
pub enum CargoIndexDecision {
    Entries(Vec<CargoIndexEntry>), // forwardable, newest-first
    InProgress,                     // shared deadline ran out mid-cascade; retry shortly
}
pub struct CargoScanner { /* ... */ }
impl CargoScanner {
    pub fn new(/* upstream, advisory_store, vet_store, verdict_store, ai_reviewer, cfg, coordinator */) -> Self;
    pub async fn decide_index(&self, package: &str) -> CargoIndexDecision;
}
```

- [ ] **Step 1: Write the failing single-candidate-passes test**, against a wiremock crates.io plus a stub `AiReviewer`-shaped dependency. Reuse this crate's existing pattern for standing in for the reviewer: `tests/scan.rs`/`tests/ai_review.rs` already define a `StubProvider` behind `ChatProvider`; build a real `AiReviewer` here wired to a stub provider that always replies clean, exactly as those tests already do, rather than inventing a second reviewer seam.

```rust
#[tokio::test]
async fn a_never_before_seen_crate_with_one_clean_version_is_forwarded() {
    // wiremock config.json + index file for "demo" with one version 1.0.0;
    // empty advisory mirror; empty cargo-vet store; real AiReviewer wired to
    // a stub provider that always replies clean.
    let decision = scanner.decide_index("demo").await;
    assert_eq!(decision, CargoIndexDecision::Entries(vec![/* the 1.0.0 entry */]));
}
```

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `decide_index`'s skeleton**: fetch `self.upstream.index_entries(package)`; on `Err(UpstreamError::NotFound)`, return `Entries(vec![])`; on any other upstream error, log and return `Entries(vec![])` built only from whatever this package's already-cached-good versions are known to be (Review Focus: don't discard known-good state on a transient upstream blip — reuse `VerdictStore::get` per candidate the same way `Scanner::serve_known_clean` already re-checks a stored verdict). Look up CVE-blocked versions via `AdvisoryStore::for_package("cargo", package)` filtered through `matching_semver::affects` against the org's `CveLine`/`Policy::blocks_advisory` (reuse `Policy` exactly as `Scanner` does — do not re-implement the severity/fix-available rule). Look up cargo-vet coverage via `CargoVetStore::covers` for each surviving version against the configured `required_criterion`/`trusted_reviewers`. Look up AI-review cache via `VerdictStore::get` per candidate (a cargo `ArtifactKey` uses `filename` as the version string again, or a fixed sentinel — see Task 7's schema note; pick one and document it in a one-line comment, since Task 7 depends on this choice). Build the `CascadeInput` and call `plan_cascade`.

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Write and implement the fetch-and-review loop** for `NextStep::NeedsReview`: download the candidate's `.crate` via `self.upstream.download_crate`, unpack it (reuse `crate::plugin::unpack` — a `.crate` is a gzipped tarball, already one of `unpack`'s supported formats; confirm against `src/plugin/unpack.rs`'s format detection and extend it if `.crate`'s extension isn't already recognized), run `self.ai_reviewer.review(...)`, store the resulting verdict via `VerdictStore::put`, update the in-memory cache, and re-call `plan_cascade` — looping until `Forward` or the shared deadline (an `Instant`/`Duration` split the same way `AiReviewer::review` already shares its own deadline across the collector run and the provider call) runs out, in which case return `CargoIndexDecision::InProgress`.

```rust
#[tokio::test]
async fn the_cascade_moves_past_a_version_that_fails_review() {
    // two versions; stub provider blocks the newer one, passes the older;
    // decide_index forwards only the older version
}

#[tokio::test]
async fn the_cascade_returns_in_progress_rather_than_hanging_past_its_shared_budget() {
    // a stub provider configured to sleep past the configured deadline;
    // decide_index returns CargoIndexDecision::InProgress, and the elapsed
    // time stays within the configured budget plus a small tolerance
}
```

- [ ] **Step 6: Run to verify both pass.**

- [ ] **Step 7: Write and implement the concurrent-dedup test** (Review Focus item 3), reusing `ScanCoordinator::start_or_join` exactly as `Scanner::scan_with_budget` already does — key the coordinator by `(package, candidate_version)` rather than by sha256, since the thing being deduplicated here is "don't review the same candidate twice," not "don't download the same bytes twice":

```rust
#[tokio::test]
async fn two_concurrent_requests_for_the_same_never_seen_crate_only_review_the_candidate_once() {
    // a provider stub that counts invocations; two concurrent decide_index
    // calls for the same package; assert the provider was called exactly once
}
```

- [ ] **Step 8: Run to verify it passes; run the whole `scan_cargo` test file.**

- [ ] **Step 9: Commit**

```bash
git add src/scan/cargo.rs src/scan/mod.rs tests/scan_cargo.rs
git commit -m "feat(scan): wire the cargo cascade against real advisories, cargo-vet, and AI review"
```

---

### Task 6: HTTP — the sparse-index handlers

**Files:**
- Create: `src/http/cargo_index.rs`
- Modify: `src/http/mod.rs` (register the new routes, extend `AppState` or add a parallel `CargoAppState` — see Step 3)
- Test: `tests/http_cargo_index.rs`

**Interfaces:**
- Consumes: `crate::scan::cargo::{CargoScanner, CargoIndexDecision}` (Task 5); `crate::ecosystem::cargo::index::validate_name` (Task 3).
- Produces: `cargo_config_handler`, `cargo_index_handler`, both wired into a router this task adds.

- [ ] **Step 1: Write the failing `config.json` test**

```rust
#[tokio::test]
async fn config_json_reports_the_configured_dl_template() {
    let response = harness.get("/config.json").await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await;
    assert!(body["dl"].as_str().unwrap().contains("{crate}"));
}
```

- [ ] **Step 2: Run to verify failure, then implement `cargo_config_handler`**, serving the static `config.json` this deployment's own `dl`/`api` templates (pointing back at this proxy's own download route, not at crates.io's — cargo must come back to this proxy for the `.crate` file too, so Task 8's plugin gate is actually in the loop).

- [ ] **Step 3: Run to verify it passes.**

- [ ] **Step 4: Decide and document `AppState`'s shape for this deployment.** The existing `AppState` (`src/http/mod.rs`) carries a `scanner: Arc<Scanner>` and `ecosystem: Arc<dyn Ecosystem>` — both PyPI-shaped per this plan's own architecture note. Add a sibling `CargoAppState { cargo_scanner: Arc<CargoScanner>, config: Arc<ConfigHandle> }` rather than widening `AppState`: a cargo deployment never boots the PyPI `Scanner`/`Ecosystem` at all (per the design doc's "second deployment," there is no process that needs both), so forcing one shared state struct would carry fields that are always unused on one side or the other.

- [ ] **Step 5: Write the failing per-crate index test**

```rust
#[tokio::test]
async fn the_index_route_serves_the_cascades_forwarded_entries_as_json_lines() {
    let response = harness.get("/ca/rg/cargo").await; // name "cargo" -> prefix ca/rg
    assert_eq!(response.status(), 200);
    let body = response.text().await;
    assert_eq!(body.lines().count(), /* however many the stub cascade forwards */);
}

#[tokio::test]
async fn an_invalid_crate_name_in_the_path_is_a_400_not_a_500() {
    let response = harness.get("/../../etc/passwd").await;
    assert_eq!(response.status(), 400);
}
```

- [ ] **Step 6: Run to verify failure, then implement `cargo_index_handler`**: extract the crate name from the path, `validate_name` it (400 on failure, mirroring `simple_handler`'s own `bad_request_response` pattern), call `cargo_scanner.decide_index`, and render `CargoIndexDecision::Entries` as newline-delimited JSON (one object per line: `name`, `vers`, `cksum`, `yanked`, an empty `deps` array — cargo requires the field to exist even when this proxy doesn't model dependency resolution itself, since dependency resolution for *this* crate's own deps happens via cargo re-querying this same index for each of them). Map `CargoIndexDecision::InProgress` to a `503` (mirroring how the PyPI path maps `Decision::InProgress` to a retryable status — check `src/http/artifact.rs`/`refusal.rs` for the exact status code used there and match it).

- [ ] **Step 7: Run to verify it passes; run the whole file.**

- [ ] **Step 8: Commit**

```bash
git add src/http/cargo_index.rs src/http/mod.rs tests/http_cargo_index.rs
git commit -m "feat(http): serve the cargo sparse index, gated on the cascade"
```

---

### Task 7: The verdict schema's "index-admitted vs. fully-scanned" state

**Files:**
- Modify: `src/db/migrations.rs` (new migration)
- Modify: `src/db/verdict.rs` (new column/method)
- Test: extend `tests/db_verdict.rs` (or wherever the existing `VerdictStore` tests live)

**Interfaces:**
- Consumes: nothing new.
- Produces: `VerdictStore::mark_plugin_checked(key: &ArtifactKey, fingerprint: &str) -> anyhow::Result<()>` and `VerdictStore::is_plugin_checked(key: &ArtifactKey, fingerprint: &str) -> anyhow::Result<bool>`, consumed by Task 8's download handler (a `Clean` verdict from Task 5's cascade is "index-admitted"; Task 8 calls `mark_plugin_checked` only once the plugin set has actually passed, and checks `is_plugin_checked` before deciding whether to re-run plugins on a later download).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_freshly_stored_clean_verdict_is_not_yet_plugin_checked() {
    store.put(&key, &Verdict::Clean, "fp").unwrap();
    assert!(!store.is_plugin_checked(&key, "fp").unwrap());
}

#[test]
fn mark_plugin_checked_flips_it_true() {
    store.put(&key, &Verdict::Clean, "fp").unwrap();
    store.mark_plugin_checked(&key, "fp").unwrap();
    assert!(store.is_plugin_checked(&key, "fp").unwrap());
}

#[test]
fn is_plugin_checked_is_false_for_a_fingerprint_with_no_stored_verdict_at_all() {
    assert!(!store.is_plugin_checked(&key, "never-scanned-fp").unwrap());
}
```

- [ ] **Step 2: Run to verify failure, then add the migration**: `ALTER TABLE verdicts ADD COLUMN plugin_checked INTEGER NOT NULL DEFAULT 0` — follow `src/db/migrations.rs`'s existing pattern for an additive, backward-compatible column (the PyPI path never reads this column and its existing rows all default to `0`, which is semantically correct for them too, since PyPI's plugin gate already ran before any `Clean` row exists there — this column only ever matters for cargo's two-phase verdicts).

- [ ] **Step 3: Implement the two new `VerdictStore` methods.**

- [ ] **Step 4: Run to verify all three pass; run the whole existing verdict test file to confirm nothing on the PyPI path regressed.**

- [ ] **Step 5: Commit**

```bash
git add src/db/migrations.rs src/db/verdict.rs tests/db_verdict.rs
git commit -m "feat(db): track plugin-checked state separately from the clean verdict"
```

---

### Task 8: HTTP — the `.crate` download handler with the plugin gate

**Files:**
- Create: `src/http/cargo_download.rs`
- Modify: `src/http/mod.rs` (register the route)
- Test: `tests/http_cargo_download.rs`

**Interfaces:**
- Consumes: `crate::plugin::{PluginRunner, unpack}` (existing, unchanged); `crate::db::verdict::VerdictStore`/`crate::model::{ArtifactKey, Verdict}` (existing); `CargoAppState` (Task 6).
- Produces: `cargo_download_handler`, wired into the router.

- [ ] **Step 1: Write the failing first-download-runs-plugins-and-serves test**

```rust
#[tokio::test]
async fn the_first_download_of_a_clean_artifact_runs_plugins_and_serves_the_bytes() {
    // a plugin stub that exits 0; GET the download route; 200, body matches
    // upstream's bytes, and the plugin was invoked exactly once
}

#[tokio::test]
async fn a_plugin_refusal_is_a_403_with_a_reason_phrase_and_a_why_link() {
    // a plugin stub that exits 1 with "malware found" on stdout;
    // the response status is 403 and its reason phrase names the plugin
    // and a /why/<id> link, mirroring crate::http::refusal's existing
    // PyPI-path rendering — reuse that module's rendering function rather
    // than re-deriving the reason-phrase format here
}

#[tokio::test]
async fn a_second_download_of_the_same_artifact_hash_does_not_re_run_plugins() {
    // same version downloaded twice; plugin invocation count stays 1
}
```

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `cargo_download_handler`**: extract crate+version from the path; look up the stored verdict for that `ArtifactKey` (same key scheme Task 5 settled on). If no verdict is stored yet (first touch), download the `.crate` via the same `CargoUpstream` the index path uses, verify its hash against the index's `cksum`, unpack it, run `PluginRunner::run_all` under the configured plugin list, store `Verdict::Clean`/`Verdict::Blocked` accordingly (reusing `crate::http::refusal`'s existing rendering for a `Blocked` response, exactly as `src/http/artifact.rs` already does for PyPI), and on `Clean`, cache and serve the bytes. On a stored verdict already present, serve from cache (or re-download+re-verify-hash if the cache entry is gone) without re-running plugins — mirror `Scanner::fetch_decision`'s cache-first shape rather than re-deriving it.

- [ ] **Step 4: Run to verify all three pass.**

- [ ] **Step 5: Commit**

```bash
git add src/http/cargo_download.rs src/http/mod.rs tests/http_cargo_download.rs
git commit -m "feat(http): gate the .crate download on org plugins, once per artifact"
```

---

### Task 9: Cargo install surface and collector wiring

**Files:**
- Modify: `src/ecosystem/install_surface.rs` (add `CargoInstallSurface`, extend `install_surface_for`)
- Test: add to the existing `#[cfg(test)] mod tests` in `src/ecosystem/install_surface.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `CargoInstallSurface`, and `install_surface_for("cargo")` now returning `Some(Box::new(CargoInstallSurface))`. Consumed by Task 5's call into `crate::ai::collect::collect` (unchanged signature — this task only adds a new `InstallSurface` implementor, exactly as the design doc's "install surface: the whole crate" section describes).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn cargo_install_surface_matches_a_root_build_script() {
    assert!(CargoInstallSurface.is_install_surface(Path::new("build.rs")));
}
#[test]
fn cargo_install_surface_matches_the_root_lib_and_main_entry_points() {
    assert!(CargoInstallSurface.is_install_surface(Path::new("src/lib.rs")));
    assert!(CargoInstallSurface.is_install_surface(Path::new("src/main.rs")));
}
#[test]
fn cargo_install_surface_does_not_match_an_ordinary_module() {
    assert!(!CargoInstallSurface.is_install_surface(Path::new("src/parser.rs")));
}
#[test]
fn cargo_install_surface_rejects_paths_that_escape_the_root() {
    assert!(!CargoInstallSurface.is_install_surface(Path::new("../../etc/passwd")));
}
```

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `CargoInstallSurface`**, structurally mirroring `PyPiInstallSurface`'s own component-rejection loop (reject non-`Normal` path components first, exactly as the existing implementation does) and then checking for an exact match against `build.rs`, `src/lib.rs`, or `src/main.rs` at the root. Document inline (one line, matching the design doc's own framing) that detecting an actual proc-macro entry point beyond `src/lib.rs` would require reading `Cargo.toml`'s content, which this trait's path-only signature cannot do — out of scope here, not a gap introduced by this task.

- [ ] **Step 4: Run to verify all four pass.**

- [ ] **Step 5: Add the one-line branch to `install_surface_for`**:

```rust
"cargo" => Some(Box::new(CargoInstallSurface)),
```

Add a test confirming it: `install_surface_for_cargo_returns_the_cargo_rules` or similar, alongside whatever existing test already covers the `"pypi"` branch.

- [ ] **Step 6: Run the whole file; all green.**

- [ ] **Step 7: Commit**

```bash
git add src/ecosystem/install_surface.rs
git commit -m "feat(ecosystem): recognize build.rs and the crate root as cargo install surface"
```

---

### Task 10: Config for the cargo deployment

**Files:**
- Modify: `src/config.rs` (new `CargoRegistryConfig` top-level table, new fields inside it)
- Modify: `src/policy/mod.rs` (fold the new config into the fingerprint)
- Test: `tests/config_cargo.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `CargoRegistryConfig` on `Config` (parallel to the existing `ai_review: Option<AiReviewConfig>`), consumed by Task 11's bootstrap.

```rust
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CargoRegistryConfig {
    pub upstream_index_url: Url,
    #[serde(with = "humantime_serde", default = "default_cargo_vet_sync_interval")]
    pub cargo_vet_sync_interval: Duration,
    #[serde(default)]
    pub cargo_vet_sources: Vec<CargoVetSource>,
    #[serde(default = "default_required_criterion")]
    pub required_criterion: String,
    #[serde(default)]
    pub trusted_reviewers: Vec<String>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CargoVetSource {
    pub name: String,
    pub url: Url,
}
```

`default_required_criterion` returns `"safe-to-deploy"`, matching the design doc's recommendation for the stricter default while leaving it fully overridable — an org that sets `required_criterion = "safe-to-run"` gets the looser bar, exactly as the design doc's answer to "make the criterion configurable" calls for.

- [ ] **Step 1: Write the failing config-loading tests**, mirroring the existing `tests/config.rs`'s `[ai_review]` test shape:

```rust
#[test]
fn cargo_registry_absent_leaves_none() { /* a config with no [cargo_registry] table -> None */ }

#[test]
fn cargo_registry_minimal_applies_documented_defaults() {
    // required_criterion defaults to "safe-to-deploy", trusted_reviewers defaults to empty,
    // cargo_vet_sources defaults to empty
}

#[test]
fn cargo_registry_accepts_an_explicit_required_criterion_override() {
    // required_criterion = "safe-to-run" loads and is honored verbatim
}

#[test]
fn cargo_registry_accepts_named_cargo_vet_sources() {
    // [[cargo_registry.cargo_vet_sources]] name = "mozilla" url = "https://..." loads correctly
}
```

- [ ] **Step 2: Run to verify failure, then implement** `CargoRegistryConfig`/`CargoVetSource` and add `#[serde(default)] pub cargo_registry: Option<CargoRegistryConfig>` to `Config`.

- [ ] **Step 3: Run to verify all four pass.**

- [ ] **Step 4: Write the failing fingerprint test**, mirroring `src/policy/mod.rs`'s existing `[ai_review]`-affects-the-fingerprint tests:

```rust
#[test]
fn changing_the_required_criterion_changes_the_fingerprint() {
    // two configs identical except required_criterion "safe-to-deploy" vs
    // "safe-to-run" -> policy_fingerprint differs
}
#[test]
fn an_unconfigured_cargo_registry_appends_nothing_to_the_fingerprint() {
    // matches the existing ai_review precedent: absence must not change
    // the digest relative to a build that predates this feature entirely
}
```

- [ ] **Step 5: Run to verify failure, then extend `policy_fingerprint`**: when `cfg.cargo_registry` is present, hash `required_criterion` and, in source-list order, each `CargoVetSource`'s `name` and `url` (not `trusted_reviewers` — narrowing or widening who's trusted is an operational judgment call like the allowlist, not a change to what gets *checked*, so exclude it from the fingerprint exactly as the allowlist itself is excluded. Document this exclusion inline the same way `src/policy/mod.rs` already documents the allowlist's).

- [ ] **Step 6: Run to verify both pass; run the whole `policy` and `config_cargo` test files.**

- [ ] **Step 7: Commit**

```bash
git add src/config.rs src/policy/mod.rs tests/config_cargo.rs
git commit -m "feat(config): add the [cargo_registry] table and fold it into the policy fingerprint"
```

---

### Task 11: Bootstrap wiring and the sync tickers for a cargo deployment

**Files:**
- Modify: `src/http/mod.rs` (a `bootstrap_cargo(config: Config) -> anyhow::Result<CargoWired>` sibling to the existing `bootstrap`, plus its own `router`)
- Modify: `src/main.rs` (dispatch to the cargo bootstrap path when `config.cargo_registry.is_some()` — see Step 1 for the exact rule)
- Test: `tests/http_cargo_bootstrap.rs`

**Interfaces:**
- Consumes: everything from Tasks 1-10.
- Produces: `CargoWired { router, cargo_scanner, cargo_vet_store, reloader }`, this plan's final integration point.

- [ ] **Step 1: Decide and document the dispatch rule.** A single config file has either `[ai_review]`/PyPI fields or `[cargo_registry]`, never both meaningfully in one running process (per the design doc's "second deployment of the same binary" decision) — but `Config` is one struct, so both are technically `Option`-al on it at once. Resolve this the simplest way that matches the design: `main.rs`'s `run` function checks `config.cargo_registry.is_some()` and calls `bootstrap_cargo` instead of `bootstrap` when true; a config file is expected to set `upstream_url` to *something* regardless (the field stays required on `Config`, unused by the cargo path) rather than restructuring `Config` into an enum — restructuring is explicitly not required by the design doc and would ripple through every existing PyPI test's config fixtures for no behavioral gain.

- [ ] **Step 2: Write the failing end-to-end bootstrap test**

```rust
#[tokio::test]
async fn bootstrap_cargo_serves_a_crate_through_the_full_cascade() {
    // a wiremock crates.io (config.json, index, download), an empty
    // advisory mirror, no cargo-vet sources configured, a stub AI
    // provider that replies clean, a plugin that exits 0 — GET the
    // index route for a never-seen crate, then GET its download route,
    // and assert both succeed end to end
}

#[tokio::test]
async fn bootstrap_cargo_runs_the_cargo_vet_sync_before_serving_anything() {
    // mirrors however the existing `bootstrap`'s initial advisory sync
    // is tested today (an empty store triggers a sync before `Wired` is
    // returned) — same shape, for CargoVetStore/CargoVetSync instead
}
```

- [ ] **Step 3: Run to verify failure.**

- [ ] **Step 4: Implement `bootstrap_cargo`**, following `bootstrap`'s own structure step for step: open the `Db`, build `CargoUpstream`, `AdvisoryStore`, `CargoVetStore`, `VerdictStore`, `PluginRunner` (reusing `default_sandbox_factory` verbatim — a cargo deployment with plugins or nothing configured needs exactly the same fail-closed sandbox detection the PyPI path already has), the `AiReviewer` (reusing `build_ai_reviewer` verbatim — it is already ecosystem-agnostic, since `AiReviewer::review` only ever took an `ArtifactKey` and a directory), run the initial OSV sync for `"crates.io"` (via Task 1's generalized `OsvSync::sync`) and the initial `CargoVetSync::sync_all` if either store is empty, then construct `CargoScanner` and the router from Task 6/8's handlers.

- [ ] **Step 5: Run to verify both pass.**

- [ ] **Step 6: Wire `main.rs`'s dispatch** per Step 1's rule, and the two periodic tickers (advisory sync for `"crates.io"`, cargo-vet sync) mirroring `spawn_advisory_sync_ticker`'s existing shape exactly.

- [ ] **Step 7: Run the full workspace test suite (`cargo test`), `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`. All green.**

- [ ] **Step 8: Commit**

```bash
git add src/http/mod.rs src/main.rs tests/http_cargo_bootstrap.rs
git commit -m "feat: wire a full cargo-registry deployment end to end"
```

---

### Task 12: The recent-refusals page

**Files:**
- Create: `src/http/refusals.rs`
- Modify: `src/http/mod.rs` (register the route on both the PyPI and cargo routers — the design doc frames this as compensating for cargo's silent refusals specifically, but nothing about it is cargo-specific, and the PyPI path gets it too at no extra cost)
- Modify: `src/db/verdict.rs` (a `recent_blocked` query)
- Test: `tests/http_refusals.rs`

**Interfaces:**
- Consumes: `crate::db::verdict::VerdictStore` (existing).
- Produces: `VerdictStore::recent_blocked(ecosystem: &str, limit: usize) -> anyhow::Result<Vec<StoredVerdict>>`; `refusals_handler`.

- [ ] **Step 1: Write the failing store-query test**

```rust
#[test]
fn recent_blocked_returns_newest_first_up_to_the_limit() {
    // store three Blocked verdicts for "cargo" and one for "pypi";
    // recent_blocked("cargo", 2) returns exactly 2, newest first, none of
    // them the "pypi" one
}
```

- [ ] **Step 2: Run to verify failure, then implement `recent_blocked`** (an indexed query against the existing `verdicts` table, `WHERE ecosystem = ? AND verdict = 'blocked' ORDER BY id DESC LIMIT ?` — match whatever column names `src/db/verdict.rs`'s existing schema actually uses).

- [ ] **Step 3: Run to verify it passes.**

- [ ] **Step 4: Write the failing HTTP test**

```rust
#[tokio::test]
async fn refusals_page_lists_recent_blocks_with_why_links() {
    let response = harness.get("/refusals").await;
    assert_eq!(response.status(), 200);
    let body = response.text().await;
    assert!(body.contains("/why/"));
}
```

- [ ] **Step 5: Run to verify failure, then implement `refusals_handler`**: a plain HTML table (package, version, refusal code, timestamp, a link to `/why/<id>`), no authentication, a fixed limit (reuse whatever constant style this codebase already favors — see `FULL_SCAN_SLOTS_MAX` for the naming convention — name it something like `RECENT_REFUSALS_LIMIT` and pick a value in the 50-200 range).

- [ ] **Step 6: Run to verify it passes; run the whole file.**

- [ ] **Step 7: Commit**

```bash
git add src/http/refusals.rs src/http/mod.rs src/db/verdict.rs tests/http_refusals.rs
git commit -m "feat(http): add a recent-refusals page for index-time blocks with no reason phrase"
```

---

### Task 13: Documentation

**Files:**
- Modify: `docs/operations.md`

- [ ] **Step 1: Add a "Running a cargo/crates.io deployment" section**, parallel to the existing PyPI operations documentation: the `[cargo_registry]` config table and its fields/defaults (Task 9), the two sync tickers and their intervals, the `.cargo/config.toml` source-replacement snippet a developer's machine needs (mirroring the existing `index-url` snippet's style), and the recent-refusals page's URL and purpose.

- [ ] **Step 2: Document the known limitation** from the design doc's "The version the proxy can't see": an explicit version pin to a crate version that was never the cascade's "newest unscanned candidate" will fail to resolve, and what an operator should do about it (re-run once the newer versions ahead of it have been resolved through, or add it to the allowlist once manually reviewed).

- [ ] **Step 3: Commit**

```bash
git add docs/operations.md
git commit -m "docs: document the cargo/crates.io deployment and its known resolution limitation"
```

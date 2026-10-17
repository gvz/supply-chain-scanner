# Supply Chain Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single-binary Rust HTTP proxy that stands in front of PyPI, scans every artifact once against advisories plus org-supplied sandboxed plugin binaries, remembers the verdict, and never serves anything that failed a check.

**Architecture:** axum/hyper over HTTP/1.1 serves the PEP 503 Simple index and artifact files, fetching from upstream PyPI on demand. A `Scanner` owns the decision path (allowlist → stored verdict → advisory re-check → full scan) and is single-flight per artifact. Everything durable lives in one SQLite file: verdicts, the OSV advisory mirror, the index cache, and artifact cache metadata. PyPI-specific code (index protocol, filename parsing, unpacking) sits behind an `Ecosystem` trait so npm and cargo can be added without touching the store, policy engine, plugin runner, or advisory matcher.

**Tech Stack:** Rust 2021 · tokio · axum 0.7 + hyper 1 (`http1`, for `hyper::ext::ReasonPhrase`) · reqwest (rustls, streaming) · rusqlite (bundled) + r2d2 · serde + toml · zip, tar, flate2 · pep440_rs · sha2 · tracing · clap. Dev: wiremock, tempfile.

**Spec:** `docs/superpowers/specs/2026-10-17-supply-chain-scanner-design.md`

## Global Constraints

- Rust, one binary, no external services. SQLite via `rusqlite` with the `bundled` feature — no system libsqlite.
- Client-facing HTTP is **HTTP/1.1 only**. HTTP/2 has no reason phrase; the refusal channel depends on it.
- **The scan path never fails open.** Any error — plugin crash, timeout, missing binary, unparseable data, unreachable upstream — produces a refusal, never a clean verdict.
- **A hash mismatch is always fatal**, including for allowlisted packages. The allowlist overrides verdicts, never hash verification.
- Scan budget default **12s**, hard requirement: below pip's 15s default timeout.
- Unmodified pip must work with only `index-url` changed. No pip timeout setting, no wrapper, no client plugin.
- Verdicts are keyed per artifact file: `(ecosystem, package, version, filename, sha256)`.
- Every verdict row carries a policy fingerprint; a verdict is reused only while the fingerprint matches.
- Artifact cache TTL is **sliding** — each request resets it, so hot packages are never evicted.
- Package names normalize per PEP 503: `[-_.]+` → `-`, lowercased.
- Status codes: **403** = blocked, **429** = scan in progress (pip does not auto-retry 429, so the phrase reaches the developer), **503** = cannot verify (upstream unreachable).

## Review Focus

1. **Refusal text containing CR/LF or non-ASCII** — package names and plugin stdout flow into the reason phrase; unsanitized, that is HTTP response splitting. Must be stripped and capped (Task 11).
2. **Archive entries with `..`, absolute paths, or symlinks** — unpacking a hostile sdist must not write outside the sandbox directory (Task 8).
3. **Index entry with no `#sha256=` fragment** — nothing to verify against, so the artifact is unverifiable and must be refused, never served (Task 10).
4. **Plugin that hangs, floods stdout, is missing, or is not executable** — each must become a refusal, not a clean verdict (Task 8).
5. **Invalid config on reload** — the running config must be kept; the proxy must never fall back to permissive defaults or exit while serving (Task 1).

---

### Task 1: Crate skeleton, core model, config

**Files:**
- Create: `Cargo.toml`, `src/main.rs`, `src/model.rs`, `src/config.rs`, `config.example.toml`
- Test: `tests/config.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```rust
  // src/model.rs
  pub struct ArtifactKey { pub ecosystem: String, pub package: String, pub version: String,
                           pub filename: String, pub sha256: String }
  pub struct RefusalReason { pub code: String, pub detail: String }   // code e.g. "cve:high", "plugin:yara", "hash-mismatch"
  pub enum Verdict { Clean, Blocked(RefusalReason) }

  // src/config.rs
  pub struct Config { pub bind: SocketAddr, pub db_path: PathBuf, pub cache_dir: PathBuf,
                      pub upstream_url: Url, pub public_url: Url,
                      pub scan_budget: Duration, pub cache_ttl: Duration,
                      pub advisory_sync_interval: Duration,
                      pub cve: CveLine, pub allowlist: Vec<AllowEntry>, pub plugins: Vec<PluginConfig> }
  pub struct CveLine { pub min_severity: f32, pub require_fix_available: bool,
                       pub unknown_severity: UnknownSeverity }     // Allow | Block, default Allow
  pub struct AllowEntry { pub package: String, pub version: String }
  pub struct PluginConfig { pub name: String, pub binary: PathBuf, pub timeout: Duration }
  impl Config { pub fn load(path: &Path) -> anyhow::Result<Config>; }
  pub struct ConfigHandle;                                          // arc-swap style holder
  impl ConfigHandle { pub fn new(Config) -> Self; pub fn current(&self) -> Arc<Config>;
                      pub fn reload(&self, path: &Path) -> anyhow::Result<()>; }
  ```

- [ ] **Step 1: Write the failing tests** in `tests/config.rs`

```rust
#[test] fn load_parses_example_config()            // config.example.toml → bind, budget 12s, ttl, plugins
#[test] fn load_rejects_unknown_field()            // serde deny_unknown_fields → Err
#[test] fn load_rejects_missing_upstream_url()
#[test] fn unknown_severity_defaults_to_allow()    // field omitted → UnknownSeverity::Allow
#[test] fn scan_budget_above_fourteen_seconds_is_rejected()  // guards pip's 15s timeout
#[test] fn reload_with_invalid_file_keeps_previous_config() {
    // handle.reload(bad) is Err and handle.current() still returns the original
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --test config`
Expected: FAIL — crate does not compile / `Config` not found.

- [ ] **Step 3: Write `Cargo.toml`** with the stack above, and `config.example.toml` covering every field with the documented defaults.

- [ ] **Step 4: Implement `src/model.rs` and `src/config.rs`**

`#[serde(deny_unknown_fields)]` on every config struct. Durations deserialize from strings like `"12s"` via `humantime_serde`. `ConfigHandle` holds an `ArcSwap<Config>`; `reload` parses fully before swapping so a bad file cannot replace a good config.

- [ ] **Step 5: Implement `src/main.rs`** as a clap CLI with `--config <path>` that loads the config, initializes `tracing_subscriber`, logs the resolved config, and exits.

- [ ] **Step 6: Run tests and the binary**

Run: `cargo test --test config && cargo run -- --config config.example.toml`
Expected: tests PASS; binary logs config and exits 0.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock config.example.toml src tests
git commit -m "feat: crate skeleton, core model, TOML config with safe reload"
```

---

### Task 2: SQLite store, migrations, verdict store

**Files:**
- Create: `src/db/mod.rs`, `src/db/migrations.rs`, `src/db/verdict.rs`
- Test: `tests/db_verdict.rs`

**Interfaces:**
- Consumes: `ArtifactKey`, `Verdict`, `RefusalReason` (Task 1).
- Produces:
  ```rust
  pub struct Db;                       // r2d2 pool over rusqlite
  impl Db { pub fn open(path: &Path) -> anyhow::Result<Db>;      // runs migrations
            pub fn conn(&self) -> anyhow::Result<PooledConnection>; }

  pub struct StoredVerdict { pub why_id: String, pub verdict: Verdict, pub scanned_at: i64 }
  pub struct VerdictStore { /* holds Db */ }
  impl VerdictStore {
      pub fn new(db: Db) -> Self;
      pub fn get(&self, key: &ArtifactKey, fingerprint: &str) -> anyhow::Result<Option<StoredVerdict>>;
      pub fn put(&self, key: &ArtifactKey, v: &Verdict, fingerprint: &str) -> anyhow::Result<String>; // why_id
      pub fn get_by_why_id(&self, why_id: &str) -> anyhow::Result<Option<(ArtifactKey, StoredVerdict)>>;
      pub fn blocked_filenames(&self, ecosystem: &str, package: &str, fingerprint: &str)
          -> anyhow::Result<HashSet<String>>;    // for index filtering, Task 12
  }
  ```

- [ ] **Step 1: Write the failing tests** in `tests/db_verdict.rs` (each opens a `tempfile::tempdir` DB)

```rust
#[test] fn put_then_get_roundtrips_clean_verdict()
#[test] fn put_then_get_roundtrips_blocked_verdict_with_reason()   // code and detail preserved
#[test] fn get_with_different_fingerprint_returns_none()           // stale policy → rescan
#[test] fn put_twice_updates_in_place_and_keeps_one_row()
#[test] fn why_id_is_url_safe_and_resolves_to_the_verdict()
#[test] fn two_artifacts_of_same_version_are_stored_separately()   // per-artifact granularity
#[test] fn blocked_filenames_lists_only_blocked_current_fingerprint_rows()
#[test] fn open_is_idempotent_and_migrations_rerun_cleanly()
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --test db_verdict`
Expected: FAIL — `Db` not found.

- [ ] **Step 3: Implement `src/db/mod.rs` + `src/db/migrations.rs`**

A `schema_version` table plus an ordered list of `&str` migrations applied in a transaction. Set `PRAGMA journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`. `verdicts` table: `why_id TEXT PRIMARY KEY`, the five key columns, `blocked INTEGER`, `reason_code`, `reason_detail`, `fingerprint`, `scanned_at`, with `UNIQUE(ecosystem, package, version, filename, sha256)`.

- [ ] **Step 4: Implement `src/db/verdict.rs`**

`why_id` is 16 lowercase base32 chars from a random 80-bit value. `put` is an upsert on the unique key, reusing the existing `why_id` when the row already exists.

- [ ] **Step 5: Run tests**

Run: `cargo test --test db_verdict`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/db tests/db_verdict.rs
git commit -m "feat: sqlite store with migrations and per-artifact verdict store"
```

---

### Task 3: PEP 503 index parsing, rendering, name validation

**Files:**
- Create: `src/ecosystem/mod.rs` (module decls only), `src/ecosystem/pypi/mod.rs`, `src/ecosystem/pypi/index.rs`
- Test: `tests/pypi_index.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```rust
  pub struct IndexEntry { pub filename: String, pub url: Url, pub sha256: Option<String>,
                          pub requires_python: Option<String>, pub metadata_hash: Option<String>,
                          pub yanked: Option<String> }
  pub struct ParsedArtifact { pub package: String, pub version: String, pub is_wheel: bool }

  pub fn normalize_name(name: &str) -> String;
  pub fn validate_package_name(name: &str) -> Result<String, InvalidName>;  // normalized, or Err
  pub fn parse_simple_page(html: &str, base: &Url) -> anyhow::Result<Vec<IndexEntry>>;
  pub fn render_simple_page(package: &str, entries: &[IndexEntry]) -> String;
  pub fn parse_filename(filename: &str) -> Option<ParsedArtifact>;
  ```

- [ ] **Step 1: Write the failing tests** in `tests/pypi_index.rs`

```rust
#[test] fn normalize_collapses_separators_and_lowercases()   // "Flask_Thing.X" → "flask-thing-x"
#[test] fn validate_rejects_path_traversal_and_slashes()     // "../../etc", "a/b", "" → Err
#[test] fn validate_rejects_non_ascii_and_control_chars()    // "pkg\r\nX", "pké" → Err
#[test] fn parse_page_extracts_filename_url_and_sha256()     // "#sha256=abc…" fragment
#[test] fn parse_page_entry_without_fragment_has_none_sha256()
#[test] fn parse_page_extracts_pep658_metadata_attribute()   // data-core-metadata / data-dist-info-metadata
#[test] fn parse_page_extracts_requires_python_and_yanked()
#[test] fn render_then_parse_round_trips_entries()
#[test] fn parse_filename_reads_wheel_name()                 // "requests-2.31.0-py3-none-any.whl"
#[test] fn parse_filename_reads_sdist_name()                 // "requests-2.31.0.tar.gz"
#[test] fn parse_filename_rejects_unknown_extension()
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --test pypi_index`
Expected: FAIL — functions not found.

- [ ] **Step 3: Implement `src/ecosystem/pypi/index.rs`**

Parse with a small HTML pass over `<a>` tags (`scraper` or a hand-rolled scan; either is fine — the page shape is fixed by PEP 503). `render_simple_page` emits the PEP 503 minimal document, HTML-escaping filenames, and re-emits `data-requires-python`, `data-yanked`, and the metadata attribute so pip sees what upstream offered.

- [ ] **Step 4: Run tests**

Run: `cargo test --test pypi_index`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ecosystem tests/pypi_index.rs
git commit -m "feat: PEP 503 index parse/render and strict package name validation"
```

---

### Task 4: Upstream client and index cache

**Files:**
- Create: `src/ecosystem/pypi/upstream.rs`, `src/db/index_cache.rs`
- Test: `tests/upstream.rs`

**Interfaces:**
- Consumes: `IndexEntry`, `parse_simple_page` (Task 3); `Db` (Task 2).
- Produces:
  ```rust
  pub struct Fetched<T> { pub value: T, pub stale: bool }
  #[derive(thiserror::Error)] pub enum UpstreamError { Unavailable, NotFound, Other(anyhow::Error) }

  pub struct Upstream { /* reqwest::Client, base Url, IndexCache */ }
  impl Upstream {
      pub fn new(base: Url, cache: IndexCache) -> anyhow::Result<Self>;
      pub async fn simple_page(&self, package: &str) -> Result<Fetched<Vec<IndexEntry>>, UpstreamError>;
      pub async fn download(&self, entry: &IndexEntry, dest: &Path) -> Result<String, UpstreamError>; // sha256 hex
      pub async fn metadata_sidecar(&self, entry: &IndexEntry) -> Result<Bytes, UpstreamError>;
  }
  pub struct IndexCache;
  impl IndexCache { pub fn new(db: Db) -> Self;
                    pub fn get(&self, package: &str) -> anyhow::Result<Option<(String, i64)>>;
                    pub fn put(&self, package: &str, body: &str) -> anyhow::Result<()>; }
  ```

- [ ] **Step 1: Write the failing tests** in `tests/upstream.rs` (wiremock as upstream)

```rust
#[tokio::test] async fn simple_page_returns_entries_and_caches_body()
#[tokio::test] async fn simple_page_falls_back_to_cache_when_upstream_errors()   // stale == true
#[tokio::test] async fn simple_page_without_cache_and_dead_upstream_is_unavailable()
#[tokio::test] async fn simple_page_404_is_not_found_and_does_not_poison_cache()
#[tokio::test] async fn download_streams_to_file_and_returns_sha256()
#[tokio::test] async fn download_of_truncated_body_errors_rather_than_leaving_partial_file()
#[tokio::test] async fn metadata_sidecar_fetches_the_dot_metadata_url()
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --test upstream`
Expected: FAIL — `Upstream` not found.

- [ ] **Step 3: Implement `src/db/index_cache.rs`**

Table `index_cache(package TEXT PRIMARY KEY, body TEXT, fetched_at INTEGER)` as a new migration.

- [ ] **Step 4: Implement `src/ecosystem/pypi/upstream.rs`**

`download` streams chunks into a temp file in the same directory as `dest`, hashing with `sha2` as it goes, then renames on success and deletes on error. Upstream timeouts are short (connect 5s, request 10s) so they cannot eat the scan budget alone.

- [ ] **Step 5: Run tests**

Run: `cargo test --test upstream`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ecosystem/pypi/upstream.rs src/db/index_cache.rs tests/upstream.rs
git commit -m "feat: upstream PyPI client with streaming hash and stale index cache"
```

---

### Task 5: Policy engine — fingerprint, allowlist, CVE line

**Files:**
- Create: `src/policy/mod.rs`
- Test: `tests/policy.rs`

**Interfaces:**
- Consumes: `Config`, `CveLine`, `AllowEntry`, `PluginConfig` (Task 1); `normalize_name` (Task 3).
- Produces:
  ```rust
  pub fn policy_fingerprint(cfg: &Config) -> anyhow::Result<String>;   // hex sha256
  pub struct Policy { /* built from Arc<Config> */ }
  impl Policy {
      pub fn build(cfg: Arc<Config>) -> anyhow::Result<Policy>;        // computes fingerprint
      pub fn fingerprint(&self) -> &str;
      pub fn allows(&self, package: &str, version: &str) -> bool;      // allowlist, normalized
      pub fn blocks_advisory(&self, m: &AdvisoryVerdictInput) -> bool;
  }
  pub struct AdvisoryVerdictInput { pub severity: Option<f32>, pub has_fix: bool }
  ```

- [ ] **Step 1: Write the failing tests** in `tests/policy.rs`

```rust
#[test] fn fingerprint_changes_when_min_severity_changes()
#[test] fn fingerprint_changes_when_plugin_binary_contents_change()  // rewrite temp binary, recompute
#[test] fn fingerprint_changes_when_plugin_order_changes()
#[test] fn fingerprint_ignores_bind_address_and_cache_ttl()          // operational knobs, not policy
#[test] fn build_errors_when_a_plugin_binary_is_missing()            // fail closed at startup
#[test] fn allows_matches_regardless_of_name_spelling()              // "Flask_X" entry vs "flask-x" query
#[test] fn unknown_severity_allow_does_not_block()
#[test] fn unknown_severity_block_does_block()
#[test] fn severity_at_or_above_threshold_blocks()
#[test] fn require_fix_available_only_blocks_when_fix_exists()
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --test policy`
Expected: FAIL — `Policy` not found.

- [ ] **Step 3: Implement `src/policy/mod.rs`**

The fingerprint hashes, in fixed order: the serialized `CveLine`, then for each plugin in list order its name and the sha256 of its binary. The allowlist is deliberately excluded — it is an override applied at request time, not an input to the scan.

- [ ] **Step 4: Run tests**

Run: `cargo test --test policy`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/policy tests/policy.rs
git commit -m "feat: policy engine with plugin-aware fingerprint, allowlist, CVE line"
```

---

### Task 6: OSV advisory sync and storage

**Files:**
- Create: `src/advisory/mod.rs`, `src/advisory/osv.rs`, `src/db/advisory.rs`
- Test: `tests/advisory_sync.rs`, fixture `tests/fixtures/osv/*.json`

**Interfaces:**
- Consumes: `Db` (Task 2).
- Produces:
  ```rust
  pub struct Advisory { pub id: String, pub package: String, pub summary: String,
                        pub severity: Option<f32>, pub versions: Vec<String>,
                        pub ranges: Vec<VersionRange>, pub fixed_versions: Vec<String> }
  pub struct VersionRange { pub introduced: Option<String>, pub fixed: Option<String> }

  pub fn parse_osv(json: &str) -> anyhow::Result<Vec<Advisory>>;   // one OSV doc → one per affected package
  pub fn severity_score(vector_or_score: &str) -> Option<f32>;     // CVSS v2/v3/v4 vector or numeric string

  pub struct AdvisoryStore;
  impl AdvisoryStore { pub fn new(db: Db) -> Self;
                       pub fn replace_all(&self, ecosystem: &str, advs: &[Advisory]) -> anyhow::Result<usize>;
                       pub fn for_package(&self, ecosystem: &str, package: &str) -> anyhow::Result<Vec<Advisory>>;
                       pub fn is_empty(&self, ecosystem: &str) -> anyhow::Result<bool>; }

  pub struct OsvSync;
  impl OsvSync { pub fn new(store: AdvisoryStore, http: reqwest::Client) -> Self;
                 pub async fn sync_pypi(&self) -> anyhow::Result<usize>; }  // all.zip → replace_all
  ```

- [ ] **Step 1: Write the failing tests** in `tests/advisory_sync.rs`

```rust
#[test] fn parse_osv_extracts_id_package_and_enumerated_versions()
#[test] fn parse_osv_extracts_introduced_and_fixed_ranges()
#[test] fn parse_osv_entry_without_severity_yields_none()
#[test] fn parse_osv_entry_with_multiple_affected_packages_yields_one_advisory_each()
#[test] fn severity_score_parses_cvss_v3_vector()      // AV:N/AC:L/.../A:H → 9.8 ± 0.05
#[test] fn severity_score_parses_bare_numeric_score()
#[test] fn severity_score_rejects_garbage()            // → None, not 0.0
#[test] fn for_package_normalizes_the_lookup_name()
#[tokio::test] async fn sync_pypi_ingests_a_zip_of_osv_docs()           // wiremock serves a built zip
#[tokio::test] async fn sync_pypi_replaces_previous_rows_atomically()   // withdrawn advisory disappears
#[tokio::test] async fn sync_pypi_failure_leaves_existing_advisories_intact()
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --test advisory_sync`
Expected: FAIL — `parse_osv` not found.

- [ ] **Step 3: Implement `src/db/advisory.rs`**

Migration adding `advisories` (id, ecosystem, package, summary, severity REAL NULL, fixed_versions JSON) and `advisory_versions` / `advisory_ranges` child tables, indexed on `(ecosystem, package)`. `replace_all` runs delete-then-insert inside one transaction.

- [ ] **Step 4: Implement `src/advisory/osv.rs`**

Source: `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip` (base URL configurable). Download to a temp file, read entries with `zip`, parse each with serde, collect, then `replace_all`. Severity comes from OSV `severity[]` entries, highest score wins; `CVSS_V3`/`CVSS_V4` vectors are scored by the base-score formula, `database_specific` numeric scores accepted as-is.

- [ ] **Step 5: Run tests**

Run: `cargo test --test advisory_sync`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/advisory src/db/advisory.rs tests/advisory_sync.rs tests/fixtures/osv
git commit -m "feat: OSV PyPI advisory mirror with atomic sync and CVSS normalization"
```

---

### Task 7: Advisory matching against a version

**Files:**
- Create: `src/advisory/matching.rs`
- Test: `tests/advisory_match.rs`

**Interfaces:**
- Consumes: `Advisory`, `VersionRange` (Task 6); `Policy::blocks_advisory` (Task 5).
- Produces:
  ```rust
  pub fn affects(adv: &Advisory, version: &str) -> bool;
  pub fn first_blocking(advs: &[Advisory], version: &str, policy: &Policy) -> Option<RefusalReason>;
  ```

- [ ] **Step 1: Write the failing tests** in `tests/advisory_match.rs`

```rust
#[test] fn exact_version_in_enumerated_list_affects()
#[test] fn version_outside_enumerated_list_does_not_affect()
#[test] fn version_inside_introduced_fixed_range_affects()
#[test] fn version_at_fixed_boundary_does_not_affect()        // [introduced, fixed)
#[test] fn open_ended_range_affects_everything_above_introduced()
#[test] fn pep440_prerelease_compares_below_release()         // 2.0.0rc1 < 2.0.0
#[test] fn unparseable_version_against_a_range_affects()      // fail closed
#[test] fn first_blocking_returns_reason_with_advisory_id_and_severity()
#[test] fn first_blocking_skips_advisories_below_the_cve_line()
#[test] fn first_blocking_returns_none_when_nothing_matches()
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --test advisory_match`
Expected: FAIL — `affects` not found.

- [ ] **Step 3: Implement `src/advisory/matching.rs`**

Enumerated `versions` are checked by normalized PEP 440 equality first; ranges use `pep440_rs::Version` comparison. A version that fails to parse while ranges exist is treated as affected — the scan path never fails open. `RefusalReason.code` is `cve:<advisory-id>`; `detail` carries the summary and severity.

- [ ] **Step 4: Run tests**

Run: `cargo test --test advisory_match`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/advisory/matching.rs tests/advisory_match.rs
git commit -m "feat: PEP 440 advisory matching, fail-closed on unparseable versions"
```

---

### Task 8: Unpacking, sandbox, plugin runner

**Files:**
- Create: `src/plugin/mod.rs`, `src/plugin/sandbox.rs`, `src/plugin/unpack.rs`
- Test: `tests/plugin.rs`

**Interfaces:**
- Consumes: `PluginConfig` (Task 1), `RefusalReason` (Task 1).
- Produces:
  ```rust
  pub fn unpack(archive: &Path, dest: &Path) -> anyhow::Result<()>;   // wheel/zip + sdist/tar.gz

  pub struct SandboxSpec { pub binary: PathBuf, pub package_dir: PathBuf, pub args: Vec<String>,
                           pub timeout: Duration, pub max_output_bytes: usize }
  pub struct SandboxOutcome { pub exit_code: Option<i32>, pub output: String, pub timed_out: bool }
  pub trait SandboxRunner: Send + Sync {
      fn run(&self, spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome>;
  }
  pub struct BubblewrapSandbox;
  impl BubblewrapSandbox { pub fn detect() -> anyhow::Result<Self>; }  // locates bwrap, errors if absent

  pub struct PluginRunner;
  impl PluginRunner {
      pub fn new(sandbox: Arc<dyn SandboxRunner>) -> Self;
      pub async fn run_all(&self, plugins: &[PluginConfig], key: &ArtifactKey, package_dir: &Path)
          -> Option<RefusalReason>;      // None = all clean; any error becomes Some
  }
  ```

**Plugin contract:** `<binary> --package-dir <dir> --name <pkg> --version <ver> --filename <file>`. Exit 0 = clean, non-zero = bad. First line of stdout (capped at 200 bytes) becomes the refusal detail.

- [ ] **Step 1: Write the failing tests** in `tests/plugin.rs`

```rust
#[test] fn unpack_extracts_wheel_contents()
#[test] fn unpack_extracts_sdist_tar_gz_contents()
#[test] fn unpack_rejects_entry_with_parent_traversal()      // "../escape" → Err, nothing written outside dest
#[test] fn unpack_rejects_absolute_path_entry()
#[test] fn unpack_rejects_symlink_entry()
#[test] fn unpack_rejects_archive_exceeding_size_limit()      // zip bomb guard

// SandboxRunner is faked for determinism; BubblewrapSandbox has its own ignored test.
#[tokio::test] async fn all_plugins_exit_zero_is_clean()
#[tokio::test] async fn nonzero_exit_blocks_with_plugin_name_in_code()   // code == "plugin:<name>"
#[tokio::test] async fn first_stdout_line_becomes_the_detail_and_is_truncated()
#[tokio::test] async fn timeout_blocks_with_plugin_timeout_code()        // fail closed
#[tokio::test] async fn sandbox_error_blocks_rather_than_passing()       // fail closed
#[tokio::test] async fn plugins_run_in_configured_order_and_stop_at_first_block()

#[test] #[ignore] fn bubblewrap_runs_a_real_binary_read_only()   // requires bwrap; package dir not writable
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --test plugin`
Expected: FAIL — `unpack` not found.

- [ ] **Step 3: Implement `src/plugin/unpack.rs`**

Validate every entry path before writing: must be relative, must contain no `..` component, must not be a symlink or device, and the running total of uncompressed bytes must stay under a fixed limit. Reject rather than skip.

- [ ] **Step 4: Implement `src/plugin/sandbox.rs`**

`BubblewrapSandbox` invokes `bwrap --unshare-all --die-with-parent --ro-bind <binary> <binary> --ro-bind <package_dir> /pkg --proc /proc --dev /dev --tmpfs /tmp --chdir /pkg -- <binary> <args…>`. No network, package directory read-only, output read with a byte cap, `timeout` enforced by killing the process group.

- [ ] **Step 5: Implement `src/plugin/mod.rs`**

`run_all` runs plugins sequentially in config order via `spawn_blocking`, returning on the first block. Every failure mode maps to a `RefusalReason`: non-zero → `plugin:<name>`, timeout → `plugin:<name>:timeout`, spawn/sandbox error → `plugin:<name>:error`.

- [ ] **Step 6: Run tests**

Run: `cargo test --test plugin`
Expected: PASS (the `bubblewrap` test stays ignored unless `bwrap` is installed).

- [ ] **Step 7: Commit**

```bash
git add src/plugin tests/plugin.rs
git commit -m "feat: hardened unpacking, bubblewrap sandbox, fail-closed plugin runner"
```

---

### Task 9: Artifact cache with sliding TTL

**Files:**
- Create: `src/artifact_cache.rs`, `src/db/cache.rs`
- Test: `tests/artifact_cache.rs`

**Interfaces:**
- Consumes: `ArtifactKey` (Task 1), `Db` (Task 2).
- Produces:
  ```rust
  pub struct ArtifactCache;
  impl ArtifactCache {
      pub fn new(db: Db, root: PathBuf) -> anyhow::Result<Self>;
      pub fn get(&self, key: &ArtifactKey) -> anyhow::Result<Option<PathBuf>>;  // touches last_access
      pub fn insert(&self, key: &ArtifactKey, file: &Path) -> anyhow::Result<PathBuf>;  // moves file in
      pub fn evict_expired(&self, ttl: Duration) -> anyhow::Result<usize>;
  }
  ```

- [ ] **Step 1: Write the failing tests** in `tests/artifact_cache.rs`

```rust
#[test] fn insert_then_get_returns_the_stored_path()
#[test] fn get_refreshes_last_access()                          // sliding TTL
#[test] fn evict_removes_untouched_entries_past_ttl()           // file deleted and row gone
#[test] fn evict_keeps_entries_touched_within_ttl()
#[test] fn repeatedly_requested_entry_survives_many_evictions() // spec: hot packages never evicted
#[test] fn get_returns_none_when_the_file_vanished_from_disk()  // row cleaned up, no panic
#[test] fn stored_path_is_derived_from_sha256()
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --test artifact_cache`
Expected: FAIL — `ArtifactCache` not found.

- [ ] **Step 3: Implement `src/db/cache.rs` and `src/artifact_cache.rs`**

Migration adds `artifact_cache(sha256 PRIMARY KEY, ecosystem, package, version, filename, bytes, last_access)`. On-disk layout is `root/<sha256[0..2]>/<sha256>`, so identical content is stored once.

- [ ] **Step 4: Run tests**

Run: `cargo test --test artifact_cache`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/artifact_cache.rs src/db/cache.rs tests/artifact_cache.rs
git commit -m "feat: content-addressed artifact cache with sliding TTL eviction"
```

---

### Task 10: Scan pipeline — decision path, budget, single flight

**Files:**
- Create: `src/scan/mod.rs`, `src/scan/coordinator.rs`
- Test: `tests/scan.rs`

**Interfaces:**
- Consumes: `VerdictStore` (2), `Upstream` (4), `Policy` (5), `AdvisoryStore` (6), `first_blocking` (7), `PluginRunner` + `unpack` (8), `ArtifactCache` (9).
- Produces:
  ```rust
  pub enum Decision { Serve(PathBuf), Refuse(RefusalReason), InProgress, Unverifiable(RefusalReason) }

  pub struct Scanner { /* all of the above, plus ConfigHandle */ }
  impl Scanner {
      pub fn new(/* dependencies */) -> Self;
      pub async fn decide(&self, key: &ArtifactKey, entry: &IndexEntry) -> Decision;
      pub async fn blocked_filenames(&self, ecosystem: &str, package: &str) -> HashSet<String>;
  }
  ```

**Decision path, in order:** allowlist hit → still verify hash, then serve · stored blocked → refuse · stored clean → advisory re-check, then serve · no verdict → full scan under budget.
**Full scan, stopping at first failure:** advisory lookup → download → hash verify → unpack + plugins → store clean, cache, serve.

- [ ] **Step 1: Write the failing tests** in `tests/scan.rs` (wiremock upstream, fake sandbox, temp DB)

```rust
#[tokio::test] async fn clean_artifact_is_served_and_verdict_stored()
#[tokio::test] async fn blocking_advisory_refuses_before_any_download()    // wiremock sees zero artifact requests
#[tokio::test] async fn hash_mismatch_refuses_with_hash_mismatch_code()
#[tokio::test] async fn entry_without_declared_hash_is_unverifiable_and_never_served()
#[tokio::test] async fn failing_plugin_refuses_and_stores_the_blocked_verdict()
#[tokio::test] async fn stored_blocked_verdict_refuses_without_contacting_upstream()
#[tokio::test] async fn stored_clean_verdict_refuses_when_a_new_advisory_appeared()
#[tokio::test] async fn allowlisted_package_is_served_despite_stored_blocked_verdict()
#[tokio::test] async fn allowlisted_package_with_hash_mismatch_is_still_refused()   // hash check is absolute
#[tokio::test] async fn policy_fingerprint_change_triggers_a_rescan()
#[tokio::test] async fn scan_exceeding_budget_returns_in_progress_then_stores_a_verdict()
#[tokio::test] async fn concurrent_requests_for_same_artifact_download_once()
#[tokio::test] async fn unreachable_upstream_for_unscanned_artifact_is_unverifiable()
#[tokio::test] async fn unreachable_upstream_for_cached_clean_artifact_still_serves()
#[tokio::test] async fn served_bytes_come_from_cache_on_the_second_request()
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --test scan`
Expected: FAIL — `Scanner` not found.

- [ ] **Step 3: Implement `src/scan/coordinator.rs`**

`ScanCoordinator` holds a `Mutex<HashMap<String, watch::Receiver<Option<Verdict>>>>` keyed by sha256. The first caller inserts a sender and owns the scan; later callers clone the receiver and await. The owning scan is spawned detached so it survives the requester's budget expiry, and removes its map entry on completion.

- [ ] **Step 4: Implement `src/scan/mod.rs`**

`decide` wraps the scan in `tokio::time::timeout(config.scan_budget, …)`; on elapse it returns `Decision::InProgress` and leaves the detached scan running. Download goes to a temp file; hash comparison is constant-time-irrelevant but case-insensitive hex; on success the file moves into the cache.

- [ ] **Step 5: Run tests**

Run: `cargo test --test scan`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/scan tests/scan.rs
git commit -m "feat: scan pipeline with budget, single flight, and absolute hash verification"
```

---

### Task 11: Refusal responses and the /why endpoint

**Files:**
- Create: `src/http/mod.rs`, `src/http/refusal.rs`, `src/http/why.rs`
- Test: `tests/http_refusal.rs`

**Interfaces:**
- Consumes: `RefusalReason` (1), `VerdictStore::get_by_why_id` (2), `Decision` (10).
- Produces:
  ```rust
  pub fn sanitize_phrase(s: &str) -> String;                       // ASCII 0x20–0x7E, ≤120 bytes
  pub fn refusal_response(reason: &RefusalReason, why_url: Option<&str>) -> Response;  // 403
  pub fn in_progress_response() -> Response;                        // 429
  pub fn unverifiable_response(reason: &RefusalReason) -> Response;  // 503
  pub async fn why_handler(State<AppState>, Path<String>) -> Response;  // GET /why/:id
  ```

- [ ] **Step 1: Write the failing tests** in `tests/http_refusal.rs`

```rust
#[test] fn sanitize_strips_cr_and_lf()                      // "bad\r\nX-Evil: 1" → no CR/LF (response splitting)
#[test] fn sanitize_strips_non_ascii_and_control_bytes()
#[test] fn sanitize_caps_length_at_120_bytes()
#[test] fn refusal_response_is_403_with_code_and_why_url_in_reason_phrase()
#[test] fn refusal_response_phrase_survives_a_hostile_plugin_detail()
#[test] fn in_progress_response_is_429_so_pip_does_not_silently_retry()
#[test] fn unverifiable_response_is_503_with_distinct_code()   // "UNVERIFIABLE", not "BLOCKED"
#[tokio::test] async fn why_page_shows_check_code_detail_and_artifact()
#[tokio::test] async fn why_page_escapes_html_in_stored_detail()
#[tokio::test] async fn unknown_why_id_is_404()
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --test http_refusal`
Expected: FAIL — `sanitize_phrase` not found.

- [ ] **Step 3: Implement `src/http/refusal.rs`**

The phrase is set by inserting `hyper::ext::ReasonPhrase::try_new(sanitized)` into the response extensions; it is built as `BLOCKED <code> — why <url>` and truncated to fit. The body repeats the same text for non-pip clients.

- [ ] **Step 4: Implement `src/http/why.rs`**

A small server-rendered HTML page from the stored verdict, HTML-escaping every stored field, plus a line on what the org can do (allowlist entry, or raise the CVE line).

- [ ] **Step 5: Run tests**

Run: `cargo test --test http_refusal`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/http tests/http_refusal.rs
git commit -m "feat: reason-phrase refusals with injection-safe sanitization and /why page"
```

---

### Task 12: Index and artifact handlers, ecosystem trait, wiring, end-to-end

**Files:**
- Create: `src/http/simple.rs`, `src/http/artifact.rs`, `src/ecosystem/traits.rs`
- Modify: `src/ecosystem/mod.rs`, `src/ecosystem/pypi/mod.rs`, `src/http/mod.rs`, `src/main.rs`
- Test: `tests/e2e.rs`

**Interfaces:**
- Consumes: everything above.
- Produces:
  ```rust
  #[async_trait] pub trait Ecosystem: Send + Sync {
      fn id(&self) -> &'static str;
      fn validate_name(&self, raw: &str) -> Result<String, InvalidName>;
      fn parse_filename(&self, filename: &str) -> Option<ParsedArtifact>;
      async fn simple_page(&self, package: &str) -> Result<Fetched<Vec<IndexEntry>>, UpstreamError>;
      async fn download(&self, entry: &IndexEntry, dest: &Path) -> Result<String, UpstreamError>;
      fn unpack(&self, archive: &Path, dest: &Path) -> anyhow::Result<()>;
  }
  pub struct PyPi { /* Upstream */ }     // impl Ecosystem

  // routes: GET /simple/:package/  ·  GET /files/:package/:version/:filename
  //         GET /files/:package/:version/:filename.metadata  ·  GET /why/:id  ·  GET /healthz
  ```

- [ ] **Step 1: Write the failing tests** in `tests/e2e.rs` (wiremock upstream + the real router on an ephemeral port)

```rust
#[tokio::test] async fn simple_page_is_served_and_rewrites_urls_to_the_proxy()
#[tokio::test] async fn simple_page_omits_known_blocked_artifacts()
#[tokio::test] async fn simple_page_keeps_allowlisted_artifacts_visible()
#[tokio::test] async fn pinned_blocked_artifact_returns_403_with_reason_phrase()
#[tokio::test] async fn clean_artifact_download_returns_bytes_with_matching_sha256()
#[tokio::test] async fn pep658_metadata_request_is_passed_through_without_scanning()
#[tokio::test] async fn invalid_package_name_in_path_is_400()         // "../../etc", "a/b", non-ascii
#[tokio::test] async fn filename_not_present_in_upstream_index_is_404()
#[tokio::test] async fn unknown_route_is_404_and_healthz_is_200()
#[tokio::test] async fn startup_syncs_advisories_when_the_mirror_is_empty()
#[tokio::test] async fn startup_fails_when_a_configured_plugin_has_no_sandbox_available()
#[tokio::test] async fn config_reload_signal_applies_a_new_allowlist_entry()
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --test e2e`
Expected: FAIL — routes not found.

- [ ] **Step 3: Implement `src/ecosystem/traits.rs` and the `PyPi` impl**

Move the PyPI-specific pieces from Tasks 3, 4, and 8 behind the trait without changing their signatures; `Scanner` and the handlers take `Arc<dyn Ecosystem>`.

- [ ] **Step 4: Implement `src/http/simple.rs`**

Validate the name, fetch the upstream page, drop entries whose filename is in `Scanner::blocked_filenames` unless the version is allowlisted, rewrite each URL to `/files/<package>/<version>/<filename>#sha256=…`, and render with `render_simple_page`.

- [ ] **Step 5: Implement `src/http/artifact.rs`**

Look the filename up in the upstream index to obtain the authoritative hash, build the `ArtifactKey`, call `Scanner::decide`, and map `Decision` onto the Task 11 responses. `Serve` streams the cached file with `application/octet-stream`. The `.metadata` route calls `Upstream::metadata_sidecar` directly.

- [ ] **Step 6: Implement wiring in `src/main.rs`**

Open the DB, build `Policy` (failing startup if a plugin binary or the sandbox is missing), build `Scanner`, run an initial advisory sync when the mirror is empty, spawn the sync ticker and the cache-eviction ticker, install a `SIGHUP` handler for config reload, and serve the router with HTTP/1.1 only.

- [ ] **Step 7: Run the whole suite**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all PASS.

- [ ] **Step 8: Real-pip smoke check**

Run the binary against live PyPI with an empty allowlist and no plugins, then in a throwaway venv:
`pip install --index-url http://127.0.0.1:8080/simple/ requests`
Expected: install succeeds. Then add `requests` at that version to the allowlist-free blocklist path by configuring a plugin that exits 1, restart, and confirm pip prints the `BLOCKED …  why http://…` phrase and the `/why/<id>` page explains it.

- [ ] **Step 9: Commit**

```bash
git add src tests
git commit -m "feat: filtered simple index, artifact handler, ecosystem trait, full wiring"
```

---

## Deferred (not in this plan)

Multi-ecosystem implementations (npm, cargo), developer authentication, metrics endpoints, and any configuration API or UI. The spec places all of these outside this version.

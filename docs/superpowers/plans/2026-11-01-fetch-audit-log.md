# Fetch Audit Log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Write a JSON Lines audit file recording which client IP fetched which package version, and which evaluated versions were withheld from which client and why, on all three ecosystem deployments.

**Architecture:** A new `src/audit.rs` owns a fallible, synchronous `AuditLog` writer (not a `tracing` layer — `tracing` macros cannot fail, and fail-closed needs the error). Handlers build records and write them *before* any response body; a write error becomes a 500. Client address comes from `ConnectInfo<SocketAddr>`, which requires rewiring `main::serve`. Listing handlers get per-version decisions from a new `ListingAudit` carried out of the cargo and npm cascades and, on PyPI, from a new verdict-store query.

**Tech Stack:** Rust 2021 (rustc 1.88.0), axum 0.8, serde/serde_json, chrono, rand, `tracing-appender` for daily rotation, `wiremock` + `tempfile` in tests.

**Spec:** `docs/superpowers/specs/2026-11-01-fetch-audit-log-design.md`

## Global Constraints

- **rustc 1.88.0**, pinned by `rust-toolchain.toml`. Every new dependency must build on it. `uuid = "=1.11.0"` in `Cargo.toml` is pinned for exactly this reason — do not let `cargo update` move it.
- **Gate for every task:** `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`.
- **axum 0.8**, HTTP/1.1 only; neither axum nor hyper is built with `http2`.
- **Client IP is the TCP peer address.** `X-Forwarded-For` is never read.
- **The client IP is written to exactly one place: the audit file.** No SQLite column, no HTTP route, no CLI subcommand exposes it.
- **Fail closed:** a failed audit write returns `500 Internal Server Error` and no package bytes. Never a 403 — a write failure must not read as a policy refusal.
- **Records are written before the response body**, including before the first streamed artifact byte.
- **Only versions the cascade actually evaluated get a verdict line.** Versions never considered are counted, never listed.
- **Reason vocabulary is the existing one:** `reason_code`, `reason_detail`, `why_id` as `src/db/verdict.rs` stores them. Existing spellings to reuse verbatim: `too-new`, `yanked`, `cve`, `plugin:*`, `ai:*`.
- **`[audit]` is restart-only**, alongside `bind` and `db_path`. A reload that changes it is rejected in full with the field named.
- **Non-package routes emit nothing:** `/healthz`, `/why/{id}`, `/refusals`, `/api/reviews`, `/-/ping`, the npm audit stubs, the npm write refusals.

## Review Focus

Five inputs the spec implies that no task's happy path exercises. Each one's test is assigned to the task that owns the code.

1. **A `reason_detail` carrying a newline or control character must not split or corrupt a JSONL line.** Refusal details quote what a scan found inside a package, so they are attacker-influenceable; one forged newline could inject a fabricated audit record. → Task 2.
2. **A client-supplied `X-Forwarded-For` must never reach the log.** Nothing sits in front of this proxy, so the header can only be a forgery, and honouring it would let a developer write someone else's address into a security log. → Task 3.
3. **An audit write failure must produce a 500 with no package bytes, and must not be mistakable for a refusal.** Operators hunting a non-existent policy problem is the failure mode. → Task 3.
4. **Concurrent requests must never interleave partial lines.** Two in-flight fetches writing at once must still yield lines that each parse as JSON. → Task 2.
5. **An unwritable audit path must fail at startup, naming the path**, not surface as 500s on the first fetch hours later. → Task 2.

---

### Task 1: The `[audit]` configuration table

**Files:**
- Modify: `src/config.rs` (add `AuditConfig`, the `Config::audit` field, validation in `Config::validate` at `src/config.rs:469`)
- Modify: `src/http/mod.rs:425` (`RESTART_ONLY_FIELDS`) and `src/http/mod.rs:449` (`restart_only_changes`)
- Modify: `config.example.toml`
- Test: `tests/config_audit.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
```rust
// src/config.rs
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub path: std::path::PathBuf,
    #[serde(default)]
    pub rotation: AuditRotation,
    #[serde(default = "default_audit_max_files")]
    pub max_files: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditRotation {
    #[default]
    Daily,
    Hourly,
}

// added to `pub struct Config`, not optional:
//     pub audit: AuditConfig,
```

`path` is a **filename prefix**, not the exact file written: the rolling appender appends a date suffix, so `path = "/var/log/scanner/audit.jsonl"` produces `audit.jsonl.2026-11-01`. Say so in the `config.example.toml` comment; a shipper has to glob.

`[audit]` is **required**. An existing config file without it fails to parse, which is the fail-closed reading of "an un-logged fetch must not happen". `deny_unknown_fields` is already on `Config`, so serde's own missing-field error does the work.

- [ ] **Step 1: Write the failing tests** in `tests/config_audit.rs`

```rust
#[test]
fn a_config_without_an_audit_table_is_rejected() {
    // config TOML with every existing required field and no [audit]
    let err = Config::load(&path).expect_err("a config with no [audit] table must not load");
    assert!(format!("{err:#}").contains("audit"), "{err:#}");
}

#[test]
fn an_audit_table_parses_path_rotation_and_max_files() {
    // [audit] path = "/var/log/scanner/audit.jsonl", rotation = "hourly", max_files = 7
    assert_eq!(config.audit.path, PathBuf::from("/var/log/scanner/audit.jsonl"));
    assert_eq!(config.audit.rotation, AuditRotation::Hourly);
    assert_eq!(config.audit.max_files, 7);
}

#[test]
fn audit_rotation_and_max_files_default_to_daily_and_fourteen() {
    // [audit] with only `path`
    assert_eq!(config.audit.rotation, AuditRotation::Daily);
    assert_eq!(config.audit.max_files, 14);
}

#[test]
fn audit_max_files_of_zero_is_rejected() {
    let err = Config::load(&path).expect_err("max_files = 0 must not load");
    assert!(format!("{err:#}").contains("max_files"), "{err:#}");
}

#[test]
fn an_audit_path_with_no_file_name_is_rejected() {
    // path = "/var/log/scanner/"
    let err = Config::load(&path).expect_err("a directory path must not load");
    assert!(format!("{err:#}").contains("audit"), "{err:#}");
}

#[test]
fn changing_the_audit_table_is_a_restart_only_reload_rejection() {
    // build a Wired via the existing test helper, write a config whose
    // [audit] path differs, reload it
    let err = reloader.reload(&changed_path).expect_err("must be rejected");
    assert!(format!("{err:#}").contains("audit"), "{err:#}");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test config_audit`
Expected: FAIL — `no field 'audit' on type Config`, `AuditConfig` unresolved.

- [ ] **Step 3: Implement `AuditConfig`, `AuditRotation`, `default_audit_max_files() -> usize` returning `14`, and the `Config::audit` field in `src/config.rs`**

Validation goes in the existing `Config::validate` (`src/config.rs:469`), in its style: `max_files` must be non-zero, and `path.file_name()` must be `Some`. Error text names `audit`.

- [ ] **Step 4: Add `"audit"` to `RESTART_ONLY_FIELDS` and the `boot.audit != candidate.audit` arm to `restart_only_changes`**

Both in `src/http/mod.rs`. Extend the `RESTART_ONLY_FIELDS` doc comment with the reason: the open file handle is built once at startup.

- [ ] **Step 5: Add the `[audit]` table to `config.example.toml`**

Document `path` as a prefix, `rotation`, `max_files`, that the file holds network-attributable developer data and deserves its own filesystem permissions, and that a write failure returns 500.

- [ ] **Step 6: Run the gate**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS. Existing config fixtures across `tests/` will need an `[audit]` table added — that is part of this task.

- [ ] **Step 7: Commit**

```bash
git add src/config.rs src/http/mod.rs config.example.toml tests/
git commit -m "feat(audit): add the restart-only [audit] configuration table"
```

---

### Task 2: The audit writer and record types

**Files:**
- Create: `src/audit.rs`
- Modify: `src/lib.rs` (add `pub mod audit;`)
- Modify: `Cargo.toml` (add `tracing-appender`)
- Test: `tests/audit.rs`

**Interfaces:**
- Consumes: `crate::config::{AuditConfig, AuditRotation}` from Task 1; `crate::model::RefusalReason` (fields `code`, `detail`).
- Produces:
```rust
// src/audit.rs
pub struct AuditLog { /* Mutex<Box<dyn std::io::Write + Send>> */ }

impl AuditLog {
    /// Opens (creating parent directories) and proves the sink writable.
    /// Error text names the configured path.
    pub fn open(config: &crate::config::AuditConfig) -> anyhow::Result<Self>;
    /// For tests: any writer, including one that always errors.
    pub fn with_writer<W: std::io::Write + Send + 'static>(writer: W) -> Self;
    /// Serializes each record as one line, under a single lock, and
    /// flushes once. Any error is returned, never swallowed.
    pub fn write(&self, records: &[AuditRecord]) -> anyhow::Result<()>;
}

/// Per-request identity, built once per HTTP request.
pub struct AuditContext {
    pub ecosystem: String,
    pub client_ip: std::net::IpAddr,
    pub client_port: u16,
    pub request_id: String,
}

impl AuditContext {
    /// `request_id` is 16 lowercase hex characters from `rand`.
    pub fn new(ecosystem: &str, client: std::net::SocketAddr) -> Self;
}

/// One decision about one evaluated version. `filename` is `Some` only
/// where the ecosystem decides per file (PyPI), `None` for cargo and npm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionDecision {
    pub version: String,
    pub filename: Option<String>,
    pub allowed: bool,
    pub reason_code: Option<String>,
    pub reason_detail: Option<String>,
    pub why_id: Option<String>,
}

/// Everything one listing response needs to report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListingAudit {
    pub versions_upstream: usize,
    pub decisions: Vec<VersionDecision>,
}

impl ListingAudit {
    pub fn versions_evaluated(&self) -> usize;
    /// `listing` line first, then one `listed` line per decision.
    pub fn records(&self, ctx: &AuditContext, package: &str) -> Vec<AuditRecord>;
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditRecord { /* fields below */ }

impl AuditRecord {
    pub fn listing(ctx: &AuditContext, package: &str, versions_upstream: usize, versions_evaluated: usize) -> Self;
    pub fn listed(ctx: &AuditContext, package: &str, decision: &VersionDecision) -> Self;
    pub fn served(ctx: &AuditContext, package: &str, version: &str, filename: &str, sha256: &str) -> Self;
    pub fn refused(ctx: &AuditContext, package: &str, version: &str, filename: Option<&str>, reason: &crate::model::RefusalReason, why_id: Option<&str>) -> Self;
}
```

**Record shape.** Always present: `ts` (RFC 3339 UTC, milliseconds, via `chrono`), `event` (`listing` | `listed` | `served` | `refused`), `ecosystem`, `client_ip`, `client_port`, `request_id`, `package`. Every other field is `Option` with `#[serde(skip_serializing_if = "Option::is_none")]`: `version`, `filename`, `sha256`, `decision` (`allowed` | `denied`), `reason_code`, `reason_detail`, `why_id`, `versions_upstream`, `versions_evaluated`.

- [ ] **Step 1: Write the failing tests** in `tests/audit.rs`

```rust
#[test]
fn a_served_record_is_one_json_line_with_the_fetch_identified() {
    // AuditLog::with_writer over a shared Vec<u8>
    // one AuditRecord::served for pypi / 10.1.2.3:51234 / requests 2.31.0
    assert_eq!(lines.len(), 1);
    assert_eq!(value["event"], "served");
    assert_eq!(value["ecosystem"], "pypi");
    assert_eq!(value["client_ip"], "10.1.2.3");
    assert_eq!(value["client_port"], 51234);
    assert_eq!(value["package"], "requests");
    assert_eq!(value["version"], "2.31.0");
    assert_eq!(value["filename"], "requests-2.31.0-py3-none-any.whl");
    assert_eq!(value["sha256"], "ab".repeat(32));
    assert!(value.get("reason_code").is_none(), "no reason on a served line");
}

#[test]
fn a_refused_record_carries_the_reason_code_detail_and_why_id() {
    assert_eq!(value["event"], "refused");
    assert_eq!(value["reason_code"], "cve:high");
    assert_eq!(value["reason_detail"], "CVE-2024-0001 affects this version");
    assert_eq!(value["why_id"], "abc23xyz");
}

#[test]
fn a_listing_audit_writes_one_listing_line_then_one_line_per_evaluated_version() {
    // ListingAudit { versions_upstream: 847, decisions: [allowed 4.17.21, denied 4.17.20] }
    assert_eq!(lines.len(), 3);
    assert_eq!(first["event"], "listing");
    assert_eq!(first["versions_upstream"], 847);
    assert_eq!(first["versions_evaluated"], 2);
    assert_eq!(second["event"], "listed");
    assert_eq!(second["decision"], "allowed");
    assert_eq!(third["decision"], "denied");
    assert_eq!(third["reason_code"], "too-new");
}

#[test]
fn every_record_of_one_request_shares_its_request_id() {
    // all three lines above, one AuditContext
    assert!(ids.iter().all(|id| id == &ids[0]));
    assert_eq!(ids[0].len(), 16);
}

// Review Focus 1
#[test]
fn a_reason_detail_containing_a_newline_stays_one_line() {
    // detail: "line one\nnot a real record\r\n{\"event\":\"served\"}"
    assert_eq!(lines.len(), 1, "a forged newline must not inject a record");
    assert!(value["reason_detail"].as_str().unwrap().contains('\n'));
}

// Review Focus 4
#[test]
fn concurrent_writers_never_interleave_a_partial_line() {
    // 8 threads x 50 records each into one AuditLog over a shared buffer
    assert_eq!(lines.len(), 400);
    for line in lines { serde_json::from_str::<serde_json::Value>(line).expect("each line parses"); }
}

// Review Focus 5
#[test]
fn opening_an_unwritable_audit_path_fails_and_names_the_path() {
    // path inside a tempdir with mode 0o500
    let err = AuditLog::open(&config).expect_err("an unwritable path must fail at open");
    assert!(format!("{err:#}").contains("audit.jsonl"), "{err:#}");
}

#[test]
fn an_ipv6_peer_address_serializes_as_address_and_port_separately() {
    // [2001:db8::1]:51234
    assert_eq!(value["client_ip"], "2001:db8::1");
    assert_eq!(value["client_port"], 51234);
}

#[test]
fn a_failing_writer_surfaces_its_error_rather_than_swallowing_it() {
    // with_writer over a writer whose write() always returns ErrorKind::Other
    let err = log.write(&records).expect_err("a write failure must be returned");
    assert!(format!("{err:#}").contains("audit"), "{err:#}");
}

#[test]
fn open_writes_nothing_on_its_own() {
    // AuditLog::open on a fresh tempdir path, then drop
    assert_eq!(std::fs::read(&written).unwrap_or_default().len(), 0);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test audit`
Expected: FAIL — `unresolved module audit`.

- [ ] **Step 3: Add `tracing-appender` to `Cargo.toml` and confirm it builds on rustc 1.88.0**

Run: `cargo build`
Confirm the rolling appender exposes daily/hourly rotation, a `max_log_files` bound, and an `io::Write` that *returns* write errors. If any of the three is missing on a version that builds here, implement `AuditLog::open` over `std::fs::OpenOptions::append` with the date suffix in the filename and a prune of the oldest files past `max_files` on each date change — do not drop the dependency silently, record which path was taken in the module docs.

- [ ] **Step 4: Implement `src/audit.rs` and add `pub mod audit;` to `src/lib.rs`**

`write` takes the lock once for the whole slice, writes `serde_json::to_writer` plus `\n` per record, then flushes once. Module docs state why this is not a `tracing` layer (macros cannot fail, so fail-closed would be unenforceable) and why the non-blocking appender is not used (it buffers and drops).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --test audit`
Expected: PASS (11 tests).

- [ ] **Step 6: Run the gate and commit**

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
git add Cargo.toml Cargo.lock src/audit.rs src/lib.rs tests/audit.rs
git commit -m "feat(audit): add the fail-closed JSONL audit writer"
```

---

### Task 3: Client address plumbing and PyPI download events

**Files:**
- Modify: `src/main.rs:268-275` (`serve`)
- Modify: `src/http/mod.rs` (`AppState`, `audit_or_500`), `src/http/artifact.rs:32`
- Modify: `src/http/mod.rs` `bootstrap` (open the `AuditLog`), `tests/e2e.rs:169`, `tests/e2e.rs:884`
- Test: `tests/http_audit_pypi.rs`

**Interfaces:**
- Consumes: `crate::audit::{AuditLog, AuditContext, AuditRecord}` from Task 2.
- Produces:
```rust
// src/http/mod.rs
// added to AppState, CargoAppState and NpmAppState alike:
//     pub audit: std::sync::Arc<crate::audit::AuditLog>,

/// Writes `records`, or returns the 500 the caller must return instead
/// of serving. Logs the cause at `error!`. Never a refusal response.
pub(crate) fn audit_or_500(
    audit: &crate::audit::AuditLog,
    records: &[crate::audit::AuditRecord],
) -> Option<axum::response::Response>;
```

`serve` becomes `axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())`. Both `axum::serve` call sites in `tests/e2e.rs` take the same change, or every handler's `ConnectInfo` extraction fails.

The spec's rule that a `304 Not Modified` listing emits nothing needs no code: no handler in `src/http/` returns 304 today, and the ETag caches are upstream-facing only. Do not go looking for it.

`artifact_handler` gains `ConnectInfo(peer): ConnectInfo<SocketAddr>` and emits exactly one record per outcome, **before** the response: `served` on `Decision::Serve` (the key's `sha256`), `refused` on `Decision::Refuse`. `Decision::InProgress` and `Decision::Unverifiable` emit nothing — no fetch happened and no verdict was reached. The `.metadata` sidecar path emits nothing; it serves no artifact.

- [ ] **Step 1: Write the failing tests** in `tests/http_audit_pypi.rs`

```rust
#[tokio::test]
async fn a_served_artifact_writes_a_served_line_naming_the_client_ip() {
    // full e2e harness over a tempdir audit path, GET /files/...
    assert_eq!(response.status(), 200);
    assert_eq!(record["event"], "served");
    assert_eq!(record["ecosystem"], "pypi");
    assert_eq!(record["client_ip"], "127.0.0.1");
    assert_eq!(record["package"], "example-package");
}

#[tokio::test]
async fn a_refused_artifact_writes_a_refused_line_with_the_stored_reason() {
    assert_eq!(response.status(), 403);
    assert_eq!(record["event"], "refused");
    assert_eq!(record["reason_code"], "plugin:yara");
    assert!(record["why_id"].is_string());
}

#[tokio::test]
async fn the_metadata_sidecar_writes_no_audit_line() {
    // GET /files/<pkg>/<ver>/<file>.metadata
    assert_eq!(response.status(), 200);
    assert_eq!(lines.len(), 0);
}

#[tokio::test]
async fn healthz_writes_no_audit_line() {
    assert_eq!(lines.len(), 0);
}

#[tokio::test]
async fn no_open_route_renders_a_client_ip() {
    // after the served and refused fetches above, read /refusals,
    // /why/<id> and /api/reviews
    for body in [refusals, why, reviews] {
        assert!(!body.contains("127.0.0.1"), "a route leaked a client address: {body}");
    }
}

// Review Focus 2
#[tokio::test]
async fn a_spoofed_x_forwarded_for_header_is_ignored() {
    // raw request carrying `X-Forwarded-For: 203.0.113.9`
    assert_eq!(record["client_ip"], "127.0.0.1", "the header must never reach the log");
}

// Review Focus 3
#[tokio::test]
async fn a_failed_audit_write_returns_500_and_no_artifact_bytes() {
    // state built with AuditLog::with_writer over an always-failing writer
    assert_eq!(response.status(), 500);
    assert!(body.is_empty(), "no artifact bytes may be served: {body:?}");
    assert_ne!(response.status(), 403, "a write failure must not read as a refusal");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test http_audit_pypi`
Expected: FAIL — `AppState` has no field `audit`.

- [ ] **Step 3: Rewire `serve` in `src/main.rs` and both `axum::serve` call sites in `tests/e2e.rs`**

Run: `cargo test --test e2e`
Expected: PASS — unchanged behavior, new service type.

- [ ] **Step 4: Add `audit: Arc<AuditLog>` to `AppState`, open it in `bootstrap`, and implement `audit_or_500` in `src/http/mod.rs`**

`bootstrap` opens the log in the existing fail-closed startup order, before the router is built, so an unwritable path aborts startup.

- [ ] **Step 5: Emit the `served` and `refused` records in `src/http/artifact.rs`**

Build the `AuditContext` once at the top of the handler. For `Decision::Serve`, write before calling `serve_file`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test --test http_audit_pypi && cargo test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/main.rs src/http/mod.rs src/http/artifact.rs tests/
git commit -m "feat(audit): log pypi artifact fetches with the client address"
```

---

### Task 4: PyPI listing events

**Files:**
- Modify: `src/db/verdict.rs` (new query beside `blocked_filenames` at `src/db/verdict.rs:325`)
- Modify: `src/scan/mod.rs` (new `Scanner` method beside `blocked_filenames` at `src/scan/mod.rs:360`)
- Modify: `src/http/simple.rs`
- Test: `tests/db_verdict.rs` (extend), `tests/http_audit_pypi.rs` (extend)

**Interfaces:**
- Consumes: `crate::audit::{ListingAudit, VersionDecision}`.
- Produces:
```rust
// src/db/verdict.rs
/// Every verdict on record for one package under `fingerprint`, keyed by
/// filename. Carries what an audit line needs that `blocked_filenames`
/// drops: whether it was blocked, why, and its `why_id`.
pub struct FileVerdict {
    pub filename: String,
    pub blocked: bool,
    pub reason_code: String,
    pub reason_detail: String,
    pub why_id: String,
}

impl VerdictStore {
    pub fn file_verdicts(
        &self,
        ecosystem: &str,
        package: &str,
        fingerprint: &str,
    ) -> anyhow::Result<Vec<FileVerdict>>;
}

// src/scan/mod.rs
impl Scanner {
    /// `file_verdicts` under the running fingerprint, off the async
    /// runtime like `blocked_filenames`. A lookup failure yields an
    /// empty vec and a `warn!`, matching `blocked_filenames`'s own
    /// degradation.
    pub async fn file_verdicts(&self, ecosystem: &str, package: &str) -> Vec<crate::db::verdict::FileVerdict>;
}
```

**What "evaluated" means on PyPI.** PyPI has no cascade: `simple.rs` serves upstream's entries minus the blocked ones, and most entries have never been scanned. So an evaluated version is one with a stored verdict under the running fingerprint. `versions_upstream` is the count of entries upstream's page carried; a `listed` line is emitted only for an entry with a `FileVerdict`, `allowed` for a clean one and `denied` for a blocked one. Each line carries both `version` and `filename`, because PyPI decides per file and one version can be part-blocked. A blocked-but-allowlisted entry stays visible (as it does today) and is logged `allowed` with `reason_code` `"allowlisted"`.

- [ ] **Step 1: Write the failing tests**

```rust
// tests/db_verdict.rs
#[test]
fn file_verdicts_returns_clean_and_blocked_rows_with_their_reasons() {
    // one Clean and one Blocked row under FINGERPRINT_A, one under B
    assert_eq!(rows.len(), 2);
    assert_eq!(blocked.reason_code, "plugin:yara");
    assert!(!clean.blocked);
    assert!(!blocked.why_id.is_empty());
}

// tests/http_audit_pypi.rs
#[tokio::test]
async fn a_simple_page_writes_a_listing_line_counting_evaluated_of_upstream() {
    // upstream page with 5 entries, 2 of them with stored verdicts
    assert_eq!(listing["event"], "listing");
    assert_eq!(listing["versions_upstream"], 5);
    assert_eq!(listing["versions_evaluated"], 2);
    assert_eq!(listed.len(), 2, "unscanned entries get no verdict line");
}

#[tokio::test]
async fn a_blocked_entry_is_a_denied_line_naming_its_version_and_filename() {
    assert_eq!(denied["decision"], "denied");
    assert_eq!(denied["version"], "1.0.0");
    assert_eq!(denied["filename"], "example-package-1.0.0.tar.gz");
    assert_eq!(denied["reason_code"], "plugin:yara");
}

#[tokio::test]
async fn an_allowlisted_blocked_entry_is_an_allowed_line_coded_allowlisted() {
    assert_eq!(record["decision"], "allowed");
    assert_eq!(record["reason_code"], "allowlisted");
}

#[tokio::test]
async fn a_failed_audit_write_on_a_simple_page_returns_500_and_no_index_html() {
    assert_eq!(response.status(), 500);
    assert!(!body.contains("<a href"), "no index may be served: {body}");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test db_verdict --test http_audit_pypi`
Expected: FAIL — `file_verdicts` not found.

- [ ] **Step 3: Implement `FileVerdict` and `VerdictStore::file_verdicts` in `src/db/verdict.rs`**

Same `WHERE ecosystem = ?1 AND package = ?2 AND fingerprint = ?3` as `blocked_filenames`, without the `blocked = 1` clause, selecting the reason columns and `why_id`.

- [ ] **Step 4: Implement `Scanner::file_verdicts` in `src/scan/mod.rs`**

Mirror `blocked_filenames`: `spawn_blocking`, and on failure a `warn!` plus an empty result.

- [ ] **Step 5: Emit the listing records in `src/http/simple.rs`**

Build the `ListingAudit` while the page is being filtered — `versions_upstream` from the fetched entry count, one `VersionDecision` per entry that has a `FileVerdict`, version from `parse_filename`. Write before the rendered page is returned.

- [ ] **Step 6: Run tests to verify they pass, then the gate**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/db/verdict.rs src/scan/mod.rs src/http/simple.rs tests/
git commit -m "feat(audit): log pypi index listings with per-file verdicts"
```

---

### Task 5: Cargo listing and download events

**Files:**
- Modify: `src/scan/cargo.rs:83` (`CargoIndexDecision`), `src/scan/cargo.rs:455-490` (the `NextStep::Forward` arm)
- Modify: `src/http/cargo_index.rs:122` (`CargoAppState`), `:165` (`cargo_router`), `:253` (`cargo_index_handler`), `src/http/cargo_download.rs:126`
- Modify: `src/http/cargo_bootstrap.rs` (open the `AuditLog`)
- Test: `tests/http_audit_cargo.rs`

**Interfaces:**
- Consumes: `ListingAudit`, `VersionDecision`, `AuditContext`, `audit_or_500`.
- Produces:
```rust
// src/scan/cargo.rs — widened variant
pub enum CargoIndexDecision {
    Entries {
        entries: Vec<CargoIndexEntry>,
        audit: crate::audit::ListingAudit,
    },
    InProgress,
}
```

**Reason codes for cascade-filtered versions**, built from the final `CascadeInput` at the `NextStep::Forward` arm, using existing spellings: `entry.yanked` → `"yanked"`; `cve_blocked` → `"cve"`; `too_new` → `"too-new"`; `review_status == Failed` → the stored verdict's own `reason_code`, `reason_detail` and `why_id` via `VerdictStore::file_verdicts`. A version in none of those sets and not forwarded was never evaluated: it gets no `VersionDecision`, only the `versions_upstream` count. Forwarded versions are `allowed`, with `reason_code` `"allowlisted"` when they are in `allowlisted`. `VersionDecision::filename` is `None` throughout — cargo decides per version.

`CargoIndexDecision::InProgress` emits nothing. `cargo_download_handler` emits `served`/`refused` exactly as Task 3 does for PyPI.

- [ ] **Step 1: Write the failing tests** in `tests/http_audit_cargo.rs`

```rust
#[tokio::test]
async fn a_cargo_index_listing_logs_forwarded_and_filtered_versions_with_reasons() {
    // upstream index with 6 versions: 1 forwarded, 1 yanked, 1 too new,
    // 1 cve-blocked, 2 never evaluated
    assert_eq!(listing["versions_upstream"], 6);
    assert_eq!(listing["versions_evaluated"], 4);
    assert_eq!(codes_by_version["0.9.0"], "yanked");
    assert_eq!(codes_by_version["2.0.0"], "too-new");
    assert_eq!(codes_by_version["1.5.0"], "cve");
    assert_eq!(allowed["decision"], "allowed");
}

#[tokio::test]
async fn a_review_failed_version_carries_the_stored_reason_and_why_id() {
    assert_eq!(record["reason_code"], "ai:malicious");
    assert!(record["why_id"].is_string());
}

#[tokio::test]
async fn a_cargo_crate_download_writes_a_served_line() {
    assert_eq!(record["event"], "served");
    assert_eq!(record["ecosystem"], "cargo");
    assert_eq!(record["filename"], "serde-1.0.0.crate");
}

#[tokio::test]
async fn a_refused_cargo_download_writes_a_refused_line() {
    assert_eq!(response.status(), 403);
    assert_eq!(record["event"], "refused");
}

#[tokio::test]
async fn an_in_progress_cargo_index_writes_no_verdict_lines() {
    assert_eq!(response.status(), 429);
    assert_eq!(lines.len(), 0);
}

#[tokio::test]
async fn cargo_config_json_and_refusals_write_no_audit_lines() {
    assert_eq!(lines.len(), 0);
}

#[tokio::test]
async fn a_failed_audit_write_on_a_cargo_index_returns_500_and_no_entries() {
    assert_eq!(response.status(), 500);
    assert!(body.is_empty(), "no index entries may be served: {body:?}");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test http_audit_cargo`
Expected: FAIL — `CargoAppState` has no field `audit`.

- [ ] **Step 3: Widen `CargoIndexDecision::Entries` and build the `ListingAudit` in `src/scan/cargo.rs`**

Construct it in the `NextStep::Forward` arm, where `entries`, `cve_blocked`, `facts.too_new`, `facts.review_status` and `facts.allowlisted` are all in scope. Update `tests/ecosystem_cargo_upstream.rs`, `tests/scan_cargo.rs` and `tests/http_cargo_index.rs` for the new variant shape.

- [ ] **Step 4: Add `audit` to `CargoAppState`, open it in `bootstrap_cargo`, and emit in both handlers**

`cargo_index_handler` and `cargo_download_handler` each gain `ConnectInfo<SocketAddr>` and write through `audit_or_500` before responding.

- [ ] **Step 5: Run tests to verify they pass, then the gate**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/scan/cargo.rs src/http/cargo_index.rs src/http/cargo_download.rs src/http/cargo_bootstrap.rs tests/
git commit -m "feat(audit): log cargo index listings and crate downloads"
```

---

### Task 6: npm listing and download events

**Files:**
- Modify: `src/scan/npm.rs:242` (`NpmIndexDecision`), `src/scan/npm.rs:540-575` (the `NpmNextStep::Forward` arm)
- Modify: `src/http/npm_packument.rs:133` (`NpmAppState`), `:283` (`npm_packument_handler`), `src/http/npm_download.rs:127`
- Modify: `src/http/npm_bootstrap.rs` (open the `AuditLog`)
- Test: `tests/http_audit_npm.rs`

**Interfaces:**
- Consumes: everything Tasks 2–5 produced.
- Produces:
```rust
// src/scan/npm.rs — widened variant
pub enum NpmIndexDecision {
    Packument {
        doc: serde_json::Value,
        audit: crate::audit::ListingAudit,
    },
    NotFound,
    InProgress,
}

// src/http/npm_download.rs — the handler is not a route, so the context
// is threaded from the catch-all that dispatches to it
pub async fn npm_download_handler(
    state: &NpmAppState,
    ctx: &crate::audit::AuditContext,
    path: &str,
) -> axum::response::Response;
```

Same reason-code mapping as Task 5, minus `yanked` (npm's cascade keeps deprecated versions as candidates — see the npm design's "Deprecated versions stay candidates"). `versions_upstream` is `packument.versions.len()`. `NotFound` and `InProgress` emit nothing.

`npm_packument_handler` builds the one `AuditContext` for the request and passes it to `npm_download_handler` on the tarball branch, so a tarball fetch and the packument fetch that preceded it are each complete on their own line. The write and auth refusals (`npm_write_refused_handler`), `/-/ping` and the audit stubs emit nothing.

- [ ] **Step 1: Write the failing tests** in `tests/http_audit_npm.rs`

```rust
#[tokio::test]
async fn a_packument_listing_logs_only_the_versions_the_cascade_evaluated() {
    // packument with 40 versions, 3 evaluated
    assert_eq!(listing["versions_upstream"], 40);
    assert_eq!(listing["versions_evaluated"], 3);
    assert_eq!(listed.len(), 3);
}

#[tokio::test]
async fn a_cve_blocked_npm_version_is_a_denied_line_coded_cve() {
    assert_eq!(record["decision"], "denied");
    assert_eq!(record["reason_code"], "cve");
    assert_eq!(record["version"], "4.17.20");
    assert!(record.get("filename").is_none(), "npm decides per version");
}

#[tokio::test]
async fn an_npm_tarball_download_writes_a_served_line() {
    assert_eq!(record["event"], "served");
    assert_eq!(record["ecosystem"], "npm");
    assert_eq!(record["filename"], "lodash-4.17.21.tgz");
}

#[tokio::test]
async fn a_refused_npm_tarball_writes_a_refused_line_with_its_why_id() {
    assert_eq!(response.status(), 403);
    assert_eq!(record["event"], "refused");
    assert!(record["why_id"].is_string());
}

#[tokio::test]
async fn a_missing_npm_package_writes_no_audit_lines() {
    assert_eq!(response.status(), 404);
    assert_eq!(lines.len(), 0);
}

#[tokio::test]
async fn ping_audit_stubs_and_write_refusals_write_no_audit_lines() {
    assert_eq!(lines.len(), 0);
}

#[tokio::test]
async fn a_failed_audit_write_on_a_packument_returns_500_and_no_packument_json() {
    assert_eq!(response.status(), 500);
    assert!(!body.contains("\"versions\""), "no packument may be served: {body}");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test http_audit_npm`
Expected: FAIL — `NpmAppState` has no field `audit`.

- [ ] **Step 3: Widen `NpmIndexDecision::Packument` and build the `ListingAudit` in `src/scan/npm.rs`**

In the `NpmNextStep::Forward` arm, where `versions`, `cve_blocked`, `facts.too_new`, `facts.review_status` and `facts.allowlisted` are in scope. Update `tests/ecosystem_npm_packument.rs`, `tests/scan_npm.rs` and `tests/http_npm_packument.rs` for the new shape.

- [ ] **Step 4: Add `audit` to `NpmAppState`, open it in `bootstrap_npm`, thread the context into `npm_download_handler`, and emit in both paths**

- [ ] **Step 5: Run tests to verify they pass, then the gate**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/scan/npm.rs src/http/npm_packument.rs src/http/npm_download.rs src/http/npm_bootstrap.rs tests/
git commit -m "feat(audit): log npm packument listings and tarball downloads"
```

---

### Task 7: Operator documentation

**Files:**
- Modify: `docs/operations.md` (the `## Logging` section at `docs/operations.md:368`, and the config-reference table)
- Create: `docs/book/src/audit-log.md`
- Modify: `docs/book/SUMMARY.md`, `docs/book/src/http-surface.md`

**Interfaces:**
- Consumes: the shipped behavior of Tasks 1–6.
- Produces: no code.

- [ ] **Step 1: Write the `docs/operations.md` audit-log section**

Cover: the JSONL schema field by field; that `path` is a prefix and a shipper must glob the date suffix; `rotation` and `max_files`; that `[audit]` is restart-only and a reload that changes it is rejected in full; that a write failure is a 500 and what the accompanying `error!` says; that the file holds network-attributable developer data and wants its own permissions and retention; the steady-state line rate (one `listing` plus one line per evaluated version, per listing request, and that `npm install` refetches packuments for the whole tree); and the two honest limitations — a `served` line is written before the body streams, so a dropped transfer still reads as served, and records are flushed but not `fsync`ed per line.

- [ ] **Step 2: Write `docs/book/src/audit-log.md` and link it from `SUMMARY.md`**

The chapter answers the three queries the feature exists for: who fetched a version, who was denied it and why, and which versions were evaluated at all. Say plainly that a version absent from the log may simply never have been a cascade candidate, and that the `listing` line's counts are how a reader tells that apart from "never fetched".

- [ ] **Step 3: Note in `docs/book/src/http-surface.md` that no route exposes the audit log or a client IP, by design**

- [ ] **Step 4: Verify the book builds**

Run: `mdbook build docs/book`
Expected: success, no broken links.

- [ ] **Step 5: Commit**

```bash
git add docs/
git commit -m "docs(audit): document the fetch audit log for operators"
```

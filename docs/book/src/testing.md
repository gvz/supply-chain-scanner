# Testing

The crate is a library plus a thin binary specifically so integration tests can exercise the public API. Roughly 5,500 lines of source carry roughly 4,400 lines of test across eleven integration test files plus inline unit tests — 177 test functions in the integration suite alone.

## Layout

| File | Covers |
|---|---|
| `tests/config.rs` | config parse, validation, safe reload |
| `tests/db_verdict.rs` | verdict store semantics, fingerprint matching, why_id upsert |
| `tests/pypi_index.rs` | PEP 503 parse/render, name normalization/validation, filename parsing |
| `tests/upstream.rs` | upstream client, streaming hash, stale index cache fallback |
| `tests/policy.rs` | fingerprint contents, allowlist matching, CVE line |
| `tests/advisory_sync.rs` | OSV sync, atomic replace, fixture documents |
| `tests/advisory_match.rs` | PEP 440 matching, every fail-closed corner |
| `tests/plugin.rs` | sandbox outcomes, unpack rules incl. the zip-bomb fixture, plugin runner mapping |
| `tests/artifact_cache.rs` | content addressing, sliding TTL, eviction retries |
| `tests/scan.rs` (960 lines) | the whole decision path: budget, single flight, allowlist, re-check, every error path |
| `tests/http_refusal.rs` | phrase sanitization, budgeting, truncation priority, response construction |

## Techniques

- **wiremock** stands in for upstream PyPI and the OSV feed. No test touches the network. Error conditions (unreachable upstream, wrong bytes) are scripted precisely.
- **`tempfile`** gives every test disposable DB files, cache dirs, and plugin binaries.
- **The `SandboxRunner` trait** lets plugin-runner tests script sandbox outcomes (timeout, signal death, spawn failure) without bubblewrap. It also lets the scan tests construct a scanner with no sandbox at all.
- **Fixture OSV documents** in `tests/fixtures/osv/` (multi-package, ranges, no-severity, withdrawn) pin the parser's real-world corners.
- **A profile tweak** optimizes only the compression crates in the dev profile (see the comment at the bottom of `Cargo.toml`). The zip-bomb test must push more than the unpacker's 512 MiB limit through deflate, which is roughly 20x slower at `opt-level 0`.

## What the suite is shaped like

The tests read as a security argument more than a feature list. Nearly every fail-closed invariant in the [security model](./security-model.md) chapter has a test that constructs the failure and asserts the refusal. The e2e file for the full HTTP wiring (`tests/e2e.rs`, planned) does not exist yet. See the [roadmap](./roadmap.md).

Run everything with:

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```
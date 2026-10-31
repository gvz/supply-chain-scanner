# Architecture

One Rust crate, one process, one SQLite file. This chapter gives the tour. The following chapters go deep on each part.

Editable draw.io diagrams of everything below live in [`docs/diagrams/`](../../diagrams/). They are the fastest way to see the shape of the system, and they are kept in step with the code: start with `01-system-overview.drawio`.

## The crate

The crate is a library plus a thin binary (`Cargo.toml` declares both):

- `src/lib.rs` exports ten modules. Integration tests exercise the public API directly.
- `src/main.rs` parses CLI arguments, loads config, and initializes logging. The HTTP server wiring is not implemented yet (see [roadmap](./roadmap.md)).

```text
src/
├── model.rs          core domain types: ArtifactKey, Verdict, RefusalReason
├── config.rs         TOML config, live reload via ArcSwap
├── db/               the single SQLite file: verdicts, advisories, index/cache metadata
├── ecosystem/pypi/   PEP 503 index protocol, upstream client
├── advisory/         OSV mirror sync, PEP 440 matching
├── policy/           fingerprint, allowlist, CVE line
├── plugin/           unpacking, bubblewrap sandbox, fail-closed runner
├── scan/             the decision pipeline, single-flight, budget
├── artifact_cache.rs content-addressed on-disk cache, sliding TTL
└── http/             refusal responses, /why page
```

## Everything durable lives in one SQLite file

`Db::open` (`src/db/mod.rs`) opens one SQLite database with a WAL journal, foreign keys on, and a 5-second busy timeout, behind an `r2d2` connection pool. Four stores share that pool:

| Store | Table(s) | What it holds |
|---|---|---|
| `VerdictStore` | `verdicts` | one row per scanned artifact file |
| `AdvisoryStore` | `advisories` + two child tables | the local OSV mirror |
| `IndexCache` | `index_cache` | last fetched PEP 503 index page per package |
| `ArtifactCache` | `artifact_cache` | metadata for on-disk cached bytes |

Schema changes go through ordered migrations in `src/db/migrations.rs`. Each migration runs exactly once, inside a transaction, tracked by a `schema_version` table. Appending is a one-line change. Applied migrations are never edited.

All stores run inside `spawn_blocking` on the caller side — the async runtime never stalls on SQLite.

## The decision path

`Scanner::decide` in `src/scan/mod.rs` is the one place that decides whether an artifact may be served:

```text
entry has no declared hash -> Unverifiable (always, allowlist or not)
allowlist hit             -> still verify hash, then serve
stored blocked            -> refuse
stored clean              -> re-check advisories, then serve
no verdict (or stale)     -> full scan under budget, single flight
```

Inside a full scan, it stops at the first failure:

```text
advisory lookup -> download -> hash verify -> unpack + plugins -> store clean, cache, serve
```

The full story is in the [scan pipeline](./scan-pipeline.md) chapter.

## Ecosystem separation

`src/ecosystem/` holds the genuinely PyPI-specific parts: the PEP 503 index protocol, name normalization, filename parsing, the upstream HTTP client. The plan is a shared `Ecosystem` trait once a second ecosystem exists. With it, npm and cargo can be added without touching the store, policy engine, plugin runner, or advisory matcher. The trait is not implemented yet (see [roadmap](./roadmap.md)).

## Concurrency model

- **Runtime:** tokio, multi-threaded.
- **Blocking work** (SQLite, sandboxed process runs, archive unpacking) goes through `spawn_blocking` with explicit `JoinError` handling.
- **Single flight:** concurrent requests for the same not-yet-verdicted artifact share one scan, keyed by artifact sha256 (`ScanCoordinator` in `src/scan/coordinator.rs`).
- **Budget:** first-time scans run under `tokio::time::timeout` against `scan_budget` (default 12s, hard ceiling 14s — below pip's 15s default timeout). A scan that exceeds the budget is not cancelled. It keeps running, detached, and stores its verdict when it finishes, so a retry lands on a stored decision.

## Stack

Rust 2021, pinned to 1.88.0 via `rust-toolchain.toml`.

- axum 0.8 over HTTP/1.1, reqwest with rustls
- rusqlite (bundled SQLite, no system dependency), serde + toml
- zip, tar, flate2 for archives. pep440_rs for version ordering. sha2 for hashing
- tracing for logs, clap for the CLI

Dev tests use wiremock for the upstream HTTP doubles and tempfile for scratch space.
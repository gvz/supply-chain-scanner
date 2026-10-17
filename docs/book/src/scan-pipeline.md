# The scan pipeline

`src/scan/mod.rs` — `Scanner::decide` is the one place that decides whether an artifact may be served. It composes every other module into a single decision path.

## The decision path

```text
entry has no declared hash -> Unverifiable (always, allowlist or not)
allowlist hit              -> still verify hash, then serve
stored blocked             -> refuse, with why_id
stored clean               -> re-check advisories, then serve
no verdict, or stale       -> full scan under budget, single flight
```

And inside a full scan, stopping at the first failure:

```text
advisory lookup -> download -> hash verify -> unpack + plugins -> store clean, cache, serve
```

## The Decision enum

```rust,ignore
pub enum Decision {
    Serve(PathBuf),
    Refuse { reason: RefusalReason, why_id: Option<String> },
    InProgress,
    Unverifiable(RefusalReason),
}
```

- `Serve` — the artifact may be served from the given path.
- `Refuse` — the artifact must not be served. `why_id`, when present, names the stored verdict behind `/why/<id>`. It is `None` for refusals with nothing durable behind them — a hash mismatch, never persisted because it may be transient download corruption.
- `InProgress` — the scan exceeded the budget and is still running.
- `Unverifiable` — "cannot verify right now", **never** "verified and blocked", and never stored as a verdict.

## No hash means unverifiable, period

An index entry with no `#sha256=` fragment is `Unverifiable` ahead of every other rule, **including the allowlist**. There is nothing to verify a download against, so it can never be scanned honestly. The allowlist overrides a *verdict*, never the integrity check the bytes must pass regardless.

## Stored clean is never a lifetime pass

A `Clean` verdict under today's policy is re-checked against the advisory mirror on **every** request. A package clean when scanned may have a CVE filed since. If an advisory matches and blocks, the fresh blocked verdict is stored, replacing the clean one, and the artifact is refused.

## The budget

First-time scans run inside `tokio::time::timeout` against `scan_budget` — default 12s, config-rejected above 14s, hard ceiling below pip's own 15s default timeout.

The key property: **a timed-out scan is never cancelled.** The scan task runs detached. Only the *caller's wait* ends at the budget. The scan keeps running, stores its verdict when it finishes, and the caller returns `InProgress`. A developer's retry a moment later lands on a stored decision instead of restarting the scan from zero.

The allowlist and stored-clean fetch paths get the same detached-plus-budget treatment. A slow upstream must not block a caller past the budget. The download keeps running, so a retried request finds a warm cache.

## Single flight

N concurrent requests for the same not-yet-verdicted artifact must not trigger N downloads and N plugin sweeps. `ScanCoordinator` (`src/scan/coordinator.rs`) dedups by **sha256** — that is what concurrent requests for "the same artifact" actually share, even when the filenames differ.

The first caller is the **owner**: it runs the scan and reports the outcome. Later callers **join**: they clone a `watch::Receiver` and wait. The channel deliberately carries `Option<Verdict>` — only a genuine scan outcome (clean or blocked) is safe for a joiner to reuse. A scan that fails before producing a verdict sends nothing and drops its sender. A joiner observing that fails closed to `Unverifiable`.

`FinishGuard` is a RAII guard constructed as the **first** statement in the owner's task. Its `Drop` removes the coordinator's map entry on every exit path, including a panic in the scan body. Without it, a panic would leak the in-flight entry. Every later request for that sha256 would join a dead receiver forever: a permanent denial of service for one artifact. The whitebox test in `src/scan/mod.rs` proves a panicked owner lets the next request rescan rather than hang.

## Fail-closed internals

Nothing in the pipeline produces `Serve` or stores `Clean` from an error path. An upstream outage. A hash mismatch. A plugin that could not run. A database error. A panic in a blocking task. Each of these becomes `Refuse` or `Unverifiable`, never a guess in the artifact's favor.

- Every blocking call (verdict lookup/store, advisory lookup, cache get/insert, unpack) goes through `spawn_blocking` with explicit `JoinError` handling.
- All DB lookup errors become `Unverifiable`, not empty-seen-as-clean.
- Internal and upstream error details are stripped of control and non-ASCII characters. They are capped at 200 characters before they can flow toward a reason phrase.

One cleanup detail: a freshly downloaded artifact that fails later scan steps is explicitly removed. The unpack destination is wiped on any unpack error. A partial extraction is a package the plugin would scan incompletely and pass.

## The full pipeline, step by step

1. **Advisory lookup** — the local mirror for `(ecosystem, package)`. First blocking advisory ends the scan, stores a blocked verdict, returns `Refuse`.
2. **Bytes** — reuse cached bytes for this content hash if present (a policy-change rescan does not pay for a redundant download). Otherwise download to a temp dir, comparing the streamed SHA-256 against the index-declared hash as it lands. A mismatch is `Refuse`, not stored.
3. **Unpack + plugins** — unpack into a fresh temp dir (see [plugins](./plugins.md)) and run every configured plugin. A cache hit is handed to unpack through a symlink named with the real filename, since content-addressed cache paths carry no extension.
4. **Store clean, cache, serve** — store the `Clean` verdict under the fingerprint, insert the artifact into the content-addressed cache, serve.

`tests/scan.rs` (960 lines) pins every branch of this path, against wiremock upstreams and an in-memory fake sandbox.
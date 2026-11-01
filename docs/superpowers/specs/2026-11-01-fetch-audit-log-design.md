# Supply Chain Scanner — Fetch Audit Log — Design

**Date:** 2026-11-01
**Status:** Design, approved scope for planning
**Extends:** `docs/superpowers/specs/2026-10-17-supply-chain-scanner-design.md`
**Touches all three ecosystems:** the PyPI, cargo and npm deployments described in
`2026-10-19-cargo-ecosystem-design.md` and `2026-10-30-npm-ecosystem-design.md`

## Intent

Give the organization's security team a record of **which client fetched which
package version, and which versions were withheld from which client and why**,
across every ecosystem this proxy serves.

### Why now

The proxy already decides well. What it cannot do is answer a question asked
*after* the fact. A CVE is disclosed for a version this proxy forwarded last
month. Security needs to know which machines pulled it, so they can go clean
those machines. Today that question has no answer: the stdout access log records
method, path, status and duration, and nothing at all identifies the client.

This is retroactive blast-radius work. The log is not a gate and changes no
verdict — it is the evidence trail that makes a past decision auditable.

The author also asked for the other half: which versions were **denied**, with
the reason, and which versions were **allowed**. A security team chasing an
incident needs both sides. "Nobody could have pulled it, it was filtered out for
everyone" is as valuable an answer as a list of affected IPs.

## Goals

- **Answer "who fetched this version".** Given a package and a version, a query
  over the shipped log returns the client IPs that received it, with timestamps.
- **Answer "who was denied this version, and why".** Same query shape, returning
  the refusal reason in this proxy's existing vocabulary, linkable to `/why/<id>`.
- **Answer "which versions were allowed".** A listing response's surviving
  versions are recorded, not just the blocked ones.
- **Keep "never evaluated" distinguishable from "never asked for".** Only
  versions the cascade actually evaluated get a verdict line, so each listing
  request also records how many versions it evaluated out of how many existed.
- **Cover all three ecosystems.** PyPI, cargo and npm deployments all produce the
  same event shapes, so three shipped logs merge into one queryable stream.
- **Be complete or refuse.** An un-logged fetch must not happen. See "Fail closed".
- **Ship cleanly.** JSON Lines on disk, one object per line, tailed by a log
  shipper into Loki or equivalent.

## Non-goals

- **No query interface.** No HTTP route, no CLI subcommand, no SQL table reads
  this log. Loki is the query tool. (And see the anti-goals: a route would be a
  disclosure risk.)
- **No identity beyond the network address.** No attempt at user accounts, no
  auth, no mapping IP to a person or host. The author was asked whether DHCP
  churn would make a bare IP useless weeks later and chose not to enrich.
- **Not a replacement for the stdout access log.** The existing `access_log`
  middleware stays exactly as it is, on the PyPI router, serving the
  refusal-rate-measurement purpose its own docs describe.
- **No change to any verdict.** Nothing in this design alters what gets blocked.
- **No new persistence in SQLite.** The verdict store is not extended.

## Anti-goals

Each of these would make the feature a failure even if it technically worked.

- **A client IP reachable over HTTP.** The author's explicit constraint: client
  IPs must not be visible on any of this proxy's open API routes. `/refusals`,
  `/why/<id>` and `/api/reviews` are unauthenticated and are read by the same
  developers whose fetches are being logged. An audit log that turns the proxy
  into a surveillance read-out for anyone who can reach it is worse than no log.
- **Silent holes.** A log that quietly stops recording — disk full, path
  unwritable — while the proxy keeps serving is actively misleading: it makes
  "not in the log" look like "not fetched". This is what drove the fail-closed
  decision.
- **Logging that changes a verdict.** If an audit write failure were to turn into
  a *refusal* with a supply-chain reason code, operators would hunt for a
  non-existent policy problem. A failure here is a 500, not a 403.
- **Per-request cost that pushes developers off the proxy.** The base design's
  false-positive anti-goal applies: a developer who finds installs slow switches
  back to the public registry and gets no gate at all.

## Shape

### Four event kinds

Every line is one JSON object. Every line carries, without exception:

| Field | Meaning |
|---|---|
| `ts` | RFC 3339 UTC, millisecond precision |
| `event` | `listing`, `listed`, `served` or `refused` |
| `ecosystem` | `pypi`, `cargo` or `npm` — the deployment's own id |
| `client_ip` | the TCP peer address |
| `client_port` | the TCP peer port |
| `request_id` | random per HTTP request, groups a listing's many lines |
| `package` | the normalized package name |

Then, per kind:

**`listing`** — one line per listing request, written before its `listed` lines.

- `versions_upstream`: how many versions upstream's listing carried
- `versions_evaluated`: how many of them the cascade actually evaluated

This line exists because of the scoping decision below: only evaluated versions
get a verdict line. Without it, a query for a CVE version that was never a
cascade candidate returns nothing — indistinguishable from a package nobody ever
fetched. With it, the gap is visible: 1 of 847 evaluated, and the reader knows to
stop concluding anything from the silence.

**`listed`** — one line per **evaluated** version in a listing response. Emitted by the PEP 503
simple page (`src/http/simple.rs`), the cargo sparse index
(`src/http/cargo_index.rs`) and the npm packument (`src/http/npm_packument.rs`).

- `version`
- `decision`: `allowed` or `denied`
- `reason_code`, `reason_detail`: present when `denied`; also present on an
  `allowed` line that survived only because of the allowlist, carrying an
  `allowlisted` code — `simple.rs` deliberately keeps allowlisted versions
  visible even when blocked, and a reader has to be able to tell that apart from
  an ordinary pass.
- `why_id`: when a stored verdict exists for it.

**Only evaluated versions get a line.** The author's decision. A large npm
packument carries on the order of a thousand versions, but `scan/npm.rs` picks
newest-per-major as candidates and scans only those; cargo's index cascade
behaves the same way. Everything else is omitted from the response without ever
being looked at, so it has no verdict and no reason to report. Logging those
would multiply the volume by two orders of magnitude to say "no opinion" a
thousand times. The `listing` line above carries the count instead.

This is the half that matters most on cargo and npm, where the listing *is* the
gate and a denied version is simply absent from the response. The client never
requests it, so there is no 403 anywhere to find it by. The author explicitly
asked for these filtered-out versions to be carried, attributed to the IP that
requested the listing.

**`served`** — a download that delivered bytes. From `src/http/artifact.rs`,
`src/http/cargo_download.rs`, `src/http/npm_download.rs`.

- `version`, `filename`, `sha256`

**`refused`** — a download that got a refusal response.

- `version`, `filename`
- `reason_code`, `reason_detail`, `why_id`

### The reason vocabulary is the existing one

`reason_code`, `reason_detail` and `why_id` are the columns `db/verdict.rs`
already stores and `/why/<id>` already renders. The audit log reuses them
verbatim rather than inventing a parallel vocabulary, so a Loki hit on a denial
carries the id that opens this proxy's own explanation page for it.

### Client IP is the TCP peer address

Nothing sits in front of this proxy — the author confirmed clients connect
directly. So `X-Forwarded-For` is **ignored entirely**: with no trusted hop, the
header could only be a spoof, and honouring it would let a client forge its own
identity in a security log.

The peer address is not currently available anywhere in the process.
`main::serve` (`src/main.rs:274`) calls `axum::serve(listener, router)`, which
exposes no connection info. This becomes
`axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())`
and handlers reach it through `ConnectInfo<SocketAddr>`.

Note for the builder: this changes the service type, and `tests/e2e.rs` and
`tests/logging.rs` both call `axum::serve` directly on a router.

### Only two of three routers log anything today

`access_log` is layered on the PyPI router only (`src/http/mod.rs:102`).
`cargo_router` (`src/http/cargo_index.rs:165`) and `npm_router`
(`src/http/npm_packument.rs:160`) have no access log at all. Audit emission has
to reach all three. Non-package routes — `/healthz`, `/why/<id>`, `/refusals`,
`/api/reviews`, `/-/ping`, the npm audit stubs, the npm write refusals — emit no
audit lines; they fetch no package.

### Fail closed

The author's decision: if the audit record cannot be written, the request fails
with **500 Internal Server Error** and no package bytes leave the process. A full
disk stops every build in the organization, which the author accepted explicitly
in exchange for the guarantee that absence from the log means absence of a fetch.

Two consequences the builder must respect:

1. **The record is written before the response body.** For a download that means
   before the first byte of the artifact is streamed. Writing afterwards would
   make fail-closed unenforceable.
2. **The writer cannot be a `tracing` layer.** `tracing` macros cannot fail, so a
   subscriber-based sink has no way to turn a write error into a 500. The audit
   log is therefore its own component with a fallible write call, not a
   `tracing_subscriber` layer and not the non-blocking appender (which buffers
   and drops by design).

A failed write also emits an `error!` on stdout, so the operator sees the cause
and not only a wave of 500s.

**Durability boundary (my call, flagged):** a record is written and flushed to
the OS, not `fsync`ed per line. At the volume this log runs at, a sync per line
would dominate request latency. The guarantee is therefore "no fetch without a
successful write", not "no fetch without a durable write" — a kernel panic can
lose the last records. Worth knowing before the log is treated as forensic
evidence.

**Honest limitation:** a `served` line is written before the body streams, so a
connection that drops mid-transfer still shows as `served`. The alternative —
logging after the last byte — breaks fail-closed. This mirrors a nuance
`docs/operations.md` already documents for `elapsed_ms`.

### Volume is accepted, deliberately

One line per version decision, by the author's choice over the compact
alternative (a single line per request carrying arrays). The author chose this
for direct queryability in Loki — a version is a field, not a nested array
needing unpacking.

Scoping to evaluated versions keeps this affordable. A packument fetch emits one
`listing` line plus a line per candidate — tens, not a thousand. The cost that
remains is repetition: every `npm install` refetches the packument for every
package in the tree, so a CI run with a few hundred dependencies emits thousands
of lines, most of them restating verdicts that have not changed since the last
run. That belongs in the operator docs as an expected steady-state rate, not as
a surprise.

### Configuration

A new `[audit]` table:

- `path` — the JSONL file to write
- `rotation` — daily (see "Decided")
- `max_files` — how many rotated files to keep

`[audit]` is **restart-only**: it joins `RESTART_ONLY_FIELDS` in `src/http/mod.rs`
next to `bind` and `db_path`, because the open file handle is built once at
startup. The existing reload contract already rejects such a change in full and
names the field, which is the right behaviour here — an operator must not believe
a redirected audit log went live when it did not.

Whether `[audit]` is mandatory or optional is left open; see "Left to the
builder".

### Where the IP is, and is not

The client IP exists in exactly one place: the audit file. It is not written to
SQLite, so the verdict store gains no IP column and `/refusals`, `/why/<id>` and
`/api/reviews` cannot expose one — the constraint holds by construction rather
than by a filter someone has to remember. No audit-reading HTTP route is built.

Operator note worth carrying into `docs/operations.md`: this file now contains
network-attributable data about developers, which the stdout log did not. It
deserves different filesystem permissions and a different retention policy from
the rest of the logs.

### Deployment

One process serves one ecosystem (`src/main.rs`, and the base design's rule). So
one audit file per deployment, three files for an organization running all three.
Each line carries `ecosystem` anyway, so the merged stream stays unambiguous.

## Constraints

- **Rust 1.88.0**, pinned by `rust-toolchain.toml`. Any new dependency must build
  on it — the `uuid = "=1.11.0"` pin in `Cargo.toml` exists for exactly this
  reason and is a live trap for a careless `cargo update`.
- **axum 0.8**, HTTP/1.1 only; neither axum nor hyper is built with `http2`.
- **The existing reload contract** must not be weakened: partial application is
  rejected in full, with the field named.
- **`cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`**
  is the gate, per `README.md`.
- **The fail-closed habit** already runs through this codebase (the AI reviewer's
  provider wiring, the plugin sandbox). This feature follows it rather than
  introducing an exception.

## Decided

**By the author:**

- Both outcomes in one log: allowed versions and denied versions with reasons.
- Versions filtered out of a listing are logged too, attributed to the IP that
  requested the listing.
- JSON Lines, shipped to Loki or similar.
- One line per version decision, accepting the volume.
- Only versions the cascade actually evaluated get a verdict line; versions it
  never considered are not logged.
- Fail closed on a write failure, returning 500 Internal Server Error.
- No reverse proxy in front; peer IP is the client.
- Client IPs must never be visible on any open API route.
- No enrichment beyond the network address.

**By me, as the designer:**

- `X-Forwarded-For` ignored outright rather than configurably trusted.
- `client_port` included alongside the IP, so the operator can correlate against
  NAT or conntrack records on their own side. It leaks nothing further.
- `request_id` included, so the many `listed` lines of one packument fetch can be
  grouped in a query.
- Reason vocabulary reused from the verdict store rather than redefined.
- Non-package routes emit nothing.
- The existing stdout access log is kept unchanged.
- Daily rotation with a kept-file count, via `tracing-appender`'s rolling
  appender (blocking, not the non-blocking wrapper) — it already does daily
  rotation and a `max_log_files` bound, so this needs no hand-rolled rotation.
- `[audit]` is restart-only.
- Flush per record, no `fsync` per record.
- An `allowed` line records the `allowlisted` reason code when that is why it
  survived.
- The `listing` event, with its evaluated-of-total counts. Scoping to evaluated
  versions is the author's call; this line is mine, and it is what keeps that
  scoping from turning into the "silent holes" anti-goal.
- `max_files` defaults to 14.
- A listing served as a `304 Not Modified` emits no lines — the proxy conveyed no
  version data on that response, and the client is reading bytes it already had.
  A listing rendered from this proxy's own index/etag cache *does* emit lines:
  the client is receiving versions, cache or no cache.
- An artifact served out of the artifact cache is a `served` line like any other.

## Left to the builder

- **Reasons for PyPI's filtered versions.** `simple.rs` filters using
  `Scanner::blocked_filenames`, which returns filenames and no reasons. Getting
  `reason_code`/`reason_detail`/`why_id` onto a PyPI `listed` denial needs that
  path widened, or a verdict lookup per filtered entry. Cargo and npm carry
  richer decision types already (`CargoIndexDecision`, `NpmIndexDecision`,
  `DownloadApproval`) but should be checked for whether the reason survives to
  the handler.
- **Where emission sits.** A middleware sees the path but not the parsed package,
  version or decision; the handlers see all of it. The likely answer is emission
  in the handlers with a shared `AuditLog` in each router's state, but the split
  is the builder's to settle.
- **Verify the appender choice.** The `tracing-appender` rolling appender is
  named above on the strength of its documented daily rotation and
  `max_log_files` bound. Confirm both on a version that builds under rustc
  1.88.0, and confirm its `io::Write` surfaces write errors rather than
  swallowing them — fail-closed depends on that. Hand-rolled rotation is the
  fallback, not the starting point.
- **Lock granularity.** A single mutex around the file at this volume is a
  contention point. Writing all of one listing's lines under one acquisition is
  the obvious mitigation.
- **Whether `[audit]` is required.** Mandatory matches the fail-closed spirit and
  is a breaking config change for existing deployments; optional-but-off is
  gentler and makes it possible to run with no audit trail. Pick one and say so
  in `docs/operations.md`.
- **Startup validation.** Failing at boot on an unwritable audit path is far
  kinder than discovering it on the first fetch, when the symptom is 500s.
- **Test strategy.** `tests/logging.rs` is its own test binary specifically
  because a global `tracing` subscriber is a per-process resource. The audit log
  is *not* a subscriber, so it may well be testable in an ordinary integration
  test against a `tempfile` path — including the fail-closed path, which an
  unwritable directory can exercise directly.
- **Docs.** `docs/operations.md` needs a section (volume, permissions, retention,
  the restart-only field, what a 500 from a write failure looks like) and
  `docs/book/src/` a chapter. `config.example.toml` needs the `[audit]` table.
  The diagrams in `docs/diagrams/` show the per-ecosystem request flows and are
  where a reviewer will look for this.

# The fetch audit log

`src/audit.rs` — a fail-closed, JSON Lines record of which client fetched which package version, and which *evaluated* versions were withheld from which client and why. All three deployments (PyPI, cargo, npm) write it, in the same shape.

The stdout access log (`access_log`, PyPI only) answers "is the proxy healthy". This log answers a different question, asked after the fact: a CVE is disclosed for a version this proxy forwarded last month, and security needs to know which machines pulled it. The verdict store and `/why/<id>` can say what the proxy decided; only this log can say *who it decided it for*.

## The three queries this exists to answer

1. **Who fetched this version?** Grep the shipped log for `"event":"served"` lines naming the package and version. Each carries `client_ip`, `client_port` and `ts`.
2. **Who was denied this version, and why?** On a download, a `refused` line. On cargo and npm, where a denied listing version never reaches a download at all, a `listed` line with `"decision":"denied"` — the only place that denial is visible anywhere in this proxy, since there is no 403 to find it by.
3. **Which versions were evaluated at all?** The `listing` line that opens every listing request's block of lines. See the next section — this is the one query a reader gets wrong by assuming silence means something it doesn't.

## "Absent from the log" is not "never fetched"

A `listed` record exists only for a version the proxy actually reached a verdict on. On cargo and npm, the cascade evaluates a handful of a package's versions per request — the newest per major line, roughly — and never looks at the rest; on PyPI, "evaluated" means an entry with a stored verdict under the policy fingerprint this process is currently running, which on a large, mostly-unscanned index is a small fraction of what upstream lists.

So a query for some specific version that returns nothing is ambiguous on its own: it could mean "nobody fetched it", or it could mean "the cascade never looked at it, so there was never an opinion to record". The `listing` line is what breaks that tie. It carries `versions_upstream` (how many versions, or on PyPI how many index entries, upstream's response carried) and `versions_evaluated` (how many of those got a `listed` line). `1 of 847 evaluated` tells a reader to stop concluding anything from the other 846 being silent. Logging a verdict for every one of those would multiply the volume by two orders of magnitude to say "no opinion" at scale — the `listing` line carries the count instead, for the cost of one line instead of hundreds.

## The four event kinds

Every line is one JSON object, one event, written as the proxy makes the decision it describes — never retroactively. Every line, regardless of kind, carries:

| Field | Meaning |
|---|---|
| `ts` | RFC 3339, UTC, millisecond precision |
| `event` | `listing`, `listed`, `served`, or `refused` |
| `ecosystem` | `pypi`, `cargo`, or `npm` — this deployment's own id |
| `client_ip` | the TCP peer address |
| `client_port` | the TCP peer port |
| `request_id` | 16 lowercase hex characters, random per HTTP request — groups one listing request's many `listed` lines, and the one `served`/`refused` line a download produces |
| `package` | the normalized package name |

Every other field is specific to one event kind and is **omitted entirely when absent — never written as `null`**. A line's shape tells you its kind without consulting `event` first.

### `listing` — one per listing request

Emitted by the PEP 503 simple page (`src/http/simple.rs`), the cargo sparse index (`src/http/cargo_index.rs`) and the npm packument (`src/http/npm_packument.rs`), written before that request's own `listed` lines.

| Field | Meaning |
|---|---|
| `versions_upstream` | how many versions (cargo, npm) or index entries (PyPI) upstream's response carried |
| `versions_evaluated` | how many of them got a `listed` line below |

### `listed` — one per evaluated version in a listing response

| Field | Meaning |
|---|---|
| `version` | the version decided |
| `filename` | present only on PyPI, which decides per file; absent on cargo and npm, which decide per version |
| `decision` | `allowed` or `denied` |
| `reason_code`, `reason_detail` | present on `denied`; also present on an `allowed` line that survived only because of the allowlist (`reason_code: "allowlisted"`) — simple.rs deliberately keeps an allowlisted-but-otherwise-blocked entry visible, and a reader needs to be able to tell that apart from an ordinary pass |
| `why_id` | present when a stored verdict backs the decision |

### `served` — a download that delivered bytes

| Field | Meaning |
|---|---|
| `version`, `filename` | the artifact served |
| `sha256` | the digest the bytes were verified against — see "the field is misnamed on npm" below |

### `refused` — a download that got a refusal response

| Field | Meaning |
|---|---|
| `version` | always present |
| `filename` | present whenever an index/packument entry was actually matched; absent for cargo's `not-index-approved` and npm's `not-packument-approved`, where no entry was ever matched to name one from |
| `reason_code`, `reason_detail` | the refusal, in the vocabulary below |
| `why_id` | present when a durable verdict backs the refusal |

## `versions_upstream` counts different units per ecosystem — on purpose

On PyPI, `versions_upstream` is a count of index **entries** — files, which is pip's own unit, so one version with a wheel and an sdist counts as two. On cargo and npm it is a count of **versions**. The field name is shared across all three anyway, deliberately: three deployments shipping logs with the same field names is what lets an organization merge three files into one queryable stream and filter by `ecosystem` rather than writing three separate queries. A reader who assumes a PyPI `versions_upstream` counts distinct versions the way cargo's and npm's do will read it high.

## The reason vocabulary is the existing one

`reason_code`, `reason_detail` and `why_id` are exactly the columns `src/db/verdict.rs` already stores and `/why/<id>` already renders — not a parallel vocabulary invented for this log. A denial's `reason_code` therefore opens the same `/why/<id>` page a 403 on that same version would link to, when `why_id` is present.

The codes actually emitted:

| Code | Meaning |
|---|---|
| `cve:<advisory-id>` | blocked by the CVE line. When several advisories match, the lexicographically smallest id is chosen, deterministically. |
| `too-new` | younger than the configured `min_release_age_days`. |
| `yanked` | cargo only. npm's cascade keeps deprecated versions as candidates (ordinary installs depend on resolving them), so there is no npm equivalent. |
| `allowlisted` | on an **allowed** line — the version survived the cascade, or stayed visible on the PyPI page, only because an operator allowlisted it. |
| `not-index-approved` | cargo only: a `.crate` download for a version the sparse-index cascade never admitted. |
| `not-packument-approved` | npm only: a tarball download for a version the packument cascade never admitted. |
| `hash-mismatch` | the downloaded bytes did not match the registry-declared digest. Logged on every ecosystem's download path. This is the highest-signal line this log carries: bytes that do not match what the registry itself declared. |
| `plugin:*` | an organization-supplied plugin refused the artifact, or failed to run. |
| `ai:*` | the AI reviewer refused the artifact (`ai:malicious`, `ai:suspicious`, `ai:coverage`, `ai:opaque-executable`). |

## Which routes emit what

A `listed` line requires a verdict; a `served`/`refused` line requires a response that was actually reached by evaluating something. So:

- **A 403 refusal is always logged** as `refused` — including a hash-mismatch refusal, and including cargo's `not-index-approved` and npm's `not-packument-approved`, both of which refuse without ever matching an index entry.
- **A 503 "unverifiable" is never logged.** Nothing was verified and no verdict was reached — there is nothing yet for a line to describe. The same request logs its own line later, if a retry resolves to `Serve` or `Refuse`.
- **A 404 is never logged.** Upstream has already said "no such package" or "no such version"; this proxy evaluated nothing.
- **A 429 "still in progress" is never logged**, for the same reason as the 503 case: the scan that will eventually produce a verdict has not finished yet.
- **Non-package routes emit nothing**, because they fetch no package: `/healthz`, `/why/{id}`, `/refusals`, `/api/reviews`, `/config.json`, `/-/ping`, npm's two security-audit stubs, and npm's write/auth refusals (`npm publish`, `npm login`, and the like).

## Configuration

A new, **required** `[audit]` table. An existing config file with no `[audit]` table fails to parse — there is no "logging off" default, because the whole point of this feature is that an un-logged fetch must never happen.

| Field | Default | Meaning |
|---|---|---|
| `path` | required | A filename **prefix**, not the exact file written. The rolling writer appends a date suffix, so `audit.jsonl` becomes `audit.jsonl.2026-11-01` (daily) or `audit.jsonl.2026-11-01-14` (hourly). A log shipper has to glob on the prefix, not tail one fixed name. |
| `rotation` | `daily` | `daily` or `hourly`. |
| `max_files` | `14` | How many rotated files to keep before the oldest is deleted. |

`[audit]` is **restart-only**, alongside `bind` and `db_path`: the open file handle is built once at startup, so there is no "close the old file, open the new one" step a `SIGHUP` reload could trigger. A reload that changes it is rejected in full, naming `audit` — the existing reload contract's rule that partial application never happens, applied here because believing a redirected audit log went live when it did not would be worse than refusing the reload.

## Fail closed

A write failure returns **500 Internal Server Error**, with no package bytes and no index/packument content — never a 403. A write failure is an operational fault in this process (a full disk, a permissions change, a vanished mount), not a verdict about the package, and reporting it as a 403 would send an operator hunting a policy problem that does not exist. The cause is logged at `error!` on stdout at the same call site, so a 500 never arrives at an operator's dashboard without an explanation beside it.

The trade this accepts, deliberately: a full disk stops every build in the organization, on every ecosystem this proxy serves. That is the cost of the guarantee the feature exists to provide — absence from the log means absence of a fetch, not a silent gap that looks identical to one.

An unwritable configured path fails **at startup**, not on the first request. `bootstrap` opens the audit log early in its fail-closed startup sequence, before the router is built, so a misconfigured path is a boot failure with the path named in the error, rather than a wave of 500s discovered hours later on a developer's first fetch.

## Security and privacy

The client IP exists in exactly **one** place in this proxy: this file. It is never written to SQLite — the verdict store gains no IP column — and it is never exposed on any HTTP route. `/refusals`, `/why/<id>` and `/api/reviews` are all unauthenticated and read by the same developers whose fetches this log describes; the constraint holds by construction (there is nowhere else in the process the IP ever travels to), not by a filter someone has to remember to apply.

`X-Forwarded-For` is never read. Nothing sits in front of this proxy, so the header could only be a client forging its own identity, and honouring it would let a developer write someone else's address into a security log. The logged address is always the raw TCP peer, via axum's `ConnectInfo`.

This file now holds network-attributable data about real developers — source IP, package, version, timestamp — which the stdout access log never did. It deserves its own filesystem permissions and its own retention policy, separate from the rest of this proxy's logs.

## Volume

One `listing` line, plus one `listed` line per evaluated version, per listing request. Scoping to evaluated versions keeps this affordable: a packument fetch emits one `listing` line and a line per candidate — tens, not the thousand-plus versions a popular package's full history might carry.

The cost that remains is repetition, not breadth: **every `npm install` refetches the packument for every package in the dependency tree.** A CI run with a few hundred dependencies therefore emits thousands of lines on a single install, most of them restating verdicts that have not changed since the last run. That is expected steady-state behavior, not a leak or a bug — size log storage and retention for it rather than being surprised by it.

## Three honest limitations

1. **A `served` line is written *before* the response body streams.** Fail-closed requires the write to happen first — writing after the body would make an un-logged artifact-serve possible, which defeats the guarantee. The consequence: a connection that drops mid-transfer still produces a `served` line. The record means "this proxy decided to serve these bytes to this client," not "these bytes arrived." (`docs/operations.md`'s own note on `elapsed_ms` measuring time-to-headers, not time-to-last-byte, is the same shape of caveat.)

2. **Records are flushed to the OS, not `fsync`ed per line.** At this log's volume, a sync on every line would dominate request latency. The guarantee this provides is "no fetch without a successful write," not "no fetch without a *durable* write" — a kernel panic between the flush and the disk committing it can lose the tail of the file. Know this before treating the log as forensic evidence of exactly what happened in the seconds before a crash.

3. **On npm, the `sha256` field on a `served` line carries whatever digest npm itself declared — which is frequently a SHA-1 or a SHA-512, never a SHA-256.** The field name predates this feature and was never renamed for it; npm's registry never actually publishes a SHA-256 for a tarball (see the integrity-cache note in `docs/operations.md`'s "Integrity" section — the digest's own length is 40 hex characters for SHA-1 or 128 for SHA-512, never 64). An operator correlating this field against an external record needs to know which algorithm actually produced it before assuming "sha256" in the field name is "sha256" in the value.

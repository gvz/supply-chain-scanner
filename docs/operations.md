# Operating the scanner: behaviour, limits, and known gaps

Written for whoever deploys this proxy. It records what the tool guarantees, what
it deliberately does not, and the defects known at the time the initial
implementation landed. Nothing here is aspirational — every item was observed in
the code or in a live run.

## What it is

A single binary. One SQLite file. No external services at request time. Point pip
at it with `index-url` and nothing else changes on the developer's machine.

Client-facing HTTP is **HTTP/1.1 only**, deliberately. pip never prints response
bodies, so the only channel that reaches a developer is the status line's reason
phrase — and HTTP/2 does not have one. The binary is built without h2 so it
cannot negotiate the channel away.

## Startup is fail-closed, and these things stop it

In order: open the database (migrations run here) → build the policy → detect the
sandbox, but only if plugins are configured → build the scanner → sync the
advisory mirror if it is empty → start the tickers → install the SIGHUP handler →
bind the listener. The listener is bound **last**, so an empty advisory mirror can
never answer a request.

It refuses to start when:

- a configured plugin binary is missing or unreadable
- `bwrap` is not on `PATH` and at least one plugin is configured
- `bwrap` is not on `PATH` and `[ai_review]` is present
- an `[ai_review]` table with an unresolvable `api_key_env` or a `base_url` the
  rules above reject
- the database cannot be opened — note the parent directory of `db_path` is **not**
  created for you
- the initial advisory sync fails

That is intentional. A proxy that cannot run the checks the organization
configured must not run with fewer of them.

**Cold start is slow.** The first boot downloads the whole OSV PyPI feed (~26,000
documents), parses it in memory, and writes it in one transaction before binding.
Expect tens of seconds to minutes and a large transient memory spike. The sync
client has no timeout, so a stalled feed stalls startup indefinitely — fail-closed,
but it looks like a hang.

## Configuration reload (SIGHUP)

A reload rebuilds the policy and the sandbox, so tightening the CVE line or
changing the plugin list takes effect, and stored verdicts produced under the old
policy are invalidated through the policy fingerprint. A reload that does not
validate — a missing plugin binary, say — fails and keeps the running policy.

**Reloadable:** `public_url`, `scan_budget`, `cve`, `allowlist`, `plugins`,
`ai_review`. A reload can turn the reviewer on or off, retarget it at another
provider or model, or adjust its thresholds. The reload rebuilds the reviewer
and the policy atomically. A reload whose `[ai_review]` table cannot be built
fails and keeps the running policy. The causes are the same ones startup
refuses: an unresolvable `api_key_env`, a `base_url` the rules above reject,
or a missing `bwrap` for a newly configured reviewer.

The model, prompt version, collector version, coverage threshold, blocking
level and opaque-executable rule are all part of the policy fingerprint.
Changing any of them invalidates every stored verdict. The next request for
each artifact re-reviews it, which means one fresh provider call per artifact.
Turning the reviewer off changes the fingerprint too. It then matches the
fingerprint of an unconfigured deployment, so each artifact needs a full
rescan without a review step.

An upgrade that bumps the collector or prompt version is therefore a one-off
cost across every ecosystem at once, not just the one that motivated the bump.
The npm support added JavaScript and TypeScript collection and an install-script
section to the reviewer's request, and both bumps invalidate every stored
verdict on every deployment. Expect one fresh provider call per artifact on the
first request after such an upgrade, for PyPI, cargo and npm alike.

**Restart-only** — a reload that changes any of these is *rejected by name* rather
than silently ignored: `bind`, `db_path`, `cache_dir`, `upstream_url`,
`advisory_source_url`, `advisory_sync_interval`, `cache_ttl`, `download`,
`max_concurrent_scans`.

## What a developer sees

Three situations, three distinguishable answers. "We could not check" never looks
like "we checked and it is bad":

| Status | Phrase | Meaning |
|---|---|---|
| 403 | `BLOCKED <code> - why <url>` | Checked, and refused. The `/why` link explains which check. |
| 429 | `SCAN IN PROGRESS` | First sighting exceeded the scan budget; the scan continues in the background, so re-running pip hits the stored verdict. 429 rather than 503 because pip auto-retries 503 and would bury the message. |
| 503 | `UNVERIFIABLE <code>` | Could not check — upstream unreachable, or an internal failure. pip's automatic retry is desirable here. |

The reason phrase is capped at 120 bytes. When it does not fit, the `/why` URL is
preserved and the code is ellipsized — a code without a link is a dead end for the
person reading it.

`/why/<id>` is **unauthenticated**. The ids are unguessable 80-bit values, and
that is the only access control on verdict detail.

## Plugin containment: what holds and what does not

Each plugin is a binary, invoked as
`<binary> --package-dir <dir> --name <pkg> --version <ver> --filename <file>`.
Exit 0 is clean, non-zero is bad, and the first line of stdout becomes the refusal
detail. Every failure to *run* a plugin — missing, non-executable, crashed, timed
out, sandbox setup failed — is a refusal, never a clean verdict.

**Holds:** no network (`--unshare-all`); the package directory is mounted
read-only; nothing on the host is writable; the process group is `SIGKILL`ed at
the timeout, and a `setsid`-detached grandchild dies with the PID namespace;
the environment is cleared (`--clearenv`), so plugins cannot read the proxy's
environment and leak it through a refusal detail onto `/why`; `--new-session`
blocks TIOCSTI injection; writable tmpfs capped at 64 MiB; address space capped
at 2 GiB (`RLIMIT_AS`); file writes capped at 64 MiB (`RLIMIT_FSIZE`); process
count bounded by `RLIMIT_NPROC` at host-threads-at-launch + 512.

**Does not hold:**

- **No seccomp filter.** A plugin can make any syscall the kernel allows in its
  namespaces.
- **No CPU quota.** `RLIMIT_CPU` is deliberately absent: Linux charges it against
  the thread-group clock, so it killed legitimate multithreaded plugins at a
  fraction of their timeout. CPU use is bounded only by the wall-clock timeout, so
  a plugin can saturate cores for its whole budget.
- **`RLIMIT_AS` bounds virtual address space**, not resident memory. It is the only
  portable handle Linux offers, and a runtime that reserves large mappings may
  need the limit raised.
- Plugins can **read** host system paths (`/usr`, `/lib`, `/nix/store`, …). They
  could already read those before being sandboxed, being binaries the operator
  installed and runs as this user.
- The heuristic distinguishing "sandbox failed to start" from "plugin failed" keys
  off a `bwrap: ` stderr prefix, which a plugin can forge. This affects only which
  refusal code is reported; both are refusals.

Plugins are third-party code from the proxy's point of view. The sandbox is the
containment boundary for both the package and the plugin, and the list above is
what that boundary is actually worth.

## The AI reviewer: an optional third gate

A third scan gate, off by default. It stays off until an `[ai_review]` table
appears in the configuration with `enabled` left at its default of `true` (or
set explicitly). With the table absent, or present with `enabled = false`,
the scan path is untouched and the policy fingerprint matches what an older
binary produced. An upgrade changes nothing for an unconfigured deployment,
and flipping `enabled` off changes nothing beyond turning the reviewer off —
`base_url`, `model`, and the rest of the table stay in the file, ready to
flip back on.

This table, and its `enabled` flag, are shared by both deployments of this
binary: a PyPI deployment reads `[ai_review]` at the top level of its config
file, and a cargo deployment reads the very same `[ai_review]` table in its
own, separate config file. There is no per-ecosystem `ai_review` setting to
configure, because each ecosystem already runs as its own deployment with its
own config file (see "Running a cargo/crates.io deployment" below) — turning
the reviewer on or off, or changing any of its settings, is already
independent between a PyPI deployment and a cargo deployment simply by
editing that deployment's own file.

Configured, one review runs per artifact, after the plugins. The proxy invokes
its own binary as a hidden `collect` subcommand inside the bwrap sandbox.
The collector reads the unpacked tree and emits one size-capped JSON payload of
the package's reviewable text. The proxy sends that payload in a single
chat-completions call to any OpenAI-compatible endpoint. It maps the reply to
a verdict, stores a row in the `reviews` table, and either refuses the
artifact or lets the scan continue.

**Settings and defaults.** Every default below comes from `src/config.rs`.

| Setting | Default | Effect |
|---|---|---|
| `enabled` | true | Set false to turn the reviewer off without deleting the rest of the table. A disabled table behaves exactly like an absent one: the policy fingerprint, the sandbox requirement, `/api/reviews`, and reviewer construction all read it the same way. The table still has to validate in full either way — this is not a way to stage an incomplete one. |
| `base_url` | required | Provider base. `chat/completions` is appended. Must be `https`, or `http` pointed at a loopback host. |
| `model` | required | Model name. Sent with every request and stored in every review row. |
| `api_key_env` | unset | Name of the environment variable that holds the API key. Unset sends no Authorization header. |
| `timeout` | 8s | Total deadline for one *review*: the collector run and the provider call, including its one possible retry, all draw from this single budget. Must stay below the deployment's own scan budget — the top-level `scan_budget` on the PyPI and cargo deployments (capped at 14s), or `npm_registry.scan_budget` (default 120s) on an npm deployment, whichever table the config actually carries. |
| `max_payload_bytes` | 262144 | Cap on the file content sent to the model in one review. Floor: 4096. |
| `max_output_tokens` | 1024 | The request's `max_tokens`. |
| `coverage_threshold` | 0.8 | Minimum share of reviewable bytes that must reach the model. |
| `block_on` | `malicious` | Set `suspicious` to block on both verdicts. |
| `block_opaque_executables` | false | Set true to block packages that carry native executables. |

**The API key never lives in a file.** `api_key_env` names an environment
variable. The proxy reads that variable at startup and again at every reload.
A name that does not resolve is a configuration error. Startup refuses, and a
reload is rejected with the running policy kept. The configuration stores only
the variable's name. The key itself never reaches a log line, a refusal
detail, or the policy fingerprint.

**`bwrap` becomes mandatory.** The collector runs inside the same sandbox as
the plugins. When `[ai_review]` is present and `bwrap` is not on `PATH`, the
proxy refuses to start. This is the same rule, and the same reason, as the
plugin requirement above.

**What the sandbox holds.** The collector is this proxy's own executable
rather than a third-party binary, but the containment is the plugin sandbox
unchanged. Everything the "Plugin containment" section above lists as holding
or not holding applies here. That means no network, the package mounted
read-only at `/pkg`, no host path writable, a cleared environment, and the
same resource caps. The collector writes one JSON payload to stdout and
nothing else.

That stdout is capped by the sandbox at `max_payload_bytes` plus a fixed
16384-byte allowance for the JSON envelope. Package text that needs more
escaping than the allowance covers arrives truncated, the payload fails to
parse, and the review reports `unverifiable:ai-collector`. That path fails
closed and never yields a clean verdict. Classifying a file reads at most its
first 8192 bytes.

**Blocking codes** are durable verdicts with a `/why` page:

- `ai:malicious`: the model judged the package malicious.
- `ai:suspicious`: the model judged it suspicious, and `block_on` is
  `suspicious`.
- `ai:coverage`: the review saw too little. This fires when measured coverage
  is below the threshold, and when an install-surface file was too large to
  send whole. The first case states the measured coverage and the threshold in
  the refusal detail.
- `ai:opaque-executable`: the package carries native code the model cannot
  read, and `block_opaque_executables` is true.

The block order is fixed. The model verdict comes first, then the install
surface, then coverage, then opaque executables. A package whose tree holds no
reviewable text at all has undefined coverage, not zero. It passes this gate,
and its review row records a NULL coverage. A pure compiled wheel crosses
unless `block_opaque_executables` is set. Like every durable block, an
allowlist entry is the sign-off that lifts one.

**Unverifiable codes** return 503 and store nothing, so the next request
re-attempts:

- `unverifiable:ai-collector`: the sandboxed collection failed.
- `unverifiable:ai-provider`: the provider call failed. A 429 or a 5xx is
  retried exactly once, a timeout is not.
- `unverifiable:ai-reply`: the reply was empty, not JSON, carried an
  unknown verdict, or was cut off at `max_output_tokens` before the model
  finished (logged with `max_output_tokens` named, so this cause is never
  confused with a broken provider or a broken parser). Raise
  `max_output_tokens` if this recurs.
- `unverifiable:ai-store`: the review row could not be written.

**`GET /api/reviews` publishes the audit trail.** It returns stored review
rows as JSON, newest first, with filters for verdict, package and timestamp,
plus cursor pagination. The default page is 50 rows and the maximum is 200.
The endpoint is unauthenticated, and unlike `/why` it is enumerable. Anyone who
can reach the proxy can page through the whole list of packages the
organization installs, with their verdicts and summaries. Network placement is
the only access control, as everywhere else in this proxy.

The route itself is always registered — `ai_review` is reloadable, and a
router cannot gain or lose a route once it is bound — but the handler 404s
whenever `[ai_review]` is absent from the running configuration, so a
deployment that never enables the reviewer never exposes this surface at
all. Enabling the reviewer later, through a reload, makes the endpoint live
without a restart.

**Review rows accumulate without bound.** Every completed review appends one
row. A repeat review sits beside its predecessor rather than replacing it, on
purpose: the check is not deterministic, and the audit trail keeps every
answer. Nothing evicts rows and nothing caps the table. An operator who wants
a bound needs to prune the `reviews` table externally.

## Archive extraction

Runs before the sandbox exists, directly against bytes from a public registry, so
it is the one component with nothing behind it. Every entry is validated before
anything is written; one bad entry rejects the **whole** archive rather than
leaving a partial tree a plugin would scan and pass.

Caps: 512 MiB total uncompressed, 20,000 entries. Formats: `.whl`, `.zip`, `.egg`
as zip; `.tar.gz`, `.tgz` as gzipped tar.

The two outcomes are deliberately different:

- **An escape attempt is a block** — absolute paths, `..` components, symlinks,
  hard links, device and FIFO entries. It stores a durable `Blocked` verdict with
  a `/why` page.
- **A format gap is "could not check"** — an unsupported extension, a truncated
  archive, a decompression budget exceeded. Nothing is stored, so it is retryable.

Anything the proxy cannot parse the *filename* of is dropped from the index
silently (only `.whl` and `.tar.gz` names are parsed), and a direct request for it
404s rather than explaining itself. If a package's only sdist is a `.zip`, it will
appear to not exist. An allowlist entry is the escape hatch.

## Downloads and the scan budget

Scan budget defaults to 12s, which must stay under pip's 15s default timeout. A
scan that finishes inside it hangs and then serves; one that exceeds it returns
429 and completes in the background.

Download limits (all restart-only): `stall_timeout` 30s — bytes must keep
arriving, not a total deadline, so a large wheel is not punished for being large;
`max_duration` 30 minutes absolute; `max_artifact_bytes` 2 GiB, also checked
against `Content-Length` before any byte is written.

A 906 MB wheel has been pulled through this proxy end to end: it exceeded the scan
budget, returned 429, finished in the background, and served on retry with a
matching hash.

## Integrity

Every served artifact is verified against the hash the index declared.
`ArtifactKey.sha256` is taken **only** from the index entry — never from a URL or
path segment — and the cache is content-addressed on that value. An index entry
with no declared hash is `Unverifiable` and is never served. The allowlist
overrides verdicts but **never** hash verification.

The artifact cache is trusted at the filesystem level: anything with write access
to `cache_dir` can replace a cached artifact's bytes and the proxy will serve them
under a clean verdict. Plugins cannot do this — the sandbox binds nothing writable
from the host — but the directory needs host-level protection.

The cache holds a registry-declared digest of any algorithm this proxy verifies,
not sha256 alone. The digest's own length distinguishes them: 40 hex characters
is SHA-1, 64 is SHA-256, and 128 is SHA-512. npm publishes SHA-512 or SHA-1 and
never SHA-256, so the npm deployment depends on this. The value is still a
filesystem-path boundary. A digest of any other length, or one carrying an
uppercase or non-hex byte, is rejected before it can reach a path.

PEP 658 `.metadata` sidecars are passed through **unverified**, by design: they are
inert metadata and the artifact itself is still gated. The proxy does not check the
`data-core-metadata` hash it re-emits.

## Advisories

A local mirror of the OSV PyPI feed, synced on a schedule, because the advisory
re-check runs on *every* request for an already-clean artifact and an upstream
outage must not become a proxy outage.

- Advisories carrying a `withdrawn` timestamp are dropped at parse time. The feed
  keeps shipping retracted documents, and ingesting them blocks packages on
  findings their own publishers withdrew.
- Advisories with missing or unparseable severity do **not** block by default.
  Blocking them would block a large share of ordinary packages; set
  `unknown_severity` if you want the strict reading.
- A version string that cannot be parsed, against an advisory with ranges, counts
  as affected. An error in a check is never a clean verdict.
- Staleness is bounded by `advisory_sync_interval`: an advisory filed upstream is
  invisible until the next sync.

## A minimum release age

`min_release_age_days` (top-level, for the PyPI deployment; `cargo_registry.
min_release_age_days` for a cargo deployment; `npm_registry.min_release_age_days`
for an npm deployment) refuses a file younger than the configured number of days
since it was published. Unset (the default) turns the gate off entirely. Each
deployment sets its own, so the three ecosystems can run different thresholds,
or one with the gate on and another with it off.

It is independent of CVE filtering and AI review/cargo-vet, and it is
best-effort rather than fail-closed: see "What a reload invalidates" under
"Running a cargo/crates.io deployment" above for exactly what that means and
why. On the PyPI side, the publish time comes from the PEP 700 JSON simple
index (`Accept: application/vnd.pypi.simple.v1+json` against the same
`upstream_url` already configured) — an index that predates PEP 700 never
supplies it, and that file is simply never checked against this gate. On the
npm side, the publish time comes from the packument's own `time` map, which is
one reason this proxy always fetches the full packument rather than the
abbreviated one npm asks for.

The gate is checked once, before CVE filtering, for a version with no stored
verdict. It is never re-checked for a version that already has one: age only
grows, so a version old enough to pass once is old enough forever after. This
also means a refusal from this gate is never stored as a verdict — storing it
would otherwise refuse the artifact permanently, even after it aged past the
threshold.

## Logging

Every refusal is logged at `warn!` with code, package, version, filename and
`why_id`, split between "checked and blocked" and "could not be checked". A hash
mismatch is logged at `error!` with both digests — it is the most
security-significant event the system can detect. There is a request-level access
log at `info!`.

Operators shipping logs off-host should know that **plugin stdout travels with
them**: it is the same string published on `/why/<id>`, stripped of control bytes,
but it is attacker-influenced text.

## The fetch audit log

A separate, structured JSON Lines file — not the `warn!`/`error!`/`info!` stdout
logging above — recording which client fetched which package version, and
which *evaluated* versions were withheld from which client and why. All three
deployments (PyPI, cargo, npm) write it, in the same shape, from `src/audit.rs`.
It exists to answer a question the stdout log cannot: a CVE is disclosed for a
version this proxy forwarded last month, and security needs to know which
machines pulled it. The full chapter, including the schema field by field and
the reason-code vocabulary, is in the mdbook: "The fetch audit log".

**Four event kinds**, one JSON object per line: `listing` (one per listing
request, carrying `versions_upstream` and `versions_evaluated` — the counts
that keep "never evaluated" distinguishable from "never fetched"), `listed`
(one per *evaluated* version in a listing response, `allowed` or `denied` with
a reason), `served` (a download that delivered bytes) and `refused` (a
download that got a refusal response). Every line carries `ts`, `event`,
`ecosystem`, `client_ip`, `client_port`, `request_id` and `package`; every
other field is omitted entirely when absent, never written as `null`.

A `listed` line requires a version the proxy actually reached a verdict on —
on cargo and npm the cascade evaluates a handful of a package's versions per
request and never looks at the rest, and on PyPI "evaluated" means an entry
with a stored verdict under the running policy fingerprint. A version absent
from the log may simply never have been a candidate; the `listing` line's
counts are the only way to tell that apart from "nobody fetched it."
`versions_upstream` counts index **entries** (files) on PyPI but **versions**
on cargo and npm — the field name is shared across all three on purpose, so
three deployments' shipped logs merge into one queryable stream, but a PyPI
reader who assumes it counts distinct versions the way cargo and npm do reads
it high.

**A 403 refusal is always logged**, including a hash-mismatch refusal and
cargo's `not-index-approved`/npm's `not-packument-approved`. **A 503, a 404,
and a 429 "still in progress" are never logged** — none of them reflects a
verdict the proxy actually reached. Non-package routes (`/healthz`,
`/why/{id}`, `/refusals`, `/api/reviews`, `/config.json`, `/-/ping`, npm's
security-audit stubs, npm's write/auth refusals) emit nothing.

**Settings and defaults.** `[audit]` is a new, **required** table — unlike
every other table in this file, an existing config with no `[audit]` table
fails to parse, because the whole point of this feature is that an un-logged
fetch must never happen; there is no "logging off" default to fall back to.

| Setting | Default | Effect |
|---|---|---|
| `path` | required | A filename **prefix**, not the exact file written. The rolling writer appends a date suffix, so `audit.jsonl` becomes `audit.jsonl.2026-11-01` (daily) or `audit.jsonl.2026-11-01-14` (hourly). A shipper has to glob on the prefix, not tail one fixed name. |
| `rotation` | `daily` | `daily` or `hourly`. |
| `max_files` | `14` | Rotated files kept before the oldest is deleted. |

**Changing `rotation` orphans the old files.** Pruning only ever considers
files whose suffix parses under the *currently configured* granularity — a
daily deployment switched to `hourly` (or back) stops counting, and stops
deleting, every file written under the old granularity. Those files are not
harmful, but they sit on disk indefinitely outside `max_files`' accounting
until an operator clears them by hand; budget disk accordingly before
changing this setting on a long-running deployment.

**`max_files` is a best-effort cap, not a hard one.** The file currently
being written to is never pruned, no matter how it sorts by name — which
matters after a clock step backward or a rotation change, where the live
file can sort *oldest* among its siblings. In that case the deployment can
briefly hold `max_files + 1` files rather than `max_files`, until the
oldest ages out naturally. Do not treat `max_files` as a guarantee when
sizing a disk right at the edge.

**Restart-only.** `[audit]` joins `bind` and `db_path` among the fields a
`SIGHUP` reload rejects in full, naming `audit`, rather than applying — the
open file handle is built once at startup, and there is no "close the old
file, open the new one" step a reload could trigger.

**Fail closed.** A write failure returns **500**, with no package bytes and
no index/packument content — never a 403, because a write failure is an
operational fault in this process, not a verdict about the package. The cause
is logged at `error!` on stdout at the same call site: `failed to write a
fetch audit record; refusing to serve rather than let this fetch go
unlogged`. The trade this accepts deliberately: a full disk stops every build
in the organization, on every ecosystem this proxy serves, in exchange for
the guarantee that absence from the log means absence of a fetch rather than
a silent gap indistinguishable from one. An unwritable configured path fails
**at startup** instead — `bootstrap` opens this log before the router is
built, naming the path in the boot error, rather than surfacing as a wave of
500s discovered hours later on a developer's first fetch.

**Where the client IP lives, and does not.** It exists in exactly one place
in this proxy: this file. It is never written to SQLite — the verdict store
gains no IP column — and never exposed on any HTTP route; `/refusals`,
`/why/<id>` and `/api/reviews` are all unauthenticated and read by the same
developers whose fetches are logged. `X-Forwarded-For` is never read: nothing
sits in front of this proxy, so the header could only be a client forging its
own identity, and the logged address is always the real TCP peer. This file
now holds network-attributable data about real developers that the stdout
log above never did, so the proxy creates it restrictively rather than leaving
it to the ambient umask: the file is created mode `0600` and any directory the
proxy has to create for it mode `0700`, owned by the user the proxy runs as.
Those modes apply only at creation, so a mode you set yourself on an existing
file or directory survives — and because every rotated file is created the same
way, a one-off `chmod` is not needed and would not have protected tomorrow's
file anyway. **A log shipper running as a different user cannot read this file
as created** — it loses both directory traversal and file read. Run the shipper
as the same user as the proxy, or add a shared group and widen the directory
once; a shipper that silently stops shipping is the failure this file exists to
prevent. Retention is still yours to set, separate from the rest of this proxy's
logs.

**Volume.** One `listing` line plus one `listed` line per evaluated version,
per listing request — tens of lines, not the thousand-plus versions a
popular package's full history might carry. The cost that remains is
repetition: every `npm install` refetches the packument for every package in
the dependency tree, so a CI run with a few hundred dependencies emits
thousands of lines on a single install, most of them restating verdicts that
have not changed since the last run. Size retention for that steady-state
rate rather than being surprised by it.

**Two honest limitations.** A `served` line is written *before* the response
body streams — fail-closed requires the write to happen first — so a
connection that drops mid-transfer still produces a `served` line; the record
means "this proxy decided to serve these bytes," not "these bytes arrived."
And records are flushed to the OS but not `fsync`ed per line, since a sync on
every line would dominate request latency at this log's volume: the
guarantee is "no fetch without a successful write," not "no fetch without a
*durable* write," so a kernel panic can still lose the tail of the file. A
third, ecosystem-specific one: on npm, the `sha256` field on a `served` line
carries whatever digest npm itself declared, which is a SHA-1 or a SHA-512 far
more often than an actual SHA-256 (see "Integrity" above) — the field name
predates this feature and was never renamed for it.

## Deployment

No authentication and no rate limiting. Security depends entirely on network
placement. Put it where only your developers and CI can reach it.

`max_concurrent_scans` bounds full scans; without it the default is derived from
available parallelism. The bound matters: each in-flight scan can hold a blocking
thread for a plugin's whole timeout, and the same pool serves every database call.

## Running a cargo/crates.io deployment

A cargo deployment is this same binary with a different config file. One process
serves one ecosystem. A config file that carries a `[cargo_registry]` table is
therefore the cargo deployment, and a config file without one is the PyPI
deployment. The split is deliberate. `Config` carries a single `upstream_url`, and
the HTTP layer routes nothing by ecosystem, so a second deployment is the change
that fits what is there. A developer points cargo at the proxy with a source
replacement in `.cargo/config.toml`, and nothing else on the machine changes,
exactly as `index-url` works for pip.

**Settings and defaults.** Every default below comes from `src/config.rs`.

| Setting | Default | Effect |
|---|---|---|
| `upstream_index_url` | required | The sparse index this proxy fetches crate metadata from. Normally `https://index.crates.io/`. |
| `cargo_vet_sync_interval` | 1h | How often the local cargo-vet audit store is refreshed from every configured source. |
| `cargo_vet_sources` | empty | The trusted cargo-vet audit sets to fetch. Each entry is a `name` for logs and errors and the `url` of that source's `audits.toml`. Empty leaves the fast path with no proof to consult. |
| `required_criterion` | `safe-to-deploy` | The criterion an audit must carry to stand in for AI review. Set `safe-to-run` for the looser bar. |
| `trusted_reviewers` | empty | The specific auditors whose entry counts, when the list is not empty. Empty means any entry from a trusted source counts, by whoever audited it. |
| `min_release_age_days` | unset (off) | The youngest a crate version may be and still be forwarded, in days since crates.io published it. Independent of the PyPI deployment's own top-level `min_release_age_days`. |

The table is additive. The base fields stay required in a cargo deployment —
`bind`, `db_path`, `cache_dir`, `upstream_url`, `public_url`, `scan_budget` and
`[cve]` — because one `Config` type parses both deployments. The cargo path does
not read `upstream_url`, but the field must still be present and valid.

Set `advisory_source_url` to the crates.io OSV feed in a cargo deployment. The
default points at the PyPI feed. The mirrors are per ecosystem, so a cargo
deployment that keeps the default syncs the wrong advisory data.

**The cargo-vet fast path.** A version carries a qualifying audit when two things
hold. A trusted source recorded an audit of that exact crate and version against
`required_criterion`. And `trusted_reviewers` accepts the auditor who signed it.
Such a version skips AI review, because a human already read it. The fast path
never replaces CVE filtering and never replaces the plugin gate. Those two
check different things from "a person read this", and a static trust database
cannot answer either of them.

**What a reload invalidates.** `required_criterion` and the cargo-vet source
list — each name and URL, in config order — are part of the policy fingerprint.
Editing either one invalidates every stored verdict, because both decide what
this deployment accepts as proof. `trusted_reviewers` stays out of the
fingerprint, for the same reason the allowlist does. It narrows who is trusted,
rather than changing what is checked. Editing it must therefore not force a
rescan of the whole crate ecosystem. `min_release_age_days` is part of the
fingerprint too, for the same reason `required_criterion` is: changing the
threshold changes what the cascade admits.

**The release-age gate is best-effort, not fail-closed.** Unlike CVE filtering
and AI review, a version the cascade cannot determine a publish time for — the
registry API has no `api` base in `config.json`, or the lookup fails outright —
is not treated as too new. The cascade logs a warning and skips the gate for
that one request rather than refusing every version, because this is a
secondary hygiene control layered on top of the CVE and AI-review/cargo-vet
gates, which keep their existing fail-closed behavior unaffected. The same
rule applies to the PyPI deployment's own `min_release_age_days`, sourced from
the PEP 700 JSON simple index: an upstream that predates PEP 700 never reports
an `upload-time`, and that is not reason enough to block everything.

**Two sync tickers, on two intervals.** The crates.io advisory mirror re-syncs
every `advisory_sync_interval`, from `advisory_source_url`. The cargo-vet audit
store re-syncs every `cargo_vet_sync_interval`, which defaults to one hour. Both
exist for the same reason as the PyPI advisory mirror. A check that runs on every
request must not turn an upstream outage into a proxy outage.

The two tickers fail differently. A failed OSV sync keeps the whole existing
mirror untouched. A failed cargo-vet sync keeps only that source's last published
audits, and it still refreshes the other sources. A down Mozilla endpoint must not
stop Google's audits or the org's own from updating. On the intended startup order
both stores sync before the listener binds, so a cold start includes two
downloads.

**What a developer's machine needs.** One source replacement, in
`~/.cargo/config.toml` or in the repository's own `.cargo/config.toml`:

```toml
[source.crates-io]
replace-with = "scanner"

[source.scanner]
registry = "sparse+https://cargo.scanner.example.internal/"
```

Use this deployment's `public_url` as the sparse root. Cargo then resolves every
crate through the proxy and believes it is talking to crates.io. Cargo's own
`[http] timeout` defaults to 30 seconds, and the cascade has to finish inside it,
the same way `scan_budget` has to stay under pip's 15 seconds. A developer who
lowers that timeout below the work the cascade needs sees resolution failures
that are not refusals.

**Where the gate sits is different from PyPI.** CVE filtering and AI review run
at the sparse-index response, which is what `cargo add` exercises. Org plugins
run at the `.crate` download, which normally happens at the `cargo build` or
`cargo check` that follows. That split has a consequence worth knowing. A version
that appears in the index response is *admitted*, and not fully scanned. It
cleared CVE and either AI review or a cargo-vet audit. Only a version that was
also downloaded has had the plugins run against it.

**The `.crate` route serves only an admitted version.** A download for a version
the index gate never admitted is refused with a `not-index-approved` reason,
without fetching the bytes and without running a plugin. The gate reads the
stored verdict as the proof of admission: the cascade writes one for every
version it forwards, so a version with no verdict is one the cascade never
reached. That version was never CVE-filtered, never age-checked, and never
reviewed. Serving it on a plugin pass would substitute one check for the other
three. An `[[allowlist]]` entry still overrides this, the same way it overrides
a stored block, and the bytes still have to match the `cksum` the index
declared.

The split also decides how a refusal reaches a person. Cargo's sparse-index
protocol gives an index-time refusal no place to put a reason phrase. A blocked
version is therefore simply absent from a successful response, and cargo reports
its own "no matching version". A plugin refusal happens on a real download, so it
arrives as a status line and a `/why` link, the same way a PyPI refusal does.

**`GET /refusals` is the compensating channel.** It is an unauthenticated HTML
page on this deployment's `public_url`. It lists the most recent blocks for this
deployment's own ecosystem, newest first, up to the last 100. Each row carries
the crate, the version, the refusal code, the detail, and a link to that
refusal's `/why/<id>`. It exists because the index-time case is otherwise silent.
A developer whose resolution failed has no other place to learn that the version
was blocked rather than broken. Plugin refusals appear on the page too, for the
convenience of one place to look, but they are not the case it exists to solve.
A database error renders a 500 and never an empty table, because "nothing was
refused" and "the refusals could not be read" are different answers.

**Startup dispatch.** The binary checks for a `[cargo_registry]` table. If the
table is present, the process boots the cargo path. If the table is absent, the
process boots the PyPI path. No process serves both ecosystems.
The cargo path builds its parts in this order: the database, the policy, the
plugin sandbox, the plugin runner, the AI reviewer, the artifact cache, the
upstream client, the advisory mirror, the cargo-vet audit store, the cascade
scanner, and the router. A failure anywhere in that chain stops startup. It
never produces a process that runs fewer checks than the config asked for.

The first start does two syncs before it serves a request. It syncs the
`crates.io` advisory mirror when the mirror is empty. It syncs the cargo-vet
audit store when that store is empty. After startup, two tickers keep both
stores current.

**SIGHUP does not reload a cargo deployment.** Configuration reload is a
deployment feature of the PyPI path only. A cargo deployment logs a warning at
startup and installs no signal handler. To change the config of a cargo
deployment, restart the process.

**The allowlist works the same way it does on PyPI.** An entry is consulted
before every stored verdict, so it lifts a CVE block, an AI-review failure, and a
plugin block alike. It never lifts the hash check: a download still has to match
the `cksum` the index declared. An entry matches the crate name in either
spelling, so `num_cpus` and `num-cpus` in the config both match the same crate.

The index gate and the download gate each consult the allowlist, because they
are two separate decisions. A version allowlisted after its index response was
served is re-checked at the next `.crate` download.

**The shared routes answer on a cargo deployment.** `/healthz`, `/why/<id>`, and
`/api/reviews` are served here exactly as they are on the PyPI path, from the
same code. Two consequences are worth knowing:

- An operator's existing liveness probe keeps working, because `/healthz` reads
  no state and both deployments mount the same handler.
- A plugin refusal's `/why/<id>` link resolves, and so does every `/refusals`
  row's link. A cargo developer who receives a refusal can read the explanation.

`/api/reviews` sits behind the same `[ai_review]` gate as on PyPI: it answers
404 when the table is absent, and a JSON listing when it is present.

## The crate version the proxy cannot see

Cargo's sparse-index request carries no version. The bytes are identical for
`cargo add foo`, for `cargo add foo@1.2.3`, and for a transitive dependency that
nobody named on a command line. So the proxy picks the review candidate itself:
the newest version that is CVE-clean, not yanked, and not already cached.

That rule is what makes an unconstrained `cargo add foo` fast after the first
touch, and it is also the known limitation. An explicit pin can name a version
that was never the newest unscanned candidate. That version is absent from the
forwarded list, so `cargo add foo@1.2.3` fails to resolve. The pin is not bad.
The proxy had no mechanism to reach it. A version becomes reviewable only by
being, at some point, the next candidate in the newest-first walk.

The failure has the same shape as a CVE block. The version is missing from an
otherwise successful response, and cargo reports that no matching version exists.
An operator or a developer should do this, in order:

1. Open `/refusals` on the proxy. This rules out a genuine refusal with a reason
   behind it, which needs a different answer.
2. Re-run the same `cargo add`. Each request continues the review walk from where
   the cache left it. The versions ahead of the pin are then resolved, one request
   at a time. When a candidate fails review, the walk moves to the next-newest
   version. When the cascade exhausts its budget instead, it answers with the
   retryable "still working" response and continues in the background, so wait and
   re-run.
3. If the pin is still absent after the walk reaches it, or the walk reviewed it
   and the review failed, manually review the crate. Then add a `[[allowlist]]`
   entry for that package and version. The allowlist lifts the verdict, and it
   never lifts the hash check: the bytes still have to match the checksum the
   index declared.

Step 2 costs nothing and fixes the common case. Step 3 is an explicit human
decision, recorded in the config, and that is the right place for it.

A cargo deployment has no reload, so an `[[allowlist]]` entry added for step 3
takes effect at the next restart. Plan for that: a developer who hits the pin
before the restart still cannot resolve it.

## Running an npm deployment

An npm deployment is this same binary with a different config file. One process
serves one ecosystem. A config file that carries an `[npm_registry]` table is
therefore the npm deployment. A config that carries `[cargo_registry]` is the
cargo deployment, and a config that carries neither is the PyPI deployment. A
config that carries both is rejected at load, naming both tables, because one
process cannot be two deployments.

**Settings and defaults.** Every default below comes from `src/config.rs`.

| Setting | Default | Effect |
|---|---|---|
| `upstream_registry_url` | required | The registry this proxy fetches package metadata from. Normally `https://registry.npmjs.org/`. |
| `scan_budget` | 120s | How long one package metadata fetch may take, covering the whole cascade for that package. Deliberately far looser than the PyPI deployment's budget: npm's own client retries a 429 only twice, so a PyPI-shaped deadline would turn ordinary slowness into a hard install failure. npm's own `fetch-timeout` is 300s, so 120s leaves headroom. |
| `max_packument_bytes` | 67108864 (64 MiB) | Hard cap on one packument's downloaded size. A body over the cap is refused before any parsing, against `Content-Length` when upstream supplies it and against the running byte total either way. |
| `min_release_age_days` | unset (off) | The youngest a published version may be and still be forwarded, in days since npm published it. Independent of the top-level setting and of the cargo deployment's own. |

The table is additive. The base fields stay required in an npm deployment,
because one `Config` type parses every deployment. The npm path does not read
`upstream_url`, but the field must still be present and valid.

Set `advisory_source_url` to OSV's npm feed in an npm deployment. The default
points at the PyPI feed. The mirrors are per ecosystem, so an npm deployment
that keeps the default syncs the wrong advisory data.

**`[ai_review]` is mandatory here.** There is no fast path past AI review on
this deployment. The cargo path has a substitute, a qualifying cargo-vet audit
signed by a trusted reviewer. npm has no equivalent, and the design leaves none
open on purpose. An npm deployment configured without `[ai_review]` therefore
cannot forward any version at all, and it refuses to start rather than serve a
registry that can never answer.

**The two gates.** A version reaches a forwarded packument only when all of the
following hold. It is CVE-clean under `[cve]`. It is past the release-age
threshold, or the operator allowlisted it. And AI review passed it, or the
operator allowlisted it. The packument gate then forwards the newest such
version per major line, newest line first, so ordinary resolution finds a
candidate in each major. Deprecated versions are not excluded, because npm
installs them routinely and excluding them would break ordinary resolution.

The tarball gate runs after that, at the download. It admits a version only when
the packument gate stored a passing verdict for it, *or* the operator
allowlisted it, and then it runs the org's plugin binaries over the unpacked
tree. A version with no stored verdict and no allowlist entry is refused with a
reason naming that the packument gate never admitted it. The download path
never reviews inline. No tarball bytes are served for an artifact that has not
passed CVE filtering, the release-age gate, AI review, and the plugins — or
been allowlisted.

**The allowlist is consulted at the download gate too, and for good reason.**
An allowlisted survivor is forwardable at the packument gate without ever being
reviewed (the whole point of the override), so it has no stored verdict for the
download gate to find. Without its own allowlist check, the download gate would
refuse every allowlisted version with "the packument gate never admitted it" —
true of the review, false of the operator's own decision. So the download
handler checks the allowlist first, exactly as the packument gate does, and
only then falls back to the stored-verdict check. The allowlist overrides the
verdict; it never overrides the integrity check, so the handler still fetches
the version's declared digest from the packument and verifies the downloaded
bytes against it regardless of which path admitted the version.

**Where the gate sits.** Both gates are reached through the same `/{*path}`
catch-all as the packument, which dispatches internally. The proxy's router
library permits a catch-all only as the final path segment, so a tarball cannot
have a route of its own. An operator reading request logs sees both kinds of
artifact under one route prefix, and that is expected.

**Write and auth endpoints are refused.** `npm publish`, `npm login`,
`npm token` and `npm dist-tag` all speak `PUT` or `POST`. This is a read-only
gateway to the public registry, so those methods answer 403 with a sentence
saying so, on every path. The refusal is explicit rather than left to the
router's own method-not-allowed answer, so an operator learns why immediately
instead of from a half-completed publish. The two audit stubs keep their own
`POST` routes and are unaffected.

**The packument cache is in memory, not on disk.** The design named the
SQLite-backed `IndexCache` as the model. What shipped instead is a bounded
in-process ETag cache plus a bounded last-good-packument map. The consequence
is worth knowing: the stale fallback that answers a request during an upstream
outage only knows packages this process has already fetched since it started.
After a restart, the first request for a package during an outage gets an
empty packument rather than the last good one. This is a deliberate
simplification, not an oversight, because the alternative was a schema and a
migration for a cache whose whole purpose is to make the common case cheap. A
warm cache is the mitigation, exactly as it is for a first `npm install`.

Both maps are bounded, by an entry count and a byte cap, each evicting its
oldest entry first once either cap is exceeded. The last-good-packument map
holds a fully *parsed* `Packument` per name, not the response text the ETag
cache holds, and a parsed document is several times heavier in memory than the
text it came from — so its caps (300 entries, a 150 MiB weighted-bytes budget)
are both lower than the ETag cache's (500 entries, 200 MiB of actual text
bytes), to keep its real memory footprint in the same small-fraction-of-
deployment-memory range despite the heavier structure. Without these caps, a
long-running deployment that fetches a wide spread of distinct package names
over its lifetime would grow either map without bound.

**What a developer's machine needs.** Point npm at the proxy:

```bash
npm config set registry https://npm.scanner.example.internal/
```

Use this deployment's `public_url`. npm then resolves every package through the
proxy and believes it is talking to the public registry. Scoped packages follow
the same setting unless the org sets a scope-specific registry, and a
scope-specific entry pointing at the public registry bypasses this proxy for
that scope.

The proxy always answers with the full packument shape, even when npm asks for
the abbreviated one, because the release-age gate needs the `time` map the
abbreviated form omits. A real npm client was verified to parse the full shape.

**The audit endpoints answer 404.** npm's bulk-advisory and quick-audit requests
are answered 404 and never forwarded. Proxying either would ship the org's entire
dependency tree to the public registry on every install. npm treats the 404 as
"no audit summary available" and continues. This deployment's own CVE gate blocks
rather than reports, which is stronger coverage for the same purpose.

**Shared routes.** `/healthz`, `/why/<id>`, `/api/reviews` and `/refusals` are
served here as they are on the PyPI path, from the same code. `/-/ping` answers
unconditionally and reads no state.

## The npm lockfile the proxy cannot see

A lockfile generated before the org adopted the proxy pins each package's
`resolved` URL at the public registry. `npm ci` fetches those tarballs directly
from that URL, so no gate applies to them. The proxy cannot intercept a request
that is never sent to it.

The operational fix is to regenerate the lockfile with the registry pointed at
the proxy, and to commit that lockfile so every install uses it. The converse is
worth knowing too. A lockfile made behind the proxy carries internal URLs, so it
does not work for anyone outside the network. That is the intended trade, and it
is why a lockfile is not portable across the boundary in either direction.

## Known defects, not yet fixed

Recorded honestly so nobody rediscovers them the hard way.

- **A reload can let one request inherit the previous policy's verdict.** A scan in
  flight when SIGHUP lands may be joined by a request running under the new policy
  and served from the old policy's result. One instant per artifact; the next
  request rescans.
- **The index page is re-fetched from upstream on every artifact request**, outside
  the scan budget. A slow upstream index can therefore push a request past pip's
  15s timeout with no scan involved, and resolving a large dependency tree
  re-downloads the same multi-megabyte page repeatedly.
- **The periodic advisory sync blocks a runtime worker** and holds the SQLite write
  lock long enough that verdict writes during that window can fail, surfacing as a
  503 to a developer once per sync interval.
- **`unverifiable:internal` has no explanation path** — no `/why` page, and the
  detail never leaves the process.
- `ConfigHandle::reload` still exists and swaps config without rebuilding the
  policy. Nothing calls it outside tests, but it is a footgun for future work.
- Cache staging files (`.<sha256>.<rand>.part`) are not swept if the process dies
  mid-copy on a cross-device move. Harmless, but they accumulate.
- `evict_expired` counts a removed malformed row but the access log's `elapsed_ms`
  measures time to response headers, not to the last byte — a large serve logs
  single-digit milliseconds.
- `Policy::build` checks that a plugin binary is *readable*, not executable, so a
  non-executable plugin passes startup and then refuses everything.
- **A cargo-vet-covered version leaves no distinguishing record.** The cascade
  never downloads or stores anything for a version admitted purely by a
  qualifying cargo-vet audit, so neither `/why/<id>` nor `/api/reviews` can say
  "covered by Mozilla's audit" the way they say "AI-reviewed, clean" for a
  version the reviewer actually examined. An operator sees the version resolve
  and sees no review row for it; nothing surfaces today to say why. The design
  spec flags this as an open question rather than a decision, and this is the
  honest state until it gets one.
- The `Ecosystem` trait is a half-realized seam: the HTTP layer goes through it,
  but the scanner still holds a concrete `Upstream` and calls `unpack` directly.
  Only `PyPi` implements the trait. Both the cargo and the npm deployments
  bypass it and hold their own concrete upstream clients, mirroring each other.
  The design spec called for npm to get "its own `Ecosystem` implementation";
  what shipped is a concrete `NpmUpstream` and `NpmScanner` instead. This is the
  same gap cargo carries, and it is the honest state until the seam is finished.
- **The AI review is not deterministic.** Two reviews of identical bytes can
  disagree. The stored verdict is whichever answer arrived first under the
  current policy fingerprint. Once a verdict is stored, later requests serve
  it without another call. Only a fingerprint change re-reviews, and the new
  answer replaces nothing.
- **Each review costs one provider call.** A wheel costs one call when it is
  requested. A package that offers many wheels costs one call per wheel
  actually requested. A cached clean verdict costs nothing until the
  fingerprint changes.
- **Nothing bounds total spend.** The per-review payload cap and the output
  cap bound one call. No counter, budget or rate limit spans calls across
  artifacts or time.
- Two tests depend on wall-clock timing and can flake on a loaded machine.

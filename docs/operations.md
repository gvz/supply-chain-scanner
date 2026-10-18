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
appears in the configuration. With the table absent, the scan path is untouched
and the policy fingerprint matches what an older binary produced. An upgrade
changes nothing for an unconfigured deployment.

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
| `base_url` | required | Provider base. `chat/completions` is appended. Must be `https`, or `http` pointed at a loopback host. |
| `model` | required | Model name. Sent with every request and stored in every review row. |
| `api_key_env` | unset | Name of the environment variable that holds the API key. Unset sends no Authorization header. |
| `timeout` | 8s | Total deadline for one provider call. Must stay below `scan_budget`. |
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
- `unverifiable:ai-reply`: the reply was empty, not JSON, or carried an
  unknown verdict.
- `unverifiable:ai-store`: the review row could not be written.

**`GET /api/reviews` publishes the audit trail.** It returns stored review
rows as JSON, newest first, with filters for verdict, package and timestamp,
plus cursor pagination. The default page is 50 rows and the maximum is 200.
The endpoint is unauthenticated, and unlike `/why` it is enumerable. Anyone who
can reach the proxy can page through the whole list of packages the
organization installs, with their verdicts and summaries. Network placement is
the only access control, as everywhere else in this proxy.

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

## Logging

Every refusal is logged at `warn!` with code, package, version, filename and
`why_id`, split between "checked and blocked" and "could not be checked". A hash
mismatch is logged at `error!` with both digests — it is the most
security-significant event the system can detect. There is a request-level access
log at `info!`.

Operators shipping logs off-host should know that **plugin stdout travels with
them**: it is the same string published on `/why/<id>`, stripped of control bytes,
but it is attacker-influenced text.

## Deployment

No authentication and no rate limiting. Security depends entirely on network
placement. Put it where only your developers and CI can reach it.

`max_concurrent_scans` bounds full scans; without it the default is derived from
available parallelism. The bound matters: each in-flight scan can hold a blocking
thread for a plugin's whole timeout, and the same pool serves every database call.

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
- The `Ecosystem` trait is a half-realized seam: the HTTP layer goes through it,
  but the scanner still holds a concrete `Upstream` and calls `unpack` directly.
  Adding npm or cargo means finishing that first.
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

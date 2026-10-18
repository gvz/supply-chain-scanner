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

**Reloadable:** `public_url`, `scan_budget`, `cve`, `allowlist`, `plugins`.

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
- Two tests depend on wall-clock timing and can flake on a loaded machine.

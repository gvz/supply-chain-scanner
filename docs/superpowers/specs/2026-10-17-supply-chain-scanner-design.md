# Supply Chain Scanner — Design

**Date:** 2026-10-17
**Status:** Design, approved scope for planning

## Intent

Today a developer runs `pip install <pkg>`, pip talks straight to pypi.org, and
unaudited third-party code executes on the developer's machine. Nothing stands
between "I want this package" and "this package now runs here".

This project puts something in between: an HTTP proxy that organizations run on
their own server, which pip (and later other package managers) talk to instead
of the public index. Every package version that passes through is checked once,
the verdict is remembered, and anything that fails a check never reaches the
developer.

### Why now

Supply chain attacks on public package registries are routine, and the default
install path has no gate at all. An organization has no place today to express
"these are the rules for code we let in" and have it enforced at the moment of
install rather than after the fact in a report nobody reads.

## Goals

- **Invisible when things are fine.** A developer with a clean package should
  not notice the proxy exists beyond the one-time index URL setting.
- **Hard stop when things are not fine.** Malicious or policy-violating
  packages are not served, at all, to anyone in the org.
- **Scan once, remember forever.** An artifact is fully scanned a single time;
  every later request for it is answered from the stored verdict.
- **Organizations own their rules.** The checks that matter differ per org, so
  the org supplies its own check logic and its own thresholds.
- **One process, one server.** Easy enough to deploy that an org actually
  deploys it.

## Non-goals

- Not a package registry or a mirror of all of PyPI. It fetches and caches on
  demand, nothing more.
- Not a developer-facing UI, dashboard, or web console in this version.
- Not multi-tenant. One deployment serves one organization.
- Not a replacement for the org's own checks — it runs them, it does not
  invent them.
- Not responsible for languages beyond Python in this version, though the
  structure must forsee adding other languages and make adding them easy.

## Anti-goals (failure even if it ships and works)

- **False positives that make developers route around it.** If devs start
  setting `--index-url https://pypi.org/simple` to get their work done, the
  tool is worse than nothing: it has consumed effort and provides zero
  protection. Every blocking decision must be explainable and overridable by
  the org.
- **Malicious code reaching a developer.** A clean verdict that is wrong is the
  other way this fails. "Fail open on error" is not acceptable behavior for the
  scan path.

## Shape

### Position in the flow

1. Developer runs `pip install requests==2.31.0`.
2. pip is configured (`index-url`) to point at the proxy.
3. The proxy serves the PyPI Simple index (PEP 503) and the artifact files,
   fetching from upstream PyPI as needed.
4. For each artifact pip asks for, the proxy decides: serve it, or refuse it.
5. Refusal is an HTTP 403 whose **reason phrase** carries a short code and a
   link, e.g. `403 BLOCKED plugin:yara-malware — why http://scanner.corp/why/a1b2c3`.

pip never prints response bodies — verified against pip 25.3, where
`pip/_internal/network/utils.py` builds its error message from the status code
and reason phrase alone — so the body is not a usable channel. The reason phrase
and the requested URL *are* both printed, which makes them the channel.

Two consequences. The proxy serves **HTTP/1.1** to clients, because HTTP/2 has
no reason phrase; the phrase stays short and ASCII. And the proxy exposes a
**`/why/<id>` endpoint** that renders the stored verdict in full: which check
failed, which advisory or plugin, and what the org can do about it.

Because pip resolves dependencies by walking the index, transitive dependencies
arrive as their own requests and are gated the same way. No special handling
needed.

### Decision path for one package version

Keyed on (ecosystem, package name, version, artifact hash).

**Allowlist hit** → serve, whatever the stored verdict says if the hash of the downloaded package fits the specifed one. Never serve packages where the hashes to not match. The allowlist is
consulted *before* the verdict, not after. An escape hatch that cannot override
an existing bad verdict would fail in exactly the case it exists for: a package
already blocked, that the org has since reviewed and accepted.

**Known-bad verdict stored** → refuse immediately, with the stored reason.

**Known-good verdict stored** → re-check the advisory database before serving.
A package that was clean when scanned may have a CVE filed against it since.
Then serve (from artifact cache if warm, else fetch).

**No verdict stored** → run the full scan, in order, stopping at the first
failure:

1. Advisory/CVE lookup against the local mirror, judged against the org's
   configured line.
2. Download the artifact from upstream.
3. Verify the artifact hash against the hash the index declared.
4. Unpack into a sandbox and run each configured org plugin.
5. All green → store the clean verdict, cache the artifact, serve it.

Any failure stores a bad verdict with the reason and refuses.

The developer's pip connection **hangs** while a first-time scan runs — but
only up to a budget. pip defaults to a 15s timeout and 5 retries
(`pip/_internal/cli/cmdoptions.py`), so an open-ended hang produces timeouts and
duplicate requests rather than a patient wait.

So the scan gets a **hard budget below pip's default timeout**. A scan that
finishes inside the budget hangs and then serves; the developer notices nothing
but a slow install. A scan that exceeds it returns a **retryable error** that
says so ("scan in progress, re-run"), while the scan continues in the
background — the developer's second attempt hits a stored verdict. Plugins
therefore run under a strict per-plugin time limit.

### Index pages are policy-filtered

Known-bad versions are **omitted from the Simple index page** the proxy serves.
pip's resolver backtracks when a download fails, so refusing only at download
time would let pip quietly resolve to an older version — a silent downgrade in
place of a hard stop, with the developer never told anything happened.

Filtering means pip never selects a known-bad version at all. A developer who
pins a bad version explicitly still reaches the artifact URL and gets the loud
refusal above. Index responses are therefore policy-dependent, not upstream
pass-through.

### Verdict granularity

A verdict is stored **per artifact file**, not per version. One version
routinely ships ten to thirty wheels plus an sdist, with different contents and
different hashes, and a clean sdist cannot license an unscanned wheel. "Scanned
once" means once per artifact, forever.

Scans are driven by what pip actually requests, so a version's unused wheels
are never scanned. **PEP 658 `.metadata` sidecars are passed through** from
upstream so dependency resolution stays cheap — they are inert metadata, and
the artifact itself is still scanned before any of its bytes are served.

### Verdicts outlive requests, not policy

Each verdict row carries a **fingerprint of the policy and plugin set that
produced it**: the CVE line, the plugin list, and each plugin binary's hash. A
stored verdict is reused only while the current fingerprint matches. Tighten the
CVE line or ship a new plugin build, and affected verdicts go stale and are
re-scanned on next request. Without this, an org could tighten its rules and
have nothing at all happen.

### Policy, owned by the org

A configuration file on the server, read at startup and on reload. It holds:

- **The CVE line.** Most real packages carry some advisory. The org sets what
  actually blocks — by severity, by whether a fixed version exists, or similar.
  Blocking on every advisory would trip the false-positive anti-goal
  immediately.
- **The allowlist.** Specific package+version entries the org has reviewed and
  decided to permit regardless of verdict. This is the escape hatch when a
  developer is blocked by something the org judges to be a false positive.
- **The plugin list.** Which check binaries to run, in what order.
- **Cache TTL** for stored artifacts.

No API and no UI for configuration — editing the file is enough for the people
who will run this.

### Plugins

Organizations supply their own checks as **binaries**. The proxy invokes the
binary with arguments pointing at the unpacked package, and reads the exit
code: **0 means clean, non-zero means bad.** Nothing about the plugin is
language-specific; an org can write one in anything that produces an
executable.

Plugins **run in a sandbox**. They are operating on code that may be actively
hostile, on the organization's server, and the plugin itself is third-party
code from the org's perspective too. The sandbox is the containment boundary
for both.

### Advisory data

A **local mirror of advisory feeds, synced on a schedule**, rather than live
API calls per request. Two reasons: clean-verdict re-checks happen on every
single request and must be fast, and an upstream advisory API outage must not
become a proxy outage or, worse, a reason to fail open.

Advisories with **missing or unparseable severity** are governed by an explicit
config rule that defaults to *not blocking*. Treating unknown severity as
blocking would block a large share of ordinary packages on day one and trip the
false-positive anti-goal immediately; orgs that want the strict reading can set
it.

### Artifact cache

Packages that pass are **kept on disk for a configured TTL** and served from
cache. After expiry, refetch. The cache is a performance feature, not a
registry — the verdict database is the durable record.
The TTL is reset on each request of the package, packages that are constanly 
requested are never deleted.


### Upstream outage

Upstream PyPI sits on the read path: the Simple index supplies the hashes the
scan verifies against. When upstream is unreachable the proxy **serves what it
already knows** — stored verdicts, cached index pages, cached artifacts — and
**refuses anything unscanned**, with a reason that distinguishes "blocked" from
"cannot verify right now". A PyPI blip must become neither a full dev-tooling
outage nor a reason to serve unverified bytes.

### Stack

- **Rust**, single binary.
- **SQLite** for the verdict database, advisory mirror, and cache metadata.

One file and one process to deploy. Postgres and multiple instances are a later
concern, not a current requirement.

### Ecosystems

Python/PyPI is the only ecosystem in this version. npm and cargo are expected
later, so the parts that are genuinely PyPI-specific — index protocol, artifact
layout, name normalization, unpacking — should be separable from the parts that
are not: the verdict store, the policy engine, the plugin runner, the advisory
matching.

## Constraints

- Must speak enough of the PyPI Simple API that an unmodified, current pip
  works against it with only `index-url` changed. No pip timeout setting, no
  wrapper script, no plugin on the developer's machine.
- Client-facing HTTP must be **HTTP/1.1**, so reason phrases survive.
- Refusals must use a status pip surfaces rather than silently retries, and the
  reason must ride in the reason phrase.
- The scan path must never fail open. An error running a check is not a clean
  verdict.
- Must run as one process on one server with no external services required.

## Decided

Everything in **Shape** above was decided and is not open for the builder to
revisit: proxy position, hanging first-request behavior with a budget and a
retryable overflow, scan order, verdict caching, policy-filtered index pages,
file-based config, org-set CVE threshold, org allowlist overriding stored
verdicts, exit-code plugin contract, plugin sandboxing, scheduled advisory
sync, TTL artifact cache, reason-phrase denials plus the `/why/<id>` endpoint,
Rust, single binary, SQLite, Python-first.

Decided by the author of this document rather than in conversation, and marked
as such: per-artifact verdict granularity, PEP 658 pass-through, the
policy/plugin fingerprint on verdict rows, unknown-severity defaulting to
non-blocking, and the upstream-outage behavior.

## Left to the builder

- Which HTTP server and client crates, and the async runtime.
- The sandbox mechanism (namespaces, container runtime, seccomp, or similar)
  and its resource and time limits for plugin execution.
- Database schema, migrations, and how the advisory mirror is stored and
  matched against package versions.
- Which advisory sources to sync and their sync cadence.
- The exact argument contract passed to plugin binaries, and what plugin
  stdout/stderr is used for beyond the exit code.
- Config file format and its schema.
- Concurrency behavior when several developers request the same unscanned
  version simultaneously (one scan, others wait, is the obvious shape).
- Whether developers authenticate to the proxy, or deployment relies on
  network placement.
- Logging, metrics, and operational surface.
- Error taxonomy: which status codes and reason-phrase codes map to which
  refusal and which transient conditions, and the exact phrase grammar.
- The actual scan budget value, and how background scans are queued and
  deduplicated.
- How `/why/<id>` is rendered and how long ids live.
- Testing approach, including how to exercise the scan path without reaching
  the real PyPI.
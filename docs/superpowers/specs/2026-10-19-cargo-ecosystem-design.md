# Supply Chain Scanner — Cargo/crates.io Support — Design

**Date:** 2026-10-19
**Status:** Design, approved scope for planning
**Extends:** `docs/superpowers/specs/2026-10-17-supply-chain-scanner-design.md`
**Reuses:** `docs/superpowers/specs/2026-10-18-ai-reviewer-design.md`'s collector/AI-review
pipeline, unchanged in shape

## Intent

The base design put a gate in front of `pip install`. This extends that gate to
`cargo add`: a developer adds a crate dependency, and the crate's code is
checked — for known CVEs and, same as any other ecosystem, for AI-reviewed
malicious behavior — before `cargo add` returns, exactly as `pip install`
already blocks on an unscanned wheel today.

### Why now

Rust's build model makes this more urgent than it sounds. A crate's `build.rs`
runs arbitrary code at build time, with full host access, before a single line
of the crate's own logic compiles; a proc-macro crate's code runs *inside the
compiler*. Nothing about today's `cargo add` / `cargo build` flow checks either
one. The same supply-chain exposure the base design closes for Python exists
here, arguably with a sharper edge.

## Goals

- **Same guarantee, new ecosystem.** A crate that reaches a developer's machine
  through this proxy has been checked the same way a PyPI package already is:
  advisories, AI-reviewed source, and org plugins — just not all at the same
  moment; see "Plugins run at fetch, not at add," below.
- **Block at `cargo add`, not later.** The gate fires before `cargo add`
  returns, not deferred to the next `cargo build`. This was the one point in
  this project's brainstorming the author was firm on, even once a simpler
  build-time alternative was on the table.
- **Reuse, don't reimplement, the scan pipeline.** CVE matching, AI review, the
  verdict store, the allowlist, and the fingerprint-driven re-scan rule all
  carry over from the PyPI implementation unchanged in shape.

## Non-goals

- Not a `cargo` wrapper, shell alias, or shim binary. The mechanism is a
  transparent registry proxy, exactly like the PyPI side — cargo is pointed at
  it and believes it is talking to crates.io directly.
- Not eager, whole-history scanning. A crate can have hundreds of published
  versions; only the versions actually in play for a given request are ever
  fetched and checked.
- Not a guarantee that every explicit version pin resolves. See "The version
  the proxy can't see," below — this is a known, accepted limitation, not an
  oversight.
- Not a second running process in the same deployment as the PyPI proxy. One
  process serves one ecosystem, same as the base design already assumes for
  PyPI; cargo support ships as a second deployment of the same binary, pointed
  at a different upstream and config.

## Anti-goals

- **A pinned dependency that silently fails to resolve with no indication why**
  would read as the proxy being broken rather than doing its job. Since
  cargo's protocol gives index-time refusals no reason-phrase channel to ride
  on, the recent-refusals page ("A page for the refusals cargo can't surface
  itself," below) is load-bearing here, not a nice-to-have.
- **A `cargo add` that blocks for tens of seconds on a crate with a long,
  mostly-malicious version history.** The cascade (below) is bounded by the
  same shared-deadline budget the AI provider retry already uses — it must
  degrade to a retryable "still working" response, never an open-ended hang.

## Shape

### The protocol difference from PyPI

PyPI's Simple index (PEP 503) mixes "list what's available" and "the bytes
pip actually needs" closer together than crates.io's sparse-index protocol
does. Cargo's registry has two genuinely separate HTTP touchpoints:

1. **Index metadata** — `GET` on a per-crate path computed from the crate
   name (a 1/2/3/4+-character prefix scheme), returning one JSON line per
   published version: version string, dependencies, checksum, `yanked` flag.
   No crate source involved.
2. **Crate download** — a separate `GET` for the actual `.crate` tarball,
   templated from the registry's `config.json` (`dl` key, with `{crate}`,
   `{version}`, `{prefix}` markers).

`cargo add` (and, generally, cargo's own dependency resolution) only ever
exercises (1). It does not fetch (2) — that happens later, when `cargo
build`/`check`/`fetch` actually need the source on disk. This is the fact that
makes "block on the actual crate fetch, before `cargo add` returns" a real
design problem rather than a free consequence of proxying: the gate has to
live in the index response itself, not in the download, because by the time
cargo would ask for the download, `cargo add` has already returned.

### The index response is the gate

For a given crate, on each index request:

1. Fetch the real upstream index data.
2. **CVE-filter every listed version.** This is metadata-only — name,
   version, and a local advisory mirror, no network fetch of source — so it
   runs across the entire version list, every request, the same way the PyPI
   side already re-checks advisories against stored-clean verdicts on every
   request. Any version matching a blocking advisory (same severity/
   fix-available/allowlist policy as PyPI) is dropped.
3. Among the surviving CVE-clean versions, **excluding any the index marks
   `yanked`** — cargo itself already discounts a yanked version for a fresh
   resolution, so spending the scarce AI-review budget on one would both
   waste it and starve the non-yanked version that a real `cargo add` would
   actually select — find the newest one whose AI review is not already
   cached.
4. If there is one, check it against the cargo-vet audit fast path (below)
   first. Only if it has no qualifying audit does the proxy fetch its
   `.crate` tarball from upstream now (server-side — cargo never asked for
   it) and run it through the same sandboxed collector → AI reviewer
   pipeline the PyPI side uses, under the shared request budget.
5. If that version fails review, cache the bad verdict and move to the
   *next*-newest CVE-clean, not-yet-cached version — repeating step 4 — until
   the budget (shared across every attempt in this cascade, same
   `Instant`/`Duration` deadline-sharing the AI provider retry already does)
   runs out, a version passes, or the CVE-clean list is exhausted.
6. The response forwarded to cargo contains exactly the versions that are
   both CVE-clean and AI-review-cached-passed — nothing unscanned, nothing
   CVE-blocked, nothing AI-rejected. Everything else is simply absent, the
   same way the PyPI side omits known-bad versions from the Simple index
   rather than relying on download-time refusal alone.

If the budget runs out mid-cascade, the request gets the same retryable
"still working" treatment `Decision::InProgress` already gives a slow PyPI
scan — the cascade that was running keeps running, detached, and its results
land in the verdict cache for the next request to find.

A version that appears in the forwarded response has already cleared CVE
and AI review (or the cargo-vet fast path in its place) to get there, but —
unlike PyPI, where every check runs before the first serve — it has not yet
had org plugins run against it; see "Plugins run at fetch, not at add,"
below, for why that check is placed at the later `.crate` download instead.

### A known-good fast path: cargo-vet audits

[cargo-vet](https://mozilla.github.io/cargo-vet/) is a static trust
database, not a scanner: an `audits.toml` recording that a specific crate
version was manually audited by a named person or org against a named
criterion (built in: `safe-to-run`, a lower bar, and `safe-to-deploy`, a
higher one), plus a mechanism for importing other organizations' published
audit sets wholesale. Mozilla and Google each publish one, and between them
cover a large share of the crates.io ecosystem's most heavily used crates —
exactly the crates this project's AI-review cascade would otherwise spend
budget reviewing on every org's first touch, for code that strangers have
already read closely.

Before fetching a candidate's source for AI review (cascade step 4, above),
the proxy checks whether that exact crate+version already carries a
qualifying audit. A version counts as covered, and skips straight to
AI-review-passed-cached without ever being fetched or sent to the AI
provider, when:

- it has an audit entry (a full audit, or a delta chain back to one) in one
  of this deployment's configured trusted audit sources — Mozilla's and
  Google's published sets by default, plus the org's own `audits.toml` if
  it has one;
- that entry's criterion meets or exceeds **the org-configured bar** —
  `required_criterion`, a setting with no hardcoded default behavior of its
  own beyond "the org sets it," though `safe-to-deploy` is the stricter and
  more defensible starting point;
- and, when the org has configured a non-empty `trusted_reviewers`
  allowlist, the entry's `who` matches an identity on that list. An empty
  list means any entry from a trusted source counts, by whoever audited it;
  a non-empty list narrows "trusted source" down to "trusted source, *and*
  I trust this specific auditor's name on it" — an org may trust Mozilla's
  process in general but still want to name the specific reviewers whose
  judgment they're relying on.

This fast path only ever substitutes for the AI-review half of the
cascade. CVE filtering still runs against every version regardless of
audit status, and org plugins — a mechanical, sandboxed check orthogonal to
"a human read this and judged it safe" — still always run at the `.crate`
download, audited or not.

The trusted audit sets are fetched on the same sync-on-schedule cadence as
the advisory mirror, for the same reason: a live fetch per request would
make an upstream outage on Mozilla's or Google's end into a proxy outage,
and this data changes slowly enough that staleness on the order of the sync
interval is an acceptable trade.

### Plugins run at fetch, not at add

Org-supplied plugins (the base design's sandboxed, exit-code binaries) are
not part of the index-time cascade. They run when the `.crate` download is
actually requested — normally at the `cargo build`/`check` that follows an
`cargo add` — against the unpacked crate source, the same sandboxed
exit-code contract and per-plugin time limit the base design already
defines. This was a deliberate choice, not an oversight the index-time
cascade forgot: plugin checks can be heavier than a single AI review call
(a static analysis pass, or something that itself partially executes
`build.rs` in a sandbox to see what it does), and nothing about this
project's goals requires them to block `cargo add` the way CVE and AI
review are specifically required to.

Mechanically, this makes the first download of a given artifact hash behave
exactly like PyPI's first download already does: it blocks, under a plugin
timeout budget, while the plugin set runs; a pass stores the artifact as
fully clean and serves it; a failure refuses it with a reason phrase — and
because this *is* a real per-request download, unlike the index response,
the reason phrase and `/why/<id>` link reach the developer exactly the way
the base design already describes for PyPI. Every later download of the
same already-plugin-checked artifact is instant.

One version can therefore sit in two different states: admitted to the
index (CVE-clean, AI-review-passed) but not yet plugin-checked, versus
fully scanned (also plugin-clean). Only the second state has ever been
downloaded; the first is all that's needed to appear in what `cargo add`
sees.

### A page for the refusals cargo can't surface itself

CVE and AI-review refusals happen at index time, where — per "The version
the proxy can't see," above — there is no HTTP error for a specific version
to attach a reason phrase to; the version is just absent from an otherwise
successful response, and cargo's own error ("no matching version") carries
nothing this proxy put there. Rather than leave that genuinely silent, the
proxy serves a small page — unauthenticated, read-only, no cargo-side
integration — listing the most recent refusals (crate, version, reason,
timestamp), each linking to that refusal's `/why/<id>`. A developer who
hits an unexplained resolution failure checks this page by hand; it is the
compensating channel for exactly the case cargo's protocol can't carry a
reason phrase for. Plugin refusals, which do get a reason phrase (above),
show up on this page too, for the same at-a-glance convenience, but aren't
the case it exists to solve.

### The version the proxy can't see

The sparse-index request cargo sends to resolve `cargo add foo` is
byte-for-byte identical to the one it sends for `cargo add foo@1.2.3`, or for
an unrelated transitive dependency resolution — the HTTP layer carries no
signal about which version, if any, the caller actually wants. The "newest
CVE-clean, not-yet-cached" convention above is what makes an unconstrained
`cargo add foo` work correctly and fast after the first touch.

It also means a pin to an older version that has never independently been
"the newest unscanned candidate" at some point won't appear in the forwarded
list, and `cargo add foo@1.2.3` will fail to resolve — not because 1.2.3 is
bad, but because it was never reachable by the only mechanism the proxy has
for picking what to review. This was discussed and accepted explicitly: it's
the same failure *shape* a CVE-blocked version already produces (absent from
the list, resolution fails), just a different cause, and it is documented
here as a known limitation rather than solved by guessing at cargo's command
line.

### Advisory data

OSV publishes a `crates.io` ecosystem feed, sourced from the RustSec
Advisory Database (`rustsec/advisory-db`), the same shape of sync-on-schedule
mirror the PyPI side already pulls OSV's PyPI feed from. Reuses
`crate::advisory::osv` and `crate::db::advisory` as-is; only the sync URL and
ecosystem tag differ from the PyPI configuration.

### Version comparison is new work, not reuse

`crate::advisory::matching::affects` is written against PEP 440 semantics
(`pep440_rs::Version`) — that's correct for PyPI but wrong for crates.io,
which uses SemVer (`semver` crate), a close but not identical scheme
(prerelease ordering, build-metadata handling, and the meaning of a bare `*`
differ). Matching needs a second, SemVer-aware implementation of the same
"does this advisory affect this version" question, not a shared one. Which
implementation runs is selected by the artifact's `ecosystem` field, the same
field that already exists on every `ArtifactKey` and advisory row.

### Install surface: the whole crate, with build.rs and proc-macros first

PyPI's install-surface split (install surface first, then as much of the
rest of the tree as fits the coverage budget) exists because a wheel can
bundle large amounts of compiled, non-reviewable material alongside a small
amount of code that actually runs on install. A crate doesn't have that
split — it is near-universally pure `.rs` source plus `Cargo.toml`, so
there's no "install surface vs. the rest" distinction to draw the same way.

The whole crate is in scope for review. The one thing worth prioritizing
within it: `build.rs` and any proc-macro entry point, since those execute
arbitrary code at build time or inside the compiler rather than at whatever
point the rest of the crate's code might run — they go into the payload
first, same as PyPI's install surface does, with the rest of the source
filling the remaining coverage budget.

### Budget

Cargo's HTTP client defaults to a **30-second per-request timeout**
(`[http] timeout` in `.cargo/config.toml`, operator-configurable), the
cargo-side equivalent of pip's 15-second default that bounds the PyPI scan
budget today. The cascade's shared deadline must stay under whatever this
deployment's cargo clients are actually configured with — looser than the
PyPI side's constraint by default, but a real ceiling, not an assumption.

### Deployment

A second deployment of the same binary: its own config file, its own
`upstream_url` (`sparse+https://index.crates.io/` plus the download host from
`config.json`'s `dl` template), its own bind address, its own `Ecosystem`
implementation (`cargo`, alongside the existing `pypi`). Not a second
ecosystem multiplexed into one running process — `Config` has a single
`upstream_url` today and nothing in the HTTP layer routes by ecosystem within
one process; splitting deployments is the change that fits what's there
rather than restructuring config and routing to carry two ecosystems at once.

Developer-side setup mirrors pip's `index-url` change: a `[source]`
replacement in `.cargo/config.toml` pointing `crates-io` at this deployment's
sparse URL, same spirit as pointing pip at the proxy, no wrapper or shim
installed on the developer's machine.

### Reused as-is

- The verdict store, per-(ecosystem, package, version, hash) granularity.
- The allowlist, consulted before the verdict, same override semantics.
- The policy/plugin/AI-reviewer fingerprint that invalidates stored verdicts
  when the rules producing them change.
- The sandboxed collector and AI reviewer pipeline in full — prompt,
  nonce-tagged file delimiters, provider client, reply parsing, sanitization,
  `block_on`/coverage-threshold config.
- The plugin runner and its sandbox: same exit-code contract, same
  per-plugin time limit, same unpack-then-run shape, just triggered by the
  `.crate` download instead of a wheel download.
- `/why/<id>` for a refused crate version; the config-gated `/api/reviews`
  read API.
- SQLite, single binary, no external services.

## Constraints

- Must speak enough of the sparse-index protocol (`config.json`, per-crate
  index files, ETag/Last-Modified conditional requests) that an unmodified,
  current `cargo` works against it with only the registry source replaced in
  `.cargo/config.toml`.
- The scan path never fails open — identical rule to the base design,
  unchanged by ecosystem.
- The cascade's total time must stay under the deployment's configured cargo
  `http.timeout`, the same way the PyPI scan budget stays under pip's.
- A version is never forwarded to cargo unless it is both CVE-clean and
  AI-review-cached-passed, where a qualifying cargo-vet audit stands in for
  AI-review-passed per "A known-good fast path," above. The `.crate`
  download is a separate, real gate on top of that — org plugins — not a
  pass-through; see "Plugins run at fetch, not at add."
- The cargo-vet fast path only ever substitutes for AI review. It never
  substitutes for CVE filtering or for the plugin gate at download time.

## Decided

Everything in **Shape**: no wrapper, pure transparent proxy; the index
response (not the download) is the one gate; eager CVE-filtering across the
whole version list per request; lazy, cached, newest-candidate-first AI
review; cascading through CVE-clean candidates within the shared request
budget on an AI-review failure, falling back to the existing retryable
"still working" response if the budget runs out; the explicit-pin
reachability limitation, accepted rather than solved; a second deployment of
the same binary rather than multi-ecosystem multiplexing in one process;
whole-crate review scope with `build.rs`/proc-macros prioritized first; org
plugins gate the `.crate` download rather than the index response, so they
run at the first `cargo build`/`check`/`fetch`, not at `cargo add`; a small
unauthenticated recent-refusals page compensates for cargo's protocol
giving index-time refusals no reason-phrase channel; a cargo-vet audit from
a trusted, org-configured source meeting an org-configured criterion bar
(optionally narrowed further to an org-configured list of trusted
reviewers) substitutes for AI review in the cascade, never for CVE
filtering or the plugin gate.

Decided by the author of this document rather than in conversation, and
marked as such: yanked versions are excluded from cascade candidate
selection entirely, never consuming AI-review budget.

## Left to the builder

- The exact `Ecosystem` impl for cargo: name validation against crates.io's
  naming rules, the prefix-path computation for index file locations,
  `config.json` parsing, and the per-crate index file's JSON line format.
- Whether ETag/Last-Modified conditional-request support is wired in at the
  same time as the base implementation or added after.
- The SemVer-aware advisory-matching module's exact structure, and whether it
  shares any code with the PEP 440 one beyond the `Advisory`/`VersionRange`
  types.
- How the cascade's per-attempt sub-budget is apportioned — equal shares,
  first-attempt-gets-more, or some other split of the shared deadline across
  however many candidates get tried.
- Config schema for the cargo deployment: field names, defaults, and how much
  (if any) is shared via a common config module versus duplicated per
  ecosystem.
- Exactly which crates.io advisory metadata fields RustSec's OSV export
  carries (ranges vs. enumerated versions, severity) and how closely it
  mirrors the PyPI OSV shape the existing sync code already expects.
- Testing approach for exercising cargo's sparse protocol and the download
  endpoint without reaching the real crates.io.
- The recent-refusals page's retention/limit (how many entries, how far
  back), whether it's global or per-ecosystem-deployment, and its exact
  rendering — likely a plain HTML table in the same spirit as `/why/<id>`'s
  own rendering, not a feature needing its own design pass.
- How a verdict row represents "index-admitted, not yet plugin-checked"
  versus "fully scanned" — an additional state on the existing verdict
  schema, or a second row/table keyed the same way.
- The cargo-vet config schema: field names and shape for
  `trusted_audit_sources` (URLs plus nicknames, mirroring cargo-vet's own
  `config.toml` import table), `required_criterion`, and
  `trusted_reviewers`; how delta-audit chains are resolved back to a full
  audit when checking coverage; and whether a verdict produced via this
  fast path is distinguished from an AI-reviewed one in storage (for the
  `/why/<id>` and recent-refusals rendering, a developer likely benefits
  from seeing "covered by Google's cargo-vet audit" rather than a generic
  "passed").

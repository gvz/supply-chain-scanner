# Supply Chain Scanner — npm Support — Design

**Date:** 2026-10-30
**Status:** Design, approved scope for planning
**Extends:** `docs/superpowers/specs/2026-10-17-supply-chain-scanner-design.md`
**Mirrors:** `docs/superpowers/specs/2026-10-19-cargo-ecosystem-design.md`, whose
two-gate shape this follows deliberately and closely
**Reuses:** `docs/superpowers/specs/2026-10-18-ai-reviewer-design.md`'s collector/AI-review
pipeline, unchanged in shape

## Intent

The base design put a gate in front of `pip install`. The cargo design extended
it to `cargo add`. This extends it to `npm install`: a developer adds a Node
dependency, and the package's code is checked — for known CVEs, for release age,
and for AI-reviewed malicious behaviour — before npm ever receives the tarball
bytes, with org plugins gating the tarball download itself.

### Why now

npm is the ecosystem where install-time code execution is the *default*, not an
edge case. A package's `preinstall`, `install`, and `postinstall` scripts in
`package.json` run automatically the moment npm extracts the tarball. There is no
separate build step a developer might skip, unlike cargo's `build.rs` (which runs
only on `cargo build`) or a PyPI wheel (where nothing auto-executes at install).

That single fact sets the deadline for this whole design: whatever the proxy
decides has to be decided *before* npm holds the tarball. Once the bytes are on
disk and npm extracts them, the scripts have already run. There is no later gate
to fall back on, which is why the tarball download is a hard refusal point here
and not merely a convenient one.

The author confirmed the motivation is the same as for the other two ecosystems —
a malicious package reaching a developer's machine — and specifically confirmed
install scripts as the risk worth calling out to the reviewer.

## Goals

- **Same guarantee, third ecosystem.** A package that reaches a developer through
  this proxy has been checked the way a PyPI package and a crate already are:
  advisories, release age, AI-reviewed source, and org plugins — with the same
  split of which check fires at which touchpoint that cargo already established.
- **Block before any install script can run.** The gate fires before npm receives
  tarball bytes. This is the npm-specific hard requirement; see "Why now."
- **Call install scripts out to the reviewer.** `preinstall`/`install`/`postinstall`
  command text is surfaced to the model as its own flagged, higher-scrutiny
  section, not left buried in the general file dump. Author's explicit request.
- **Reuse, don't reimplement.** CVE matching (including the SemVer matcher cargo
  already added), the release-age gate, the verdict store, the allowlist, the
  fingerprint-driven re-scan rule, the single-flight coordinators, the collector
  and AI reviewer, the plugin runner, `/why/<id>`, and the recent-refusals page
  all carry over.

## Non-goals

- **No shortcuts past AI review.** cargo got a cargo-vet fast path: a human audit
  from a trusted source substitutes for AI review. npm has no equivalent standard
  — npm's own provenance attestations prove *where* a package was built, not that
  a person read it — and the author was explicit: "no short cuts." Every
  not-yet-reviewed version goes through a real AI review or is not forwarded. No
  fast path, no stand-in, no exceptions.
- Not an `npm` wrapper, shim, or `.npmrc` script hook. The mechanism is a
  transparent registry proxy, exactly like the other two — npm is pointed at it
  with a registry setting and believes it is talking to `registry.npmjs.org`.
- Not eager, whole-history scanning. A popular npm package can have a thousand
  published versions; only versions actually in play are fetched and reviewed.
- Not private or scoped-registry support, and no auth passthrough. This proxy
  fronts the public registry only. Author confirmed out of scope.
- Not a guarantee that every explicit version pin resolves. The same limitation
  the cargo design accepted applies here, with the same cause, now scoped to a
  major-version line rather than the whole package; see "Breadth: newest per
  major."
- Not a defence against a lockfile that pins the public registry. `npm ci` against
  such a lockfile never contacts this proxy at all; see "The tarball route."
- Not a second ecosystem multiplexed into one running process. npm ships as a
  third deployment of the same binary, same as cargo.

## Anti-goals

- **An `npm install` that succeeds while a malicious `postinstall` runs.** This is
  the failure the whole design exists to prevent, and it is why no code path may
  serve tarball bytes that have not cleared every gate.
- **A broken `dist-tags.latest`.** npm resolves a bare `npm install foo` through
  `dist-tags.latest`. A filtered packument whose `latest` points at a version the
  proxy removed would make every unpinned install fail with an error that looks
  like registry corruption rather than a policy decision. See "Repointing
  dist-tags."
- **A resolution failure with no indication why.** As with cargo, metadata-time
  refusals have no reason-phrase channel: the version is simply absent from an
  otherwise-successful response. The existing recent-refusals page is the
  compensating channel and is load-bearing here too.

## Shape

### The protocol: packument and tarball

npm's registry has two touchpoints, cleanly separated the way cargo's are:

1. **The packument** — `GET /{package}` returns one JSON document describing the
   whole package: a `versions` object (every published version, each with its
   `dist.tarball` URL, `dist.integrity`/`dist.shasum`, dependencies, `bin`,
   `scripts` in the full form, and `hasInstallScript` in the abbreviated form), a
   `dist-tags` object mapping tag names to versions, and — in the full form only —
   a `time` object mapping each version to its publish timestamp.
2. **The tarball** — a separate `GET` for the `.tgz` named by `dist.tarball`.

npm's dependency resolution exercises only (1). It fetches (2) once it has decided
what to install — and extraction, with its install scripts, follows immediately.
So, exactly as in the cargo design, the metadata response is where the decision
has to be made, and the tarball download is the last point at which bytes can
still be withheld.

**Abbreviated vs. full packument.** npm requests the abbreviated form by sending
`Accept: application/vnd.npm.install-v1+json`; the abbreviated document omits
`time`, which the release-age gate needs. The proxy therefore always requests the
**full** packument from upstream regardless of what the client asked for, filters
it, and serves the filtered document back. Serving a full document to a client
that asked for the abbreviated one is believed safe — the abbreviated form is a
size optimisation over a subset of the same fields — but this is the single
protocol assumption in this design most worth verifying against a real npm client
early; see "Left to the builder."

### The packument response is the gate

For a given package, on each packument request:

1. Fetch the real upstream full packument.
2. **CVE-filter every listed version**, metadata-only against the local advisory
   mirror, every request — same policy (severity, fix-available, allowlist) and
   same reasoning as the other two ecosystems.
3. **Apply the release-age gate** to every version, from the packument's own `time`
   map. Unlike PyPI and cargo, this needs no extra upstream call: the publish
   timestamps arrive in the document already being fetched. The gate keeps its
   established best-effort semantics — a version with no usable timestamp is not
   blocked on age grounds — and its existing per-deployment configurability.
4. **Group the survivors by major version**, and within each major line find the
   newest version whose AI review is not already cached. Review it: fetch its
   tarball server-side (npm never asked for it), verify its integrity, unpack it,
   and run the same sandboxed collector → AI reviewer pipeline the other two
   ecosystems use, under the shared request budget. See "Breadth: newest per
   major," below, for why this is per-major rather than one version per package.
5. If a version fails review, cache the verdict and cascade to the *next*-newest
   not-yet-reviewed survivor **within that same major line**, repeating step 4,
   until that line yields a pass or is exhausted. Move through the major lines
   newest-first, so the most likely-wanted version is reviewed before budget runs
   low.
6. The packument forwarded to npm contains exactly the versions that are
   CVE-clean, old enough, and AI-review-cached-passed. Everything else is absent
   from `versions`.
7. **Repoint `dist-tags`** against the surviving set; see below.
8. **Rewrite each surviving version's `dist.tarball`** to point at this proxy, so
   the download gate stays in the loop; see "The tarball route," below.

Budget exhaustion mid-cascade gets the retryable "still working" response, but the
npm deployment holds the connection far longer before reaching for it than the
other two do; see "Budget," below.

### Breadth: newest per major

cargo's cascade stops at the first version that passes and forwards essentially
one version per crate, accepting that an unreachable pin fails to resolve. That
trade does not survive contact with npm.

npm resolves a whole tree, and every dependency carries a range. Two different
dependents needing different majors of the same package is not an edge case in npm
— it is the ordinary state of a real `node_modules`. If a packument carries only
the single newest reviewed version, a dependent needing an older major finds
nothing satisfying its range, and that failure is not local: it fails the **entire**
`npm install`, not one package. One-version-per-package would mean most real
projects never resolve at all.

So the cascade works per major-version line: for each distinct major among the
survivors, the newest not-yet-reviewed version in that line is a candidate, and
the forwarded packument can carry one passing version per major. Major lines are
visited newest-first so that if the budget runs out partway, what got reviewed is
what a fresh `npm install` most likely wanted.

This costs more review budget on a package's first touch than cargo's model does —
a package with five live majors may need five reviews before its packument is
useful. That is the price of resolving at all, and it is paid once per
(package, major) and then cached like any other verdict.

The explicit-pin limitation the cargo design accepted still applies *within* a
major line: a pin to an old patch release that was never the newest unreviewed
candidate in its line will not appear. Same cause, same accepted trade, now scoped
to a line rather than the whole package.

A version present in the forwarded packument has cleared CVE, age, and AI review,
but has **not** yet had org plugins run against it — same two-state split cargo
has, same reason; see "Plugins run at fetch."

### Repointing dist-tags

`dist-tags` is npm-specific and has no cargo analogue. `npm install foo` with no
version resolves through `dist-tags.latest`; a tag pointing at a filtered-out
version would break every unpinned install with a misleading error.

The forwarded packument's `dist-tags` is rewritten: every tag whose target version
survived is kept as-is, and `latest` specifically is repointed to the newest
surviving version when its original target did not survive. A non-`latest` tag
(`next`, `beta`, an org's own) whose target did not survive is **dropped** rather
than repointed — repointing an arbitrary tag would silently redirect a developer
who asked for `beta` to a version nobody tagged that way, which is a worse
outcome than the tag being absent. When no version survives at all, `dist-tags` is
empty and the packument is served with an empty `versions` map, which npm reports
as "no matching version" — the same shape as a package that genuinely has none.

### Deprecated versions stay candidates

cargo excludes `yanked` versions from cascade candidacy entirely: cargo itself
discounts a yanked version for fresh resolution, so reviewing one wastes scarce
budget. npm's nearest equivalent is a version's `deprecated` field, and it is
**not** the same thing: npm installs deprecated versions routinely, emitting only
a warning, and a great many widely-depended-on versions carry a deprecation
notice. Excluding them from candidacy would make ordinary installs fail.

So deprecated versions remain full candidates: reviewed, forwarded, and served
like any other. The `deprecated` field itself is passed through untouched so npm
still shows the developer its warning.

Decided by the author of this document rather than in conversation, and marked as
such.

### The tarball route

Each surviving version's `dist.tarball` in the forwarded packument is rewritten to
a URL on this proxy, so npm asks this proxy for the bytes and the plugin gate
stays in the loop. This mirrors the cargo deployment rewriting `config.json`'s
`dl` template back at itself, for exactly the same reason.

The route shape follows the registry's own:
`/{name}/-/{name-without-scope}-{version}.tgz`. For a scoped package that is
`/@scope/name/-/name-1.0.0.tgz`, carrying the scope's literal unencoded slash —
unlike the packument path, where the slash must be `%2f`-encoded. Name validation
therefore permits exactly one `/` when the name begins with `@`, and the tarball
route is matched as a wildcard path rather than a single segment. Everything else
the validator rejects (`..`, control characters, a second slash, a leading `.` or
`_`) it keeps rejecting.

**`npm ci` can bypass this, and nothing server-side can stop it.** The rewritten
URL lands in `package-lock.json`'s `resolved` field, which has two consequences
worth stating plainly rather than discovering later:

- A lockfile generated behind the proxy is proxy-specific. Its `resolved` URLs name
  an internal host, so the same lockfile does not work for anyone outside the
  network.
- A lockfile generated *without* the proxy pins `resolved` at
  `registry.npmjs.org`, and `npm ci` honours those URLs directly. Those fetches
  never reach this proxy, so no gate applies to them.

This is recorded as a known limitation in the same honest spirit as the cargo
explicit-pin limitation, not solved: the proxy cannot intercept a request that is
not sent to it, and the alternative — not rewriting `dist.tarball` — would remove
the plugin gate entirely, which is strictly worse. An org that cares closes it
operationally, by regenerating lockfiles behind the proxy. The author considered
shipping operator tooling for this (a CI check, a lockfile audit endpoint) and
chose the documented-limitation option.

### Integrity: sha512, sha1, and the artifact key

npm declares a tarball's digest two ways. Modern packages carry
`dist.integrity`, a Subresource Integrity string (`sha512-<base64>`, occasionally
`sha1-`); older ones carry only `dist.shasum`, a hex sha1. npm itself prefers
`integrity` when present and falls back to `shasum`. The proxy does the same, and
verifies downloaded bytes against whichever it used — a mismatch is the same
security-significant hash-mismatch refusal the other ecosystems already log at
`error!`.

This collides with an existing type: `ArtifactKey.sha256` is named for the digest
PyPI and crates.io both happen to publish. npm publishes neither. The field is
therefore widened in meaning — "the registry-declared content digest for this
artifact, lowercase hex" — and carries npm's sha512 (or sha1) hex digest for an
npm artifact. The field name stays as-is: renaming it would touch the database
schema, every stored verdict row, and both existing ecosystems, for a cosmetic
gain.

**This reaches further than the key.** `artifact_cache::validated_sha256` rejects
anything that is not exactly 64 lowercase hex characters, and it gates both `get`
and `insert`, with `path_for` sharding on the first two characters. An npm sha512
(128 hex) or sha1 (40 hex) in that field makes every cache operation fail. That
validator must therefore accept the digest lengths this proxy can actually
produce — 40, 64, and 128 lowercase hex — while keeping the rest of its
rejection behaviour and its two-character sharding, which works unchanged at any
of those lengths.

Settled here rather than left open, because the alternative does not exist: keying
on a sha256 the proxy computes itself cannot work, since the metadata-time verdict
lookup needs a digest *before* anything is downloaded, and the registry never
publishes one. Widening the validator is additive — no currently-valid digest
becomes invalid — so neither existing ecosystem changes behaviour. The cache stops
being single-algorithm content-addressed, which is a real if modest loss:
a pre-2017 npm package's cache identity is a sha1.

A sha1-only package is worth noting as a weaker guarantee than the other two
ecosystems offer: sha1 is collision-prone, so "the bytes match what the registry
declared" is a weaker statement there. It is still strictly better than no
verification, it is all the registry offers for those packages, and npm itself
accepts them — so the proxy accepts them too, rather than making every pre-2017
package unservable.

### Plugins run at fetch, not at resolve

Org plugins run when the tarball download is requested, against the unpacked
package, with the same sandboxed exit-code contract, per-plugin timeout, and
once-per-artifact single-flight dedup the cargo download gate already uses. A pass
stores the artifact fully clean and serves it; a failure refuses it with a reason
phrase and a `/why/<id>` link, which — unlike a metadata-time refusal — does reach
the developer directly.

The reasoning is cargo's, unchanged: plugin checks can be much heavier than one AI
review call, and nothing requires them to block dependency resolution the way CVE
and AI review specifically must.

### The tarball gate is not plugins alone

The cargo download handler, as built, looks a requested version up in the
*upstream* index and — when no verdict is stored for it — downloads, verifies the
checksum, unpacks, runs plugins, and serves on plugin-pass alone. That version was
never CVE-filtered, never age-checked, never AI-reviewed. The handler's gate is
the plugin set and nothing else.

On cargo that is survivable: a `.crate` on disk still needs a `cargo build` before
`build.rs` runs. On npm it is the stated anti-goal directly — those bytes are a
`postinstall` that runs seconds later, with no further step a developer might not
take.

So the npm tarball route is **not** a port of that handler. Before serving any
bytes, it requires the requested version to be metadata-approved: CVE-clean, past
the release-age threshold (or exempt), and AI-review-passed, read from the same
stored verdicts the packument gate writes. A version that is not approved is
refused outright; it is never reviewed inline on the download path, because a
download request is not where a review belongs and because the packument gate has
necessarily already run for any version npm could have learned about.

**The same hole gets closed on the cargo download path.** It is the same defect
with a longer fuse, and leaving one ecosystem with a known bypass while
documenting the other as airtight would be indefensible. The cargo handler gains
the same metadata-approval requirement. That is a behaviour change to a shipped
path, so it needs its own tests and its own note in `docs/operations.md`, and it
belongs in this work rather than being deferred.

### Install scripts are called out to the reviewer

The collector gains an npm-specific step. Beyond the ordinary file walk, it parses
the package's `package.json` and extracts the `scripts` entries that npm executes
automatically on install — `preinstall`, `install`, `postinstall` — plus
`prepare`, which runs on install from a git dependency. Their literal command text
goes to the model as its own labelled, flagged section of the payload, ahead of
the file blocks, described as commands that run automatically at install time
without the developer invoking anything.

This is distinct from `package.json` merely being a reviewable file that happens to
be in the payload. The scripts get their own call-out because they are the npm
attack surface: a one-line `postinstall` is the single most common shape of a real
weaponised npm package, and burying it in a `package.json` block among
`dependencies` and `devDependencies` noise invites the model to skim past it.

The system prompt gains matching text telling the model those commands run
automatically at install time and warrant the closest scrutiny in the payload.
Both the collector change and the prompt change bump their respective versions
(`COLLECTOR_VERSION`, `PROMPT_VERSION`), which the policy fingerprint carries — so
this re-reviews every artifact in every ecosystem on next request. That is correct
and intended: the prompt a verdict was produced under has changed.

A missing, unparseable, or script-less `package.json` yields no scripts section
and is not an error — a package with no install scripts is the common, benign
case.

### Install surface: the whole package, scripts and entry points first

An npm tarball unpacks with every entry under a `package/` prefix (npm's own
convention, independent of the package's name). The install surface, relative to
that root:

- `package/package.json` — holds the scripts that execute on install.
- Any file path named by a `scripts` value that runs on install (a
  `postinstall` of `node scripts/setup.js` makes `package/scripts/setup.js`
  install surface).
- `package/index.js`, and whatever `main` names — the module body runs on first
  `require`/`import`.
- Whatever `bin` names — installed onto the developer's `PATH`.

The existing `InstallSurface` trait decides on path shape alone and has no access
to file contents, which is a real constraint here: resolving `main`, `bin`, and
script targets requires reading `package.json`. The path-only implementation
therefore covers the fixed, conventional paths (`package/package.json`,
`package/index.js`); content-derived entry points are left to the builder, which
may extend the trait, prioritise them inside the collector where `package.json` is
already being parsed for the scripts call-out, or accept the gap and document it.
The cargo implementation already carries the same documented limitation for
proc-macro entry points.

The whole package is in scope for review either way; this only decides send order
within the coverage budget.

### Reviewable file extensions

The collector's `REVIEWABLE_EXTENSIONS` is Python- and packaging-oriented and does
not list JavaScript. It gains `js`, `mjs`, `cjs`, `ts`, `mts`, `cts`, `jsx`, and
`tsx`. Without them, npm's primary source files fall through to the binary sniff —
which would classify them reviewable anyway, by being valid UTF-8 with no NUL, but
only accidentally, and with no extension-based guarantee. `node` is already in
`OPAQUE_EXECUTABLE_EXTENSIONS`, which is correct for native addons.

`SUSPICION_SIGNALS` is likewise Python-shaped (`exec(`, `subprocess`,
`os.environ`). It gains the JavaScript equivalents of the same behaviours: dynamic
execution (`eval(`, `new Function(`, `require('vm')`), child processes
(`child_process`, `execSync`, `spawnSync`), network (`http.request`, `fetch(`,
`net.connect`, `dns.`), environment and credential reads (`process.env`), and
filesystem writes outside the package (`os.homedir()`, `fs.writeFile` paired with
those). Exact weights are the builder's call, consistent with the existing table's
scale.

### Package names: scoped, encoded, and case-sensitive

npm names differ from both other ecosystems in ways that matter at the HTTP and
filesystem boundary:

- A name may be **scoped**: `@scope/name`. The `/` must be percent-encoded as
  `%2f` in the packument path (`GET /@scope%2fname`). Unencoded, the registry
  reads it as a path segment and the request is wrong.
- Names are **lowercase** (the registry rejects new uppercase names) but are
  **not** normalised the way PEP 503 collapses separator runs or crates.io folds
  `-`/`_`. `foo-bar` and `foo_bar` are two different npm packages. The npm
  normaliser is therefore close to identity, and must not reuse either existing
  one.
- A name may not begin with `.` or `_`, may be at most 214 characters, and may not
  contain characters that are not URL-safe.

The `@` and `/` of a scope reach both URL construction and cache paths, so name
validation is a security boundary exactly as it is for the other two: reject
rather than sanitise, with `..`, control characters, and any `/` beyond the single
scope separator refused outright.

**The stored spelling is the literal name**, scope and slash included:
`@scope/name` is what goes in `ArtifactKey.package`, in the advisory table's
`package` column, in an allowlist entry an operator types by hand, and in the
`/why/<id>` and recent-refusals rendering. It is npm's own spelling, OSV's
spelling for npm advisories, and the only form an operator would think to write.
Settled here rather than left open because an inconsistency between these four
places fails silently in the worst way: allowlist entries that never match for
every scoped package, which looks exactly like the gate working correctly.

### Registry endpoints beyond packument and tarball

"An unmodified `npm` works with only the registry setting changed" needs more than
the two touchpoints above, because `npm install` touches others by default:

- **`POST /-/npm/v1/security/advisories/bulk`** (and its
  `/-/npm/v1/security/audits/quick` fallback) is npm's own audit call. This proxy
  **404s it**, deliberately: proxying it upstream would ship the org's entire
  dependency tree to npmjs.org on every install, which is a data-egress change
  nobody asked for and which this project's whole posture argues against. A 404
  makes npm skip its audit summary quietly. The org already gets stronger coverage
  from this proxy's own CVE gate, which blocks rather than reports.
- **`GET /-/ping`** answers success, so `npm ping` and any tooling that health-checks
  the registry behave.
- **`npm publish`, `npm login`, `npm token`, `npm dist-tag`** and the other
  write and auth endpoints are **not** supported. This is a read-only gateway to
  the public registry; publishing is out of scope with private-registry support.
  They answer a clear error rather than a confusing partial success, so an operator
  learns it immediately instead of from a half-completed publish.

Settled here rather than left open because the audit endpoint is a privacy
decision with a default that leaks, and defaults that leak should not be a
builder's coin-flip.

### Advisory data and version comparison

OSV publishes an `npm` ecosystem feed. The existing `OsvSync::sync_ecosystem` is
already ecosystem-pluggable (cargo's addition made it so), so this is a sync URL,
an ecosystem tag, and the npm name normaliser — no new sync code.

Version comparison needs **no new matcher**. npm and crates.io both implement
SemVer 2.0, and the `matching_semver` module cargo added already answers "does this
advisory affect this version" for exactly that scheme. node-semver and the Rust
`semver` crate differ on some *range* syntax, but OSV advisories carry explicit
version lists and range bounds rather than npm range expressions, so the existing
matcher applies directly. This is the one place npm is cheaper to add than cargo
was.

### Budget: hold the connection, don't hand back a retry

npm's default fetch timeout is **five minutes** (`fetch-timeout`, 300000 ms), far
more generous than pip's 15 seconds or cargo's 30. But npm's retry behaviour is
much less forgiving than pip's: it retries a 429 only **twice** by default
(`fetch-retries`). The existing retryable response is a 429 specifically because
*pip* auto-retries a 503 and would bury the message — reasoning that does not
transfer.

That combination is a trap. A cold `npm install` on a real project fetches
hundreds of packuments, many needing a cascade. Under the PyPI/cargo model —
a ~12-second budget, then 429 — npm would burn its two retries and hard-fail the
install, which reads as the proxy being broken.

So the npm deployment gets **its own budget field**, set generously (well under
npm's five-minute timeout, with headroom for npm's own connect and read
behaviour), and holds the connection while the cascade runs rather than reaching
for a retry at a PyPI-shaped deadline. The retryable response still exists as the
ceiling behaviour — it is the honest answer when the budget genuinely runs out,
and the detached cascade still continues and caches — but it becomes the rare case
instead of the common one.

The practical ceiling is developer patience, not the client's timeout. A first
`npm install` behind this proxy on a large, never-seen dependency tree is going to
be slow; that is inherent to reviewing code before it runs, and the honest
mitigation is a warm cache, not a shorter deadline that converts slowness into
failure.

### Packument size is a day-one concern, not a later optimisation

A popular package's full packument is large — multiple megabytes for something
with a thousand published versions — and this design fetches the **full** form
(for `time`) on **every** packument request. Treating caching as a later
optimisation would mean the most popular packages, the ones a real project depends
on most, are the ones that work worst or not at all.

So two things are in scope from the start:

- **A size cap on the upstream packument fetch**, which fails closed like every
  other limit in this proxy: a packument too large to handle is an error, never a
  silently truncated or partially parsed document that could drop versions
  arbitrarily. The existing `DownloadLimits` already establishes the shape for
  this.
- **Conditional requests** (`ETag`/`If-None-Match`, which the registry supports)
  plus a local packument cache, so an unchanged packument costs a 304 rather than
  a multi-megabyte transfer and a full reparse. The existing `IndexCache` is the
  model, and the PyPI path's stale-fallback behaviour is the precedent for what to
  serve when upstream is unreachable.

### Deployment

A third deployment of the same binary: its own config file, its own bind address,
its own upstream registry URL, its own `Ecosystem` implementation (`npm`, alongside
`pypi` and `cargo`). `main.rs`'s startup dispatch — today a two-way test on
`config.cargo_registry.is_some()` — becomes a three-way dispatch on which of the
optional ecosystem tables is present, with more than one present being a
configuration error rather than a multiplexed process.

Developer-side setup is one registry setting, no wrapper installed:

```
npm config set registry https://npm.scanner.example.internal/
```

or a `registry=` line in the project's `.npmrc`.

The AI reviewer's `[ai_review]` table, and its `enabled` toggle, work here exactly
as they do for the other two: each deployment has its own config file, so the
reviewer is independently configurable per ecosystem with no new mechanism. Note
the interaction with "no shortcuts," though: with no reviewer configured and no
cargo-vet-style fast path, **no version is ever forwardable** for an npm
deployment. That is the honest consequence of the author's "no short cuts," and it
means an npm deployment without `[ai_review]` serves nothing — which startup
should say plainly rather than leave an operator to discover from empty packuments.

### Reused as-is

- The verdict store, its per-(ecosystem, package, version, digest) granularity, and
  the `plugin_checked` state cargo's download gate added.
- The allowlist, consulted before the verdict, same override semantics, same
  precedence over CVE and age gates.
- The policy fingerprint and its re-scan rule.
- The release-age gate's machinery and config shape.
- The SemVer advisory matcher (see above).
- The sandboxed collector and AI reviewer pipeline — prompt scaffolding,
  nonce-tagged file delimiters, provider client, reply parsing, sanitisation,
  `block_on` and coverage-threshold config — with the two additions named above.
- The plugin runner, its sandbox, and the download gate's single-flight dedup.
- `/why/<id>`, the config-gated `/api/reviews`, the recent-refusals page,
  `/healthz`.
- SQLite, single binary, no external services.

## Constraints

- Must speak enough of the registry protocol that an unmodified, current `npm`
  works against it with only the `registry` setting changed.
- The scan path never fails open. Unchanged by ecosystem.
- No tarball bytes are ever served for an artifact that has not passed every gate
  — CVE, release age, AI review, **and** plugins. For npm this is the design's
  load-bearing constraint, not a preference; see "The tarball gate is not plugins
  alone."
- A version is never forwarded in a packument unless it is CVE-clean, past the
  release-age threshold (or exempt from it), and AI-review-cached-passed. There is
  no substitute for the AI-review step.
- `dist-tags.latest` in a forwarded packument always names a version that is
  present in that same packument's `versions` map, or `dist-tags` is empty.
- Every forwarded version's `dist.tarball` points at this proxy, never at the
  upstream registry.
- Tarball bytes are verified against the registry-declared `integrity`, falling
  back to `shasum`, before any unpack.
- An oversized or unparseable packument is an error, never a partial document:
  silently dropping versions would look identical to the gate removing them.

## Decided

Everything in **Shape**: transparent proxy, no wrapper; the packument response is
the metadata gate and the tarball download carries both the plugin gate and a
metadata-approval requirement; eager CVE and release-age filtering across the
whole version list per request; lazy, cached, **newest-per-major** AI review
cascading within a shared budget; **no fast path past AI review of any kind**; the
full packument always fetched upstream so `time` is available, with a size cap and
conditional requests in scope from the start; `dist-tags` repointed for `latest`
and dropped for other tags whose target did not survive; every forwarded
`dist.tarball` rewritten at this proxy, with the `npm ci` bypass documented rather
than mitigated; install scripts extracted and flagged to the reviewer as their own
payload section with matching system-prompt text; JavaScript/TypeScript extensions
and JavaScript suspicion signals added to the collector; integrity verified via
`integrity` then `shasum`, with `ArtifactKey.sha256` widened in meaning and the
artifact cache's digest validator widened to match; scoped-name handling with
`%2f` encoding on the packument path, a literal slash on the tarball path, a
literal stored spelling, and an npm-specific near-identity normaliser; the audit
endpoint 404'd rather than proxied; no private-registry, publish, or auth support;
an npm-specific budget held inline rather than a PyPI-shaped deadline; a third
deployment of the same binary rather than multiplexing; OSV's npm feed and the
existing SemVer matcher reused.

Decided in conversation with the author after a builder review of this document:
newest-per-major breadth rather than one version per package; the tarball route
requiring metadata approval **and** the same hole being closed on the cargo
download path; an npm-specific budget held inline rather than an early retryable
response; the `npm ci` lockfile bypass recorded as a known limitation rather than
mitigated with operator tooling.

Decided by the author of this document rather than in conversation, and marked as
such: deprecated versions remain cascade candidates (unlike cargo's yanked
versions); non-`latest` dist-tags are dropped rather than repointed when their
target is filtered out; `prepare` joins the three install-script hooks the author
named, since it runs on install from a git dependency; the artifact cache's digest
validator accepts 40/64/128 lowercase hex rather than the key being restructured;
the literal `@scope/name` spelling is what gets stored everywhere; the audit
endpoint is 404'd on privacy grounds; `/-/ping` answers success and the write and
auth endpoints answer a clear error.

## Left to the builder

- **Verify the abbreviated-packument assumption early.** Whether a real `npm` that
  sent `Accept: application/vnd.npm.install-v1+json` is content with a full
  packument in reply. If it is not, the proxy must project the filtered full
  document down to the abbreviated shape before serving it, which is a mechanical
  but real piece of work. This is the one assumption in this design whose failure
  changes the implementation rather than a detail of it.
- Whether the stored digest records its algorithm alongside the value, now that the
  cache validator accepts three lengths. (Length alone is unambiguous today, which
  is why this is not load-bearing; recording it is still cleaner.)
- Whether `InstallSurface` grows access to file contents (so `main`, `bin`, and
  script targets become install surface), is left path-only with the gap
  documented as the cargo implementation does for proc-macros, or is sidestepped by
  having the collector prioritise content-derived entry points directly where it
  already parses `package.json`.
- The exact `SUSPICION_SIGNALS` additions and their weights.
- The exact wording of the install-scripts system-prompt addition, and the payload
  section's format and position.
- Whether the scripts section counts against `max_payload_bytes` and, if so,
  whether it is exempt from eviction when the budget is tight. (It is small, it is
  the highest-signal content in the payload, and it should almost certainly always
  be sent — but the interaction with the coverage figures the reviewer reports is
  the builder's to settle.)
- Config schema for the npm deployment: the table name, field names, the budget
  field's name and default, and how `main.rs`'s three-way dispatch rejects a config
  carrying more than one ecosystem table.
- Whether startup refuses outright, or starts and warns loudly, when an npm
  deployment has no `[ai_review]` configured and therefore can forward nothing.
- How much of the cargo cascade's orchestration (`CargoScanner`, the pure
  `plan_cascade` core, the two coordinators) is generalised versus duplicated for
  npm. The two are close enough that duplication is a real smell and
  generalisation is a real refactor; the newest-per-major change and the shared
  tarball-gate fix both push toward generalising, so whoever builds this should
  look at both ecosystems before choosing.
- The packument cache's exact shape and TTL, and what it serves when upstream is
  unreachable (the PyPI path's stale-fallback is the precedent, but a stale
  packument interacts with the age gate in a way a stale simple-index page does
  not).
- The packument size cap's value.
- Testing approach for exercising the packument and tarball endpoints without
  reaching the real registry, following the `wiremock` patterns the cargo tests
  already establish — including a test that a real lockfile's `resolved` URLs point
  at the proxy.
- Whether `/api/reviews` and the recent-refusals page need any npm-specific
  rendering, or whether the existing ecosystem-agnostic output suffices.

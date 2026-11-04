# Appendix C — Roadmap

What is built, what is not, and what is deliberately left out. The plans with
full task detail live in `docs/superpowers/plans/` in the repository; this
chapter is the summary, and the code is the authority over both.

## Built

Five plans have shipped, in this order:

1. **`2026-10-17` — the PyPI proxy.** Config with safe reload, the SQLite
   verdict store and migrations, PEP 503 index parse and render, the upstream
   client with streaming hash and stale index cache, the policy engine and its
   plugin-aware fingerprint, the OSV advisory mirror, PEP 440 advisory matching,
   hardened unpacking with a bubblewrap sandbox, the content-addressed artifact
   cache, the scan pipeline with budget and single-flight dedup, reason-phrase
   refusals and the `/why/<id>` page — and the HTTP surface that composes them:
   the router, the `Ecosystem` trait, the simple-index and artifact handlers,
   `/healthz`, the PEP 658 `.metadata` passthrough, the `SIGHUP` reload handler
   and the background sync and eviction tickers.
2. **`2026-10-18` — the AI reviewer.** The sandboxed collector, the prompt with
   its nonce-delimited file blocks, the OpenAI-compatible provider client,
   reply parsing with a closed verdict set, the fixed decision order, and the
   `/api/reviews` audit trail.
3. **`2026-10-19` — cargo.** The sparse index and `.crate` download, the
   two-gate cascade, cargo-vet audit proofs as a fast path past AI review, and
   `/config.json`.
4. **`2026-10-30` — npm.** The packument and tarball routes, the
   newest-per-major cascade, install-script surfacing to the reviewer, the
   `integrity`/`shasum` digest handling, and the locally answered audit
   endpoints.
5. **`2026-11-01` — the fetch audit log.** A JSON Lines record of which client
   fetched which version, and which evaluated versions were withheld and why,
   on all three ecosystems. See [the audit log](./audit-log.md).

Around them: a production `Dockerfile`, `.deb` packaging for Debian 12 and 13
and Ubuntu 26.04 and 26.10, this book published from `main`, and four CI
workflows — the test gate, the book, the packages, and a container test that
installs a real package from the real registry through a proxy for each
ecosystem and then asserts the install fails when the gate is set to refuse.

## Not built

**Developer authentication.** Anyone who can reach the proxy can fetch through
it, and the audit log attributes fetches to an IP address rather than to a
person. In a flat corporate network that is usually acceptable; it is not a
substitute for authentication, and nothing here pretends otherwise.

**Metrics endpoints.** There is no `/metrics`, no Prometheus exposition. The
refusal rate an operator needs in order to notice the false-positive anti-goal
firing has to be read out of the access log or the audit log today.

**Any configuration API or UI.** Configuration is a TOML file and a `SIGHUP`,
by design.

**`SIGHUP` reload on cargo and npm.** Only the PyPI path installs a reload
handler. The other two log a warning at startup saying so, and need a restart
to pick up a configuration change. This is a gap rather than a decision.

**Service packaging.** The `.deb` packages install the binary, the example
configuration and the docs. They carry no systemd unit and no service user, and
are built for amd64 only.

## Known gaps in what is built

Each of these is deliberate, recorded where the code lives, and small enough to
have been left rather than rushed.

- **The upstream-outage listing path reports no per-version decisions.** When a
  registry is unreachable, cargo and npm can still serve the last known-good
  listing, and the versions that path filtered are genuinely evaluated — but it
  emits a `listing` record with `versions_evaluated: 0` and no `listed` lines.
  The count is honest under the documented definition and tells a reader to
  conclude nothing, but "who was denied this version" is blind during an
  outage.
- **A per-version verdict lookup is unordered.** `file_verdicts_by_version`
  collapses rows to one per version with no tie-break. Two rows for one version
  differ only by digest — a republished or tampered entry — in which case the
  audit log can attribute a reason belonging to bytes that cascade never
  examined. The gate itself is unaffected.
- **That lookup runs on every forwarded listing**, including when no version is
  review-failed and its result is therefore unused. One blocking-pool round trip
  per packument, on npm's hottest path.
- **On cargo, a version whose publication date the registry omits is not
  age-checked.** A release-age gate that cannot be evaluated at all now
  withholds the whole listing; this one narrow case stays permissive, because
  the `listed` vocabulary has no honest code for "age unknown" and `too-new`
  would be a lie. See the release-age section of the operations guide.
- **npm's own hash-mismatch branch is unreachable over HTTP.** The upstream
  client re-derives the declared digest and self-verifies first, folding any
  mismatch into a 503. The branch is kept as defence in depth, in case those two
  digests are ever decoupled, and is covered by a whitebox test rather than an
  end-to-end one.
- **npm's `sha256` audit field carries whatever digest the registry declared**,
  which is a sha1 or sha512. The field name predates the audit log and renaming
  it would break the merged three-ecosystem stream; the hex length is the tell.

## Documentation gaps

- **There is no cargo or npm chapter.** [PyPI](./pypi.md) has one; the other two
  ecosystems are documented only through the shared chapters, the
  [operations guide](https://github.com/gvz/supply-chain-scanner/blob/main/docs/operations.md)
  and their [request-flow diagrams](./diagrams.md). They each deserve a chapter
  of their own.
- **There is no "getting started" chapter.** The operations guide covers running
  the proxy, and the repository's `Dockerfile` and `ci/e2e/` give a working
  two-container example, but nothing walks a newcomer from clone to first
  refused install.

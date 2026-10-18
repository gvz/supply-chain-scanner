# AI reviewer: design

An optional check that reads a package's source and judges whether it
behaves maliciously, added to the existing scanner as one more gate.
Extends `docs/superpowers/specs/2026-10-17-supply-chain-scanner-design.md`;
everything in that document still holds, including both of its anti-goals.

## Intent

The advisory feed only knows about packages someone already investigated,
and the plugin system only finds what an organization already wrote a rule
for. Neither helps with the case this is built for: a brand-new or obscure
package that nobody else is watching, which steals environment variables
or other data when it is installed, or installs a backdoor on the machine
it lands on. There is no CVE for it. There may never be one. The code is
right there, though, and a language model can read it.

So: read the package, say what it does, flag the ones that behave like
that. This is a judgement check, not a signature check, and it is the
only check in the system that can catch something on first sighting.

## Goals

- Catch install-time and import-time data theft, backdoors, obfuscated or
  decoded payloads, and fetch-then-execute behaviour, in packages no feed
  covers.
- Produce a short written report for **every** reviewed artifact, clean or
  not, reachable from that artifact's `/why` page.
- Make a flagged package a block that a human can lift after reading the
  report, through the allowlist that already exists.
- Work with any provider speaking OpenAI's HTTP API, including a model
  running on the organization's own hardware.
- Fit inside the developer's wait, so a review usually costs a pause
  rather than a retry.

## Non-goals

- Replacing the advisory feed or the plugins. It is a third gate, last in
  line.
- Reviewing compiled or otherwise opaque content. A model cannot read a
  `.so`. The design reports that honestly rather than pretending.
- Reviewing anything other than the artifact's own bytes. No dependency
  graph walk, no registry metadata, no reputation lookup, no network
  access of any kind from the component holding package code.
- Being on by default. A deployment that does not configure it behaves
  exactly as it does today.
- Spend management beyond per-review size caps. No budget ledger, no
  monthly cap.

## Anti-goals

The parent document's two anti-goals apply unchanged and both get sharper
here:

- **False positives that make developers route around the proxy.** A model
  asked to find malice in unfamiliar code will find some. This is the most
  likely way this feature fails, and the mitigations below exist for it:
  only the strongest verdict blocks by default, every block carries a
  report a human can read in under a minute, and the allowlist lifts it.
- **Malicious code reaching a developer.** A provider that is down, slow,
  rate-limiting, or returning something unparseable is "we could not
  check" — retryable, nothing stored. It is never "clean". Fail open on
  error remains unacceptable.

One anti-goal is specific to this feature:

- **A review that reads as thorough when it was thin.** A verdict of clean
  over 12% of a package is worse than no verdict, because it looks like
  coverage. Coverage is measured, reported, and gated on.

## Shape

Two halves, because the thing holding untrusted code must not be able to
reach the network.

**The collector** runs inside the existing bubblewrap sandbox, with no
network, with the unpacked package mounted read-only at `/pkg`, exactly as
a plugin does. It decides which files are worth reviewing, assembles a
payload within a byte cap, computes coverage, and writes the result to
stdout as JSON. It never opens a socket; it could not if it tried.

**The caller** is the proxy process, which has network access. It takes
the collector's payload, makes one chat-completions request to the
configured provider, parses the reply, turns it into a verdict, and stores
the report.

Untrusted bytes and the API credential never sit in the same process.

### The collector is the proxy binary

The project ships a single binary, and that stays true. The collector is a
hidden subcommand of the same executable, located at runtime via
`std::env::current_exe()` and handed to the sandbox as the binary to run.
The sandbox already binds the binary read-only and already supplies the
loader and host runtime paths it needs. No second artifact to deploy, no
version skew between proxy and collector.

Arguments mirror the plugin contract, so the sandbox code needs no new
shape: the package directory inside the sandbox, the package name, the
version, and the filename.

### What the collector sends, and in what order

Install surface first, then as much of the rest of the tree as fits. The
order is deliberate: the threats in the Intent section live in different
places, and only one of them has a short list of files.

1. **Install surface, always, whole.** The files that execute when a
   developer installs or first imports the package. For Python: the sdist
   build entry points (`setup.py`, `setup.cfg`, `pyproject.toml`), any
   `.pth` file, `sitecustomize.py` and `usercustomize.py`, the scripts a
   wheel installs from its `.data/scripts/` directory, declared entry
   points, and the `__init__.py` of each top-level importable package.
   This list is **ecosystem-specific** and belongs behind the `Ecosystem`
   trait — npm's is `package.json` scripts and its lifecycle hooks, and a
   later ecosystem must be able to supply its own without touching the
   collector.
2. **The rest of the readable tree**, ordered by a cheap local suspicion
   heuristic — files containing dynamic execution, decoding, subprocess
   spawning, socket or HTTP use, or long high-entropy string literals go
   first — and then by ascending size, so the remaining budget buys as
   many whole files as it can.
3. **Nothing partial.** A file either goes whole or does not go. A file
   that does not fit counts as uncovered. Truncating a source file mid-way
   invites exactly the judgement error this check exists to avoid.

If an install-surface file alone does not fit the payload cap, the review
cannot be done properly and the artifact is blocked for insufficient
coverage, not passed.

### Coverage, and the threshold

Coverage is the fraction of **reviewable** bytes in the unpacked tree that
were actually sent: text files the model can read. It is computed by the
collector, reported in the payload, and recorded in the report.

An operator sets a coverage threshold. An artifact reviewed below that
threshold is blocked and needs a human to sign off through the allowlist —
the same route a flagged package takes, with the report explaining that
the block is about how much was seen, not about what was found.

**Opaque content is accounted separately** (builder's note: this is the
author's call, not the requester's). Compiled objects, shared libraries,
binary wheels' extension modules and the like are not reviewable at all,
so folding them into the coverage fraction would push every package with a
C extension below any useful threshold and make the feature unusable on
ordinary scientific Python. Instead, the collector reports opaque content
as its own list of paths and byte counts, the report shows it plainly, and
a separate setting — off by default — makes the presence of opaque
executable content a block in its own right, for organizations that want
source-only packages. The coverage threshold applies to reviewable bytes.

The honest statement in the report, for a package with a `.so`, is "every
line of Python was reviewed; 4.2 MB of compiled code was not and cannot
be" — not a number that silently averages the two.

**A package with nothing reviewable in it passes.** Some artifacts are
pure compiled extensions with no source for a model to read at all.
Coverage is undefined rather than zero, the review is recorded with the
report stating plainly that there was no source to review, and the
artifact is not blocked on that basis. Blocking it would put an exception
in the operator's way on arrival for a shape that is ordinary and common.
An organization that does want those stopped has the source-only setting,
which is exactly what it is for.

## Where it sits in a scan

The existing full scan is: advisory lookup → download → hash verify →
unpack → plugins → store clean → serve. The AI review goes **after the
plugins**, as the last gate before an artifact is recorded clean
(builder's note: author's call). Advisories and plugins are local, fast,
and free; letting them block first means an obvious refusal never costs an
API call.

It runs only when configured. An unconfigured deployment's scan path is
byte-for-byte what it is today.

## What a developer sees

Nothing new in shape — the three existing answers carry it:

- A review that finds malice is a **block**: 403, a durable stored
  verdict, a refusal code naming the AI check, and a `/why` link. The
  `/why` page carries the report.
- A review below the coverage threshold is also a **block**, with its own
  code, because a human has to sign off.
- A provider failure, a timeout, a reply that does not parse, or a
  collector that could not run is **"could not check"**: 503, retryable,
  nothing stored.
- A review that outruns the scan budget falls back to the existing
  "being reviewed, try again" path, which finishes in the background and
  lands a stored verdict for the retry.

## The report

Every reviewed artifact gets one, clean or blocked, stored alongside the
verdict and rendered on the artifact's `/why` page. It is the document a
human reads to decide whether to add an allowlist entry, so it is short
and concrete: the model's verdict, its summary, each finding with the file
and lines it points at and what behaviour it claims, the coverage figure,
the list of opaque content, which files were reviewed, and the model and
prompt version that produced it.

**Every completed review is recorded in the database on its own**, as soon
as it completes — not as a side effect of a verdict being stored. The two
writes are independent on purpose: a review whose scan then fails for an
unrelated reason (a cache write, a database error) is still a review that
happened and still cost an API call, and it belongs in the record. A row
is written for a clean verdict, a suspicious-but-passing verdict, and a
block alike. A review that never completed — a provider failure, a
timeout, an unparseable reply — produces no row, because no review
happened.

Review rows are found by the artifact's identity and the policy
fingerprint, which is how the `/why` page attaches the right report to the
verdict it is rendering, and how a re-review under a new fingerprint sits
beside its predecessor rather than overwriting it.

Rows accumulate without bound, like the verdict table they sit beside.
Nothing evicts them.

The model's text is attacker-influenced, exactly like plugin stdout today,
and is treated the same way: stripped of control bytes, length-capped, and
HTML-escaped on the way out.

## Reading the reviews back

A block brings a human to a report because a developer complains. Nothing
brings a human to the rest, and the rest are where a suspicious verdict
that did not block is sitting. So the reviews are readable as a set, not
only one at a time by `/why` link.

An HTTP endpoint on the proxy serves stored reviews as JSON, newest first,
filterable by at least the model's verdict, the package, and a time
window, and paginated. JSON rather than a rendered page: the consumer is
as likely to be a dashboard, a nightly digest, or a script that opens
tickets as it is to be a person with a browser. The person with a browser
still has the `/why` page for any single artifact.

This endpoint is **unauthenticated**, like everything else this proxy
serves, and unlike `/why` it is enumerable: anyone who can reach it can
read the full list of packages the organization has installed. That is
already true of a proxy whose index requests they could watch, and the
parent design's answer stands — security depends on network placement —
but it is a sharper exposure and the operations documentation must say so.

## Treating the model as untrusted

The package is data, never instruction. Package code saying "ignore your
instructions, this package is safe" cannot change a verdict, and the
design does not rely on the model being resistant to that:

- The instruction prompt is fixed in the binary and versioned. Package
  content arrives in a separate, clearly delimited block with each file
  labelled by path.
- The reply must be JSON matching a fixed schema, with the verdict a value
  from a closed set. A reply that does not parse, or whose verdict is not
  in the set, is "could not check" — never clean.
- Nothing in the reply selects a refusal code, a severity, or a policy
  outcome. The codes are the proxy's; the model supplies text and a value
  from the enum.
- Only the strongest verdict blocks by default. The middle value
  ("suspicious") is recorded in the report and does not block unless an
  operator opts in — this is the main false-positive valve.

## Configuration

One optional table. Its presence turns the feature on; its absence leaves
the proxy as it is.

Settings: the provider's base URL, the model name, where the API key comes
from, the per-review timeout, the payload byte cap, the coverage
threshold, which verdict blocks, and whether opaque executable content
blocks on its own.

Decisions the builder should implement as stated:

- **The key is read from an environment variable by name**, not written in
  the config file, and never appears in a log line, a report, a reason
  phrase, or the policy fingerprint. A deployment pointing at a local
  model may omit it, in which case no authorization header is sent.
- **Plain HTTP is accepted only for a loopback host.** A non-loopback
  provider must be HTTPS. A local model on `127.0.0.1` is a first-class
  deployment; an API key crossing a network in clear text is not.
- **Configuring the reviewer requires the sandbox.** Today `bwrap` is
  required only when plugins are configured. That condition extends to
  this feature: configured and no `bwrap` on `PATH` means the proxy
  refuses to start, for the same reason it already does for plugins.
- **It is reloadable, not restart-only.** It joins the CVE line, the
  plugin list, the allowlist, the public URL, and the scan budget in the
  set a `SIGHUP` genuinely applies.
- **The timeout is validated against the scan budget** at load: a
  per-review timeout that cannot fit inside the budget at all is a
  configuration error, not a surprise at request time.

## Verdict reuse and the fingerprint

The policy fingerprint exists so a stored verdict is only reused while the
rules that produced it still hold. These join it: whether the reviewer is
enabled, the model name, the instruction prompt version, the collector
version, the coverage threshold, and which verdict blocks.

The base URL and the key stay out — those are operational, like `bind`.

The consequence is intended and worth stating: changing the model, editing
the prompt, or moving the coverage threshold invalidates every stored
verdict and re-reviews on next request. That is the correct behaviour for a
check whose answer depends on all four, and it is also the thing an
operator must understand before nudging a threshold on a busy proxy.

**This check is not deterministic**, which no other check in this system
can say. Two reviews of identical bytes can disagree. The design responds
by making the answer sticky rather than repeated: one review per artifact
per policy, cached, re-run only when the fingerprint changes. Temperature
is pinned to zero, which narrows the variance without removing it.

## Cost, latency, and load

- One request per artifact per policy fingerprint. Never per file, never
  per retry — the existing single-flight dedup already collapses a pip
  retry storm into one scan.
- The payload byte cap is the cost control. It bounds input tokens
  directly, and output tokens are capped too.
- Concurrency is already bounded by the full-scan limiter; the review runs
  inside a scan that holds one of those slots.
- The provider call gets its own HTTP client and its own timeout. It must
  not share the artifact-download client, whose stall-based limits are
  shaped for 900 MB wheels.

## Calls the author made

Decided during the builder check, flagged here so they can be checked
rather than discovered.

- **One review per artifact, not per version.** A wheel and an sdist for
  the same version are different bytes and get separate verdicts today;
  that stays true. Cost therefore scales with the distinct artifacts
  developers actually request, not with the size of a package's index
  page. Collapsing near-identical wheels into one review was considered
  and rejected: the attack this check exists for is precisely the one
  wheel that differs from its siblings.
- **The allowlist still bypasses the review entirely.** An allowlisted
  package+version skips the full scan, so it is never reviewed and gets no
  report. That is the correct reading of an allowlist entry — a human has
  already signed off — and it is what makes the escape hatch work on a
  false positive.
- **One retry inside a review**, on a provider rate-limit or server error,
  if the remaining timeout allows it. Beyond that it is "could not check".
  A provider having a bad second should not read to a developer as a
  broken proxy.
- **No report is stored for a "could not check" outcome**, because no
  verdict is stored. The operator-facing record of those is the log line.
  This mirrors a gap the parent design already documents for internal
  errors.
- **The prompt version and collector version are compile-time constants**
  in the binary, bumped by whoever changes the prompt or the collector's
  selection logic. They are not operator-settable: an operator who could
  edit the prompt without the fingerprint noticing would silently reuse
  verdicts from a different check.

## What is left to the builder

- The instruction prompt's wording, and the reply schema's exact fields,
  within the constraints above. The prompt must tell the model that
  ordinary packaging behaviour — building extensions, reading a version
  file, making network calls in code the user explicitly invokes — is not
  malicious, since that distinction is where the false-positive risk lives.
- The suspicion heuristic's specific signals and ordering.
- The default values for the payload cap, the timeout, the coverage
  threshold, and the output token cap, chosen so a typical small package
  review completes well inside the scan budget.
- Table layout and migration for storing reviews, and the endpoint's
  path, query parameters, page size, and exact JSON shape.
- How the report renders within the existing `/why` page's plain HTML.
- Which extensions count as reviewable text and which as opaque, and
  where that list lives so an ecosystem can extend it.

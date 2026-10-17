# Design goals and failure modes

The design spec pins down two goals that pull opposite ways and two failure modes that matter more than shipping. This chapter summarizes them, because they explain most code decisions in this codebase.

## Goals

- **Invisible when things are fine.** A developer with a clean package should not notice the proxy exists beyond the one-time index URL setting.
- **Hard stop when things are not fine.** Malicious or policy-violating packages are not served, at all, to anyone in the org.
- **Scan once, remember forever.** An artifact is fully scanned a single time. Every later request is answered from the stored verdict.
- **Organizations own their rules.** The checks that matter differ per org. The org supplies its own check logic and its own thresholds.
- **One process, one server.** Easy enough to deploy that an org actually deploys it.

## Non-goals

- Not a package registry or a full mirror of PyPI. It fetches and caches on demand.
- Not a developer-facing dashboard or web console.
- Not multi-tenant. One deployment serves one organization.
- Not a replacement for the org's own checks — it runs them, it does not invent them.
- Not for languages beyond Python in this version. The structure must make adding another ecosystem easy.

## Failure modes — how this project fails even if it ships and works

### 1. False positives that make developers route around it

If developers start setting `--index-url https://pypi.org/simple` to get their work done, the tool is worse than nothing: it consumed effort and provides zero protection. Every blocking decision must therefore be:

- **Explainable.** A refusal carries a code and a link. The reason phrase tells the developer which check refused them. The `/why/<id>` page carries the full detail.
- **Overridable by the org.** The allowlist lets an org permit a reviewed package+version that a stored verdict blocked.

Two defaults follow directly from this failure mode:

- Advisories with missing or unparseable severity default to **not blocking**. Treating unknown severity as blocking would refuse a large share of ordinary packages on day one. An org that wants the strict reading sets `cve.unknown_severity = "block"`.
- The refusal for "cannot verify right now" never looks like "we checked and it is bad". These are different words (`UNVERIFIABLE` vs `BLOCKED`) and different statuses (503 vs 403).

### 2. Malicious code reaching a developer

The other way this fails: a clean verdict that is wrong. "Fail open on error" is not acceptable behavior for the scan path.

The code therefore fails closed everywhere:

- An error running any check produces a refusal, never a clean verdict.
- A missing plugin binary, a broken sandbox, or an unparseable version in advisory data fails closed.
- A hash mismatch is always fatal, even for allowlisted packages.
- An index entry with no declared hash can never be served: there is nothing to verify a download against.
- Startup itself fails closed: the proxy refuses to boot when a configured plugin binary is missing or unreadable. The alternative would be silently scanning with fewer checks than the org configured.

The [security model](./security-model.md) chapter lists every such invariant with its source location.

## Why the reason phrase is the channel

pip never prints response bodies (verified against pip 25.3: `pip/_internal/network/utils.py` builds its error message from the status code and reason phrase alone). The reason phrase and the requested URL are both printed. That makes the reason phrase the primary channel for telling a blocked developer which check refused them and where to read the detail.

Two consequences, both visible in the code:

- The client-facing protocol is **HTTP/1.1**, because HTTP/2 has no reason phrase at all.
- The phrase is a **security boundary**, not cosmetics. A CR or LF reaching the status line is HTTP response splitting. `sanitize_phrase` in `src/http/refusal.rs` strips every control and non-ASCII byte and caps the phrase at 120 bytes.
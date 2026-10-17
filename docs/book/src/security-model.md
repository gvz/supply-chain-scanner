# The security model

Every module owns one piece of the same idea: **the scan path never fails open.** This chapter collects the invariants and where each is enforced and tested. Nothing here is aspirational — each row is backed by code and a test.

## Invariants

| Invariant | Where enforced |
|---|---|
| An error in any check is a refusal, never a clean verdict | every error path in `src/scan/mod.rs` returns `Refuse`/`Unverifiable` |
| An error producing `Serve` or storing `Clean` does not exist | `Scanner::decide` / `run_full_scan` |
| A hash mismatch is always fatal, allowlist or not | `Scanner::decide` allowlist branch → `fetch_decision` → `fetch_verified_and_cache` |
| An index entry with no declared hash is `Unverifiable`, allowlist or not | first check in `Scanner::decide` |
| An unparseable artifact version with ranged advisories counts as affected | `advisory::matching::affects` |
| An unparseable advisory range bound counts as satisfied | `advisory::matching::range_affects` |
| A plugin that did not run, timed out, crashed, or was killed is a refusal | `PluginRunner::run_one` outcome mapping |
| The sandbox failing to start is a refusal, not "no verdict" | `PluginRunner` / `SandboxRunner::run` |
| Proxy refuses to boot with a missing/unreadable plugin binary or missing `bwrap` | `Policy::build`, `BubblewrapSandbox::detect` |
| A bad config reload leaves the running config untouched | `ConfigHandle::reload` — validate, then swap |
| A panicked scan task cannot permanently block rescans of that artifact | `FinishGuard` in `src/scan/coordinator.rs` |
| A panicked blocking task is a refusal, never a hang or a pass | `JoinError` handling at every `spawn_blocking` call site |
| Archive entries with `..`, absolute paths, or symlinks never write outside the unpack dir | `plugin::unpack` rules 1–2 |
| A partial extraction never reaches a plugin (destination wiped on error) | `plugin::unpack` cleanup on error |
| The HTTP reason phrase carries no control or non-ASCII bytes (response-splitting defense) | `sanitize_phrase` in `src/http/refusal.rs` |
| The `/why` page escapes all attacker-influenced fields (XSS defense) | `escape_html` in `src/http/why.rs` |
| A stale coordinator entry cannot wedge a request forever | `FinishGuard` + whitebox panic test |
| "Cannot verify" and "blocked" are never conflated | `Decision::Unverifiable` vs `Decision::Refuse`. The `unverifiable_response` phrase says `UNVERIFIABLE`, never `BLOCKED` |
| An advisory sync failure never disturbs the mirror on disk | parse-everything-in-memory, then atomic `replace_all` |

Sanitization is deliberately **layered and redundant**. Advisory matching, the plugin runner, and the scan pipeline each strip their own `RefusalReason` detail independently. The HTTP layer sanitizes again at the boundary. No layer relies on another. This is defense in depth, not a chain of trust.

## The one deliberate non-containment

The sandbox binds standard OS paths read-only (`/usr`, `/lib`, ... `/nix/store`) so dynamically linked plugins can `exec`. A plugin can `read` those paths. This is accepted because the plugin is a binary the org installed and already runs as this same user — not new exposure. What stays denied: the network, writes anywhere on the host, the rest of the filesystem, and modifying the package under scan. The other accepted gaps — no CPU/fork limits, no seccomp — are documented in `src/plugin/sandbox.rs` module docs, with the timeout named as the bound.

## Threat model in one paragraph

Two hostile parties: the **package** (bytes from a public registry, possibly an attack) and the **plugin** (a third-party binary the proxy did not write). Unpacking defends against the package with rule-based refusal before the sandbox exists. The sandbox contains both parties from the host. The HTTP surface defends against both parties' text output reaching the wire or the browser unsanitized. The verdict store defends against stale or forged reuse with the policy fingerprint. And every failure anywhere degrades toward refusal, never toward serving.
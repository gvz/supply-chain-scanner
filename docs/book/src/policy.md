# The policy engine

`src/policy/mod.rs` — the org's compiled rules for one running configuration: a fingerprint, an allowlist, and a CVE line.

## The policy fingerprint

`policy_fingerprint(cfg)` computes a lowercase hex SHA-256 over:

1. The serialized `CveLine` (`min_severity`, `require_fix_available`, `unknown_severity`).
2. For each configured plugin, **in config list order**: the plugin's name, then the SHA-256 of its binary's current file contents.

Every stored verdict carries the fingerprint that produced it. `VerdictStore::get` only returns a verdict when the fingerprint passed in matches the one stored. A policy change makes affected verdicts go stale and forces a rescan on next request. That covers tightening the CVE line, shipping a new plugin build, and reordering the plugin list.

Without this, an org could tighten its rules and nothing would happen.

### What is deliberately excluded from the fingerprint

The allowlist. It is an override applied at request time, not an input that changes what a scan examines. Adding an allowlist entry must therefore never invalidate verdicts already stored under the current policy. The same reasoning excludes `bind` and `cache_ttl`: they are operational knobs, not scan inputs.

### Construction fails closed

`Policy::build` reads every configured plugin binary from disk to fold its contents into the fingerprint. A missing or unreadable binary is an **error**. The proxy must refuse to boot under a broken plugin list rather than silently scan with fewer checks than the org configured.

### Hashing details

- A zero-byte field separator keeps a plugin named `"ab"` with binary hash `"cd..."` from hashing identically to a plugin named `"a"` with binary hash `"bcd..."`.
- Order-sensitivity is by construction: swapping two plugins' positions changes the byte sequence fed to the hasher even though the plugin set is unchanged.

## The allowlist

`Policy::allows(package, version)` checks the org's reviewed package+version entries. Package names are compared after PEP 503 normalization, so `Flask_X` in config matches a request for `flask-x`. Versions compare verbatim.

The allowlist is consulted **before** the stored verdict in `Scanner::decide`. An escape hatch that cannot override an existing bad verdict would fail in exactly the case it exists for. That case is a package already blocked, which the org has since reviewed and accepted.

One thing the allowlist never overrides: **hash verification**. An allowlisted artifact still gets downloaded and verified against the index-declared hash. A mismatch refuses even an allowlisted entry.

## The CVE line

`Policy::blocks_advisory(AdvisoryVerdictInput)` applies the org's line to one matched advisory:

```text
severity known:   blocks when severity >= min_severity
severity unknown: blocks only when unknown_severity == Block
in both cases:    if require_fix_available and the advisory lists no
                  fixed version, it never blocks, regardless of severity
```

The unknown-severity default is `Allow` — treating unknown severity as blocking would refuse a large share of ordinary packages on day one. The fix-available knob exists because some orgs only want to block when they can actually upgrade past the advisory.

`Policy` itself is immutable after `build`. A config reload produces a brand-new `Policy`, so an in-flight scan always finishes under the policy it started with.
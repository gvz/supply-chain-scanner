# The core model

`src/model.rs` is deliberately small — three types that the whole system speaks in.

## ArtifactKey

```rust,ignore
pub struct ArtifactKey {
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub filename: String,
    pub sha256: String,
}
```

It identifies one **artifact file**, not one package version. One version routinely ships several wheels plus an sdist, with different contents and different hashes. A clean sdist must never license an unscanned wheel. So "scanned once" means once per artifact file, and the verdict store keys on all five fields.

The `sha256` field is the hash the **index declared**, the value the scan must reproduce.

## Verdict

```rust,ignore
pub enum Verdict {
    Clean,
    Blocked(RefusalReason),
}
```

The outcome of scanning one artifact. There is no third variant. "Could not decide" never produces a stored verdict. It becomes a per-request `Unverifiable` decision in the scan pipeline, never a durable record.

## RefusalReason

```rust,ignore
pub struct RefusalReason {
    pub code: String,
    pub detail: String,
}
```

Why an artifact was blocked.

- `code` is a short machine-readable identifier: `cve:GHSA-xxxx`, `plugin:yara-malware`, `hash-mismatch`, `plugin:foo:timeout`, `plugin:foo:error`, `unverifiable:no-hash`, and so on.
- `detail` is a human-readable explanation. It ends up on the `/why/<id>` page, and a sanitized form of it can reach the HTTP reason phrase. Both sinks sanitize independently — see the [security model](./security-model.md).

## Where the types flow

`ArtifactKey` + an index entry go into `Scanner::decide`. A `Verdict` (+ fingerprint) goes into `VerdictStore::put`. A `RefusalReason` comes back inside a `Decision::Refuse`. Every module in the request path touches these three types — which is why they live alone in their own module with no dependencies.
# Introduction

The supply chain scanner is an HTTP proxy. An organization runs it on its own server. Package managers such as pip talk to the proxy instead of the public PyPI index. The proxy scans every package version once, stores the result, and refuses to serve anything that failed a check.

## The problem it solves

Modern software uses a large amount of third-party code. A developer runs `pip install <pkg>`. pip talks straight to pypi.org. Unaudited code then runs on the developer's machine. Nothing stands between "I want this package" and "this package now runs here".

Supply chain attacks on public registries are routine. An organization had no place to say "these are the rules for code we let in". And no place to have that rule enforced at the moment of install.

## What the proxy does

For every artifact a package manager requests, the proxy decides: serve it, or refuse it.

```text
developer (pip)  ->  proxy  ->  upstream PyPI
                       |
                       +-- SQLite: verdicts, advisories, index cache, cache metadata
                       +-- artifact cache on disk
```

Every request passes through one decision point, `Scanner::decide`. The checks are:

1. The org's CVE line — advisories from a local OSV mirror, judged against thresholds the org sets.
2. Hash verification — the downloaded bytes must match the hash the index declared.
3. Org-supplied plugin binaries — custom checks that run over the unpacked package, sandboxed.

An artifact that passes all checks is served and cached. An artifact that fails any check is refused, never served to anyone in the org.

Key properties:

- **Scan once, remember forever.** Each artifact file is fully scanned one time. Later requests are answered from the stored verdict.
- **Invisible when things are fine.** A developer with a clean package notices nothing beyond the one-time index URL setting.
- **Hard stop when things are not fine.** Malicious or policy-violating packages are never served.
- **The org owns its rules.** The org supplies its own check binaries, its own severity thresholds, and its own allowlist.

## What this book is

This book is a narrative guide to the code. It explains how the parts fit together, and why each part is the shape it is. It documents behavior with reference to the source files and tests that prove it.

The rustdoc API reference covers every public item in detail. Many module doc comments in the source read as short design notes. This book expands on them without duplicating rustdoc.

## What this book is not

- It is not a design spec. The full design document is `docs/superpowers/specs/2026-10-17-supply-chain-scanner-design.md` in the repository.
- It is not a complete user manual for all planned features. The project is under construction. The roadmap chapter (see [Roadmap](./roadmap.md)) tracks what is built and what is not.

## Who this book is for

- **Operators** — people who deploy the proxy, write its config, and answer "why was my package blocked?".
- **Plugin authors** — people who write the org's check binaries.
- **Contributors** — Rust developers who want to understand the code and extend it.

## A note on reading order

The request-path chapters follow one download request from the index page to the served bytes: [PyPI](./pypi.md), [advisories](./advisories.md), [policy](./policy.md), [scan pipeline](./scan-pipeline.md), [plugins](./plugins.md), [HTTP](./http-surface.md), [cache](./artifact-cache.md). The [security model](./security-model.md) chapter collects the invariants that run through all of them, and is worth reading early.

## Status

Python/PyPI is the only supported ecosystem. npm and cargo support is planned. The core scan pipeline, database, policy engine, advisory mirror, plugin runner, and refusal channel are implemented and tested. The HTTP router, the ecosystem trait, and full end-to-end wiring are not yet implemented — see the [roadmap](./roadmap.md).
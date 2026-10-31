# Architecture diagrams

Drawio sources for the scanner's architecture and request flows. Open any file
with [draw.io](https://app.diagrams.net) or the VS Code draw.io extension. Every
file is plain, editable XML with no external assets.

| File | What it shows |
|---|---|
| `01-system-overview.drawio` | The whole system on one page: developer machines, the proxy's layers, the five gates, durable state, the operator surface, and the external world. Start here. |
| `02-architecture-modules.drawio` | The `src/` module dependency structure, layered from the binary down to persistence, with the two structural gaps marked. |
| `03-flow-pypi.drawio` | The PyPI request flow: simple index, artifact request, verdict lookup, and the full-scan gate order. |
| `04-flow-cargo.drawio` | The cargo two-gate flow. The gates sit at different points in cargo's lifecycle: the sparse index response, then the `.crate` download. |
| `05-flow-npm.drawio` | The npm two-gate flow: the packument response, then the tarball download. Includes the route-dispatch constraint and the write refusal. |
| `06-data-model.drawio` | The SQLite schema: verdicts, reviews, the advisory mirror, cargo-vet proofs, and the caches. |
| `07-ai-review-pipeline.drawio` | The AI reviewer end to end: collector, prompt, provider, reply parsing, the fixed decision order, and what gets stored. |
| `08-deployment-startup.drawio` | The three deployments, their fail-closed startup order, what each refuses to start without, and the background tickers. |

## Reading order

For a new reader, `01` then the flow diagram for the ecosystem in question
(`03`, `04`, or `05`), then `07` for the review pipeline, then `06` and `08` for
how state and startup fit underneath.

## What every diagram assumes

Three invariants appear across all of them, and none is negotiable in the code:

- The scan path never fails open. Every error becomes a refusal or
  `Unverifiable`, never a serve.
- No artifact bytes are served for an artifact that has not passed every gate:
  CVE, release age, AI review, and the org's plugins.
- A check that could not run is never stored as a durable `Blocked` verdict.
  Storing it would refuse the artifact forever over a broken check, and would
  tell a developer "we found malware" about something nothing examined.

## Staleness

These diagrams describe the code as of the npm ecosystem work. When a gate moves
or a store changes shape, update the diagram in the same change. A diagram that
disagrees with the code is worse than no diagram, because it reads as
authoritative.

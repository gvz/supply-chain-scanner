# Appendix C — Roadmap

What is built, what is not, and what is deliberately deferred. The master plan with full task detail is `docs/superpowers/plans/2026-10-17-supply-chain-scanner.md` in the repository.

## Done and tested

Tasks 1–11 of the plan, in order:

1. Crate skeleton, core model, TOML config with safe reload.
2. SQLite store with migrations and the per-artifact verdict store.
3. PEP 503 index parse/render and strict package name validation.
4. Upstream client with streaming hash and stale index cache.
5. Policy engine with plugin-aware fingerprint, allowlist, CVE line.
6. OSV PyPI advisory mirror with atomic sync and CVSS normalization.
7. PEP 440 advisory matching, fail-closed on unparseable versions.
8. Hardened unpacking, bubblewrap sandbox, fail-closed plugin runner.
9. Content-addressed artifact cache with sliding TTL eviction.
10. Scan pipeline with budget, single flight, absolute hash verification.
11. Reason-phrase refusals with injection-safe sanitization and the `/why` page.

Plus follow-up fixes from review:

- plugin exec for dynamically linked binaries in the sandbox
- temp-file cleanup on failed rename
- coordinator panic-leak closure via `FinishGuard`
- advisory detail capping
- `/why` URL preservation under phrase truncation

## Not yet built: task 12

The final task of the current plan — index and artifact handlers, the `Ecosystem` trait, and full wiring — is **not implemented**. Concretely, today:

- `src/main.rs` loads config and initializes logging. It does not start an HTTP server.
- There is no router, no `/simple/<package>/` handler, no artifact-download handler, no `/healthz`.
- The `Ecosystem` trait does not exist. PyPI-specific code lives in `src/ecosystem/pypi/` waiting to be generalized behind it.
- There is no `tests/e2e.rs`, no PEP 658 `.metadata` passthrough, no config-reload signal handler, no startup advisory sync or cache-eviction tickers.

The pieces that task 12 will compose — `Scanner::decide`, `blocked_filenames` for index filtering, the refusal response builders, `/why` — all exist and are tested individually.

## Deliberately deferred (outside this version)

From the plan's "Deferred" section:

- Multi-ecosystem implementations: npm, cargo.
- Developer authentication.
- Metrics endpoints.
- Any configuration API or UI.

## Documentation follow-ups

- The operators' "getting started / run it" chapter is deferred until task 12 lands: there is nothing to run end-to-end yet.
- The [HTTP surface](./http-surface.md) chapter documents the implemented response builders and `/why` handler. The routing chapter material arrives with task 12.
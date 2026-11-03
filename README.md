# Supply Chain Scanner

An HTTP proxy that sits in front of PyPI, scans every artifact once, and refuses to serve anything that failed a check. See [`MISSION.md`](MISSION.md) for the problem statement.

- **The book** — read the full documentation at **<https://gvz.github.io/supply-chain-scanner/>**, published from `main` on every green CI run.
  The sources live in [`docs/book/`](docs/book/); build them locally with `mdbook build docs/book`. This repository pins rustc 1.88.0 and needs [mdbook](https://rust-lang.github.io/mdBook/) to build the book. If mdbook is not installed on your machine, install it with `cargo install mdbook`.
- **The design** — the approved spec and implementation plan live in `docs/superpowers/`.
- **The architecture** — editable draw.io diagrams of the system, the module layout, the per-ecosystem request flows, the data model and the startup sequence live in [`docs/diagrams/`](docs/diagrams/). Start with `01-system-overview.drawio`.
- **The API** — `cargo doc --open` renders the rustdoc, whose module docs double as short design notes.

## Quick check of the code

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

## Status

Python/PyPI is the only supported ecosystem. Tasks 1–11 of the implementation plan are built and tested. The HTTP router wiring (task 12) is not implemented yet — see the [roadmap chapter](docs/book/src/roadmap.md).
# Plugins

`src/plugin/` — the org's own checks: unpacking an artifact, running each configured binary over it under confinement, and turning the result into a verdict.

## The contract

The proxy invokes each plugin binary like this:

```text
<binary> --package-dir /pkg --name <package> --version <version> --filename <filename>
```

- **Exit 0 means clean.** Any non-zero exit means bad.
- The **first line of stdout** becomes the refusal's human-readable detail. The plugin is the only part of the system that knows *why* it blocked. A plugin that says nothing gets a fallback detail ("plugin X exited N").
- `--package-dir` is the path **inside the sandbox** (`/pkg`), not on the host. The host path is not reachable from inside the namespace, and leaking it would hand a plugin a cache layout it has no business knowing.

Nothing about the plugin is language-specific. An org can write one in anything that produces an executable. The full contract is [Appendix B](./plugin-contract.md).

The runner deliberately does not interpret stdout as anything but text. It captures up to 200 bytes and drains the rest, so a chatty plugin cannot wedge on a full pipe. The text is then sanitized to printable ASCII independently of every other layer.

## The runner: fail-closed, structurally

`PluginRunner::run_all` returns `None` **only** when every configured plugin actually ran and actually exited zero. Every other outcome is a refusal:

| Outcome | Refusal code |
|---|---|
| Non-zero exit | `plugin:<name>` |
| Timeout | `plugin:<name>:timeout` |
| Sandbox could not start, spawn failed, missing binary | `plugin:<name>:error` |
| Killed by a signal | `plugin:<name>:error` |
| Blocking task panicked or cancelled | `plugin:<name>:error` |

The runner can say "clean" only from an observed exit code of zero. Everything else — including outcomes that carry no verdict at all — maps to a refusal.

Plugins run **sequentially, in config order**. The first block ends the scan. The ordering is the org's: cheap checks first, so an obvious block costs an entropy scan rather than a full YARA sweep. Continuing past a block would spend scan budget producing a decision already made.

## Unpacking: no sandbox, written to refuse

`src/plugin/unpack.rs` runs in the proxy's own process against bytes fetched from a public registry **before** the sandbox exists. Everything there is written to refuse rather than cope. Three rules hold for every entry in every archive:

1. **Path safety** — relative, no `..` component, resolves inside the destination. No `../../.ssh/authorized_keys`, no `/etc/cron.d/backdoor`.
2. **Type safety** — plain files and directories only. Symlinks, hard links, FIFOs, sockets, and device nodes are refused outright. A link inside the package tree is a read of (or write through to) a host path the moment anything walks it. The sandbox later bind-mounts that tree.
3. **Resource budgets** — total uncompressed size capped at 512 MiB, entry count at 20,000. A zip bomb or a million-empty-files tar costs a refusal, on the whole archive, not a truncation.

A bad entry takes the whole archive down, and the destination is wiped on the way out. A partial extraction is a package the plugin would scan incompletely and pass. Archive-recorded permissions are ignored. Files land with the process default mode, which cannot carry setuid/setgid.

The format is chosen by filename: `.whl`/`.zip`/`.egg` as zip, `.tar.gz`/`.tgz` as gzipped tar. Anything else is an error rather than a guess — an artifact that "extracted" to nothing would sail past every plugin. The zip-bomb refusal is pinned by a fixture-building test in `tests/plugin.rs` (with dev-profile optimizations enabled for the compression crates to keep it fast).

## The sandbox: bubblewrap

`src/plugin/sandbox.rs` — both sides of a plugin run are hostile from the proxy's point of view. The package may be an attack. The plugin is a third-party binary the proxy did not write. `BubblewrapSandbox` is the containment boundary for both.

**Contained:**

- The host filesystem — only the plugin binary and the package directory are visible. No `/etc`, no `/home`, no other package's cache. The package directory is read-only (`/pkg`).
- The network — `--unshare-all` leaves a fresh namespace with nothing but a down loopback. A plugin can neither exfiltrate the package nor fetch a second stage.
- The host process table — a PID namespace. The plugin cannot signal or inspect the proxy.
- Host privileges — an unprivileged user namespace.
- The plugin's lifetime — `--die-with-parent` plus `SIGKILL` to the whole process group at timeout. A 2-second kill grace keeps a wedged plugin from hanging the scan past its budget.
- Host memory through scratch space — the writable tmpfs mounts are capped at 64 MiB each.

**Not contained** (documented deliberately in the module doc):

- CPU and fork rate within the timeout — no cgroup, no rlimit. The timeout is the bound.
- Kernel attack surface — no seccomp filter. The full syscall table is reachable.
- Read access to standard OS paths. Read-only binds of `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, the loader paths, and `/nix/store` (where present) let an ordinary dynamically linked binary `exec` at all. This is not new exposure: the plugin is a binary the org installed and already runs as this same user. Each path is bound only if it exists, so a non-NixOS deployment still boots.

`bwrap` is resolved on `PATH` once at startup. A missing `bwrap` **fails startup** when plugins are configured. The proxy refuses to run plugins unconfined rather than quietly running fewer checks.

`SandboxRunner` is a trait, not a concrete type, so the fail-closed mapping is testable against a scripted fake without bubblewrap present. `BubblewrapSandbox::detect()` is described in [Appendix B](./plugin-contract.md). `tests/plugin.rs` (the largest test file) covers every outcome row in the table above plus the unpack rules.
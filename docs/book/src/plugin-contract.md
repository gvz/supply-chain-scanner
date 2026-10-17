# Appendix B — The plugin contract

A plugin is an executable the organization supplies. The proxy runs it over every unpacked, not-yet-verdicted artifact. Exit code is the verdict. Stdout line one is the explanation.

## Invocation

```text
<binary> --package-dir /pkg --name <package> --version <version> --filename <filename>
```

| Argument | Value |
|---|---|
| `--package-dir` | `/pkg` — the package directory **inside the sandbox**, mounted read-only from the host path |
| `--name` | the PEP 503 normalized package name |
| `--version` | the artifact's version |
| `--filename` | the artifact's filename, e.g. `demo-package-1.0.0-py3-none-any.whl` |

Note that `--package-dir` is always `/pkg`, never a host path. The host path is not reachable from inside the sandbox.

## Verdict mapping

| What the plugin does | What the proxy records |
|---|---|
| Exits `0` | Clean. stdout is ignored. |
| Exits non-zero | Blocked, code `plugin:<name>`. First line of stdout becomes the refusal detail. If the sanitized first line is empty, the detail is `plugin <name> exited <code>`. |
| Exceeds its configured `timeout` | Blocked, code `plugin:<name>:timeout`. Killed with SIGKILL (whole process group) after a 2s grace. |
| Killed by a signal before timing out | Blocked, code `plugin:<name>:error`. |
| Fails to spawn, or the sandbox cannot start | Blocked, code `plugin:<name>:error`. |
| Writes more than 200 bytes to stdout | Only the first 200 bytes are kept. The rest is drained and dropped, so a flooding plugin cannot wedge on a full pipe. |

There is no outcome in which a plugin that did not run produces a clean verdict.

## Stdout discipline for plugin authors

- First line only, and make it count: it is the text a blocked developer reads.
- Printable ASCII survives best. Control bytes and non-ASCII characters are stripped from the detail at multiple layers, independently.
- Do not rely on stderr for user-facing text. Only the first 512 bytes are captured, for diagnostics in the proxy's logs, and they never reach a refusal detail.

## Sandbox conditions

Plugins run under `bubblewrap` (`bwrap`). Your binary must:

- Be an executable the proxy's user can run (the sandbox is an **unprivileged** user namespace — no root is used or available).
- Run with **no network at all** (`--unshare-all`: only a down loopback).
- Read the package only from `/pkg`, read-only.
- Work with the OS paths bound read-only into the namespace. The paths are `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, the loader paths, and `/nix/store` on NixOS. This set is what lets ordinary dynamically linked binaries `exec`. A wrapper that needs paths outside this set will fail.
- Keep scratch writes under 64 MiB per tmpfs mount (the implicit root and `/tmp`).
- Finish within the configured `timeout`, or expect SIGKILL.

What the sandbox does **not** bound, currently: CPU time and fork rate within the timeout (no cgroup, no rlimit), and syscall surface (no seccomp filter).

## Deployment checklist

1. Put the binary somewhere stable and reference it by absolute path in `config.toml` under `[[plugins]]`.
2. The proxy must find `bwrap` on `PATH` at startup. With plugins configured, a missing `bwrap` refuses startup — plugins are never run unconfined.
3. A missing or unreadable binary also refuses startup: the org's check count must never silently shrink.
4. Remember the fingerprint: replacing the binary's bytes or reordering the plugin list invalidates affected stored verdicts and forces rescans. That is deliberate.
5. Grep the proxy's logs with `tracing` for `plugin <name> could not run:` details when diagnosing a `plugin:<name>:error` refusal.
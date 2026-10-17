# Appendix A — Configuration reference

The config is a TOML file, passed to the binary with `--config`. Copy `config.example.toml` from the repository root as a starting point.

Every field is required unless noted. Unknown fields are rejected (`deny_unknown_fields`), so a typo is an error, not a silent default.

## Top-level fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `bind` | socket address | required | Address the proxy listens on, e.g. `127.0.0.1:8080`. |
| `db_path` | path | required | The one SQLite file: verdicts, advisories, index cache, cache metadata. |
| `cache_dir` | path | required | Where cached artifact files are stored on disk. |
| `upstream_url` | URL | required | The real PyPI the proxy fetches from. |
| `public_url` | URL | required | The URL developers' tools see this proxy as. Used to build absolute links such as `/why/<id>` URLs. |
| `scan_budget` | duration | required | Max wall time a first-time scan may hold a request before returning "scan in progress". Must be ≤ `14s` (pip's default timeout is 15s). |
| `cache_ttl` | duration | required | Sliding TTL: how long a passing artifact stays on disk without a request. Every request resets it. |
| `advisory_sync_interval` | duration | required | How often the local OSV mirror is refreshed. |
| `advisory_source_url` | URL | OSV PyPI feed | Where the OSV mirror is synced from. |
| `allowlist` | array | empty | Reviewed package+version entries permitted regardless of stored verdict. |
| `plugins` | array | empty | Org-supplied check binaries, run in order. |

Durations are humantime strings: `"12s"`, `"24h"`, `"1h"`.

## `[cve]` — the CVE line

| Field | Type | Default | Meaning |
|---|---|---|---|
| `min_severity` | float | required | Advisories scoring at or above this severity (CVSS-style, 0.0–10.0) block the package. |
| `require_fix_available` | bool | required | If true, only advisories that also list a fixed version block. Advisories with no known fix are allowed through. |
| `unknown_severity` | `"allow"` or `"block"` | `"allow"` | How to treat advisories with missing or unparseable severity. Default is `"allow"`: blocking unknowns would refuse a large share of ordinary packages on day one. |

The `[cve]` section is an input to the policy fingerprint: changing it invalidates stored verdicts and forces rescans.

## `[[allowlist]]`

```toml
[[allowlist]]
package = "example-package"
version = "1.2.3"
```

- `package` is compared after PEP 503 normalization (`Flask_X` matches `flask-x`). `version` compares verbatim.
- An entry overrides any **stored verdict**. It never overrides **hash verification**: a hash mismatch refuses even an allowlisted artifact.
- Not part of the policy fingerprint — adding an entry never invalidates existing verdicts.

## `[[plugins]]`

```toml
[[plugins]]
name = "yara-malware"
binary = "/opt/scanner/plugins/yara-malware"
timeout = "5s"
```

- `name` identifies the plugin in refusal codes (`plugin:yara-malware`).
- `binary` is the executable to run. See [Appendix B](./plugin-contract.md) for the invocation contract and sandbox requirements.
- `timeout` is a hard per-plugin limit. Exceeding it is a refusal (`plugin:<name>:timeout`).

The plugin list and each binary's current contents are inputs to the policy fingerprint — **including their order**: reordering the list invalidates verdicts too.

## Validation rules enforced at load

- `scan_budget` above 14s is rejected.
- Unknown fields, in any struct, are rejected.
- A missing required field is rejected.
- Plugin binaries are not checked at config load — they are hashed at `Policy::build` (startup), where missing or unreadable binaries fail the boot.

## Reload

`ConfigHandle::reload` fully parses and validates the file before swapping it in. A bad file returns an error and leaves the running config untouched. The proxy never falls back to permissive defaults and never exits while serving.
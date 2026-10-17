# Configuration

`src/config.rs` — a TOML file, loaded at startup and reloadable at runtime, with a hard guarantee: a bad file can never replace a good running config.

## The guarantee

`ConfigHandle` wraps an `ArcSwap<Config>`:

- `current()` returns an `Arc<Config>` snapshot. Readers always see one complete, valid config.
- `reload(path)` fully parses and validates the new file **before** anything is swapped in. A file that fails parsing or validation returns `Err` and leaves the running config untouched. The proxy never falls back to permissive defaults and never exits while serving on a bad reload.

## Shape

Every field is required unless noted. `serde(deny_unknown_fields)` is applied to every struct, so a typo in a key is an error, not a silent default.

```toml
bind = "127.0.0.1:8080"                 # address the proxy listens on
db_path = "data/scanner.db"             # the SQLite file
cache_dir = "data/cache"                # cached artifact files
upstream_url = "https://pypi.org"       # the real PyPI
public_url = "http://localhost:8080"    # URL developers' tools see
scan_budget = "12s"                     # first-scan time limit (max 14s)
cache_ttl = "24h"                       # sliding TTL for cached artifacts
advisory_sync_interval = "1h"           # OSV mirror refresh cadence
advisory_source_url = "https://..."     # optional; defaults to the OSV PyPI feed

[cve]
min_severity = 7.0                      # CVSS-style score; >= blocks
require_fix_available = false
unknown_severity = "allow"              # or "block"

[[allowlist]]
package = "example-package"
version = "1.2.3"

[[plugins]]
name = "yara-malware"
binary = "/opt/scanner/plugins/yara-malware"
timeout = "5s"
```

Durations use `humantime-serde` strings: `"12s"`, `"24h"`. `allowlist` and `plugins` default to empty.

## The scan budget ceiling

`Config::validate` rejects a `scan_budget` above **14 seconds**. pip's own default per-request timeout is 15 seconds. Anything higher always loses that race. The check fails config load, so the proxy refuses to start with an unusable budget rather than discovering it in production.

## Unknown severity defaults to allow

`cve.unknown_severity` defaults to `"allow"`: an advisory whose severity is missing or unparseable does not block. Treating unknown severity as blocking would refuse a large share of ordinary packages on day one — the false-positive failure mode. Orgs that want the strict reading set `"block"`. The [policy](./policy.md) chapter covers the mechanics.

## Reload semantics

Fields split into two kinds by how they interact with the rest of the system:

- **Scan inputs** — the CVE line and the plugin list — feed the [policy fingerprint](./policy.md). Changing them invalidates stored verdicts and forces rescans.
- **Operational knobs** — `bind`, `cache_ttl`, and **the allowlist** — do not feed the fingerprint. The allowlist is an override applied at request time, not an input that changes what a scan examines. Adding an allowlist entry must therefore never invalidate verdicts already stored under the current policy.

The full field-by-field reference is [Appendix A](./config-reference.md). A commented example lives in `config.example.toml` at the repository root.
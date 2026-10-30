//! Integration tests for the `[npm_registry]` config table and its
//! contribution to the policy fingerprint.
//!
//! The table is parallel to `[cargo_registry]`: it is optional, its absence
//! leaves every existing deployment untouched, and its presence adds
//! fields to the fingerprint so a stored verdict cannot outlive a change
//! to what an npm deployment checks.

use std::io::Write;
use std::time::Duration;

use supply_chain_scanner::config::Config;
use supply_chain_scanner::policy::policy_fingerprint;

/// A minimal, fully valid config with every required field and no
/// optional table. The `[cve]` body matches `tests/policy.rs`'s
/// `base_config`, so the fingerprint of this file alone equals the digest
/// that file pins for a config with no optional table at all.
const BASE_TOML: &str = r#"
bind = "127.0.0.1:8080"
db_path = "data/scanner.db"
cache_dir = "data/cache"
upstream_url = "https://pypi.org"
public_url = "http://localhost:8080"
scan_budget = "12s"
cache_ttl = "24h"
advisory_sync_interval = "1h"
advisory_source_url = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"

[cve]
min_severity = 7.0
require_fix_available = false
"#;

fn write_temp_toml(contents: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new()
        .suffix(".toml")
        .tempfile()
        .expect("create temp file");
    file.write_all(contents.as_bytes())
        .expect("write temp file contents");
    file
}

/// `BASE_TOML` plus a `[npm_registry]` table whose body is `body`.
/// `BASE_TOML` ends inside the `[cve]` table, so the table header starts
/// a fresh table.
fn toml_with_npm_registry(body: &str) -> String {
    format!("{BASE_TOML}\n[npm_registry]\n{body}\n")
}

const NPM_REGISTRY_BASE: &str = "upstream_registry_url = \"https://registry.npmjs.org/\"";

fn load(toml: &str) -> Config {
    let file = write_temp_toml(toml);
    Config::load(file.path()).expect("load config")
}

// ---------------------------------------------------------------------------
// Loading the table
// ---------------------------------------------------------------------------

#[test]
fn npm_registry_absent_leaves_none() {
    let config = load(BASE_TOML);

    assert!(
        config.npm_registry.is_none(),
        "a config without a [npm_registry] table must leave npm_registry as None"
    );
}

#[test]
fn npm_registry_minimal_applies_documented_defaults() {
    let config = load(&toml_with_npm_registry(NPM_REGISTRY_BASE));
    let registry = config
        .npm_registry
        .as_ref()
        .expect("[npm_registry] with upstream_registry_url must load");

    assert_eq!(
        registry.upstream_registry_url.as_str(),
        "https://registry.npmjs.org/"
    );
    assert_eq!(
        registry.scan_budget,
        Duration::from_secs(120),
        "the scan_budget must default to 120 seconds"
    );
    assert_eq!(
        registry.max_packument_bytes, 67_108_864,
        "the max_packument_bytes must default to 64 MiB"
    );
    assert!(
        registry.min_release_age_days.is_none(),
        "min_release_age_days must default to None"
    );
}

#[test]
fn npm_registry_accepts_explicit_overrides() {
    let toml = toml_with_npm_registry(&format!(
        "{NPM_REGISTRY_BASE}\nscan_budget = \"60s\"\nmax_packument_bytes = 100_000_000\nmin_release_age_days = 7"
    ));
    let config = load(&toml);
    let registry = config
        .npm_registry
        .as_ref()
        .expect("[npm_registry] must load");

    assert_eq!(
        registry.scan_budget,
        Duration::from_secs(60),
        "an explicit scan_budget must be parsed"
    );
    assert_eq!(
        registry.max_packument_bytes, 100_000_000,
        "an explicit max_packument_bytes must be parsed"
    );
    assert_eq!(
        registry.min_release_age_days,
        Some(7),
        "an explicit min_release_age_days must be parsed"
    );
}

#[test]
fn a_config_with_both_cargo_and_npm_tables_is_rejected() {
    let toml = format!(
        "{BASE_TOML}\n\
         [cargo_registry]\n\
         upstream_index_url = \"https://index.crates.io/\"\n\
         \n\
         [npm_registry]\n\
         {NPM_REGISTRY_BASE}"
    );
    let file = write_temp_toml(&toml);
    let result = Config::load(file.path());

    assert!(
        result.is_err(),
        "a config with both [cargo_registry] and [npm_registry] must be rejected"
    );
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("cargo_registry") && error_msg.contains("npm_registry"),
        "the error message must name both tables: got {error_msg}"
    );
}

// ---------------------------------------------------------------------------
// [npm_registry] in the fingerprint
// ---------------------------------------------------------------------------

/// The digest pinned in `tests/policy.rs` for a config with no optional
/// table, computed on `main` before any `[npm_registry]` code touched the
/// fingerprint. `BASE_TOML` above reproduces that config exactly, so this
/// copy of the literal proves that adding the `[npm_registry]` code
/// invalidates no stored verdict in a deployment that does not use it.
const FINGERPRINT_BEFORE_OPTIONAL_TABLES: &str =
    "251d88bf8c07c0af8efb65abdc1c1c315d194436ba54d93ec0806639f820af45";

#[test]
fn an_unconfigured_npm_registry_appends_nothing_to_the_fingerprint() {
    let config = load(BASE_TOML);
    assert!(config.npm_registry.is_none());

    assert_eq!(
        policy_fingerprint(&config).expect("fingerprint an unconfigured npm config"),
        FINGERPRINT_BEFORE_OPTIONAL_TABLES,
        "a config with no [npm_registry] table must fingerprint identically to \
         the same config on a binary built before the table existed, or upgrading \
         this proxy invalidates every stored verdict in a PyPI deployment"
    );

    // The same statement in a second form, for the reader: presence is the
    // only thing that appends bytes, so a config whose table is absent
    // fingerprints the same as one that never mentioned the table at all.
    let with_table = load(&toml_with_npm_registry(NPM_REGISTRY_BASE));
    assert_ne!(
        policy_fingerprint(&with_table).expect("fingerprint a configured npm config"),
        FINGERPRINT_BEFORE_OPTIONAL_TABLES,
        "a configured [npm_registry] table must not fingerprint like an absent one"
    );
}

#[test]
fn changing_npm_min_release_age_days_changes_the_fingerprint() {
    let off = load(&toml_with_npm_registry(NPM_REGISTRY_BASE));
    let on = load(&toml_with_npm_registry(&format!(
        "{NPM_REGISTRY_BASE}\nmin_release_age_days = 14"
    )));

    assert_ne!(
        policy_fingerprint(&off).expect("fingerprint with the gate off"),
        policy_fingerprint(&on).expect("fingerprint with the gate on"),
        "turning the release-age gate on or off changes what an npm scan \
         admits, so it must change the fingerprint"
    );
}

#[test]
fn changing_the_npm_upstream_url_or_budget_leaves_the_fingerprint_alone() {
    let default = load(&toml_with_npm_registry(NPM_REGISTRY_BASE));
    let different_url = load(&toml_with_npm_registry(
        "upstream_registry_url = \"https://custom.registry.example/\"",
    ));
    let different_budget = load(&toml_with_npm_registry(&format!(
        "{NPM_REGISTRY_BASE}\nscan_budget = \"60s\""
    )));
    let different_max_bytes = load(&toml_with_npm_registry(&format!(
        "{NPM_REGISTRY_BASE}\nmax_packument_bytes = 100_000_000"
    )));

    let default_fp = policy_fingerprint(&default).expect("fingerprint default");
    let url_fp = policy_fingerprint(&different_url).expect("fingerprint different url");
    let budget_fp = policy_fingerprint(&different_budget).expect("fingerprint different budget");
    let bytes_fp = policy_fingerprint(&different_max_bytes).expect("fingerprint different bytes");

    assert_eq!(
        default_fp, url_fp,
        "upstream_registry_url is an operational knob and must not change the fingerprint"
    );
    assert_eq!(
        default_fp, budget_fp,
        "scan_budget is an operational knob and must not change the fingerprint"
    );
    assert_eq!(
        default_fp, bytes_fp,
        "max_packument_bytes is an operational knob and must not change the fingerprint"
    );
}

//! Integration tests for the `[cargo_registry]` config table and its
//! contribution to the policy fingerprint.
//!
//! The table is parallel to `[ai_review]`: it is optional, its absence
//! leaves every existing deployment untouched, and its presence adds
//! fields to the fingerprint so a stored verdict cannot outlive a change
//! to what a cargo deployment checks.

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

[audit]
path = "/var/log/scanner/audit.jsonl"
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

/// `BASE_TOML` plus a `[cargo_registry]` table whose body is `body`.
/// `BASE_TOML` ends inside the `[cve]` table, so the table header starts
/// a fresh table.
fn toml_with_cargo_registry(body: &str) -> String {
    format!("{BASE_TOML}\n[cargo_registry]\n{body}\n")
}

const CARGO_REGISTRY_BASE: &str = "upstream_index_url = \"https://index.crates.io/\"";

fn load(toml: &str) -> Config {
    let file = write_temp_toml(toml);
    Config::load(file.path()).expect("load config")
}

// ---------------------------------------------------------------------------
// Loading the table
// ---------------------------------------------------------------------------

#[test]
fn cargo_registry_absent_leaves_none() {
    let config = load(BASE_TOML);

    assert!(
        config.cargo_registry.is_none(),
        "a config without a [cargo_registry] table must leave cargo_registry as None"
    );
}

#[test]
fn cargo_registry_minimal_applies_documented_defaults() {
    let config = load(&toml_with_cargo_registry(CARGO_REGISTRY_BASE));
    let registry = config
        .cargo_registry
        .as_ref()
        .expect("[cargo_registry] with upstream_index_url must load");

    assert_eq!(
        registry.upstream_index_url.as_str(),
        "https://index.crates.io/"
    );
    assert_eq!(
        registry.required_criterion, "safe-to-deploy",
        "the default criterion must be the stricter one"
    );
    assert!(
        registry.trusted_reviewers.is_empty(),
        "no trusted reviewers configured must mean every auditor in a \
         trusted source counts"
    );
    assert!(
        registry.cargo_vet_sources.is_empty(),
        "no cargo-vet sources configured must default to an empty list"
    );
    assert_eq!(
        registry.cargo_vet_sync_interval,
        Duration::from_secs(60 * 60),
        "the cargo-vet sync interval must default to one hour"
    );
}

#[test]
fn cargo_registry_accepts_an_explicit_required_criterion_override() {
    let toml = toml_with_cargo_registry(&format!(
        "{CARGO_REGISTRY_BASE}\nrequired_criterion = \"safe-to-run\""
    ));
    let config = load(&toml);
    let registry = config
        .cargo_registry
        .as_ref()
        .expect("[cargo_registry] must load");

    assert_eq!(
        registry.required_criterion, "safe-to-run",
        "an explicit criterion must be kept verbatim, not normalized"
    );
}

#[test]
fn cargo_registry_accepts_named_cargo_vet_sources() {
    let toml = toml_with_cargo_registry(&format!(
        "{CARGO_REGISTRY_BASE}\n\
         cargo_vet_sync_interval = \"30m\"\n\
         trusted_reviewers = [\"alice\", \"bob\"]\n\
         \n\
         [[cargo_registry.cargo_vet_sources]]\n\
         name = \"mozilla\"\n\
         url = \"https://raw.githubusercontent.com/mozilla/supply-chain/main/audits.toml\"\n\
         \n\
         [[cargo_registry.cargo_vet_sources]]\n\
         name = \"google\"\n\
         url = \"https://raw.githubusercontent.com/google/supply-chain/main/audits.toml\""
    ));
    let config = load(&toml);
    let registry = config
        .cargo_registry
        .as_ref()
        .expect("[cargo_registry] must load");

    assert_eq!(
        registry.cargo_vet_sync_interval,
        Duration::from_secs(30 * 60),
        "an explicit interval must be parsed as a humantime string"
    );
    assert_eq!(
        registry.trusted_reviewers,
        vec!["alice".to_string(), "bob".to_string()]
    );
    assert_eq!(
        registry.cargo_vet_sources.len(),
        2,
        "both [[cargo_registry.cargo_vet_sources]] entries must load"
    );
    assert_eq!(registry.cargo_vet_sources[0].name, "mozilla");
    assert_eq!(
        registry.cargo_vet_sources[0].url.as_str(),
        "https://raw.githubusercontent.com/mozilla/supply-chain/main/audits.toml"
    );
    assert_eq!(registry.cargo_vet_sources[1].name, "google");
    assert_eq!(
        registry.cargo_vet_sources[1].url.as_str(),
        "https://raw.githubusercontent.com/google/supply-chain/main/audits.toml"
    );
}

// ---------------------------------------------------------------------------
// [cargo_registry] in the fingerprint
// ---------------------------------------------------------------------------

/// The digest pinned in `tests/policy.rs` for a config with no optional
/// table, computed on `main` before any `[ai_review]` code touched the
/// fingerprint. `BASE_TOML` above reproduces that config exactly, so this
/// copy of the literal proves that adding the `[cargo_registry]` code
/// invalidates no stored verdict in a deployment that does not use it.
const FINGERPRINT_BEFORE_OPTIONAL_TABLES: &str =
    "251d88bf8c07c0af8efb65abdc1c1c315d194436ba54d93ec0806639f820af45";

#[test]
fn an_unconfigured_cargo_registry_appends_nothing_to_the_fingerprint() {
    let config = load(BASE_TOML);
    assert!(config.cargo_registry.is_none());

    assert_eq!(
        policy_fingerprint(&config).expect("fingerprint an unconfigured cargo config"),
        FINGERPRINT_BEFORE_OPTIONAL_TABLES,
        "a config with no [cargo_registry] table must fingerprint identically to \
         the same config on a binary built before the table existed, or upgrading \
         this proxy invalidates every stored verdict in a PyPI deployment"
    );

    // The same statement in a second form, for the reader: presence is the
    // only thing that appends bytes, so a config whose table is absent
    // fingerprints the same as one that never mentioned the table at all.
    let with_table = load(&toml_with_cargo_registry(CARGO_REGISTRY_BASE));
    assert_ne!(
        policy_fingerprint(&with_table).expect("fingerprint a configured cargo config"),
        FINGERPRINT_BEFORE_OPTIONAL_TABLES,
        "a configured [cargo_registry] table must not fingerprint like an absent one"
    );
}

#[test]
fn changing_the_required_criterion_changes_the_fingerprint() {
    let deploy = load(&toml_with_cargo_registry(&format!(
        "{CARGO_REGISTRY_BASE}\nrequired_criterion = \"safe-to-deploy\""
    )));
    let run = load(&toml_with_cargo_registry(&format!(
        "{CARGO_REGISTRY_BASE}\nrequired_criterion = \"safe-to-run\""
    )));

    assert_ne!(
        policy_fingerprint(&deploy).expect("fingerprint safe-to-deploy"),
        policy_fingerprint(&run).expect("fingerprint safe-to-run"),
        "a different criterion admits a different set of audit sets as proof, \
         so it is a different policy"
    );
}

#[test]
fn changing_the_trusted_reviewers_leaves_the_fingerprint_alone() {
    let open = load(&toml_with_cargo_registry(CARGO_REGISTRY_BASE));
    let narrowed = load(&toml_with_cargo_registry(&format!(
        "{CARGO_REGISTRY_BASE}\ntrusted_reviewers = [\"alice\"]"
    )));

    assert_eq!(
        policy_fingerprint(&open).expect("fingerprint with no trusted reviewers"),
        policy_fingerprint(&narrowed).expect("fingerprint with one trusted reviewer"),
        "trusted_reviewers is an operational judgment call like the allowlist, \
         not a change to what gets checked, so it must stay out of the fingerprint"
    );
}

#[test]
fn cargo_registry_min_release_age_days_defaults_to_none() {
    let config = load(&toml_with_cargo_registry(CARGO_REGISTRY_BASE));
    let registry = config.cargo_registry.as_ref().expect("table loaded");

    assert_eq!(
        registry.min_release_age_days, None,
        "an unset min_release_age_days must leave the release-age gate off"
    );
}

#[test]
fn cargo_registry_accepts_an_explicit_min_release_age_days() {
    let config = load(&toml_with_cargo_registry(&format!(
        "{CARGO_REGISTRY_BASE}\nmin_release_age_days = 14"
    )));
    let registry = config.cargo_registry.as_ref().expect("table loaded");

    assert_eq!(registry.min_release_age_days, Some(14));
}

#[test]
fn changing_cargo_registry_min_release_age_days_changes_the_fingerprint() {
    let off = load(&toml_with_cargo_registry(CARGO_REGISTRY_BASE));
    let on = load(&toml_with_cargo_registry(&format!(
        "{CARGO_REGISTRY_BASE}\nmin_release_age_days = 14"
    )));

    assert_ne!(
        policy_fingerprint(&off).expect("fingerprint with the gate off"),
        policy_fingerprint(&on).expect("fingerprint with the gate on"),
        "turning the release-age gate on or off changes what a cargo scan \
         admits, so it must change the fingerprint"
    );
}

#[test]
fn changing_a_cargo_vet_source_url_changes_the_fingerprint() {
    let source = |url: &str| {
        toml_with_cargo_registry(&format!(
            "{CARGO_REGISTRY_BASE}\n\
             [[cargo_registry.cargo_vet_sources]]\n\
             name = \"mozilla\"\n\
             url = \"{url}\""
        ))
    };
    let one = load(&source("https://example.com/one/audits.toml"));
    let two = load(&source("https://example.com/two/audits.toml"));

    assert_ne!(
        policy_fingerprint(&one).expect("fingerprint the first source"),
        policy_fingerprint(&two).expect("fingerprint the second source"),
        "which audit sets are fetched changes what counts as proof, so it is a \
         different policy"
    );
}

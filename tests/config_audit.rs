//! Integration tests for the `[audit]` config table.
//!
//! `[audit]` is required, unlike the optional `[ai_review]`/
//! `[cargo_registry]`/`[npm_registry]` tables: the whole point of the
//! audit log is that an un-logged fetch must never happen, so a config
//! file that omits the table must fail to load rather than silently run
//! with logging off. `deny_unknown_fields` is already on `Config`, so
//! serde's own "missing field" error does the rejection; these tests
//! pin that behavior plus the table's own field defaults and bounds.
//!
//! The restart-only reload rejection for this table lives in
//! `tests/reload.rs`, which already carries the `Harness` a live-reload
//! test needs; duplicating that harness here would just be a second copy
//! of the same scaffolding.

use std::io::Write;
use std::path::PathBuf;

use supply_chain_scanner::config::{AuditRotation, Config};

/// A minimal, fully valid config covering every required field,
/// including `[audit]`. Individual tests mutate this string to exercise
/// one failure mode or one `[audit]` shape at a time.
const VALID_TOML: &str = r#"
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

#[test]
fn a_config_without_an_audit_table_is_rejected() {
    let toml = VALID_TOML.replace(
        r#"[audit]
path = "/var/log/scanner/audit.jsonl"
"#,
        "",
    );
    let file = write_temp_toml(&toml);

    let err = Config::load(file.path()).expect_err("a config with no [audit] table must not load");

    assert!(format!("{err:#}").contains("audit"), "{err:#}");
}

#[test]
fn an_audit_table_parses_path_rotation_and_max_files() {
    let toml = VALID_TOML.replace(
        r#"[audit]
path = "/var/log/scanner/audit.jsonl"
"#,
        r#"[audit]
path = "/var/log/scanner/audit.jsonl"
rotation = "hourly"
max_files = 7
"#,
    );
    let file = write_temp_toml(&toml);

    let config = Config::load(file.path()).expect("load config with a full [audit] table");

    assert_eq!(
        config.audit.path,
        PathBuf::from("/var/log/scanner/audit.jsonl")
    );
    assert_eq!(config.audit.rotation, AuditRotation::Hourly);
    assert_eq!(config.audit.max_files, 7);
}

#[test]
fn audit_rotation_and_max_files_default_to_daily_and_fourteen() {
    // VALID_TOML's [audit] table sets only `path`.
    let file = write_temp_toml(VALID_TOML);

    let config = Config::load(file.path()).expect("load config with a minimal [audit] table");

    assert_eq!(config.audit.rotation, AuditRotation::Daily);
    assert_eq!(config.audit.max_files, 14);
}

#[test]
fn audit_max_files_of_zero_is_rejected() {
    let toml = VALID_TOML.replace(
        r#"[audit]
path = "/var/log/scanner/audit.jsonl"
"#,
        r#"[audit]
path = "/var/log/scanner/audit.jsonl"
max_files = 0
"#,
    );
    let file = write_temp_toml(&toml);

    let err = Config::load(file.path()).expect_err("max_files = 0 must not load");

    assert!(format!("{err:#}").contains("max_files"), "{err:#}");
}

#[test]
fn an_audit_path_with_no_file_name_is_rejected() {
    let toml = VALID_TOML.replace(
        r#"path = "/var/log/scanner/audit.jsonl""#,
        r#"path = "/var/log/scanner/""#,
    );
    let file = write_temp_toml(&toml);

    let err = Config::load(file.path()).expect_err("a directory path must not load");

    assert!(format!("{err:#}").contains("audit"), "{err:#}");
}

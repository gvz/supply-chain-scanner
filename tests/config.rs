//! Integration tests for `supply_chain_scanner::config`.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use supply_chain_scanner::config::{Config, ConfigHandle, UnknownSeverity};

/// A minimal, fully valid config covering every required field. Individual
/// tests mutate this string to exercise one failure mode at a time.
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

[[allowlist]]
package = "example-package"
version = "1.2.3"

[[plugins]]
name = "yara-malware"
binary = "/opt/scanner/plugins/yara-malware"
timeout = "5s"
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

fn example_config_path() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.toml"))
}

#[test]
fn load_parses_example_config() {
    let config = Config::load(example_config_path()).expect("load example config");

    assert_eq!(config.bind.port(), 8080);
    assert_eq!(config.scan_budget, Duration::from_secs(12));
    assert_eq!(config.cache_ttl, Duration::from_secs(24 * 60 * 60));
    assert_eq!(config.plugins.len(), 1);
    assert_eq!(config.plugins[0].name, "yara-malware");
}

#[test]
fn load_rejects_unknown_field() {
    let toml = format!("{VALID_TOML}\nnot_a_real_field = true\n");
    let file = write_temp_toml(&toml);

    let result = Config::load(file.path());

    assert!(result.is_err(), "unknown field must be rejected");
}

#[test]
fn load_rejects_missing_upstream_url() {
    let toml = VALID_TOML.replace("upstream_url = \"https://pypi.org\"\n", "");
    let file = write_temp_toml(&toml);

    let result = Config::load(file.path());

    assert!(result.is_err(), "missing upstream_url must be rejected");
}

#[test]
fn unknown_severity_defaults_to_allow() {
    // VALID_TOML omits unknown_severity entirely.
    let file = write_temp_toml(VALID_TOML);

    let config = Config::load(file.path()).expect("load config");

    assert_eq!(config.cve.unknown_severity, UnknownSeverity::Allow);
}

#[test]
fn scan_budget_above_fourteen_seconds_is_rejected() {
    let toml = VALID_TOML.replace("scan_budget = \"12s\"", "scan_budget = \"15s\"");
    let file = write_temp_toml(&toml);

    let result = Config::load(file.path());

    assert!(
        result.is_err(),
        "a scan_budget above 14s must be rejected (pip's default timeout is 15s)"
    );
}

#[test]
fn reload_with_invalid_file_keeps_previous_config() {
    let good_file = write_temp_toml(VALID_TOML);
    let config = Config::load(good_file.path()).expect("load good config");
    let handle = ConfigHandle::new(config);

    let bad_toml = format!("{VALID_TOML}\nnot_a_real_field = true\n");
    let bad_file = write_temp_toml(&bad_toml);

    let result = handle.reload(bad_file.path());
    assert!(result.is_err(), "reload with a bad file must fail");

    let current = handle.current();
    assert_eq!(
        current.bind.port(),
        8080,
        "previous config must still be in place after a failed reload"
    );
}

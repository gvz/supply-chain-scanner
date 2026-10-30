//! Integration tests for `supply_chain_scanner::config`.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use supply_chain_scanner::config::{BlockOn, Config, ConfigHandle, UnknownSeverity};

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

/// `VALID_TOML` plus an `[ai_review]` table whose body is `body`.
/// `VALID_TOML` ends with a `[[plugins]]` array, so the table header
/// after it starts a fresh TOML table.
fn toml_with_ai_review(body: &str) -> String {
    format!("{VALID_TOML}\n[ai_review]\n{body}\n")
}

const AI_REVIEW_BASE: &str = "base_url = \"https://provider.example/v1/\"\nmodel = \"reviewer-1\"";

fn env_var_name_for_the_debug_test() -> &'static str {
    "SCS_TEST_DEBUG_KEY"
}

#[test]
fn ai_review_absent_leaves_none() {
    let file = write_temp_toml(VALID_TOML);

    let config = Config::load(file.path()).expect("load config");

    assert!(
        config.ai_review.is_none(),
        "a config without an [ai_review] table must leave ai_review as None"
    );
}

#[test]
fn ai_review_minimal_applies_documented_defaults() {
    let toml = toml_with_ai_review(AI_REVIEW_BASE);
    let file = write_temp_toml(&toml);

    let config = Config::load(file.path()).expect("load config");
    let ai = config
        .ai_review
        .as_ref()
        .expect("[ai_review] with base_url and model must load");

    assert!(
        ai.enabled,
        "enabled must default to true, so an [ai_review] table that omits it \
         behaves exactly as it always has"
    );
    assert_eq!(ai.base_url.as_str(), "https://provider.example/v1/");
    assert_eq!(ai.model, "reviewer-1");
    assert_eq!(ai.api_key_env, None);
    assert_eq!(ai.timeout, Duration::from_secs(8));
    assert_eq!(ai.max_payload_bytes, 262_144);
    assert_eq!(ai.max_output_tokens, 1024);
    assert!((ai.coverage_threshold - 0.8).abs() < 1e-6);
    assert_eq!(ai.block_on, BlockOn::Malicious);
    assert!(!ai.block_opaque_executables);
}

#[test]
fn ai_review_accepts_an_explicit_enabled_false() {
    let toml = toml_with_ai_review(&format!("{AI_REVIEW_BASE}\nenabled = false"));
    let file = write_temp_toml(&toml);

    let config = Config::load(file.path()).expect("load config");

    assert!(!config.ai_review.as_ref().expect("table loaded").enabled);
    assert!(
        config.ai_review().is_none(),
        "Config::ai_review must read a disabled table as absent"
    );
}

#[test]
fn ai_review_disabled_still_validates_the_rest_of_the_table() {
    let toml = toml_with_ai_review(&format!(
        "{AI_REVIEW_BASE}\nenabled = false\ncoverage_threshold = 1.5"
    ));
    let file = write_temp_toml(&toml);

    let result = Config::load(file.path());

    assert!(
        result.is_err(),
        "a disabled table is not a way to stage an invalid one; it must still \
         be fully validated"
    );
}

#[test]
fn ai_review_rejects_timeout_at_or_above_scan_budget() {
    let toml = toml_with_ai_review(&format!("{AI_REVIEW_BASE}\ntimeout = \"12s\""));
    let file = write_temp_toml(&toml);

    let result = Config::load(file.path());

    let err = result.expect_err("a timeout equal to scan_budget must be rejected");
    let message = format!("{err:#}");
    assert!(
        message.contains("timeout") && message.contains("scan_budget"),
        "the error must name both settings, got: {message}"
    );
    assert!(
        message.contains("12"),
        "the error must state both offending values, got: {message}"
    );
}

#[test]
fn ai_review_rejects_coverage_threshold_above_one() {
    let toml = toml_with_ai_review(&format!("{AI_REVIEW_BASE}\ncoverage_threshold = 1.5"));
    let file = write_temp_toml(&toml);

    let result = Config::load(file.path());

    let err = result.expect_err("a coverage_threshold above 1.0 must be rejected");
    assert!(
        format!("{err:#}").contains("1.5"),
        "the error must state the offending value, got: {err:#}"
    );
}

#[test]
fn ai_review_rejects_negative_coverage_threshold() {
    let toml = toml_with_ai_review(&format!("{AI_REVIEW_BASE}\ncoverage_threshold = -0.1"));
    let file = write_temp_toml(&toml);

    let result = Config::load(file.path());

    let err = result.expect_err("a negative coverage_threshold must be rejected");
    assert!(
        format!("{err:#}").contains("-0.1"),
        "the error must state the offending value, got: {err:#}"
    );
}

#[test]
fn ai_review_rejects_plain_http_to_non_loopback() {
    let toml =
        toml_with_ai_review("base_url = \"http://provider.example/v1/\"\nmodel = \"reviewer-1\"");
    let file = write_temp_toml(&toml);

    let result = Config::load(file.path());

    let err = result.expect_err("plain http to a non-loopback host must be rejected");
    assert!(
        format!("{err:#}").contains("http://provider.example/v1/"),
        "the error must state the offending value, got: {err:#}"
    );
}

#[test]
fn ai_review_accepts_plain_http_to_loopback() {
    let toml =
        toml_with_ai_review("base_url = \"http://127.0.0.1:8000/v1/\"\nmodel = \"reviewer-1\"");
    let file = write_temp_toml(&toml);

    let config = Config::load(file.path()).expect("plain http to loopback must load");

    assert_eq!(
        config
            .ai_review
            .expect("ai_review must be present")
            .base_url
            .as_str(),
        "http://127.0.0.1:8000/v1/"
    );
}

#[test]
fn ai_review_accepts_plain_http_to_ipv6_loopback() {
    // `Url::host_str()` returns an IPv6 literal's authority form with
    // its brackets intact (`[::1]`), so a validator that compared
    // against the bare string `"::1"` would reject this and silently
    // contradict the error message's own claim that `::1` is allowed.
    let toml = toml_with_ai_review("base_url = \"http://[::1]:8000/v1/\"\nmodel = \"reviewer-1\"");
    let file = write_temp_toml(&toml);

    let config = Config::load(file.path()).expect("plain http to an ipv6 loopback must load");

    assert!(config.ai_review.is_some());
}

#[test]
fn ai_review_accepts_plain_http_to_localhost() {
    let toml =
        toml_with_ai_review("base_url = \"http://localhost:8000/v1/\"\nmodel = \"reviewer-1\"");
    let file = write_temp_toml(&toml);

    let config = Config::load(file.path()).expect("plain http to localhost must load");

    assert!(config.ai_review.is_some());
}

#[test]
fn ai_review_accepts_https_to_non_loopback() {
    let file = write_temp_toml(&toml_with_ai_review(AI_REVIEW_BASE));

    let config = Config::load(file.path()).expect("https to a non-loopback host must load");

    assert!(config.ai_review.is_some());
}

#[test]
fn ai_review_rejects_unset_api_key_env() {
    // No test in this file sets this name, so it stays unset. Remove it
    // first to keep this test true even if it runs after another one.
    std::env::remove_var("SCS_TEST_UNSET_KEY");
    let toml = toml_with_ai_review(&format!(
        "{AI_REVIEW_BASE}\napi_key_env = \"SCS_TEST_UNSET_KEY\""
    ));
    let file = write_temp_toml(&toml);

    let result = Config::load(file.path());

    let err = result.expect_err("an api_key_env that does not resolve must be rejected");
    assert!(
        format!("{err:#}").contains("SCS_TEST_UNSET_KEY"),
        "the error must name the variable, got: {err:#}"
    );
}

#[test]
fn ai_review_rejects_max_payload_below_4096() {
    let toml = toml_with_ai_review(&format!("{AI_REVIEW_BASE}\nmax_payload_bytes = 1024"));
    let file = write_temp_toml(&toml);

    let result = Config::load(file.path());

    let err = result.expect_err("a max_payload_bytes below 4096 must be rejected");
    assert!(
        format!("{err:#}").contains("1024"),
        "the error must state the offending value, got: {err:#}"
    );
}

#[test]
fn ai_review_config_debug_never_contains_a_key() {
    // This test uses its own variable name. The unset-key test uses a
    // different name, so the two tests do not race on one variable even
    // though each test process runs them in parallel threads.
    let name = env_var_name_for_the_debug_test();
    std::env::set_var(name, "sk-test-value-that-must-not-leak");
    let toml = toml_with_ai_review(&format!("{AI_REVIEW_BASE}\napi_key_env = \"{name}\""));
    let file = write_temp_toml(&toml);

    let config = Config::load(file.path()).expect("load config with a resolvable key variable");

    let debug = format!("{config:?}");
    assert!(
        !debug.contains("sk-test-value-that-must-not-leak"),
        "Debug output of Config must not contain the API key, got: {debug}"
    );
    std::env::remove_var(name);
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

//! Integration tests for `supply_chain_scanner::policy`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use supply_chain_scanner::config::{AllowEntry, Config, CveLine, PluginConfig, UnknownSeverity};
use supply_chain_scanner::policy::{policy_fingerprint, AdvisoryVerdictInput, Policy};

/// A minimal, fully valid `Config` with no plugins and no allowlist
/// entries. Individual tests clone and mutate the fields they care about.
fn base_config() -> Config {
    Config {
        bind: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
        db_path: PathBuf::from("data/scanner.db"),
        cache_dir: PathBuf::from("data/cache"),
        upstream_url: "https://pypi.org".parse().unwrap(),
        public_url: "http://localhost:8080".parse().unwrap(),
        scan_budget: Duration::from_secs(12),
        cache_ttl: Duration::from_secs(24 * 60 * 60),
        advisory_sync_interval: Duration::from_secs(60 * 60),
        advisory_source_url: "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
            .parse()
            .unwrap(),
        cve: CveLine {
            min_severity: 7.0,
            require_fix_available: false,
            unknown_severity: UnknownSeverity::Allow,
        },
        allowlist: Vec::new(),
        plugins: Vec::new(),
    }
}

/// Writes `contents` to a freshly created temp file and returns the temp
/// dir (kept alive by the caller) plus the file's path.
fn plugin_binary(dir: &tempfile::TempDir, name: &str, contents: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).expect("write plugin binary");
    path
}

fn plugin(name: &str, binary: &Path) -> PluginConfig {
    PluginConfig {
        name: name.to_string(),
        binary: binary.to_path_buf(),
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn fingerprint_changes_when_min_severity_changes() {
    let mut cfg_a = base_config();
    cfg_a.cve.min_severity = 7.0;
    let mut cfg_b = base_config();
    cfg_b.cve.min_severity = 8.0;

    let fp_a = policy_fingerprint(&cfg_a).expect("fingerprint a");
    let fp_b = policy_fingerprint(&cfg_b).expect("fingerprint b");

    assert_ne!(
        fp_a, fp_b,
        "changing min_severity must change the policy fingerprint"
    );
}

#[test]
fn fingerprint_changes_when_plugin_binary_contents_change() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let binary_path = plugin_binary(&dir, "yara-malware", b"version one");

    let mut cfg = base_config();
    cfg.plugins = vec![plugin("yara-malware", &binary_path)];

    let fp_before = policy_fingerprint(&cfg).expect("fingerprint before rewrite");

    // Rewrite the same binary path with different contents, simulating the
    // org shipping an updated plugin build.
    std::fs::write(&binary_path, b"version two - different signatures")
        .expect("rewrite plugin binary with new contents");

    let fp_after = policy_fingerprint(&cfg).expect("fingerprint after rewrite");

    assert_ne!(
        fp_before, fp_after,
        "changing a plugin binary's contents must change the fingerprint"
    );
}

#[test]
fn fingerprint_changes_when_plugin_order_changes() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let binary_a = plugin_binary(&dir, "plugin-a", b"plugin a contents");
    let binary_b = plugin_binary(&dir, "plugin-b", b"plugin b contents");

    let mut cfg_forward = base_config();
    cfg_forward.plugins = vec![plugin("plugin-a", &binary_a), plugin("plugin-b", &binary_b)];

    let mut cfg_reversed = base_config();
    cfg_reversed.plugins = vec![plugin("plugin-b", &binary_b), plugin("plugin-a", &binary_a)];

    let fp_forward = policy_fingerprint(&cfg_forward).expect("fingerprint forward order");
    let fp_reversed = policy_fingerprint(&cfg_reversed).expect("fingerprint reversed order");

    assert_ne!(
        fp_forward, fp_reversed,
        "reordering the same two plugins must change the fingerprint"
    );
}

#[test]
fn fingerprint_ignores_bind_address_and_cache_ttl() {
    let cfg_a = base_config();
    let mut cfg_b = base_config();
    cfg_b.bind = "0.0.0.0:9999".parse().unwrap();
    cfg_b.cache_ttl = Duration::from_secs(60);

    // Sanity check that the two configs really do differ in these fields.
    assert_ne!(cfg_a.bind, cfg_b.bind);
    assert_ne!(cfg_a.cache_ttl, cfg_b.cache_ttl);

    let fp_a = policy_fingerprint(&cfg_a).expect("fingerprint a");
    let fp_b = policy_fingerprint(&cfg_b).expect("fingerprint b");

    assert_eq!(
        fp_a, fp_b,
        "bind and cache_ttl are operational knobs, not policy inputs"
    );
}

#[test]
fn build_errors_when_a_plugin_binary_is_missing() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let missing_path = dir.path().join("does-not-exist");

    let mut cfg = base_config();
    cfg.plugins = vec![plugin("missing-plugin", &missing_path)];

    let result = Policy::build(Arc::new(cfg));

    assert!(
        result.is_err(),
        "a missing plugin binary must fail Policy::build rather than silently \
         scanning under a shorter plugin list"
    );
}

#[test]
fn allows_matches_regardless_of_name_spelling() {
    let mut cfg = base_config();
    cfg.allowlist = vec![AllowEntry {
        package: "Flask_X".to_string(),
        version: "1.0.0".to_string(),
    }];

    let policy = Policy::build(Arc::new(cfg)).expect("build policy");

    assert!(
        policy.allows("flask-x", "1.0.0"),
        "allowlist matching must use PEP 503 normalization"
    );
    assert!(
        !policy.allows("flask-x", "2.0.0"),
        "a different version must not be allowlisted"
    );
    assert!(
        !policy.allows("some-other-package", "1.0.0"),
        "a different package must not be allowlisted"
    );
}

#[test]
fn unknown_severity_allow_does_not_block() {
    let mut cfg = base_config();
    cfg.cve.unknown_severity = UnknownSeverity::Allow;
    let policy = Policy::build(Arc::new(cfg)).expect("build policy");

    let input = AdvisoryVerdictInput {
        severity: None,
        has_fix: false,
    };

    assert!(
        !policy.blocks_advisory(&input),
        "unknown severity must not block when unknown_severity is Allow"
    );
}

#[test]
fn unknown_severity_block_does_block() {
    let mut cfg = base_config();
    cfg.cve.unknown_severity = UnknownSeverity::Block;
    let policy = Policy::build(Arc::new(cfg)).expect("build policy");

    let input = AdvisoryVerdictInput {
        severity: None,
        has_fix: false,
    };

    assert!(
        policy.blocks_advisory(&input),
        "unknown severity must block when unknown_severity is Block"
    );
}

#[test]
fn severity_at_or_above_threshold_blocks() {
    let mut cfg = base_config();
    cfg.cve.min_severity = 7.0;
    let policy = Policy::build(Arc::new(cfg)).expect("build policy");

    let at_threshold = AdvisoryVerdictInput {
        severity: Some(7.0),
        has_fix: false,
    };
    let above_threshold = AdvisoryVerdictInput {
        severity: Some(9.1),
        has_fix: false,
    };
    let below_threshold = AdvisoryVerdictInput {
        severity: Some(6.9),
        has_fix: false,
    };

    assert!(
        policy.blocks_advisory(&at_threshold),
        "severity exactly at min_severity must block"
    );
    assert!(
        policy.blocks_advisory(&above_threshold),
        "severity above min_severity must block"
    );
    assert!(
        !policy.blocks_advisory(&below_threshold),
        "severity below min_severity must not block"
    );
}

#[test]
fn require_fix_available_only_blocks_when_fix_exists() {
    let mut cfg = base_config();
    cfg.cve.min_severity = 7.0;
    cfg.cve.require_fix_available = true;
    let policy = Policy::build(Arc::new(cfg)).expect("build policy");

    let no_fix = AdvisoryVerdictInput {
        severity: Some(9.0),
        has_fix: false,
    };
    let with_fix = AdvisoryVerdictInput {
        severity: Some(9.0),
        has_fix: true,
    };

    assert!(
        !policy.blocks_advisory(&no_fix),
        "require_fix_available must not block an advisory with no known fix"
    );
    assert!(
        policy.blocks_advisory(&with_fix),
        "require_fix_available must block an advisory that does have a fix"
    );
}

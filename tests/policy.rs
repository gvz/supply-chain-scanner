//! Integration tests for `supply_chain_scanner::policy`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use supply_chain_scanner::config::{
    AiReviewConfig, BlockOn, Config, CveLine, PluginConfig, UnknownSeverity,
};
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
        min_release_age_days: None,
        download: Default::default(),
        allowlist: Vec::new(),
        plugins: Vec::new(),
        max_concurrent_scans: None,
        ai_review: None,
        cargo_registry: None,
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

// ---------------------------------------------------------------------------
// [ai_review] in the fingerprint
// ---------------------------------------------------------------------------

/// A minimal `[ai_review]` table. Individual tests clone and mutate the
/// fields the plan pins as fingerprint inputs.
fn ai_review() -> AiReviewConfig {
    AiReviewConfig {
        enabled: true,
        base_url: "https://provider.example/v1/".parse().unwrap(),
        model: "gpt-reviewer".to_string(),
        api_key_env: None,
        timeout: Duration::from_secs(8),
        max_payload_bytes: 262_144,
        max_output_tokens: 1024,
        coverage_threshold: 0.8,
        block_on: BlockOn::Malicious,
        block_opaque_executables: false,
    }
}

/// The digest committed below was computed on `main` at commit 4ee4130,
/// before any `[ai_review]` code touched `policy_fingerprint` (the plain
/// config, and the two-plugin config, both by running the then-current
/// fingerprint on that commit). Pinning the literal digest, rather than
/// recomputing it with today's code, is the whole point: upgrading this
/// binary must never invalidate a stored verdict in an unconfigured
/// deployment, and only a fixed expected value can prove that.
const FINGERPRINT_BEFORE_AI_REVIEW_PLAIN: &str =
    "251d88bf8c07c0af8efb65abdc1c1c315d194436ba54d93ec0806639f820af45";

/// Same, for a config with two plugins: the `ai_review` absence is
/// appended after the plugin loop, so a deployment that runs plugins but
/// no reviewer is pinned too.
const FINGERPRINT_BEFORE_AI_REVIEW_WITH_PLUGINS: &str =
    "63a7276e165548815a9c12475361d49a0697781a8190f0f5d494bc06240387c8";

#[test]
fn a_config_without_ai_review_fingerprints_exactly_as_before() {
    let fp_plain = policy_fingerprint(&base_config()).expect("fingerprint plain");
    assert_eq!(
        fp_plain, FINGERPRINT_BEFORE_AI_REVIEW_PLAIN,
        "a config with no [ai_review] table must fingerprint identically to the \
         same config before the reviewer existed, or upgrading this binary \
         invalidates every stored verdict in an unconfigured deployment"
    );

    let dir = tempfile::tempdir().expect("create temp dir");
    let binary_a = plugin_binary(&dir, "yara-malware", b"version one");
    let binary_b = plugin_binary(&dir, "semgrep", b"semgrep rules");
    let mut cfg = base_config();
    cfg.plugins = vec![
        plugin("yara-malware", &binary_a),
        plugin("semgrep", &binary_b),
    ];
    let fp_plugins = policy_fingerprint(&cfg).expect("fingerprint with plugins");
    assert_eq!(
        fp_plugins, FINGERPRINT_BEFORE_AI_REVIEW_WITH_PLUGINS,
        "a config with plugins but no [ai_review] table must fingerprint \
         identically to before the reviewer existed"
    );

    // Same config with ai_review explicitly absent, stated a second way,
    // for the reader: None appends nothing at all to the hashed bytes.
    let mut cfg_none = base_config();
    cfg_none.ai_review = None;
    assert_eq!(
        policy_fingerprint(&cfg_none).expect("fingerprint explicit none"),
        FINGERPRINT_BEFORE_AI_REVIEW_PLAIN
    );
}

#[test]
fn enabling_the_reviewer_changes_the_fingerprint() {
    let fp_off = policy_fingerprint(&base_config()).expect("fingerprint off");
    let mut cfg = base_config();
    cfg.ai_review = Some(ai_review());
    let fp_on = policy_fingerprint(&cfg).expect("fingerprint on");

    assert_ne!(
        fp_off, fp_on,
        "turning the reviewer on must change the fingerprint, or artifacts scanned \
         clean without a review would keep serving from a verdict that never met it"
    );
}

#[test]
fn a_disabled_reviewer_fingerprints_exactly_like_no_reviewer_at_all() {
    let mut disabled = ai_review();
    disabled.enabled = false;
    let mut cfg_disabled = base_config();
    cfg_disabled.ai_review = Some(disabled);

    assert_eq!(
        policy_fingerprint(&cfg_disabled).expect("fingerprint disabled"),
        policy_fingerprint(&base_config()).expect("fingerprint absent"),
        "an [ai_review] table with enabled = false must fingerprint identically \
         to a config with no table at all"
    );
}

#[test]
fn re_enabling_a_disabled_reviewer_changes_the_fingerprint() {
    let mut disabled = ai_review();
    disabled.enabled = false;
    let mut cfg_disabled = base_config();
    cfg_disabled.ai_review = Some(disabled);

    let mut cfg_enabled = base_config();
    cfg_enabled.ai_review = Some(ai_review());

    assert_ne!(
        policy_fingerprint(&cfg_disabled).expect("fingerprint disabled"),
        policy_fingerprint(&cfg_enabled).expect("fingerprint enabled"),
        "flipping enabled back to true must change the fingerprint, same as \
         turning the reviewer on from nothing"
    );
}

#[test]
fn changing_the_model_changes_the_fingerprint() {
    let mut cfg_a = base_config();
    cfg_a.ai_review = Some(ai_review());
    let mut cfg_b = base_config();
    let mut ai = ai_review();
    ai.model = "gpt-reviewer-v2".to_string();
    cfg_b.ai_review = Some(ai);

    assert_ne!(
        policy_fingerprint(&cfg_a).expect("fp a"),
        policy_fingerprint(&cfg_b).expect("fp b"),
        "the model is which checks ran; a different model must be a different policy"
    );
    // The config really does differ in that field and nothing else.
    let fp_same = {
        let mut cfg = base_config();
        let mut ai = ai_review();
        ai.model = "gpt-reviewer-v2".to_string();
        cfg.ai_review = Some(ai);
        policy_fingerprint(&cfg).expect("fp same")
    };
    assert_eq!(
        policy_fingerprint(&cfg_b).expect("fp b"),
        fp_same,
        "two identical configs must agree (sanity for the ne-comparison above)"
    );
}

#[test]
fn changing_the_coverage_threshold_changes_the_fingerprint() {
    let mut cfg_a = base_config();
    cfg_a.ai_review = Some(ai_review());
    let mut cfg_b = base_config();
    let mut ai = ai_review();
    ai.coverage_threshold = 0.9;
    cfg_b.ai_review = Some(ai);

    assert_ne!(
        policy_fingerprint(&cfg_a).expect("fp a"),
        policy_fingerprint(&cfg_b).expect("fp b"),
        "a different coverage threshold blocks different artifacts, so it is a \n         different policy"
    );
}

#[test]
fn changing_block_on_changes_the_fingerprint() {
    let mut cfg_a = base_config();
    cfg_a.ai_review = Some(ai_review());
    let mut cfg_b = base_config();
    let mut ai = ai_review();
    ai.block_on = BlockOn::Suspicious;
    cfg_b.ai_review = Some(ai);

    assert_ne!(
        policy_fingerprint(&cfg_a).expect("fp a"),
        policy_fingerprint(&cfg_b).expect("fp b"),
        "block_on changes which verdicts refuse the artifact, so it is a \n         different policy"
    );
}

#[test]
fn changing_block_opaque_executables_changes_the_fingerprint() {
    let mut cfg_a = base_config();
    cfg_a.ai_review = Some(ai_review());
    let mut cfg_b = base_config();
    let mut ai = ai_review();
    ai.block_opaque_executables = true;
    cfg_b.ai_review = Some(ai);

    assert_ne!(
        policy_fingerprint(&cfg_a).expect("fp a"),
        policy_fingerprint(&cfg_b).expect("fp b"),
        "block_opaque_executables changes which artifacts refuse, so it is \n         a different policy"
    );
}

#[test]
fn changing_the_base_url_leaves_the_fingerprint_alone() {
    let mut cfg_a = base_config();
    cfg_a.ai_review = Some(ai_review());
    let mut cfg_b = base_config();
    let mut ai = ai_review();
    ai.base_url = "https://other-provider.example/v1/".parse().unwrap();
    cfg_b.ai_review = Some(ai);

    assert_eq!(
        policy_fingerprint(&cfg_a).expect("fp a"),
        policy_fingerprint(&cfg_b).expect("fp b"),
        "base_url is operational, like bind: moving to a different provider \n         host must not invalidate a single stored verdict"
    );
}

#[test]
fn changing_the_api_key_env_leaves_the_fingerprint_alone() {
    let mut cfg_a = base_config();
    cfg_a.ai_review = Some(ai_review());
    let mut cfg_b = base_config();
    let mut ai = ai_review();
    ai.api_key_env = Some("SCS_OTHER_PROVIDER_KEY".to_string());
    cfg_b.ai_review = Some(ai);

    assert_eq!(
        policy_fingerprint(&cfg_a).expect("fp a"),
        policy_fingerprint(&cfg_b).expect("fp b"),
        "api_key_env is operational: rotating which variable holds the key \n         changes nothing about which checks ran"
    );
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
fn fingerprint_changes_when_min_release_age_days_changes() {
    let cfg_off = base_config();
    let mut cfg_on = base_config();
    cfg_on.min_release_age_days = Some(14);

    let fp_off = policy_fingerprint(&cfg_off).expect("fingerprint with the gate off");
    let fp_on = policy_fingerprint(&cfg_on).expect("fingerprint with the gate on");

    assert_ne!(
        fp_off, fp_on,
        "turning the release-age gate on or off must change the policy fingerprint"
    );
}

#[test]
fn min_release_age_days_defaults_to_off() {
    let policy = Policy::build(Arc::new(base_config())).expect("build policy");
    assert_eq!(
        policy.min_release_age_days(),
        None,
        "an unconfigured deployment must leave the release-age gate off"
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

// The allowlist test that used to live here, against `Policy::allows`,
// has moved to `src/scan/mod.rs`'s unit tests
// (`allowlist_matching_uses_pep_503_normalization`). `Policy::allows` had
// no callers outside this file; the live comparison is
// `scan::is_allowlisted`, which is `pub(crate)` and therefore only
// reachable from a unit test. Testing the dead copy while the two live
// ones went untested is how a divergence between them would have shipped.

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

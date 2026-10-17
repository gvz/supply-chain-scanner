//! Integration tests for `supply_chain_scanner::advisory::matching`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use supply_chain_scanner::advisory::matching::{affects, first_blocking};
use supply_chain_scanner::advisory::{Advisory, VersionRange};
use supply_chain_scanner::config::{Config, CveLine, UnknownSeverity};
use supply_chain_scanner::policy::Policy;

/// A minimal, fully valid `Config` with no plugins and no allowlist
/// entries. Individual tests clone and mutate the fields they care about.
/// Mirrors `tests/policy.rs`'s helper of the same name.
fn base_config() -> Config {
    Config {
        bind: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
        db_path: "data/scanner.db".into(),
        cache_dir: "data/cache".into(),
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

/// A minimal advisory with no enumerated versions and no ranges. Tests
/// override the fields they care about with struct-update syntax.
fn advisory(id: &str, severity: Option<f32>) -> Advisory {
    Advisory {
        id: id.to_string(),
        package: "demo-package".to_string(),
        summary: "a demo vulnerability".to_string(),
        severity,
        versions: Vec::new(),
        ranges: Vec::new(),
        fixed_versions: Vec::new(),
    }
}

#[test]
fn exact_version_in_enumerated_list_affects() {
    let adv = Advisory {
        versions: vec!["1.2.3".to_string()],
        ..advisory("GHSA-exact", Some(9.0))
    };

    assert!(
        affects(&adv, "1.2.3"),
        "a version present in the enumerated list must affect"
    );
}

#[test]
fn version_outside_enumerated_list_does_not_affect() {
    let adv = Advisory {
        versions: vec!["1.2.3".to_string()],
        ..advisory("GHSA-outside", Some(9.0))
    };

    assert!(
        !affects(&adv, "1.2.4"),
        "a version absent from the enumerated list, with no ranges, must not affect"
    );
}

#[test]
fn version_inside_introduced_fixed_range_affects() {
    let adv = Advisory {
        ranges: vec![VersionRange {
            introduced: Some("1.0.0".to_string()),
            fixed: Some("2.0.0".to_string()),
        }],
        ..advisory("GHSA-range", Some(9.0))
    };

    assert!(
        affects(&adv, "1.5.0"),
        "a version strictly between introduced and fixed must affect"
    );
}

#[test]
fn version_at_fixed_boundary_does_not_affect() {
    let adv = Advisory {
        ranges: vec![VersionRange {
            introduced: Some("1.0.0".to_string()),
            fixed: Some("2.0.0".to_string()),
        }],
        ..advisory("GHSA-boundary", Some(9.0))
    };

    assert!(
        !affects(&adv, "2.0.0"),
        "the range is half-open [introduced, fixed); the version equal to fixed must not affect"
    );
    assert!(
        affects(&adv, "1.0.0"),
        "sanity: the version equal to introduced must affect"
    );
}

#[test]
fn open_ended_range_affects_everything_above_introduced() {
    let adv = Advisory {
        ranges: vec![VersionRange {
            introduced: Some("1.0.0".to_string()),
            fixed: None,
        }],
        ..advisory("GHSA-open", Some(9.0))
    };

    assert!(
        affects(&adv, "1.0.0"),
        "a range with no fixed bound must affect the introduced version itself"
    );
    assert!(
        affects(&adv, "999.0.0"),
        "a range with no fixed bound must affect everything above introduced"
    );
    assert!(
        !affects(&adv, "0.9.0"),
        "a range with no fixed bound must not affect versions below introduced"
    );
}

#[test]
fn pep440_prerelease_compares_below_release() {
    let range_adv = Advisory {
        ranges: vec![VersionRange {
            introduced: Some("1.0.0".to_string()),
            fixed: Some("2.0.0".to_string()),
        }],
        ..advisory("GHSA-prerelease", Some(9.0))
    };
    assert!(
        affects(&range_adv, "2.0.0rc1"),
        "2.0.0rc1 must compare below 2.0.0 (PEP 440 prerelease ordering), \
         so it still falls inside [1.0.0, 2.0.0)"
    );

    let numeric_adv = Advisory {
        ranges: vec![VersionRange {
            introduced: Some("1.10".to_string()),
            fixed: None,
        }],
        ..advisory("GHSA-numeric", Some(9.0))
    };
    assert!(
        !affects(&numeric_adv, "1.9"),
        "1.9 must compare below 1.10 numerically (PEP 440), not lexically"
    );
}

#[test]
fn unparseable_version_against_a_range_affects() {
    let adv = Advisory {
        ranges: vec![VersionRange {
            introduced: Some("1.0.0".to_string()),
            fixed: Some("2.0.0".to_string()),
        }],
        ..advisory("GHSA-unparseable", Some(9.0))
    };

    assert!(
        affects(&adv, "not-a-version"),
        "a version that fails to parse, against an advisory that carries ranges, \
         must fail closed as affected rather than fail open"
    );
}

#[test]
fn first_blocking_returns_reason_with_advisory_id_and_severity() {
    let mut cfg = base_config();
    cfg.cve.min_severity = 7.0;
    let policy = Policy::build(Arc::new(cfg)).expect("build policy");

    let adv = Advisory {
        versions: vec!["1.2.3".to_string()],
        summary: "remote code execution via unsafe deserialization".to_string(),
        ..advisory("GHSA-rce-1234", Some(9.8))
    };

    let reason = first_blocking(&[adv], "1.2.3", &policy).expect("expected a blocking advisory");

    assert_eq!(reason.code, "cve:GHSA-rce-1234");
    assert!(
        reason.detail.contains("remote code execution"),
        "detail must carry the advisory summary, got {:?}",
        reason.detail
    );
    assert!(
        reason.detail.contains("9.8"),
        "detail must carry the advisory severity, got {:?}",
        reason.detail
    );
}

#[test]
fn first_blocking_skips_advisories_below_the_cve_line() {
    let mut cfg = base_config();
    cfg.cve.min_severity = 7.0;
    let policy = Policy::build(Arc::new(cfg)).expect("build policy");

    let below_line = Advisory {
        versions: vec!["1.2.3".to_string()],
        ..advisory("GHSA-below-line", Some(3.0))
    };
    let above_line = Advisory {
        versions: vec!["1.2.3".to_string()],
        ..advisory("GHSA-above-line", Some(9.0))
    };

    let reason = first_blocking(&[below_line, above_line], "1.2.3", &policy)
        .expect("expected the advisory above the CVE line to block");

    assert_eq!(
        reason.code, "cve:GHSA-above-line",
        "an advisory below the CVE line must be skipped in favor of a later \
         advisory above it, not reported, and not cause a None result"
    );
}

#[test]
fn first_blocking_returns_none_when_nothing_matches() {
    let mut cfg = base_config();
    cfg.cve.min_severity = 7.0;
    let policy = Policy::build(Arc::new(cfg)).expect("build policy");

    let adv = Advisory {
        versions: vec!["1.2.3".to_string()],
        ..advisory("GHSA-nomatch", Some(9.0))
    };

    let result = first_blocking(&[adv], "9.9.9", &policy);

    assert!(
        result.is_none(),
        "no advisory affects this version, so first_blocking must return None"
    );
}

#[test]
fn refusal_detail_strips_control_chars_non_ascii_and_caps_length() {
    let mut cfg = base_config();
    cfg.cve.min_severity = 7.0;
    let policy = Policy::build(Arc::new(cfg)).expect("build policy");

    // CR, LF (the response-splitting bytes task 11 guards against), a
    // non-ASCII character, and a summary much longer than the cap, all in
    // one go.
    let malicious_summary = format!("evil\r\nheader-injection-\u{00f1}-{}", "a".repeat(500));
    let adv = Advisory {
        versions: vec!["1.2.3".to_string()],
        summary: malicious_summary,
        ..advisory("GHSA-malicious", Some(9.0))
    };

    let reason = first_blocking(&[adv], "1.2.3", &policy).expect("expected a blocking advisory");

    assert!(!reason.detail.contains('\r'), "detail must not contain CR");
    assert!(!reason.detail.contains('\n'), "detail must not contain LF");
    assert!(
        reason.detail.is_ascii(),
        "detail must be ASCII only, got {:?}",
        reason.detail
    );

    let (summary_part, _) = reason
        .detail
        .split_once(" (severity")
        .expect("detail must contain the severity suffix");
    assert!(
        summary_part.chars().count() <= 200,
        "sanitized summary must be capped at 200 characters, got {} chars: {:?}",
        summary_part.chars().count(),
        summary_part
    );
}

#[test]
fn malformed_enumerated_version_falls_back_to_raw_string_match() {
    let adv = Advisory {
        versions: vec!["not-a-pep440-version".to_string()],
        ..advisory("GHSA-malformed-enum", Some(9.0))
    };

    assert!(
        affects(&adv, "not-a-pep440-version"),
        "a malformed enumerated entry must still match an identical raw version string"
    );
    assert!(
        affects(&adv, "NOT-A-PEP440-VERSION"),
        "the raw-string fallback must be case-insensitive"
    );
    assert!(
        !affects(&adv, "some-other-version"),
        "a malformed enumerated entry must not match an unrelated version"
    );
}

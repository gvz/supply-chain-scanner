use supply_chain_scanner::ecosystem::npm::packument::{
    declared_digest, filter_packument, parse_packument, DigestAlgorithm,
};

/// A real SHA-512 SRI string for the bytes `b"hello world"`, and its
/// lowercase hex equivalent, so tests can assert the decoded digest
/// without re-implementing base64 decoding.
const SHA512_INTEGRITY: &str =
    "sha512-MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==";
const SHA512_HEX: &str = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";

#[test]
fn parse_reads_versions_dist_tags_and_time() {
    let body = r#"{
        "name": "demo",
        "versions": {
            "1.0.0": {
                "version": "1.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"}
            },
            "2.0.0": {
                "version": "2.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-2.0.0.tgz"}
            }
        },
        "dist-tags": {"latest": "2.0.0"},
        "time": {
            "1.0.0": "2020-01-01T00:00:00.000Z",
            "2.0.0": "2021-01-01T00:00:00.000Z"
        }
    }"#;

    let packument = parse_packument(body).unwrap();
    assert_eq!(packument.name, "demo");
    assert_eq!(packument.versions.len(), 2);
    assert!(packument.versions.contains_key("1.0.0"));
    assert!(packument.versions.contains_key("2.0.0"));
    assert_eq!(packument.dist_tags.get("latest").unwrap(), "2.0.0");
    assert_eq!(packument.time.len(), 2);
    assert!(packument.time.contains_key("1.0.0"));
    assert!(packument.time.contains_key("2.0.0"));
}

#[test]
fn parse_reads_integrity_shasum_deprecated_and_scripts() {
    let body = format!(
        r#"{{
        "name": "demo",
        "versions": {{
            "1.0.0": {{
                "version": "1.0.0",
                "dist": {{
                    "tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                    "integrity": "{SHA512_INTEGRITY}",
                    "shasum": "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
                }},
                "deprecated": "use demo2 instead",
                "scripts": {{"postinstall": "node setup.js"}}
            }}
        }},
        "dist-tags": {{"latest": "1.0.0"}}
    }}"#
    );

    let packument = parse_packument(&body).unwrap();
    let version = packument.versions.get("1.0.0").unwrap();
    assert_eq!(version.dist.integrity.as_deref(), Some(SHA512_INTEGRITY));
    assert_eq!(
        version.dist.shasum.as_deref(),
        Some("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
    );
    assert_eq!(version.deprecated.as_deref(), Some("use demo2 instead"));
    assert_eq!(
        version.scripts.get("postinstall").map(String::as_str),
        Some("node setup.js")
    );
}

#[test]
fn parse_tolerates_an_absent_time_map() {
    // Abbreviated-shaped body: the "time" map is sometimes entirely absent
    // from upstream's response. That is not an error, just empty.
    let body = r#"{
        "name": "demo",
        "versions": {
            "1.0.0": {
                "version": "1.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"}
            }
        },
        "dist-tags": {"latest": "1.0.0"}
    }"#;

    let packument = parse_packument(body).unwrap();
    assert!(packument.time.is_empty());
}

#[test]
fn declared_digest_prefers_integrity_over_shasum() {
    let dist = supply_chain_scanner::ecosystem::npm::packument::Dist {
        tarball: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".to_string(),
        integrity: Some(SHA512_INTEGRITY.to_string()),
        shasum: Some("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed".to_string()),
    };

    let digest = declared_digest(&dist).unwrap();
    assert_eq!(digest.algorithm, DigestAlgorithm::Sha512);
    assert_eq!(digest.hex, SHA512_HEX);
}

#[test]
fn declared_digest_falls_back_to_shasum_when_integrity_is_absent() {
    let dist = supply_chain_scanner::ecosystem::npm::packument::Dist {
        tarball: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".to_string(),
        integrity: None,
        shasum: Some("2AAE6C35C94FCFB415DBE95F408B9CE91EE846ED".to_string()),
    };

    let digest = declared_digest(&dist).unwrap();
    assert_eq!(digest.algorithm, DigestAlgorithm::Sha1);
    assert_eq!(digest.hex, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
    assert_eq!(digest.hex.len(), 40);
}

#[test]
fn declared_digest_rejects_an_unverifiable_integrity_algorithm() {
    // "sha384-..." yields None even when a shasum is also present: a
    // stronger declared digest must never be silently downgraded.
    let dist = supply_chain_scanner::ecosystem::npm::packument::Dist {
        tarball: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".to_string(),
        integrity: Some("sha384-deadbeef".to_string()),
        shasum: Some("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed".to_string()),
    };

    assert!(declared_digest(&dist).is_none());
}

#[test]
fn declared_digest_rejects_malformed_base64_under_a_valid_prefix() {
    // "!!!" is not valid base64 under any prefix. A decode failure must
    // not fall back to shasum either.
    let dist = supply_chain_scanner::ecosystem::npm::packument::Dist {
        tarball: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".to_string(),
        integrity: Some("sha512-!!!not-valid-base64!!!".to_string()),
        shasum: Some("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed".to_string()),
    };

    assert!(declared_digest(&dist).is_none());
}

#[test]
fn declared_digest_rejects_a_shasum_of_the_wrong_length() {
    // A SHA-1 hex digest is always exactly 40 characters. A truncated
    // shasum must not be silently accepted as a shorter, weaker hash.
    let dist = supply_chain_scanner::ecosystem::npm::packument::Dist {
        tarball: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".to_string(),
        integrity: None,
        shasum: Some("2aae6c35c94fcfb415dbe95f408b9ce91ee846".to_string()), // 39 chars
    };

    assert!(declared_digest(&dist).is_none());
}

#[test]
fn declared_digest_rejects_a_shasum_with_non_hex_characters() {
    let dist = supply_chain_scanner::ecosystem::npm::packument::Dist {
        tarball: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".to_string(),
        integrity: None,
        // 40 characters, but "g" and "!" are not hex digits.
        shasum: Some("gaae6c35c94fcfb415dbe95f408b9ce91ee846!!".to_string()),
    };

    assert!(declared_digest(&dist).is_none());
}

#[test]
fn declared_digest_rejects_a_sha512_payload_of_the_wrong_decoded_length() {
    // Valid sha512- prefix, valid base64, but the decoded payload is only
    // 5 bytes rather than SHA-512's 64. A truncated or corrupted
    // integrity string must not be accepted just because it parses.
    let dist = supply_chain_scanner::ecosystem::npm::packument::Dist {
        tarball: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".to_string(),
        integrity: Some("sha512-c2hvcnQ=".to_string()),
        shasum: Some("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed".to_string()),
    };

    assert!(declared_digest(&dist).is_none());
}

fn three_version_body() -> String {
    r#"{
        "name": "demo",
        "versions": {
            "1.0.0": {
                "version": "1.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"}
            },
            "2.0.0": {
                "version": "2.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-2.0.0.tgz"}
            },
            "3.0.0": {
                "version": "3.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-3.0.0.tgz"}
            }
        },
        "dist-tags": {"latest": "2.0.0"},
        "time": {}
    }"#
    .to_string()
}

#[test]
fn filter_keeps_only_the_named_versions() {
    let packument = parse_packument(&three_version_body()).unwrap();
    let keep = vec!["2.0.0".to_string()];
    let filtered = filter_packument(&packument, &keep, "https://proxy.example/npm");

    let versions = filtered.get("versions").unwrap().as_object().unwrap();
    assert_eq!(versions.len(), 1);
    assert!(versions.contains_key("2.0.0"));
    assert!(!versions.contains_key("1.0.0"));
    assert!(!versions.contains_key("3.0.0"));
}

#[test]
fn filter_rewrites_every_tarball_url_at_the_proxy() {
    let packument = parse_packument(&three_version_body()).unwrap();
    let keep = vec![
        "1.0.0".to_string(),
        "2.0.0".to_string(),
        "3.0.0".to_string(),
    ];
    let filtered = filter_packument(&packument, &keep, "https://proxy.example/npm");

    let versions = filtered.get("versions").unwrap().as_object().unwrap();
    for (version, entry) in versions {
        let tarball = entry
            .get("dist")
            .unwrap()
            .get("tarball")
            .unwrap()
            .as_str()
            .unwrap();
        assert!(!tarball.contains("registry.npmjs.org"));
        assert_eq!(
            tarball,
            format!("https://proxy.example/npm/demo/-/demo-{version}.tgz")
        );
    }
}

#[test]
fn filter_keeps_a_dist_tag_whose_target_survived() {
    let packument = parse_packument(&three_version_body()).unwrap();
    let keep = vec!["1.0.0".to_string(), "2.0.0".to_string()];
    let filtered = filter_packument(&packument, &keep, "https://proxy.example/npm");

    let dist_tags = filtered.get("dist-tags").unwrap().as_object().unwrap();
    assert_eq!(dist_tags.get("latest").unwrap().as_str().unwrap(), "2.0.0");
}

#[test]
fn filter_repoints_latest_when_its_target_was_removed() {
    // latest pointed at 3.0.0 which was filtered out; kept 2.0.0 and 1.0.0
    // => latest == "2.0.0" (newest survivor by semver, not by map order)
    let mut body = three_version_body();
    body = body.replace("\"latest\": \"2.0.0\"", "\"latest\": \"3.0.0\"");
    let packument = parse_packument(&body).unwrap();
    let keep = vec!["1.0.0".to_string(), "2.0.0".to_string()];
    let filtered = filter_packument(&packument, &keep, "https://proxy.example/npm");

    let dist_tags = filtered.get("dist-tags").unwrap().as_object().unwrap();
    assert_eq!(dist_tags.get("latest").unwrap().as_str().unwrap(), "2.0.0");
}

#[test]
fn filter_drops_a_non_latest_tag_whose_target_was_removed() {
    // "beta" -> 3.0.0-beta.1, filtered out => "beta" absent, not repointed
    let body = r#"{
        "name": "demo",
        "versions": {
            "1.0.0": {
                "version": "1.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"}
            },
            "3.0.0-beta.1": {
                "version": "3.0.0-beta.1",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-3.0.0-beta.1.tgz"}
            }
        },
        "dist-tags": {"latest": "1.0.0", "beta": "3.0.0-beta.1"},
        "time": {}
    }"#;
    let packument = parse_packument(body).unwrap();
    let keep = vec!["1.0.0".to_string()];
    let filtered = filter_packument(&packument, &keep, "https://proxy.example/npm");

    let dist_tags = filtered.get("dist-tags").unwrap().as_object().unwrap();
    assert!(!dist_tags.contains_key("beta"));
    assert_eq!(dist_tags.get("latest").unwrap().as_str().unwrap(), "1.0.0");
}

#[test]
fn filter_never_repoints_latest_to_a_prerelease_when_a_final_release_survived() {
    // semver ranks 2.0.0-beta.1 above 1.0.0 (a higher series' prerelease
    // outranks a lower series' final release), so an unfiltered
    // semver-max would repoint `latest` at the prerelease once the real
    // 2.0.0 is filtered out. npm's own convention is that `latest` is
    // never a prerelease, so 1.0.0 — the newest *final* release among the
    // survivors — must win instead.
    let body = r#"{
        "name": "demo",
        "versions": {
            "1.0.0": {
                "version": "1.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"}
            },
            "2.0.0": {
                "version": "2.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-2.0.0.tgz"}
            },
            "2.0.0-beta.1": {
                "version": "2.0.0-beta.1",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-2.0.0-beta.1.tgz"}
            }
        },
        "dist-tags": {"latest": "2.0.0"},
        "time": {}
    }"#;
    let packument = parse_packument(body).unwrap();
    // 2.0.0 (the original `latest` target) is filtered out; both 1.0.0
    // and the 2.0.0 prerelease survive.
    let keep = vec!["1.0.0".to_string(), "2.0.0-beta.1".to_string()];
    let filtered = filter_packument(&packument, &keep, "https://proxy.example/npm");

    let dist_tags = filtered.get("dist-tags").unwrap().as_object().unwrap();
    assert_eq!(
        dist_tags.get("latest").unwrap().as_str().unwrap(),
        "1.0.0",
        "latest must prefer the final release over a semver-higher prerelease"
    );
}

#[test]
fn filter_repoints_latest_to_a_prerelease_when_that_is_the_only_survivor() {
    let body = r#"{
        "name": "demo",
        "versions": {
            "1.0.0": {
                "version": "1.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"}
            },
            "2.0.0-beta.1": {
                "version": "2.0.0-beta.1",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-2.0.0-beta.1.tgz"}
            }
        },
        "dist-tags": {"latest": "1.0.0"},
        "time": {}
    }"#;
    let packument = parse_packument(body).unwrap();
    // Only the prerelease survives.
    let keep = vec!["2.0.0-beta.1".to_string()];
    let filtered = filter_packument(&packument, &keep, "https://proxy.example/npm");

    let dist_tags = filtered.get("dist-tags").unwrap().as_object().unwrap();
    assert_eq!(
        dist_tags.get("latest").unwrap().as_str().unwrap(),
        "2.0.0-beta.1",
        "a prerelease must still be used when it is the only survivor"
    );
}

#[test]
fn filter_with_no_survivors_emits_empty_versions_and_empty_dist_tags() {
    // Review Focus: must be a well-formed document, never an error
    let packument = parse_packument(&three_version_body()).unwrap();
    let keep: Vec<String> = vec![];
    let filtered = filter_packument(&packument, &keep, "https://proxy.example/npm");

    let versions = filtered.get("versions").unwrap().as_object().unwrap();
    assert!(versions.is_empty());
    let dist_tags = filtered.get("dist-tags").unwrap().as_object().unwrap();
    assert!(dist_tags.is_empty());
}

#[test]
fn filter_preserves_the_deprecated_field_on_a_surviving_version() {
    let body = r#"{
        "name": "demo",
        "versions": {
            "1.0.0": {
                "version": "1.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"},
                "deprecated": "use demo2 instead"
            }
        },
        "dist-tags": {"latest": "1.0.0"},
        "time": {}
    }"#;
    let packument = parse_packument(body).unwrap();
    let keep = vec!["1.0.0".to_string()];
    let filtered = filter_packument(&packument, &keep, "https://proxy.example/npm");

    let version_entry = filtered.get("versions").unwrap().get("1.0.0").unwrap();
    assert_eq!(
        version_entry.get("deprecated").unwrap().as_str().unwrap(),
        "use demo2 instead"
    );
}

#[test]
fn parse_then_filter_an_upstream_packument_with_no_versions_object_is_empty_not_an_error() {
    // Review Focus: `{"name":"x"}` parses, filters to empty, does not panic
    let packument = parse_packument(r#"{"name":"x"}"#).unwrap();
    assert_eq!(packument.name, "x");
    assert!(packument.versions.is_empty());

    let keep: Vec<String> = vec![];
    let filtered = filter_packument(&packument, &keep, "https://proxy.example/npm");
    let versions = filtered.get("versions").unwrap().as_object().unwrap();
    assert!(versions.is_empty());
}

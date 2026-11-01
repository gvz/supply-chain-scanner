use supply_chain_scanner::ecosystem::npm::{
    normalize_name, packument_path, tarball_path, validate_name,
};

#[test]
fn validate_accepts_a_plain_name() {
    assert_eq!(validate_name("lodash").unwrap(), "lodash");
}

#[test]
fn validate_accepts_a_scoped_name() {
    assert_eq!(validate_name("@babel/core").unwrap(), "@babel/core");
}

#[test]
fn validate_rejects_a_second_slash() {
    assert!(validate_name("@a/b/c").is_err());
}

#[test]
fn validate_rejects_an_unscoped_slash() {
    assert!(validate_name("a/b").is_err());
}

#[test]
fn validate_rejects_a_leading_dot_or_underscore() {
    assert!(validate_name(".hidden").is_err());
    assert!(validate_name("_internal").is_err());
}

#[test]
fn validate_rejects_path_traversal_and_control_characters() {
    assert!(validate_name("../etc/passwd").is_err());
    assert!(validate_name("foo\nbar").is_err());
    assert!(validate_name("foo\\bar").is_err());
}

#[test]
fn validate_rejects_a_name_over_214_characters() {
    assert!(validate_name(&"a".repeat(215)).is_err());
}

#[test]
fn validate_rejects_a_bare_at_or_empty_scope() {
    assert!(validate_name("@").is_err());
    assert!(validate_name("@/name").is_err());
}

// Regression coverage for the C1 finding: `validate_name` enforced no
// character set at all, so a name carrying a URL-structural character
// passed every other check. Confirmed empirically against the WHATWG URL
// implementation `url` implements: "lodash?x" and "lodash#x" both resolve
// upstream against the real registry host (the query/fragment is simply
// ignored, so the CVE-gate keys on the wrong, unblocked name), and a
// `scheme:host`-shaped name such as "http:evil.example.com" resolves to a
// request against that other host entirely when joined as a relative URL
// reference.
#[test]
fn validate_rejects_a_query_string_appended_to_the_name() {
    assert!(validate_name("lodash?x").is_err());
}

#[test]
fn validate_rejects_a_fragment_appended_to_the_name() {
    assert!(validate_name("lodash#x").is_err());
}

#[test]
fn validate_rejects_a_scheme_shaped_name_that_would_escape_the_registry_host() {
    assert!(validate_name("http:evil.example.com").is_err());
}

#[test]
fn validate_rejects_an_embedded_space() {
    assert!(validate_name("a b").is_err());
}

#[test]
fn validate_rejects_a_percent_encoded_slash() {
    assert!(validate_name("lodash%2fx").is_err());
}

#[test]
fn validate_rejects_an_embedded_at_sign() {
    // Only a single, leading `@` introducing a scope is legal. An `@`
    // anywhere else (here, read by a careless caller as a version pin) is
    // not a character npm permits in a name.
    assert!(validate_name("lodash@1.2.3").is_err());
}

#[test]
fn validate_accepts_a_mixed_case_name_unchanged() {
    // npm stopped accepting *new* uppercase names but still serves
    // grandfathered ones case-sensitively — `JSONStream` is the canonical
    // example and a common transitive dependency. `validate_name`'s
    // contract is to return the name unchanged, not to fold it, so a
    // mixed-case name must validate as-is, not be rejected or lowercased.
    assert_eq!(validate_name("JSONStream").unwrap(), "JSONStream");
    assert_eq!(validate_name("@Babel/core").unwrap(), "@Babel/core");
    assert_eq!(normalize_name("JSONStream"), "jsonstream");
}

#[test]
fn normalize_lowercases_but_folds_nothing() {
    assert_eq!(normalize_name("Lodash"), "lodash");
    assert_eq!(normalize_name("foo_bar"), "foo_bar");
    assert_eq!(normalize_name("foo-bar"), "foo-bar");
    assert_eq!(normalize_name("foo.bar"), "foo.bar");
}

#[test]
fn packument_path_encodes_a_scope_separator() {
    assert_eq!(packument_path("@babel/core"), "@babel%2fcore");
    assert_eq!(packument_path("lodash"), "lodash");
}

#[test]
fn packument_path_preserves_case() {
    // npm serves grandfathered mixed-case names case-sensitively, so
    // lowercasing the path here would 404 against the real registry.
    assert_eq!(packument_path("JSONStream"), "JSONStream");
}

#[test]
fn tarball_path_drops_the_scope_from_the_filename() {
    assert_eq!(
        tarball_path("@babel/core", "7.0.0"),
        "@babel/core/-/core-7.0.0.tgz"
    );
    assert_eq!(
        tarball_path("lodash", "4.17.21"),
        "lodash/-/lodash-4.17.21.tgz"
    );
}

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

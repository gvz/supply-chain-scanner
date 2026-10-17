//! Integration tests for `supply_chain_scanner::ecosystem::pypi::index`
//! (PEP 503 simple-index parsing/rendering and package name validation).

use supply_chain_scanner::ecosystem::pypi::index::{
    normalize_name, parse_filename, parse_simple_page, render_simple_page, validate_package_name,
    IndexEntry,
};
use url::Url;

fn base_url() -> Url {
    Url::parse("https://pypi.org/simple/flask/").expect("valid base url")
}

#[test]
fn normalize_collapses_separators_and_lowercases() {
    assert_eq!(normalize_name("Flask_Thing.X"), "flask-thing-x");
    assert_eq!(normalize_name("already-normal"), "already-normal");
    assert_eq!(normalize_name("multi___sep...run"), "multi-sep-run");
}

#[test]
fn validate_rejects_path_traversal_and_slashes() {
    assert!(validate_package_name("../../etc").is_err());
    assert!(validate_package_name("a/b").is_err());
    assert!(validate_package_name("").is_err());
    assert!(validate_package_name("a\\b").is_err());
}

#[test]
fn validate_rejects_non_ascii_and_control_chars() {
    assert!(validate_package_name("pkg\r\nX").is_err());
    assert!(validate_package_name("pké").is_err());
}

#[test]
fn validate_accepts_and_normalizes_a_plain_name() {
    let normalized = validate_package_name("Flask_Thing").expect("valid name");
    assert_eq!(normalized, "flask-thing");
}

#[test]
fn parse_page_extracts_filename_url_and_sha256() {
    let html = r#"
        <!DOCTYPE html>
        <html><body>
        <a href="https://files.pythonhosted.org/packages/flask/Flask-2.0.0-py3-none-any.whl#sha256=abc123">Flask-2.0.0-py3-none-any.whl</a>
        </body></html>
    "#;
    let entries = parse_simple_page(html, &base_url()).expect("page parses");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.filename, "Flask-2.0.0-py3-none-any.whl");
    assert_eq!(
        entry.url.as_str(),
        "https://files.pythonhosted.org/packages/flask/Flask-2.0.0-py3-none-any.whl"
    );
    assert_eq!(entry.sha256, Some("abc123".to_string()));
}

#[test]
fn parse_page_entry_without_fragment_has_none_sha256() {
    let html = r#"
        <a href="https://files.pythonhosted.org/packages/flask/Flask-2.0.0.tar.gz">Flask-2.0.0.tar.gz</a>
    "#;
    let entries = parse_simple_page(html, &base_url()).expect("page parses");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].sha256, None);
}

#[test]
fn parse_page_extracts_pep658_metadata_attribute() {
    let html_core = r#"
        <a href="https://files.pythonhosted.org/packages/flask/Flask-2.0.0-py3-none-any.whl#sha256=abc123"
           data-core-metadata="sha256=def456">Flask-2.0.0-py3-none-any.whl</a>
    "#;
    let entries = parse_simple_page(html_core, &base_url()).expect("page parses");
    assert_eq!(entries[0].metadata_hash, Some("sha256=def456".to_string()));

    let html_dist_info = r#"
        <a href="https://files.pythonhosted.org/packages/flask/Flask-2.0.0-py3-none-any.whl"
           data-dist-info-metadata="true">Flask-2.0.0-py3-none-any.whl</a>
    "#;
    let entries = parse_simple_page(html_dist_info, &base_url()).expect("page parses");
    assert_eq!(entries[0].metadata_hash, Some("true".to_string()));
}

#[test]
fn parse_page_extracts_requires_python_and_yanked() {
    let html = r#"
        <a href="https://files.pythonhosted.org/packages/flask/Flask-2.0.0-py3-none-any.whl"
           data-requires-python="&gt;=3.6"
           data-yanked="broken build">Flask-2.0.0-py3-none-any.whl</a>
    "#;
    let entries = parse_simple_page(html, &base_url()).expect("page parses");
    assert_eq!(entries[0].requires_python, Some(">=3.6".to_string()));
    assert_eq!(entries[0].yanked, Some("broken build".to_string()));
}

#[test]
fn parse_page_without_yanked_attribute_has_none() {
    let html = r#"
        <a href="https://files.pythonhosted.org/packages/flask/Flask-2.0.0-py3-none-any.whl">Flask-2.0.0-py3-none-any.whl</a>
    "#;
    let entries = parse_simple_page(html, &base_url()).expect("page parses");
    assert_eq!(entries[0].yanked, None);
    assert_eq!(entries[0].requires_python, None);
    assert_eq!(entries[0].metadata_hash, None);
}

#[test]
fn render_then_parse_round_trips_entries() {
    let base = base_url();
    let entries = vec![
        IndexEntry {
            filename: "Flask-2.0.0-py3-none-any.whl".to_string(),
            url: Url::parse(
                "https://files.pythonhosted.org/packages/flask/Flask-2.0.0-py3-none-any.whl",
            )
            .unwrap(),
            sha256: Some("abc123".to_string()),
            requires_python: Some(">=3.6".to_string()),
            metadata_hash: Some("sha256=def456".to_string()),
            yanked: None,
        },
        IndexEntry {
            filename: "Flask \"Special\" & <Weird>'Name'-2.0.0.tar.gz".to_string(),
            url: Url::parse("https://files.pythonhosted.org/packages/flask/weird.tar.gz").unwrap(),
            sha256: None,
            requires_python: None,
            metadata_hash: None,
            yanked: Some("security issue".to_string()),
        },
        IndexEntry {
            filename: "Flask-1.0.0.tar.gz".to_string(),
            url: Url::parse("https://files.pythonhosted.org/packages/flask/Flask-1.0.0.tar.gz")
                .unwrap(),
            sha256: None,
            requires_python: None,
            metadata_hash: None,
            yanked: Some(String::new()),
        },
    ];

    let rendered = render_simple_page("flask", &entries);
    let parsed = parse_simple_page(&rendered, &base).expect("rendered page parses");

    assert_eq!(parsed, entries);
}

#[test]
fn parse_filename_reads_wheel_name() {
    let parsed = parse_filename("requests-2.31.0-py3-none-any.whl").expect("parses wheel");
    assert_eq!(parsed.package, "requests");
    assert_eq!(parsed.version, "2.31.0");
    assert!(parsed.is_wheel);
}

#[test]
fn parse_filename_reads_sdist_name() {
    let parsed = parse_filename("requests-2.31.0.tar.gz").expect("parses sdist");
    assert_eq!(parsed.package, "requests");
    assert_eq!(parsed.version, "2.31.0");
    assert!(!parsed.is_wheel);
}

#[test]
fn parse_filename_reads_sdist_name_with_hyphenated_package() {
    let parsed = parse_filename("scikit-learn-1.2.3.tar.gz").expect("parses sdist");
    assert_eq!(parsed.package, "scikit-learn");
    assert_eq!(parsed.version, "1.2.3");
    assert!(!parsed.is_wheel);
}

#[test]
fn parse_filename_rejects_unknown_extension() {
    assert!(parse_filename("requests-2.31.0.zip").is_none());
    assert!(parse_filename("malware.exe").is_none());
    assert!(parse_filename("no-extension-at-all").is_none());
}

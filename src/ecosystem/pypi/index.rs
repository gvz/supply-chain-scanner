//! PEP 503 "simple" index pages: parsing what upstream PyPI serves,
//! rendering a filtered page back to pip, and validating/normalizing
//! package names.
//!
//! This module is pure: no I/O, no network, no database. The HTML is
//! parsed with a small hand-rolled scan over `<a>` tags rather than a
//! general-purpose HTML parser — PEP 503 fixes the page shape to a flat
//! list of anchors with a handful of `data-*` attributes, so a focused
//! parser is both sufficient and avoids pulling in a full HTML/CSS
//! selector engine for a format this constrained.

use std::collections::HashMap;
use std::fmt;

use anyhow::{bail, Context, Result};
use url::Url;

/// One artifact offered by a PEP 503 simple index page.
///
/// Fields mirror exactly what PEP 503 (and its extensions, PEP 592 yanking
/// and PEP 658/714 metadata hashes) allow upstream to attach to an anchor.
/// `url` never carries the `#sha256=...` fragment: that hash, when present,
/// is split out into `sha256` so callers can use it directly for
/// verification (task 10) without re-parsing the URL.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexEntry {
    pub filename: String,
    pub url: Url,
    pub sha256: Option<String>,
    pub requires_python: Option<String>,
    pub metadata_hash: Option<String>,
    pub yanked: Option<String>,
}

/// A package/version/kind triple read out of an artifact filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedArtifact {
    pub package: String,
    pub version: String,
    pub is_wheel: bool,
}

/// A package name that failed [`validate_package_name`]'s checks.
///
/// Carries a human-readable reason for logging/diagnostics, not for
/// exposing to untrusted clients (the name itself is untrusted input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidName {
    pub reason: String,
}

impl fmt::Display for InvalidName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid package name: {}", self.reason)
    }
}

impl std::error::Error for InvalidName {}

fn invalid(reason: &str) -> InvalidName {
    InvalidName {
        reason: reason.to_string(),
    }
}

/// Normalizes a package name per PEP 503: runs of `-`, `_`, `.` collapse to
/// a single `-`, then the whole name is lowercased.
///
/// This is a pure string transform with no validation; see
/// [`validate_package_name`] for the security-sensitive entry point that
/// should be used on names arriving from untrusted input (e.g. a URL
/// path).
pub fn normalize_name(name: &str) -> String {
    let mut collapsed = String::with_capacity(name.len());
    let mut prev_was_sep = false;
    for ch in name.chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !prev_was_sep {
                collapsed.push('-');
            }
            prev_was_sep = true;
        } else {
            collapsed.push(ch);
            prev_was_sep = false;
        }
    }
    collapsed.to_lowercase()
}

/// Validates a package name arriving from untrusted input (a URL path
/// segment) and returns it normalized on success.
///
/// This is a security boundary: the name goes on to become part of
/// upstream HTTP requests and filesystem cache paths, so this function
/// rejects rather than sanitizes anything that could escape its intended
/// context — path traversal (`..`), path separators (`/`, `\`), the empty
/// string, non-ASCII characters, and ASCII control characters (which
/// includes CR and LF, the bytes that would otherwise let a crafted name
/// inject extra HTTP header lines or a forged refusal-reason phrase).
pub fn validate_package_name(name: &str) -> Result<String, InvalidName> {
    if name.is_empty() {
        return Err(invalid("name is empty"));
    }
    if !name.is_ascii() {
        return Err(invalid("name contains non-ASCII characters"));
    }
    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(invalid(
            "name contains ASCII control characters (including CR/LF)",
        ));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(invalid("name contains a path separator"));
    }
    if name.contains("..") {
        return Err(invalid("name contains a path traversal sequence (..)"));
    }

    let normalized = normalize_name(name);
    if normalized.is_empty() || normalized.chars().all(|c| c == '-') {
        return Err(invalid("name has no valid characters after normalization"));
    }
    Ok(normalized)
}

/// Escapes text for safe inclusion in HTML attribute values and element
/// text content.
fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Decodes the small set of HTML entities this module's own
/// [`escape_html`] can produce, plus numeric character references.
/// Anything unrecognized (or missing its terminating `;`) is left as
/// literal text rather than guessed at.
fn decode_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp_idx) = rest.find('&') {
        out.push_str(&rest[..amp_idx]);
        let after_amp = &rest[amp_idx + 1..];
        if let Some(semi_idx) = after_amp.find(';') {
            let entity = &after_amp[..semi_idx];
            if let Some(decoded) = decode_one_entity(entity) {
                out.push(decoded);
                rest = &after_amp[semi_idx + 1..];
                continue;
            }
        }
        out.push('&');
        rest = after_amp;
    }
    out.push_str(rest);
    out
}

fn decode_one_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let digits = entity.strip_prefix('#')?;
            let code = if let Some(hex) = digits
                .strip_prefix('x')
                .or_else(|| digits.strip_prefix('X'))
            {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                digits.parse::<u32>().ok()?
            };
            char::from_u32(code)
        }
    }
}

/// Finds the start (`<`) of the next `<a` tag at or after `from`, using a
/// pre-lowercased copy of the page so matching is case-insensitive.
/// `to_ascii_lowercase` only touches ASCII letters, so byte offsets stay
/// aligned with the original string.
fn find_anchor_open(lower: &str, from: usize) -> Option<usize> {
    let mut search_from = from;
    while let Some(idx) = lower[search_from..].find("<a") {
        let abs = search_from + idx;
        let after = abs + 2;
        match lower[after..].chars().next() {
            Some(c) if c.is_whitespace() || c == '>' || c == '/' => return Some(abs),
            None => return Some(abs),
            _ => search_from = after,
        }
    }
    None
}

/// From the `<` of an opening `<a` tag, finds the unquoted `>` that
/// terminates it and returns the attribute text plus the index just past
/// the `>`.
fn find_tag_end(html: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = html.as_bytes();
    let mut i = start + 2; // skip "<a"
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == b'\'' || c == b'"' {
                    quote = Some(c);
                } else if c == b'>' {
                    return Some((&html[start + 2..i], i + 1));
                }
            }
        }
        i += 1;
    }
    None
}

/// From just past an opening tag's `>`, finds the matching `</a...>` and
/// returns the inner text plus the index just past the closing tag.
fn find_anchor_text<'a>(html: &'a str, lower: &str, tag_end: usize) -> Option<(&'a str, usize)> {
    let close_rel = lower[tag_end..].find("</a")?;
    let close_start = tag_end + close_rel;
    let after_marker = close_start + 3; // skip "</a"
    let gt_rel = html[after_marker..].find('>')?;
    let close_end = after_marker + gt_rel + 1;
    Some((&html[tag_end..close_start], close_end))
}

/// Parses a tag's attribute text into a case-insensitive name -> value
/// map. An attribute with no `=value` (a bare boolean attribute, e.g.
/// `data-yanked`) maps to `None`; an attribute with a value maps to
/// `Some(raw value)` (not yet entity-decoded).
fn parse_attributes(attrs_str: &str) -> HashMap<String, Option<String>> {
    let mut attrs = HashMap::new();
    let chars: Vec<char> = attrs_str.chars().collect();
    let n = chars.len();
    let mut i = 0;

    while i < n {
        while i < n && (chars[i].is_whitespace() || chars[i] == '/') {
            i += 1;
        }
        if i >= n {
            break;
        }

        let name_start = i;
        while i < n && chars[i] != '=' && !chars[i].is_whitespace() && chars[i] != '/' {
            i += 1;
        }
        let name: String = chars[name_start..i]
            .iter()
            .collect::<String>()
            .to_ascii_lowercase();
        if name.is_empty() {
            i += 1;
            continue;
        }

        while i < n && chars[i].is_whitespace() {
            i += 1;
        }

        if i < n && chars[i] == '=' {
            i += 1;
            while i < n && chars[i].is_whitespace() {
                i += 1;
            }
            if i < n && (chars[i] == '"' || chars[i] == '\'') {
                let quote = chars[i];
                i += 1;
                let value_start = i;
                while i < n && chars[i] != quote {
                    i += 1;
                }
                let value: String = chars[value_start..i].iter().collect();
                if i < n {
                    i += 1; // skip closing quote
                }
                attrs.insert(name, Some(value));
            } else {
                let value_start = i;
                while i < n && !chars[i].is_whitespace() {
                    i += 1;
                }
                let value: String = chars[value_start..i].iter().collect();
                attrs.insert(name, Some(value));
            }
        } else {
            attrs.insert(name, None);
        }
    }

    attrs
}

/// Parses a PEP 503 simple index page into its list of artifact entries.
///
/// `base` is the URL the page was fetched from; relative `href`s are
/// resolved against it, matching how a browser (and pip) would interpret
/// them. A page this function cannot make sense of is an error, never a
/// silently-empty `Ok(vec![])` — an artifact that fails to parse must not
/// be treated as "upstream offered nothing" and let through unexamined.
pub fn parse_simple_page(html: &str, base: &Url) -> Result<Vec<IndexEntry>> {
    let lower = html.to_ascii_lowercase();
    let mut entries = Vec::new();
    let mut pos = 0usize;

    while let Some(start) = find_anchor_open(&lower, pos) {
        let (attrs_str, tag_end) =
            find_tag_end(html, start).context("unterminated <a> tag in simple index page")?;
        let (inner_text, next_pos) = find_anchor_text(html, &lower, tag_end)
            .context("missing closing </a> tag in simple index page")?;
        pos = next_pos;

        let attrs = parse_attributes(attrs_str);

        let raw_href = attrs
            .get("href")
            .and_then(|v| v.clone())
            .context("<a> tag in simple index page is missing an href attribute")?;
        let href = decode_entities(&raw_href);
        let mut url = base
            .join(&href)
            .with_context(|| format!("resolving href {href:?} against base {base}"))?;

        let mut sha256 = None;
        if let Some(fragment) = url.fragment() {
            if let Some(hash) = fragment.strip_prefix("sha256=") {
                sha256 = Some(hash.to_string());
                url.set_fragment(None);
            }
        }

        let filename = decode_entities(inner_text.trim());
        if filename.is_empty() {
            bail!("<a> tag in simple index page has empty filename text");
        }

        let requires_python = attrs
            .get("data-requires-python")
            .and_then(|v| v.clone())
            .map(|v| decode_entities(&v));
        let yanked = attrs
            .get("data-yanked")
            .map(|v| decode_entities(v.as_deref().unwrap_or("")));
        let metadata_hash = attrs
            .get("data-core-metadata")
            .or_else(|| attrs.get("data-dist-info-metadata"))
            .map(|v| decode_entities(v.as_deref().unwrap_or("true")));

        entries.push(IndexEntry {
            filename,
            url,
            sha256,
            requires_python,
            metadata_hash,
            yanked,
        });
    }

    Ok(entries)
}

/// Renders a PEP 503 minimal simple index page for `package` from
/// `entries`.
///
/// This is served directly to pip (task 12 filters `entries` down to the
/// clean ones first), so every piece of untrusted text — filenames and
/// URLs alike — is HTML-escaped, and `data-requires-python`,
/// `data-yanked`, and the PEP 658/714 metadata attribute are re-emitted
/// whenever upstream supplied them, so pip's own resolver logic keeps
/// seeing exactly what upstream offered.
pub fn render_simple_page(package: &str, entries: &[IndexEntry]) -> String {
    let escaped_package = escape_html(package);
    let mut page = String::new();
    page.push_str("<!DOCTYPE html>\n<html>\n  <head>\n");
    page.push_str("    <meta name=\"pypi:repository-version\" content=\"1.0\">\n");
    page.push_str(&format!("    <title>Links for {escaped_package}</title>\n"));
    page.push_str("  </head>\n  <body>\n");
    page.push_str(&format!("    <h1>Links for {escaped_package}</h1>\n"));

    for entry in entries {
        let mut href = entry.url.to_string();
        if let Some(sha256) = &entry.sha256 {
            href.push_str("#sha256=");
            href.push_str(sha256);
        }

        page.push_str("    <a href=\"");
        page.push_str(&escape_html(&href));
        page.push('"');

        if let Some(requires_python) = &entry.requires_python {
            page.push_str(" data-requires-python=\"");
            page.push_str(&escape_html(requires_python));
            page.push('"');
        }
        if let Some(yanked) = &entry.yanked {
            page.push_str(" data-yanked=\"");
            page.push_str(&escape_html(yanked));
            page.push('"');
        }
        if let Some(metadata_hash) = &entry.metadata_hash {
            page.push_str(" data-core-metadata=\"");
            page.push_str(&escape_html(metadata_hash));
            page.push('"');
        }

        page.push('>');
        page.push_str(&escape_html(&entry.filename));
        page.push_str("</a>\n");
    }

    page.push_str("  </body>\n</html>\n");
    page
}

/// Reads the package, version, and artifact kind out of an artifact
/// filename. Returns `None` for anything that isn't a recognized wheel
/// (`.whl`) or sdist (`.tar.gz`) filename — never a best-guess parse of an
/// extension this proxy doesn't otherwise handle.
pub fn parse_filename(filename: &str) -> Option<ParsedArtifact> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        // Wheel filenames are `{name}-{version}-{build tag}?-{python
        // tag}-{abi tag}-{platform tag}.whl`; only the first two
        // hyphen-delimited fields are needed here.
        let mut parts = stem.splitn(3, '-');
        let package = parts.next()?;
        let version = parts.next()?;
        if package.is_empty() || version.is_empty() {
            return None;
        }
        return Some(ParsedArtifact {
            package: package.to_string(),
            version: version.to_string(),
            is_wheel: true,
        });
    }

    if let Some(stem) = filename.strip_suffix(".tar.gz") {
        // Sdist filenames are `{name}-{version}.tar.gz`; the package name
        // may itself contain hyphens, but normalized versions do not, so
        // splitting on the *last* hyphen correctly isolates the version.
        let (package, version) = stem.rsplit_once('-')?;
        if package.is_empty() || version.is_empty() {
            return None;
        }
        return Some(ParsedArtifact {
            package: package.to_string(),
            version: version.to_string(),
            is_wheel: false,
        });
    }

    None
}

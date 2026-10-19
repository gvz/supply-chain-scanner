//! The cargo sparse index: per-crate path layout, crate-name validation,
//! and parsing of one crate's index file.
//!
//! This module is pure. It has no I/O, no network, and no database. The
//! sparse index serves one plain-text file per crate, with one JSON object
//! per published version on its own line (the "JSON lines" format). The
//! path of that file depends on the crate name, by the rule the Cargo Book
//! documents.
//!
//! Names are ASCII by rule. crates.io accepts only ASCII letters, ASCII
//! digits, `-`, and `_` in a name, and the name must start with a letter.

use std::fmt;

use anyhow::{Context, Result};
use serde::Deserialize;

/// The longest crate name crates.io accepts, in characters.
///
/// crates.io enforces this limit when a crate is published. This proxy
/// rejects longer names rather than pass them upstream.
const MAX_NAME_LEN: usize = 64;

/// One published version of a crate, as one line of the crate's index
/// file.
///
/// Only the fields this proxy needs are declared. The index line also
/// carries `deps`, `features`, `links`, and other fields. Serde ignores
/// fields a struct does not declare, so an upstream that adds a field does
/// not break this parser.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CargoIndexEntry {
    /// The crate name as upstream published it.
    pub name: String,
    /// The version, as a SemVer string.
    pub vers: String,
    /// The lowercase hex SHA-256 of the `.crate` file.
    pub cksum: String,
    /// True if the author yanked this version. Absent means false.
    #[serde(default)]
    pub yanked: bool,
}

/// A crate name that failed [`validate_name`]'s checks.
///
/// It carries a reason for logs and diagnostics. Do not show it to
/// untrusted clients: the name it describes is untrusted input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidName {
    pub reason: String,
}

impl fmt::Display for InvalidName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid crate name: {}", self.reason)
    }
}

impl std::error::Error for InvalidName {}

fn invalid(reason: &str) -> InvalidName {
    InvalidName {
        reason: reason.to_string(),
    }
}

/// Returns the index directory prefix for `name`, without the name.
///
/// The sparse index puts a crate's file in a directory that comes from the
/// first characters of the name. This function returns that directory, so
/// a `dl` template's `{prefix}` marker can use it directly:
///
/// - one character (`a`) goes in `1/`
/// - two characters (`ab`) go in `2/`
/// - three characters (`abc`) go in `3/a/`
/// - four or more (`cargo`) go in `ca/rg/`
///
/// Call [`crate::ecosystem::cargo::normalize_name`] first. This function
/// does no case folding. It counts characters, not bytes, so any string
/// input is safe. crates.io names are ASCII, which makes the two counts
/// equal for real input.
///
/// An empty name has no prefix. It returns `""`, and the caller's own path
/// then ends up malformed, which [`validate_name`] rejects before it gets
/// this far.
pub(crate) fn prefix_for(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    match chars.len() {
        0 => String::new(),
        1 => "1".to_string(),
        2 => "2".to_string(),
        3 => format!("3/{}", chars[0]),
        _ => format!("{}{}/{}{}", chars[0], chars[1], chars[2], chars[3]),
    }
}

/// Returns the sparse-index path of `name`'s crate file, for example
/// `ca/rg/cargo`.
///
/// The path is relative to the sparse index root. Join it onto the index
/// base URL to get the file's URL. Call
/// [`crate::ecosystem::cargo::normalize_name`] first. This function does no
/// case folding.
pub fn index_path_for(name: &str) -> String {
    let prefix = prefix_for(name);
    if prefix.is_empty() {
        return String::new();
    }
    format!("{prefix}/{name}")
}

/// Validates a crate name from untrusted input and returns it unchanged on
/// success.
///
/// This is a security boundary. The name becomes part of upstream HTTP
/// requests and of filesystem paths. So this function rejects anything that
/// could escape its context, and it does not sanitize. It rejects:
///
/// - the empty string, and names longer than [`MAX_NAME_LEN`]
/// - non-ASCII characters, including ASCII control characters (CR and LF
///   can inject HTTP header lines into a request)
/// - path separators (`/`, `\`) and the traversal sequence `..`
/// - a first character that is not an ASCII letter
/// - any character that is not an ASCII letter, digit, `-`, or `_`
///
/// The name is returned as given, not normalized. Normalize it separately
/// with [`crate::ecosystem::cargo::normalize_name`] when you need the
/// canonical form.
pub fn validate_name(name: &str) -> Result<String, InvalidName> {
    if name.is_empty() {
        return Err(invalid("name is empty"));
    }
    if !name.is_ascii() {
        return Err(invalid("name contains non-ASCII characters"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(invalid("name is longer than 64 characters"));
    }
    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(invalid(
            "name contains ASCII control characters (including CR/LF)",
        ));
    }
    // Checked before the character-class check so the reason names the real
    // risk. `/` and `\` would also fail that check, but as "disallowed
    // character", which hides what a caller has to fix.
    if name.contains('/') || name.contains('\\') {
        return Err(invalid("name contains a path separator"));
    }
    if name.contains("..") {
        return Err(invalid("name contains a path traversal sequence (..)"));
    }
    if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return Err(invalid("name does not start with an ASCII letter"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(invalid(
            "name contains a character that is not a letter, digit, '-' or '_'",
        ));
    }
    Ok(name.to_string())
}

/// Parses the body of a crate's sparse-index file into its version
/// entries.
///
/// The body has one JSON object per line. Empty lines are skipped, so a
/// trailing newline is permitted. A line that is not valid JSON is an
/// error, never a silently empty result: a version that fails to parse
/// must not look like "upstream published nothing".
pub fn parse_index_lines(body: &str) -> Result<Vec<CargoIndexEntry>> {
    let mut entries = Vec::new();
    for (index, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<CargoIndexEntry>(line)
            .with_context(|| format!("parsing cargo index line {}", index + 1))?;
        entries.push(entry);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::{index_path_for, parse_index_lines, validate_name};

    #[test]
    fn a_one_character_name_uses_the_1_prefix() {
        assert_eq!(index_path_for("a"), "1/a");
    }

    #[test]
    fn a_two_character_name_uses_the_2_prefix() {
        assert_eq!(index_path_for("ab"), "2/ab");
    }

    #[test]
    fn a_three_character_name_uses_the_3_prefix_plus_first_letter() {
        assert_eq!(index_path_for("abc"), "3/a/abc");
    }

    #[test]
    fn a_longer_name_uses_the_first_four_characters_as_two_two_character_prefixes() {
        assert_eq!(index_path_for("cargo"), "ca/rg/cargo");
    }

    #[test]
    fn validate_name_accepts_an_ordinary_name() {
        assert_eq!(validate_name("serde_json").unwrap(), "serde_json");
    }

    #[test]
    fn validate_name_rejects_a_name_with_a_disallowed_character() {
        assert!(validate_name("serde/json").is_err());
    }

    #[test]
    fn validate_name_rejects_a_name_not_starting_with_a_letter() {
        assert!(validate_name("1crate").is_err());
    }

    #[test]
    fn parses_one_json_line_per_version_ignoring_unknown_fields() {
        let body = "{\"name\":\"demo\",\"vers\":\"1.0.0\",\"cksum\":\"deadbeef\",\"yanked\":false,\"deps\":[]}\n\
                    {\"name\":\"demo\",\"vers\":\"1.1.0\",\"cksum\":\"abc123\",\"yanked\":true,\"deps\":[]}\n";
        let entries = parse_index_lines(body).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].vers, "1.1.0");
        assert!(entries[1].yanked);
    }
}

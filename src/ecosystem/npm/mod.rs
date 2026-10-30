//! npm/npmjs.com ecosystem support.
//!
//! This module is pure. It has no I/O, no network, and no database. It provides
//! validation of npm package names, path building for registry operations, and
//! normalization for lookups.
//!
//! npm package names are either plain (unscoped) or scoped. An unscoped name
//! is a plain identifier like `lodash`. A scoped name is `@scope/name`, where
//! the scope groups related packages.

use std::fmt;

/// The longest npm package name the registry accepts, in characters.
const MAX_NAME_LEN: usize = 214;

/// A package name that failed [`validate_name`]'s checks.
///
/// It carries a reason for logs and diagnostics. Do not show it to
/// untrusted clients: the name it describes is untrusted input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidName {
    pub reason: String,
}

impl fmt::Display for InvalidName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid npm package name: {}", self.reason)
    }
}

impl std::error::Error for InvalidName {}

fn invalid(reason: &str) -> InvalidName {
    InvalidName {
        reason: reason.to_string(),
    }
}

/// Validates a package name from untrusted input and returns it unchanged on
/// success.
///
/// This is a security boundary. The name becomes part of upstream HTTP
/// requests and of filesystem paths. So this function rejects anything that
/// could escape its context, and it does not sanitize. It rejects:
///
/// - the empty string, and names longer than [`MAX_NAME_LEN`]
/// - non-ASCII characters, including ASCII control characters (CR and LF
///   can inject HTTP header lines into a request)
/// - path traversal sequences (`..`), path separators (`/`, `\`)
/// - a leading `.` or `_` in the name or scope
/// - a bare `@` without a scope, or an empty scope in a scoped name
/// - any `/` except the single scope separator in a scoped name (one starting
///   with `@`)
///
/// The name is returned as given, not normalized. Normalize it separately
/// with [`normalize_name`] when you need the canonical form.
pub fn validate_name(name: &str) -> Result<String, InvalidName> {
    // Check basic constraints first
    if name.is_empty() {
        return Err(invalid("name is empty"));
    }
    if !name.is_ascii() {
        return Err(invalid("name contains non-ASCII characters"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(invalid("name is longer than 214 characters"));
    }
    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(invalid(
            "name contains ASCII control characters (including CR/LF)",
        ));
    }

    // Checked before the character-class or format check so the reason names
    // the real risk. These would also fail other checks, but as "disallowed
    // character" or "invalid format", which hides what a caller has to fix.
    if name.contains("..") {
        return Err(invalid("name contains a path traversal sequence (..)"));
    }
    if name.contains('\\') {
        return Err(invalid("name contains a path separator (\\)"));
    }

    // Determine if scoped or unscoped
    if name.starts_with('@') {
        // Scoped name: must be @scope/name format
        if name == "@" {
            return Err(invalid("bare @ without scope"));
        }

        // Scoped names must have exactly one /
        let slash_count = name.matches('/').count();
        if slash_count == 0 {
            return Err(invalid("scoped name must have the @scope/name format"));
        }
        if slash_count > 1 {
            return Err(invalid("scoped name can have at most one /"));
        }

        let slash_pos = name.find('/').unwrap();
        let scope = &name[1..slash_pos];
        let pkg_name = &name[slash_pos + 1..];

        // Scope and package name can't be empty
        if scope.is_empty() {
            return Err(invalid("scope is empty"));
        }
        if pkg_name.is_empty() {
            return Err(invalid("package name is empty"));
        }

        // Scope and package name can't start with . or _
        if scope.starts_with('.') || scope.starts_with('_') {
            return Err(invalid("scope starts with . or _"));
        }
        if pkg_name.starts_with('.') || pkg_name.starts_with('_') {
            return Err(invalid("package name starts with . or _"));
        }
    } else {
        // Unscoped name: must not contain / and can't start with . or _
        if name.contains('/') {
            return Err(invalid("unscoped name cannot contain /"));
        }

        if name.starts_with('.') || name.starts_with('_') {
            return Err(invalid("name starts with . or _"));
        }
    }

    Ok(name.to_string())
}

/// Returns the name normalized for lookup: lowercase only.
///
/// npm does not fold `-`, `_`, or `.` into each other, unlike some other
/// registries. `foo-bar` and `foo_bar` are different packages. This function
/// lowercases the name and leaves all other characters unchanged.
///
/// Use this for every keyed lookup that must find a package regardless of how
/// the caller spelled the case: advisory mirrors, audit stores, and stored
/// verdicts.
pub fn normalize_name(name: &str) -> String {
    name.to_lowercase()
}

/// Returns the registry path for a package's metadata (packument), with `/`
/// percent-encoded.
///
/// The npm registry serves a package's metadata at a path like
/// `/@scope%2fname` for scoped packages and `/lodash` for unscoped packages.
/// The `/` in the scope separator must be percent-encoded as `%2f` in URLs
/// and filesystem paths.
pub fn packument_path(name: &str) -> String {
    name.replace('/', "%2f")
}

/// Returns the path to a package's tarball in the registry.
///
/// npm tarballs are addressed as `{name}/-/{unscoped}-{version}.tgz`, where
/// `unscoped` is the package name with any `@scope/` prefix removed. For
/// example, `@babel/core@7.0.0` is at `@babel/core/-/core-7.0.0.tgz`.
pub fn tarball_path(name: &str, version: &str) -> String {
    // Remove @scope/ prefix if present
    let unscoped = if let Some(slash_pos) = name.find('/') {
        &name[slash_pos + 1..]
    } else {
        name
    };

    format!("{name}/-/{unscoped}-{version}.tgz")
}

#[cfg(test)]
mod tests {
    use super::{normalize_name, packument_path, tarball_path, validate_name};

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
}

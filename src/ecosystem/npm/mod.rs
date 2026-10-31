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

pub mod packument;
pub mod upstream;

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

/// Whether `c` is a character npm permits inside a name's body (the part
/// after an optional leading `@` and scope separator): lowercase ASCII
/// letters, digits, and `-` `_` `.` `~`. Nothing else is a legal npm
/// package name character, so anything outside this set is also not
/// URL-safe as a path segment — `?` `#` `%` `&` `=` `:` space and every
/// other ASCII punctuation character are all excluded.
fn is_npm_name_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.' | '~')
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
/// - any character in the name or scope body outside npm's own legal set:
///   lowercase ASCII letters, digits, `-`, `_`, `.`, `~` (see
///   [`is_npm_name_char`]). This is what stops a name like `lodash?x` or
///   `http:evil.example.com` from reaching [`crate::ecosystem::npm::upstream::NpmUpstream::packument`]'s
///   `Url::join`, where a character such as `?`, `#`, or a `:`-led scheme
///   would be interpreted by the URL parser rather than treated as a
///   literal path segment. An uppercase letter is rejected here too,
///   deliberately: npm names are lowercase at the registry, but this
///   function's contract is to return the name unchanged, not to fold it —
///   that is [`normalize_name`]'s job, kept separate on purpose.
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

        // Charset check last: every more specific check above gives a
        // precise reason first, so a traversal or leading-dot name is
        // never reported as merely "disallowed character".
        if let Some(c) = scope.chars().find(|c| !is_npm_name_char(*c)) {
            return Err(invalid(&format!(
                "scope contains a character npm does not allow in a package name: {c:?}"
            )));
        }
        if let Some(c) = pkg_name.chars().find(|c| !is_npm_name_char(*c)) {
            return Err(invalid(&format!(
                "package name contains a character npm does not allow in a package name: {c:?}"
            )));
        }
    } else {
        // Unscoped name: must not contain / and can't start with . or _
        if name.contains('/') {
            return Err(invalid("unscoped name cannot contain /"));
        }

        if name.starts_with('.') || name.starts_with('_') {
            return Err(invalid("name starts with . or _"));
        }

        // Charset check last, for the same reason as the scoped branch
        // above.
        if let Some(c) = name.chars().find(|c| !is_npm_name_char(*c)) {
            return Err(invalid(&format!(
                "name contains a character npm does not allow in a package name: {c:?}"
            )));
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
///
/// Requires `name` to have already passed [`validate_name`]. This function
/// does nothing to confirm that: it only replaces `/`, and the result is
/// joined onto the registry base as a relative URL reference by
/// [`crate::ecosystem::npm::upstream::NpmUpstream::packument`], not treated
/// as an opaque path segment. A `name` carrying `?`, `#`, a `:`-led scheme,
/// or any other character [`validate_name`]'s charset check would reject
/// can therefore change the request's query, fragment, or host entirely.
/// Callers must validate first.
pub fn packument_path(name: &str) -> String {
    name.replace('/', "%2f")
}

/// Returns the path to a package's tarball in the registry.
///
/// npm tarballs are addressed as `{name}/-/{unscoped}-{version}.tgz`, where
/// `unscoped` is the package name with any `@scope/` prefix removed. For
/// example, `@babel/core@7.0.0` is at `@babel/core/-/core-7.0.0.tgz`.
///
/// Requires `name` to have already passed [`validate_name`]. The result is
/// concatenated, unescaped, into the `dist.tarball` URL
/// [`crate::ecosystem::npm::packument::filter_packument`] serves back to
/// npm, so an unvalidated `name` carrying `?`, `#`, or other URL-structural
/// characters could alter that URL's query or fragment rather than merely
/// naming a bad path.
pub fn tarball_path(name: &str, version: &str) -> String {
    // Remove @scope/ prefix if present
    let unscoped = if let Some(slash_pos) = name.find('/') {
        &name[slash_pos + 1..]
    } else {
        name
    };

    format!("{name}/-/{unscoped}-{version}.tgz")
}

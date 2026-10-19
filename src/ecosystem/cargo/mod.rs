//! Cargo/crates.io ecosystem support.

pub mod index;
pub mod upstream;

/// Normalizes a crate name the way crates.io does: lowercase it, then
/// replace every `_` with `-`.
///
/// This mirrors crates.io's own name-collision rule (`serde_json` and
/// `serde-json` name the same crate), which is *not* PEP 503: it does not
/// collapse runs of `-`/`_`/`.` or touch dots at all.
pub fn normalize_name(name: &str) -> String {
    name.to_lowercase().replace('_', "-")
}

#[cfg(test)]
mod tests {
    use super::normalize_name;

    #[test]
    fn normalize_name_lowercases_and_treats_underscore_as_hyphen() {
        assert_eq!(normalize_name("Serde_JSON"), "serde-json");
        assert_eq!(normalize_name("serde-json"), "serde-json");
    }
}

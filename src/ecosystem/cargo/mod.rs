//! Cargo/crates.io ecosystem support.

pub mod index;
pub mod upstream;

/// The lookup key for a crate name: lowercase it, then replace every `_`
/// with `-`.
///
/// This is crates.io's own name-collision rule (`serde_json` and
/// `serde-json` name the same crate), and it is *not* PEP 503: it does not
/// collapse runs of `-`/`_`/`.`, and it leaves dots alone.
///
/// Use this for every keyed lookup that must find a row regardless of how
/// the caller spelled the name: the advisory mirror, the cargo-vet audit
/// store, and a stored verdict's package column.
///
/// Do **not** use it to build a sparse-index path or a `dl` URL. Those
/// must address the name crates.io actually published, which keeps its
/// underscores; see [`index_name`]. crates.io answers `404` for
/// `nu/m_/num_cpus`'s hyphenated twin.
pub fn normalize_name(name: &str) -> String {
    name.to_lowercase().replace('_', "-")
}

/// The canonical name for addressing the sparse index and the download
/// endpoint: lowercase only, with every `_` kept.
///
/// crates.io publishes `num_cpus` at `nu/m_/num_cpus` and serves its
/// `.crate` from a path containing `num_cpus`. Hyphenating the name here
/// reaches a different path that does not exist, so this function must not
/// replace `_` with `-`. Cargo itself lowercases a requested name and
/// keeps the separators, which is what this mirrors.
///
/// Use [`normalize_name`] instead for a keyed store lookup. The two
/// differ only in the `_`/`-` collapse, and the index tolerates neither
/// substitution.
pub fn index_name(name: &str) -> String {
    name.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{index_name, normalize_name};

    #[test]
    fn normalize_name_lowercases_and_treats_underscore_as_hyphen() {
        assert_eq!(normalize_name("Serde_JSON"), "serde-json");
        assert_eq!(normalize_name("serde-json"), "serde-json");
    }

    #[test]
    fn index_name_lowercases_but_keeps_the_underscore() {
        // crates.io answers 404 for the hyphenated spelling of a crate
        // whose published name carries an underscore, so the index path
        // must not collapse it.
        assert_eq!(index_name("Serde_JSON"), "serde_json");
        assert_eq!(index_name("num_cpus"), "num_cpus");
    }
}

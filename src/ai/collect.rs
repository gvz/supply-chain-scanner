//! File classification for the AI reviewer's payload collector.
//!
//! This module holds the pure filesystem side of collection: which
//! files a model can read at all, and how suspicious a readable file
//! looks to a cheap local heuristic. Selection, coverage, and the JSON
//! payload wire type arrive in the next task. Everything here runs
//! inside the sandbox with no network, no database, and no config.

use std::path::Path;

/// Version of the collector's file-selection logic. It joins the policy
/// fingerprint, so any change here re-reviews every artifact.
pub const COLLECTOR_VERSION: &str = "1";

/// What the collector can do with one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileClass {
    /// Text the model can read and judge.
    Reviewable,
    /// Binary that runs as code. The model cannot read it, and the
    /// collector reports it separately so an operator can block on it.
    OpaqueExecutable,
    /// Binary or documentation that is not executable. The model cannot
    /// read it, and it does not run at install or import time.
    OpaqueData,
}

/// File name extensions the collector treats as text a model can read.
/// The lists are exhaustive and ordered by class, so a file with one of
/// these extensions never reaches the binary sniff.
pub const REVIEWABLE_EXTENSIONS: &[&str] = &[
    // Python source and the Cython forms that compile to it.
    "py", "pyi", "pyx", "pxd", "pxi", //
    // Packaging metadata in text form.
    "cfg", "toml", "ini", "txt", "lock", // Shell scripts: executable text.
    "sh", "bash", "zsh", // General-purpose configuration and data-interchange text.
    "json", "yaml", "yml", "xml", "csv", "html",
];

/// File name extensions that hold native, executable code.
pub const OPAQUE_EXECUTABLE_EXTENSIONS: &[&str] = &[
    "so", "pyd", "dll", "dylib", //
    "exe", "a", "o", "obj", "lib", "node",
];

/// Whose bytes are neither executable code nor text the model can use.
pub const OPAQUE_DATA_EXTENSIONS: &[&str] = &[
    // Prose documentation.
    "md", "rst", //
    // Images.
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "tif", "tiff", "webp", "svgz",
    // Archives and compiled Python bytecode.
    "pdf", "zip", "tar", "gz", "bz2", "xz", "zst", "7z", "rar", "pyc", "pyo", "whl", "egg",
];

/// How many bytes of a file [`classify`] looks at when the extension
/// does not decide: the caller passes the first `HEAD_BYTES` bytes of
/// the file, or all of it when the file is shorter.
pub const HEAD_BYTES: usize = 8 * 1024;

/// `head` is the first [`HEAD_BYTES`] bytes of the file, or all of it
/// when the file is shorter.
///
/// Extension lookup goes first, then known executable magic bytes, then
/// a binary sniff: a NUL byte marks binary data, valid UTF-8 marks text.
/// A file with a shebang and no extension is reviewable.
pub fn classify(path: &Path, head: &[u8]) -> FileClass {
    match extension_of(path) {
        Some(ext) => {
            if REVIEWABLE_EXTENSIONS.contains(&ext.as_str()) {
                FileClass::Reviewable
            } else if OPAQUE_EXECUTABLE_EXTENSIONS.contains(&ext.as_str()) {
                FileClass::OpaqueExecutable
            } else if OPAQUE_DATA_EXTENSIONS.contains(&ext.as_str()) {
                FileClass::OpaqueData
            } else {
                classify_head(head)
            }
        }
        None => classify_head(head),
    }
}

/// Returns the file name extension in lower case, with no leading dot.
/// A path with no extension, or with an empty one in a non-UTF-8
/// encoding, returns `None`.
fn extension_of(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
}

/// Magic bytes at the start of a native executable: ELF and the two
/// Mach-O byte orders in 32-bit little-endian and big-endian form, plus
/// `MZ` for Windows PE binaries.
const EXECUTABLE_MAGICS: [&[u8]; 4] = [
    b"\x7fELF", //
    b"MZ",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
];

/// `head` decides when the extension does not: known executable magic
/// first, then the binary sniff. A NUL byte marks binary data. Valid
/// UTF-8 without one marks text, so a shebang with no extension stays
/// reviewable.
fn classify_head(head: &[u8]) -> FileClass {
    for magic in EXECUTABLE_MAGICS {
        if head.starts_with(magic) {
            return FileClass::OpaqueExecutable;
        }
    }
    if head.contains(&0) {
        FileClass::OpaqueData
    } else if std::str::from_utf8(head).is_ok() {
        FileClass::Reviewable
    } else {
        FileClass::OpaqueData
    }
}

/// Substring signals for [`suspicion_score`], with a weight each. A
/// weight reflects how directly the substring enables the behaviours
/// the spec names: running a decoded string as code, reading secrets the
/// developer never gave the package, spawning processes, and reaching
/// the network. The table is a plain `const` so both the model prompt
/// and the operations guide can cite it.
pub const SUSPICION_SIGNALS: &[(&str, u32)] = &[
    // Dynamic execution: a string becomes running code.
    ("exec(", 3),
    ("eval(", 3),
    ("compile(", 1),
    ("__import__", 2),
    ("importlib", 1),
    // Decoding and deserialization of opaque payloads.
    ("base64", 1),
    ("b64decode", 2),
    ("b85decode", 2),
    ("a85decode", 2),
    ("zlib.decompress", 1),
    ("gzip.decompress", 1),
    ("lzma.decompress", 1),
    ("binascii", 1),
    ("pickle.loads", 2),
    ("marshal.loads", 2),
    // Child processes.
    ("subprocess", 2),
    ("os.system", 2),
    ("os.popen", 2),
    ("Popen", 1),
    // Foreign function calls into native code.
    ("ctypes", 2),
    ("cffi", 1),
    // Network.
    ("socket", 2),
    ("urllib", 2),
    ("requests", 2),
    ("http.client", 2),
    ("httpx", 1),
    ("aiohttp", 1),
    // Environment and credential reads.
    ("os.environ", 1),
    ("getenv", 1),
    ("environ", 1),
];

/// Bonus weight for a long run of base64-alphabet characters. One
/// literal this large holds far more opaque payload than any ordinary
/// source file needs.
const BASE64_RUN_BONUS: u32 = 3;
/// Minimum run length, in base64-alphabet characters, that earns
/// [`BASE64_RUN_BONUS`].
const BASE64_RUN_MIN: usize = 200;
/// Bonus weight for a long run of backslash-x escapes. It marks a
/// payload spelled out in raw bytes rather than decoded.
const HEX_ESCAPE_RUN_BONUS: u32 = 2;
/// Minimum count of `\x` escapes that earns [`HEX_ESCAPE_RUN_BONUS`].
const HEX_ESCAPE_RUN_MIN: usize = 40;

/// Scores how much dynamic, decoding, and network behaviour one
/// reviewable file contains. Higher means more suspicious. The score is
/// additive by construction, so stacked signals always outrank a single
/// one.
pub fn suspicion_score(content: &str) -> u32 {
    let mut score = 0;
    for (needle, weight) in SUSPICION_SIGNALS {
        if content.contains(needle) {
            score += weight;
        }
    }
    if has_long_base64_run(content) {
        score += BASE64_RUN_BONUS;
    }
    if hex_escape_count(content) >= HEX_ESCAPE_RUN_MIN {
        score += HEX_ESCAPE_RUN_BONUS;
    }
    score
}

/// True when `content` contains a run of base64-alphabet characters
/// longer than [`BASE64_RUN_MIN`] + 1.
fn has_long_base64_run(content: &str) -> bool {
    let mut longest = 0;
    let mut current = 0;
    for byte in content.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/') {
            current += 1;
            if current > longest {
                longest = current;
            }
        } else {
            current = 0;
        }
    }
    longest > BASE64_RUN_MIN
}

/// Counts the `\x` byte-escape occurrences.
fn hex_escape_count(content: &str) -> usize {
    content.matches("\\x").count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_sources_are_reviewable() {
        for name in ["a.py", "a.pyi", "a.pyx"] {
            let class = classify(Path::new(name), b"");
            assert_eq!(class, FileClass::Reviewable, "{name} was not reviewable");
        }
    }

    #[test]
    fn packaging_text_is_reviewable() {
        for name in ["setup.cfg", "pyproject.toml", "requirements.txt", "a.sh"] {
            let class = classify(Path::new(name), b"");
            assert_eq!(class, FileClass::Reviewable, "{name} was not reviewable");
        }
    }

    #[test]
    fn shared_objects_are_opaque_executables() {
        for name in ["_speedup.cpython-311-x86_64-linux-gnu.so", "a.pyd", "a.dll"] {
            let class = classify(Path::new(name), b"");
            assert_eq!(
                class,
                FileClass::OpaqueExecutable,
                "{name} was not an opaque executable"
            );
        }
    }

    #[test]
    fn elf_magic_without_an_extension_is_opaque_executable() {
        let class = classify(Path::new("scripts/run"), b"\x7fELF\x02\x01\x01\x00");
        assert_eq!(class, FileClass::OpaqueExecutable);
    }

    #[test]
    fn documentation_and_images_are_opaque_data() {
        for name in ["README.md", "doc.rst", "logo.png"] {
            let class = classify(Path::new(name), b"");
            assert_eq!(class, FileClass::OpaqueData, "{name} was not opaque data");
        }
    }

    #[test]
    fn extensionless_utf8_text_is_reviewable() {
        let class = classify(Path::new("scripts/run"), b"#!/bin/sh\nexit 0\n");
        assert_eq!(class, FileClass::Reviewable);
    }

    #[test]
    fn a_nul_byte_in_the_head_is_opaque_data() {
        let class = classify(Path::new("data.bin"), b"ab\x00cd");
        assert_eq!(class, FileClass::OpaqueData);
    }

    #[test]
    fn plain_code_scores_zero() {
        assert_eq!(suspicion_score("x = 1\ny = x + 1\nprint(y)\n"), 0);
    }

    #[test]
    fn dynamic_execution_scores_above_plain_code() {
        assert!(suspicion_score("exec(payload)") > suspicion_score("x = 1"));
    }

    #[test]
    fn base64_decode_scores_above_plain_code() {
        assert!(suspicion_score("data = b64decode(blob)") > suspicion_score("x = 1"));
    }

    #[test]
    fn environment_reads_score_above_plain_code() {
        assert!(suspicion_score("value = os.environ[\"HOME\"]") > suspicion_score("x = 1"));
    }

    #[test]
    fn a_long_base64_literal_scores_above_plain_code() {
        let literal = "Q".repeat(240);
        assert!(suspicion_score(&format!("blob = \"{literal}\"")) > suspicion_score("x = 1"));
    }

    #[test]
    fn stacked_signals_score_above_a_single_signal() {
        let stacked = "exec(base64.b64decode(d))\nsocket.connect(h)\n";
        let single = "exec(payload)";
        assert!(suspicion_score(stacked) > suspicion_score(single));
    }
}

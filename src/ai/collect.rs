//! File classification and payload selection for the AI reviewer's
//! collector.
//!
//! This module holds the pure filesystem side of collection: which
//! files a model can read at all, how suspicious a readable file looks
//! to a cheap local heuristic, which of those files fit a size-capped
//! payload, and the JSON wire type that carries them. Everything here
//! runs inside the sandbox with no network, no database, and no config.
//! It uses only `std`, so nothing outside the mounted package is
//! reachable.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ecosystem::install_surface::InstallSurface;

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

/// One reviewable file exactly as the model receives it: the path
/// relative to the package root, the install-surface flag, and the full
/// text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectedFile {
    pub path: String,
    pub install_surface: bool,
    pub content: String,
}

/// One reviewable file the payload left out, with its size on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSize {
    pub path: String,
    pub bytes: u64,
}

/// The collector's output. This is the wire type between the sandboxed
/// collector and the proxy: one JSON value on stdout, nothing else.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectedPayload {
    pub collector_version: String,
    /// The reviewable files in send order: install-surface files first,
    /// then the remainder by descending suspicion score.
    pub files: Vec<CollectedFile>,
    pub reviewable_bytes_total: u64,
    pub reviewable_bytes_sent: u64,
    pub skipped_reviewable: Vec<FileSize>,
    pub opaque_executables: Vec<FileSize>,
    pub opaque_data_bytes: u64,
    pub install_surface_complete: bool,
}

impl CollectedPayload {
    /// The fraction of reviewable bytes the model received. `None`
    /// means the package holds no reviewable source at all, so coverage
    /// is undefined rather than zero. Callers treat it as no evidence.
    pub fn coverage(&self) -> Option<f32> {
        if self.reviewable_bytes_total == 0 {
            return None;
        }
        Some(self.reviewable_bytes_sent as f32 / self.reviewable_bytes_total as f32)
    }
}

/// Everything the classifier needs about one walked file.
struct Entry {
    /// Path relative to the root, with `/` separators.
    rel: String,
    /// Size on disk in bytes. This is the recorded size a skipped file
    /// reports, and a file whose size alone exceeds the cap is skipped
    /// through it without any read.
    size: u64,
    install_surface: bool,
    score: u32,
}

impl Entry {
    /// The sort key for the reviewable remainder: suspicion score first,
    /// then a smaller file, then a smaller path. The path key makes two
    /// identical trees produce identical output, because no two files
    /// in one unpacked artifact share a path.
    fn rank(&self) -> (std::cmp::Reverse<u32>, u64, &str) {
        (std::cmp::Reverse(self.score), self.size, self.rel.as_str())
    }
}

/// Builds the size-capped review payload for one unpacked package.
///
/// `root` is the package root as the sandbox mounts it. `surface`
/// decides which paths run at install or import time. Selection takes
/// install-surface files first, then the remainder by descending
/// suspicion score, and sends each chosen file whole while the running
/// total of content bytes stays within `max_payload_bytes`. A file that
/// never arrives whole is never read at all.
///
/// Returns an error only when the walk itself fails, for example on a
/// unreadable directory. A package with no reviewable source yields an
/// empty payload, not an error.
pub fn collect(
    root: &Path,
    surface: &dyn InstallSurface,
    max_payload_bytes: usize,
) -> anyhow::Result<CollectedPayload> {
    let mut reviewable: Vec<Entry> = Vec::new();
    let mut opaque_executables: Vec<FileSize> = Vec::new();
    let mut opaque_data_bytes: u64 = 0;

    walk(root, "", &mut |rel, size, class, head| {
        match class {
            FileClass::Reviewable => {
                // A reviewable file is scored wherever its text is
                // already at hand; the rest read one file when its turn
                // comes, so an oversize candidate never reaches memory.
                let score = std::str::from_utf8(head).map_or(0, suspicion_score);
                reviewable.push(Entry {
                    rel: rel.to_string(),
                    size,
                    install_surface: surface.is_install_surface(Path::new(rel)),
                    score,
                });
            }
            FileClass::OpaqueExecutable => {
                opaque_executables.push(FileSize {
                    path: rel.to_string(),
                    bytes: size,
                });
            }
            FileClass::OpaqueData => opaque_data_bytes += size,
        }
    })?;

    // Install-surface files first, sorted by path.
    let (mut surface_files, mut others): (Vec<Entry>, Vec<Entry>) = reviewable
        .into_iter()
        .partition(|entry| entry.install_surface);
    surface_files.sort_by(|a, b| a.rel.cmp(&b.rel));
    others.sort_by(|a, b| a.rank().cmp(&b.rank()));

    let mut files: Vec<CollectedFile> = Vec::new();
    let mut skipped_reviewable: Vec<FileSize> = Vec::new();
    let mut sent: usize = 0;
    let mut total: u64 = 0;
    let mut install_surface_complete = true;

    let candidates = surface_files.into_iter().chain(others);
    for entry in candidates {
        total += entry.size;
        if entry.size as usize > max_payload_bytes || sent + entry.size as usize > max_payload_bytes
        {
            // Send whole or not at all. Oversize and closed-out
            // candidates alike are skipped on their recorded size and
            // never read.
            skipped_reviewable.push(FileSize {
                path: entry.rel,
                bytes: entry.size,
            });
            continue;
        }

        let abs_path = root.join(&entry.rel);
        let content = match fs::read_to_string(&abs_path) {
            Ok(content) => content,
            // The file turned out not to be UTF-8 text. Its bytes stay
            // in `total` and it goes to `skipped_reviewable` rather than
            // the opaque pile: it was already counted as reviewable (its
            // extension or head said so), so dropping it from the
            // denominator here would silently inflate coverage, and
            // treating it as mere data would let an install-surface file
            // vanish from `install_surface_complete` instead of failing
            // it. A file this proxy could not actually show the model is
            // uncovered, not clean.
            Err(_) => {
                skipped_reviewable.push(FileSize {
                    path: entry.rel,
                    bytes: entry.size,
                });
                continue;
            }
        };
        sent += content.len();
        files.push(CollectedFile {
            path: entry.rel,
            install_surface: entry.install_surface,
            content,
        });
    }

    // An install-surface file that did not fit makes the review of the
    // install surface incomplete, which matters more than any coverage
    // figure.
    for skipped in &skipped_reviewable {
        if surface.is_install_surface(Path::new(&skipped.path)) {
            install_surface_complete = false;
            break;
        }
    }

    Ok(CollectedPayload {
        collector_version: COLLECTOR_VERSION.to_string(),
        files,
        reviewable_bytes_total: total,
        reviewable_bytes_sent: sent as u64,
        skipped_reviewable,
        opaque_executables,
        opaque_data_bytes,
        install_surface_complete,
    })
}

/// Reads the first [`HEAD_BYTES`] bytes of `path` and returns them in a
/// buffer. Returns an empty buffer when the file cannot be opened or
/// read, because the walk already saw it as a readable regular file,
/// so a failure here is transient.
fn read_head(path: &Path) -> Vec<u8> {
    let mut head = vec![0; HEAD_BYTES];
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Vec::new(),
    };
    match Read::read(&mut file, &mut head) {
        Ok(0) => Vec::new(),
        Ok(read) => {
            head.truncate(read);
            head
        }
        Err(_) => Vec::new(),
    }
}

/// The callback [`walk`] fires for every regular file: the path
/// relative to the walk root, the size on disk, the classified
/// [`FileClass`], and the first [`HEAD_BYTES`] bytes.
type Visit<'a> = &'a mut dyn FnMut(&str, u64, FileClass, &[u8]);

/// Walks `dir` and its subdirectories in unspecified order. For each
/// regular file calls `visit` with the path relative to the walk's
/// root, the size on disk, the classified [`FileClass`], and its first
/// [`HEAD_BYTES`] bytes. Directories, symlinks, and every other
/// irregular entry are skipped without error. An `Err` names the
/// directory `read_dir` could not list.
fn walk(dir: &Path, rel: &str, visit: Visit<'_>) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if !metadata.is_file() {
            continue;
        }
        let name = entry.file_name();
        let mut rel_path = String::with_capacity(rel.len() + name.len() + 1);
        if !rel.is_empty() {
            rel_path.push_str(rel);
            rel_path.push('/');
        }
        rel_path.push_str(&name.to_string_lossy());
        let head = read_head(&entry.path());
        let class = classify(Path::new(&rel_path), &head);
        visit(&rel_path, metadata.len(), class, &head);
    }

    // Recurse into the subdirectories the flat pass just saw, so one
    // unreadable file cannot abort the whole walk.
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            let name = entry.file_name();
            let mut rel_sub = String::with_capacity(rel.len() + name.len() + 1);
            if !rel.is_empty() {
                rel_sub.push_str(rel);
                rel_sub.push('/');
            }
            rel_sub.push_str(&name.to_string_lossy());
            walk(&entry.path(), &rel_sub, visit)?;
        }
    }

    Ok(())
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

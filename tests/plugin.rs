//! Task 8: hostile-archive unpacking, the bubblewrap sandbox, and the
//! fail-closed plugin runner.
//!
//! Two different trust boundaries are under test here. The archive tests
//! feed deliberately malicious wheels and sdists to [`unpack`], which runs
//! before any sandbox exists and so must reject them itself. The runner
//! tests drive [`PluginRunner`] through a scripted [`SandboxRunner`] so
//! that every failure mode — non-zero exit, timeout, sandbox error, a
//! process that died without an exit code — can be checked for *refusal*
//! rather than for a mere `Err`, with no dependence on `bwrap` working in
//! the test environment. Only the two `#[ignore]`d tests at the bottom
//! exercise the real [`BubblewrapSandbox`].

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flate2::write::GzEncoder;
use flate2::Compression;
use tar::{EntryType, Header};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use supply_chain_scanner::config::PluginConfig;
use supply_chain_scanner::model::ArtifactKey;
use supply_chain_scanner::plugin::{
    unpack, BubblewrapSandbox, PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec,
    UnpackError,
};

// ---------------------------------------------------------------------------
// Archive fixtures
// ---------------------------------------------------------------------------

/// Writes a zip archive at `path`, letting `build` add the entries.
fn write_zip(path: &Path, build: impl FnOnce(&mut ZipWriter<fs::File>)) {
    let file = fs::File::create(path).expect("create zip fixture");
    let mut zip = ZipWriter::new(file);
    build(&mut zip);
    zip.finish().expect("finish zip fixture");
}

/// Writes a gzipped tar archive at `path`, letting `build` add the entries.
fn write_tar_gz(path: &Path, build: impl FnOnce(&mut tar::Builder<GzEncoder<fs::File>>)) {
    let file = fs::File::create(path).expect("create tar.gz fixture");
    let mut builder = tar::Builder::new(GzEncoder::new(file, Compression::fast()));
    build(&mut builder);
    builder
        .into_inner()
        .expect("finish tar fixture")
        .finish()
        .expect("finish gzip fixture");
}

/// Builds a tar header with `name` written straight into the name field.
///
/// [`Header::set_path`] refuses `..` components and absolute paths — which
/// are exactly the entries these tests need to forge — so the raw bytes go
/// in directly and the checksum is recomputed afterwards.
fn forged_header(name: &str, entry_type: EntryType, size: u64) -> Header {
    let mut header = Header::new_gnu();
    {
        let gnu = header
            .as_gnu_mut()
            .expect("Header::new_gnu builds a GNU header");
        let bytes = name.as_bytes();
        assert!(
            bytes.len() < gnu.name.len(),
            "forged tar entry name is too long for the header field"
        );
        gnu.name[..bytes.len()].copy_from_slice(bytes);
    }
    header.set_entry_type(entry_type);
    header.set_size(size);
    header.set_mode(0o644);
    header.set_cksum();
    header
}

/// Asserts that [`unpack`] refused `result` *and* left nothing behind: no
/// file (or symlink) at any path in `must_not_exist`, and an empty
/// destination directory, because a partial extraction is a package a
/// plugin would then scan incompletely.
fn assert_refused_and_clean(
    result: Result<(), UnpackError>,
    dest: &Path,
    must_not_exist: &[&Path],
) {
    let err = result.expect_err("unpack must refuse this archive");

    for path in must_not_exist {
        assert!(
            fs::symlink_metadata(path).is_err(),
            "unpack created {} (refusal was: {err:#})",
            path.display()
        );
    }

    let leftovers: Vec<PathBuf> = match fs::read_dir(dest) {
        Ok(entries) => entries
            .map(|entry| entry.expect("read destination entry").path())
            .collect(),
        // Refused before the destination was even created.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("could not inspect {}: {error}", dest.display()),
    };
    assert!(
        leftovers.is_empty(),
        "unpack left a partial extraction in {}: {leftovers:?} (refusal was: {err:#})",
        dest.display()
    );
}

// ---------------------------------------------------------------------------
// unpack: well-formed archives
// ---------------------------------------------------------------------------

#[test]
fn unpack_extracts_wheel_contents() {
    let tmp = TempDir::new().unwrap();
    let wheel = tmp.path().join("pkg-1.0-py3-none-any.whl");
    write_zip(&wheel, |zip| {
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.add_directory("pkg/", options).unwrap();
        zip.start_file("pkg/__init__.py", options).unwrap();
        zip.write_all(b"VERSION = \"1.0\"\n").unwrap();
        zip.start_file("pkg-1.0.dist-info/METADATA", options)
            .unwrap();
        zip.write_all(b"Name: pkg\n").unwrap();
    });

    let dest = tmp.path().join("unpacked");
    unpack(&wheel, &dest).expect("a well-formed wheel unpacks");

    assert_eq!(
        fs::read_to_string(dest.join("pkg/__init__.py")).unwrap(),
        "VERSION = \"1.0\"\n"
    );
    assert_eq!(
        fs::read_to_string(dest.join("pkg-1.0.dist-info/METADATA")).unwrap(),
        "Name: pkg\n"
    );
}

#[test]
fn unpack_extracts_sdist_tar_gz_contents() {
    let tmp = TempDir::new().unwrap();
    let sdist = tmp.path().join("pkg-1.0.tar.gz");
    write_tar_gz(&sdist, |tar| {
        let mut dir = Header::new_gnu();
        dir.set_entry_type(EntryType::Directory);
        dir.set_size(0);
        dir.set_mode(0o755);
        dir.set_path("pkg-1.0/pkg/").unwrap();
        dir.set_cksum();
        tar.append(&dir, io::empty()).unwrap();

        let setup = b"from setuptools import setup\n";
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_size(setup.len() as u64);
        header.set_mode(0o644);
        header.set_path("pkg-1.0/setup.py").unwrap();
        header.set_cksum();
        tar.append(&header, &setup[..]).unwrap();

        let init = b"VERSION = \"1.0\"\n";
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_size(init.len() as u64);
        header.set_mode(0o644);
        header.set_path("pkg-1.0/pkg/__init__.py").unwrap();
        header.set_cksum();
        tar.append(&header, &init[..]).unwrap();
    });

    let dest = tmp.path().join("unpacked");
    unpack(&sdist, &dest).expect("a well-formed sdist unpacks");

    assert_eq!(
        fs::read_to_string(dest.join("pkg-1.0/setup.py")).unwrap(),
        "from setuptools import setup\n"
    );
    assert_eq!(
        fs::read_to_string(dest.join("pkg-1.0/pkg/__init__.py")).unwrap(),
        "VERSION = \"1.0\"\n"
    );
}

/// GNU `tar` routinely writes a `./` entry for the archive root, and many
/// real PyPI sdists carry one. It resolves to an empty relative path, which
/// `resolve_entry_path` used to reject before the `is_dir` branch could see
/// it — taking the whole archive down and (because `run_full_scan` stored
/// that as `Verdict::Blocked`) permanently blocking a perfectly legitimate
/// sdist with a refusal that reads to a developer as "we found malware".
#[test]
fn unpack_accepts_the_archive_root_directory_entry_gnu_tar_emits() {
    let tmp = TempDir::new().unwrap();
    let sdist = tmp.path().join("pkg-1.0.tar.gz");
    write_tar_gz(&sdist, |tar| {
        // The `./` archive-root entry, exactly as GNU tar writes it, and
        // first — so an unpacker that refuses it never reaches the real
        // contents at all.
        let mut root = Header::new_gnu();
        root.set_entry_type(EntryType::Directory);
        root.set_size(0);
        root.set_mode(0o755);
        root.set_path("./").unwrap();
        root.set_cksum();
        tar.append(&root, io::empty()).unwrap();

        let setup = b"from setuptools import setup\n";
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_size(setup.len() as u64);
        header.set_mode(0o644);
        header.set_path("./pkg-1.0/setup.py").unwrap();
        header.set_cksum();
        tar.append(&header, &setup[..]).unwrap();
    });

    let dest = tmp.path().join("unpacked");
    unpack(&sdist, &dest).expect("a `./` archive-root entry must not refuse the archive");
    assert_eq!(
        fs::read_to_string(dest.join("pkg-1.0/setup.py")).unwrap(),
        "from setuptools import setup\n"
    );
}

/// The `./` allowance is for *directory* entries only. A zero-length path
/// on a file entry names nothing to write and is still refused.
#[test]
fn unpack_still_rejects_an_empty_path_on_a_file_entry() {
    let tmp = TempDir::new().unwrap();
    let sdist = tmp.path().join("evil-1.0.tar.gz");
    write_tar_gz(&sdist, |tar| {
        let body = b"payload";
        let mut header = forged_header("./", EntryType::Regular, body.len() as u64);
        header.set_cksum();
        tar.append(&header, &body[..]).unwrap();
    });

    let dest = tmp.path().join("unpacked");
    assert!(
        unpack(&sdist, &dest).is_err(),
        "a file entry naming no path must still refuse the archive"
    );
}

// ---------------------------------------------------------------------------
// unpack: hostile archives
// ---------------------------------------------------------------------------

#[test]
fn unpack_rejects_entry_with_parent_traversal() {
    let tmp = TempDir::new().unwrap();
    let escape = tmp.path().join("escape.txt");

    // The traversal entry comes *second*, so a unpacker that skipped the
    // bad entry (or bailed without cleaning up) would leave `pkg/ok.py`
    // behind — a partial extraction.
    let wheel = tmp.path().join("evil-1.0-py3-none-any.whl");
    write_zip(&wheel, |zip| {
        let options = SimpleFileOptions::default();
        zip.start_file("pkg/ok.py", options).unwrap();
        zip.write_all(b"ok\n").unwrap();
        zip.start_file("../escape.txt", options).unwrap();
        zip.write_all(b"pwned\n").unwrap();
    });
    let zip_dest = tmp.path().join("unpacked-zip");
    assert_refused_and_clean(unpack(&wheel, &zip_dest), &zip_dest, &[&escape]);

    let sdist = tmp.path().join("evil-1.0.tar.gz");
    write_tar_gz(&sdist, |tar| {
        let header = forged_header("../escape.txt", EntryType::Regular, 6);
        tar.append(&header, &b"pwned\n"[..]).unwrap();
    });
    let tar_dest = tmp.path().join("unpacked-tar");
    assert_refused_and_clean(unpack(&sdist, &tar_dest), &tar_dest, &[&escape]);
}

#[test]
fn unpack_rejects_absolute_path_entry() {
    let tmp = TempDir::new().unwrap();
    // An absolute entry path aimed at a real location we can check
    // afterwards, rather than at something like `/etc/passwd` that would
    // be unwritable for unrelated reasons.
    let target = tmp.path().join("pwned.txt");
    let absolute = target.to_str().expect("tempdir path is UTF-8").to_string();

    let wheel = tmp.path().join("evil-1.0-py3-none-any.whl");
    write_zip(&wheel, |zip| {
        zip.start_file(&absolute, SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"pwned\n").unwrap();
    });
    let zip_dest = tmp.path().join("unpacked-zip");
    assert_refused_and_clean(unpack(&wheel, &zip_dest), &zip_dest, &[&target]);

    let sdist = tmp.path().join("evil-1.0.tar.gz");
    write_tar_gz(&sdist, |tar| {
        let header = forged_header(&absolute, EntryType::Regular, 6);
        tar.append(&header, &b"pwned\n"[..]).unwrap();
    });
    let tar_dest = tmp.path().join("unpacked-tar");
    assert_refused_and_clean(unpack(&sdist, &tar_dest), &tar_dest, &[&target]);
}

#[test]
fn unpack_rejects_symlink_entry() {
    let tmp = TempDir::new().unwrap();
    let secret = tmp.path().join("secret.txt");
    fs::write(&secret, "token\n").unwrap();
    let secret_str = secret.to_str().expect("tempdir path is UTF-8");

    // A wheel carrying a symlink out of the destination: materializing it
    // would let the plugin — and later pip — read through the link.
    let wheel = tmp.path().join("evil-1.0-py3-none-any.whl");
    write_zip(&wheel, |zip| {
        zip.add_symlink("pkg/leak.txt", secret_str, SimpleFileOptions::default())
            .unwrap();
    });
    let zip_dest = tmp.path().join("unpacked-zip");
    assert_refused_and_clean(
        unpack(&wheel, &zip_dest),
        &zip_dest,
        &[&zip_dest.join("pkg/leak.txt")],
    );

    // Hard links and device nodes are the same class of problem: an entry
    // that is not a plain file or directory must take the whole archive
    // down with it.
    for (label, entry_type) in [
        ("symlink", EntryType::Symlink),
        ("hard link", EntryType::Link),
        ("fifo", EntryType::Fifo),
        ("character device", EntryType::Char),
    ] {
        let sdist = tmp.path().join(format!("evil-{}.tar.gz", label.len()));
        write_tar_gz(&sdist, |tar| {
            let mut header = forged_header("pkg/leak.txt", entry_type, 0);
            if entry_type == EntryType::Symlink || entry_type == EntryType::Link {
                header.set_link_name(secret_str).unwrap();
                header.set_cksum();
            }
            tar.append(&header, io::empty()).unwrap();
        });
        let dest = tmp.path().join(format!("unpacked-{}", label.len()));
        assert_refused_and_clean(unpack(&sdist, &dest), &dest, &[&dest.join("pkg/leak.txt")]);
    }
}

/// Re-review finding: `EntryType::is_file()` is `true` only for the plain
/// `Regular` type, not for `Continuous` (tar type `'7'`, which the `tar`
/// crate's own docs describe as "Implementation-defined 'high-performance'
/// type, treated as regular file") or `GNUSparse` (`'S'`, GNU tar's
/// sparse-file extension for an ordinary file with holes). Before this
/// fix both fell through the "neither a regular file nor a directory"
/// check into `escape(..)`, turning a rare-but-legitimate sdist into a
/// sticky, durable `Blocked` verdict — the false-positive anti-goal,
/// reintroduced at a different seam by the fix that was supposed to close
/// it. These two tests build real `Continuous`/`GNUSparse` entries with
/// the `tar` crate's own `Header`/`EntryType` API, so they exercise the
/// actual entry-type and (for the sparse case) sparse-reconstruction path
/// a hand-rolled header would not reach.
#[test]
fn unpack_accepts_a_continuous_type_entry_as_a_regular_file() {
    let tmp = TempDir::new().unwrap();
    let body = b"implementation-defined high-performance content\n";
    let sdist = tmp.path().join("pkg-1.0.tar.gz");
    write_tar_gz(&sdist, |tar| {
        let mut header = Header::new_gnu();
        header.set_path("pkg-1.0/data.bin").unwrap();
        header.set_entry_type(EntryType::Continuous);
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, &body[..]).unwrap();
    });

    let dest = tmp.path().join("unpacked");
    unpack(&sdist, &dest).expect(
        "a Continuous-type entry is an ordinary file by the tar format's \
         own definition and must extract, not be treated as an escape attempt",
    );
    assert_eq!(fs::read(dest.join("pkg-1.0/data.bin")).unwrap(), body);
}

#[test]
fn unpack_accepts_a_gnu_sparse_entry_as_a_regular_file() {
    let tmp = TempDir::new().unwrap();
    let body = b"an ordinary file stored with the GNU sparse extension\n";
    let sdist = tmp.path().join("pkg-1.0.tar.gz");
    write_tar_gz(&sdist, |tar| {
        let mut header = Header::new_gnu();
        header.set_path("pkg-1.0/data.bin").unwrap();
        {
            let gnu = header
                .as_gnu_mut()
                .expect("Header::new_gnu builds a GNU header");
            // One sparse block covering the whole file at offset 0 — a
            // sparse-format entry with no actual hole in it, exactly the
            // shape a real archiver can produce for a file that is no
            // longer sparse on an incremental re-pack. The rest of
            // `gnu.sparse` stays zeroed, which the reader treats as "no
            // more blocks" (`GnuSparseHeader::is_empty`).
            gnu.sparse[0].set_offset(0);
            gnu.sparse[0].set_length(body.len() as u64);
            gnu.set_is_extended(false);
            gnu.set_real_size(body.len() as u64);
        }
        header.set_entry_type(EntryType::GNUSparse);
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, &body[..]).unwrap();
    });

    let dest = tmp.path().join("unpacked");
    unpack(&sdist, &dest).expect(
        "a GNUSparse entry is an ordinary file the tar crate reconstructs \
         transparently and must extract, not be treated as an escape attempt",
    );
    assert_eq!(fs::read(dest.join("pkg-1.0/data.bin")).unwrap(), body);
}

#[test]
fn unpack_rejects_archive_exceeding_size_limit() {
    let tmp = TempDir::new().unwrap();

    // A tar header may declare any size it likes. 600 MiB is past the
    // 512 MiB budget, and the guard must refuse on the declared size
    // before extracting a single byte.
    let sdist = tmp.path().join("bomb-1.0.tar.gz");
    write_tar_gz(&sdist, |tar| {
        let header = forged_header(
            "bomb-1.0/payload.bin",
            EntryType::Regular,
            600 * 1024 * 1024,
        );
        tar.append(&header, io::empty()).unwrap();
    });
    let tar_dest = tmp.path().join("unpacked-tar");
    assert_refused_and_clean(unpack(&sdist, &tar_dest), &tar_dest, &[]);

    // A genuine zip bomb: 513 MiB of zeros, a few hundred KiB on disk.
    // Compression level 1 keeps building the fixture cheap; the guard
    // reads the central directory's uncompressed size either way.
    let wheel = tmp.path().join("bomb-1.0-py3-none-any.whl");
    write_zip(&wheel, |zip| {
        zip.start_file(
            "bomb/payload.bin",
            SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .compression_level(Some(1)),
        )
        .unwrap();
        io::copy(&mut io::repeat(0).take(513 * 1024 * 1024), zip).unwrap();
    });
    let zip_dest = tmp.path().join("unpacked-zip");
    assert_refused_and_clean(unpack(&wheel, &zip_dest), &zip_dest, &[]);
}

#[test]
fn unpack_rejects_archive_exceeding_entry_count_limit() {
    let tmp = TempDir::new().unwrap();
    // 20_001 empty entries: past the 20_000 entry cap, and cheap to build.
    let wheel = tmp.path().join("many-1.0-py3-none-any.whl");
    write_zip(&wheel, |zip| {
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for i in 0..20_001 {
            zip.start_file(format!("pkg/f{i}.py"), options).unwrap();
        }
    });

    let zip_dest = tmp.path().join("unpacked-zip");
    assert_refused_and_clean(unpack(&wheel, &zip_dest), &zip_dest, &[]);

    // A tar has no up-front entry count, so the running counter is the only
    // thing standing between the unpacker and a million-file archive.
    let sdist = tmp.path().join("many-1.0.tar.gz");
    write_tar_gz(&sdist, |tar| {
        for i in 0..20_001 {
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Regular);
            header.set_size(0);
            header.set_mode(0o644);
            header.set_path(format!("pkg-1.0/f{i}.py")).unwrap();
            header.set_cksum();
            tar.append(&header, io::empty()).unwrap();
        }
    });
    let tar_dest = tmp.path().join("unpacked-tar");
    assert_refused_and_clean(unpack(&sdist, &tar_dest), &tar_dest, &[]);
}

#[test]
fn unpack_rejects_unrecognized_archive_format() {
    let tmp = TempDir::new().unwrap();
    // Fail closed: an extension this unpacker does not understand is a
    // refusal, not an empty "successful" extraction that every plugin
    // would then wave through.
    let blob = tmp.path().join("pkg-1.0.tar.bz2");
    fs::write(&blob, b"not an archive this unpacker reads").unwrap();

    let dest = tmp.path().join("unpacked");
    assert_refused_and_clean(unpack(&blob, &dest), &dest, &[]);
}

// ---------------------------------------------------------------------------
// PluginRunner, against a scripted sandbox
// ---------------------------------------------------------------------------

/// A deterministic [`SandboxRunner`]: it records every spec it is handed,
/// in call order, and replays a scripted outcome (or error) per plugin
/// binary. This keeps the runner tests independent of `bwrap`, of the
/// filesystem, and of wall-clock time.
struct FakeSandbox {
    scripted: HashMap<PathBuf, Result<SandboxOutcome, String>>,
    calls: Mutex<Vec<SandboxSpec>>,
}

impl FakeSandbox {
    fn new<I>(scripted: I) -> Arc<Self>
    where
        I: IntoIterator<Item = (&'static str, Result<SandboxOutcome, String>)>,
    {
        Arc::new(Self {
            scripted: scripted
                .into_iter()
                .map(|(binary, outcome)| (PathBuf::from(binary), outcome))
                .collect(),
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<SandboxSpec> {
        self.calls.lock().unwrap().clone()
    }

    fn binaries_called(&self) -> Vec<PathBuf> {
        self.calls()
            .into_iter()
            .map(|spec| spec.binary)
            .collect::<Vec<_>>()
    }
}

impl SandboxRunner for FakeSandbox {
    fn run(&self, spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        self.calls.lock().unwrap().push(spec.clone());
        match self.scripted.get(&spec.binary) {
            Some(Ok(outcome)) => Ok(outcome.clone()),
            Some(Err(message)) => Err(anyhow::anyhow!(message.clone())),
            None => panic!(
                "fake sandbox was asked to run an unscripted binary: {}",
                spec.binary.display()
            ),
        }
    }
}

fn clean() -> SandboxOutcome {
    SandboxOutcome {
        exit_code: Some(0),
        output: String::new(),
        timed_out: false,
        signal: None,
    }
}

fn exited(code: i32, output: &str) -> SandboxOutcome {
    SandboxOutcome {
        exit_code: Some(code),
        output: output.to_string(),
        timed_out: false,
        signal: None,
    }
}

fn plugin(name: &str, binary: &str) -> PluginConfig {
    PluginConfig {
        name: name.to_string(),
        binary: PathBuf::from(binary),
        timeout: Duration::from_secs(5),
    }
}

fn key() -> ArtifactKey {
    ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "requests".to_string(),
        version: "2.31.0".to_string(),
        filename: "requests-2.31.0-py3-none-any.whl".to_string(),
        sha256: "a".repeat(64),
    }
}

#[tokio::test]
async fn all_plugins_exit_zero_is_clean() {
    let fake = FakeSandbox::new([
        ("/plugins/yara", Ok(clean())),
        ("/plugins/entropy", Ok(clean())),
    ]);
    let runner = PluginRunner::new(fake.clone());
    let plugins = [
        plugin("yara", "/plugins/yara"),
        plugin("entropy", "/plugins/entropy"),
    ];
    let package_dir = Path::new("/var/cache/scan/unpacked");

    assert_eq!(runner.run_all(&plugins, &key(), package_dir).await, None);

    let calls = fake.calls();
    assert_eq!(calls.len(), 2, "both plugins must run when both are clean");
    // The org-facing invocation contract. `--package-dir` is the path
    // *inside* the sandbox, not the host path.
    assert_eq!(
        calls[0].args,
        vec![
            "--package-dir",
            "/pkg",
            "--name",
            "requests",
            "--version",
            "2.31.0",
            "--filename",
            "requests-2.31.0-py3-none-any.whl",
        ]
    );
    assert_eq!(calls[0].binary, Path::new("/plugins/yara"));
    assert_eq!(calls[0].package_dir, package_dir);
    assert_eq!(calls[0].timeout, Duration::from_secs(5));
}

#[tokio::test]
async fn nonzero_exit_blocks_with_plugin_name_in_code() {
    let fake = FakeSandbox::new([("/plugins/yara", Ok(exited(2, "")))]);
    let runner = PluginRunner::new(fake.clone());
    let plugins = [plugin("yara", "/plugins/yara")];

    let reason = runner
        .run_all(&plugins, &key(), Path::new("/unpacked"))
        .await
        .expect("a non-zero exit must block");

    assert_eq!(reason.code, "plugin:yara");
    // A plugin that says nothing still has to produce a usable reason.
    assert!(
        reason.detail.contains("yara") && reason.detail.contains('2'),
        "silent plugin produced an unhelpful detail: {:?}",
        reason.detail
    );

    // Output that survives sanitizing as nothing at all is the same case
    // as saying nothing: the refusal still has to explain itself, because
    // this detail is what the `/why` page shows an operator.
    let fake = FakeSandbox::new([("/plugins/yara", Ok(exited(3, "\u{1f480}\u{e9}\u{7}\n")))]);
    let runner = PluginRunner::new(fake.clone());

    let reason = runner
        .run_all(&plugins, &key(), Path::new("/unpacked"))
        .await
        .expect("a non-zero exit must block");

    assert_eq!(reason.code, "plugin:yara");
    assert!(
        reason.detail.contains("yara") && reason.detail.contains('3'),
        "unsanitizable plugin output left an empty detail: {:?}",
        reason.detail
    );
}

#[tokio::test]
async fn first_stdout_line_becomes_the_detail_and_is_truncated() {
    // Attacker-influenced output: a NUL, a non-ASCII byte, 300 padding
    // characters, and a second line that must never surface.
    let output = format!(
        "mal\u{0}ware:\u{e9} {}\nsecond line never shown\n",
        "A".repeat(300)
    );
    let fake = FakeSandbox::new([("/plugins/yara", Ok(exited(1, &output)))]);
    let runner = PluginRunner::new(fake.clone());
    let plugins = [plugin("yara", "/plugins/yara")];

    let reason = runner
        .run_all(&plugins, &key(), Path::new("/unpacked"))
        .await
        .expect("a non-zero exit must block");

    assert_eq!(reason.code, "plugin:yara");
    // "malware: " is 9 characters, leaving 191 of the 200-byte budget.
    assert_eq!(reason.detail, format!("malware: {}", "A".repeat(191)));
    assert_eq!(reason.detail.len(), 200);
    assert!(!reason.detail.contains("second line"));
    assert!(
        reason
            .detail
            .chars()
            .all(|c| c.is_ascii() && !c.is_ascii_control()),
        "detail reached RefusalReason unsanitized: {:?}",
        reason.detail
    );
}

#[tokio::test]
async fn timeout_blocks_with_plugin_timeout_code() {
    let timed_out = SandboxOutcome {
        exit_code: None,
        output: String::new(),
        timed_out: true,
        signal: None,
    };
    let fake = FakeSandbox::new([("/plugins/slowpoke", Ok(timed_out))]);
    let runner = PluginRunner::new(fake.clone());
    let plugins = [plugin("slowpoke", "/plugins/slowpoke")];

    let reason = runner
        .run_all(&plugins, &key(), Path::new("/unpacked"))
        .await
        .expect("a timed-out plugin must block, never pass");

    assert_eq!(reason.code, "plugin:slowpoke:timeout");
    assert!(
        reason.detail.contains("slowpoke"),
        "timeout detail does not name the plugin: {:?}",
        reason.detail
    );
}

#[tokio::test]
async fn sandbox_error_blocks_rather_than_passing() {
    // The sandbox could not run the plugin at all.
    let fake = FakeSandbox::new([(
        "/plugins/broken",
        Err("creating a user namespace failed".to_string()),
    )]);
    let runner = PluginRunner::new(fake.clone());
    let plugins = [plugin("broken", "/plugins/broken")];

    let reason = runner
        .run_all(&plugins, &key(), Path::new("/unpacked"))
        .await
        .expect("a sandbox failure must block, never pass");
    assert_eq!(reason.code, "plugin:broken:error");
    assert!(
        reason.detail.contains("user namespace"),
        "sandbox error detail lost the cause: {:?}",
        reason.detail
    );

    // The plugin ran but died on a signal, so it never reported a verdict.
    // That is also not a clean result, and the refusal detail must name
    // the signal rather than just saying "no exit code" (N1).
    let killed = SandboxOutcome {
        exit_code: None,
        output: String::new(),
        timed_out: false,
        signal: Some(libc::SIGSEGV),
    };
    let fake = FakeSandbox::new([("/plugins/crasher", Ok(killed))]);
    let runner = PluginRunner::new(fake.clone());
    let plugins = [plugin("crasher", "/plugins/crasher")];

    let reason = runner
        .run_all(&plugins, &key(), Path::new("/unpacked"))
        .await
        .expect("a plugin that died without an exit code must block");
    assert_eq!(reason.code, "plugin:crasher:error");
    assert!(
        reason.detail.contains("SIGSEGV"),
        "refusal detail did not name the terminating signal: {:?}",
        reason.detail
    );

    // No signal determined at all (e.g. the sandbox could not read it):
    // still a refusal, with the old uninformative-but-safe fallback text.
    let killed_unknown = SandboxOutcome {
        exit_code: None,
        output: String::new(),
        timed_out: false,
        signal: None,
    };
    let fake = FakeSandbox::new([("/plugins/crasher2", Ok(killed_unknown))]);
    let runner = PluginRunner::new(fake.clone());
    let plugins = [plugin("crasher2", "/plugins/crasher2")];

    let reason = runner
        .run_all(&plugins, &key(), Path::new("/unpacked"))
        .await
        .expect("a plugin that died without an exit code must block");
    assert_eq!(reason.code, "plugin:crasher2:error");
    assert!(
        reason.detail.contains("without an exit code"),
        "refusal detail changed for the no-signal-known case: {:?}",
        reason.detail
    );
}

#[tokio::test]
async fn plugins_run_in_configured_order_and_stop_at_first_block() {
    let fake = FakeSandbox::new([
        ("/plugins/cheap", Ok(clean())),
        ("/plugins/strict", Ok(exited(1, "found a dropper\n"))),
        ("/plugins/expensive", Ok(clean())),
    ]);
    let runner = PluginRunner::new(fake.clone());
    let plugins = [
        plugin("cheap", "/plugins/cheap"),
        plugin("strict", "/plugins/strict"),
        plugin("expensive", "/plugins/expensive"),
    ];

    let reason = runner
        .run_all(&plugins, &key(), Path::new("/unpacked"))
        .await
        .expect("the second plugin blocks");

    assert_eq!(reason.code, "plugin:strict");
    assert_eq!(reason.detail, "found a dropper");
    // The org orders plugins deliberately, cheap checks first, and nothing
    // after a block should have been paid for.
    assert_eq!(
        fake.binaries_called(),
        vec![
            PathBuf::from("/plugins/cheap"),
            PathBuf::from("/plugins/strict"),
        ],
        "the runner did not stop at the first block"
    );
}

// ---------------------------------------------------------------------------
// The real sandbox
// ---------------------------------------------------------------------------

/// An ordinary, dynamically linked shell to stand in for a plugin binary.
///
/// The bind set mounts the standard read-only OS paths (`/usr`, `/lib`,
/// `/lib64`, `/bin`, the loader's cache/config, and `/nix/store`) precisely
/// so that a binary like this — linked against libc and the dynamic
/// loader, exactly what a real plugin looks like — can `exec` inside the
/// sandbox. Using a statically linked stand-in here would prove nothing
/// about that bind set; it would pass even with the defect this task
/// fixes (binding only the plugin binary, no loader). Set `SCS_TEST_SH` to
/// point at a different shell explicitly.
fn dynamic_shell() -> PathBuf {
    if let Some(path) = std::env::var_os("SCS_TEST_SH") {
        return PathBuf::from(path);
    }
    PathBuf::from("/bin/sh")
}

#[test]
#[ignore = "requires bwrap and usable namespaces"]
fn bubblewrap_runs_a_real_binary_read_only() {
    let shell = dynamic_shell();
    let pkg = TempDir::new().unwrap();
    fs::write(pkg.path().join("payload.txt"), "contents\n").unwrap();

    let sandbox = BubblewrapSandbox::detect().expect("bwrap must be on PATH");
    let script = "if [ ! -f /pkg/payload.txt ]; then echo 'package dir not mounted'; exit 1; fi; \
                  if echo x > /pkg/escape 2>/dev/null; then echo 'package dir was writable'; exit 1; fi; \
                  echo ok";
    let outcome = sandbox
        .run(&SandboxSpec {
            binary: shell,
            package_dir: pkg.path().to_path_buf(),
            args: vec!["-c".to_string(), script.to_string()],
            timeout: Duration::from_secs(10),
            max_output_bytes: 200,
        })
        .expect("bwrap should run the plugin");

    assert!(!outcome.timed_out);
    // The exit code and output only come back if `/bin/sh` — dynamically
    // linked, not a statically linked stand-in — actually `exec`'d inside
    // the sandbox. A bind set missing the loader would surface as a
    // sandbox `Err`, not as this `Ok` outcome with a real exit code.
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "sandbox reported: {}",
        outcome.output
    );
    assert_eq!(outcome.output.trim(), "ok");
    assert!(
        !pkg.path().join("escape").exists(),
        "the plugin wrote into the host package directory"
    );
}

#[test]
#[ignore = "requires bwrap and usable namespaces"]
fn bubblewrap_timeout_kills_a_plugin_that_ignores_sigterm() {
    let shell = dynamic_shell();
    let pkg = TempDir::new().unwrap();

    let sandbox = BubblewrapSandbox::detect().expect("bwrap must be on PATH");
    let started = std::time::Instant::now();
    let outcome = sandbox
        .run(&SandboxSpec {
            binary: shell,
            package_dir: pkg.path().to_path_buf(),
            // Ignores SIGTERM and then spins forever, using only shell
            // builtins so nothing short of a real kill ends this.
            args: vec![
                "-c".to_string(),
                "trap '' TERM; while :; do :; done".to_string(),
            ],
            timeout: Duration::from_secs(1),
            max_output_bytes: 200,
        })
        .expect("the sandbox reports a timeout rather than failing");

    assert!(outcome.timed_out, "the run was not reported as timed out");
    assert_eq!(outcome.exit_code, None);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the timeout did not kill promptly: {:?}",
        started.elapsed()
    );
}

/// Builds, into a fresh temp directory, a small but genuinely
/// multithreaded CPU-burning binary: `threads` threads, each spinning on
/// its own core for roughly `burn_seconds` wall-clock seconds before the
/// process exits 0 and prints `ok`.
///
/// This is the fixture N1's regression test needs: an N-threaded burner
/// is exactly the shape of plugin `RLIMIT_CPU` used to kill early, because
/// Linux enforces `RLIMIT_CPU` against the thread-*group's* total CPU
/// time, not wall-clock time, so it burns a CPU-seconds allowance in
/// roughly `allowance / N` wall seconds. Needs a C compiler (`cc`) on
/// `PATH`, which — like `bwrap` for the sandbox tests around it — is a
/// requirement of this `#[ignore]`d test only, never of `cargo test`.
fn build_multithreaded_cpu_burner(threads: u32, burn_seconds: u32) -> (TempDir, PathBuf) {
    // Built under the crate's own `target/`, not the system temp
    // directory: the sandbox mounts a *second*, fresh tmpfs over `/tmp`
    // after binding the plugin binary into place (see `command()`'s doc
    // comment on mount ordering), so a binary whose host path happens to
    // live under `/tmp` would be hidden by that later mount and fail to
    // `exec` — a sandbox quirk unrelated to what this test is checking.
    let target_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
    let dir = tempfile::Builder::new()
        .prefix("n1-burner-")
        .tempdir_in(&target_dir)
        .expect("create burner fixture tempdir under target/");
    let source = dir.path().join("burn.c");
    let binary = dir.path().join("burn");
    fs::write(
        &source,
        format!(
            r#"
#include <pthread.h>
#include <time.h>
#include <stdio.h>

static void *burn(void *arg) {{
    (void) arg;
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    volatile unsigned long x = 0;
    for (;;) {{
        for (long i = 0; i < 10000000; i++) {{
            x += (unsigned long) i;
        }}
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (double) (now.tv_sec - start.tv_sec)
            + (double) (now.tv_nsec - start.tv_nsec) / 1e9;
        if (elapsed > {burn_seconds}) {{
            break;
        }}
    }}
    return NULL;
}}

int main(void) {{
    pthread_t threads[{threads}];
    for (int i = 0; i < {threads}; i++) {{
        pthread_create(&threads[i], NULL, burn, NULL);
    }}
    for (int i = 0; i < {threads}; i++) {{
        pthread_join(threads[i], NULL);
    }}
    printf("ok\n");
    return 0;
}}
"#
        ),
    )
    .expect("write burner fixture source");

    let status = std::process::Command::new("cc")
        .args(["-O2", "-pthread", "-o"])
        .arg(&binary)
        .arg(&source)
        .status()
        .expect("invoke cc to build the multithreaded burner fixture");
    assert!(status.success(), "cc failed to build the burner fixture");

    (dir, binary)
}

/// N1 regression test: a `RLIMIT_CPU` sized as `timeout + 1` CPU-seconds
/// kills a multithreaded plugin at a small fraction of its wall-clock
/// timeout, because Linux charges `RLIMIT_CPU` against the thread-group's
/// combined CPU time rather than wall-clock time. Reproduced empirically
/// against this sandbox's exact `bwrap` flag set before the fix: a
/// 4-thread burner with a 10-second timeout (`RLIMIT_CPU` = 11) died with
/// `SIGXCPU` (exit 152) after about 2.88 wall seconds.
///
/// This burner needs only 3 wall seconds across 4 threads to finish, well
/// inside a 10-second wall-clock timeout, and must now be allowed to run
/// to completion rather than being killed partway through.
#[test]
#[ignore = "requires bwrap, usable namespaces, and a C compiler (cc) on PATH"]
fn bubblewrap_allows_a_multithreaded_plugin_to_finish_within_its_wall_clock_timeout() {
    let (_source_dir, binary) = build_multithreaded_cpu_burner(4, 3);
    let pkg = TempDir::new().unwrap();

    let sandbox = BubblewrapSandbox::detect().expect("bwrap must be on PATH");
    let started = std::time::Instant::now();
    let outcome = sandbox
        .run(&SandboxSpec {
            binary,
            package_dir: pkg.path().to_path_buf(),
            args: vec![],
            timeout: Duration::from_secs(10),
            max_output_bytes: 200,
        })
        .expect("the sandbox must report an outcome, not fail to run");

    assert!(
        !outcome.timed_out,
        "the multithreaded plugin did not finish inside its wall-clock timeout"
    );
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the multithreaded plugin was killed before finishing (signal: {:?}, output: {:?})",
        outcome.signal,
        outcome.output
    );
    assert_eq!(outcome.output.trim(), "ok");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the burner took unexpectedly long to be reported: {:?}",
        started.elapsed()
    );
}

#[test]
#[ignore = "requires bwrap and usable namespaces"]
fn bubblewrap_clears_the_environment_and_bounds_memory_and_forks() {
    let shell = dynamic_shell();
    let pkg = TempDir::new().unwrap();

    // A secret the operator "exported". Without `--clearenv` this reaches
    // the plugin, and a plugin's first stdout line becomes `reason.detail`
    // and is rendered on `/why/<id>` to anyone who can reach the proxy.
    std::env::set_var("SCS_FAKE_SECRET", "exfiltrate-me");

    let sandbox = BubblewrapSandbox::detect().expect("bwrap must be on PATH");

    // 1. The environment is empty, and in particular the secret is gone.
    let outcome = sandbox
        .run(&SandboxSpec {
            binary: shell.clone(),
            package_dir: pkg.path().to_path_buf(),
            args: vec![
                "-c".to_string(),
                "if [ -n \"$SCS_FAKE_SECRET\" ]; then echo \"LEAKED $SCS_FAKE_SECRET\"; exit 1; fi; \
                 echo clean"
                    .to_string(),
            ],
            timeout: Duration::from_secs(10),
            max_output_bytes: 200,
        })
        .expect("bwrap should run the plugin");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the proxy's environment reached the plugin: {}",
        outcome.output
    );

    // 2. A plugin that tries to take a huge anonymous allocation fails
    //    rather than succeeding inside its timeout. `dd` writing to a
    //    tmpfs-backed file would hit the tmpfs cap instead, so this uses
    //    an allocation the kernel must back with address space: a shell
    //    variable grown far past RLIMIT_AS.
    let outcome = sandbox
        .run(&SandboxSpec {
            binary: shell.clone(),
            package_dir: pkg.path().to_path_buf(),
            args: vec![
                "-c".to_string(),
                // Doubles a shell string towards 2^40 bytes using only
                // builtins (nothing from the bind set, no `seq`), so it
                // must hit RLIMIT_AS long before finishing.
                "s=x; i=0; while [ $i -lt 40 ]; do s=\"$s$s\"; i=$((i+1)); done; \
                 echo survived"
                    .to_string(),
            ],
            timeout: Duration::from_secs(20),
            max_output_bytes: 200,
        })
        .expect("the sandbox must report an outcome, not fail to run");
    assert_ne!(
        outcome.exit_code,
        Some(0),
        "an unbounded allocation succeeded inside the sandbox: {}",
        outcome.output
    );
    assert!(
        !outcome.output.contains("survived"),
        "RLIMIT_AS did not bound the plugin's address space: {}",
        outcome.output
    );

    // 3. `--new-session` must not have broken the timeout kill path: a
    //    plugin that forks a long-lived child and then hangs must still be
    //    reported as timed out promptly, not wedge the pipe readers.
    let started = std::time::Instant::now();
    let outcome = sandbox
        .run(&SandboxSpec {
            binary: shell,
            package_dir: pkg.path().to_path_buf(),
            args: vec![
                "-c".to_string(),
                "(while :; do :; done) & trap '' TERM; while :; do :; done".to_string(),
            ],
            timeout: Duration::from_secs(1),
            max_output_bytes: 200,
        })
        .expect("the sandbox reports a timeout rather than failing");
    assert!(outcome.timed_out, "the run was not reported as timed out");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "a forked grandchild outside the process group wedged the kill path: {:?}",
        started.elapsed()
    );

    std::env::remove_var("SCS_FAKE_SECRET");
}

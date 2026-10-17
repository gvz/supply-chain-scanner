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
fn assert_refused_and_clean(result: anyhow::Result<()>, dest: &Path, must_not_exist: &[&Path]) {
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
    }
}

fn exited(code: i32, output: &str) -> SandboxOutcome {
    SandboxOutcome {
        exit_code: Some(code),
        output: output.to_string(),
        timed_out: false,
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
    // That is also not a clean result.
    let killed = SandboxOutcome {
        exit_code: None,
        output: String::new(),
        timed_out: false,
    };
    let fake = FakeSandbox::new([("/plugins/crasher", Ok(killed))]);
    let runner = PluginRunner::new(fake.clone());
    let plugins = [plugin("crasher", "/plugins/crasher")];

    let reason = runner
        .run_all(&plugins, &key(), Path::new("/unpacked"))
        .await
        .expect("a plugin that died without an exit code must block");
    assert_eq!(reason.code, "plugin:crasher:error");
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

/// Locates a statically linked `busybox` to stand in for a plugin binary.
///
/// The sandbox binds only the plugin binary — no `/lib`, no dynamic
/// loader — so a dynamically linked plugin cannot `exec` inside it. Set
/// `SCS_TEST_STATIC_SH` to point at one explicitly.
fn static_shell() -> PathBuf {
    if let Some(path) = std::env::var_os("SCS_TEST_STATIC_SH") {
        return PathBuf::from(path);
    }
    for candidate in ["/bin/busybox", "/usr/bin/busybox"] {
        let path = Path::new(candidate);
        if path.is_file() {
            return path.to_path_buf();
        }
    }
    if let Some(path) = nix_store_static_busybox() {
        return path;
    }
    panic!("no statically linked shell found; set SCS_TEST_STATIC_SH to one");
}

fn nix_store_static_busybox() -> Option<PathBuf> {
    for entry in fs::read_dir("/nix/store").ok()?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.contains("busybox-static") || name.ends_with(".drv") {
            continue;
        }
        let candidate = entry.path().join("bin/busybox");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[test]
#[ignore = "requires bwrap, usable namespaces, and a statically linked test plugin"]
fn bubblewrap_runs_a_real_binary_read_only() {
    let shell = static_shell();
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
            args: vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            timeout: Duration::from_secs(10),
            max_output_bytes: 200,
        })
        .expect("bwrap should run the plugin");

    assert!(!outcome.timed_out);
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
#[ignore = "requires bwrap, usable namespaces, and a statically linked test plugin"]
fn bubblewrap_timeout_kills_a_plugin_that_ignores_sigterm() {
    let shell = static_shell();
    let pkg = TempDir::new().unwrap();

    let sandbox = BubblewrapSandbox::detect().expect("bwrap must be on PATH");
    let started = std::time::Instant::now();
    let outcome = sandbox
        .run(&SandboxSpec {
            binary: shell,
            package_dir: pkg.path().to_path_buf(),
            // Ignores SIGTERM and then spins forever, using only shell
            // builtins because the sandbox binds no other executable.
            // Nothing short of a real kill ends this.
            args: vec![
                "sh".to_string(),
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

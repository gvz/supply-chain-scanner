//! Extracting a downloaded wheel or sdist so a plugin can look at it.
//!
//! This is the one piece of the scanner with no sandbox behind it: it runs
//! against bytes that were just fetched from a public registry, in the
//! proxy's own process, *before* the sandbox exists. Everything here is
//! therefore written to refuse rather than to cope.
//!
//! Three rules hold for every entry in every archive:
//!
//! 1. The path must be relative, must contain no `..` component, and must
//!    resolve inside the destination. No `../../.ssh/authorized_keys`, no
//!    `/etc/cron.d/backdoor`.
//! 2. The entry must be a plain file or a directory. Symlinks, hard links,
//!    FIFOs, sockets and device nodes are refused outright — a symlink in
//!    the tree is a read of (or a write through to) a host path the moment
//!    anything walks it, and the sandbox binds the package directory, so a
//!    link inside it is a link out of it.
//! 3. The total uncompressed size and the entry count stay under fixed
//!    budgets, so a zip bomb costs a refusal rather than the disk.
//!
//! A bad entry takes the whole archive down with it, and the destination is
//! wiped on the way out: a partial extraction is a package the plugin would
//! then scan incompletely and pass.
//!
//! The one entry that looks bad and is not: the `./` archive-root
//! directory GNU `tar` writes, carried by many real PyPI sdists. It
//! reduces to an empty relative path, which is refused on a *file* entry
//! (it names nothing to write) and skipped on a *directory* entry (the
//! archive root already exists as the destination). Refusing it outright
//! took legitimate sdists down, and the caller stored that as a durable
//! block — see [`relative_entry_path`].
//!
//! Archive-recorded permissions are deliberately ignored. Files land with
//! the process's default mode, which cannot carry setuid, setgid, or the
//! sticky bit no matter what the package asked for.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context};
use flate2::read::MultiGzDecoder;

/// Hard cap on the total uncompressed bytes one archive may extract to.
///
/// Deliberately a constant and not configuration: it is a guard against a
/// decompression bomb, not a policy knob, and a deployment that could raise
/// it would eventually be asked to. 512 MiB is far above any real PyPI
/// artifact (the largest wheels on the index are tens of MiB) while still
/// being a bounded, survivable write on any machine that can run the proxy.
/// An archive past this is refused, never truncated.
const MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// Hard cap on the number of entries one archive may contain.
///
/// Bounds the per-entry syscall cost independently of total size, which is
/// what a tar of a million empty files attacks. Large real packages run to
/// a few thousand files, so 20,000 leaves generous headroom.
const MAX_ENTRIES: usize = 20_000;

/// `S_IFMT`: the file-type bits of a unix mode.
const S_IFMT: u32 = 0o170000;
/// `S_IFREG`: a regular file.
const S_IFREG: u32 = 0o100000;
/// `S_IFDIR`: a directory.
const S_IFDIR: u32 = 0o040000;

/// Extracts `archive` into `dest`, creating `dest` if it does not exist.
///
/// The archive format is chosen from `archive`'s file name: `.whl`, `.zip`
/// and `.egg` are read as zip, `.tar.gz` and `.tgz` as gzipped tar.
/// Anything else is an error rather than a guess — an unrecognized artifact
/// that "extracted" to nothing would sail past every plugin.
///
/// On any error the contents of `dest` are removed, so a caller can never
/// hand a plugin a half-extracted package. `dest` must therefore be a
/// directory this archive owns — a fresh one per artifact — and not a
/// shared location holding anything the caller wants to keep.
pub fn unpack(archive: &Path, dest: &Path) -> anyhow::Result<()> {
    let kind = ArchiveKind::of(archive)?;

    fs::create_dir_all(dest)
        .with_context(|| format!("creating unpack destination {}", dest.display()))?;

    let mut budget = Budget::new();
    let result = match kind {
        ArchiveKind::Zip => unpack_zip(archive, dest, &mut budget),
        ArchiveKind::TarGz => unpack_tar_gz(archive, dest, &mut budget),
    };

    if result.is_err() {
        // Reject the whole archive, not just the offending entry.
        if let Err(cleanup_error) = clear_dir(dest) {
            tracing::warn!(
                dest = %dest.display(),
                error = %cleanup_error,
                "could not remove a partial extraction after a refused archive"
            );
        }
    }

    result.with_context(|| format!("unpacking {}", archive.display()))
}

enum ArchiveKind {
    Zip,
    TarGz,
}

impl ArchiveKind {
    fn of(archive: &Path) -> anyhow::Result<Self> {
        let name = archive
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                anyhow::anyhow!("archive path {} has no usable file name", archive.display())
            })?
            .to_ascii_lowercase();

        if name.ends_with(".whl") || name.ends_with(".zip") || name.ends_with(".egg") {
            Ok(Self::Zip)
        } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            Ok(Self::TarGz)
        } else {
            bail!("unsupported archive format for {name}; expected a wheel/zip or a .tar.gz sdist")
        }
    }
}

/// The remaining extraction allowance for one archive.
struct Budget {
    remaining_bytes: u64,
    remaining_entries: usize,
}

impl Budget {
    fn new() -> Self {
        Self {
            remaining_bytes: MAX_TOTAL_UNCOMPRESSED_BYTES,
            remaining_entries: MAX_ENTRIES,
        }
    }

    /// Charges one entry against the entry budget.
    fn count_entry(&mut self) -> anyhow::Result<()> {
        if self.remaining_entries == 0 {
            bail!("archive has more than {MAX_ENTRIES} entries");
        }
        self.remaining_entries -= 1;
        Ok(())
    }

    /// Checks an entry's declared uncompressed size against what is left of
    /// the byte budget, *before* any of it is written. A single entry that
    /// alone exceeds the budget is refused here, same as the cumulative
    /// case.
    fn check_declared(&self, declared: u64) -> anyhow::Result<()> {
        if declared > self.remaining_bytes {
            bail!(
                "archive exceeds the {MAX_TOTAL_UNCOMPRESSED_BYTES}-byte uncompressed limit \
                 (an entry declares {declared} bytes with {} left)",
                self.remaining_bytes
            );
        }
        Ok(())
    }

    fn charge_bytes(&mut self, written: u64) {
        self.remaining_bytes = self.remaining_bytes.saturating_sub(written);
    }
}

/// Validates one archive-supplied entry name and reduces it to a safe
/// relative path, **which may be empty**.
///
/// Every component must be a plain name: a `..` component, a root, or a
/// Windows path prefix is an attempt to write outside `dest` and takes the
/// archive down. `.` components are dropped — `tar` writes them routinely
/// and they are not an escape.
///
/// An entry made entirely of `.` components (i.e. `./`, the archive-root
/// entry GNU `tar` emits and that many real PyPI sdists carry) reduces to
/// the empty path. That is deliberately *not* an error here: whether it is
/// acceptable depends on the entry type, which only the caller knows. A
/// directory entry naming the archive root is a no-op to skip; a file
/// entry naming no path is still refused. Conflating the two is what used
/// to turn a legitimate sdist into a permanent `BLOCKED`.
fn relative_entry_path(raw: &Path) -> anyhow::Result<PathBuf> {
    let shown = raw.display();

    if raw.is_absolute() {
        bail!("archive entry {shown} has an absolute path");
    }

    let mut relative = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            Component::ParentDir => bail!("archive entry {shown} contains a `..` component"),
            Component::RootDir | Component::Prefix(_) => {
                bail!("archive entry {shown} is not a relative path")
            }
        }
    }

    Ok(relative)
}

/// Maps an already-validated, non-empty `relative` path into `dest`.
fn resolve_within(dest: &Path, relative: &Path, raw: &Path) -> anyhow::Result<PathBuf> {
    let resolved = dest.join(relative);
    // Belt and braces. The component walk in `relative_entry_path`
    // already makes an escape impossible; this catches any future change
    // to it.
    if !resolved.starts_with(dest) {
        bail!(
            "archive entry {} resolves outside the destination directory",
            raw.display()
        );
    }
    Ok(resolved)
}

/// What one archive entry's path resolves to inside `dest`.
enum EntryTarget {
    /// A real path to create or write.
    Path(PathBuf),
    /// The archive root itself (`./`), which already exists as `dest`.
    /// Valid only for a directory entry.
    ArchiveRoot,
}

/// Resolves `raw` for an entry that is or is not a directory, allowing the
/// archive-root entry through only in the directory case.
fn resolve_entry_target(dest: &Path, raw: &Path, is_dir: bool) -> anyhow::Result<EntryTarget> {
    let relative = relative_entry_path(raw)?;
    if relative.as_os_str().is_empty() {
        if is_dir {
            return Ok(EntryTarget::ArchiveRoot);
        }
        bail!("archive entry {} names no file", raw.display());
    }
    Ok(EntryTarget::Path(resolve_within(dest, &relative, raw)?))
}

/// Writes one file entry, reading at most its declared size.
///
/// The file is created with `O_EXCL`, which fails if anything already
/// exists at that path — including a dangling symlink. That makes the
/// classic two-entry trick (plant a link, then write "through" it) fail at
/// the `open` even if the link had somehow been created. It also means two
/// entries naming the same path refuse the archive rather than letting the
/// later one silently replace a file a plugin may already have been shown.
fn write_file_entry(
    path: &Path,
    source: &mut dyn Read,
    declared: u64,
    budget: &mut Budget,
) -> anyhow::Result<()> {
    budget.check_declared(declared)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }

    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;

    // `declared + 1` so an entry whose real contents run past its declared
    // size is detected rather than silently truncated.
    let written = io::copy(&mut source.take(declared + 1), &mut out)
        .with_context(|| format!("writing {}", path.display()))?;
    if written != declared {
        bail!(
            "archive entry {} declared {declared} bytes but contained {written}",
            path.display()
        );
    }

    budget.charge_bytes(written);
    Ok(())
}

fn create_dir_entry(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating directory {}", path.display()))
}

fn unpack_zip(archive: &Path, dest: &Path, budget: &mut Budget) -> anyhow::Result<()> {
    let file = fs::File::open(archive).with_context(|| format!("opening {}", archive.display()))?;
    let mut zip = zip::ZipArchive::new(io::BufReader::new(file)).context("reading zip archive")?;

    // A zip's entry count is known up front, so an over-long archive can be
    // refused without touching a single entry.
    if zip.len() > MAX_ENTRIES {
        bail!("archive has {} entries, more than {MAX_ENTRIES}", zip.len());
    }

    for index in 0..zip.len() {
        budget.count_entry()?;

        let mut entry = zip
            .by_index(index)
            .with_context(|| format!("reading zip entry {index}"))?;

        // A name this crate cannot decode is refused rather than guessed
        // at: the bytes that reach disk have to be the bytes we validated.
        let name = entry
            .name()
            .with_context(|| format!("decoding the name of zip entry {index}"))?
            .into_owned();

        if entry.is_symlink() {
            bail!("archive entry {name} is a symlink");
        }
        if let Some(mode) = entry.unix_mode() {
            let file_type = mode & S_IFMT;
            // A zip entry may legitimately record no file-type bits at all,
            // in which case it is a plain file.
            if file_type != 0 && file_type != S_IFREG && file_type != S_IFDIR {
                bail!("archive entry {name} is neither a regular file nor a directory");
            }
        }

        let is_dir = entry.is_dir();
        let declared = entry.size();

        match resolve_entry_target(dest, Path::new(&name), is_dir)? {
            // The archive root already exists as `dest`; nothing to do.
            EntryTarget::ArchiveRoot => continue,
            EntryTarget::Path(path) if is_dir => create_dir_entry(&path)?,
            EntryTarget::Path(path) => write_file_entry(&path, &mut entry, declared, budget)?,
        }
    }

    Ok(())
}

fn unpack_tar_gz(archive: &Path, dest: &Path, budget: &mut Budget) -> anyhow::Result<()> {
    let file = fs::File::open(archive).with_context(|| format!("opening {}", archive.display()))?;
    // `MultiGzDecoder`, not `GzDecoder`: a gzip stream may carry several
    // concatenated members, Python's `tarfile` reads them all, and content
    // this unpacker stopped short of is content the plugin never sees.
    let mut tar = tar::Archive::new(MultiGzDecoder::new(io::BufReader::new(file)));

    for entry in tar.entries().context("reading tar archive")? {
        let mut entry = entry.context("reading tar entry")?;
        budget.count_entry()?;

        let entry_type = entry.header().entry_type();
        let declared = entry.header().size().context("reading tar entry size")?;

        // Extension headers carry metadata for the *next* entry and never
        // produce anything on disk, so they have no path to validate.
        if entry_type.is_pax_global_extensions()
            || entry_type.is_pax_local_extensions()
            || entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
        {
            budget.check_declared(declared)?;
            budget.charge_bytes(declared);
            continue;
        }

        let raw = entry
            .path()
            .context("decoding a tar entry path")?
            .to_path_buf();

        if !entry_type.is_dir() && !entry_type.is_file() {
            bail!(
                "archive entry {} is neither a regular file nor a directory \
                 (tar type {:?})",
                raw.display(),
                entry_type
            );
        }

        match resolve_entry_target(dest, &raw, entry_type.is_dir())? {
            // The `./` archive-root entry GNU tar emits: `dest` already
            // exists, so there is nothing to create.
            EntryTarget::ArchiveRoot => continue,
            EntryTarget::Path(path) if entry_type.is_dir() => create_dir_entry(&path)?,
            EntryTarget::Path(path) => write_file_entry(&path, &mut entry, declared, budget)?,
        }
    }

    Ok(())
}

/// Removes everything inside `dir`, leaving `dir` itself in place.
///
/// Safe to point at the destination: nothing this module writes is a
/// symlink, so there is no link here to delete through.
fn clear_dir(dir: &Path) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let entry = entry.with_context(|| format!("listing {}", dir.display()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspecting {}", path.display()))?;
        if metadata.is_dir() {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        }
        .with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(())
}

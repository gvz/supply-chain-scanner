//! Content-addressed, on-disk cache of scanned artifact bytes, with a
//! sliding TTL.
//!
//! The verdict database ([`crate::db::verdict::VerdictStore`]) is the
//! durable record of whether an artifact may be served; this cache is
//! purely a performance feature sitting in front of upstream PyPI
//! downloads. The scanner serves from here when an artifact is already on
//! disk and re-downloads (then re-inserts) when it is not — emptying this
//! cache never changes what the proxy decides to serve, only how long
//! that takes.
//!
//! Layout is content-addressed: `<root>/<sha256[0..2]>/<sha256>`. Because
//! the path is the hash, identical bytes shipped under different
//! filenames (or by different packages entirely) are stored once, and the
//! two-character prefix directory keeps any one directory's fan-out sane.
//! The cache table is keyed by `sha256` alone for the same reason: for
//! storage purposes the rest of an [`ArtifactKey`] is redundant, but the
//! descriptive columns are kept (see [`crate::db::cache::CacheEntry`]) so
//! an operator can tell what a cached blob actually is.
//!
//! The TTL is sliding, not fixed: every [`ArtifactCache::get`] call
//! refreshes the entry's clock, so a package the organization installs
//! constantly is never evicted while one-off downloads age out.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;

use crate::db::cache::CacheStore;
use crate::db::Db;
use crate::model::ArtifactKey;

/// On-disk cache of artifact bytes, keyed by content hash.
pub struct ArtifactCache {
    store: CacheStore,
    root: PathBuf,
}

impl ArtifactCache {
    /// Opens the cache rooted at `root`, creating the directory if it
    /// doesn't exist yet.
    pub fn new(db: Db, root: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&root)
            .with_context(|| format!("creating artifact cache root {}", root.display()))?;
        Ok(Self {
            store: CacheStore::new(db),
            root,
        })
    }

    /// Returns the on-disk path for `key`'s content, if it is cached,
    /// refreshing its sliding-TTL clock on the way out — this is what
    /// "repeatedly requested artifacts are never evicted" means in
    /// practice.
    ///
    /// If the metadata row exists but the backing file has vanished from
    /// disk (e.g. someone pruned the cache directory by hand), that is
    /// not treated as an error: the stale row is cleaned up and `None` is
    /// returned, so the caller simply re-downloads and re-inserts rather
    /// than ever being handed a path to missing or partially-written
    /// bytes.
    ///
    /// The file's length is checked against the length recorded when it
    /// was inserted, and a disagreement is treated exactly like a missing
    /// file: a miss, with the row and the file both removed. `is_file()`
    /// alone was not enough. A crash partway through writing into the
    /// cache leaves a *truncated* file whose row says it is complete, and
    /// nothing downstream re-verifies a cache hit — the artifact was
    /// hash-verified once, on the way in — so those bytes would be served
    /// as `Clean` for as long as the entry lived. Length is not a hash,
    /// but it catches every truncation, which is the only corruption this
    /// cache's own write path can produce.
    pub fn get(&self, key: &ArtifactKey) -> anyhow::Result<Option<PathBuf>> {
        let sha256 = validated_sha256(&key.sha256)?;

        let Some(entry) = self.store.get(sha256)? else {
            return Ok(None);
        };

        let path = self.path_for(sha256);
        let on_disk = match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => metadata.len(),
            _ => {
                self.store.remove(sha256)?;
                return Ok(None);
            }
        };

        let recorded = u64::try_from(entry.bytes).unwrap_or(u64::MAX);
        if on_disk != recorded {
            tracing::warn!(
                sha256 = %sha256,
                path = %path.display(),
                recorded_bytes = recorded,
                on_disk_bytes = on_disk,
                "cached artifact file does not match its recorded length; \
                 discarding it rather than serving bytes this cache cannot \
                 vouch for. The artifact will be re-downloaded and re-verified."
            );
            // Remove the file too: leaving it would make the next
            // `insert` for this hash take the already-cached branch.
            let _ = std::fs::remove_file(&path);
            self.store.remove(sha256)?;
            return Ok(None);
        }

        self.store.touch(sha256)?;
        Ok(Some(path))
    }

    /// Moves `file` into the cache under `key`'s content hash and records
    /// its metadata, returning the path it now lives at.
    ///
    /// `file` is expected to be a freshly downloaded, already
    /// hash-verified temp file: on success it no longer exists at its
    /// original path, having been moved (or, if a same-filesystem rename
    /// isn't possible, copied and then removed) into the cache.
    ///
    /// A file already present at the content-addressed path is kept, and
    /// the incoming copy removed as redundant, **only if the two lengths
    /// agree**. Trusting any pre-existing file unconditionally was a hole
    /// with a complete failure sequence behind it: a crash mid-write
    /// leaves a truncated file at the content-addressed path with no row;
    /// the next request re-downloads, verifies the bytes, calls `insert`,
    /// sees a file there, deletes the *good* bytes, and writes a row
    /// pointing at the truncated ones. The incoming file has just been
    /// verified against the index-declared hash, so when the lengths
    /// disagree it is the pre-existing file that is wrong, and it is
    /// replaced.
    pub fn insert(&self, key: &ArtifactKey, file: &Path) -> anyhow::Result<PathBuf> {
        let sha256 = validated_sha256(&key.sha256)?;
        let dest = self.path_for(sha256);

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating cache shard directory {}", parent.display()))?;
        }

        let incoming_bytes = std::fs::metadata(file)
            .with_context(|| format!("statting incoming artifact file {}", file.display()))?
            .len();

        let existing_bytes = match std::fs::metadata(&dest) {
            Ok(metadata) if metadata.is_file() => Some(metadata.len()),
            _ => None,
        };

        match existing_bytes {
            Some(bytes) if bytes == incoming_bytes => {
                std::fs::remove_file(file).with_context(|| {
                    format!(
                        "removing redundant source file {} (content already cached at {})",
                        file.display(),
                        dest.display()
                    )
                })?;
            }
            Some(bytes) => {
                tracing::warn!(
                    sha256 = %sha256,
                    path = %dest.display(),
                    existing_bytes = bytes,
                    incoming_bytes,
                    "a file already at this content-addressed path has the wrong \
                     length (most likely a truncated write left by an earlier \
                     crash); replacing it with the freshly verified bytes"
                );
                move_into_place(file, &dest)?;
            }
            None => move_into_place(file, &dest)?,
        }

        let bytes = std::fs::metadata(&dest)
            .with_context(|| format!("statting cached file {}", dest.display()))?
            .len();
        self.store.insert(key, bytes)?;

        Ok(dest)
    }

    /// Removes every cache entry whose sliding clock has not been
    /// refreshed within `ttl`, deleting both the database row and the
    /// backing file. Returns how many entries were removed.
    ///
    /// A file that can't be deleted is logged and its row is left in
    /// place so a later sweep retries, rather than dropping the row and
    /// silently orphaning the bytes on disk.
    pub fn evict_expired(&self, ttl: Duration) -> anyhow::Result<usize> {
        let ttl_secs = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
        let cutoff = now_unix() - ttl_secs;
        let expired = self.store.expired_before(cutoff)?;

        let mut removed = 0;
        for sha256 in expired {
            // `path_for` slices `&sha256[0..2]`, and this value came
            // straight out of the database rather than through
            // `validated_sha256` the way `get` and `insert` do. One short
            // or non-hex row — a hand-edited database, a future caller
            // that skipped the guard — used to panic the eviction ticker
            // instead of skipping the row.
            let Ok(sha256) = validated_sha256(&sha256).map(str::to_owned) else {
                tracing::warn!(
                    sha256 = %sha256,
                    "artifact cache row has a malformed sha256; skipping it \
                     rather than deriving a path from it"
                );
                continue;
            };
            let path = self.path_for(&sha256);
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    self.store.remove(&sha256)?;
                    removed += 1;
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    // Already gone from disk; the row was stale anyway.
                    self.store.remove(&sha256)?;
                    removed += 1;
                }
                Err(err) => {
                    tracing::warn!(
                        sha256 = %sha256,
                        path = %path.display(),
                        error = %err,
                        "failed to delete expired artifact cache file; keeping its row for a later sweep"
                    );
                }
            }
        }

        Ok(removed)
    }

    fn path_for(&self, sha256: &str) -> PathBuf {
        self.root.join(&sha256[0..2]).join(sha256)
    }
}

/// Rejects anything that isn't a lowercase 64-character hex string before
/// it reaches the filesystem: a cache key is not a safe path component
/// just because it is *usually* one, and `sha256` ultimately traces back
/// to upstream-supplied artifact data by way of [`ArtifactKey`].
fn validated_sha256(sha256: &str) -> anyhow::Result<&str> {
    let is_valid = sha256.len() == 64
        && sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !is_valid {
        anyhow::bail!("sha256 is not a lowercase 64-character hex string: {sha256:?}");
    }
    Ok(sha256)
}

/// Moves `src` to `dest`, falling back to copy-then-rename when the
/// rename fails because they're on different filesystems. The fallback
/// matters because `src` is normally a freshly downloaded temp file and
/// temp directories are sometimes a different mount than the cache root;
/// losing a successfully scanned artifact to a plain rename error would
/// be worse than paying for a copy.
///
/// The fallback copies to a temp name *beside* `dest` and then renames,
/// never straight to `dest`. A `fs::copy` directly onto the
/// content-addressed path is non-atomic: a crash partway through leaves a
/// truncated file at exactly the path a cache hit is looked up by, with no
/// row to contradict it. Copy-then-rename means `dest` only ever appears
/// complete. The temp file is removed if the copy or the rename fails, so
/// a failure leaves nothing behind either.
fn move_into_place(src: &Path, dest: &Path) -> anyhow::Result<()> {
    match std::fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {
            let staged = staging_path_beside(dest)?;
            if let Err(err) = std::fs::copy(src, &staged) {
                let _ = std::fs::remove_file(&staged);
                return Err(err).with_context(|| {
                    format!(
                        "copying {} to {} (cross-device move)",
                        src.display(),
                        staged.display()
                    )
                });
            }
            if let Err(err) = std::fs::rename(&staged, dest) {
                let _ = std::fs::remove_file(&staged);
                return Err(err).with_context(|| {
                    format!(
                        "renaming {} into place at {} after a cross-device copy",
                        staged.display(),
                        dest.display()
                    )
                });
            }
            std::fs::remove_file(src).with_context(|| {
                format!(
                    "removing source file {} after cross-device copy",
                    src.display()
                )
            })?;
            Ok(())
        }
        Err(err) => Err(err)
            .with_context(|| format!("moving {} into cache at {}", src.display(), dest.display())),
    }
}

/// A staging path in `dest`'s own directory, so the final rename is
/// same-filesystem and therefore atomic. The name is randomized so two
/// concurrent inserts of the same content cannot stage over each other.
fn staging_path_beside(dest: &Path) -> anyhow::Result<PathBuf> {
    let parent = dest
        .parent()
        .context("cache destination path has no parent directory")?;
    let file_name = dest
        .file_name()
        .context("cache destination path has no file name")?
        .to_string_lossy()
        .into_owned();

    let mut suffix = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut suffix);
    Ok(parent.join(format!(".{file_name}.{}.part", hex::encode(suffix))))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs() as i64
}

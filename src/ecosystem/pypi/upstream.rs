//! The only module in this crate that talks to upstream PyPI.
//!
//! [`Upstream`] fetches PEP 503 simple index pages and downloads artifact
//! files. It never fails open: a network error, a non-2xx status other
//! than 404, or a page that fails to parse becomes an error (or, for the
//! index page specifically, a fallback to the last known-good cached copy)
//! — never a silent empty result that would let an unexamined artifact
//! through.
//!
//! Timeouts come in two shapes, because the two jobs need different ones.
//!
//! **Index pages** keep a tight total deadline (5s to connect, 10s for the
//! whole request): they fetch small documents and sit in front of the
//! scanner's 12s whole-scan budget, so one of them must never be able to
//! consume it alone.
//!
//! **Artifact downloads** have no total deadline at all. `reqwest`'s
//! `ClientBuilder::timeout` runs from connect until the response body
//! finishes, so on a download path it is a cap on artifact *size* wearing
//! the costume of a cap on time: at 10 seconds total, a 300 MB wheel
//! needed 30 MB/s sustained and a 900 MB `torch` wheel needed 90 MB/s, and
//! every large ML/CUDA wheel was permanently unservable. Instead the
//! download client detects *stalls* (`read_timeout`, which resets on every
//! successful read) with a generous absolute cap behind it; both are
//! configurable via [`crate::config::DownloadLimits`].
//!
//! A long legitimate download does outlive the 12s scan budget. That is
//! the designed behavior, not a failure: the request returns the retryable
//! scan-in-progress response while the *detached* scan keeps running and
//! stores its verdict, so the developer's retry lands on a stored
//! decision (see [`crate::scan`]).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};
use bytes::Bytes;
use futures_util::StreamExt;
use rand::Rng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::config::DownloadLimits;
use crate::db::index_cache::IndexCache;
use crate::ecosystem::pypi::index::{self, IndexEntry};

/// Upper bound on establishing the TCP/TLS connection to upstream.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on an entire *index-page* request (connect + headers +
/// body). The scanner's whole-scan budget is 12s; this must stay well
/// under that so one slow index fetch cannot eat the whole budget by
/// itself.
///
/// Deliberately not applied to the download path — see the module docs
/// and [`DownloadLimits`].
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A value that may have come straight from upstream (`stale == false`) or
/// from the fallback cache because upstream could not be reached
/// (`stale == true`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched<T> {
    pub value: T,
    pub stale: bool,
}

/// What went wrong talking to upstream PyPI.
///
/// `NotFound` (a real 404) is deliberately distinct from `Unavailable` (an
/// outage, timeout, or any other non-2xx status): a 404 means upstream
/// has spoken and said "no such thing," and must never be treated as a
/// reason to fall back to a cached page or to wipe one.
#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("upstream PyPI is unavailable: {0}")]
    Unavailable(String),
    #[error("not found upstream")]
    NotFound,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// HTTP client for upstream PyPI, backed by a stale-tolerant index cache.
///
/// Two clients, deliberately, because the two jobs need opposite timeout
/// shapes. `index_client` fetches small documents in front of the scan
/// budget and keeps a total deadline. `download_client` streams artifact
/// bodies of unbounded size and must *not* have one — see
/// [`DownloadLimits`].
pub struct Upstream {
    index_client: reqwest::Client,
    download_client: reqwest::Client,
    base: Url,
    cache: IndexCache,
    /// Absolute cap applied around a whole download; see
    /// [`DownloadLimits::max_duration`].
    download_max_duration: Duration,
    /// Hard cap, in bytes, on one artifact's downloaded size; see
    /// [`DownloadLimits::max_artifact_bytes`].
    max_artifact_bytes: u64,
}

impl Upstream {
    /// Builds an `Upstream` with the default [`DownloadLimits`].
    pub fn new(base: Url, cache: IndexCache) -> anyhow::Result<Self> {
        Self::with_limits(base, cache, &DownloadLimits::default())
    }

    /// Builds an `Upstream` pointed at `base` (the PEP 503 simple index
    /// root, e.g. `https://pypi.org/simple/`), using `cache` as the
    /// fallback store for index pages and `limits` for the download path.
    pub fn with_limits(
        base: Url,
        cache: IndexCache,
        limits: &DownloadLimits,
    ) -> anyhow::Result<Self> {
        let index_client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("building the upstream index HTTP client")?;
        // Deliberately no `.timeout(..)`: that is a *total* deadline
        // (connect through end-of-body), which on this path is a cap on
        // artifact size disguised as a cap on time. `read_timeout` is the
        // right shape — it bounds how long the transfer may go without
        // receiving a byte and resets on every successful read, so a
        // dead connection still fails in seconds while a large honest
        // download is not penalized for being large. The absolute cap
        // lives in `download_max_duration`, applied around the whole
        // call in `download`.
        let download_client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(limits.stall_timeout)
            .build()
            .context("building the upstream download HTTP client")?;
        Ok(Self {
            index_client,
            download_client,
            base,
            cache,
            download_max_duration: limits.max_duration,
            max_artifact_bytes: limits.max_artifact_bytes,
        })
    }

    /// Fetches the PEP 503 simple index page for `package`.
    ///
    /// On success, the raw body is cached under the normalized package
    /// name and the parsed entries are returned with `stale: false`. If
    /// upstream cannot be reached or returns an error status other than
    /// 404, the last cached body (if any) is parsed and returned instead
    /// with `stale: true`; with no cached body, this is
    /// [`UpstreamError::Unavailable`]. A 404 is always
    /// [`UpstreamError::NotFound`] and never touches the cache.
    pub async fn simple_page(
        &self,
        package: &str,
    ) -> Result<Fetched<Vec<IndexEntry>>, UpstreamError> {
        let normalized = index::normalize_name(package);
        let url = self
            .base
            .join(&format!("{normalized}/"))
            .with_context(|| format!("building simple index URL for {normalized:?}"))?;

        match self.index_client.get(url.clone()).send().await {
            Ok(response) if response.status() == reqwest::StatusCode::NOT_FOUND => {
                Err(UpstreamError::NotFound)
            }
            Ok(response) if response.status().is_success() => {
                let body = response
                    .text()
                    .await
                    .with_context(|| format!("reading simple index body for {normalized:?}"))?;
                let entries = index::parse_simple_page(&body, &url)
                    .with_context(|| format!("parsing simple index page for {normalized:?}"))?;
                self.cache
                    .put(&normalized, &body)
                    .with_context(|| format!("caching simple index page for {normalized:?}"))?;
                Ok(Fetched {
                    value: entries,
                    stale: false,
                })
            }
            Ok(response) => {
                let reason = format!(
                    "upstream returned status {} for {normalized:?}",
                    response.status()
                );
                self.fall_back_to_cache(&normalized, &url, reason)
            }
            Err(err) => {
                let reason = format!("request to upstream failed for {normalized:?}: {err}");
                self.fall_back_to_cache(&normalized, &url, reason)
            }
        }
    }

    /// Looks up `package` in the index cache and, if present, parses the
    /// cached body against `url` and returns it marked stale; otherwise
    /// returns [`UpstreamError::Unavailable`] carrying `reason`.
    fn fall_back_to_cache(
        &self,
        package: &str,
        url: &Url,
        reason: String,
    ) -> Result<Fetched<Vec<IndexEntry>>, UpstreamError> {
        let cached = self
            .cache
            .get(package)
            .with_context(|| format!("reading index cache for {package:?}"))?;
        match cached {
            Some((body, _fetched_at)) => {
                let entries = index::parse_simple_page(&body, url)
                    .with_context(|| format!("parsing cached simple index page for {package:?}"))?;
                Ok(Fetched {
                    value: entries,
                    stale: true,
                })
            }
            None => Err(UpstreamError::Unavailable(reason)),
        }
    }

    /// Downloads `entry`'s artifact to `dest`, streaming the response body
    /// to disk while hashing it, and returns the lowercase hex SHA-256 of
    /// the bytes actually written.
    ///
    /// The file is written to a temporary path beside `dest` and renamed
    /// into place only once the download completes successfully; on any
    /// error (network failure, truncated body, I/O error) the temporary
    /// file is removed and `dest` is left untouched, so a failed download
    /// never leaves a partial file where a caller might find it.
    ///
    /// Bounded by stall detection (see [`DownloadLimits::stall_timeout`],
    /// configured on `download_client`) plus the absolute
    /// [`DownloadLimits::max_duration`] cap applied here — never by a
    /// total deadline short enough to make large artifacts unservable.
    /// Exceeding `max_duration` is an error, and a partially written temp
    /// file is removed on that path as on every other, so the fail-closed
    /// guarantee holds: a download that ran out of time never produces
    /// bytes a caller could mistake for a complete artifact.
    pub async fn download(&self, entry: &IndexEntry, dest: &Path) -> Result<String, UpstreamError> {
        match tokio::time::timeout(self.download_max_duration, self.download_inner(entry, dest))
            .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                // The inner future was dropped mid-stream, so its temp
                // file (named `.<filename>.<random>.part` beside `dest`)
                // was never removed by its own error path. Sweep it.
                remove_part_files_beside(dest).await;
                Err(UpstreamError::Unavailable(format!(
                    "downloading {:?} exceeded the {:?} absolute download limit",
                    entry.filename, self.download_max_duration
                )))
            }
        }
    }

    async fn download_inner(
        &self,
        entry: &IndexEntry,
        dest: &Path,
    ) -> Result<String, UpstreamError> {
        let response = self
            .download_client
            .get(entry.url.clone())
            .send()
            .await
            .map_err(|err| {
                UpstreamError::Unavailable(format!(
                    "request to download {:?} failed: {err}",
                    entry.filename
                ))
            })?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(UpstreamError::NotFound);
        }
        if !response.status().is_success() {
            return Err(UpstreamError::Unavailable(format!(
                "upstream returned status {} downloading {:?}",
                response.status(),
                entry.filename
            )));
        }
        // Refused before a single byte is written when upstream declares
        // the size up front: no point opening a temp file (or waiting on
        // a stall timeout) for a transfer `stream_to_file`'s own running
        // check would abort anyway. A response with no `Content-Length`,
        // or one that understates it, still goes through that check.
        if let Some(declared) = response.content_length() {
            if declared > self.max_artifact_bytes {
                return Err(UpstreamError::Unavailable(format!(
                    "upstream declared {declared} bytes for {:?}, over the \
                     {}-byte artifact size limit",
                    entry.filename, self.max_artifact_bytes
                )));
            }
        }

        let tmp_path = temp_path_beside(dest)
            .with_context(|| format!("choosing a temp path beside {}", dest.display()))?;

        let result = stream_to_file(response, &tmp_path, self.max_artifact_bytes).await;

        match result {
            Ok(digest) => match tokio::fs::rename(&tmp_path, dest).await {
                Ok(()) => Ok(digest),
                Err(err) => {
                    // Best-effort cleanup: the rename failed, so the fully
                    // written temp file must not be left orphaned beside
                    // dest.
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    Err(UpstreamError::Other(anyhow::Error::new(err).context(
                        format!(
                            "renaming {} to {} after a successful download",
                            tmp_path.display(),
                            dest.display()
                        ),
                    )))
                }
            },
            Err(err) => {
                // Best-effort cleanup: the download already failed, so a
                // failure to remove the temp file must not mask the
                // original error.
                let _ = tokio::fs::remove_file(&tmp_path).await;
                Err(UpstreamError::Other(err.context(format!(
                    "downloading {:?} to {}",
                    entry.filename,
                    dest.display()
                ))))
            }
        }
    }

    /// Fetches the PEP 658/714 "core metadata" sidecar file for `entry`
    /// (the artifact's own URL with `.metadata` appended) and returns its
    /// raw bytes.
    pub async fn metadata_sidecar(&self, entry: &IndexEntry) -> Result<Bytes, UpstreamError> {
        let mut url = entry.url.clone();
        let metadata_path = format!("{}.metadata", url.path());
        url.set_path(&metadata_path);

        let response = self.index_client.get(url).send().await.map_err(|err| {
            UpstreamError::Unavailable(format!(
                "request for metadata sidecar of {:?} failed: {err}",
                entry.filename
            ))
        })?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(UpstreamError::NotFound);
        }
        if !response.status().is_success() {
            return Err(UpstreamError::Unavailable(format!(
                "upstream returned status {} fetching metadata sidecar of {:?}",
                response.status(),
                entry.filename
            )));
        }

        response.bytes().await.map_err(|err| {
            UpstreamError::Other(anyhow::Error::new(err).context(format!(
                "reading metadata sidecar body for {:?}",
                entry.filename
            )))
        })
    }
}

/// Streams `response`'s body into a freshly created file at `path`,
/// hashing every chunk as it is written, and returns the lowercase hex
/// SHA-256 digest of everything received. Any I/O or network error during
/// the stream is returned to the caller, who is responsible for removing
/// the (incomplete) file at `path`.
///
/// `max_bytes` bounds the running total of bytes actually received,
/// independent of (and in addition to) the `Content-Length` precheck in
/// [`Upstream::download_inner`]: that check only catches a response that
/// *declares* its size, so this one is what actually stops a chunked body
/// with no declared length, or one that understates it, from being
/// written indefinitely — up to [`DownloadLimits::max_duration`] of it,
/// into what is usually a RAM-backed tmpfs. Exceeding it is an error, same
/// as any other failure on this path: nothing is served, and the caller
/// removes the partial file.
async fn stream_to_file(
    response: reqwest::Response,
    path: &Path,
    max_bytes: u64,
) -> anyhow::Result<String> {
    let mut file = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("creating temp file {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut stream = response.bytes_stream();
    let mut received: u64 = 0;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading response chunk from upstream")?;
        received = received.saturating_add(chunk.len() as u64);
        if received > max_bytes {
            bail!(
                "download exceeded the {max_bytes}-byte artifact size limit \
                 ({received} bytes received so far)"
            );
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .with_context(|| format!("writing to temp file {}", path.display()))?;
    }

    file.flush()
        .await
        .with_context(|| format!("flushing temp file {}", path.display()))?;

    Ok(to_hex(&hasher.finalize()))
}

/// Removes any `.<name>.<random>.part` file this module may have left
/// beside `dest`, used when the download future is cancelled (by the
/// absolute cap) and so never reaches its own cleanup path.
///
/// Scoped to the exact naming scheme [`temp_path_beside`] produces, so it
/// can never delete a caller's own files: `dest`'s directory is a
/// per-download temp directory in every current caller, but this does not
/// rely on that.
async fn remove_part_files_beside(dest: &Path) {
    let Some(parent) = dest.parent() else { return };
    let Some(file_name) = dest.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return;
    };
    let prefix = format!(".{file_name}.");

    let Ok(mut entries) = tokio::fs::read_dir(parent).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) && name.ends_with(".part") {
            let _ = tokio::fs::remove_file(entry.path()).await;
        }
    }
}

/// Picks a temp file path in the same directory as `dest`, so the final
/// rename is same-filesystem (and therefore atomic). The name is
/// randomized to avoid colliding with a concurrent download of the same
/// artifact.
fn temp_path_beside(dest: &Path) -> anyhow::Result<PathBuf> {
    let parent = dest
        .parent()
        .context("destination path has no parent directory")?;
    let file_name = dest
        .file_name()
        .context("destination path has no file name")?
        .to_string_lossy();

    let mut suffix_bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut suffix_bytes);
    let suffix = to_hex(&suffix_bytes);

    Ok(parent.join(format!(".{file_name}.{suffix}.part")))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

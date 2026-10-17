//! The only module in this crate that talks to upstream PyPI.
//!
//! [`Upstream`] fetches PEP 503 simple index pages and downloads artifact
//! files. It never fails open: a network error, a non-2xx status other
//! than 404, or a page that fails to parse becomes an error (or, for the
//! index page specifically, a fallback to the last known-good cached copy)
//! — never a silent empty result that would let an unexamined artifact
//! through.
//!
//! Timeouts are deliberately tight (5s to connect, 10s total per request):
//! the scanner's whole-scan budget is 12s, so a single upstream call must
//! never be able to consume it alone.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use futures_util::StreamExt;
use rand::Rng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::db::index_cache::IndexCache;
use crate::ecosystem::pypi::index::{self, IndexEntry};

/// Upper bound on establishing the TCP/TLS connection to upstream.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on the entire request (connect + headers + body). The
/// scanner's whole-scan budget is 12s; this must stay well under that so
/// one slow upstream call cannot eat the whole budget by itself.
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
pub struct Upstream {
    client: reqwest::Client,
    base: Url,
    cache: IndexCache,
}

impl Upstream {
    /// Builds an `Upstream` pointed at `base` (the PEP 503 simple index
    /// root, e.g. `https://pypi.org/simple/`), using `cache` as the
    /// fallback store for index pages.
    pub fn new(base: Url, cache: IndexCache) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("building upstream HTTP client")?;
        Ok(Self {
            client,
            base,
            cache,
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

        match self.client.get(url.clone()).send().await {
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
    pub async fn download(&self, entry: &IndexEntry, dest: &Path) -> Result<String, UpstreamError> {
        let response = self
            .client
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

        let tmp_path = temp_path_beside(dest)
            .with_context(|| format!("choosing a temp path beside {}", dest.display()))?;

        let result = stream_to_file(response, &tmp_path).await;

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

        let response = self.client.get(url).send().await.map_err(|err| {
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
async fn stream_to_file(response: reqwest::Response, path: &Path) -> anyhow::Result<String> {
    let mut file = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("creating temp file {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading response chunk from upstream")?;
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

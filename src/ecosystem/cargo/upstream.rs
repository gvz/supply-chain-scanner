//! The only module in this crate that talks to the cargo registry
//! upstream: the sparse index for crate metadata, and the `dl` endpoint for
//! `.crate` files.
//!
//! The client never fails open. A network error, a non-2xx status other
//! than 404, or a body that fails to parse becomes an error. A 404 is
//! separate: it means upstream said "no such crate", so callers must not
//! read it as an outage.
//!
//! The two jobs need different timeout shapes, as on the PyPI path.
//!
//! - **Index files and `config.json`** are small documents. They keep a
//!   total deadline and a connect deadline.
//! - **`.crate` downloads** have no total deadline. A total deadline caps
//!   artifact size while it pretends to cap time. Instead the download
//!   client detects stalls with `read_timeout`, and
//!   [`crate::config::DownloadLimits::max_duration`] bounds the whole call
//!   from outside.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};
use futures_util::StreamExt;
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::config::DownloadLimits;
use crate::ecosystem::cargo::index::{self, CargoIndexEntry};
use crate::ecosystem::cargo::normalize_name;

/// Upper bound on establishing the TCP/TLS connection to upstream.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on an entire index-file or `config.json` request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// What went wrong talking to the cargo registry upstream.
///
/// `NotFound` (a real 404) is deliberately separate from `Unavailable` (an
/// outage, a timeout, or any other non-2xx status). A 404 means upstream
/// has spoken and said "no such thing". Callers must not treat it as an
/// outage, and must not let it wipe data they already hold.
#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("upstream cargo registry is unavailable: {0}")]
    Unavailable(String),
    #[error("not found upstream")]
    NotFound,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// The parts of the sparse index's `config.json` this client uses.
///
/// `api` and the other fields are ignored: serde drops fields a struct
/// does not declare.
#[derive(Debug, Deserialize)]
struct ConfigJson {
    /// The `.crate` download URL template. It may contain the markers
    /// `{crate}`, `{version}`, and `{prefix}`.
    dl: String,
}

/// HTTP client for the cargo sparse index and the `.crate` download
/// endpoint.
///
/// Two clients, deliberately. `index_client` fetches small documents and
/// keeps a total deadline. `download_client` streams bodies of unbounded
/// size and must not have one. See [`DownloadLimits`].
pub struct CargoUpstream {
    /// Client for `config.json` and per-crate index files.
    index_client: reqwest::Client,
    /// Client for `.crate` bodies. It has a stall timeout and no total
    /// timeout.
    download_client: reqwest::Client,
    /// Sparse index root, for example `https://index.crates.io/`.
    index_base: Url,
    /// Absolute cap applied around one whole download. See
    /// [`DownloadLimits::max_duration`].
    download_max_duration: Duration,
    /// Hard cap, in bytes, on one `.crate` file. See
    /// [`DownloadLimits::max_artifact_bytes`].
    max_artifact_bytes: u64,
    /// The `dl` template from `config.json`, fetched on first use and
    /// kept.
    ///
    /// A failed fetch leaves this empty, so the next call tries again.
    /// [`tokio::sync::OnceCell::get_or_try_init`] stores a value only when
    /// the future returns `Ok`, which gives that behavior for free.
    dl_template: tokio::sync::OnceCell<String>,
}

impl CargoUpstream {
    /// Builds a `CargoUpstream` against `index_base` (the sparse index
    /// root) with `download_limits` for the `.crate` download path.
    pub fn with_limits(index_base: Url, download_limits: &DownloadLimits) -> anyhow::Result<Self> {
        let index_client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("building the cargo index HTTP client")?;
        // No `.timeout(..)` on this client on purpose. That sets a total
        // deadline from connect to end of body, which caps artifact size
        // while it looks like a cap on time. `read_timeout` is the right
        // shape: it bounds how long the transfer may go without a byte and
        // resets on every read. `download_max_duration` bounds the whole
        // call from outside.
        let download_client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(download_limits.stall_timeout)
            .build()
            .context("building the cargo download HTTP client")?;
        Ok(Self {
            index_client,
            download_client,
            index_base,
            download_max_duration: download_limits.max_duration,
            max_artifact_bytes: download_limits.max_artifact_bytes,
            dl_template: tokio::sync::OnceCell::new(),
        })
    }

    /// Fetches and parses the sparse-index file for `name`.
    ///
    /// The name is normalized first, so `serde_json` and `serde-json` reach
    /// the same file. A 404 is [`UpstreamError::NotFound`]. Any other
    /// failure is [`UpstreamError::Unavailable`] or
    /// [`UpstreamError::Other`], never an empty list.
    pub async fn index_entries(&self, name: &str) -> Result<Vec<CargoIndexEntry>, UpstreamError> {
        let normalized = normalize_name(name);
        let url = self
            .index_base
            .join(&index::index_path_for(&normalized))
            .with_context(|| format!("building sparse index URL for {normalized:?}"))
            .map_err(UpstreamError::Other)?;

        let response = self.index_client.get(url).send().await.map_err(|err| {
            UpstreamError::Unavailable(format!(
                "request to the sparse index failed for {normalized:?}: {err}"
            ))
        })?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(UpstreamError::NotFound);
        }
        if !status.is_success() {
            return Err(UpstreamError::Unavailable(format!(
                "sparse index returned status {status} for {normalized:?}"
            )));
        }

        let body = response.text().await.map_err(|err| {
            UpstreamError::Unavailable(format!(
                "reading the sparse index body for {normalized:?} failed: {err}"
            ))
        })?;

        index::parse_index_lines(&body)
            .with_context(|| format!("parsing the sparse index file for {normalized:?}"))
            .map_err(UpstreamError::Other)
    }

    /// Returns the `dl` template from upstream's `config.json`, fetching it
    /// on first use.
    ///
    /// The template is kept only when the fetch succeeds and the body has
    /// a `dl` field. A failed fetch is not recorded, so the next call
    /// starts a new fetch.
    async fn dl_template(&self) -> Result<&str, UpstreamError> {
        self.dl_template
            .get_or_try_init(|| async {
                let url = self.acquire_config_url()?;
                let response = self
                    .index_client
                    .get(url.clone())
                    .send()
                    .await
                    .map_err(|err| {
                        UpstreamError::Unavailable(format!(
                            "request for cargo registry config.json failed: {err}"
                        ))
                    })?;
                let status = response.status();
                if status == reqwest::StatusCode::NOT_FOUND {
                    return Err(UpstreamError::NotFound);
                }
                if !status.is_success() {
                    return Err(UpstreamError::Unavailable(format!(
                        "cargo registry config.json returned status {status}"
                    )));
                }
                let body = response.text().await.map_err(|err| {
                    UpstreamError::Unavailable(format!(
                        "reading cargo registry config.json failed: {err}"
                    ))
                })?;
                let config: ConfigJson = serde_json::from_str(&body)
                    .with_context(|| format!("parsing cargo registry config.json from {url}"))?;
                Ok(config.dl)
            })
            .await
            .map(String::as_str)
    }

    /// Builds the URL of `config.json` under the sparse index root.
    fn acquire_config_url(&self) -> Result<Url, UpstreamError> {
        self.index_base
            .join("config.json")
            .context("building the cargo registry config.json URL")
            .map_err(UpstreamError::Other)
    }

    /// Downloads `name` at `version` to `dest` and returns the lowercase
    /// hex SHA-256 of the bytes written.
    ///
    /// The URL comes from the `dl` template in `config.json`, with the
    /// `{crate}`, `{version}`, and `{prefix}` markers expanded. The body is
    /// written to a temp file beside `dest` and renamed into place only
    /// after the transfer completes, so a failed download leaves nothing
    /// where a caller might find it.
    pub async fn download_crate(
        &self,
        name: &str,
        version: &str,
        dest: &Path,
    ) -> Result<String, UpstreamError> {
        match tokio::time::timeout(
            self.download_max_duration,
            self.download_inner(name, version, dest),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                // The inner future was dropped mid-stream, so its own
                // cleanup path never ran. Sweep the temp file it left.
                remove_part_files_beside(dest).await;
                Err(UpstreamError::Unavailable(format!(
                    "downloading {name:?} {version} exceeded the {:?} absolute download limit",
                    self.download_max_duration
                )))
            }
        }
    }

    async fn download_inner(
        &self,
        name: &str,
        version: &str,
        dest: &Path,
    ) -> Result<String, UpstreamError> {
        let url = self.download_url(name, version).await?;

        let response = self.download_client.get(url).send().await.map_err(|err| {
            UpstreamError::Unavailable(format!(
                "request to download {name:?} {version} failed: {err}"
            ))
        })?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(UpstreamError::NotFound);
        }
        if !status.is_success() {
            return Err(UpstreamError::Unavailable(format!(
                "upstream returned status {status} downloading {name:?} {version}"
            )));
        }
        // Refuse a body that declares its size and is too large, before a
        // single byte is written. A body with no `Content-Length`, or one
        // that understates it, still meets the running check in
        // `stream_to_file`.
        if let Some(declared) = response.content_length() {
            if declared > self.max_artifact_bytes {
                return Err(UpstreamError::Unavailable(format!(
                    "upstream declared {declared} bytes for {name:?} {version}, over the \
                     {}-byte artifact size limit",
                    self.max_artifact_bytes
                )));
            }
        }

        let tmp_path = temp_path_beside(dest)
            .with_context(|| format!("choosing a temp path beside {}", dest.display()))
            .map_err(UpstreamError::Other)?;

        match stream_to_file(response, &tmp_path, self.max_artifact_bytes).await {
            Ok(digest) => match tokio::fs::rename(&tmp_path, dest).await {
                Ok(()) => Ok(digest),
                Err(err) => {
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
                // Best effort: the download already failed, so a failed
                // cleanup must not hide the original error.
                let _ = tokio::fs::remove_file(&tmp_path).await;
                Err(UpstreamError::Other(err.context(format!(
                    "downloading {name:?} {version} to {}",
                    dest.display()
                ))))
            }
        }
    }

    /// Expands the `dl` template for `name` and `version` and parses the
    /// result as a URL.
    ///
    /// `{crate}` is the name as the caller gave it, not the normalized
    /// form. Task 5 passes the `name` field from the index entry, which is
    /// the name upstream published, and the download endpoint serves files
    /// under that name. `{prefix}` uses the normalized name, because it
    /// comes from the index path.
    async fn download_url(&self, name: &str, version: &str) -> Result<Url, UpstreamError> {
        let template = self.dl_template().await?;
        let expanded = template
            .replace("{crate}", name)
            .replace("{version}", version)
            .replace("{prefix}", &index::prefix_for(&normalize_name(name)));

        Url::parse(&expanded)
            .with_context(|| format!("parsing the expanded dl URL {expanded:?}"))
            .map_err(UpstreamError::Other)
    }
}

/// Streams `response`'s body into a freshly created file at `path`, hashes
/// every chunk as it writes it, and returns the lowercase hex SHA-256 of
/// everything received.
///
/// The caller removes the file at `path` on any error.
///
/// `max_bytes` bounds the running total of bytes received. It is the check
/// that stops a chunked body with no declared length, or one that
/// understates its `Content-Length`, from being written without end.
///
/// This is a local copy of the private helper of the same name in
/// `crate::ecosystem::pypi::upstream`. That copy is private to the PyPI
/// client, and the PyPI client's behavior must not change, so this module
/// keeps its own.
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
/// beside `dest`. The absolute duration cap cancels the download future,
/// so that future never reaches its own cleanup path.
///
/// It matches only the names [`temp_path_beside`] makes, so it cannot
/// delete a caller's files.
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
/// rename stays on one filesystem and is atomic. The random suffix keeps
/// two concurrent downloads of the same crate apart.
fn temp_path_beside(dest: &Path) -> anyhow::Result<std::path::PathBuf> {
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

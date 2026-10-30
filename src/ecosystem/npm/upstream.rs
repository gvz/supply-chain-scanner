//! The only module in this crate that talks to the npm registry upstream:
//! fetching a package's packument (its full metadata document) and
//! downloading a version's tarball with its digest verified.
//!
//! The scan path never fails open. A network error, a non-2xx status other
//! than 404, an oversized or unparseable packument, or a tarball whose
//! bytes do not match the digest upstream declared all become errors —
//! never a partial document and never unverified bytes on disk.
//!
//! As on the cargo and PyPI upstream paths, the two jobs need different
//! timeout shapes, so this client keeps two [`reqwest::Client`]s.
//!
//! - **The packument fetch** is a small JSON document. It keeps a total
//!   deadline, generous enough to stay well under
//!   [`crate::config::NpmRegistryConfig::scan_budget`]'s documented
//!   default of 120s (npm's own `fetch-timeout` is 300s, so a PyPI-shaped
//!   ~10s deadline would turn ordinary upstream slowness into a hard
//!   `npm install` failure).
//! - **The tarball download** has no total deadline. A total deadline
//!   caps artifact size while it pretends to cap time. Instead this
//!   client detects stalls with `read_timeout`, and
//!   [`crate::config::DownloadLimits::max_duration`] bounds the whole call
//!   from outside.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Context};
use futures_util::StreamExt;
use rand::Rng;
// `sha1::Digest` and `sha2::Digest` are the same trait, re-exported from
// the `digest` crate by both crates. Importing it once (via `sha1`) is
// enough to bring `.update(..)` and `.finalize()` into scope for both
// `Sha1` and `Sha512` below; a second import of the identical trait
// would be flagged as unused.
use sha1::{Digest, Sha1};
use sha2::Sha512;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::config::DownloadLimits;
use crate::ecosystem::npm::packument::{
    declared_digest, parse_packument, DeclaredDigest, DigestAlgorithm, Dist, Packument,
};
use crate::ecosystem::npm::packument_path;

/// Upper bound on establishing the TCP/TLS connection to upstream.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on an entire packument request (connect through end of
/// body). Kept well under
/// [`crate::config::NpmRegistryConfig::scan_budget`]'s documented default
/// of 120s, so one slow packument fetch cannot by itself consume the whole
/// scan budget.
///
/// Deliberately not applied to the tarball download path — see the module
/// docs and [`DownloadLimits`].
const REQUEST_TIMEOUT: Duration = Duration::from_secs(100);

/// What went wrong talking to the npm registry upstream.
///
/// `NotFound` (a real 404) is deliberately separate from `Unavailable` (an
/// outage, a timeout, or any other non-2xx status). A 404 means upstream
/// has spoken and said "no such thing". Callers must not treat it as an
/// outage, and must not let it wipe data they already hold.
#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("upstream npm registry is unavailable: {0}")]
    Unavailable(String),
    #[error("not found upstream")]
    NotFound,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// HTTP client for the npm registry's packument and tarball endpoints.
///
/// Two clients, deliberately. `packument_client` fetches small JSON
/// documents and keeps a total deadline. `download_client` streams
/// tarball bodies of unbounded size and must not have one. See
/// [`DownloadLimits`].
///
/// The ETag cache is a simple in-memory map of package name to (etag,
/// body). A `304` with no cached body for that name is
/// [`UpstreamError::Unavailable`], never an empty [`Packument`] — see
/// [`NpmUpstream::packument`].
pub struct NpmUpstream {
    /// Client for packument requests.
    packument_client: reqwest::Client,
    /// Client for tarball bodies. It has a stall timeout and no total
    /// timeout.
    download_client: reqwest::Client,
    /// The npm registry root, for example `https://registry.npmjs.org/`.
    registry_base: Url,
    /// Hard cap, in bytes, on one packument's downloaded size. See
    /// [`crate::config::NpmRegistryConfig::max_packument_bytes`].
    max_packument_bytes: u64,
    /// Absolute cap applied around one whole tarball download. See
    /// [`DownloadLimits::max_duration`].
    download_max_duration: Duration,
    /// Hard cap, in bytes, on one tarball. See
    /// [`DownloadLimits::max_artifact_bytes`].
    max_artifact_bytes: u64,
    /// Name -> (etag, body) of the last successfully fetched packument for
    /// that name. Populated only when upstream sends an `ETag`, and
    /// consulted on the next fetch via `If-None-Match`.
    etag_cache: Mutex<HashMap<String, (String, String)>>,
}

impl NpmUpstream {
    /// Builds an `NpmUpstream` against `registry_base` (the registry
    /// root) with `max_packument_bytes` bounding the packument path and
    /// `download_limits` bounding the tarball download path.
    pub fn with_limits(
        registry_base: Url,
        max_packument_bytes: u64,
        download_limits: &DownloadLimits,
    ) -> anyhow::Result<Self> {
        let packument_client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("building the npm packument HTTP client")?;
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
            .context("building the npm tarball download HTTP client")?;
        Ok(Self {
            packument_client,
            download_client,
            registry_base,
            max_packument_bytes,
            download_max_duration: download_limits.max_duration,
            max_artifact_bytes: download_limits.max_artifact_bytes,
            etag_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Fetches and parses `name`'s packument.
    ///
    /// Always requests the full document: no `Accept:
    /// application/vnd.npm.install-v1+json` header is sent, because the
    /// abbreviated form npm's own client requests omits the `time` map
    /// that the release-age gate needs.
    ///
    /// Sends `If-None-Match` from the ETag cache when a cached body
    /// exists for `name`. On a `304`, the cached body is reparsed and
    /// returned; if the cache has no body for `name` (which should not
    /// happen in practice, since a `304` implies a prior successful
    /// fetch), this is [`UpstreamError::Unavailable`], never an empty
    /// [`Packument`].
    ///
    /// The body is refused, before any parsing, if it is over
    /// `max_packument_bytes`: checked against `Content-Length` up front
    /// when upstream supplies one, and against the running byte total
    /// while streaming either way, since a response can omit or
    /// understate its length.
    pub async fn packument(&self, name: &str) -> Result<Packument, UpstreamError> {
        let url = self
            .registry_base
            .join(&packument_path(name))
            .with_context(|| format!("building the packument URL for {name:?}"))
            .map_err(UpstreamError::Other)?;

        let cached_etag = {
            let cache = self.etag_cache.lock().expect("etag cache mutex poisoned");
            cache.get(name).map(|(etag, _)| etag.clone())
        };

        let mut request = self.packument_client.get(url);
        if let Some(etag) = &cached_etag {
            request = request.header("If-None-Match", etag.clone());
        }

        let response = request.send().await.map_err(|err| {
            UpstreamError::Unavailable(format!(
                "request for the packument of {name:?} failed: {err}"
            ))
        })?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(UpstreamError::NotFound);
        }
        if status == reqwest::StatusCode::NOT_MODIFIED {
            let cache = self.etag_cache.lock().expect("etag cache mutex poisoned");
            return match cache.get(name) {
                Some((_, body)) => parse_packument(body)
                    .with_context(|| format!("parsing the cached packument for {name:?}"))
                    .map_err(UpstreamError::Other),
                None => Err(UpstreamError::Unavailable(format!(
                    "upstream answered 304 for {name:?} with no cached body to reuse"
                ))),
            };
        }
        if !status.is_success() {
            return Err(UpstreamError::Unavailable(format!(
                "upstream returned status {status} for the packument of {name:?}"
            )));
        }

        // Refuse a body that declares its size and is already over the
        // cap, before a single byte is read. A body with no
        // `Content-Length`, or one that understates it, still meets the
        // running check in `read_body_with_cap`.
        if let Some(declared) = response.content_length() {
            if declared > self.max_packument_bytes {
                return Err(UpstreamError::Unavailable(format!(
                    "upstream declared {declared} bytes for the packument of {name:?}, over \
                     the {}-byte packument size limit",
                    self.max_packument_bytes
                )));
            }
        }

        let etag_header = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);

        let body = read_body_with_cap(response, self.max_packument_bytes)
            .await
            .with_context(|| format!("reading the packument body for {name:?}"))
            .map_err(UpstreamError::Other)?;

        let packument = parse_packument(&body)
            .with_context(|| format!("parsing the packument for {name:?}"))
            .map_err(UpstreamError::Other)?;

        if let Some(etag) = etag_header {
            let mut cache = self.etag_cache.lock().expect("etag cache mutex poisoned");
            cache.insert(name.to_string(), (etag, body));
        }

        Ok(packument)
    }

    /// Downloads `name` at `version`'s tarball (from `dist.tarball`) to
    /// `dest`, verifying it against the digest [`declared_digest`]
    /// selects from `dist`, and returns the digest actually verified.
    ///
    /// A `dist` whose digest is unverifiable (`declared_digest` returns
    /// `None` — an unsupported `integrity` algorithm, malformed base64,
    /// or a decoded length that does not match the declared algorithm)
    /// is [`UpstreamError::Other`] before any request is made.
    ///
    /// The body is streamed to a temp path beside `dest` and renamed into
    /// place only once the transfer completes and its digest matches, so
    /// a failed or digest-mismatched download never leaves bytes where a
    /// caller might find them.
    pub async fn download_tarball(
        &self,
        name: &str,
        version: &str,
        dist: &Dist,
        dest: &Path,
    ) -> Result<DeclaredDigest, UpstreamError> {
        let declared = declared_digest(dist).ok_or_else(|| {
            UpstreamError::Other(anyhow::anyhow!(
                "{name:?}@{version} has no verifiable digest in its dist (an unsupported or \
                 malformed integrity string, with no usable shasum fallback)"
            ))
        })?;

        match tokio::time::timeout(
            self.download_max_duration,
            self.download_inner(name, version, dist, &declared, dest),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                // The inner future was dropped mid-stream, so its own
                // cleanup path never ran. Sweep the temp file it left.
                remove_part_files_beside(dest).await;
                Err(UpstreamError::Unavailable(format!(
                    "downloading {name:?}@{version} exceeded the {:?} absolute download limit",
                    self.download_max_duration
                )))
            }
        }
    }

    async fn download_inner(
        &self,
        name: &str,
        version: &str,
        dist: &Dist,
        declared: &DeclaredDigest,
        dest: &Path,
    ) -> Result<DeclaredDigest, UpstreamError> {
        let url = Url::parse(&dist.tarball)
            .with_context(|| format!("parsing the tarball URL for {name:?}@{version}"))
            .map_err(UpstreamError::Other)?;

        let response = self.download_client.get(url).send().await.map_err(|err| {
            UpstreamError::Unavailable(format!(
                "request to download {name:?}@{version} failed: {err}"
            ))
        })?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(UpstreamError::NotFound);
        }
        if !status.is_success() {
            return Err(UpstreamError::Unavailable(format!(
                "upstream returned status {status} downloading {name:?}@{version}"
            )));
        }
        // Refuse a body that declares its size and is too large, before a
        // single byte is written. A body with no `Content-Length`, or one
        // that understates it, still meets the running check in
        // `stream_to_file_verifying`.
        if let Some(declared_len) = response.content_length() {
            if declared_len > self.max_artifact_bytes {
                return Err(UpstreamError::Unavailable(format!(
                    "upstream declared {declared_len} bytes for {name:?}@{version}, over the \
                     {}-byte artifact size limit",
                    self.max_artifact_bytes
                )));
            }
        }

        let tmp_path = temp_path_beside(dest)
            .with_context(|| format!("choosing a temp path beside {}", dest.display()))
            .map_err(UpstreamError::Other)?;

        let streamed = stream_to_file_verifying(
            response,
            &tmp_path,
            self.max_artifact_bytes,
            declared.algorithm,
        )
        .await;

        match streamed {
            Ok(actual_hex) if actual_hex == declared.hex => {
                match tokio::fs::rename(&tmp_path, dest).await {
                    Ok(()) => Ok(declared.clone()),
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
                }
            }
            Ok(actual_hex) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                Err(UpstreamError::Other(anyhow::anyhow!(
                    "digest mismatch downloading {name:?}@{version}: upstream declared \
                     {}, computed {actual_hex}",
                    declared.hex
                )))
            }
            Err(err) => {
                // Best effort: the download already failed, so a failed
                // cleanup must not hide the original error.
                let _ = tokio::fs::remove_file(&tmp_path).await;
                Err(UpstreamError::Other(err.context(format!(
                    "downloading {name:?}@{version} to {}",
                    dest.display()
                ))))
            }
        }
    }
}

/// Reads `response`'s body into memory as UTF-8, bounded by `max_bytes`.
///
/// `max_bytes` bounds the running total of bytes received, independent of
/// (and in addition to) the `Content-Length` precheck in
/// [`NpmUpstream::packument`]: that check only catches a response that
/// *declares* its size, so this one is what actually stops a body with no
/// declared length, or one that understates it, from being read without
/// end.
async fn read_body_with_cap(response: reqwest::Response, max_bytes: u64) -> anyhow::Result<String> {
    let mut stream = response.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    let mut received: u64 = 0;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading response chunk from upstream")?;
        received = received.saturating_add(chunk.len() as u64);
        if received > max_bytes {
            bail!(
                "packument body exceeded the {max_bytes}-byte size limit \
                 ({received} bytes received so far)"
            );
        }
        buf.extend_from_slice(&chunk);
    }

    String::from_utf8(buf).context("packument body was not valid UTF-8")
}

/// A running hash over either of the two algorithms [`declared_digest`]
/// can select, so [`stream_to_file_verifying`] can hash with whichever
/// one a tarball's `dist` actually declared instead of a fixed algorithm.
enum RunningHash {
    Sha1(Sha1),
    Sha512(Sha512),
}

impl RunningHash {
    fn new(algorithm: DigestAlgorithm) -> Self {
        match algorithm {
            DigestAlgorithm::Sha1 => RunningHash::Sha1(Sha1::new()),
            DigestAlgorithm::Sha512 => RunningHash::Sha512(Sha512::new()),
        }
    }

    fn update(&mut self, chunk: &[u8]) {
        match self {
            RunningHash::Sha1(hasher) => hasher.update(chunk),
            RunningHash::Sha512(hasher) => hasher.update(chunk),
        }
    }

    fn finalize_hex(self) -> String {
        match self {
            RunningHash::Sha1(hasher) => hex::encode(hasher.finalize()),
            RunningHash::Sha512(hasher) => hex::encode(hasher.finalize()),
        }
    }
}

/// Streams `response`'s body into a freshly created file at `path`,
/// hashing every chunk as it writes it with `algorithm`, and returns the
/// lowercase hex digest of everything received.
///
/// The caller removes the file at `path` on any error.
///
/// `max_bytes` bounds the running total of bytes received, the same way
/// as [`read_body_with_cap`] does for packument bodies — it is what
/// actually stops a chunked or close-delimited body with no declared
/// length, or one that understates it, from being written without end.
async fn stream_to_file_verifying(
    response: reqwest::Response,
    path: &Path,
    max_bytes: u64,
    algorithm: DigestAlgorithm,
) -> anyhow::Result<String> {
    let mut file = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("creating temp file {}", path.display()))?;
    let mut hasher = RunningHash::new(algorithm);
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

    Ok(hasher.finalize_hex())
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
/// two concurrent downloads of the same tarball apart.
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
    let suffix = hex::encode(suffix_bytes);

    Ok(parent.join(format!(".{file_name}.{suffix}.part")))
}

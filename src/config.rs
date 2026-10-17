//! TOML configuration: loaded at startup and reloadable at runtime, with a
//! hard guarantee that a bad file can never replace a good running config.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use arc_swap::ArcSwap;
use serde::Deserialize;
use url::Url;

/// pip's default per-request timeout (`pip/_internal/cli/cmdoptions.py`).
/// The scan budget must stay below this, or a first-time scan always loses
/// the race against pip's own timeout.
const PIP_DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// The largest `scan_budget` this proxy will accept.
const MAX_SCAN_BUDGET: Duration = Duration::from_secs(14);

fn default_advisory_source_url() -> Url {
    Url::parse("https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip")
        .expect("default advisory source URL is valid")
}

/// The org's policy and runtime settings, read from a TOML file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    pub db_path: PathBuf,
    pub cache_dir: PathBuf,
    pub upstream_url: Url,
    pub public_url: Url,
    #[serde(with = "humantime_serde")]
    pub scan_budget: Duration,
    #[serde(with = "humantime_serde")]
    pub cache_ttl: Duration,
    #[serde(with = "humantime_serde")]
    pub advisory_sync_interval: Duration,
    /// Where the OSV advisory mirror is synced from. Defaults to the public
    /// OSV PyPI feed; a later task's tests point this at a local server.
    #[serde(default = "default_advisory_source_url")]
    pub advisory_source_url: Url,
    pub cve: CveLine,
    /// Timeouts for downloading an artifact's bytes. Optional — see
    /// [`DownloadLimits::default`].
    #[serde(default)]
    pub download: DownloadLimits,
    #[serde(default)]
    pub allowlist: Vec<AllowEntry>,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
    /// Overrides the automatic sizing of the full-scan concurrency bound
    /// (see `scan::full_scan_slots`). `None` (the default) derives the
    /// bound from the host's available parallelism — 2 per CPU, clamped
    /// to 2..=16 — which is the right call for most deployments: each
    /// full scan holds a `spawn_blocking` slot for the whole of a
    /// plugin's timeout plus three further OS threads for the sandbox
    /// run, and that same blocking pool also serves every SQLite call
    /// this crate makes, so an unbounded number of concurrent scans can
    /// starve ordinary verdict lookups.
    ///
    /// Baked into the `Scanner`'s semaphore once at construction (see
    /// `RESTART_ONLY_FIELDS`), not re-read on reload: shrinking a
    /// `tokio::sync::Semaphore` that already has permits checked out is
    /// not a well-defined operation, so this is a restart-only knob like
    /// `download`.
    #[serde(default)]
    pub max_concurrent_scans: Option<usize>,
}

/// How long an artifact download may take.
///
/// These exist because the obvious knob — one total request deadline — is
/// the wrong shape for this job. `reqwest`'s `ClientBuilder::timeout`
/// applies from connect until the response body finishes, so a 10 second
/// total deadline silently capped every servable artifact at 10 seconds ×
/// sustained throughput: a 300 MB wheel needed 30 MB/s held for the whole
/// transfer, and a 900 MB `torch` wheel needed 90 MB/s. Every large
/// ML/CUDA wheel was permanently unservable, surfacing to a developer as a
/// 503 that pip retries five times and then reports as an upstream
/// problem. A developer who cannot `pip install torch` through the proxy
/// sets `--index-url https://pypi.org/simple` the same afternoon, which is
/// the project's first anti-goal firing on ordinary input.
///
/// So the download path detects *stalls* instead of bounding *duration*,
/// with a generous absolute cap behind it as a backstop. The index-page
/// path is unaffected and keeps its total deadline: it fetches small
/// documents and sits in front of the scan budget.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DownloadLimits {
    /// How long a transfer may go without receiving a single byte before
    /// it is abandoned. This is the real safety limit: it catches a dead
    /// or black-holed connection in seconds regardless of artifact size,
    /// and it resets on every successful read, so an honest slow transfer
    /// is never penalized for being large.
    ///
    /// 30s is well above any pause a healthy CDN introduces mid-transfer
    /// and well below the point at which an operator would think the
    /// proxy had hung.
    #[serde(with = "humantime_serde")]
    pub stall_timeout: Duration,

    /// Absolute cap on one download, as a backstop against a connection
    /// that dribbles a byte at a time forever (which stall detection
    /// alone would never catch).
    ///
    /// 30 minutes is deliberately generous: the largest artifacts on PyPI
    /// are roughly 1 GB, which this allows at a sustained 600 KB/s — slow
    /// enough to cover a bad day on a bad link, which is exactly the case
    /// a tight cap gets wrong. A scan that outlives the much shorter
    /// `scan_budget` is not a failure: the request returns a retryable
    /// scan-in-progress while the detached scan keeps running and stores
    /// its verdict, so the developer's retry lands on a stored decision.
    #[serde(with = "humantime_serde")]
    pub max_duration: Duration,

    /// Hard cap, in bytes, on one artifact's downloaded size.
    ///
    /// Removing the old total-duration deadline (see `max_duration`'s own
    /// doc comment) left the download path with no byte budget at all:
    /// only stall detection and this struct's absolute-duration backstop
    /// stood between a tampered or MITM'd upstream — a threat this
    /// project explicitly models, since a hash mismatch against exactly
    /// such an upstream is logged as one — and up to `max_duration` of
    /// writing into `$TMPDIR`, which on a default Linux host is tmpfs
    /// backed by RAM. This closes that gap the same way
    /// [`crate::plugin::unpack`]'s own 512 MiB extraction cap closes the
    /// analogous one on the unpack side.
    ///
    /// 2 GiB clears every real artifact this proxy has been tested
    /// against with room to spare — including a 906 MB `torch` wheel —
    /// while still bounding a single download to a survivable write on
    /// any host that can run the proxy at all. Checked twice: against
    /// `Content-Length` up front when upstream supplies one (so an
    /// obviously oversized artifact is refused before a single byte
    /// arrives), and against the running total of bytes actually
    /// received (so a response lacking that header, or one that lies in
    /// it, is still caught while streaming).
    pub max_artifact_bytes: u64,
}

/// Default for [`DownloadLimits::max_artifact_bytes`]: 2 GiB. See that
/// field's own doc comment for why.
fn default_max_artifact_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}

impl Default for DownloadLimits {
    fn default() -> Self {
        Self {
            stall_timeout: Duration::from_secs(30),
            max_duration: Duration::from_secs(30 * 60),
            max_artifact_bytes: default_max_artifact_bytes(),
        }
    }
}

/// The org's line on CVE/advisory severity.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CveLine {
    pub min_severity: f32,
    pub require_fix_available: bool,
    /// How to treat advisories with missing or unparseable severity.
    /// Defaults to `Allow`: treating unknown severity as blocking would
    /// block a large share of ordinary packages on day one.
    #[serde(default)]
    pub unknown_severity: UnknownSeverity,
}

/// Whether advisories with missing or unparseable severity block a package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnknownSeverity {
    #[default]
    Allow,
    Block,
}

/// A specific package+version the org has reviewed and decided to permit,
/// overriding any stored verdict (but never hash verification).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    pub package: String,
    pub version: String,
}

/// One org-supplied check binary: invoked with the unpacked package, exit
/// code 0 means clean.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    pub name: String,
    pub binary: PathBuf,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

impl Config {
    /// Reads and parses the config file at `path`, rejecting unknown
    /// fields, missing required fields, and a `scan_budget` above the
    /// 14-second ceiling.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("parsing config file {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.scan_budget > MAX_SCAN_BUDGET {
            bail!(
                "scan_budget of {:?} exceeds the maximum of {:?} \
                 (pip's default timeout is {:?})",
                self.scan_budget,
                MAX_SCAN_BUDGET,
                PIP_DEFAULT_TIMEOUT
            );
        }
        Ok(())
    }
}

/// Holds the currently active [`Config`] and allows it to be reloaded from
/// disk without ever exposing a partially-applied or invalid config to
/// concurrent readers.
pub struct ConfigHandle {
    current: ArcSwap<Config>,
}

impl ConfigHandle {
    pub fn new(config: Config) -> Self {
        Self {
            current: ArcSwap::from_pointee(config),
        }
    }

    /// Returns the currently active config.
    pub fn current(&self) -> Arc<Config> {
        self.current.load_full()
    }

    /// Reloads the config from `path`. The file is fully parsed and
    /// validated before anything is swapped in, so a bad file leaves the
    /// previously running config untouched and returns `Err`.
    ///
    /// Swapping *only* this handle is not a complete reload: the policy
    /// fingerprint and the CVE line are compiled into
    /// [`crate::policy::Policy`], and the plugin list needs a sandbox
    /// built for it, so a `SIGHUP` goes through
    /// [`crate::http::Reloader::apply`] instead — which builds all of
    /// those from the new file first and calls [`ConfigHandle::store`]
    /// only once they have all succeeded. This method remains for callers
    /// that genuinely only want the config snapshot replaced.
    pub fn reload(&self, path: &Path) -> anyhow::Result<()> {
        let config = Config::load(path)?;
        self.store(config);
        Ok(())
    }

    /// Replaces the active config with one the caller has already parsed
    /// and validated.
    ///
    /// Separate from [`ConfigHandle::reload`] so a reload that must also
    /// rebuild the policy and the sandbox can do all of that *before*
    /// anything becomes visible to concurrent readers. That keeps the "a
    /// bad reload never replaces a good running configuration" guarantee
    /// across the whole reload, not just across TOML parsing.
    pub fn store(&self, config: Config) {
        self.current.store(Arc::new(config));
    }
}

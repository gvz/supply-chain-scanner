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
    /// The youngest a published file may be and still be forwarded, in
    /// days since it was uploaded. `None` (the default) turns this gate
    /// off entirely, so an unconfigured deployment behaves as it does
    /// today. This is the PyPI deployment's setting; a `[cargo_registry]`
    /// deployment sets `CargoRegistryConfig::min_release_age_days`
    /// instead, so the two ecosystems can run different thresholds (or
    /// one with the gate off and the other with it on).
    ///
    /// This is a best-effort hygiene control, not a security gate like
    /// `cve` or AI review: when upstream does not report a file's publish
    /// time at all (an index that predates PEP 700, or a lookup that
    /// fails), the gate does not block — it logs and defers to the other
    /// checks, which is why an age it cannot determine is never treated
    /// as "too new" the way a confirmed CVE is always treated as
    /// blocking.
    #[serde(default)]
    pub min_release_age_days: Option<u64>,
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
    /// The optional third scan gate: a language model reviews a package's
    /// source and judges whether it behaves maliciously. Absent means off,
    /// and an unconfigured deployment behaves as it does today.
    #[serde(default)]
    pub ai_review: Option<AiReviewConfig>,
    /// The cargo/crates.io deployment's own settings, read from the
    /// optional `[cargo_registry]` table. Absent means this process runs
    /// the PyPI deployment, exactly as it does today.
    ///
    /// One config file carries either this table or the PyPI settings,
    /// never both meaningfully: the two ecosystems ship as two
    /// deployments of the same binary.
    #[serde(default)]
    pub cargo_registry: Option<CargoRegistryConfig>,
    /// The npm registry deployment's own settings, read from the optional
    /// `[npm_registry]` table. Absent means this process runs the PyPI
    /// deployment, exactly as it does today.
    ///
    /// One config file carries at most one of `[cargo_registry]` or
    /// `[npm_registry]` — never both: the three ecosystems (PyPI, cargo,
    /// npm) ship as three deployments of the same binary.
    #[serde(default)]
    pub npm_registry: Option<NpmRegistryConfig>,
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

/// The smallest `max_payload_bytes` this proxy accepts. Below this, the
/// collector cannot hold even a small install-surface file plus the JSON
/// envelope.
const MIN_MAX_PAYLOAD_BYTES: usize = 4096;

fn default_ai_review_timeout() -> Duration {
    Duration::from_secs(8)
}

fn default_ai_review_max_payload_bytes() -> usize {
    262_144
}

fn default_ai_review_max_output_tokens() -> u32 {
    1024
}

fn default_ai_review_coverage_threshold() -> f32 {
    0.8
}

fn default_ai_review_enabled() -> bool {
    true
}

/// The reviewer and its bounds, read from the optional `[ai_review]`
/// table.
///
/// The struct holds the *name* of the environment variable that carries
/// the provider's API key. It never holds the key itself: the key must not
/// appear in a log line, a report, or a `Debug` output.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiReviewConfig {
    /// Whether the reviewer actually runs. Defaults to `true`, so a
    /// `[ai_review]` table that omits this behaves exactly as it always
    /// has. Setting it to `false` turns the reviewer off without losing
    /// the rest of the table — `base_url`, `model`, and everything else
    /// stay in the file, ready to flip back on — and [`Config::ai_review`]
    /// is the one place that reads it, so every caller that asks "is the
    /// reviewer on" sees the same answer. A disabled table still has to
    /// parse and validate in full (see [`Config::validate`]): disabling
    /// the reviewer is not a way to stage an incomplete one.
    #[serde(default = "default_ai_review_enabled")]
    pub enabled: bool,
    pub base_url: Url,
    pub model: String,
    /// Name of the environment variable that holds the API key. `None`
    /// sends no Authorization header. The variable must resolve at load
    /// and reload time, or the config is rejected.
    pub api_key_env: Option<String>,
    #[serde(with = "humantime_serde", default = "default_ai_review_timeout")]
    pub timeout: Duration,
    #[serde(default = "default_ai_review_max_payload_bytes")]
    pub max_payload_bytes: usize,
    #[serde(default = "default_ai_review_max_output_tokens")]
    pub max_output_tokens: u32,
    #[serde(default = "default_ai_review_coverage_threshold")]
    pub coverage_threshold: f32,
    #[serde(default)]
    pub block_on: BlockOn,
    #[serde(default)]
    pub block_opaque_executables: bool,
}

fn default_cargo_vet_sync_interval() -> Duration {
    Duration::from_secs(60 * 60)
}

fn default_required_criterion() -> String {
    "safe-to-deploy".to_string()
}

fn default_npm_scan_budget() -> Duration {
    Duration::from_secs(120)
}

fn default_npm_max_packument_bytes() -> u64 {
    67_108_864
}

/// The npm registry deployment's settings, read from the optional
/// `[npm_registry]` table.
///
/// Mirrors [`CargoRegistryConfig`]: every field that can have a sane
/// default has one, so a minimal table names only the upstream registry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NpmRegistryConfig {
    /// The npm registry this proxy fetches package metadata from, normally
    /// `https://registry.npmjs.org/`.
    pub upstream_registry_url: Url,
    /// How long a package metadata fetch may take. npm's client retries a
    /// 429 only twice by default, so a PyPI-shaped ~12-second deadline
    /// would convert ordinary slowness into a hard `npm install` failure.
    /// npm's own `fetch-timeout` is 300 seconds, so this deployment holds
    /// the connection on a much more generous budget (default 120s) instead.
    #[serde(with = "humantime_serde", default = "default_npm_scan_budget")]
    pub scan_budget: Duration,
    /// Hard cap, in bytes, on one packument's downloaded size. Packuments
    /// are small JSON documents (typically under 1 MiB) but must allow
    /// reasonable overages for packages with many versions. This is an
    /// operational safety limit, like [`DownloadLimits::max_artifact_bytes`].
    #[serde(default = "default_npm_max_packument_bytes")]
    pub max_packument_bytes: u64,
    /// The youngest a published package version may be and still be
    /// forwarded, in days since npm published it. `None` (the default) turns
    /// this gate off entirely, so an unconfigured npm deployment behaves as
    /// it does today. This is the npm deployment's setting; the
    /// `[cargo_registry]` deployment has its own independent setting, so
    /// the two ecosystems can run different thresholds (or one with the gate
    /// off and the other with it on).
    ///
    /// This is a best-effort hygiene control, not a security gate like
    /// `cve` or AI review: when upstream does not report a version's publish
    /// time at all, the gate does not block — it logs and defers to the
    /// other checks, which is why an age it cannot determine is never
    /// treated as "too new" the way a confirmed CVE is always treated as
    /// blocking.
    #[serde(default)]
    pub min_release_age_days: Option<u64>,
}

/// The cargo/crates.io deployment's settings, read from the optional
/// `[cargo_registry]` table.
///
/// Mirrors [`AiReviewConfig`]: every field that can have a sane default
/// has one, so a minimal table names only the upstream index.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CargoRegistryConfig {
    /// The sparse index this proxy fetches crate metadata from, normally
    /// `https://index.crates.io/`.
    pub upstream_index_url: Url,
    /// How often the local cargo-vet audit store is refreshed from every
    /// configured source.
    #[serde(with = "humantime_serde", default = "default_cargo_vet_sync_interval")]
    pub cargo_vet_sync_interval: Duration,
    /// The trusted cargo-vet audit sets to fetch. Optional — defaults to
    /// empty, which leaves the fast path with no proof to consult.
    #[serde(default)]
    pub cargo_vet_sources: Vec<CargoVetSource>,
    /// The cargo-vet criterion an audit must carry to stand in for AI
    /// review. Defaults to `"safe-to-deploy"`, the stricter of the two
    /// standard criteria, and is fully overridable: an org that sets
    /// `"safe-to-run"` gets the looser bar.
    #[serde(default = "default_required_criterion")]
    pub required_criterion: String,
    /// The specific auditors whose entry counts, when non-empty. Empty
    /// means any entry from a trusted source counts, by whoever audited
    /// it. Optional — defaults to empty.
    #[serde(default)]
    pub trusted_reviewers: Vec<String>,
    /// The cargo deployment's own version of [`Config::min_release_age_days`]:
    /// the youngest a crate version may be and still be forwarded, in days
    /// since crates.io published it. `None` turns the gate off for this
    /// deployment, independently of whatever the PyPI deployment's own
    /// setting is. Same best-effort semantics: a version whose publish
    /// time cannot be determined is never blocked on age grounds alone.
    #[serde(default)]
    pub min_release_age_days: Option<u64>,
}

/// One trusted cargo-vet audit set: a name for logs and errors, and the
/// URL its `audits.toml` is fetched from.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CargoVetSource {
    pub name: String,
    pub url: Url,
}

/// Which model verdicts block the artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockOn {
    #[default]
    Malicious,
    Suspicious,
}

/// Whether `url`'s host is a loopback address, to which plain HTTP is
/// acceptable (the traffic cannot leave the machine).
///
/// Matches on `Url::host()`, not `Url::host_str()`: an IPv6 literal's
/// string form in a URL's authority carries its brackets (`[::1]`), so a
/// plain string comparison against `"::1"` never matches, and the design
/// calls a local provider on an IPv6 loopback address first-class.
/// `Host`'s `Ipv4`/`Ipv6` variants carry a parsed `IpAddr` instead of
/// that string, so `is_loopback()` is correct regardless of bracket or
/// zone-id formatting.
fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
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

    /// The active `[ai_review]` table, or `None` when the table is
    /// absent *or* present with `enabled = false`. This is the one place
    /// that reads `AiReviewConfig::enabled`; every other caller that
    /// needs to know whether the reviewer is on should call this instead
    /// of reading `ai_review` directly, so a disabled table reads as
    /// "off" everywhere — the policy fingerprint, the reviewer
    /// construction at startup and on reload, the sandbox-requirement
    /// check, and the `/api/reviews` route gate all agree.
    pub fn ai_review(&self) -> Option<&AiReviewConfig> {
        self.ai_review.as_ref().filter(|ai| ai.enabled)
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
        if self.cargo_registry.is_some() && self.npm_registry.is_some() {
            bail!(
                "a config file must carry at most one of [cargo_registry] or \
                 [npm_registry], never both: each ecosystem runs as a separate deployment"
            );
        }
        if let Some(ai) = self.ai_review.as_ref() {
            // The reviewer's timeout must fit under the budget the
            // *selected deployment* actually draws from while reviewing
            // one candidate. On an npm deployment that is
            // `npm_registry.scan_budget` (default 120s, deliberately far
            // looser than the top-level field), never the top-level
            // `scan_budget` the PyPI and cargo paths read: that field is
            // capped at `MAX_SCAN_BUDGET` (14s), so validating against it
            // on an npm deployment would make a sensible 60s reviewer
            // timeout unloadable even though the npm cascade never reads
            // that field at all. The PyPI and cargo paths are untouched —
            // neither has a budget field of its own, so they keep
            // validating against `self.scan_budget` exactly as before.
            let effective_budget = self
                .npm_registry
                .as_ref()
                .map(|npm| npm.scan_budget)
                .unwrap_or(self.scan_budget);
            validate_ai_review(ai, effective_budget)?;
        }
        Ok(())
    }
}

/// Validates `[ai_review]`. In order: `timeout` against the scan budget,
/// `coverage_threshold` bounds, `max_payload_bytes` floor, `base_url`
/// scheme and host, `api_key_env` resolution.
///
/// `scan_budget` is the budget of whichever deployment this config
/// selects — `npm_registry.scan_budget` on an npm deployment, the
/// top-level `scan_budget` otherwise. See the call site in
/// [`Config::validate`].
fn validate_ai_review(ai: &AiReviewConfig, scan_budget: Duration) -> anyhow::Result<()> {
    if ai.timeout >= scan_budget {
        bail!(
            "ai_review timeout of {:?} must be below the scan_budget of {:?}",
            ai.timeout,
            scan_budget
        );
    }
    if !(0.0..=1.0).contains(&ai.coverage_threshold) {
        bail!(
            "ai_review coverage_threshold of {} is outside the allowed range 0.0 to 1.0",
            ai.coverage_threshold
        );
    }
    if ai.max_payload_bytes < MIN_MAX_PAYLOAD_BYTES {
        bail!(
            "ai_review max_payload_bytes of {} is below the minimum of {}",
            ai.max_payload_bytes,
            MIN_MAX_PAYLOAD_BYTES
        );
    }
    let scheme = ai.base_url.scheme();
    if scheme != "https" {
        let is_loopback = is_loopback_host(&ai.base_url);
        if scheme != "http" || !is_loopback {
            bail!(
                "ai_review base_url of \"{}\" must use https, or http with a loopback host \
                 (127.0.0.1, ::1, localhost)",
                ai.base_url
            );
        }
    }
    if let Some(name) = ai.api_key_env.as_ref() {
        if std::env::var(name).is_err() {
            bail!(
                "ai_review api_key_env of \"{name}\" does not resolve: the environment variable \
                 is not set"
            );
        }
    }
    Ok(())
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

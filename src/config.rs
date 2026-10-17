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
    #[serde(default)]
    pub allowlist: Vec<AllowEntry>,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
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
    pub fn reload(&self, path: &Path) -> anyhow::Result<()> {
        let config = Config::load(path)?;
        self.current.store(Arc::new(config));
        Ok(())
    }
}

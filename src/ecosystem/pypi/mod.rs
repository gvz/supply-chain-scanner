//! PyPI-specific protocol logic.

pub mod index;
pub mod upstream;

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;

use crate::ecosystem::traits::Ecosystem;

use index::{IndexEntry, InvalidName, ParsedArtifact};
use upstream::{Fetched, Upstream, UpstreamError};

/// The short identifier stored in [`crate::model::ArtifactKey::ecosystem`]
/// for every artifact scanned through this backend.
const ECOSYSTEM_ID: &str = "pypi";

/// The PyPI [`Ecosystem`] backend: every method here is a thin
/// pass-through to the PyPI-specific functions in [`index`] and the
/// [`Upstream`] client built in task 4, moved behind the trait without
/// changing their signatures.
pub struct PyPi {
    upstream: Arc<Upstream>,
}

impl PyPi {
    pub fn new(upstream: Arc<Upstream>) -> Self {
        Self { upstream }
    }

    /// The underlying upstream HTTP client, shared (not cloned) so the
    /// HTTP layer can call PyPI-specific operations — the PEP 658/714
    /// `.metadata` sidecar passthrough — that fall outside the
    /// ecosystem-agnostic [`Ecosystem`] trait.
    pub fn upstream(&self) -> Arc<Upstream> {
        Arc::clone(&self.upstream)
    }
}

#[async_trait]
impl Ecosystem for PyPi {
    fn id(&self) -> &'static str {
        ECOSYSTEM_ID
    }

    fn validate_name(&self, raw: &str) -> Result<String, InvalidName> {
        index::validate_package_name(raw)
    }

    fn parse_filename(&self, filename: &str) -> Option<ParsedArtifact> {
        index::parse_filename(filename)
    }

    async fn simple_page(&self, package: &str) -> Result<Fetched<Vec<IndexEntry>>, UpstreamError> {
        self.upstream.simple_page(package).await
    }

    async fn download(&self, entry: &IndexEntry, dest: &Path) -> Result<String, UpstreamError> {
        self.upstream.download(entry, dest).await
    }

    fn unpack(&self, archive: &Path, dest: &Path) -> anyhow::Result<()> {
        crate::plugin::unpack(archive, dest).map_err(anyhow::Error::from)
    }
}

//! The ecosystem-agnostic interface every package registry backend
//! implements.
//!
//! PyPI ([`crate::ecosystem::pypi::PyPi`]) is the only implementation
//! today. This trait exists so the HTTP layer (`src/http/simple.rs`,
//! `src/http/artifact.rs`) and the policy/scan layer can be written once
//! against `Arc<dyn Ecosystem>` rather than against PyPI concretely —
//! the seam a later npm or cargo backend would slot into without
//! touching the handlers at all.
//!
//! Every method here is a thin pass-through to the PyPI-specific function
//! or type it wraps (tasks 3, 4, and 8): this trait changes none of their
//! signatures or behavior, it only gives callers one name to hold
//! regardless of which ecosystem backend is behind it.

use std::path::Path;

use async_trait::async_trait;

use crate::ecosystem::pypi::index::{IndexEntry, InvalidName, ParsedArtifact};
use crate::ecosystem::pypi::upstream::{Fetched, UpstreamError};

/// One package registry backend: name validation, filename parsing, the
/// PEP-503-style simple index, artifact download, and archive unpacking.
#[async_trait]
pub trait Ecosystem: Send + Sync {
    /// The short identifier stored in [`crate::model::ArtifactKey::ecosystem`]
    /// and used as the `ecosystem` column throughout the database (e.g.
    /// `"pypi"`).
    fn id(&self) -> &'static str;

    /// Validates and normalizes a package name arriving from untrusted
    /// input (a URL path segment).
    fn validate_name(&self, raw: &str) -> Result<String, InvalidName>;

    /// Reads the package and version out of an artifact filename, if this
    /// ecosystem recognizes the filename's shape.
    fn parse_filename(&self, filename: &str) -> Option<ParsedArtifact>;

    /// Fetches the package index page listing every artifact offered for
    /// `package`.
    async fn simple_page(&self, package: &str) -> Result<Fetched<Vec<IndexEntry>>, UpstreamError>;

    /// Downloads `entry`'s artifact bytes to `dest`, returning the
    /// lowercase hex SHA-256 of what was actually written.
    async fn download(&self, entry: &IndexEntry, dest: &Path) -> Result<String, UpstreamError>;

    /// Extracts `archive` (as downloaded) into `dest` so a plugin can
    /// inspect its contents.
    fn unpack(&self, archive: &Path, dest: &Path) -> anyhow::Result<()>;
}

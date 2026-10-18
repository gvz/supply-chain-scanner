//! Supply chain scanner: an HTTP proxy that sits in front of PyPI, scans
//! every artifact exactly once (advisories plus org-supplied plugin
//! binaries), remembers the verdict, and refuses anything that failed a
//! check.
//!
//! This crate is organized as a library plus a thin binary so integration
//! tests can exercise the public API directly.

pub mod advisory;
pub mod ai;
pub mod artifact_cache;
pub mod config;
pub mod db;
pub mod ecosystem;
pub mod http;
pub mod model;
pub mod plugin;
pub mod policy;
pub mod scan;

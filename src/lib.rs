//! Supply chain scanner: an HTTP proxy that sits in front of PyPI, scans
//! every artifact exactly once (advisories plus org-supplied plugin
//! binaries), remembers the verdict, and refuses anything that failed a
//! check.
//!
//! This crate is organized as a library plus a thin binary so integration
//! tests can exercise the public API directly.

pub mod config;
pub mod model;

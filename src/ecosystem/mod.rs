//! Ecosystem-specific protocol logic. PyPI is implemented first; npm and
//! cargo are expected to follow. The trait that abstracts over ecosystems
//! arrives in a later task once there is more than one implementation to
//! generalize from.

pub mod pypi;

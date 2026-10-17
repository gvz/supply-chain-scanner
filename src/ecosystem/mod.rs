//! Ecosystem-specific protocol logic. PyPI is implemented first; npm and
//! cargo are expected to follow behind the same [`Ecosystem`] trait.

pub mod pypi;
pub mod traits;

pub use traits::Ecosystem;

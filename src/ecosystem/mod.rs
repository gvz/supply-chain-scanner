//! Ecosystem-specific protocol logic. PyPI is implemented first; npm and
//! cargo are expected to follow behind the same [`Ecosystem`] trait.

pub mod cargo;
pub mod install_surface;
pub mod pypi;
pub mod traits;

pub use install_surface::{install_surface_for, InstallSurface};
pub use traits::Ecosystem;

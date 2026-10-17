//! The HTTP surface a developer's package manager actually talks to.
//!
//! This module (and `refusal` and `why` alongside it) is the one part of
//! the system a blocked developer ever sees. [`AppState`] is deliberately
//! small today — just enough for the `/why/<id>` page this task builds —
//! and is extended by a later task with an `ecosystem` field and the rest
//! of the router (the simple-index passthrough and the download proxy).

pub mod refusal;
pub mod why;

use std::sync::Arc;

use crate::config::ConfigHandle;
use crate::db::verdict::VerdictStore;
use crate::scan::Scanner;

/// Shared state handed to every HTTP handler.
///
/// Cheap to clone (every field is an `Arc`), as required by axum's
/// `State` extractor.
#[derive(Clone)]
pub struct AppState {
    pub scanner: Arc<Scanner>,
    pub verdicts: Arc<VerdictStore>,
    pub config: Arc<ConfigHandle>,
}

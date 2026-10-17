//! Single-flight deduplication for in-progress scans, keyed by sha256.
//!
//! Without this, N concurrent requests for the same not-yet-verdicted
//! artifact would each independently download it from upstream, each
//! unpack it, and each run every plugin over it — N times the upstream
//! load and N times the plugin cost for one artifact. [`ScanCoordinator`]
//! makes the first caller for a given sha256 the owner of the scan; every
//! later caller for the *same* sha256, arriving while that scan is still
//! running, clones a [`watch::Receiver`] and waits on it instead of
//! starting a scan of its own.
//!
//! The channel carries `Option<Verdict>` rather than a richer result type
//! deliberately: only a genuine scan outcome (clean or blocked) is
//! something a late joiner can safely reuse. A scan that fails before
//! producing a verdict — a download error, a hash mismatch — sends
//! nothing and simply lets its [`watch::Sender`] drop; a joiner observing
//! that treats it as "this artifact could not be verified," which is
//! exactly the fail-closed answer such a failure deserves (see
//! [`crate::scan::Decision::Unverifiable`]).
//!
//! The owning scan is always driven by a detached `tokio::spawn`, started
//! by [`crate::scan::Scanner`] before this coordinator is ever consulted
//! for the result: a caller's own budget timeout only stops *that caller*
//! from waiting any longer, never the scan itself, so a scan a requester
//! gave up on still finishes and still gets stored.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

use crate::model::Verdict;

/// Deduplicates concurrent scans of the same artifact content.
pub struct ScanCoordinator {
    inflight: Mutex<HashMap<String, watch::Receiver<Option<Verdict>>>>,
}

impl ScanCoordinator {
    pub fn new() -> Self {
        Self {
            inflight: Mutex::new(HashMap::new()),
        }
    }

    /// Either claims ownership of the scan for `sha256`, or joins one
    /// already running.
    ///
    /// `Ok(sender)` means the caller is the owner: no other scan for this
    /// sha256 is in flight, and the caller is now responsible for running
    /// the scan, sending its outcome (or dropping the sender without
    /// sending, on a failure with no verdict to report), and calling
    /// [`ScanCoordinator::finish`] exactly once when it's done.
    ///
    /// `Err(receiver)` means a scan for this sha256 is already running;
    /// the caller should await the receiver's value instead of starting
    /// its own scan.
    pub fn start_or_join(
        &self,
        sha256: &str,
    ) -> Result<watch::Sender<Option<Verdict>>, watch::Receiver<Option<Verdict>>> {
        let mut inflight = self.inflight.lock().expect("scan coordinator mutex");
        if let Some(existing) = inflight.get(sha256) {
            return Err(existing.clone());
        }
        let (tx, rx) = watch::channel(None);
        inflight.insert(sha256.to_string(), rx);
        Ok(tx)
    }

    /// Removes the in-flight entry for `sha256`, called by the owner once
    /// its scan has finished (successfully or not) and its outcome, if
    /// any, has already been sent. A request for the same sha256 arriving
    /// after this call starts a fresh scan rather than joining a finished
    /// one — which is safe, because by construction the owner only calls
    /// this after any verdict it produced is already durably stored.
    ///
    /// Prefer [`FinishGuard`] over calling this directly from the owner's
    /// task body: a bare call here is skipped if the scan body panics,
    /// leaking the entry for the rest of the process's life (see
    /// [`FinishGuard`]'s docs).
    pub fn finish(&self, sha256: &str) {
        self.inflight
            .lock()
            .expect("scan coordinator mutex")
            .remove(sha256);
    }
}

impl Default for ScanCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Guarantees [`ScanCoordinator::finish`] runs for the owner's sha256 no
/// matter how its scan task exits — a normal return, an early `return`,
/// or a panic unwinding through it.
///
/// Without this, a panic inside the owner's scan body (a bug in a future
/// check, an unexpected `unwrap`, anything) unwinds straight past a bare
/// `coordinator.finish(...)` call placed after the scan. The in-flight
/// map entry is never removed. Every later request for that same sha256
/// then calls [`ScanCoordinator::start_or_join`], finds the stale entry,
/// and joins a receiver whose sender was already dropped during the
/// panic — which [`wait_for_verdict`] correctly resolves to `None` (fail
/// closed, never a false `Serve`), but *every* request for that artifact
/// gets stuck there forever, for the life of the process: a permanent
/// denial of service for one artifact, which is exactly the failure mode
/// this project exists to avoid on the other side of the ledger.
///
/// Constructing a `FinishGuard` as the very first statement in the
/// owner's task body — before the scan itself runs — means its `Drop`
/// fires last among that task's locals, after the scan has produced its
/// outcome and that outcome has been sent, on every exit path including
/// one added later by a future change to that body.
pub struct FinishGuard {
    coordinator: Arc<ScanCoordinator>,
    sha256: String,
}

impl FinishGuard {
    pub fn new(coordinator: Arc<ScanCoordinator>, sha256: String) -> Self {
        Self {
            coordinator,
            sha256,
        }
    }
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        self.coordinator.finish(&self.sha256);
    }
}

/// Awaits the outcome of a scan this caller joined rather than owns:
/// `Some(verdict)` once the owner reports one, or `None` if the owner's
/// sender is dropped without ever sending (a failure with no verdict to
/// share).
pub async fn wait_for_verdict(mut rx: watch::Receiver<Option<Verdict>>) -> Option<Verdict> {
    if let Some(verdict) = rx.borrow().clone() {
        return Some(verdict);
    }
    loop {
        if rx.changed().await.is_err() {
            return None;
        }
        if let Some(verdict) = rx.borrow().clone() {
            return Some(verdict);
        }
    }
}

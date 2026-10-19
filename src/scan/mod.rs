//! The scan pipeline: the one place that decides whether an artifact may
//! be served.
//!
//! [`Scanner::decide`] composes every earlier task — the verdict store,
//! the policy and its allowlist, the advisory mirror and matcher, the
//! upstream HTTP client, the plugin runner, and the artifact cache — into
//! a single decision path:
//!
//! ```text
//! allowlist hit        -> still verify hash, then serve
//! stored blocked        -> refuse
//! stored clean          -> re-check advisories, then serve
//! no verdict            -> full scan under budget, single flight
//! ```
//!
//! and, inside a full scan, stops at the first failure:
//!
//! ```text
//! advisory lookup -> download -> hash verify -> unpack + plugins -> ai review -> store clean, cache, serve
//! ```
//!
//! Nothing here ever produces [`Decision::Serve`] or a stored
//! [`Verdict::Clean`] from an error path. An upstream outage, a hash
//! mismatch, a plugin that could not run, a database error, a panic in a
//! blocking task — every one of them becomes a refusal or
//! [`Decision::Unverifiable`], never a guess in the artifact's favor. An
//! index entry with no declared hash is always `Unverifiable`: there is
//! nothing to verify a download against, so it can never be scanned
//! honestly, allowlisted or not — allowlisting overrides a *verdict*, not
//! the integrity check the artifact's bytes have to pass regardless.
//!
//! The full-scan path alone is wrapped in [`ScanCoordinator`]'s
//! single-flight dedup (keyed by the artifact's sha256, since that is
//! what a concurrent request for "the same artifact" actually shares) and
//! in [`tokio::time::timeout`] against `config.scan_budget`: a slow scan
//! returns [`Decision::InProgress`] to its caller without being cancelled
//! — it keeps running, detached, and stores its verdict when it finishes,
//! so a developer's retry lands on a stored decision instead of
//! restarting the scan from zero.

pub mod cargo_cascade;
pub mod coordinator;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use arc_swap::ArcSwap;
use tokio::sync::Semaphore;

use crate::advisory::matching::first_blocking;
use crate::advisory::Advisory;
use crate::ai::{AiReviewer, ReviewOutcome};
use crate::artifact_cache::ArtifactCache;
use crate::config::{Config, ConfigHandle, PluginConfig};
use crate::db::advisory::AdvisoryStore;
use crate::db::verdict::{StoredVerdict, VerdictStore};
use crate::ecosystem::pypi::index::{normalize_name, IndexEntry};
use crate::ecosystem::pypi::upstream::{Upstream, UpstreamError};
use crate::model::{ArtifactKey, RefusalReason, Verdict};
use crate::plugin::{unpack, PluginRunner, UnpackError};
use crate::policy::Policy;

use coordinator::{FinishGuard, ScanCoordinator};

/// The cap, in characters, on a sanitized internal-error or upstream-error
/// detail. These details can embed attacker-influenced or merely verbose
/// upstream text (an HTTP error body, an `anyhow` error chain), and this
/// text ultimately feeds an HTTP reason phrase (task 11), so it is capped
/// and stripped of anything that could make that unsafe or unreadable —
/// the same discipline [`crate::advisory::matching`] and
/// [`crate::plugin`] already apply to their own refusal details.
const DETAIL_MAX_CHARS: usize = 200;

/// How many full scans may run at once, as a multiple of the host's
/// available parallelism, and the floor/ceiling that multiple is clamped
/// to.
///
/// A full scan is the expensive path: it holds a `spawn_blocking` slot for
/// the whole of each plugin's timeout, and [`crate::plugin::sandbox`]
/// spends three further OS threads per sandbox run (two pipe readers and a
/// `wait`). The *same* blocking pool serves every SQLite call this crate
/// makes, so without a bound, a parallel dependency resolution or a pip
/// retry storm starves verdict lookups and turns ordinary requests into
/// `Unverifiable`/`InProgress` — a self-inflicted outage that reads to a
/// developer as the proxy being broken.
///
/// The bound is deliberately on *concurrent full scans*, not on requests:
/// a request that cannot get a slot returns the retryable
/// [`Decision::InProgress`] (HTTP 429) while its scan waits, which is the
/// same contract a scan that merely exceeds its budget already has.
const FULL_SCAN_SLOTS_PER_CPU: usize = 2;
const FULL_SCAN_SLOTS_MIN: usize = 2;
const FULL_SCAN_SLOTS_MAX: usize = 16;

/// The bound on concurrent full scans for this host: `override_slots`
/// (`Config::max_concurrent_scans`) verbatim when the operator set one
/// (clamped only to a minimum of 1 — a configured `0` would deadlock every
/// scan forever rather than express "no limit"), otherwise derived from
/// the host's available parallelism at 2 per CPU, clamped to
/// `FULL_SCAN_SLOTS_MIN..=FULL_SCAN_SLOTS_MAX`.
fn full_scan_slots(override_slots: Option<usize>) -> usize {
    if let Some(configured) = override_slots {
        return configured.max(1);
    }
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    (cpus * FULL_SCAN_SLOTS_PER_CPU).clamp(FULL_SCAN_SLOTS_MIN, FULL_SCAN_SLOTS_MAX)
}

/// The outcome of [`Scanner::decide`] for one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The artifact may be served from the path given.
    Serve(PathBuf),
    /// The artifact must not be served. `why_id`, when present, names a
    /// stored verdict a developer can look up at `/why/<id>` (task 11);
    /// it is `None` for a refusal with no stored verdict behind it, such
    /// as a hash mismatch that was never persisted because it may be a
    /// transient download corruption rather than a property of the
    /// artifact itself.
    Refuse {
        reason: RefusalReason,
        why_id: Option<String>,
    },
    /// The scan is still running, having exceeded the configured budget.
    /// The caller should ask again shortly; the scan itself was not
    /// cancelled and will store its verdict when it finishes.
    InProgress,
    /// The artifact cannot currently be confirmed safe or unsafe — an
    /// index entry with no declared hash, an unreachable upstream with
    /// nothing cached, or an internal failure partway through a scan.
    /// Distinct from [`Decision::Refuse`]: this is "cannot verify right
    /// now," never "verified and blocked," and it is never stored as a
    /// verdict.
    Unverifiable(RefusalReason),
}

/// What went wrong fetching and verifying an artifact's bytes against its
/// index-declared hash, used internally to tell "could not even check"
/// apart from "checked, and it failed."
enum FetchError {
    /// The artifact could not be downloaded (or re-downloaded) right now.
    Unverifiable(RefusalReason),
    /// The downloaded bytes do not match the index-declared hash.
    Mismatch(RefusalReason),
}

/// The checks one decision runs under, swapped as a single unit on a
/// configuration reload.
///
/// These three travel together deliberately. A `SIGHUP` that only swapped
/// some of them produced exactly the defect this type exists to prevent:
/// the plugin list was read live from `ConfigHandle` while the fingerprint
/// and the CVE line came from a `Policy` frozen at startup, so a reload
/// could add a plugin that ran on new scans while already-`Clean`
/// artifacts kept serving from a verdict that had never met it — and the
/// fingerprint column, whose entire job is to identify which checks
/// produced a row, stopped doing so. `sandbox` is in here for the same
/// reason: a proxy that booted with no plugins holds a panicking stub
/// sandbox, so a reload that adds a plugin has to bring a real one with
/// it or every subsequent scan refuses.
///
/// [`Scanner::decide`] loads one snapshot of this at its entry point and
/// uses that same snapshot all the way down, so a reload landing mid-scan
/// can never give one decision a mixture of old and new checks.
pub struct ScanRules {
    policy: Arc<Policy>,
    plugins: Vec<PluginConfig>,
    plugin_runner: Arc<PluginRunner>,
    /// The reviewer, when `[ai_review]` is configured. Travels with the
    /// policy for the same reason the plugin runner does: the reviewer
    /// is built from the same config that produced the fingerprint, so
    /// a scan always runs the review policy its snapshot was built
    /// under, and a reload swaps the two as one unit.
    ai_reviewer: Option<Arc<AiReviewer>>,
}

impl ScanRules {
    fn new(
        policy: Policy,
        plugin_runner: PluginRunner,
        plugins: Vec<PluginConfig>,
        ai_reviewer: Option<Arc<AiReviewer>>,
    ) -> Self {
        Self {
            policy: Arc::new(policy),
            plugins,
            plugin_runner: Arc::new(plugin_runner),
            ai_reviewer,
        }
    }
}

/// Composes every scanning dependency into the one place that decides
/// whether an artifact may be served.
///
/// Cheap to clone: every field is an `Arc`, so a clone can be moved into a
/// detached `tokio::spawn`'d scan without borrowing from the caller's
/// stack frame — which is exactly what letting a scan outlive a caller's
/// budget timeout requires. The clone also shares the `ArcSwap` holding
/// the [`ScanRules`], so a reload applied through any clone is visible to
/// all of them.
#[derive(Clone)]
pub struct Scanner {
    verdict_store: Arc<VerdictStore>,
    upstream: Arc<Upstream>,
    rules: Arc<ArcSwap<ScanRules>>,
    advisory_store: Arc<AdvisoryStore>,
    artifact_cache: Arc<ArtifactCache>,
    config: Arc<ConfigHandle>,
    coordinator: Arc<ScanCoordinator>,
    /// Single-flight dedup for the hash-verified fetch path (allowlist
    /// hits and stored-clean re-serves), kept separate from
    /// `coordinator` — see [`Scanner::fetch_decision`].
    fetch_coordinator: Arc<ScanCoordinator>,
    /// The bound on concurrent full scans; see [`full_scan_slots`] and
    /// [`Config::max_concurrent_scans`].
    full_scan_slots: Arc<Semaphore>,
}

impl Scanner {
    // The argument count is the plan's own interface: every construction
    // dependency is handed in explicitly, so a test can substitute any
    // one of them. Grouping them into a builder would hide which callers
    // replaced which seam, for no gain at eight call sites.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verdict_store: VerdictStore,
        upstream: Upstream,
        policy: Policy,
        advisory_store: AdvisoryStore,
        plugin_runner: PluginRunner,
        artifact_cache: ArtifactCache,
        config: Arc<ConfigHandle>,
        ai_reviewer: Option<Arc<AiReviewer>>,
    ) -> Self {
        let plugins = config.current().plugins.clone();
        let slots = full_scan_slots(config.current().max_concurrent_scans);
        Self {
            verdict_store: Arc::new(verdict_store),
            upstream: Arc::new(upstream),
            rules: Arc::new(ArcSwap::from_pointee(ScanRules::new(
                policy,
                plugin_runner,
                plugins,
                ai_reviewer,
            ))),
            advisory_store: Arc::new(advisory_store),
            artifact_cache: Arc::new(artifact_cache),
            config,
            coordinator: Arc::new(ScanCoordinator::new()),
            fetch_coordinator: Arc::new(ScanCoordinator::new()),
            full_scan_slots: Arc::new(Semaphore::new(slots)),
        }
    }

    /// Replaces the checks every *subsequent* decision runs under, as one
    /// atomic swap.
    ///
    /// A decision already in flight keeps the snapshot it loaded at its
    /// entry point, so it finishes under the rules it started with — the
    /// invariant [`crate::policy::Policy`]'s immutability was always
    /// meant to provide, now preserved by snapshotting rather than by
    /// never rebuilding.
    ///
    /// The caller is responsible for having built `policy`, `sandbox` and
    /// the plugin list successfully *before* calling this; see
    /// [`crate::http::Reloader::apply`], which is the only caller and
    /// which keeps the previous rules in place if any part of that build
    /// fails.
    ///
    /// `ai_reviewer` is `None` when the reloaded configuration has no
    /// `[ai_review]` table: a reload that turns the reviewer off must
    /// remove it from the snapshot the same way the reverse adds it.
    pub fn apply_reloaded_rules(
        &self,
        policy: Policy,
        plugin_runner: PluginRunner,
        plugins: Vec<PluginConfig>,
        ai_reviewer: Option<Arc<AiReviewer>>,
    ) {
        self.rules.store(Arc::new(ScanRules::new(
            policy,
            plugin_runner,
            plugins,
            ai_reviewer,
        )));
    }

    /// The fingerprint of the policy currently in force.
    pub fn fingerprint(&self) -> String {
        self.rules.load().policy.fingerprint().to_string()
    }

    /// Decides whether `key` (as offered by `entry` in the simple index)
    /// may be served. See the module docs for the decision path.
    pub async fn decide(&self, key: &ArtifactKey, entry: &IndexEntry) -> Decision {
        let decision = self.decide_inner(key, entry).await;
        log_decision(key, &decision);
        decision
    }

    async fn decide_inner(&self, key: &ArtifactKey, entry: &IndexEntry) -> Decision {
        if entry.sha256.is_none() {
            // Absolute, ahead of every other rule: there is nothing to
            // verify a download against, so this artifact can never be
            // scanned honestly, allowlisted or not.
            return Decision::Unverifiable(no_hash_reason());
        }

        if is_allowlisted(&self.config.current(), &key.package, &key.version) {
            // The allowlist overrides any stored verdict, but never the
            // integrity check: the bytes still have to match the hash
            // the index declared.
            return self.fetch_decision(key, entry).await;
        }

        // One snapshot for the whole decision: see [`ScanRules`].
        let rules = self.rules.load_full();
        let fingerprint = rules.policy.fingerprint().to_string();

        match self.lookup_stored_verdict(key, &fingerprint).await {
            Ok(Some(stored)) => match stored.verdict {
                Verdict::Blocked(reason) => Decision::Refuse {
                    reason,
                    why_id: Some(stored.why_id),
                },
                Verdict::Clean => {
                    self.serve_known_clean(key, entry, &rules, &fingerprint)
                        .await
                }
            },
            // No verdict stored under today's policy — either this
            // artifact has never been scanned, or the policy changed
            // since it last was. Either way, a full scan is required.
            Ok(None) => {
                self.scan_with_budget(key, entry, &rules, &fingerprint)
                    .await
            }
            Err(_) => Decision::Unverifiable(internal_error_reason_simple(
                "looking up the stored verdict",
            )),
        }
    }

    /// Lists the filenames currently blocked for `(ecosystem, package)`
    /// under today's policy, for filtering the simple index page. This is
    /// a display-only convenience — the real gate is [`Scanner::decide`],
    /// which every download request still goes through regardless of
    /// what the index page showed — so a lookup failure here fails back
    /// to an empty set rather than propagating an error that this
    /// signature has no way to report.
    pub async fn blocked_filenames(&self, ecosystem: &str, package: &str) -> HashSet<String> {
        let fingerprint = self.fingerprint();
        let store = Arc::clone(&self.verdict_store);
        let ecosystem_owned = ecosystem.to_string();
        let package_owned = package.to_string();

        let result = tokio::task::spawn_blocking(move || {
            store.blocked_filenames(&ecosystem_owned, &package_owned, &fingerprint)
        })
        .await;

        match result {
            Ok(Ok(filenames)) => filenames,
            Ok(Err(err)) => {
                tracing::warn!(
                    ecosystem,
                    package,
                    error = %err,
                    "blocked_filenames lookup failed; the index listing for this \
                     package will not be filtered until this is resolved, though \
                     decide() independently refuses any blocked artifact regardless"
                );
                HashSet::new()
            }
            Err(join_error) => {
                tracing::warn!(
                    ecosystem,
                    package,
                    error = %join_error,
                    "blocked_filenames lookup task panicked; the index listing for \
                     this package will not be filtered until this is resolved, \
                     though decide() independently refuses any blocked artifact \
                     regardless"
                );
                HashSet::new()
            }
        }
    }

    // -----------------------------------------------------------------
    // Stored-clean re-check
    // -----------------------------------------------------------------

    /// A verdict of `Clean` was stored under today's policy. It is
    /// re-checked against the advisory mirror before ever being served,
    /// because a package clean when scanned may have a CVE filed since.
    async fn serve_known_clean(
        &self,
        key: &ArtifactKey,
        entry: &IndexEntry,
        rules: &ScanRules,
        fingerprint: &str,
    ) -> Decision {
        let advisories = match self.advisory_lookup(&key.ecosystem, &key.package).await {
            Ok(advisories) => advisories,
            Err(_) => {
                return Decision::Unverifiable(internal_error_reason_simple(
                    "looking up advisories",
                ))
            }
        };

        if let Some(reason) = first_blocking(&advisories, &key.version, &rules.policy) {
            let why_id = self
                .store_verdict(key, &Verdict::Blocked(reason.clone()), fingerprint)
                .await
                .ok();
            return Decision::Refuse { reason, why_id };
        }

        self.fetch_decision(key, entry).await
    }

    // -----------------------------------------------------------------
    // Full scan: budget + single flight
    // -----------------------------------------------------------------

    /// Runs (or joins) a full scan for `key`, deduplicated by sha256 and
    /// bounded by `config.scan_budget`. See the module docs for why the
    /// scan itself is never cancelled by a caller's budget running out.
    async fn scan_with_budget(
        &self,
        key: &ArtifactKey,
        entry: &IndexEntry,
        rules: &Arc<ScanRules>,
        fingerprint: &str,
    ) -> Decision {
        let sha256 = key.sha256.clone();
        let budget = self.config.current().scan_budget;

        match self.coordinator.start_or_join(&sha256) {
            Ok(tx) => {
                let scanner = self.clone();
                let key = key.clone();
                let entry = entry.clone();
                let rules = Arc::clone(rules);
                let fingerprint = fingerprint.to_string();
                let coordinator = Arc::clone(&self.coordinator);
                let sha256_for_cleanup = sha256.clone();

                // Detached: this task is not cancelled by the owner's own
                // budget timeout below, nor by any later joiner's. It
                // runs to completion, stores whatever it finds, and
                // reports the outcome to anyone still listening.
                //
                // `_finish_guard` is constructed first so its `Drop` runs
                // last — after the scan and the send below on a normal
                // exit, and in place of them if `run_full_scan` panics —
                // so the coordinator's map entry for this sha256 is
                // removed no matter how this task ends, never leaking it
                // for the rest of the process's life.
                let handle = tokio::spawn(async move {
                    let _finish_guard = FinishGuard::new(coordinator, sha256_for_cleanup);
                    // The permit is taken *inside* the detached task, not
                    // by the caller: a caller that gives up on its budget
                    // must not hold a slot, and a caller still waiting
                    // sees `InProgress` (a retryable 429) rather than a
                    // thread of the blocking pool being tied up on its
                    // behalf. See `FULL_SCAN_CONCURRENCY`.
                    let permit = scanner.full_scan_slots.clone().acquire_owned().await;
                    let decision = match permit {
                        Ok(permit) => {
                            let decision = scanner
                                .run_full_scan(&key, &entry, &rules, &fingerprint)
                                .await;
                            drop(permit);
                            decision
                        }
                        // The semaphore is owned by this `Scanner` and is
                        // never closed, so this is unreachable in
                        // practice; refuse rather than scan unbounded.
                        Err(_) => Decision::Unverifiable(internal_error_reason_simple(
                            "the scan concurrency limiter was closed",
                        )),
                    };
                    let _ = tx.send(verdict_for_dedup(&decision));
                    decision
                });

                match tokio::time::timeout(budget, handle).await {
                    Ok(Ok(decision)) => decision,
                    Ok(Err(_join_error)) => {
                        Decision::Unverifiable(internal_error_reason_simple("scan task panicked"))
                    }
                    Err(_elapsed) => Decision::InProgress,
                }
            }
            Err(rx) => {
                match tokio::time::timeout(budget, coordinator::wait_for_verdict(rx)).await {
                    Ok(verdict) => {
                        self.decision_from_joined_verdict(key, verdict, fingerprint)
                            .await
                    }
                    Err(_elapsed) => Decision::InProgress,
                }
            }
        }
    }

    /// Resolves a verdict learned from another caller's scan (via the
    /// coordinator) into this caller's own [`Decision`]. `None` means the
    /// owning scan ended without producing a verdict at all (e.g. a
    /// download failure) — nothing to reuse, so this is `Unverifiable`
    /// too.
    async fn decision_from_joined_verdict(
        &self,
        key: &ArtifactKey,
        verdict: Option<Verdict>,
        fingerprint: &str,
    ) -> Decision {
        match verdict {
            None => Decision::Unverifiable(scan_incomplete_reason()),
            Some(Verdict::Clean) => match self.cache_get(key).await {
                Ok(Some(path)) => Decision::Serve(path),
                _ => Decision::Unverifiable(internal_error_reason_simple(
                    "a verified artifact was missing from the cache",
                )),
            },
            Some(Verdict::Blocked(reason)) => {
                let why_id = match self.lookup_stored_verdict(key, fingerprint).await {
                    Ok(Some(stored)) => Some(stored.why_id),
                    _ => None,
                };
                Decision::Refuse { reason, why_id }
            }
        }
    }

    /// Runs the full scan, stopping at the first failure: advisory lookup
    /// -> download -> hash verify -> unpack + plugins -> store clean,
    /// cache, serve.
    async fn run_full_scan(
        &self,
        key: &ArtifactKey,
        entry: &IndexEntry,
        rules: &ScanRules,
        fingerprint: &str,
    ) -> Decision {
        let advisories = match self.advisory_lookup(&key.ecosystem, &key.package).await {
            Ok(advisories) => advisories,
            Err(_) => {
                return Decision::Unverifiable(internal_error_reason_simple(
                    "looking up advisories",
                ))
            }
        };
        if let Some(reason) = first_blocking(&advisories, &key.version, &rules.policy) {
            let why_id = self
                .store_verdict(key, &Verdict::Blocked(reason.clone()), fingerprint)
                .await
                .ok();
            return Decision::Refuse { reason, why_id };
        }

        // Reuse already-cached bytes for this content hash if we have
        // them, so a rescan forced only by a policy change does not pay
        // for a redundant download. A cache read error is not fatal here
        // — the cache is a performance feature only — it just means this
        // falls through to a fresh download.
        let cached = self.cache_get(key).await.ok().flatten();

        let (artifact_path, freshly_downloaded) = match cached {
            Some(path) => (path, false),
            None => {
                let expected = match entry.sha256.as_deref() {
                    Some(hash) => hash.to_lowercase(),
                    None => return Decision::Unverifiable(no_hash_reason()),
                };
                let download_dir = match tempfile::tempdir() {
                    Ok(dir) => dir,
                    Err(err) => {
                        return Decision::Unverifiable(internal_error_reason(
                            "creating a temporary download directory",
                            &err,
                        ))
                    }
                };
                let dest = download_dir.path().join(&key.filename);
                let actual = match self.upstream.download(entry, &dest).await {
                    Ok(hash) => hash.to_lowercase(),
                    Err(err) => return Decision::Unverifiable(upstream_error_reason(&err)),
                };
                if actual != expected {
                    log_hash_mismatch(key, &expected, &actual);
                    return Decision::Refuse {
                        reason: hash_mismatch_reason(&expected, &actual),
                        why_id: None,
                    };
                }
                // `dest` must outlive this scan's remaining steps, so
                // `download_dir`'s guard is intentionally leaked via
                // `keep`: this function (not the temp dir's own `Drop`)
                // now owns cleanup, via the explicit removal in
                // `cleanup_fresh_download` on every exit path that
                // doesn't hand the file to the cache.
                let _ = download_dir.keep();
                (dest, true)
            }
        };

        let unpack_dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => {
                cleanup_fresh_download(&artifact_path, freshly_downloaded);
                return Decision::Unverifiable(internal_error_reason(
                    "creating a temporary unpack directory",
                    &err,
                ));
            }
        };

        // A freshly downloaded file already lives at a path ending in
        // `key.filename`, which `unpack` uses to recognize the archive
        // format. A cache hit does not: the artifact cache names files by
        // content hash, with no extension at all. A symlink under the
        // right name lets `unpack` read the same bytes without copying
        // them; `_link_guard` just has to outlive the `unpack` call.
        let (_link_guard, unpack_source) = if freshly_downloaded {
            (None, artifact_path.clone())
        } else {
            match symlink_for_unpack(&artifact_path, &key.filename) {
                Ok((guard, link_path)) => (Some(guard), link_path),
                Err(err) => {
                    return Decision::Unverifiable(internal_error_reason(
                        "preparing the cached artifact for unpacking",
                        &err,
                    ))
                }
            }
        };

        let unpack_result = {
            let archive = unpack_source;
            let dest = unpack_dir.path().to_path_buf();
            tokio::task::spawn_blocking(move || unpack(&archive, &dest)).await
        };
        match unpack_result {
            Ok(Ok(())) => {}
            Ok(Err(UnpackError::Escape(detail))) => {
                cleanup_fresh_download(&artifact_path, freshly_downloaded);
                // Unlike the `Other` arm below, this is not a gap in our
                // coverage: an absolute path, a `..` component, a
                // symlink, a hard link, or a device/FIFO entry is a
                // deliberate attempt to write outside the unpack
                // destination — an unambiguous attack, not a format we
                // merely failed to read. "We checked and it is bad," so
                // it is stored as a durable `Blocked` verdict (a 403 with
                // a `/why` page), unlike every other `unpack` failure.
                let reason = RefusalReason {
                    code: "unpack:escape".to_string(),
                    detail: sanitize_text(&detail, DETAIL_MAX_CHARS),
                };
                let why_id = self
                    .store_verdict(key, &Verdict::Blocked(reason.clone()), fingerprint)
                    .await
                    .ok();
                return Decision::Refuse { reason, why_id };
            }
            Ok(Err(UnpackError::Other(err))) => {
                cleanup_fresh_download(&artifact_path, freshly_downloaded);
                // Deliberately `Unverifiable`, not `Blocked`: an archive
                // this unpacker cannot read is a gap in *our* coverage —
                // an unsupported format, a tar quirk, a truncated
                // download — and storing it as `Blocked` made a format
                // gap permanently indistinguishable from a malware
                // finding, which reads to a developer as "we found
                // malware in your package" and is precisely how this
                // proxy earns being routed around. Nothing is stored, so
                // the next request re-attempts rather than being stuck
                // behind a verdict no check ever justified.
                return Decision::Unverifiable(RefusalReason {
                    code: "unverifiable:unpack-failed".to_string(),
                    detail: sanitize_text(&format!("{err:#}"), DETAIL_MAX_CHARS),
                });
            }
            Err(join_error) => {
                cleanup_fresh_download(&artifact_path, freshly_downloaded);
                return Decision::Unverifiable(internal_error_reason(
                    "the unpack task panicked",
                    &join_error,
                ));
            }
        }

        // The plugin list comes from the same `ScanRules` snapshot the
        // fingerprint above came from, so the row this scan stores
        // actually identifies the checks that produced it.
        if let Some(reason) = rules
            .plugin_runner
            .run_all(&rules.plugins, key, unpack_dir.path())
            .await
        {
            cleanup_fresh_download(&artifact_path, freshly_downloaded);
            // A plugin that could not be run, or that never reached a
            // verdict before its timeout, has not examined this artifact
            // — so this is "we could not check", not "we checked and it
            // is bad", and it must not be stored as a `Blocked` verdict
            // that outlives the broken plugin.
            if crate::plugin::is_check_failure(&reason) {
                return Decision::Unverifiable(reason);
            }
            let why_id = self
                .store_verdict(key, &Verdict::Blocked(reason.clone()), fingerprint)
                .await
                .ok();
            return Decision::Refuse { reason, why_id };
        }

        // The AI-review gate, immediately after the plugins and before
        // the clean verdict is stored. Uses the `rules` snapshot's
        // reviewer, never a live config read, so a scan finishes under
        // the review policy it started with even if a reload lands
        // mid-scan. A `Blocked` review is stored like a plugin refusal:
        // a durable verdict the allowlist can override. An
        // `Unverifiable` review stores nothing, exactly like a check
        // failure, so a later request re-attempts rather than being
        // stuck behind a review that never happened.
        //
        // Allowlisted artifacts never reach here: `decide_inner` sends
        // them down the fetch path before any scan starts, so an
        // allowlist entry for a package+version is a human sign-off
        // that skips the review as it skips every other check.
        if let Some(reviewer) = rules.ai_reviewer.as_ref() {
            match reviewer.review(key, unpack_dir.path(), fingerprint).await {
                ReviewOutcome::Clean => {}
                ReviewOutcome::Blocked(reason) => {
                    cleanup_fresh_download(&artifact_path, freshly_downloaded);
                    let why_id = self
                        .store_verdict(key, &Verdict::Blocked(reason.clone()), fingerprint)
                        .await
                        .ok();
                    return Decision::Refuse { reason, why_id };
                }
                ReviewOutcome::Unverifiable(reason) => {
                    cleanup_fresh_download(&artifact_path, freshly_downloaded);
                    return Decision::Unverifiable(reason);
                }
            }
        }
        drop(unpack_dir);

        if self
            .store_verdict(key, &Verdict::Clean, fingerprint)
            .await
            .is_err()
        {
            cleanup_fresh_download(&artifact_path, freshly_downloaded);
            return Decision::Unverifiable(internal_error_reason_simple(
                "recording the scan verdict",
            ));
        }

        let served_path = if freshly_downloaded {
            match self.cache_insert(key, &artifact_path).await {
                Ok(path) => path,
                Err(err) => {
                    cleanup_fresh_download(&artifact_path, freshly_downloaded);
                    return Decision::Unverifiable(internal_error_reason(
                        "caching the scanned artifact",
                        &err,
                    ));
                }
            }
        } else {
            artifact_path
        };

        Decision::Serve(served_path)
    }

    // -----------------------------------------------------------------
    // Hash-verified fetch (allowlist path and stored-clean re-serve)
    // -----------------------------------------------------------------

    /// Serves `key`/`entry` after confirming the bytes match the
    /// index-declared hash: a cache hit (content-addressed, so already
    /// known to match) is reused as-is; otherwise the artifact is
    /// downloaded fresh, verified, and cached. Used by the allowlist path
    /// and by a stored-clean re-check that passed its advisory recheck —
    /// neither of those paths runs plugins again, so neither goes through
    /// [`Scanner::run_full_scan`].
    /// Deduplicated by sha256 through [`Scanner::fetch_coordinator`] —
    /// its own coordinator, not the full-scan one, so the two paths can
    /// never hand each other a verdict the other's rules did not produce
    /// (a joiner on the allowlist path must not inherit a `Blocked`
    /// verdict from a full scan it was entitled to override). Without
    /// this dedup, a pip retry storm against one large allowlisted
    /// artifact launched one fresh download per request.
    async fn fetch_decision(&self, key: &ArtifactKey, entry: &IndexEntry) -> Decision {
        let budget = self.config.current().scan_budget;
        let sha256 = key.sha256.clone();

        match self.fetch_coordinator.start_or_join(&sha256) {
            Ok(tx) => {
                let scanner = self.clone();
                let key = key.clone();
                let entry = entry.clone();
                let coordinator = Arc::clone(&self.fetch_coordinator);
                let sha256_for_cleanup = sha256.clone();

                // Detached, exactly like the full-scan owner in
                // `scan_with_budget`: a slow-but-reachable upstream must
                // not make this call block past the budget, and the
                // download is not cancelled when the budget elapses — it
                // keeps running, so a retried request shortly after finds
                // the artifact already sitting in the warm cache instead
                // of paying for the download all over again.
                let handle = tokio::spawn(async move {
                    let _finish_guard = FinishGuard::new(coordinator, sha256_for_cleanup);
                    let result = scanner.fetch_verified_and_cache(&key, &entry).await;
                    let _ = tx.send(match &result {
                        Ok(_) => Some(Verdict::Clean),
                        // A mismatch is worth sharing with a joiner (it
                        // is a property of the bytes upstream served, not
                        // of this caller), but it is still never stored.
                        Err(FetchError::Mismatch(reason)) => Some(Verdict::Blocked(reason.clone())),
                        Err(FetchError::Unverifiable(_)) => None,
                    });
                    result
                });

                match tokio::time::timeout(budget, handle).await {
                    Ok(Ok(Ok(path))) => Decision::Serve(path),
                    Ok(Ok(Err(FetchError::Unverifiable(reason)))) => Decision::Unverifiable(reason),
                    Ok(Ok(Err(FetchError::Mismatch(reason)))) => Decision::Refuse {
                        reason,
                        why_id: None,
                    },
                    Ok(Err(_join_error)) => {
                        Decision::Unverifiable(internal_error_reason_simple("fetch task panicked"))
                    }
                    Err(_elapsed) => Decision::InProgress,
                }
            }
            Err(rx) => {
                match tokio::time::timeout(budget, coordinator::wait_for_verdict(rx)).await {
                    Ok(Some(Verdict::Clean)) => match self.cache_get(key).await {
                        Ok(Some(path)) => Decision::Serve(path),
                        _ => Decision::Unverifiable(internal_error_reason_simple(
                            "a verified artifact was missing from the cache",
                        )),
                    },
                    Ok(Some(Verdict::Blocked(reason))) => Decision::Refuse {
                        reason,
                        why_id: None,
                    },
                    Ok(None) => Decision::Unverifiable(scan_incomplete_reason()),
                    Err(_elapsed) => Decision::InProgress,
                }
            }
        }
    }

    async fn fetch_verified_and_cache(
        &self,
        key: &ArtifactKey,
        entry: &IndexEntry,
    ) -> Result<PathBuf, FetchError> {
        if let Ok(Some(path)) = self.cache_get(key).await {
            return Ok(path);
        }

        let expected = match entry.sha256.as_deref() {
            Some(hash) => hash.to_lowercase(),
            None => return Err(FetchError::Unverifiable(no_hash_reason())),
        };

        let download_dir = tempfile::tempdir().map_err(|err| {
            FetchError::Unverifiable(internal_error_reason(
                "creating a temporary download directory",
                &err,
            ))
        })?;
        let dest = download_dir.path().join(&key.filename);

        let actual = self
            .upstream
            .download(entry, &dest)
            .await
            .map_err(|err| FetchError::Unverifiable(upstream_error_reason(&err)))?
            .to_lowercase();

        if actual != expected {
            log_hash_mismatch(key, &expected, &actual);
            return Err(FetchError::Mismatch(hash_mismatch_reason(
                &expected, &actual,
            )));
        }

        self.cache_insert(key, &dest).await.map_err(|err| {
            FetchError::Unverifiable(internal_error_reason("caching the artifact", &err))
        })
    }

    // -----------------------------------------------------------------
    // Blocking-store access, each on the blocking pool
    // -----------------------------------------------------------------

    async fn lookup_stored_verdict(
        &self,
        key: &ArtifactKey,
        fingerprint: &str,
    ) -> anyhow::Result<Option<StoredVerdict>> {
        let store = Arc::clone(&self.verdict_store);
        let key = key.clone();
        let fingerprint = fingerprint.to_string();
        tokio::task::spawn_blocking(move || store.get(&key, &fingerprint))
            .await
            .context("verdict lookup task panicked")?
    }

    async fn store_verdict(
        &self,
        key: &ArtifactKey,
        verdict: &Verdict,
        fingerprint: &str,
    ) -> anyhow::Result<String> {
        let store = Arc::clone(&self.verdict_store);
        let key = key.clone();
        let verdict = verdict.clone();
        let fingerprint = fingerprint.to_string();
        tokio::task::spawn_blocking(move || store.put(&key, &verdict, &fingerprint))
            .await
            .context("store verdict task panicked")?
    }

    async fn advisory_lookup(
        &self,
        ecosystem: &str,
        package: &str,
    ) -> anyhow::Result<Vec<Advisory>> {
        let store = Arc::clone(&self.advisory_store);
        let ecosystem = ecosystem.to_string();
        let package = package.to_string();
        tokio::task::spawn_blocking(move || store.for_package(&ecosystem, &package))
            .await
            .context("advisory lookup task panicked")?
    }

    async fn cache_get(&self, key: &ArtifactKey) -> anyhow::Result<Option<PathBuf>> {
        let cache = Arc::clone(&self.artifact_cache);
        let key = key.clone();
        tokio::task::spawn_blocking(move || cache.get(&key))
            .await
            .context("artifact cache lookup task panicked")?
    }

    async fn cache_insert(
        &self,
        key: &ArtifactKey,
        file: &std::path::Path,
    ) -> anyhow::Result<PathBuf> {
        let cache = Arc::clone(&self.artifact_cache);
        let key = key.clone();
        let file = file.to_path_buf();
        tokio::task::spawn_blocking(move || cache.insert(&key, &file))
            .await
            .context("artifact cache insert task panicked")?
    }
}

/// Derives the value to broadcast to concurrent joiners from this scan's
/// own [`Decision`]: `Some(verdict)` exactly when a verdict was actually
/// persisted (signalled by `why_id` being present on a refusal, or by a
/// successful serve), `None` otherwise — a hash mismatch or an
/// unverifiable failure has nothing durable for a joiner to reuse.
fn verdict_for_dedup(decision: &Decision) -> Option<Verdict> {
    match decision {
        Decision::Serve(_) => Some(Verdict::Clean),
        Decision::Refuse {
            reason,
            why_id: Some(_),
        } => Some(Verdict::Blocked(reason.clone())),
        _ => None,
    }
}

/// Creates a fresh temp directory containing one symlink, named
/// `filename`, pointing at `target`. Used to hand `unpack` a path it can
/// recognize the archive format from when the real bytes live under a
/// content-addressed cache path that carries no extension at all. The
/// returned [`tempfile::TempDir`] must be kept alive for as long as the
/// symlink needs to resolve.
fn symlink_for_unpack(
    target: &std::path::Path,
    filename: &str,
) -> anyhow::Result<(tempfile::TempDir, PathBuf)> {
    let dir = tempfile::tempdir().context("creating a temp directory for the unpack symlink")?;
    let link_path = dir.path().join(filename);
    std::os::unix::fs::symlink(target, &link_path).with_context(|| {
        format!(
            "symlinking {} to {} for unpacking",
            link_path.display(),
            target.display()
        )
    })?;
    Ok((dir, link_path))
}

/// Removes a freshly downloaded artifact file that is not going to be
/// handed to the cache (because the scan refused or errored before
/// reaching that point). A no-op for a cache hit, which this function is
/// never supposed to delete.
fn cleanup_fresh_download(path: &std::path::Path, freshly_downloaded: bool) {
    if freshly_downloaded {
        let _ = std::fs::remove_file(path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

/// Logs every refusal, in one place, so an organization can both see that
/// it happened and measure how often it happens.
///
/// Measuring the refusal rate is the only way an org notices the
/// false-positive anti-goal firing — a developer who quietly switches back
/// to `--index-url https://pypi.org/simple` generates no signal at all
/// otherwise. A served artifact is logged at `debug!` so the default
/// `info` filter carries refusals only; the request-level access log in
/// [`crate::http`] records the rest.
fn log_decision(key: &ArtifactKey, decision: &Decision) {
    match decision {
        Decision::Serve(_) => tracing::debug!(
            package = %key.package,
            version = %key.version,
            filename = %key.filename,
            "artifact served"
        ),
        Decision::Refuse { reason, why_id } => tracing::warn!(
            code = %reason.code,
            package = %key.package,
            version = %key.version,
            filename = %key.filename,
            why_id = why_id.as_deref().unwrap_or("-"),
            detail = %reason.detail,
            "refused: artifact was checked and blocked"
        ),
        Decision::Unverifiable(reason) => tracing::warn!(
            code = %reason.code,
            package = %key.package,
            version = %key.version,
            filename = %key.filename,
            detail = %reason.detail,
            "refused: artifact could not be checked"
        ),
        Decision::InProgress => tracing::debug!(
            package = %key.package,
            version = %key.version,
            filename = %key.filename,
            "scan still running; returned retryable scan-in-progress"
        ),
    }
}

/// Logs a hash mismatch at `error!`, with both digests.
///
/// This is the most security-significant event this system can detect: the
/// bytes upstream served are not the bytes the index declared, which is
/// either a tampered mirror/CDN or an active man-in-the-middle. The
/// computed digests exist nowhere else an operator can reach them — the
/// refusal is never persisted (it may be transient download corruption,
/// not a property of the artifact), so there is no `/why` page for it —
/// which means without this line an org being fed tampered bytes gets no
/// signal whatsoever.
fn log_hash_mismatch(key: &ArtifactKey, expected: &str, actual: &str) {
    tracing::error!(
        package = %key.package,
        version = %key.version,
        filename = %key.filename,
        expected_sha256 = %expected,
        actual_sha256 = %actual,
        "HASH MISMATCH: upstream bytes do not match the index-declared sha256; \
         refusing. This is either a tampered upstream or a corrupted transfer \
         and should be investigated, not retried blindly."
    );
}

/// Whether `package`@`version` is explicitly allowlisted by the org,
/// overriding any stored verdict (but never the hash check).
///
/// Reads `config` — the live snapshot behind
/// [`crate::config::ConfigHandle`] — rather than the [`Policy`], because
/// the allowlist "is an override applied at request time, not an input
/// that changes what a scan examines" (see [`crate::policy`]'s module
/// docs): it is deliberately excluded from the fingerprint, so adding an
/// entry must take effect immediately without invalidating any stored
/// verdict. Package names are compared after PEP 503 normalization,
/// versions verbatim.
///
/// `pub(crate)` and the *only* implementation of this comparison in the
/// crate. It used to be one of three: a `Policy::allows` whose only
/// callers were its own tests, plus two untested live copies here and in
/// `http::simple`. The tested copy being the dead one is how a divergence
/// between them would have shipped unnoticed.
pub(crate) fn is_allowlisted(config: &Config, package: &str, version: &str) -> bool {
    let normalized = normalize_name(package);
    config
        .allowlist
        .iter()
        .any(|entry| normalize_name(&entry.package) == normalized && entry.version == version)
}

fn no_hash_reason() -> RefusalReason {
    RefusalReason {
        code: "unverifiable:no-hash".to_string(),
        detail: "the package index did not declare a hash for this artifact".to_string(),
    }
}

fn scan_incomplete_reason() -> RefusalReason {
    RefusalReason {
        code: "unverifiable:scan-incomplete".to_string(),
        detail: "the scan for this artifact did not complete".to_string(),
    }
}

fn hash_mismatch_reason(expected: &str, actual: &str) -> RefusalReason {
    RefusalReason {
        code: "hash-mismatch".to_string(),
        detail: sanitize_text(
            &format!(
                "downloaded artifact sha256 {actual} does not match the index-declared sha256 {expected}"
            ),
            DETAIL_MAX_CHARS,
        ),
    }
}

fn upstream_error_reason(err: &UpstreamError) -> RefusalReason {
    RefusalReason {
        code: "unverifiable:upstream".to_string(),
        detail: sanitize_text(
            &format!("could not verify this artifact right now: {err:#}"),
            DETAIL_MAX_CHARS,
        ),
    }
}

fn internal_error_reason(context: &str, err: &dyn std::fmt::Display) -> RefusalReason {
    RefusalReason {
        code: "unverifiable:internal".to_string(),
        detail: sanitize_text(&format!("{context}: {err}"), DETAIL_MAX_CHARS),
    }
}

fn internal_error_reason_simple(context: &str) -> RefusalReason {
    RefusalReason {
        code: "unverifiable:internal".to_string(),
        detail: sanitize_text(context, DETAIL_MAX_CHARS),
    }
}

/// Strips ASCII control characters (CR/LF included — the bytes a
/// response-splitting attack needs) and non-ASCII characters, then caps
/// length. Mirrors the same discipline [`crate::advisory::matching`] and
/// [`crate::plugin`] apply to their own refusal details, independently of
/// this module and of task 11's own sanitizing downstream.
fn sanitize_text(text: &str, max_chars: usize) -> String {
    text.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .take(max_chars)
        .collect()
}

#[cfg(test)]
mod tests {
    //! A whitebox test for `FinishGuard`, placed here rather than in
    //! `tests/scan.rs` because it needs to reach `Scanner`'s private
    //! `coordinator` field directly.
    //!
    //! Code review on this task found that no dependency currently
    //! available to `Scanner` can actually make `run_full_scan` panic:
    //! every blocking call (`VerdictStore`, `AdvisoryStore`,
    //! `ArtifactCache`, `unpack`) goes through `spawn_blocking` with
    //! explicit `JoinError` handling, and `PluginRunner::run_one` applies
    //! the same pattern around `SandboxRunner::run` — confirmed
    //! empirically: a `SandboxRunner` that panics resolves to a normal
    //! `RefusalReason`, never a propagated panic, because
    //! `tokio::task::spawn_blocking` itself catches it. So this test
    //! builds the exact shape `scan_with_budget`'s owner constructs around
    //! a real scan — `start_or_join`, then a task whose first statement is
    //! a `FinishGuard` — and panics in place of the scan body, which is
    //! the one thing a future change to this module's own code could
    //! still do. It then drives the *real* `Scanner::decide` for the
    //! second assertion, so the proof that a later request re-scans
    //! rather than being stuck forever goes through the actual public
    //! API, not a second manual coordinator probe.

    use super::*;

    use sha2::{Digest, Sha256};
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::config::{AllowEntry, Config, CveLine, UnknownSeverity};
    use crate::db::index_cache::IndexCache;
    use crate::plugin::{SandboxOutcome, SandboxRunner, SandboxSpec};

    /// Moved here from `tests/policy.rs`, where it tested
    /// `Policy::allows` — a copy of this comparison with no callers
    /// outside that test. This is the surviving implementation, and the
    /// one both the download gate and the index-page filter actually use.
    #[test]
    fn full_scan_slots_honors_an_explicit_override() {
        assert_eq!(
            full_scan_slots(Some(7)),
            7,
            "an explicit override must be used verbatim"
        );
    }

    #[test]
    fn full_scan_slots_rejects_a_zero_override_rather_than_deadlocking() {
        assert_eq!(
            full_scan_slots(Some(0)),
            1,
            "a configured 0 must not produce a semaphore with no permits ever"
        );
    }

    #[test]
    fn full_scan_slots_falls_back_to_host_derived_sizing_by_default() {
        let derived = full_scan_slots(None);
        assert!(
            (FULL_SCAN_SLOTS_MIN..=FULL_SCAN_SLOTS_MAX).contains(&derived),
            "the default must stay within the documented floor/ceiling, got {derived}"
        );
    }

    #[test]
    fn allowlist_matching_uses_pep_503_normalization() {
        let mut cfg = base_config(std::time::Duration::from_secs(12));
        cfg.allowlist = vec![AllowEntry {
            package: "Flask_X".to_string(),
            version: "1.0.0".to_string(),
        }];

        assert!(
            is_allowlisted(&cfg, "flask-x", "1.0.0"),
            "allowlist matching must use PEP 503 normalization"
        );
        assert!(
            !is_allowlisted(&cfg, "flask-x", "2.0.0"),
            "a different version must not be allowlisted"
        );
        assert!(
            !is_allowlisted(&cfg, "some-other-package", "1.0.0"),
            "a different package must not be allowlisted"
        );
    }

    #[test]
    fn a_plugin_that_could_not_run_is_a_check_failure_and_a_real_block_is_not() {
        use crate::plugin::is_check_failure;

        assert!(is_check_failure(&RefusalReason {
            code: "plugin:yara:error".to_string(),
            detail: String::new(),
        }));
        assert!(is_check_failure(&RefusalReason {
            code: "plugin:yara:timeout".to_string(),
            detail: String::new(),
        }));
        assert!(
            !is_check_failure(&RefusalReason {
                code: "plugin:yara".to_string(),
                detail: String::new(),
            }),
            "a plugin that ran and exited non-zero is a genuine block, not a \
             check failure"
        );
        assert!(!is_check_failure(&RefusalReason {
            code: "cve:high".to_string(),
            detail: String::new(),
        }));
    }

    /// No plugins are configured in this test, so this must never run.
    struct NeverCalledSandbox;
    impl SandboxRunner for NeverCalledSandbox {
        fn run(&self, _spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
            panic!("no plugins are configured in this test; the sandbox must never run");
        }
    }

    fn base_config(scan_budget: std::time::Duration) -> Config {
        Config {
            bind: "127.0.0.1:8080".parse().unwrap(),
            db_path: PathBuf::from("data/scanner.db"),
            cache_dir: PathBuf::from("data/cache"),
            upstream_url: "https://pypi.org".parse().unwrap(),
            public_url: "http://localhost:8080".parse().unwrap(),
            scan_budget,
            cache_ttl: std::time::Duration::from_secs(24 * 60 * 60),
            advisory_sync_interval: std::time::Duration::from_secs(60 * 60),
            advisory_source_url: "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
                .parse()
                .unwrap(),
            cve: CveLine {
                min_severity: 7.0,
                require_fix_available: false,
                unknown_severity: UnknownSeverity::Allow,
            },
            download: Default::default(),
            allowlist: Vec::new(),
            plugins: Vec::new(),
            max_concurrent_scans: None,
            ai_review: None,
            cargo_registry: None,
        }
    }

    fn build_wheel_bytes() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut zip = zip::ZipWriter::new(cursor);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("demo/__init__.py", options)
                .expect("start zip entry");
            std::io::Write::write_all(&mut zip, b"VERSION = '1.0.0'\n")
                .expect("write zip entry contents");
            zip.finish().expect("finish zip fixture");
        }
        buf
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[tokio::test]
    async fn a_panicked_owner_does_not_leak_the_coordinator_entry_forever() {
        let server = MockServer::start().await;
        let filename = "demo_package-1.0.0-py3-none-any.whl";
        let body = build_wheel_bytes();
        let sha256 = sha256_hex(&body);

        Mock::given(method("GET"))
            .and(path(format!("/packages/{filename}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;

        let db_dir = tempfile::tempdir().expect("create db temp dir");
        let db = crate::db::Db::open(&db_dir.path().join("scanner.db")).expect("open db");
        let cache_dir = tempfile::tempdir().expect("create cache temp dir");
        let artifact_cache = ArtifactCache::new(db.clone(), cache_dir.path().join("artifacts"))
            .expect("create artifact cache");
        let index_cache = IndexCache::new(db.clone());
        let base = Url::parse(&format!("{}/simple/", server.uri())).expect("valid base url");
        let upstream = Upstream::new(base, index_cache).expect("construct upstream");
        let verdict_store = VerdictStore::new(db.clone());
        let advisory_store = AdvisoryStore::new(db.clone());
        let plugin_runner = PluginRunner::new(Arc::new(NeverCalledSandbox));
        let cfg = base_config(std::time::Duration::from_secs(12));
        let policy = Policy::build(Arc::new(cfg.clone())).expect("build policy");
        let config_handle = Arc::new(ConfigHandle::new(cfg));

        let scanner = Scanner::new(
            verdict_store,
            upstream,
            policy,
            advisory_store,
            plugin_runner,
            artifact_cache,
            config_handle,
            None,
        );

        let key = ArtifactKey {
            ecosystem: "pypi".to_string(),
            package: "demo-package".to_string(),
            version: "1.0.0".to_string(),
            filename: filename.to_string(),
            sha256: sha256.clone(),
        };
        let entry = IndexEntry {
            filename: filename.to_string(),
            url: Url::parse(&format!("{}/packages/{filename}", server.uri())).unwrap(),
            sha256: Some(sha256.clone()),
            requires_python: None,
            metadata_hash: None,
            yanked: None,
        };

        // Claim ownership exactly as `scan_with_budget` would, and start a
        // joiner that is already waiting when the owner fails.
        let tx = scanner
            .coordinator
            .start_or_join(&sha256)
            .expect("the coordinator must be empty for a brand-new sha256");
        let joined_rx = match scanner.coordinator.start_or_join(&sha256) {
            Err(rx) => rx,
            Ok(_) => panic!("a second start_or_join for the same sha256 must join, not own"),
        };

        // The owner's task: a `FinishGuard` constructed first, exactly as
        // in `scan_with_budget`, then a panic standing in for a bug in a
        // future `run_full_scan` change.
        let coordinator_for_owner = Arc::clone(&scanner.coordinator);
        let sha256_for_owner = sha256.clone();
        let owner = tokio::spawn(async move {
            let _finish_guard = FinishGuard::new(coordinator_for_owner, sha256_for_owner);
            let _tx = tx;
            panic!("simulated panic inside the scan body");
        });
        let owner_result = owner.await;
        assert!(
            owner_result.is_err(),
            "the simulated owner task must have panicked"
        );

        // First assertion: a caller that was already waiting resolves to
        // a refusal, not a hang, once the owner panics.
        let joined_verdict = coordinator::wait_for_verdict(joined_rx).await;
        assert!(
            joined_verdict.is_none(),
            "a panicked owner must close the channel without ever sending a verdict"
        );

        // Second assertion — the finding itself. Without the
        // `FinishGuard` fix, the coordinator's map entry for this sha256
        // would still be present (the bare `coordinator.finish(...)` call
        // it replaced never runs on a panic), so this `decide()` would
        // join the dead receiver above and resolve to
        // `Decision::Unverifiable` immediately, forever, without ever
        // touching upstream again.
        let decision = scanner.decide(&key, &entry).await;
        match decision {
            Decision::Serve(_) => {}
            other => panic!(
                "a panicked owner must not permanently block rescans of the \
                 same artifact, got {other:?}"
            ),
        }
    }
}

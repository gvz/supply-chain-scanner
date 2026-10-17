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
//! advisory lookup -> download -> hash verify -> unpack + plugins -> store clean, cache, serve
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

pub mod coordinator;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;

use crate::advisory::matching::first_blocking;
use crate::advisory::Advisory;
use crate::artifact_cache::ArtifactCache;
use crate::config::ConfigHandle;
use crate::db::advisory::AdvisoryStore;
use crate::db::verdict::{StoredVerdict, VerdictStore};
use crate::ecosystem::pypi::index::IndexEntry;
use crate::ecosystem::pypi::upstream::{Upstream, UpstreamError};
use crate::model::{ArtifactKey, RefusalReason, Verdict};
use crate::plugin::{unpack, PluginRunner};
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

/// Composes every scanning dependency into the one place that decides
/// whether an artifact may be served.
///
/// Cheap to clone: every field is an `Arc`, so a clone can be moved into a
/// detached `tokio::spawn`'d scan without borrowing from the caller's
/// stack frame — which is exactly what letting a scan outlive a caller's
/// budget timeout requires.
#[derive(Clone)]
pub struct Scanner {
    verdict_store: Arc<VerdictStore>,
    upstream: Arc<Upstream>,
    policy: Arc<Policy>,
    advisory_store: Arc<AdvisoryStore>,
    plugin_runner: Arc<PluginRunner>,
    artifact_cache: Arc<ArtifactCache>,
    config: Arc<ConfigHandle>,
    coordinator: Arc<ScanCoordinator>,
}

impl Scanner {
    pub fn new(
        verdict_store: VerdictStore,
        upstream: Upstream,
        policy: Policy,
        advisory_store: AdvisoryStore,
        plugin_runner: PluginRunner,
        artifact_cache: ArtifactCache,
        config: Arc<ConfigHandle>,
    ) -> Self {
        Self {
            verdict_store: Arc::new(verdict_store),
            upstream: Arc::new(upstream),
            policy: Arc::new(policy),
            advisory_store: Arc::new(advisory_store),
            plugin_runner: Arc::new(plugin_runner),
            artifact_cache: Arc::new(artifact_cache),
            config,
            coordinator: Arc::new(ScanCoordinator::new()),
        }
    }

    /// Decides whether `key` (as offered by `entry` in the simple index)
    /// may be served. See the module docs for the decision path.
    pub async fn decide(&self, key: &ArtifactKey, entry: &IndexEntry) -> Decision {
        if entry.sha256.is_none() {
            // Absolute, ahead of every other rule: there is nothing to
            // verify a download against, so this artifact can never be
            // scanned honestly, allowlisted or not.
            return Decision::Unverifiable(no_hash_reason());
        }

        if self.policy.allows(&key.package, &key.version) {
            // The allowlist overrides any stored verdict, but never the
            // integrity check: the bytes still have to match the hash
            // the index declared.
            return self.fetch_decision(key, entry).await;
        }

        let fingerprint = self.policy.fingerprint().to_string();

        match self.lookup_stored_verdict(key, &fingerprint).await {
            Ok(Some(stored)) => match stored.verdict {
                Verdict::Blocked(reason) => Decision::Refuse {
                    reason,
                    why_id: Some(stored.why_id),
                },
                Verdict::Clean => self.serve_known_clean(key, entry, &fingerprint).await,
            },
            // No verdict stored under today's policy — either this
            // artifact has never been scanned, or the policy changed
            // since it last was. Either way, a full scan is required.
            Ok(None) => self.scan_with_budget(key, entry, &fingerprint).await,
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
        let fingerprint = self.policy.fingerprint().to_string();
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

        if let Some(reason) = first_blocking(&advisories, &key.version, &self.policy) {
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
        fingerprint: &str,
    ) -> Decision {
        let sha256 = key.sha256.clone();
        let budget = self.config.current().scan_budget;

        match self.coordinator.start_or_join(&sha256) {
            Ok(tx) => {
                let scanner = self.clone();
                let key = key.clone();
                let entry = entry.clone();
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
                    let decision = scanner.run_full_scan(&key, &entry, &fingerprint).await;
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
        if let Some(reason) = first_blocking(&advisories, &key.version, &self.policy) {
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
            Ok(Err(err)) => {
                cleanup_fresh_download(&artifact_path, freshly_downloaded);
                let reason = RefusalReason {
                    code: "unpack-failed".to_string(),
                    detail: sanitize_text(&format!("{err:#}"), DETAIL_MAX_CHARS),
                };
                let why_id = self
                    .store_verdict(key, &Verdict::Blocked(reason.clone()), fingerprint)
                    .await
                    .ok();
                return Decision::Refuse { reason, why_id };
            }
            Err(join_error) => {
                cleanup_fresh_download(&artifact_path, freshly_downloaded);
                return Decision::Unverifiable(internal_error_reason(
                    "the unpack task panicked",
                    &join_error,
                ));
            }
        }

        let plugins = self.config.current().plugins.clone();
        if let Some(reason) = self
            .plugin_runner
            .run_all(&plugins, key, unpack_dir.path())
            .await
        {
            cleanup_fresh_download(&artifact_path, freshly_downloaded);
            let why_id = self
                .store_verdict(key, &Verdict::Blocked(reason.clone()), fingerprint)
                .await
                .ok();
            return Decision::Refuse { reason, why_id };
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
    async fn fetch_decision(&self, key: &ArtifactKey, entry: &IndexEntry) -> Decision {
        let budget = self.config.current().scan_budget;
        let scanner = self.clone();
        let key = key.clone();
        let entry = entry.clone();

        // Detached, exactly like the full-scan owner in `scan_with_budget`:
        // a slow-but-reachable upstream must not make this call block past
        // the budget, but the download it's not cancelled on elapse — it
        // keeps running, so a retried request shortly after can find the
        // artifact already sitting in the warm cache instead of paying for
        // the download all over again.
        let handle =
            tokio::spawn(async move { scanner.fetch_verified_and_cache(&key, &entry).await });

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

    use crate::config::{Config, CveLine, UnknownSeverity};
    use crate::db::index_cache::IndexCache;
    use crate::plugin::{SandboxOutcome, SandboxRunner, SandboxSpec};

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
            allowlist: Vec::new(),
            plugins: Vec::new(),
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

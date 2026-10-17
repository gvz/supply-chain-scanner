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

use coordinator::ScanCoordinator;

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
        let ecosystem = ecosystem.to_string();
        let package = package.to_string();

        tokio::task::spawn_blocking(move || {
            store.blocked_filenames(&ecosystem, &package, &fingerprint)
        })
        .await
        .unwrap_or_else(|_| Ok(HashSet::new()))
        .unwrap_or_else(|_| HashSet::new())
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
                let handle = tokio::spawn(async move {
                    let decision = scanner.run_full_scan(&key, &entry, &fingerprint).await;
                    let _ = tx.send(verdict_for_dedup(&decision));
                    coordinator.finish(&sha256_for_cleanup);
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
        match self.fetch_verified_and_cache(key, entry).await {
            Ok(path) => Decision::Serve(path),
            Err(FetchError::Unverifiable(reason)) => Decision::Unverifiable(reason),
            Err(FetchError::Mismatch(reason)) => Decision::Refuse {
                reason,
                why_id: None,
            },
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

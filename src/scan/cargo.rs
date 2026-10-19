//! Orchestration for the cargo cascade: the I/O half of
//! [`crate::scan::cargo_cascade`].
//!
//! Task 4's [`plan_cascade`] decides which versions of one crate this
//! proxy may forward. It decides from data handed to it, and it names the
//! single version to review next. This module fetches that data from the
//! real stores and services, runs the review, and repeats. It stops at
//! [`NextStep::Forward`], or when the shared budget runs out.
//!
//! One call to [`CargoScanner::decide_index`] is one crate question:
//! which of its published versions can a `cargo add` see? The answer is
//! never a guess in a crate's favour:
//!
//! - An advisory-lookup failure forwards nothing.
//! - A review that could not run reports [`CargoIndexDecision::InProgress`]
//!   rather than quietly falling back to an older version.
//! - An upstream outage forwards only versions already known to pass.
//!   It never marks a previously passed version bad.
//!
//! # The shared budget
//!
//! The whole cascade for one crate draws from one deadline. The deadline
//! comes from `Config::scan_budget` through [`ConfigHandle`]. `Config` has
//! no cargo-specific budget field. `scan_budget` is the budget the
//! deployment already sets for this job: how long one proxy-side answer
//! may take before the client must retry. Once the deadline passes,
//! `decide_index` returns [`CargoIndexDecision::InProgress`]. It stores
//! nothing new, so a retry starts from the work the finished reviews
//! recorded.
//!
//! # The artifact key
//!
//! A candidate version's [`ArtifactKey`] has these five fields. Ecosystem
//! is `"cargo"`. Package is [`normalize_name`]`(name)`. Version is the
//! index entry's `vers`. Filename is `"{name}-{vers}.crate"`. Sha256 is
//! the entry's `cksum` in lowercase. Tasks 7 and 8 use the same scheme, so
//! a verdict stored here is the verdict the download gate reads.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::advisory::matching_semver::affects;
use crate::advisory::Advisory;
use crate::ai::{AiReviewer, ReviewOutcome};
use crate::config::ConfigHandle;
use crate::db::advisory::AdvisoryStore;
use crate::db::cargo_vet::CargoVetStore;
use crate::db::verdict::VerdictStore;
use crate::ecosystem::cargo::index::{validate_name, CargoIndexEntry};
use crate::ecosystem::cargo::normalize_name;
use crate::ecosystem::cargo::upstream::{CargoUpstream, UpstreamError};
use crate::model::{ArtifactKey, RefusalReason, Verdict};
use crate::plugin::unpack;
use crate::policy::{AdvisoryVerdictInput, Policy};
use crate::scan::cargo_cascade::{plan_cascade, CascadeInput, NextStep, ReviewStatus};
use crate::scan::coordinator::{self, FinishGuard, ScanCoordinator};

/// The ecosystem id this module stores verdicts under. It is `"cargo"`
/// (the same id [`crate::ecosystem::install_surface`] and the collector
/// use), not `"crates.io"` (the OSV feed's own spelling).
const ECOSYSTEM: &str = "cargo";

/// The ecosystem keys the advisory mirror may hold crate advisories under.
///
/// The advisory sync stores crates.io advisories under the feed's own
/// ecosystem name, `"crates.io"`. This plan's task text names `"cargo"`
/// for the lookup instead. This module reads both and joins the results.
/// A CVE is then never missed because the two spellings disagree. A
/// missed advisory here fails *open*, which is the one outcome this proxy
/// must never produce.
const ADVISORY_ECOSYSTEMS: &[&str] = &[ECOSYSTEM, "crates.io"];

/// The criterion assumed when no `[cargo_registry]` table is present.
/// It matches `crate::config`'s own default for
/// `CargoRegistryConfig::required_criterion`.
const DEFAULT_REQUIRED_CRITERION: &str = "safe-to-deploy";

/// What [`CargoScanner::decide_index`] tells the sparse-index handler to
/// serve for one crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoIndexDecision {
    /// The forwardable versions, newest first. The list can be empty, and
    /// an empty list is rendered like a crate with no usable version —
    /// never an error.
    Entries(Vec<CargoIndexEntry>),
    /// The shared budget ran out mid-cascade. The caller tells the client
    /// to retry shortly. The reviews that already finished are stored, so
    /// a retry resumes rather than restarts.
    InProgress,
}

/// Decides, for one crate, which published versions this proxy may
/// forward.
///
/// Cheap to clone: every field is an `Arc`, so a clone can be moved into
/// the detached review task that outlives its caller's budget.
#[derive(Clone)]
pub struct CargoScanner {
    upstream: Arc<CargoUpstream>,
    advisory_store: Arc<AdvisoryStore>,
    vet_store: Arc<CargoVetStore>,
    verdict_store: Arc<VerdictStore>,
    policy: Arc<Policy>,
    /// The reviewer, when `[ai_review]` is configured. Without one, no
    /// version can ever pass review. Only cargo-vet-covered versions are
    /// then forwardable. See [`CargoScanner::facts`].
    ai_reviewer: Option<Arc<AiReviewer>>,
    config: Arc<ConfigHandle>,
    coordinator: Arc<ScanCoordinator>,
    /// The last successfully fetched index body per normalized crate
    /// name.
    ///
    /// The upstream client keeps no index body of its own. Without this
    /// map, a transient blip (a timeout, a 5xx) would discard every
    /// version this proxy already forwarded for the crate. This map lets
    /// an outage answer with the versions already known to pass instead of
    /// an empty list. It holds only upstream's published metadata, never a
    /// review outcome. A failed review therefore never leaves a version in
    /// a half-cached state here.
    last_good_index: Arc<Mutex<HashMap<String, Vec<CargoIndexEntry>>>>,
}

/// The per-version facts one cascade iteration needs, all fetched from
/// the stores in one blocking-pool call.
struct Facts {
    advisories: Vec<Advisory>,
    review_status: HashMap<String, ReviewStatus>,
    vet_covered: HashSet<String>,
}

/// Why one candidate's review did not put it in the forwardable set.
enum ReviewResult {
    Passed,
    /// The review ran and blocked the version (a durable verdict).
    Failed(RefusalReason),
    /// The review could not run, so nothing was stored and nothing is
    /// known. The caller must not treat this as decided.
    Unverifiable,
}

impl CargoScanner {
    // The argument count is the plan's own interface. Every construction
    // dependency is handed in explicitly, so a test can replace any one of
    // them. A builder would hide which caller replaced which seam, for no
    // gain.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        upstream: CargoUpstream,
        advisory_store: AdvisoryStore,
        vet_store: CargoVetStore,
        verdict_store: VerdictStore,
        policy: Arc<Policy>,
        ai_reviewer: Option<Arc<AiReviewer>>,
        config: Arc<ConfigHandle>,
        coordinator: Arc<ScanCoordinator>,
    ) -> Self {
        Self {
            upstream: Arc::new(upstream),
            advisory_store: Arc::new(advisory_store),
            vet_store: Arc::new(vet_store),
            verdict_store: Arc::new(verdict_store),
            policy,
            ai_reviewer,
            config,
            coordinator,
            last_good_index: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The policy fingerprint every verdict this scanner stores carries.
    pub fn fingerprint(&self) -> String {
        self.policy.fingerprint().to_string()
    }

    /// Decides which versions of `package` may be forwarded.
    ///
    /// `package` is untrusted input. A name that fails [`validate_name`]
    /// yields an empty list, and no upstream request. The HTTP layer
    /// validates the name first and answers 400. This second test is
    /// defense in depth.
    pub async fn decide_index(&self, package: &str) -> CargoIndexDecision {
        if validate_name(package).is_err() {
            tracing::debug!(
                package,
                "refusing to cascade an invalid crate name; the caller validates first"
            );
            return CargoIndexDecision::Entries(Vec::new());
        }
        let normalized = normalize_name(package);
        // `Config` has no cargo-specific budget field. `scan_budget` is
        // the budget the deployment already sets for one proxy-side
        // answer, so the whole cascade for one crate draws from it.
        let deadline = Instant::now() + self.config.current().scan_budget;

        let entries = match self.upstream.index_entries(package).await {
            Ok(entries) => {
                self.remember_index(&normalized, &entries);
                entries
            }
            Err(UpstreamError::NotFound) => {
                // Upstream answered: no such crate. This is not an
                // outage. It must not wipe what earlier requests
                // already learned, so the remembered body stays.
                return CargoIndexDecision::Entries(Vec::new());
            }
            Err(err) => {
                tracing::warn!(
                    package,
                    error = %err,
                    "the cargo sparse index could not be read; answering with the \
                     versions already known to pass"
                );
                let known = entries_fallback(&self.last_good_index, &normalized);
                return self.decide_from_known_good(&normalized, &known).await;
            }
        };

        self.run_cascade(&normalized, &entries, deadline).await
    }

    /// Stores `entries` as the last good index body for `normalized`.
    fn remember_index(&self, normalized: &str, entries: &[CargoIndexEntry]) {
        if let Ok(mut cache) = self.last_good_index.lock() {
            cache.insert(normalized.to_string(), entries.to_vec());
        }
    }

    /// Answers an upstream outage from versions this proxy already knows
    /// to pass. A yanked version is out. A CVE-blocked version is out.
    /// What is left must be cargo-vet covered or already reviewed clean. A
    /// version the cascade never examined is not forwardable here. An
    /// outage is not evidence.
    async fn decide_from_known_good(
        &self,
        normalized: &str,
        entries: &[CargoIndexEntry],
    ) -> CargoIndexDecision {
        if entries.is_empty() {
            return CargoIndexDecision::Entries(Vec::new());
        }
        let facts = match self.facts(normalized, entries).await {
            Ok(facts) => facts,
            Err(_) => return CargoIndexDecision::Entries(Vec::new()),
        };

        // Nothing can be reviewed during an outage, so every version with
        // no verdict and no vet coverage is "nothing left to try" for
        // this pass. It is not written to any store, so the next
        // successful request reviews it normally.
        let mut review_status = facts.review_status;
        for entry in entries {
            review_status
                .entry(entry.vers.clone())
                .or_insert(ReviewStatus::Failed);
        }
        let input =
            self.cascade_input(entries, &facts.advisories, review_status, facts.vet_covered);
        match plan_cascade(&input) {
            NextStep::Forward(versions) => {
                CargoIndexDecision::Entries(entries_for_versions(entries, &versions))
            }
            // Unreachable: every non-forwardable survivor was just marked
            // failed. Answering empty rather than panicking keeps an
            // outage path free of unwraps.
            NextStep::NeedsReview(vers) => {
                tracing::warn!(
                    package = normalized,
                    version = vers,
                    "the cascade wanted a review during an upstream outage; \
                     forwarding nothing"
                );
                CargoIndexDecision::Entries(Vec::new())
            }
        }
    }

    /// Runs the cascade against `entries` until it forwards or the
    /// deadline passes.
    async fn run_cascade(
        &self,
        normalized: &str,
        entries: &[CargoIndexEntry],
        deadline: Instant,
    ) -> CargoIndexDecision {
        let mut facts = match self.facts(normalized, entries).await {
            Ok(facts) => facts,
            Err(err) => {
                // No advisory mirror means no CVE filtering, and a
                // cascade without CVE filtering would fail open.
                tracing::warn!(
                    package = normalized,
                    error = %err,
                    "the advisory or cargo-vet lookup failed; forwarding nothing"
                );
                return CargoIndexDecision::Entries(Vec::new());
            }
        };

        // `ReviewStatus` is Task 4's type, and it carries no `Clone`.
        // Each iteration moves the two maps into the input. It then takes
        // them back after the pure decision. Nothing is lost between
        // iterations.
        let mut cve_blocked = HashSet::new();
        for entry in entries {
            if facts
                .advisories
                .iter()
                .any(|adv| self.advisory_blocks(adv, &entry.vers))
            {
                cve_blocked.insert(entry.vers.clone());
            }
        }

        loop {
            let input = CascadeInput {
                entries: entries.to_vec(),
                cve_blocked: cve_blocked.clone(),
                review_status: std::mem::take(&mut facts.review_status),
                vet_covered: std::mem::take(&mut facts.vet_covered),
            };
            let step = plan_cascade(&input);
            // Recover both maps: they are this caller's own data, and the
            // next iteration needs them.
            facts.review_status = input.review_status;
            facts.vet_covered = input.vet_covered;
            let candidate = match step {
                NextStep::Forward(versions) => {
                    let forwarded = entries_for_versions(entries, &versions);
                    tracing::debug!(
                        package = normalized,
                        forwarded = forwarded.len(),
                        "the cargo cascade forwarded this crate"
                    );
                    return CargoIndexDecision::Entries(forwarded);
                }
                NextStep::NeedsReview(vers) => vers,
            };

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                tracing::debug!(
                    package = normalized,
                    version = candidate,
                    "the cargo cascade ran out of its shared budget"
                );
                return CargoIndexDecision::InProgress;
            }

            let Some(entry) = entries
                .iter()
                .find(|entry| entry.vers == candidate)
                .cloned()
            else {
                // `plan_cascade` only ever names a version from its own
                // input, so this cannot happen. Forwarding nothing is the
                // safe answer if it ever does.
                tracing::warn!(
                    package = normalized,
                    version = candidate,
                    "the cascade named a version that is not in the index; forwarding nothing"
                );
                return CargoIndexDecision::Entries(Vec::new());
            };

            match self.review_one(normalized, &entry, remaining).await {
                Ok(ReviewResult::Passed) => {
                    facts
                        .review_status
                        .insert(entry.vers.clone(), ReviewStatus::Passed);
                }
                Ok(ReviewResult::Failed(reason)) => {
                    tracing::debug!(
                        package = normalized,
                        version = %entry.vers,
                        code = %reason.code,
                        "the cargo cascade moved past a version that failed review"
                    );
                    facts
                        .review_status
                        .insert(entry.vers.clone(), ReviewStatus::Failed);
                }
                // The review never happened, so nothing is known about
                // this version. Falling through to an older version
                // would turn a provider outage into a silent downgrade,
                // so the caller is asked to retry instead.
                Ok(ReviewResult::Unverifiable) => {
                    tracing::warn!(
                        package = normalized,
                        version = %entry.vers,
                        "the cargo review could not run; answering in progress"
                    );
                    return CargoIndexDecision::InProgress;
                }
                Err(()) => return CargoIndexDecision::InProgress,
            }
        }
    }

    /// Builds the pure cascade input from the fetched facts.
    fn cascade_input(
        &self,
        entries: &[CargoIndexEntry],
        advisories: &[Advisory],
        review_status: HashMap<String, ReviewStatus>,
        vet_covered: HashSet<String>,
    ) -> CascadeInput {
        let mut cve_blocked = HashSet::new();
        for entry in entries {
            if advisories
                .iter()
                .any(|adv| self.advisory_blocks(adv, &entry.vers))
            {
                cve_blocked.insert(entry.vers.clone());
            }
        }
        CascadeInput {
            entries: entries.to_vec(),
            cve_blocked,
            review_status,
            vet_covered,
        }
    }

    /// Whether one advisory blocks `version` under the org's CVE line.
    ///
    /// [`crate::advisory::matching::first_blocking`] does this same job on
    /// the PyPI path, with the PEP 440 matcher. Here the rule is
    /// [`Policy::blocks_advisory`] too: never a second copy of the
    /// severity and fix-available logic. The only difference is the
    /// SemVer matcher in place of the PEP 440 one.
    fn advisory_blocks(&self, adv: &Advisory, version: &str) -> bool {
        if !affects(adv, version) {
            return false;
        }
        self.policy.blocks_advisory(&AdvisoryVerdictInput {
            severity: adv.severity,
            has_fix: !adv.fixed_versions.is_empty(),
        })
    }

    /// Reads every per-version fact one cascade iteration needs, on the
    /// blocking pool.
    async fn facts(&self, normalized: &str, entries: &[CargoIndexEntry]) -> anyhow::Result<Facts> {
        let advisory_store = Arc::clone(&self.advisory_store);
        let vet_store = Arc::clone(&self.vet_store);
        let verdict_store = Arc::clone(&self.verdict_store);
        let fingerprint = self.fingerprint();
        let normalized = normalized.to_string();
        let entries = entries.to_vec();
        let (criterion, reviewers) = self.vet_requirements();
        let review_disabled = self.ai_reviewer.is_none();

        tokio::task::spawn_blocking(move || {
            let mut advisories: Vec<Advisory> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            for ecosystem in ADVISORY_ECOSYSTEMS {
                for adv in advisory_store.for_package(ecosystem, &normalized)? {
                    if seen.insert(adv.id.clone()) {
                        advisories.push(adv);
                    }
                }
            }

            let mut review_status = HashMap::new();
            let mut vet_covered = HashSet::new();
            for entry in &entries {
                let key = artifact_key(&normalized, entry);
                match verdict_store.get(&key, &fingerprint)? {
                    Some(stored) => {
                        let status = match stored.verdict {
                            Verdict::Clean => ReviewStatus::Passed,
                            Verdict::Blocked(_) => ReviewStatus::Failed,
                        };
                        review_status.insert(entry.vers.clone(), status);
                    }
                    // With no reviewer configured, no unreviewed
                    // version can ever pass. Marking it failed here
                    // stops the cascade from asking for a review it
                    // cannot run. The mark is local to this call:
                    // nothing is stored.
                    None if review_disabled => {
                        review_status.insert(entry.vers.clone(), ReviewStatus::Failed);
                    }
                    None => {}
                }
                if vet_store.covers(&normalized, &entry.vers, &criterion, &reviewers)? {
                    vet_covered.insert(entry.vers.clone());
                }
            }

            Ok(Facts {
                advisories,
                review_status,
                vet_covered,
            })
        })
        .await
        .map_err(|join_error| {
            anyhow::anyhow!("the cargo cascade fact lookup panicked: {join_error}")
        })?
    }

    /// The cargo-vet criterion and reviewer list the fast path uses.
    fn vet_requirements(&self) -> (String, Vec<String>) {
        match self.config.current().cargo_registry.as_ref() {
            Some(cargo) => (
                cargo.required_criterion.clone(),
                cargo.trusted_reviewers.clone(),
            ),
            None => (DEFAULT_REQUIRED_CRITERION.to_string(), Vec::new()),
        }
    }

    /// Reviews one candidate version, deduplicated by
    /// `(package, version)`.
    ///
    /// `Err(())` means this caller answers
    /// [`CargoIndexDecision::InProgress`]. The review did not finish
    /// inside `remaining`. The owning review itself is *not* cancelled
    /// when that happens. It runs detached and stores what it finds, so a
    /// developer's retry lands on a stored verdict. Two concurrent
    /// requests for the same candidate run one review between them. The
    /// first owns it. The second joins and reuses the outcome.
    async fn review_one(
        &self,
        normalized: &str,
        entry: &CargoIndexEntry,
        remaining: Duration,
    ) -> Result<ReviewResult, ()> {
        // A crate name contains no `@` (see `validate_name`), so this key
        // separates the two fields unambiguously.
        let inflight_key = format!("{normalized}@{}", entry.vers);
        let key = artifact_key(normalized, entry);
        let fingerprint = self.fingerprint();

        match self.coordinator.start_or_join(&inflight_key) {
            Ok(tx) => {
                let scanner = self.clone();
                let reviewed = entry.clone();
                let vers = entry.vers.clone();
                let coordinator = Arc::clone(&self.coordinator);
                let cleanup_key = inflight_key.clone();

                // Detached on purpose, in the same shape
                // `Scanner::scan_with_budget` uses. This caller's budget
                // running out stops this caller from waiting. It does not
                // stop the review. A review that finishes late still
                // stores its verdict for the retry.
                //
                // `_finish_guard` is the first local, so its `Drop` runs
                // last on every exit path, including a panic. It runs
                // after the review and the send. The coordinator's entry
                // is therefore never leaked.
                let handle = tokio::spawn(async move {
                    let _finish_guard = FinishGuard::new(coordinator, cleanup_key);
                    let result = scanner.run_review(&reviewed, &key, &fingerprint).await;
                    let _ = tx.send(verdict_for_dedup(&result));
                    result
                });

                match tokio::time::timeout(remaining, handle).await {
                    Ok(Ok(result)) => Ok(result),
                    Ok(Err(join_error)) => {
                        tracing::warn!(
                            package = normalized,
                            version = %vers,
                            error = %join_error,
                            "the cargo review task did not complete"
                        );
                        Err(())
                    }
                    Err(_elapsed) => {
                        tracing::debug!(
                            package = normalized,
                            version = %vers,
                            "the cargo review outlived the shared budget; it keeps running"
                        );
                        Err(())
                    }
                }
            }
            Err(rx) => {
                match tokio::time::timeout(remaining, coordinator::wait_for_verdict(rx)).await {
                    Ok(Some(Verdict::Clean)) => Ok(ReviewResult::Passed),
                    Ok(Some(Verdict::Blocked(reason))) => Ok(ReviewResult::Failed(reason)),
                    // The owner's review produced no verdict, or this caller
                    // stopped waiting. Either way nothing is known yet.
                    Ok(None) => Err(()),
                    Err(_elapsed) => Err(()),
                }
            }
        }
    }

    /// Downloads, verifies, unpacks and reviews one candidate, then
    /// stores its verdict.
    async fn run_review(
        &self,
        entry: &CargoIndexEntry,
        key: &ArtifactKey,
        fingerprint: &str,
    ) -> ReviewResult {
        let Some(reviewer) = self.ai_reviewer.as_ref() else {
            // `facts` marks every unreviewed candidate failed when no
            // reviewer is configured, so the cascade never asks for this.
            return ReviewResult::Unverifiable;
        };

        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => {
                tracing::warn!(
                    package = %key.package,
                    version = %key.version,
                    error = %err,
                    "the cargo review could not create a temporary directory"
                );
                return ReviewResult::Unverifiable;
            }
        };

        let archive = dir.path().join(&key.filename);
        let actual = match self
            .upstream
            .download_crate(&entry.name, &entry.vers, &archive)
            .await
        {
            Ok(hash) => hash.to_lowercase(),
            Err(err) => {
                tracing::warn!(
                    package = %key.package,
                    version = %key.version,
                    error = %err,
                    "the cargo artifact could not be downloaded for review"
                );
                return ReviewResult::Unverifiable;
            }
        };
        if actual != key.sha256 {
            // The bytes do not match the index's checksum, so there is
            // nothing trustworthy to review and nothing to store.
            tracing::warn!(
                package = %key.package,
                version = %key.version,
                expected = %key.sha256,
                actual = %actual,
                "the downloaded .crate did not match the index checksum"
            );
            return ReviewResult::Unverifiable;
        }

        let unpacked = dir.path().join("unpacked");
        let unpack_source = archive.clone();
        let unpack_dest = unpacked.clone();
        let unpacked_ok =
            tokio::task::spawn_blocking(move || unpack(&unpack_source, &unpack_dest)).await;
        match unpacked_ok {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::warn!(
                    package = %key.package,
                    version = %key.version,
                    error = %err,
                    "the downloaded .crate could not be unpacked for review"
                );
                return ReviewResult::Unverifiable;
            }
            Err(join_error) => {
                tracing::warn!(
                    package = %key.package,
                    version = %key.version,
                    error = %join_error,
                    "the cargo unpack task did not complete"
                );
                return ReviewResult::Unverifiable;
            }
        }

        let outcome = reviewer.review(key, &unpacked, fingerprint).await;
        let (result, verdict) = match outcome {
            ReviewOutcome::Clean => (ReviewResult::Passed, Verdict::Clean),
            ReviewOutcome::Blocked(reason) => (
                ReviewResult::Failed(reason.clone()),
                Verdict::Blocked(reason),
            ),
            // Nothing was reviewed, so nothing is recorded and a later
            // request retries.
            ReviewOutcome::Unverifiable(reason) => {
                tracing::warn!(
                    package = %key.package,
                    version = %key.version,
                    code = %reason.code,
                    "the cargo review could not run"
                );
                return ReviewResult::Unverifiable;
            }
        };

        if self.store_verdict(key, verdict, fingerprint).await.is_err() {
            // A verdict that cannot be stored is not a verdict. Reporting
            // in progress makes the retry start over rather than serve a
            // version whose review record does not exist.
            tracing::warn!(
                package = %key.package,
                version = %key.version,
                "the cargo review verdict could not be stored"
            );
            return ReviewResult::Unverifiable;
        }
        result
    }

    /// Stores one verdict on the blocking pool.
    async fn store_verdict(
        &self,
        key: &ArtifactKey,
        verdict: Verdict,
        fingerprint: &str,
    ) -> anyhow::Result<String> {
        let store = Arc::clone(&self.verdict_store);
        let key = key.clone();
        let fingerprint = fingerprint.to_string();
        tokio::task::spawn_blocking(move || store.put(&key, &verdict, &fingerprint))
            .await
            .map_err(|join_error| {
                anyhow::anyhow!("the verdict store task panicked: {join_error}")
            })?
    }
}

/// Builds the artifact key for one candidate version.
///
/// Tasks 7 and 8 depend on this scheme. Ecosystem is `"cargo"`. Package
/// is the normalized crate name. Version is the index entry's `vers`.
/// Filename is `"{name}-{vers}.crate"`, with the name as upstream
/// published it. Sha256 is the entry's `cksum` in lowercase.
///
/// [`crate::http::cargo_download`] calls this same function, so the
/// verdict the index cascade stores is the verdict the download gate
/// reads. There is one definition of the scheme, not two.
pub(crate) fn artifact_key(normalized: &str, entry: &CargoIndexEntry) -> ArtifactKey {
    ArtifactKey {
        ecosystem: ECOSYSTEM.to_string(),
        package: normalized.to_string(),
        version: entry.vers.clone(),
        filename: format!("{}-{}.crate", entry.name, entry.vers),
        sha256: entry.cksum.to_lowercase(),
    }
}

/// Selects the index entries for `versions`, keeping `versions`' order
/// (newest first, as `plan_cascade` produced it).
fn entries_for_versions(entries: &[CargoIndexEntry], versions: &[String]) -> Vec<CargoIndexEntry> {
    let mut by_version: HashMap<&str, &CargoIndexEntry> = HashMap::new();
    for entry in entries {
        by_version.entry(entry.vers.as_str()).or_insert(entry);
    }
    versions
        .iter()
        .filter_map(|vers| by_version.get(vers.as_str()).copied().cloned())
        .collect()
}

/// Reads the remembered index body for `normalized` out of the shared
/// map, or returns an empty list when there is none.
fn entries_fallback(
    cache: &Mutex<HashMap<String, Vec<CargoIndexEntry>>>,
    normalized: &str,
) -> Vec<CargoIndexEntry> {
    cache
        .lock()
        .ok()
        .and_then(|cache| cache.get(normalized).cloned())
        .unwrap_or_default()
}

/// The value to broadcast to a concurrent joiner. It is `Some(verdict)`
/// only when a verdict was actually stored, and `None` otherwise. A
/// review that could not run has nothing durable for a joiner to reuse.
fn verdict_for_dedup(result: &ReviewResult) -> Option<Verdict> {
    match result {
        ReviewResult::Passed => Some(Verdict::Clean),
        ReviewResult::Failed(reason) => Some(Verdict::Blocked(reason.clone())),
        ReviewResult::Unverifiable => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, vers: &str, yanked: bool) -> CargoIndexEntry {
        CargoIndexEntry {
            name: name.to_string(),
            vers: vers.to_string(),
            cksum: format!("CKSUM{vers}"),
            yanked,
        }
    }

    #[test]
    fn the_artifact_key_uses_the_normalized_package_and_lowercase_checksum() {
        let key = artifact_key("serde-json", &entry("serde_json", "1.0.0", false));
        assert_eq!(key.ecosystem, "cargo");
        assert_eq!(key.package, "serde-json");
        assert_eq!(key.version, "1.0.0");
        assert_eq!(key.filename, "serde_json-1.0.0.crate");
        assert_eq!(key.sha256, "cksum1.0.0");
    }

    #[test]
    fn entries_for_versions_keeps_the_cascade_order() {
        let entries = vec![entry("demo", "0.9.0", false), entry("demo", "1.0.0", false)];
        let selected = entries_for_versions(&entries, &["1.0.0".to_string(), "0.9.0".to_string()]);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].vers, "1.0.0");
        assert_eq!(selected[1].vers, "0.9.0");
    }

    #[test]
    fn entries_for_versions_skips_a_version_with_no_entry() {
        let entries = vec![entry("demo", "1.0.0", false)];
        assert!(entries_for_versions(&entries, &["2.0.0".to_string()]).is_empty());
    }
}

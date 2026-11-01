//! Orchestration for the npm cascade: the I/O half of
//! [`crate::scan::npm_cascade`].
//!
//! [`plan_npm_cascade`] decides, from data handed to it, which published
//! versions of one package this proxy may forward, and names the single
//! version to review next. This module fetches that data from the real
//! stores and services, runs the review, and repeats. It stops when the
//! cascade forwards, or when the shared budget runs out.
//!
//! One call to [`NpmScanner::decide_packument`] is one package question:
//! which of its published versions should the filtered packument this
//! proxy serves advertise? The answer is never a guess in a package's
//! favour:
//!
//! - An advisory-lookup failure forwards nothing.
//! - A review that could not run reports [`NpmIndexDecision::InProgress`]
//!   rather than quietly falling back to an older version.
//! - An upstream outage forwards only versions already known to pass. It
//!   never marks a previously passed version bad.
//! - With no `[ai_review]` configured, every unreviewed version is
//!   locally (never durably) marked review-failed, so the cascade never
//!   asks for a review it cannot run. There is no cargo-vet-shaped fast
//!   path for npm, so that means nothing at all is forwardable.
//!
//! # The shared budget
//!
//! The whole cascade for one package draws from one deadline, taken from
//! [`crate::config::NpmRegistryConfig::scan_budget`] — the npm
//! deployment's own field, not the top-level `Config::scan_budget` the
//! cargo path reads, because a packument fetch and a tarball review need
//! a far more generous allowance than the PyPI-shaped budget that field
//! is capped at. Once the deadline passes, `decide_packument` returns
//! [`NpmIndexDecision::InProgress`]. It stores nothing new, so a retry
//! starts from the work the finished reviews already recorded.
//!
//! # The artifact key
//!
//! A candidate version's [`ArtifactKey`] has these five fields. Ecosystem
//! is `"npm"`. Package is the normalized (lowercased) package name.
//! Version is the packument's own version string. Filename is
//! `"{unscoped}-{version}.tgz"`, with `unscoped` stripping any
//! `@scope/` prefix off the registry's own `name` field, matching
//! [`crate::ecosystem::npm::tarball_path`]'s own unscoping. Sha256 is the
//! registry-declared digest (sha512 or sha1) in lowercase hex. Task 11's
//! download gate uses this exact scheme via [`artifact_key`], so a
//! verdict stored here is the verdict the download gate reads.
//!
//! # The download gate's metadata query
//!
//! [`NpmScanner::approved_for_download`] answers the one question the
//! packument gate cannot: has this exact version already been durably
//! approved? [`DownloadApproval::NotApproved`] means "no stored pass for
//! this version" and is a refusal at download time — this function never
//! runs a review. The packument gate has necessarily already run for any
//! version npm could have learned about, so a download request is simply
//! not the place a review belongs.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::advisory::matching::sanitize_detail_text;
use crate::advisory::matching_semver::affects;
use crate::advisory::Advisory;
use crate::ai::{AiReviewer, ReviewOutcome};
use crate::artifact_cache::ArtifactCache;
use crate::audit::{ListingAudit, VersionDecision};
use crate::config::ConfigHandle;
use crate::db::advisory::AdvisoryStore;
use crate::db::verdict::{FileVerdict, StoredVerdict, VerdictStore};
use crate::ecosystem::npm::packument::{
    declared_digest, filter_packument, DeclaredDigest, Dist, Packument, PackumentVersion,
};
use crate::ecosystem::npm::upstream::{NpmUpstream, UpstreamError};
use crate::ecosystem::npm::{normalize_name, validate_name};
use crate::model::{ArtifactKey, RefusalReason, Verdict};
use crate::plugin::unpack;
use crate::policy::{AdvisoryVerdictInput, Policy};
use crate::scan::cargo_cascade::ReviewStatus;
use crate::scan::coordinator::{self, FinishGuard, ScanCoordinator};
use crate::scan::is_allowlisted;
use crate::scan::npm_cascade::{plan_npm_cascade, NpmCascadeInput, NpmNextStep};

/// The ecosystem id this module stores verdicts under and reads
/// advisories from. OSV's own feed already spells npm's ecosystem
/// `"npm"`, so — unlike the cargo path — there is no second spelling to
/// join against.
const ECOSYSTEM: &str = "npm";

/// The scan budget assumed when, for whatever reason, this scanner runs
/// with no `[npm_registry]` table at all. Mirrors
/// `crate::config`'s own default for `NpmRegistryConfig::scan_budget`.
/// A real npm deployment always configures the table; this is defense in
/// depth, not a path any production deployment exercises.
const DEFAULT_SCAN_BUDGET: Duration = Duration::from_secs(120);

/// Entry-count cap on [`LastGoodPackumentCache`]. Lower than
/// [`crate::ecosystem::npm::upstream::EtagCache`]'s 500: a cached
/// [`Packument`] is a heavier resident than that cache's plain `String`
/// bodies (see [`PACKUMENT_WEIGHT_MULTIPLIER`]), so even disregarding the
/// weighted-bytes cap below, holding as many entries costs more baseline
/// memory per entry. A long-running deployment that queries a wide spread
/// of distinct package names over its lifetime would otherwise grow this
/// map without bound, exactly the gap the `EtagCache` bounding pass
/// missed for this map.
const MAX_LAST_GOOD_PACKUMENT_ENTRIES: usize = 300;

/// Approximation of how much larger a parsed [`Packument`] is in memory
/// than the JSON text it was parsed from. [`EtagCache`] can cap directly
/// on a cached body's own `len()`, because it caches the text itself;
/// `LastGoodPackumentCache` caches the *parsed* [`Packument`], whose
/// dominant cost is `Packument::raw`'s `serde_json::Value` tree — one
/// heap-allocated node per JSON token, each carrying `Value`'s own enum
/// discriminant plus a `String`, `Vec`, or `Map` of its own, rather than
/// one contiguous byte buffer. 4x is a conservative estimate for that
/// per-node overhead, not a measured figure: the alternative was
/// threading the original response's byte length through
/// [`crate::ecosystem::npm::upstream::NpmUpstream::packument`]'s public
/// return type solely so this weight check could use it, which this cache
/// chooses not to do.
const PACKUMENT_WEIGHT_MULTIPLIER: u64 = 4;

/// Weighted-bytes cap on [`LastGoodPackumentCache`], in the same units
/// [`packument_weight`] returns (a re-serialized length, multiplied by
/// [`PACKUMENT_WEIGHT_MULTIPLIER`]). Lower than
/// [`crate::ecosystem::npm::upstream::EtagCache`]'s 200 MiB (of actual
/// text bytes) by roughly the weight multiplier, so this cache's real
/// memory footprint stays in the same small-fraction-of-deployment-memory
/// range as that one, despite caching a heavier structure per entry.
const MAX_LAST_GOOD_PACKUMENT_WEIGHT: u64 = 150 * 1024 * 1024;

/// Approximates `packument`'s in-memory weight, for
/// [`LastGoodPackumentCache`]'s eviction policy: the size of its `raw`
/// document re-serialized to JSON text, multiplied by
/// [`PACKUMENT_WEIGHT_MULTIPLIER`] to approximate the larger footprint of
/// the parsed `Value` tree actually held in memory. A re-serialization
/// failure (not expected: `raw` came from a successful `parse_packument`
/// call) weighs as zero rather than erroring — this is a soft eviction
/// hint, not a correctness-bearing size, so the worst a wrong weight can
/// do is cache slightly more or less than intended.
fn packument_weight(packument: &Packument) -> u64 {
    serde_json::to_vec(&packument.raw)
        .map(|bytes| bytes.len() as u64 * PACKUMENT_WEIGHT_MULTIPLIER)
        .unwrap_or(0)
}

/// A bounded cache of the last successfully fetched [`Packument`] per
/// normalized package name, used by [`NpmScanner`] to answer an upstream
/// outage with the versions already known to pass rather than an empty
/// packument.
///
/// Shaped exactly like
/// [`crate::ecosystem::npm::upstream::EtagCache`]: an entry count cap and
/// a total-weight cap ([`MAX_LAST_GOOD_PACKUMENT_ENTRIES`],
/// [`MAX_LAST_GOOD_PACKUMENT_WEIGHT`] in [`LastGoodPackumentCache::new`]),
/// whichever is exceeded evicting the single oldest entry (by insertion or
/// last-update order, tracked the same `VecDeque` way), repeating until
/// both caps are satisfied again. A cache miss during an outage only
/// costs falling back to an empty packument for that one request — see
/// [`NpmScanner::decide_packument`] — never a wrong decision, so a soft,
/// approximate eviction policy is the right trade here exactly as it is
/// for `EtagCache`.
///
/// `with_limits` is `pub` for the same reason `EtagCache::with_limits` is:
/// it gives `tests/` a seam to drive eviction directly with tiny caps,
/// rather than needing hundreds of distinct upstream fetches to exercise
/// the production caps.
pub struct LastGoodPackumentCache {
    entries: HashMap<String, Packument>,
    /// Insertion/last-update order, oldest first. A name appears at most
    /// once; re-inserting a name already cached removes its old position
    /// before pushing the fresh one to the back, so it is not evicted as
    /// though it were the stalest entry.
    order: VecDeque<String>,
    total_weight: u64,
    max_entries: usize,
    max_weight: u64,
}

impl LastGoodPackumentCache {
    fn new() -> Self {
        Self::with_limits(
            MAX_LAST_GOOD_PACKUMENT_ENTRIES,
            MAX_LAST_GOOD_PACKUMENT_WEIGHT,
        )
    }

    /// Builds a cache with explicit caps. Production code always goes
    /// through [`LastGoodPackumentCache::new`]; this exists so tests can
    /// exercise eviction with caps small enough to hit in a handful of
    /// inserts.
    pub fn with_limits(max_entries: usize, max_weight: u64) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            total_weight: 0,
            max_entries,
            max_weight,
        }
    }

    pub fn get(&self, name: &str) -> Option<Packument> {
        self.entries.get(name).cloned()
    }

    /// Inserts (or replaces) `name`'s cached packument, then evicts the
    /// oldest entry, repeatedly, until both caps are satisfied.
    pub fn insert(&mut self, name: String, packument: Packument) {
        if let Some(old) = self.entries.remove(&name) {
            self.total_weight = self.total_weight.saturating_sub(packument_weight(&old));
            self.order.retain(|cached| cached != &name);
        }
        self.total_weight = self
            .total_weight
            .saturating_add(packument_weight(&packument));
        self.order.push_back(name.clone());
        self.entries.insert(name, packument);

        while self.entries.len() > self.max_entries || self.total_weight > self.max_weight {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(evicted) = self.entries.remove(&oldest) {
                self.total_weight = self.total_weight.saturating_sub(packument_weight(&evicted));
            }
        }
    }

    /// The number of entries currently cached. Not used by production
    /// code; exposed so `tests/` can assert on eviction directly.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// What [`NpmScanner::decide_packument`] tells the registry-metadata
/// handler to serve for one package.
#[derive(Debug, Clone, PartialEq)]
pub enum NpmIndexDecision {
    /// The filtered packument this proxy serves back to npm, with only
    /// the forwardable versions' entries kept and their tarballs
    /// repointed at this proxy. Can carry zero versions; that is
    /// rendered exactly like a package with no usable version, never as
    /// an error.
    ///
    /// `audit` is the fetch audit log's record of this same decision:
    /// `versions_upstream` plus one [`VersionDecision`] per version the
    /// cascade actually evaluated. It is built with the full picture
    /// only at [`NpmScanner::run_cascade`]'s own `NpmNextStep::Forward`
    /// arm, which is the only point every fact a `listed` line needs
    /// (which versions were CVE-blocked, too-new, review-failed,
    /// allowlisted, and which were ultimately forwarded) is in scope at
    /// the same time — see [`NpmScanner::listing_audit`]'s own doc
    /// comment. Every other path that produces this variant (an invalid
    /// name, a package upstream does not have, an upstream outage, an
    /// internal lookup failure) never ran that decision, so it carries a
    /// minimal audit instead: the `versions_upstream` count it actually
    /// knows, and no `listed` lines — the honest answer when nothing was
    /// evaluated.
    Packument {
        doc: serde_json::Value,
        audit: ListingAudit,
    },
    /// Upstream answered: no such package. Distinct from an outage —
    /// callers must not treat this as "nothing passed yet" the way an
    /// empty `Packument` would read. No fetch audit record either: on
    /// npm the packument *is* the gate, and there is no packument here
    /// at all to have evaluated anything from.
    NotFound,
    /// The shared budget ran out mid-cascade. The caller tells the
    /// client to retry shortly. The reviews that already finished are
    /// stored, so a retry resumes rather than restarts. No fetch audit
    /// record either: no verdict was reached, so there is nothing yet
    /// for a line to describe.
    InProgress,
}

/// What [`NpmScanner::approved_for_download`] tells the download handler
/// about one exact package version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadApproval {
    /// A durable `Clean` verdict is on record for this version, under
    /// the running policy fingerprint. `dist` is upstream's own `dist`
    /// object for this version, fetched fresh, so the download handler
    /// has what it needs to fetch and verify the bytes.
    Approved { key: ArtifactKey, dist: Dist },
    /// A durable `Blocked` verdict is on record. Carries the stored
    /// reason and, when one exists, the `why_id` for a `/why/<id>` link.
    Refused(RefusalReason, Option<String>),
    /// No stored verdict exists for this version at all. This is a
    /// refusal at download time, never an invitation to review inline —
    /// see the module docs.
    NotApproved,
    /// Upstream has no such package, or no such version of it.
    NotFound,
    /// The version's `dist` carries no digest this proxy can verify
    /// (an unsupported or malformed `integrity` string, with no usable
    /// `shasum` fallback).
    Unverifiable(RefusalReason),
}

/// Decides, for one npm package, which published versions this proxy may
/// forward, and answers the download gate's per-version approval query.
///
/// Cheap to clone: every field is an `Arc`, so a clone can be moved into
/// the detached review task that outlives its caller's budget.
#[derive(Clone)]
pub struct NpmScanner {
    upstream: Arc<NpmUpstream>,
    advisory_store: Arc<AdvisoryStore>,
    verdict_store: Arc<VerdictStore>,
    policy: Arc<Policy>,
    /// The reviewer, when `[ai_review]` is configured. Without one, no
    /// version can ever pass review — npm has no cargo-vet-shaped fast
    /// path, so an unconfigured reviewer means nothing is forwardable at
    /// all. See [`NpmScanner::facts`].
    ai_reviewer: Option<Arc<AiReviewer>>,
    config: Arc<ConfigHandle>,
    coordinator: Arc<ScanCoordinator>,
    /// Caches a freshly reviewed, clean tarball's bytes so a later
    /// download-gate request for the same content need not re-fetch it
    /// from upstream. Never consulted to make a *decision* — only
    /// [`VerdictStore`] does that.
    artifact_cache: Arc<ArtifactCache>,
    /// The last successfully fetched packument per normalized package
    /// name.
    ///
    /// The upstream client keeps no packument of its own beyond its ETag
    /// cache, which this scanner never reads directly. Without this map,
    /// a transient blip (a timeout, a 5xx) would discard every version
    /// this proxy already forwarded for the package. This map lets an
    /// outage answer with the versions already known to pass instead of
    /// an empty packument. It holds only upstream's published metadata,
    /// never a review outcome, so a failed review never leaves a version
    /// in a half-cached state here.
    ///
    /// Bounded by both an entry count and a weighted-bytes cap — see
    /// [`LastGoodPackumentCache`]. A long-running deployment that fetches
    /// many distinct package names over its lifetime would otherwise grow
    /// this map without bound, holding a full parsed [`Packument`]
    /// (including its `raw` JSON tree) for every one of them forever.
    last_good_packument: Arc<Mutex<LastGoodPackumentCache>>,
}

/// The per-version facts one cascade iteration needs, all fetched from
/// the stores in one blocking-pool call.
struct Facts {
    advisories: Vec<Advisory>,
    review_status: HashMap<String, ReviewStatus>,
    /// Versions the release-age gate removed this round. Always empty
    /// when `NpmRegistryConfig::min_release_age_days` is unset, and
    /// best-effort when it is set — see [`NpmScanner::too_new_versions`].
    too_new: HashSet<String>,
    /// Versions the operator has allowlisted for this package. Computed
    /// once per cascade, not per iteration: an allowlist read is a
    /// config snapshot, and every iteration of one cascade must see the
    /// same one.
    allowlisted: HashSet<String>,
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

impl NpmScanner {
    // The argument count is the plan's own interface. Every construction
    // dependency is handed in explicitly, so a test can replace any one
    // of them.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        upstream: NpmUpstream,
        advisory_store: AdvisoryStore,
        verdict_store: VerdictStore,
        policy: Arc<Policy>,
        ai_reviewer: Option<Arc<AiReviewer>>,
        config: Arc<ConfigHandle>,
        coordinator: Arc<ScanCoordinator>,
        artifact_cache: Arc<ArtifactCache>,
    ) -> Self {
        Self {
            upstream: Arc::new(upstream),
            advisory_store: Arc::new(advisory_store),
            verdict_store: Arc::new(verdict_store),
            policy,
            ai_reviewer,
            config,
            coordinator,
            artifact_cache,
            last_good_packument: Arc::new(Mutex::new(LastGoodPackumentCache::new())),
        }
    }

    /// The policy fingerprint every verdict this scanner stores carries.
    pub fn fingerprint(&self) -> String {
        self.policy.fingerprint().to_string()
    }

    /// Decides which versions of `package` may be forwarded, as the
    /// filtered packument this proxy serves.
    ///
    /// `package` is untrusted input. A name that fails [`validate_name`]
    /// yields [`NpmIndexDecision::NotFound`], and no upstream request.
    /// The HTTP layer validates the name first; this is defense in
    /// depth.
    pub async fn decide_packument(&self, package: &str) -> NpmIndexDecision {
        if validate_name(package).is_err() {
            tracing::debug!(
                package,
                "refusing to cascade an invalid npm package name; the caller validates first"
            );
            return NpmIndexDecision::NotFound;
        }
        let normalized = normalize_name(package);
        let deadline = Instant::now() + self.scan_budget();

        let packument = match self.upstream.packument(package).await {
            Ok(packument) => {
                self.remember_packument(&normalized, &packument);
                packument
            }
            Err(UpstreamError::NotFound) => {
                // Upstream answered: no such package. Not an outage, and
                // must not wipe what earlier requests already learned.
                return NpmIndexDecision::NotFound;
            }
            Err(err) => {
                tracing::warn!(
                    package = normalized,
                    error = %err,
                    "the npm packument could not be read; answering with the versions \
                     already known to pass"
                );
                return match self.known_good(&normalized) {
                    Some(known) => self.decide_from_known_good(&normalized, &known).await,
                    None => NpmIndexDecision::Packument {
                        doc: filter_packument(
                            &empty_packument(&normalized),
                            &[],
                            &self.public_base(),
                        ),
                        audit: ListingAudit::default(),
                    },
                };
            }
        };

        self.run_cascade(&normalized, &packument, deadline).await
    }

    /// Stores `packument` as the last good fetch for `normalized`.
    fn remember_packument(&self, normalized: &str, packument: &Packument) {
        if let Ok(mut cache) = self.last_good_packument.lock() {
            cache.insert(normalized.to_string(), packument.clone());
        }
    }

    /// Reads the remembered packument for `normalized`, if any.
    fn known_good(&self, normalized: &str) -> Option<Packument> {
        self.last_good_packument
            .lock()
            .ok()
            .and_then(|cache| cache.get(normalized))
    }

    /// Answers an upstream outage from versions this proxy already knows
    /// to pass. What is left must already be reviewed clean. A version
    /// the cascade never examined is not forwardable here. An outage is
    /// not evidence.
    async fn decide_from_known_good(
        &self,
        normalized: &str,
        packument: &Packument,
    ) -> NpmIndexDecision {
        if packument.versions.is_empty() {
            return NpmIndexDecision::Packument {
                doc: filter_packument(packument, &[], &self.public_base()),
                audit: ListingAudit::default(),
            };
        }
        let mut facts = match self.facts(normalized, packument).await {
            Ok(facts) => facts,
            // An outage path's own lookup failure: no cascade decision
            // was reached for any of these versions, so none of them were
            // evaluated. See the `NpmIndexDecision::Packument` doc
            // comment for why this is a minimal, not the rich, audit.
            Err(_) => {
                return NpmIndexDecision::Packument {
                    doc: filter_packument(packument, &[], &self.public_base()),
                    audit: ListingAudit {
                        versions_upstream: packument.versions.len(),
                        decisions: Vec::new(),
                    },
                }
            }
        };

        // Nothing can be reviewed during an outage, so every version with
        // no verdict is "nothing left to try" for this pass. It is not
        // written to any store, so the next successful request reviews
        // it normally.
        for vers in packument.versions.keys() {
            facts
                .review_status
                .entry(vers.clone())
                .or_insert(ReviewStatus::Failed);
        }

        let versions: Vec<String> = packument.versions.keys().cloned().collect();
        let cve_blocked = self.cve_blocked(&versions, &facts.advisories);
        let input = NpmCascadeInput {
            versions,
            cve_blocked,
            too_new: facts.too_new,
            review_status: facts.review_status,
            allowlisted: facts.allowlisted,
        };

        match plan_npm_cascade(&input) {
            // See the `NpmIndexDecision::Packument` doc comment: this
            // outage path never has the full per-version picture
            // `run_cascade`'s own `NpmNextStep::Forward` arm does (no
            // `cve_blocked` set survives past this `input`, and nothing
            // here was actually reviewed), so it reports only the count
            // it does know, with no `listed` lines.
            NpmNextStep::Forward(versions) => NpmIndexDecision::Packument {
                doc: filter_packument(packument, &versions, &self.public_base()),
                audit: ListingAudit {
                    versions_upstream: packument.versions.len(),
                    decisions: Vec::new(),
                },
            },
            // Unreachable: every non-forwardable survivor was just
            // marked failed. Answering with no survivors rather than
            // panicking keeps an outage path free of unwraps.
            NpmNextStep::NeedsReview(vers) => {
                tracing::warn!(
                    package = normalized,
                    version = vers,
                    "the cascade wanted a review during an npm upstream outage; forwarding \
                     nothing"
                );
                NpmIndexDecision::Packument {
                    doc: filter_packument(packument, &[], &self.public_base()),
                    audit: ListingAudit {
                        versions_upstream: packument.versions.len(),
                        decisions: Vec::new(),
                    },
                }
            }
        }
    }

    /// Runs the cascade against `packument` until it forwards or the
    /// deadline passes.
    async fn run_cascade(
        &self,
        normalized: &str,
        packument: &Packument,
        deadline: Instant,
    ) -> NpmIndexDecision {
        let mut facts = match self.facts(normalized, packument).await {
            Ok(facts) => facts,
            Err(err) => {
                // No advisory mirror means no CVE filtering, and a
                // cascade without CVE filtering would fail open.
                tracing::warn!(
                    package = normalized,
                    error = %err,
                    "the npm advisory lookup failed; forwarding nothing"
                );
                return NpmIndexDecision::Packument {
                    doc: filter_packument(packument, &[], &self.public_base()),
                    audit: ListingAudit {
                        versions_upstream: packument.versions.len(),
                        decisions: Vec::new(),
                    },
                };
            }
        };

        let versions: Vec<String> = packument.versions.keys().cloned().collect();
        let cve_blocked = self.cve_blocked(&versions, &facts.advisories);

        loop {
            let input = NpmCascadeInput {
                versions: versions.clone(),
                cve_blocked: cve_blocked.clone(),
                too_new: facts.too_new.clone(),
                review_status: std::mem::take(&mut facts.review_status),
                allowlisted: facts.allowlisted.clone(),
            };
            let step = plan_npm_cascade(&input);
            facts.review_status = input.review_status;

            let candidate = match step {
                NpmNextStep::Forward(forward_versions) => {
                    let doc = filter_packument(packument, &forward_versions, &self.public_base());
                    tracing::debug!(
                        package = normalized,
                        forwarded = forward_versions.len(),
                        "the npm cascade forwarded this package"
                    );
                    // The only point every fact a `listed` line needs is
                    // in scope at once: `versions` (all of them, not just
                    // survivors), `cve_blocked`, `facts.too_new`,
                    // `facts.review_status` (just recovered above, so it
                    // reflects every review this cascade run completed),
                    // and `facts.allowlisted`. See
                    // `NpmScanner::listing_audit`'s own doc comment.
                    let audit = self
                        .listing_audit(
                            normalized,
                            &versions,
                            &facts.advisories,
                            &cve_blocked,
                            &facts.too_new,
                            &facts.review_status,
                            &facts.allowlisted,
                            &forward_versions,
                        )
                        .await;
                    return NpmIndexDecision::Packument { doc, audit };
                }
                NpmNextStep::NeedsReview(vers) => vers,
            };

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                tracing::debug!(
                    package = normalized,
                    version = candidate,
                    "the npm cascade ran out of its shared budget"
                );
                return NpmIndexDecision::InProgress;
            }

            let Some(entry) = packument.versions.get(&candidate).cloned() else {
                // `plan_npm_cascade` only ever names a version from its
                // own input, so this cannot happen. Forwarding nothing is
                // the safe answer if it ever does.
                tracing::warn!(
                    package = normalized,
                    version = candidate,
                    "the npm cascade named a version that is not in the packument; forwarding \
                     nothing"
                );
                return NpmIndexDecision::Packument {
                    doc: filter_packument(packument, &[], &self.public_base()),
                    audit: ListingAudit {
                        versions_upstream: packument.versions.len(),
                        decisions: Vec::new(),
                    },
                };
            };

            match self
                .review_one(normalized, packument, &candidate, &entry, remaining)
                .await
            {
                Ok(ReviewResult::Passed) => {
                    facts
                        .review_status
                        .insert(candidate.clone(), ReviewStatus::Passed);
                }
                Ok(ReviewResult::Failed(reason)) => {
                    tracing::debug!(
                        package = normalized,
                        version = %candidate,
                        code = %reason.code,
                        "the npm cascade moved past a version that failed review"
                    );
                    facts
                        .review_status
                        .insert(candidate.clone(), ReviewStatus::Failed);
                }
                // The review never happened, so nothing is known about
                // this version. Falling through to an older version
                // would turn a provider outage into a silent downgrade,
                // so the caller is asked to retry instead.
                Ok(ReviewResult::Unverifiable) => {
                    tracing::warn!(
                        package = normalized,
                        version = %candidate,
                        "the npm review could not run; answering in progress"
                    );
                    return NpmIndexDecision::InProgress;
                }
                Err(()) => return NpmIndexDecision::InProgress,
            }
        }
    }

    /// Whether one advisory blocks `version` under the org's CVE line.
    /// See `scan::cargo`'s equivalent for why this delegates to
    /// [`Policy::blocks_advisory`] rather than duplicating its logic.
    fn advisory_blocks(&self, adv: &Advisory, version: &str) -> bool {
        if !affects(adv, version) {
            return false;
        }
        self.policy.blocks_advisory(&AdvisoryVerdictInput {
            severity: adv.severity,
            has_fix: !adv.fixed_versions.is_empty(),
        })
    }

    /// The versions among `versions` that `advisories` blocks under the
    /// org's CVE line.
    fn cve_blocked(&self, versions: &[String], advisories: &[Advisory]) -> HashSet<String> {
        versions
            .iter()
            .filter(|vers| advisories.iter().any(|adv| self.advisory_blocks(adv, vers)))
            .cloned()
            .collect()
    }

    /// The advisory the fetch audit log cites for one CVE-blocked
    /// version's `cve:<advisory-id>` reason code: the lowest-id advisory
    /// among `advisories` that [`NpmScanner::advisory_blocks`] this
    /// `version`, chosen deterministically when more than one blocks it
    /// rather than by whatever order `advisories` happens to iterate in.
    /// Mirrors [`crate::scan::cargo::CargoScanner::blocking_advisory`]
    /// exactly, with the SemVer matcher in its `advisory_blocks` in place
    /// of cargo's. `None` only when the caller's own `cve_blocked` set
    /// disagrees with this same rule, which should not happen since both
    /// are built from the same `advisories` list.
    fn blocking_advisory<'a>(
        &self,
        advisories: &'a [Advisory],
        version: &str,
    ) -> Option<&'a Advisory> {
        advisories
            .iter()
            .filter(|adv| self.advisory_blocks(adv, version))
            .min_by(|a, b| a.id.cmp(&b.id))
    }

    /// Builds the fetch audit log's record of one listing response:
    /// `versions_upstream` plus one [`VersionDecision`] per *evaluated*
    /// version, in the vocabulary [`crate::audit`] defines.
    ///
    /// Called from exactly one place, [`NpmScanner::run_cascade`]'s own
    /// `NpmNextStep::Forward` arm, because that is the only point this
    /// cascade run's entire picture is in scope at once: every version
    /// upstream published, which of them `cve_blocked`/`too_new`
    /// removed, `review_status` as this run's reviews left it, the
    /// operator's `allowlisted` set, and `forwarded` — the exact
    /// versions the cascade decided to serve.
    ///
    /// Unlike cargo, there is no `yanked` check here: npm's own
    /// `deprecated` field is not equivalent (see `scan::npm_cascade`'s
    /// module docs), and a deprecated version stays an ordinary
    /// candidate rather than being excluded up front, so it is denied or
    /// forwarded by the same rules as any other version.
    ///
    /// A version not in `forwarded` and not caught by CVE or too-new is a
    /// survivor the cascade marked `ReviewStatus::Failed` without a real
    /// review ever running — the default stamp [`NpmScanner::facts`]
    /// applies to every unreviewed survivor when no `[ai_review]`
    /// reviewer is configured. Nothing was actually evaluated for it, so
    /// it gets no [`VersionDecision`] at all, exactly like a version the
    /// cascade never looked at. A review-failed version's reason text is
    /// read back from [`VerdictStore::file_verdicts`] — one bulk read,
    /// done here and nowhere else in this call — so a version with no
    /// *blocked* row (including the default-stamped, never-really-
    /// reviewed case above) correctly finds nothing, which is exactly the
    /// signal used to treat it as never evaluated. See
    /// `crate::scan::cargo::CargoScanner::listing_audit`'s own doc
    /// comment for the full reasoning behind reading this back rather
    /// than threading a reason up from inside the cascade loop; it
    /// applies identically here.
    ///
    /// Every argument is a distinct fact the single caller already has in
    /// scope at its own call site; bundling them into a struct would only
    /// move the same list one level out, for no gain.
    #[allow(clippy::too_many_arguments)]
    async fn listing_audit(
        &self,
        normalized: &str,
        versions: &[String],
        advisories: &[Advisory],
        cve_blocked: &HashSet<String>,
        too_new: &HashSet<String>,
        review_status: &HashMap<String, ReviewStatus>,
        allowlisted: &HashSet<String>,
        forwarded: &[String],
    ) -> ListingAudit {
        let forwarded_set: HashSet<&str> = forwarded.iter().map(String::as_str).collect();
        let file_verdicts = self.file_verdicts_by_version(normalized).await;

        let mut decisions = Vec::new();
        for vers in versions {
            if forwarded_set.contains(vers.as_str()) {
                decisions.push(VersionDecision {
                    version: vers.clone(),
                    filename: None,
                    allowed: true,
                    reason_code: allowlisted
                        .contains(vers)
                        .then(|| "allowlisted".to_string()),
                    reason_detail: None,
                    why_id: None,
                });
                continue;
            }

            // Not forwarded: find the reason, in the cascade's own
            // filtering order (CVE, then too-new — see
            // `plan_npm_cascade`'s module docs), falling through to a
            // real review failure last. A version matching none of these
            // was never evaluated and gets no line at all.
            let reason = if cve_blocked.contains(vers) {
                // The reason vocabulary is reused verbatim rather than
                // invented, per the design spec: `cve:<advisory-id>` is
                // the exact spelling `src/advisory/matching.rs`'s own
                // `refusal_reason` already uses for the PyPI path, so a
                // Loki hit on this denial carries the same id a `/why`
                // link (were one to exist for this code) would. When
                // more than one advisory blocks the same version, the
                // lowest id is chosen, deterministically rather than by
                // whatever order `advisories` happens to iterate in. The
                // summary is sanitized and capped through the same
                // `sanitize_detail_text` the PyPI path already applies to
                // this exact upstream text, so this line never carries
                // unbounded or unsanitized OSV data.
                Some(match self.blocking_advisory(advisories, vers) {
                    Some(adv) => {
                        let severity = match adv.severity {
                            Some(score) => format!("{score}"),
                            None => "unknown".to_string(),
                        };
                        let summary = sanitize_detail_text(&adv.summary);
                        (
                            format!("cve:{}", adv.id),
                            Some(format!("{summary} (severity {severity})")),
                            None,
                        )
                    }
                    // Unreachable in practice: `cve_blocked` was built
                    // from this same `advisories` list via the same
                    // `advisory_blocks` rule a moment earlier in
                    // `run_cascade`. Falls back to the bare code rather
                    // than panicking if that invariant is ever broken.
                    None => ("cve".to_string(), None, None),
                })
            } else if too_new.contains(vers) {
                Some((
                    "too-new".to_string(),
                    Some(
                        "this version was published too recently to meet the configured \
                         minimum release age"
                            .to_string(),
                    ),
                    None,
                ))
            } else if matches!(review_status.get(vers.as_str()), Some(ReviewStatus::Failed)) {
                // `blocked` is checked rather than trusting that a row
                // existing at all means "denied": this bulk read runs
                // after `facts()`'s own per-version reads decided
                // `review_status`, so a verdict a concurrent rescan
                // flipped to `Clean` in between must not be reported as
                // a denial with a stale or empty reason. Finding no
                // *blocked* row here is folded into the same "never
                // evaluated" outcome as finding no row at all.
                file_verdicts
                    .get(vers.as_str())
                    .filter(|verdict| verdict.blocked)
                    .map(|verdict| {
                        (
                            verdict.reason_code.clone(),
                            Some(verdict.reason_detail.clone()),
                            Some(verdict.why_id.clone()),
                        )
                    })
            } else {
                None
            };

            if let Some((reason_code, reason_detail, why_id)) = reason {
                decisions.push(VersionDecision {
                    version: vers.clone(),
                    filename: None,
                    allowed: false,
                    reason_code: Some(reason_code),
                    reason_detail,
                    why_id,
                });
            }
        }

        ListingAudit {
            versions_upstream: versions.len(),
            decisions,
        }
    }

    /// Every stored verdict for `normalized` under this scanner's running
    /// policy fingerprint, keyed by version — npm decides per version,
    /// not per file. Used only by [`NpmScanner::listing_audit`], as the
    /// single source of the reason text a review-failed version's audit
    /// line reports.
    ///
    /// A lookup failure is logged and answered as an empty map rather
    /// than propagated: this is enrichment for the fetch audit log's
    /// `listed` lines, not the gate itself, so a read error here must not
    /// turn into a failure to serve the packument that is already
    /// decided. The affected lines simply carry no reason text, which is
    /// honest — not a wrong answer, an absent one.
    async fn file_verdicts_by_version(&self, normalized: &str) -> HashMap<String, FileVerdict> {
        let store = Arc::clone(&self.verdict_store);
        let package = normalized.to_string();
        let fingerprint = self.fingerprint();
        match tokio::task::spawn_blocking(move || {
            store.file_verdicts(ECOSYSTEM, &package, &fingerprint)
        })
        .await
        {
            Ok(Ok(verdicts)) => verdicts
                .into_iter()
                .map(|verdict| (verdict.version.clone(), verdict))
                .collect(),
            Ok(Err(err)) => {
                tracing::warn!(
                    package = normalized,
                    error = %format!("{err:#}"),
                    "could not read stored verdicts for the listing audit; review-failed \
                     reasons will be omitted from this response's audit lines"
                );
                HashMap::new()
            }
            Err(join_error) => {
                tracing::warn!(
                    package = normalized,
                    error = %join_error,
                    "the listing-audit verdict lookup task panicked; review-failed reasons \
                     will be omitted from this response's audit lines"
                );
                HashMap::new()
            }
        }
    }

    /// Reads every per-version fact one cascade iteration needs, on the
    /// blocking pool.
    async fn facts(&self, normalized: &str, packument: &Packument) -> anyhow::Result<Facts> {
        let advisory_store = Arc::clone(&self.advisory_store);
        let verdict_store = Arc::clone(&self.verdict_store);
        let fingerprint = self.fingerprint();
        let normalized_owned = normalized.to_string();
        let versions_map = packument.versions.clone();
        let name = packument.name.clone();
        let review_disabled = self.ai_reviewer.is_none();

        let version_list: Vec<String> = versions_map.keys().cloned().collect();
        // Read the config snapshot once, here, so every iteration of this
        // cascade and every version in it sees the same allowlist.
        let allowlisted = self.allowlisted_for(&name, &version_list);
        // No network I/O: the release-age gate reads the packument's own
        // `time` map, never a separate upstream call.
        let too_new = self.too_new_versions(packument);

        tokio::task::spawn_blocking(move || {
            let advisories = advisory_store.for_package(ECOSYSTEM, &normalized_owned)?;

            let mut review_status = HashMap::new();
            for (vers, entry) in &versions_map {
                let Some(digest) = declared_digest(&entry.dist) else {
                    // No verifiable digest: this version can never be
                    // downloaded or reviewed honestly. Marking it failed
                    // locally (never stored) keeps the cascade from ever
                    // proposing it as a candidate.
                    review_status.insert(vers.clone(), ReviewStatus::Failed);
                    continue;
                };
                let key = artifact_key(&normalized_owned, &name, vers, &digest);
                match verdict_store.get(&key, &fingerprint)? {
                    Some(stored) => {
                        let status = match stored.verdict {
                            Verdict::Clean => ReviewStatus::Passed,
                            Verdict::Blocked(_) => ReviewStatus::Failed,
                        };
                        review_status.insert(vers.clone(), status);
                    }
                    // With no reviewer configured, no unreviewed version
                    // can ever pass. Marking it failed here stops the
                    // cascade from asking for a review it cannot run.
                    // The mark is local to this call: nothing is stored.
                    None if review_disabled => {
                        review_status.insert(vers.clone(), ReviewStatus::Failed);
                    }
                    None => {}
                }
            }

            Ok(Facts {
                advisories,
                review_status,
                too_new,
                allowlisted,
            })
        })
        .await
        .map_err(|join_error| {
            anyhow::anyhow!("the npm cascade fact lookup panicked: {join_error}")
        })?
    }

    /// The versions of `packument` published too recently under
    /// `NpmRegistryConfig::min_release_age_days`, read straight from the
    /// packument's own `time` map — no extra upstream call, unlike the
    /// PyPI and cargo paths.
    ///
    /// Best-effort, not fail-closed like the CVE filter: when the gate is
    /// unset, or when a version has no usable timestamp in `time` at
    /// all, this leaves that version out of the returned set rather than
    /// treating the missing information as a reason to forward nothing.
    /// The release-age gate is a secondary hygiene control layered on top
    /// of the CVE and AI-review gates, which stay fail-closed exactly as
    /// before.
    fn too_new_versions(&self, packument: &Packument) -> HashSet<String> {
        let Some(min_days) = self
            .config
            .current()
            .npm_registry
            .as_ref()
            .and_then(|npm| npm.min_release_age_days)
        else {
            return HashSet::new();
        };

        let min_age = chrono::Duration::days(min_days as i64);
        let now = chrono::Utc::now();
        packument
            .versions
            .keys()
            .filter(|vers| match packument.time.get(vers.as_str()) {
                Some(released) => now.signed_duration_since(*released) < min_age,
                // No reported publish time for this version: cannot
                // tell, so it is not flagged.
                None => false,
            })
            .cloned()
            .collect()
    }

    /// The versions of the package that the operator has allowlisted.
    ///
    /// Reuses [`crate::scan::is_allowlisted`], the crate's single
    /// implementation of the allowlist comparison, rather than comparing
    /// names a second way here — see `scan::cargo`'s equivalent method
    /// for the full reasoning, which applies identically here: the name
    /// is offered both as `name` (the registry's own spelling, scope and
    /// all) and as its npm-lowercased form, because `is_allowlisted`'s
    /// PEP 503 rule and npm's own lowercase-only rule agree for every
    /// ordinary package name but could in principle diverge on a
    /// pathological one.
    fn allowlisted_for(&self, name: &str, versions: &[String]) -> HashSet<String> {
        let config = self.config.current();
        let normalized = normalize_name(name);
        let mut allowlisted = HashSet::new();
        for vers in versions {
            let matched =
                is_allowlisted(&config, name, vers) || is_allowlisted(&config, &normalized, vers);
            if matched {
                allowlisted.insert(vers.clone());
            }
        }
        allowlisted
    }

    /// The whole cascade's shared deadline, from
    /// `NpmRegistryConfig::scan_budget` when the table is configured, or
    /// [`DEFAULT_SCAN_BUDGET`] otherwise.
    fn scan_budget(&self) -> Duration {
        self.config
            .current()
            .npm_registry
            .as_ref()
            .map(|npm| npm.scan_budget)
            .unwrap_or(DEFAULT_SCAN_BUDGET)
    }

    /// The base URL every forwarded tarball is rewritten to point at,
    /// with any trailing slash trimmed so `filter_packument`'s
    /// `"{public_base}/{path}"` join never doubles one up.
    fn public_base(&self) -> String {
        self.config
            .current()
            .public_url
            .as_str()
            .trim_end_matches('/')
            .to_string()
    }

    /// Reviews one candidate version, deduplicated by
    /// `(package, version)`.
    ///
    /// `Err(())` means this caller answers [`NpmIndexDecision::InProgress`].
    /// The review did not finish inside `remaining`. The owning review
    /// itself is *not* cancelled when that happens. It runs detached and
    /// stores what it finds, so a developer's retry lands on a stored
    /// verdict. Two concurrent requests for the same candidate run one
    /// review between them: the first owns it, the second joins and
    /// reuses the outcome.
    async fn review_one(
        &self,
        normalized: &str,
        packument: &Packument,
        vers: &str,
        entry: &PackumentVersion,
        remaining: Duration,
    ) -> Result<ReviewResult, ()> {
        // A package name contains no `@` outside its scope marker and no
        // bare `@` can begin a version string, so this key separates the
        // two fields unambiguously even for a scoped name.
        let inflight_key = format!("{normalized}@{vers}");

        // `facts` already marks any version with no verifiable digest
        // locally review-failed, so `plan_npm_cascade` never names one as
        // a candidate. This `None` branch is defense in depth, not a path
        // this call expects to take.
        let Some(digest) = declared_digest(&entry.dist) else {
            tracing::warn!(
                package = normalized,
                version = vers,
                "the npm cascade was asked to review a version with no verifiable digest"
            );
            return Ok(ReviewResult::Unverifiable);
        };
        let key = artifact_key(normalized, &packument.name, vers, &digest);
        let fingerprint = self.fingerprint();

        match self.coordinator.start_or_join(&inflight_key) {
            Ok(tx) => {
                let scanner = self.clone();
                let dist = entry.dist.clone();
                let reviewed_name = packument.name.clone();
                let reviewed_vers = vers.to_string();
                let coordinator = Arc::clone(&self.coordinator);
                let cleanup_key = inflight_key.clone();
                let review_key = key.clone();

                // Detached on purpose, in the same shape `cargo::CargoScanner`
                // uses. This caller's budget running out stops this caller
                // from waiting. It does not stop the review. A review that
                // finishes late still stores its verdict for the retry.
                //
                // `_finish_guard` is the first local, so its `Drop` runs
                // last on every exit path, including a panic. The
                // coordinator's entry is therefore never leaked.
                let handle = tokio::spawn(async move {
                    let _finish_guard = FinishGuard::new(coordinator, cleanup_key);
                    let result = scanner
                        .run_review(
                            &reviewed_name,
                            &reviewed_vers,
                            &dist,
                            &review_key,
                            &fingerprint,
                        )
                        .await;
                    let _ = tx.send(verdict_for_dedup(&result));
                    result
                });

                match tokio::time::timeout(remaining, handle).await {
                    Ok(Ok(result)) => Ok(result),
                    Ok(Err(join_error)) => {
                        tracing::warn!(
                            package = normalized,
                            version = vers,
                            error = %join_error,
                            "the npm review task did not complete"
                        );
                        Err(())
                    }
                    Err(_elapsed) => {
                        tracing::debug!(
                            package = normalized,
                            version = vers,
                            "the npm review outlived the shared budget; it keeps running"
                        );
                        Err(())
                    }
                }
            }
            Err(rx) => {
                match tokio::time::timeout(remaining, coordinator::wait_for_verdict(rx)).await {
                    Ok(Some(Verdict::Clean)) => Ok(ReviewResult::Passed),
                    Ok(Some(Verdict::Blocked(reason))) => Ok(ReviewResult::Failed(reason)),
                    // The owner's review produced no verdict, or this
                    // caller stopped waiting. Either way nothing is known
                    // yet.
                    Ok(None) => Err(()),
                    Err(_elapsed) => Err(()),
                }
            }
        }
    }

    /// Downloads (or reuses a cached copy of), unpacks and reviews one
    /// candidate, then stores its verdict.
    async fn run_review(
        &self,
        name: &str,
        vers: &str,
        dist: &Dist,
        key: &ArtifactKey,
        fingerprint: &str,
    ) -> ReviewResult {
        let Some(reviewer) = self.ai_reviewer.as_ref() else {
            // `facts` marks every unreviewed candidate failed when no
            // reviewer is configured, so the cascade never asks for this.
            return ReviewResult::Unverifiable;
        };

        let unpack_dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => {
                tracing::warn!(
                    package = %key.package,
                    version = %key.version,
                    error = %err,
                    "the npm review could not create a temporary directory"
                );
                return ReviewResult::Unverifiable;
            }
        };
        let unpacked = unpack_dir.path().join("unpacked");

        // A clean artifact already sitting in the artifact cache (from an
        // earlier review of the same content) is reused as-is: it was
        // hash-verified on the way in, so there is nothing to download
        // again.
        let (archive_path, _download_dir, freshly_downloaded) = match self.cache_get(key).await {
            Ok(Some(cached_path)) => match super::symlink_for_unpack(&cached_path, &key.filename) {
                Ok((guard, link)) => (link, Some(guard), false),
                Err(err) => {
                    tracing::warn!(
                        package = %key.package,
                        version = %key.version,
                        error = %err,
                        "the npm review could not symlink a cached artifact for unpacking"
                    );
                    return ReviewResult::Unverifiable;
                }
            },
            _ => {
                let download_dir = match tempfile::tempdir() {
                    Ok(dir) => dir,
                    Err(err) => {
                        tracing::warn!(
                            package = %key.package,
                            version = %key.version,
                            error = %err,
                            "the npm review could not create a download directory"
                        );
                        return ReviewResult::Unverifiable;
                    }
                };
                let dest = download_dir.path().join(&key.filename);
                if let Err(err) = self
                    .upstream
                    .download_tarball(name, vers, dist, &dest)
                    .await
                {
                    tracing::warn!(
                        package = %key.package,
                        version = %key.version,
                        error = %err,
                        "the npm tarball could not be downloaded (or failed digest \
                         verification) for review"
                    );
                    return ReviewResult::Unverifiable;
                }
                (dest, Some(download_dir), true)
            }
        };

        let unpack_source = archive_path.clone();
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
                    "the downloaded npm tarball could not be unpacked for review"
                );
                return ReviewResult::Unverifiable;
            }
            Err(join_error) => {
                tracing::warn!(
                    package = %key.package,
                    version = %key.version,
                    error = %join_error,
                    "the npm unpack task did not complete"
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
                    "the npm review could not run"
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
                "the npm review verdict could not be stored"
            );
            return ReviewResult::Unverifiable;
        }

        // Caching is a performance optimization for the download gate,
        // not part of the decision: a failure here is logged and
        // otherwise ignored. The verdict above is already durable, so a
        // later download simply re-downloads and re-verifies instead of
        // reusing this cache entry.
        if freshly_downloaded {
            if let Err(err) = self.cache_insert(key, &archive_path).await {
                tracing::warn!(
                    package = %key.package,
                    version = %key.version,
                    error = %err,
                    "could not cache a freshly reviewed npm tarball; a later download will \
                     re-fetch it"
                );
            }
        }

        result
    }

    /// Answers the download gate's one question for one exact version:
    /// is there a durable pass on record for it? Never runs a review —
    /// see the module docs.
    ///
    /// An upstream outage here is never a hard "no": falling through to
    /// [`DownloadApproval::NotApproved`] would read, to the download
    /// handler, as "the packument gate never admitted this version" —
    /// which is false for a version that may well carry a stored `Clean`
    /// verdict already, blocked only by a momentary blip re-reading its
    /// `dist`. [`DownloadApproval::Unverifiable`] maps to a retryable
    /// response instead, exactly as [`crate::scan::cargo::CargoScanner::approved_for_download`]'s
    /// own outage path does. Before giving up, this also falls back to
    /// [`NpmScanner::known_good`] — the same last-good packument
    /// [`NpmScanner::decide_packument`] falls back to — purely to look up
    /// `version`'s `dist`. That fallback cannot weaken the gate: the
    /// digest it yields is still the one the caller re-verifies against
    /// the downloaded bytes, so a stale or wrong `dist.tarball` there
    /// only risks a download that then fails its hash check, never a
    /// wrongly-approved one.
    pub async fn approved_for_download(&self, name: &str, version: &str) -> DownloadApproval {
        if validate_name(name).is_err() {
            tracing::debug!(
                package = name,
                "refusing a download approval check for an invalid npm package name"
            );
            return DownloadApproval::NotFound;
        }
        let normalized = normalize_name(name);

        // `is_live` distinguishes a freshly fetched packument from a
        // last-good fallback: only a live fetch can turn a missing
        // version into a confident `NotFound`. A version absent from a
        // stale cached packument during an outage is merely unconfirmed,
        // not confirmed absent.
        let (packument, is_live) = match self.upstream.packument(name).await {
            Ok(packument) => (packument, true),
            Err(UpstreamError::NotFound) => return DownloadApproval::NotFound,
            Err(err) => match self.known_good(&normalized) {
                Some(packument) => (packument, false),
                None => {
                    tracing::warn!(
                        package = normalized,
                        version,
                        error = %err,
                        "could not read the npm packument for a download approval check, and no \
                         last-good packument is cached for it; answering unverifiable rather \
                         than a hard refusal"
                    );
                    return DownloadApproval::Unverifiable(RefusalReason {
                        code: "unverifiable:upstream".to_string(),
                        detail: format!("could not read the npm packument right now: {err:#}"),
                    });
                }
            },
        };

        let Some(entry) = packument.versions.get(version) else {
            return if is_live {
                DownloadApproval::NotFound
            } else {
                tracing::warn!(
                    package = normalized,
                    version,
                    "the version is absent from the last-good cached npm packument, and \
                     upstream could not be reached to confirm whether it exists at all"
                );
                DownloadApproval::Unverifiable(RefusalReason {
                    code: "unverifiable:upstream".to_string(),
                    detail: format!(
                        "could not confirm whether {normalized} {version} exists: upstream is \
                         unreachable and it is not in the last cached packument"
                    ),
                })
            };
        };

        let Some(digest) = declared_digest(&entry.dist) else {
            return DownloadApproval::Unverifiable(RefusalReason {
                code: "unverifiable:npm-digest".to_string(),
                detail: format!(
                    "{normalized} {version} has no verifiable digest declared upstream"
                ),
            });
        };

        let key = artifact_key(&normalized, &packument.name, version, &digest);
        let fingerprint = self.fingerprint();

        match self.lookup_stored_verdict(&key, &fingerprint).await {
            Ok(Some(stored)) => match stored.verdict {
                Verdict::Clean => DownloadApproval::Approved {
                    key,
                    dist: entry.dist.clone(),
                },
                Verdict::Blocked(reason) => DownloadApproval::Refused(reason, Some(stored.why_id)),
            },
            Ok(None) => DownloadApproval::NotApproved,
            Err(err) => {
                tracing::warn!(
                    package = normalized,
                    version,
                    error = %err,
                    "could not read the stored npm verdict; refusing the download rather than \
                     approving it"
                );
                DownloadApproval::NotApproved
            }
        }
    }

    // -----------------------------------------------------------------
    // Blocking-store and cache access, each on the blocking pool
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
            .map_err(|join_error| {
                anyhow::anyhow!("the npm verdict lookup task panicked: {join_error}")
            })?
    }

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
                anyhow::anyhow!("the npm verdict store task panicked: {join_error}")
            })?
    }

    async fn cache_get(&self, key: &ArtifactKey) -> anyhow::Result<Option<PathBuf>> {
        let cache = Arc::clone(&self.artifact_cache);
        let key = key.clone();
        tokio::task::spawn_blocking(move || cache.get(&key))
            .await
            .map_err(|join_error| {
                anyhow::anyhow!("the npm artifact cache lookup task panicked: {join_error}")
            })?
    }

    async fn cache_insert(&self, key: &ArtifactKey, file: &Path) -> anyhow::Result<PathBuf> {
        let cache = Arc::clone(&self.artifact_cache);
        let key = key.clone();
        let file = file.to_path_buf();
        tokio::task::spawn_blocking(move || cache.insert(&key, &file))
            .await
            .map_err(|join_error| {
                anyhow::anyhow!("the npm artifact cache insert task panicked: {join_error}")
            })?
    }
}

/// Builds the artifact key for one candidate version.
///
/// Ecosystem is `"npm"`. Package is `normalized`. Version is the
/// packument's own version string. Filename is `"{unscoped}-{version}.tgz"`,
/// where `unscoped` strips any `@scope/` prefix off `name` — the same
/// unscoping [`crate::ecosystem::npm::tarball_path`] applies, so a
/// filename built here always matches the one upstream's own tarball
/// path would produce. Sha256 is `digest.hex`.
///
/// Task 11's download gate calls this same function, so the verdict the
/// packument cascade stores is the verdict the download gate reads.
/// There is one definition of the scheme, not two.
pub fn artifact_key(
    normalized: &str,
    name: &str,
    version: &str,
    digest: &DeclaredDigest,
) -> ArtifactKey {
    let unscoped = match name.find('/') {
        Some(idx) => &name[idx + 1..],
        None => name,
    };
    ArtifactKey {
        ecosystem: ECOSYSTEM.to_string(),
        package: normalized.to_string(),
        version: version.to_string(),
        filename: format!("{unscoped}-{version}.tgz"),
        sha256: digest.hex.clone(),
    }
}

/// A synthetic, zero-version packument for `name`, used only when
/// upstream cannot be reached at all and no earlier successful fetch has
/// ever been cached for it. [`filter_packument`] renders this exactly as
/// it would render a real packument with every version filtered out: a
/// well-formed document with empty `versions` and empty `dist-tags`.
fn empty_packument(name: &str) -> Packument {
    Packument {
        name: name.to_string(),
        versions: BTreeMap::new(),
        dist_tags: BTreeMap::new(),
        time: BTreeMap::new(),
        raw: serde_json::json!({ "name": name, "versions": {}, "dist-tags": {} }),
    }
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

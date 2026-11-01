//! `GET /crates/{crate}/{version}/download`: the `.crate` download that
//! runs the organization's plugins, once per artifact.
//!
//! This route is the cargo deployment's counterpart to
//! [`crate::http::artifact`], and the second half of the cargo gate. The
//! sparse-index handler ([`crate::http::cargo_index`]) already refused any
//! version the CVE line or the AI review rejected, before `cargo add`
//! returned. This handler decides the one question the index never could:
//! does the artifact pass the organization's own plugin binaries?
//!
//! `cargo_config_handler` advertises this exact path in its `dl` template,
//! so cargo comes back here for the bytes and this gate stays in the loop.
//!
//! # The stored verdict is the cache
//!
//! `VerdictStore` is the durable memory of this gate, exactly as it is for
//! PyPI. A plugin run is expensive, so it happens once per artifact, not
//! once per download:
//!
//! - **A stored `Clean` verdict, not yet plugin-checked** — download the
//!   `.crate`, verify it against the index's `cksum`, unpack it, run every
//!   configured plugin, then store and serve the outcome.
//! - **A stored `Clean` verdict already marked plugin-checked** — serve
//!   the bytes without running a plugin. The artifact cache holds them. If
//!   an operator emptied the cache directory, the bytes are downloaded and
//!   hash-verified again, because a cache hit is only as good as the hash
//!   that admitted it.
//! - **A stored `Blocked` verdict** — refuse, with the stored reason and
//!   its `/why/<id>` link.
//! - **No stored verdict at all** — refuse, without downloading anything.
//!   See below.
//!
//! # The index gate is the admission, and this gate cannot replace it
//!
//! The index cascade is the gate that CVE-filters, age-checks, and
//! reviews a version, and it records a `Clean` verdict for every version
//! it admits. A version with no stored verdict is therefore a version the
//! cascade never admitted: it is not in any sparse-index response this
//! proxy served, so cargo had no way to learn about it except by asking
//! this route directly.
//!
//! Such a request used to fall through to the plugin gate and be served on
//! plugin-pass alone, which meant an artifact nobody had CVE-filtered,
//! age-checked, or reviewed could reach a developer. It is now
//! [`RefusalReason`] code `not-index-approved`. This handler cannot review
//! the version itself — reviewing belongs to the cascade, which is what
//! decides whether a version is *advertisable*, and a download request is
//! not evidence that it should be. An operator who wants a version the
//! cascade could not reach allowlists it; that override is checked first,
//! below, and still requires the bytes to match the index `cksum`.
//!
//! The one exception is the allowlist, by design: an operator's explicit
//! decision in the config stands in for the index gate's judgement checks.
//!
//! `plugin_checked` is a separate flag from the verdict on purpose. The
//! index cascade stores `Verdict::Clean` for a crate-vet-covered version
//! it never unpacked, and [`VerdictStore::put`] resets the flag whenever
//! it rewrites a verdict. A `Clean` row alone therefore does not mean the
//! plugins have seen this artifact; only the flag does. See
//! [`crate::db::verdict`].
//!
//! # One plugin run per artifact, even under concurrency
//!
//! A first-touch download is deduplicated by
//! [`CargoAppState::plugin_run_coordinator`], keyed by `key.sha256`:
//! concurrent requests for the same not-yet-plugin-checked artifact share
//! one download-unpack-plugin run rather than each paying for their own.
//! See [`serve_with_plugin_dedup`].
//!
//! # What is checked, and what is not
//!
//! The crate name is untrusted and goes through
//! [`crate::ecosystem::cargo::index::validate_name`], the same boundary the
//! index path uses, so a name that would escape its context is a 400.
//!
//! The version is **not** validated the same way, deliberately. Cargo
//! versions are SemVer strings, and this proxy does not second-guess
//! upstream's version spelling. The version only has to match a version
//! the index lists. Any other version is a 404, and an unreachable index is
//! unverifiable. This is why no path segment of a version can reach a
//! filesystem path here: the download destination comes from the matched
//! index entry's own `name` and `vers` fields, never from the request.
//!
//! # Why `application/gzip`
//!
//! A `.crate` file is a gzipped tar. Cargo reads the bytes and unpacks them
//! itself; it does not branch on this header. `application/gzip` is the
//! honest description of the bytes for every other client (a browser, a
//! mirror, an operator with `curl`), so this handler sends it rather than
//! the `application/octet-stream` the PyPI path uses for wheels and sdists.
//! A caller must not depend on cargo rejecting an incorrect header.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, StatusCode};
use axum::response::Response;

use crate::audit::{AuditContext, AuditRecord};
use crate::db::verdict::VerdictStore;
use crate::ecosystem::cargo::index::{validate_name, CargoIndexEntry};
use crate::ecosystem::cargo::normalize_name;
use crate::ecosystem::cargo::upstream::UpstreamError;
use crate::model::{ArtifactKey, RefusalReason, Verdict};
use crate::plugin::{is_check_failure, unpack};
use crate::scan::cargo::CargoDownloadApproval;
use crate::scan::coordinator::{self, FinishGuard};
use crate::scan::is_allowlisted;

use super::cargo_index::{CargoAppState, CARGO_ECOSYSTEM};
use super::refusal::{refusal_response, unverifiable_response};
use super::{audit_or_500, bad_request_response, not_found_response, why_url};

/// The `Content-Type` sent for a `.crate` body. See the module docs.
const CRATE_CONTENT_TYPE: &str = "application/gzip";

/// The longest version string this handler accepts, in bytes. A SemVer
/// version with build metadata is far shorter than this. The cap exists so
/// an absurd path segment cannot reach a log line or an error message
/// unbounded.
const MAX_VERSION_LEN: usize = 128;

/// What one `.crate` download request actually did, carried up from
/// whichever gate decided it so [`cargo_download_handler`] writes exactly
/// one fetch audit record at the point the response is finalized — never
/// earlier.
///
/// This matters because an index-approved version
/// ([`CargoDownloadApproval::Approved`]) is not yet a *decided* download:
/// the plugin gate still has to run, and it can still refuse the
/// artifact. Writing a `served` record as soon as the index gate's
/// admission is matched, before the plugin gate has had its say, would
/// log a request as served that the very same request later refused —
/// exactly the kind of record this feature exists to never produce. So
/// every function between the index-approval match and the final
/// `Response` threads this type back up instead of writing audit records
/// itself, and [`cargo_download_handler`] is the only place that calls
/// [`audit_or_500`] for a download.
enum DownloadOutcome {
    /// Bytes were served for this artifact key.
    Served { key: ArtifactKey },
    /// A refusal response was built from a durable reason. `why_id` is
    /// `Some` only when storing the verdict that produced this refusal
    /// actually succeeded.
    Refused {
        key: ArtifactKey,
        reason: RefusalReason,
        why_id: Option<String>,
    },
    /// No definite verdict was reached (a 404, an upstream outage, a
    /// plugin that could not run, an internal I/O failure): there is
    /// nothing yet for an audit line to describe, exactly as
    /// `Decision::Unverifiable`/`Decision::InProgress` write nothing on
    /// the PyPI path.
    Silent,
}

impl DownloadOutcome {
    /// The records [`AuditLog::write`](crate::audit::AuditLog::write)
    /// needs for this outcome: zero or one.
    fn into_records(self, ctx: &AuditContext) -> Vec<AuditRecord> {
        match self {
            DownloadOutcome::Served { key } => vec![AuditRecord::served(
                ctx,
                &key.package,
                &key.version,
                &key.filename,
                &key.sha256,
            )],
            DownloadOutcome::Refused {
                key,
                reason,
                why_id,
            } => vec![AuditRecord::refused(
                ctx,
                &key.package,
                &key.version,
                Some(key.filename.as_str()),
                &reason,
                why_id.as_deref(),
            )],
            DownloadOutcome::Silent => Vec::new(),
        }
    }
}

/// Writes the fetch audit record `outcome` implies (if any) and returns
/// either `response` unchanged or the 500 [`audit_or_500`] substitutes
/// for it on a write failure.
fn finish_with_audit(
    state: &CargoAppState,
    ctx: &AuditContext,
    response: Response,
    outcome: DownloadOutcome,
) -> Response {
    let records = outcome.into_records(ctx);
    if records.is_empty() {
        return response;
    }
    match audit_or_500(&state.audit, &records) {
        Some(failure) => failure,
        None => response,
    }
}

/// `GET /crates/{crate}/{version}/download`: the `.crate` bytes, gated on
/// the organization's plugins, and only for a version the index gate
/// admitted or the operator allowlisted.
pub async fn cargo_download_handler(
    State(state): State<CargoAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((raw_name, raw_version)): Path<(String, String)>,
) -> Response {
    // Built from the real TCP peer, never a client-supplied header — see
    // `crate::http::artifact::artifact_handler`'s own doc comment for why.
    let ctx = AuditContext::new(CARGO_ECOSYSTEM, peer);

    let name = match validate_name(&raw_name) {
        Ok(name) => name,
        Err(err) => return bad_request_response(&format!("invalid crate name: {err}")),
    };

    // Documented in the module docs: the version is only checked for being
    // non-empty, short, and printable. It is never used as a path.
    if let Err(detail) = validate_version_segment(&raw_version) {
        return bad_request_response(&detail);
    }

    // The allowlist is consulted first, matching `Scanner::decide_inner`
    // on the PyPI path: an operator who allowlisted this crate and version
    // has overridden the judgement checks, and that override has to reach
    // the stored block and the index gate's own admission alike. It never
    // overrides the integrity check — the bytes still have to match the
    // index `cksum`, which `download_and_verify` enforces on every path
    // this branches to.
    //
    // This branch is the one place a request reaches the plugins without a
    // stored verdict, so it is also the one place that fetches the index
    // itself: `approved_for_download` fetches it on every other path.
    if is_allowlisted_crate(&state.config.current(), &name, &raw_version) {
        return match allowlisted_entry(&state, &name, &raw_version).await {
            Ok((key, entry)) => {
                let (response, outcome) = serve_gated(&state, &key, &entry, true).await;
                finish_with_audit(&state, &ctx, response, outcome)
            }
            Err(response) => response,
        };
    }

    match state
        .cargo_scanner
        .approved_for_download(&name, &raw_version)
        .await
    {
        CargoDownloadApproval::Approved { key, entry } => {
            let fingerprint = state.cargo_scanner.fingerprint();
            let run_plugins = !plugin_checked(&state.verdicts, &key, &fingerprint).await;
            let (response, outcome) = serve_gated(&state, &key, &entry, run_plugins).await;
            finish_with_audit(&state, &ctx, response, outcome)
        }
        CargoDownloadApproval::Refused {
            key,
            reason,
            why_id,
        } => {
            // A stored block carries its own `/why` id, fetched the same
            // way the PyPI path fetches it. Already a fully decided
            // outcome — no plugin gate left to run — so the audit record
            // is built right here rather than threaded any further.
            let link = why_id
                .clone()
                .and_then(|id| why_url(&state.config.current(), &id));
            let response = refusal_response(&reason, link.as_deref());
            finish_with_audit(
                &state,
                &ctx,
                response,
                DownloadOutcome::Refused {
                    key,
                    reason,
                    why_id,
                },
            )
        }
        // Per the fetch audit log's own "only evaluated versions get a
        // record" rule (see `crate::scan::cargo::CargoScanner::listing_audit`'s
        // doc comment): a version with no stored verdict was never
        // admitted by the index gate, so nothing was ever evaluated about
        // it. No audit record either.
        CargoDownloadApproval::NotApproved => {
            refusal_response(&not_index_approved_reason(&name, &raw_version), None)
        }
        CargoDownloadApproval::NotFound => not_found_response(),
        CargoDownloadApproval::Unverifiable(reason) => unverifiable_response(&RefusalReason {
            code: reason.code,
            detail: sanitize(&reason.detail),
        }),
    }
}

/// Looks up the index entry for an allowlisted `name`/`version` without
/// consulting any verdict, so an allowlisted version is served even when
/// the cascade never admitted it.
///
/// This is the allowlist override's own index read. The version still has
/// to exist upstream: the `cksum` in the returned entry is what the
/// downloaded bytes are verified against, and a version the index does not
/// list is a 404 exactly as it is on the approval path.
async fn allowlisted_entry(
    state: &CargoAppState,
    name: &str,
    version: &str,
) -> Result<(ArtifactKey, CargoIndexEntry), Response> {
    let entries = match state.upstream.index_entries(name).await {
        Ok(entries) => entries,
        Err(UpstreamError::NotFound) => return Err(not_found_response()),
        Err(err) => {
            return Err(unverifiable_response(&RefusalReason {
                code: "unverifiable:upstream".to_string(),
                detail: sanitize(&format!(
                    "could not read the cargo sparse index right now: {err:#}"
                )),
            }))
        }
    };

    let Some(entry) = entries.iter().find(|entry| entry.vers == version).cloned() else {
        return Err(not_found_response());
    };

    let key = crate::scan::cargo::artifact_key(&normalize_name(name), &entry);
    Ok((key, entry))
}

/// The refusal for a version the sparse-index cascade never admitted: no
/// stored verdict, so no CVE filter, no release-age check, and no review
/// ever saw it.
fn not_index_approved_reason(name: &str, version: &str) -> RefusalReason {
    RefusalReason {
        code: "not-index-approved".to_string(),
        detail: sanitize(&format!(
            "{name} {version} was never admitted by the sparse-index gate, so it has not \
             been CVE-filtered, age-checked, or reviewed; this proxy does not download it"
        )),
    }
}

/// Serves the verified bytes for `key`, running the plugins first when
/// `run_plugins` is set.
///
/// `run_plugins` is false only on the fast path: a stored `Clean` verdict
/// already marked plugin-checked. The bytes are then served from the cache
/// when it still has them, and re-downloaded and re-verified against the
/// index `cksum` when it does not.
async fn serve_gated(
    state: &CargoAppState,
    key: &ArtifactKey,
    entry: &CargoIndexEntry,
    run_plugins: bool,
) -> (Response, DownloadOutcome) {
    if !run_plugins {
        return serve_verified_bytes(state, key, entry).await;
    }
    serve_with_plugin_dedup(state, key, entry).await
}

/// Serves already-admitted bytes for `key`: a cache hit read straight
/// back, or a fresh download re-verified against the index `cksum` when
/// the cache entry is gone. Used both by the plugin-checked fast path and
/// by a caller that just learned, via [`serve_with_plugin_dedup`]'s
/// coordinator, that another request's plugin run already passed.
async fn serve_verified_bytes(
    state: &CargoAppState,
    key: &ArtifactKey,
    entry: &CargoIndexEntry,
) -> (Response, DownloadOutcome) {
    match cache_get(state, key).await {
        Ok(Some(path)) => match tokio::fs::read(&path).await {
            Ok(bytes) => (
                crate_response(bytes),
                DownloadOutcome::Served { key: key.clone() },
            ),
            Err(err) => (
                unverifiable_response(&internal_reason(&format!(
                    "reading the cached artifact: {err}"
                ))),
                DownloadOutcome::Silent,
            ),
        },
        Ok(None) => {
            // The cache entry is gone. Re-download and re-verify, but no
            // plugin needs to see bytes an earlier run already admitted
            // for this exact hash.
            let temp = match tempfile::tempdir() {
                Ok(dir) => dir,
                Err(err) => {
                    return (
                        unverifiable_response(&internal_reason(&format!(
                            "creating a temporary download directory: {err}"
                        ))),
                        DownloadOutcome::Silent,
                    )
                }
            };
            let dest = temp.path().join(&key.filename);
            match download_and_verify(state, entry, key, &dest).await {
                Ok(local) => serve_cached(state, key, &local).await,
                Err(response) => (response, DownloadOutcome::Silent),
            }
        }
        Err(err) => (
            unverifiable_response(&internal_reason(&format!(
                "reading the artifact cache: {err:#}"
            ))),
            DownloadOutcome::Silent,
        ),
    }
}

/// Runs the full plugin gate for `key`/`entry` for exactly one caller at a
/// time, deduplicated by `key.sha256` through
/// [`CargoAppState::plugin_run_coordinator`].
///
/// Without this, two concurrent first-touch requests for the same
/// never-plugin-checked artifact (two `cargo build`s in a CI matrix, two
/// developers) would each independently download, unpack, and run every
/// configured plugin — the same N-times cost
/// [`crate::scan::coordinator`]'s own docs describe for the analogous PyPI
/// case, which this gate had been missing. The owner runs
/// [`run_plugin_gate`] and broadcasts its verdict, if one was durably
/// stored, to every joiner; a joiner that learns the outcome was `Clean`
/// still calls [`serve_verified_bytes`] itself rather than reusing the
/// owner's response directly, since the owner's bytes were read into a
/// response the joiner never held — this re-verification is cheap (a
/// cache hit) and mirrors how the PyPI path's own joined-verdict handling
/// (`Scanner::decision_from_joined_verdict`) always re-fetches rather than
/// shares a `Response` across callers.
async fn serve_with_plugin_dedup(
    state: &CargoAppState,
    key: &ArtifactKey,
    entry: &CargoIndexEntry,
) -> (Response, DownloadOutcome) {
    match state.plugin_run_coordinator.start_or_join(&key.sha256) {
        Ok(tx) => {
            // Constructed first, exactly as `Scanner::scan_with_budget`'s
            // owner does: its `Drop` must run after the gate finishes and
            // its outcome is sent, on every exit path including a future
            // one added by a change to `run_plugin_gate`, so a panic
            // there can never leave this sha256 permanently stuck for
            // every later request.
            let _finish_guard = FinishGuard::new(
                Arc::clone(&state.plugin_run_coordinator),
                key.sha256.clone(),
            );
            let (response, verdict, outcome) = run_plugin_gate(state, key, entry).await;
            let _ = tx.send(verdict);
            (response, outcome)
        }
        Err(rx) => match coordinator::wait_for_verdict(rx).await {
            Some(Verdict::Clean) => serve_verified_bytes(state, key, entry).await,
            Some(Verdict::Blocked(reason)) => {
                let fingerprint = state.cargo_scanner.fingerprint();
                let why_id = stored_why_id(&state.verdicts, key, &fingerprint).await;
                let link = why_id
                    .clone()
                    .and_then(|id| why_url(&state.config.current(), &id));
                (
                    refusal_response(&reason, link.as_deref()),
                    DownloadOutcome::Refused {
                        key: key.clone(),
                        reason,
                        why_id,
                    },
                )
            }
            None => (
                unverifiable_response(&scan_incomplete_reason()),
                DownloadOutcome::Silent,
            ),
        },
    }
}

/// Downloads, verifies, unpacks, and runs every configured plugin over
/// `key`/`entry` once. Returns the response to send to the caller that
/// owns this run, alongside the verdict to broadcast to any joiners —
/// `Some` only when that verdict was actually stored durably (mirroring
/// `crate::scan::verdict_for_dedup`'s own rule: a joiner must only ever
/// reuse a verdict this run actually persisted, never one a storage
/// failure or a check failure left unrecorded).
async fn run_plugin_gate(
    state: &CargoAppState,
    key: &ArtifactKey,
    entry: &CargoIndexEntry,
) -> (Response, Option<Verdict>, DownloadOutcome) {
    let fingerprint = state.cargo_scanner.fingerprint();

    let temp = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(err) => {
            return (
                unverifiable_response(&internal_reason(&format!(
                    "creating a temporary download directory: {err}"
                ))),
                None,
                DownloadOutcome::Silent,
            )
        }
    };
    let dest = temp.path().join(&key.filename);
    let local = match download_and_verify(state, entry, key, &dest).await {
        Ok(local) => local,
        Err(response) => return (response, None, DownloadOutcome::Silent),
    };

    let unpacked = temp.path().join("unpacked");
    let unpack_source = local.clone();
    let unpack_dest = unpacked.clone();
    match tokio::task::spawn_blocking(move || unpack(&unpack_source, &unpack_dest)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            return (
                unverifiable_response(&internal_reason(&format!(
                    "unpacking the downloaded .crate: {err:#}"
                ))),
                None,
                DownloadOutcome::Silent,
            )
        }
        Err(join_error) => {
            return (
                unverifiable_response(&internal_reason(&format!(
                    "the unpack task did not complete: {join_error}"
                ))),
                None,
                DownloadOutcome::Silent,
            )
        }
    }

    let plugins = state.config.current().plugins.clone();
    match state.plugins.run_all(&plugins, key, &unpacked).await {
        None => {
            // Every plugin ran and passed: store the clean verdict, mark
            // it plugin-checked, then cache and serve the bytes.
            if let Err(err) = store_verdict(state, key, &Verdict::Clean, &fingerprint).await {
                // A verdict that cannot be stored is not a verdict. Serve
                // nothing rather than bytes whose record does not exist,
                // and broadcast nothing: a joiner must re-attempt rather
                // than believe a clean outcome that was never recorded.
                return (
                    unverifiable_response(&internal_reason(&format!(
                        "storing the clean verdict: {err:#}"
                    ))),
                    None,
                    DownloadOutcome::Silent,
                );
            }
            if let Err(err) = mark_plugin_checked(state, key, &fingerprint).await {
                return (
                    unverifiable_response(&internal_reason(&format!(
                        "marking the verdict plugin-checked: {err:#}"
                    ))),
                    None,
                    DownloadOutcome::Silent,
                );
            }
            let (response, outcome) = serve_cached(state, key, &local).await;
            (response, Some(Verdict::Clean), outcome)
        }
        Some(reason) => {
            if is_check_failure(&reason) {
                // The plugin never reached a verdict. Nothing is stored,
                // so a retry — including a joiner that was waiting on
                // this very run — attempts the plugins again rather than
                // being handed a durable block about an artifact nothing
                // examined.
                tracing::warn!(
                    package = %key.package,
                    version = %key.version,
                    code = %reason.code,
                    "a cargo plugin could not run; answering unverifiable and storing nothing"
                );
                return (
                    unverifiable_response(&reason),
                    None,
                    DownloadOutcome::Silent,
                );
            }
            let stored =
                store_verdict(state, key, &Verdict::Blocked(reason.clone()), &fingerprint).await;
            let (why_id, broadcast) = match stored {
                Ok(why_id) => (Some(why_id), Some(Verdict::Blocked(reason.clone()))),
                Err(err) => {
                    tracing::warn!(
                        package = %key.package,
                        version = %key.version,
                        error = %format!("{err:#}"),
                        "a cargo plugin block could not be stored; refusing without a /why link"
                    );
                    (None, None)
                }
            };
            let link = why_id
                .clone()
                .and_then(|id| why_url(&state.config.current(), &id));
            tracing::warn!(
                package = %key.package,
                version = %key.version,
                code = %reason.code,
                "a cargo plugin blocked this artifact"
            );
            (
                refusal_response(&reason, link.as_deref()),
                broadcast,
                DownloadOutcome::Refused {
                    key: key.clone(),
                    reason,
                    why_id,
                },
            )
        }
    }
}

/// The refusal used when a joiner learns the owning plugin run ended
/// without ever producing a verdict (a download failure, an unpack
/// failure, a plugin check failure, a storage failure) — mirrors
/// `crate::scan`'s own `scan_incomplete_reason`.
fn scan_incomplete_reason() -> RefusalReason {
    RefusalReason {
        code: "unverifiable:scan-incomplete".to_string(),
        detail: "the plugin run for this artifact did not complete".to_string(),
    }
}

/// Whether the operator has allowlisted `name` at `version`.
///
/// Reuses [`is_allowlisted`], the crate's single implementation of the
/// allowlist comparison, for both spellings a crate name can arrive in:
/// the published one (`num_cpus`) and the normalized one (`num-cpus`).
/// An operator's config entry matches whichever they wrote.
fn is_allowlisted_crate(config: &crate::config::Config, name: &str, version: &str) -> bool {
    is_allowlisted(config, name, version) || is_allowlisted(config, &normalize_name(name), version)
}

/// Downloads the `.crate` to `dest` and checks its SHA-256 against the
/// index `cksum`.
///
/// `Ok(path)` is a verified file at `path`. `Err(response)` is the refusal
/// to send instead: unverifiable for an upstream failure, 403 for bytes
/// that do not match the checksum (mirroring
/// [`crate::http::artifact`]'s handling of the same condition).
async fn download_and_verify(
    state: &CargoAppState,
    entry: &CargoIndexEntry,
    key: &ArtifactKey,
    dest: &std::path::Path,
) -> Result<std::path::PathBuf, Response> {
    let actual = match state
        .upstream
        .download_crate(&entry.name, &entry.vers, dest)
        .await
    {
        Ok(hash) => hash.to_lowercase(),
        Err(UpstreamError::NotFound) => return Err(not_found_response()),
        Err(err) => {
            return Err(unverifiable_response(&RefusalReason {
                code: "unverifiable:upstream".to_string(),
                detail: sanitize(&format!(
                    "could not download this artifact right now: {err:#}"
                )),
            }))
        }
    };

    if actual != key.sha256 {
        tracing::warn!(
            package = %key.package,
            version = %key.version,
            expected = %key.sha256,
            actual = %actual,
            "the downloaded .crate did not match the index checksum; refusing it"
        );
        return Err(refusal_response(
            &RefusalReason {
                code: "hash-mismatch".to_string(),
                detail: sanitize(&format!(
                    "downloaded artifact sha256 {actual} does not match the \
                     index-declared sha256 {}",
                    key.sha256
                )),
            },
            None,
        ));
    }

    Ok(dest.to_path_buf())
}

/// Inserts the verified file at `local` into the artifact cache and serves
/// it from there.
///
/// A cache insert that fails still serves the verified bytes: the cache is
/// a performance feature, and this file was hash-verified a moment ago.
/// The response is built from the bytes read back out of the cache so the
/// `Content-Length` always describes what is sent.
async fn serve_cached(
    state: &CargoAppState,
    key: &ArtifactKey,
    local: &std::path::Path,
) -> (Response, DownloadOutcome) {
    let cache = Arc::clone(&state.artifact_cache);
    let key_owned = key.clone();
    let file = local.to_path_buf();
    let cached = tokio::task::spawn_blocking(move || cache.insert(&key_owned, &file)).await;

    let path = match cached {
        Ok(Ok(path)) => path,
        Ok(Err(err)) => {
            tracing::warn!(
                package = %key.package,
                version = %key.version,
                error = %format!("{err:#}"),
                "the verified .crate could not be inserted into the artifact cache; \
                 serving it anyway"
            );
            local.to_path_buf()
        }
        Err(join_error) => {
            tracing::warn!(
                package = %key.package,
                version = %key.version,
                error = %join_error,
                "the cache insert task did not complete; serving the verified bytes anyway"
            );
            local.to_path_buf()
        }
    };

    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            crate_response(bytes),
            DownloadOutcome::Served { key: key.clone() },
        ),
        Err(err) => (
            unverifiable_response(&internal_reason(&format!(
                "reading the verified artifact: {err}"
            ))),
            DownloadOutcome::Silent,
        ),
    }
}

/// Builds the 200 response for a `.crate` body: the bytes, the crate
/// media type, and a `Content-Length` that matches them.
fn crate_response(bytes: Vec<u8>) -> Response {
    let len = bytes.len();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, CRATE_CONTENT_TYPE)
        .header(header::CONTENT_LENGTH, len)
        .body(Body::from(Bytes::from(bytes)))
        .unwrap_or_else(|_| {
            unverifiable_response(&internal_reason("building the download response"))
        })
}

/// Rejects a version segment that is empty, too long, or contains a byte
/// outside printable ASCII. See the module docs for what this does not
/// check.
fn validate_version_segment(version: &str) -> Result<(), String> {
    if version.is_empty() {
        return Err("invalid crate version: the version is empty".to_string());
    }
    if version.len() > MAX_VERSION_LEN {
        return Err(format!(
            "invalid crate version: the version is longer than {MAX_VERSION_LEN} bytes"
        ));
    }
    if version
        .chars()
        .any(|c| !c.is_ascii() || c.is_ascii_control())
    {
        return Err("invalid crate version: the version contains a non-printable byte".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Blocking-store access, each on the blocking pool
// ---------------------------------------------------------------------------

async fn stored_why_id(
    store: &Arc<VerdictStore>,
    key: &ArtifactKey,
    fingerprint: &str,
) -> Option<String> {
    let store = Arc::clone(store);
    let key = key.clone();
    let fingerprint = fingerprint.to_string();
    match tokio::task::spawn_blocking(move || store.get(&key, &fingerprint)).await {
        Ok(Ok(Some(stored))) => Some(stored.why_id),
        _ => None,
    }
}

async fn plugin_checked(store: &Arc<VerdictStore>, key: &ArtifactKey, fingerprint: &str) -> bool {
    let store = Arc::clone(store);
    let key = key.clone();
    let package = key.package.clone();
    let version = key.version.clone();
    let fingerprint = fingerprint.to_string();
    match tokio::task::spawn_blocking(move || store.is_plugin_checked(&key, &fingerprint)).await {
        Ok(Ok(checked)) => checked,
        Ok(Err(err)) => {
            tracing::warn!(
                package = %package,
                version = %version,
                error = %format!("{err:#}"),
                "the plugin-checked flag could not be read; running the plugins again"
            );
            false
        }
        Err(join_error) => {
            tracing::warn!(
                package = %package,
                version = %version,
                error = %join_error,
                "the plugin-checked lookup task panicked; running the plugins again"
            );
            false
        }
    }
}

async fn store_verdict(
    state: &CargoAppState,
    key: &ArtifactKey,
    verdict: &Verdict,
    fingerprint: &str,
) -> anyhow::Result<String> {
    let store = Arc::clone(&state.verdicts);
    let key = key.clone();
    let verdict = verdict.clone();
    let fingerprint = fingerprint.to_string();
    tokio::task::spawn_blocking(move || store.put(&key, &verdict, &fingerprint))
        .await
        .map_err(|join_error| anyhow::anyhow!("the verdict store task panicked: {join_error}"))?
}

async fn mark_plugin_checked(
    state: &CargoAppState,
    key: &ArtifactKey,
    fingerprint: &str,
) -> anyhow::Result<()> {
    let store = Arc::clone(&state.verdicts);
    let key = key.clone();
    let fingerprint = fingerprint.to_string();
    tokio::task::spawn_blocking(move || store.mark_plugin_checked(&key, &fingerprint))
        .await
        .map_err(|join_error| {
            anyhow::anyhow!("the plugin-checked mark task panicked: {join_error}")
        })?
}

async fn cache_get(
    state: &CargoAppState,
    key: &ArtifactKey,
) -> anyhow::Result<Option<std::path::PathBuf>> {
    let cache = Arc::clone(&state.artifact_cache);
    let key = key.clone();
    tokio::task::spawn_blocking(move || cache.get(&key))
        .await
        .map_err(|join_error| anyhow::anyhow!("the cache lookup task panicked: {join_error}"))?
}

fn internal_reason(context: &str) -> RefusalReason {
    RefusalReason {
        code: "unverifiable:internal".to_string(),
        detail: sanitize(context),
    }
}

/// Strips ASCII control characters (including CR/LF) and non-ASCII bytes
/// before this text can reach an HTTP reason phrase, mirroring the same
/// discipline [`crate::http::artifact`] applies.
fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .take(200)
        .collect()
}

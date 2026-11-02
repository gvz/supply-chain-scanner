//! `GET /{name}/-/{file}`: the npm tarball download, gated on metadata
//! approval and then the organization's plugins.
//!
//! This is the npm deployment's second gate, and the counterpart to
//! [`super::cargo_download`]. The packument handler
//! ([`super::npm_packument`]) already refused every version the CVE line,
//! the release-age threshold or the AI review rejected, before npm
//! resolved anything. This module answers the one question the packument
//! never could: was this exact version admitted by that gate, and does the
//! artifact pass the organization's own plugin binaries?
//!
//! # Route shape: dispatched, not registered
//!
//! The plan called for a route of its own, `/{*name}/-/{file}`. That is
//! not expressible with this proxy's router: `matchit`, which axum 0.8
//! uses, rejects a catch-all that is not the final path segment, with
//! "Catch-all parameters are only allowed at the end of a route". The
//! narrower form `/{name}/-/{file}` is rejected too, because it conflicts
//! with the packument route (`/{*path}`) that already exists.
//!
//! So the tarball route is *dispatched* from the one catch-all instead.
//! [`looks_like_tarball`] recognizes a tarball path, and
//! [`super::npm_packument::npm_packument_handler`] hands it here before
//! treating the path as a package name. The externally visible behaviour
//! is the same: a scoped package's literal slash
//! (`/@babel/core/-/core-7.0.0.tgz`) reaches this handler, and the
//! packument route keeps serving everything else.
//!
//! # The metadata approval comes first, and never runs inline
//!
//! Order is the whole point of this module. [`NpmScanner::approved_for_download`]
//! is asked before any byte is fetched. Only its `Approved` answer
//! proceeds; `NotApproved` means the packument gate never stored a pass
//! for this version, and that is a refusal here, not an invitation to
//! review inline. A version the packument gate never admitted was never
//! CVE-filtered, never age-checked and never reviewed, so serving it on a
//! plugin pass would substitute one check for the other three. This is
//! the same hole [`super::cargo_download`] closed on the cargo path.
//!
//! # The allowlist is consulted first of all, and still requires a digest
//!
//! Mirroring [`super::cargo_download`] exactly: an allowlist entry is
//! checked before [`NpmScanner::approved_for_download`] is ever called,
//! because the packument gate stores a verdict only for a version it
//! reviewed, and the allowlist exists precisely to admit a version that
//! gate never saw. Without this branch an allowlisted version can be
//! *advertised* (the packument cascade treats an allowlisted survivor as
//! forwardable) but never *downloaded* — `approved_for_download` would
//! answer `NotApproved` for it forever, since no review ever ran to store
//! a `Clean` verdict. The allowlist overrides the verdict, never the
//! integrity check: this branch still fetches the version's `dist` fresh
//! from upstream and still runs it through [`download_and_verify`], the
//! same digest check every other path goes through.
//!
//! # The stored verdict is the cache, exactly as on the other paths
//!
//! - **Approved and already plugin-checked** — serve the bytes from the
//!   artifact cache, re-downloading and re-verifying only when the cache
//!   entry is gone. No plugin runs a second time.
//! - **Approved but not plugin-checked** — download, verify against the
//!   declared digest, unpack, run every configured plugin, store the
//!   outcome, then cache and serve.
//! - **Refused** — a stored block, answered with its `/why/<id>` link.
//!
//! A first-touch download is deduplicated by
//! [`NpmAppState::plugin_run_coordinator`], keyed by the artifact digest,
//! so two concurrent requests for the same artifact share one
//! download-unpack-plugin run. See [`serve_with_plugin_dedup`].
//!
//! # The filename is never a path
//!
//! The version comes from the tarball filename, which must be exactly
//! `{unscoped}-{version}.tgz` for the requested package. Anything else is
//! a 400 rather than a guess. The filename is compared as text and is
//! never used as a filesystem path: the download destination is built
//! from the artifact key, which comes from the packument's own fields.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::http::{header, StatusCode};
use axum::response::Response;

use crate::audit::{AuditContext, AuditRecord};
use crate::db::verdict::VerdictStore;
use crate::ecosystem::npm::packument::{declared_digest, Dist};
use crate::ecosystem::npm::upstream::UpstreamError;
use crate::ecosystem::npm::{normalize_name, validate_name};
use crate::model::{ArtifactKey, RefusalReason, Verdict};
use crate::plugin::{is_check_failure, unpack};
use crate::scan::coordinator::{self, FinishGuard};
use crate::scan::is_allowlisted;
use crate::scan::npm::{artifact_key, DownloadApproval};

use super::npm_packument::NpmAppState;
use super::refusal::{refusal_response, unverifiable_response};
use super::{audit_or_500, bad_request_response, not_found_response, why_url};

/// The `Content-Type` sent for a `.tgz` body. npm does not branch on it;
/// this is the honest description of the bytes for every other client.
const TARBALL_CONTENT_TYPE: &str = "application/octet-stream";

/// The longest version string this handler accepts, in bytes. An npm
/// SemVer version is far shorter than this. The cap exists so an absurd
/// path segment cannot reach a log line unbounded.
const MAX_VERSION_LEN: usize = 128;

/// Whether `path` is a tarball request rather than a packument one.
///
/// A packument path never carries the `/-/` infix and never ends in
/// `.tgz`, so requiring both is unambiguous. See this module's docs for
/// why the two live on one catch-all route.
pub fn looks_like_tarball(path: &str) -> bool {
    path.ends_with(".tgz") && path.contains("/-/")
}

/// One approved artifact, bundled so the serving helpers below keep short
/// argument lists.
struct Target<'a> {
    key: &'a ArtifactKey,
    name: &'a str,
    version: &'a str,
    dist: &'a Dist,
}

/// What one tarball download request actually did, carried up from
/// whichever gate decided it so [`npm_download_handler`] writes exactly
/// one fetch audit record at the point the response is finalized — never
/// earlier.
///
/// Mirrors [`crate::http::cargo_download`]'s own `DownloadOutcome`
/// exactly, for the same reason: a packument-approved version
/// ([`DownloadApproval::Approved`]) is not yet a *decided* download —
/// the plugin gate still has to run, and it can still refuse the
/// artifact. Writing a `served` record as soon as the packument gate's
/// admission is matched, before the plugin gate has had its say, would
/// log a request as served that the very same request later refused.
/// So every function between the approval match and the final `Response`
/// threads this type back up instead of writing audit records itself,
/// and [`npm_download_handler`] is the only place that calls
/// [`audit_or_500`] for a download.
enum DownloadOutcome {
    /// Bytes were served for this artifact key.
    Served { key: ArtifactKey },
    /// A refusal response was built from a reason. `filename` is the
    /// requested tarball's own filename: unlike the cargo `.crate` route
    /// (whose path carries only a version, so a never-admitted version
    /// has no filename to name until an index entry is matched), npm's
    /// tarball path *is* a filename, already validated by
    /// [`version_from_filename`] against the requested package before
    /// this point — so it is always known here, whether or not the
    /// packument gate ever admitted this version. `why_id` is `Some`
    /// only when a durable verdict backs this refusal and storing it
    /// actually succeeded.
    Refused {
        package: String,
        version: String,
        filename: Option<String>,
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
                package,
                version,
                filename,
                reason,
                why_id,
            } => vec![AuditRecord::refused(
                ctx,
                &package,
                &version,
                filename.as_deref(),
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
async fn finish_with_audit(
    state: &NpmAppState,
    ctx: &AuditContext,
    response: Response,
    outcome: DownloadOutcome,
) -> Response {
    let records = outcome.into_records(ctx);
    if records.is_empty() {
        return response;
    }
    match audit_or_500(&state.audit, &records).await {
        Some(failure) => failure,
        None => response,
    }
}

/// The tarball handler. `path` is the whole catch-all path, already
/// percent-decoded by axum. `ctx` is the one [`AuditContext`] the caller
/// built from the real `ConnectInfo` peer address — this handler is not a
/// route (see the module docs), so it cannot extract its own.
pub async fn npm_download_handler(state: &NpmAppState, ctx: &AuditContext, path: &str) -> Response {
    let Some((raw_name, file)) = split_tarball_path(path) else {
        return bad_request_response("invalid npm tarball path");
    };

    let name = match validate_name(raw_name) {
        Ok(name) => name,
        Err(err) => return bad_request_response(&format!("invalid npm package name: {err}")),
    };

    let version = match version_from_filename(&name, file) {
        Ok(version) => version,
        Err(detail) => return bad_request_response(&detail),
    };

    // The allowlist is consulted first, matching `cargo_download_handler`'s
    // own rule: an operator's explicit decision overrides the packument
    // gate's admission entirely, because that gate's stored verdict is the
    // only thing `approved_for_download` can ever answer `Approved` from,
    // and an allowlisted version may never have been reviewed at all. It
    // never overrides the integrity check — `download_and_verify` still
    // checks the downloaded bytes against the digest this lookup fetches
    // fresh from upstream, below.
    if is_allowlisted_npm(&state.config.current(), &name, &version) {
        return match allowlisted_target(state, &name, &version).await {
            Ok((key, dist)) => {
                let fingerprint = state.npm_scanner.fingerprint();
                let target = Target {
                    key: &key,
                    name: &name,
                    version: &version,
                    dist: &dist,
                };
                // Always runs the plugin gate, exactly as
                // `cargo_download_handler`'s own allowlist branch does:
                // this is the one place a request reaches the plugins
                // without `approved_for_download` ever answering
                // `Approved`, so it is also the one place that fetches the
                // packument itself.
                let (response, outcome) =
                    serve_with_plugin_dedup(state, &target, &fingerprint).await;
                finish_with_audit(state, ctx, response, outcome).await
            }
            Err(response) => response,
        };
    }

    // Documented above: the metadata approval is asked first, and nothing
    // is fetched from upstream until it answers `Approved`.
    match state
        .npm_scanner
        .approved_for_download(&name, &version)
        .await
    {
        DownloadApproval::Approved { key, dist } => {
            let fingerprint = state.npm_scanner.fingerprint();
            let target = Target {
                key: &key,
                name: &name,
                version: &version,
                dist: &dist,
            };
            let (response, outcome) = if plugin_checked(&state.verdicts, &key, &fingerprint).await {
                serve_verified_bytes(state, &target).await
            } else {
                serve_with_plugin_dedup(state, &target, &fingerprint).await
            };
            finish_with_audit(state, ctx, response, outcome).await
        }
        DownloadApproval::Refused(reason, why_id) => {
            let link = why_id
                .clone()
                .and_then(|id| why_url(&state.config.current(), &id));
            let response = refusal_response(&reason, link.as_deref());
            finish_with_audit(
                state,
                ctx,
                response,
                DownloadOutcome::Refused {
                    package: name,
                    version,
                    filename: Some(file.to_string()),
                    reason,
                    why_id,
                },
            )
            .await
        }
        // The packument gate never admitted this version. Refuse without
        // fetching anything, and never review inline. A refusal response
        // still reaches the client here, and the design spec defines
        // `refused` as exactly that ("a download that got a refusal
        // response"), so this still writes one.
        DownloadApproval::NotApproved => {
            let reason = not_packument_approved_reason(&name, &version);
            let response = refusal_response(&reason, None);
            finish_with_audit(
                state,
                ctx,
                response,
                DownloadOutcome::Refused {
                    package: name,
                    version,
                    filename: Some(file.to_string()),
                    reason,
                    why_id: None,
                },
            )
            .await
        }
        DownloadApproval::NotFound => not_found_response(),
        DownloadApproval::Unverifiable(reason) => unverifiable_response(&reason),
    }
}

/// Splits `{name}/-/{file}` at its last `/-/`.
///
/// A scoped name keeps its literal slash in `name`, so
/// `@babel/core/-/core-7.0.0.tgz` yields `("@babel/core", "core-7.0.0.tgz")`.
fn split_tarball_path(path: &str) -> Option<(&str, &str)> {
    let (name, file) = path.rsplit_once("/-/")?;
    if name.is_empty() || file.is_empty() {
        return None;
    }
    Some((name, file))
}

/// Derives the version from a tarball filename.
///
/// The filename must be exactly `{unscoped}-{version}.tgz`, where
/// `unscoped` drops any `@scope/` prefix, matching
/// [`crate::ecosystem::npm::tarball_path`]. Anything else is an error
/// rather than a guess, because a mismatch means the caller asked for
/// bytes this package does not name.
fn version_from_filename(name: &str, file: &str) -> Result<String, String> {
    let unscoped = name.rsplit('/').next().unwrap_or(name);
    let prefix = format!("{unscoped}-");
    let version = file
        .strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix(".tgz"))
        .ok_or_else(|| {
            format!("invalid npm tarball filename: expected {unscoped}-<version>.tgz")
        })?;

    if version.is_empty() {
        return Err("invalid npm tarball filename: the version is empty".to_string());
    }
    // A version is never a path. Reject path syntax explicitly rather than
    // rely on the fact that it is only ever compared as text: a request
    // that names traversal never reaches upstream, and never reads as a
    // 404 for a package that simply does not exist.
    if version.contains('/') || version.contains('\\') || version.contains("..") {
        return Err(
            "invalid npm tarball filename: the version contains a path separator or traversal"
                .to_string(),
        );
    }
    if version.len() > MAX_VERSION_LEN {
        return Err(format!(
            "invalid npm tarball filename: the version is longer than {MAX_VERSION_LEN} bytes"
        ));
    }
    if version
        .chars()
        .any(|c| !c.is_ascii() || c.is_ascii_control())
    {
        return Err(
            "invalid npm tarball filename: the version contains a non-printable byte".to_string(),
        );
    }

    Ok(version.to_string())
}

/// Whether the operator has allowlisted `name` at `version`.
///
/// Reuses [`is_allowlisted`], the crate's single implementation of the
/// allowlist comparison, for both spellings a package name can arrive in:
/// the registry's own spelling (scope and slash included) and its
/// npm-lowercased form. Mirrors `cargo_download::is_allowlisted_crate`.
fn is_allowlisted_npm(config: &crate::config::Config, name: &str, version: &str) -> bool {
    is_allowlisted(config, name, version) || is_allowlisted(config, &normalize_name(name), version)
}

/// Looks up `name`'s packument upstream for an allowlisted `version`,
/// without consulting any stored verdict, so an allowlisted version is
/// served even when the packument gate never admitted it (never reviewed
/// it at all, in fact — the allowlist is what lets this proxy serve a
/// version the cascade never saw).
///
/// This is the allowlist override's own packument read, mirroring
/// `cargo_download::allowlisted_entry`. The version still has to exist
/// upstream: the digest in the returned [`Dist`] is what the downloaded
/// bytes are verified against in [`download_and_verify`], so a version
/// upstream does not list is a 404 exactly as it is on the approval path,
/// and a `dist` with no digest this proxy can verify is `Unverifiable`
/// exactly as it is there too.
async fn allowlisted_target(
    state: &NpmAppState,
    name: &str,
    version: &str,
) -> Result<(ArtifactKey, Dist), Response> {
    let packument = match state.upstream.packument(name).await {
        Ok(packument) => packument,
        Err(UpstreamError::NotFound) => return Err(not_found_response()),
        Err(err) => {
            return Err(unverifiable_response(&RefusalReason {
                code: "unverifiable:upstream".to_string(),
                detail: sanitize(&format!(
                    "could not read the npm packument right now: {err:#}"
                )),
            }))
        }
    };

    let Some(entry) = packument.versions.get(version).cloned() else {
        return Err(not_found_response());
    };

    let Some(digest) = declared_digest(&entry.dist) else {
        return Err(unverifiable_response(&RefusalReason {
            code: "unverifiable:npm-digest".to_string(),
            detail: sanitize(&format!(
                "{name} {version} has no verifiable digest declared upstream"
            )),
        }));
    };

    let normalized = normalize_name(name);
    let key = artifact_key(&normalized, &packument.name, version, &digest);
    Ok((key, entry.dist))
}

/// The refusal for a version the packument gate never admitted.
fn not_packument_approved_reason(name: &str, version: &str) -> RefusalReason {
    RefusalReason {
        code: "not-packument-approved".to_string(),
        detail: sanitize(&format!(
            "{name} {version} was not admitted by the packument gate, so it was never \
             CVE-filtered, age-checked or reviewed; refusing it rather than serving bytes \
             whose checks never ran"
        )),
    }
}

/// Serves already-admitted bytes for `target`: a cache hit read straight
/// back, or a fresh download re-verified against the declared digest when
/// the cache entry is gone. Used by the plugin-checked fast path and by a
/// joiner that learned another request's plugin run already passed.
async fn serve_verified_bytes(
    state: &NpmAppState,
    target: &Target<'_>,
) -> (Response, DownloadOutcome) {
    match cache_get(state, target.key).await {
        Ok(Some(path)) => match tokio::fs::read(&path).await {
            Ok(bytes) => (
                tarball_response(bytes),
                DownloadOutcome::Served {
                    key: target.key.clone(),
                },
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
            // for this exact digest.
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
            let dest = temp.path().join(&target.key.filename);
            match download_and_verify(state, target, &dest).await {
                Ok(local) => serve_cached(state, &local, target).await,
                Err((response, outcome)) => (response, outcome),
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

/// Runs the full plugin gate for `target` for exactly one caller at a
/// time, deduplicated by the artifact digest through
/// [`NpmAppState::plugin_run_coordinator`].
///
/// Mirrors [`super::cargo_download`]'s own function: the owner runs
/// [`run_plugin_gate`] and broadcasts its verdict, if one was durably
/// stored, to every joiner. A joiner that learns the outcome was `Clean`
/// re-verifies and serves the bytes itself rather than sharing the
/// owner's `Response`.
async fn serve_with_plugin_dedup(
    state: &NpmAppState,
    target: &Target<'_>,
    fingerprint: &str,
) -> (Response, DownloadOutcome) {
    match state
        .plugin_run_coordinator
        .start_or_join(&target.key.sha256)
    {
        Ok(tx) => {
            // Constructed first, exactly as the cargo path does: its
            // `Drop` must run after the gate finishes and its outcome is
            // sent, on every exit path, so a panic in the gate can never
            // leave this digest permanently stuck for later requests.
            let _finish_guard = FinishGuard::new(
                Arc::clone(&state.plugin_run_coordinator),
                target.key.sha256.clone(),
            );
            let (response, verdict, outcome) = run_plugin_gate(state, target, fingerprint).await;
            let _ = tx.send(verdict);
            (response, outcome)
        }
        Err(rx) => match coordinator::wait_for_verdict(rx).await {
            Some(Verdict::Clean) => serve_verified_bytes(state, target).await,
            Some(Verdict::Blocked(reason)) => {
                let why_id = stored_why_id(&state.verdicts, target.key, fingerprint).await;
                let link = why_id
                    .clone()
                    .and_then(|id| why_url(&state.config.current(), &id));
                (
                    refusal_response(&reason, link.as_deref()),
                    DownloadOutcome::Refused {
                        package: target.key.package.clone(),
                        version: target.key.version.clone(),
                        filename: Some(target.key.filename.clone()),
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

/// Downloads, verifies, unpacks and runs every configured plugin over
/// `target` once. Returns the owner's response plus the verdict to
/// broadcast, which is `Some` only when that verdict was stored durably,
/// plus the [`DownloadOutcome`] the caller's fetch audit record needs.
async fn run_plugin_gate(
    state: &NpmAppState,
    target: &Target<'_>,
    fingerprint: &str,
) -> (Response, Option<Verdict>, DownloadOutcome) {
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
    let dest = temp.path().join(&target.key.filename);
    let local = match download_and_verify(state, target, &dest).await {
        Ok(local) => local,
        Err((response, outcome)) => return (response, None, outcome),
    };

    let unpacked = temp.path().join("unpacked");
    let unpack_source = local.clone();
    let unpack_dest = unpacked.clone();
    match tokio::task::spawn_blocking(move || unpack(&unpack_source, &unpack_dest)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            return (
                unverifiable_response(&internal_reason(&format!(
                    "unpacking the downloaded npm tarball: {err:#}"
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
    match state.plugins.run_all(&plugins, target.key, &unpacked).await {
        None => {
            // Every plugin ran and passed: store the clean verdict, mark
            // it plugin-checked, then cache and serve the bytes.
            if let Err(err) = store_verdict(state, target.key, &Verdict::Clean, fingerprint).await {
                // A verdict that cannot be stored is not a verdict.
                return (
                    unverifiable_response(&internal_reason(&format!(
                        "storing the clean verdict: {err:#}"
                    ))),
                    None,
                    DownloadOutcome::Silent,
                );
            }
            if let Err(err) = mark_plugin_checked(state, target.key, fingerprint).await {
                return (
                    unverifiable_response(&internal_reason(&format!(
                        "marking the verdict plugin-checked: {err:#}"
                    ))),
                    None,
                    DownloadOutcome::Silent,
                );
            }
            let (response, outcome) = serve_cached(state, &local, target).await;
            (response, Some(Verdict::Clean), outcome)
        }
        Some(reason) => {
            if is_check_failure(&reason) {
                // The plugin never reached a verdict, so nothing is
                // stored and a retry attempts the plugins again rather
                // than being handed a durable block about an artifact
                // nothing examined.
                tracing::warn!(
                    package = %target.key.package,
                    version = %target.key.version,
                    code = %reason.code,
                    "an npm plugin could not run; answering unverifiable and storing nothing"
                );
                return (
                    unverifiable_response(&reason),
                    None,
                    DownloadOutcome::Silent,
                );
            }
            let stored = store_verdict(
                state,
                target.key,
                &Verdict::Blocked(reason.clone()),
                fingerprint,
            )
            .await;
            let (why_id, broadcast) = match stored {
                Ok(why_id) => (Some(why_id), Some(Verdict::Blocked(reason.clone()))),
                Err(err) => {
                    tracing::warn!(
                        package = %target.key.package,
                        version = %target.key.version,
                        error = %format!("{err:#}"),
                        "an npm plugin block could not be stored; refusing without a /why link"
                    );
                    (None, None)
                }
            };
            let link = why_id
                .clone()
                .and_then(|id| why_url(&state.config.current(), &id));
            tracing::warn!(
                package = %target.key.package,
                version = %target.key.version,
                code = %reason.code,
                "an npm plugin blocked this artifact"
            );
            (
                refusal_response(&reason, link.as_deref()),
                broadcast,
                DownloadOutcome::Refused {
                    package: target.key.package.clone(),
                    version: target.key.version.clone(),
                    filename: Some(target.key.filename.clone()),
                    reason,
                    why_id,
                },
            )
        }
    }
}

/// The refusal used when a joiner learns the owning plugin run ended
/// without a verdict. Mirrors the cargo path's own reason.
fn scan_incomplete_reason() -> RefusalReason {
    RefusalReason {
        code: "unverifiable:scan-incomplete".to_string(),
        detail: "the plugin run for this artifact did not complete".to_string(),
    }
}

/// Downloads the tarball to `dest` and checks it against the digest the
/// packument declared, which is the same value the artifact key carries.
///
/// A hash mismatch is a 403 the same as any other refusal, and unlike a
/// 404/503 outage it is a definite negative verdict this proxy actually
/// reached: the proxy downloaded real bytes and found them tampered with
/// relative to what the registry itself declared — the shape of a
/// tampered mirror, cache poisoning, or a compromised CDN edge, and the
/// highest-signal denial this log can carry. So the error carries its own
/// [`DownloadOutcome`] alongside the response, rather than letting every
/// caller fold it into `DownloadOutcome::Silent` the way a 404 or an
/// upstream outage correctly does — correction 2's own rule applies here
/// too: this must not copy cargo's identical gap in `cargo_download.rs`,
/// which is fixed in the same change as this one.
async fn download_and_verify(
    state: &NpmAppState,
    target: &Target<'_>,
    dest: &std::path::Path,
) -> Result<std::path::PathBuf, (Response, DownloadOutcome)> {
    let actual = match state
        .upstream
        .download_tarball(target.name, target.version, target.dist, dest)
        .await
    {
        Ok(digest) => digest.hex.to_lowercase(),
        Err(UpstreamError::NotFound) => {
            return Err((not_found_response(), DownloadOutcome::Silent))
        }
        Err(err) => {
            return Err((
                unverifiable_response(&RefusalReason {
                    code: "unverifiable:upstream".to_string(),
                    detail: sanitize(&format!(
                        "could not download this artifact right now: {err:#}"
                    )),
                }),
                DownloadOutcome::Silent,
            ))
        }
    };

    if actual != target.key.sha256 {
        tracing::warn!(
            package = %target.key.package,
            version = %target.key.version,
            expected = %target.key.sha256,
            actual = %actual,
            "the downloaded npm tarball did not match the declared digest; refusing it"
        );
        let reason = RefusalReason {
            code: "hash-mismatch".to_string(),
            detail: sanitize(&format!(
                "downloaded artifact digest {actual} does not match the \
                 registry-declared digest {}",
                target.key.sha256
            )),
        };
        let response = refusal_response(&reason, None);
        return Err((
            response,
            DownloadOutcome::Refused {
                package: target.key.package.clone(),
                version: target.key.version.clone(),
                filename: Some(target.key.filename.clone()),
                reason,
                why_id: None,
            },
        ));
    }

    Ok(dest.to_path_buf())
}

/// Inserts the verified file at `local` into the artifact cache and serves
/// it from there.
///
/// A cache insert that fails still serves the verified bytes: the cache is
/// a performance feature, and this file was digest-verified a moment ago.
async fn serve_cached(
    state: &NpmAppState,
    local: &std::path::Path,
    target: &Target<'_>,
) -> (Response, DownloadOutcome) {
    let cache = Arc::clone(&state.artifact_cache);
    let key_owned = target.key.clone();
    let file = local.to_path_buf();
    let cached = tokio::task::spawn_blocking(move || cache.insert(&key_owned, &file)).await;

    let path = match cached {
        Ok(Ok(path)) => path,
        Ok(Err(err)) => {
            tracing::warn!(
                package = %target.key.package,
                version = %target.key.version,
                error = %format!("{err:#}"),
                "the verified npm tarball could not be inserted into the artifact cache; \
                 serving it anyway"
            );
            local.to_path_buf()
        }
        Err(join_error) => {
            tracing::warn!(
                package = %target.key.package,
                version = %target.key.version,
                error = %join_error,
                "the cache insert task did not complete; serving the verified bytes anyway"
            );
            local.to_path_buf()
        }
    };

    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            tarball_response(bytes),
            DownloadOutcome::Served {
                key: target.key.clone(),
            },
        ),
        Err(err) => (
            unverifiable_response(&internal_reason(&format!(
                "reading the verified artifact: {err}"
            ))),
            DownloadOutcome::Silent,
        ),
    }
}

/// Builds the 200 response for a tarball body.
fn tarball_response(bytes: Vec<u8>) -> Response {
    let len = bytes.len();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, TARBALL_CONTENT_TYPE)
        .header(header::CONTENT_LENGTH, len)
        .body(Body::from(Bytes::from(bytes)))
        .unwrap_or_else(|_| {
            unverifiable_response(&internal_reason("building the download response"))
        })
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
    state: &NpmAppState,
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
    state: &NpmAppState,
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
    state: &NpmAppState,
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

/// Strips ASCII control characters and non-ASCII bytes before this text
/// can reach an HTTP reason phrase, mirroring the same discipline the
/// other download paths apply.
fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scoped_tarball_path_splits_at_its_infix() {
        assert_eq!(
            split_tarball_path("@babel/core/-/core-7.0.0.tgz"),
            Some(("@babel/core", "core-7.0.0.tgz"))
        );
        assert_eq!(
            split_tarball_path("lodash/-/lodash-4.17.21.tgz"),
            Some(("lodash", "lodash-4.17.21.tgz"))
        );
    }

    #[test]
    fn a_packument_path_is_not_a_tarball_path() {
        assert!(!looks_like_tarball("lodash"));
        assert!(!looks_like_tarball("@babel/core"));
        assert!(looks_like_tarball("lodash/-/lodash-4.17.21.tgz"));
    }

    #[test]
    fn the_version_comes_from_the_unscoped_filename() {
        assert_eq!(
            version_from_filename("@babel/core", "core-7.0.0.tgz").unwrap(),
            "7.0.0"
        );
        assert_eq!(
            version_from_filename("lodash", "lodash-4.17.21.tgz").unwrap(),
            "4.17.21"
        );
    }

    #[test]
    fn a_filename_for_another_package_is_rejected() {
        assert!(version_from_filename("lodash", "other-4.17.21.tgz").is_err());
        assert!(version_from_filename("@babel/core", "babel-7.0.0.tgz").is_err());
        assert!(version_from_filename("lodash", "lodash-.tgz").is_err());
        assert!(version_from_filename("lodash", "lodash-1.0.0.tar.gz").is_err());
    }

    #[test]
    fn a_path_traversal_in_the_filename_is_rejected() {
        assert!(version_from_filename("lodash", "lodash-../../etc/passwd.tgz").is_err());
    }

    /// Reaches `download_and_verify` directly because no HTTP-level
    /// scenario can exercise its own `actual != target.key.sha256`
    /// branch: every call site builds `target.key` and `target.dist`
    /// from the exact same live packument entry in the same scope (see
    /// `approved_for_download`/`allowlisted_target`), so the two always
    /// agree by construction — and `NpmUpstream::download_tarball`
    /// itself already verifies the downloaded bytes against that same
    /// declared digest before this function ever sees them, which is
    /// why `tests/http_npm_download.rs`'s own
    /// `a_digest_mismatch_is_refused_even_for_an_approved_version` only
    /// asserts `status >= 400`, not `== 403` — on npm, a live tampered
    /// tarball is actually caught one layer up, as an
    /// `unverifiable:upstream` 503, not this function's own check.
    ///
    /// This test proves the belt-and-suspenders branch itself is
    /// correct on its own terms: if `target.key.sha256` ever did
    /// disagree with what was actually downloaded (a defect elsewhere,
    /// not a scenario reachable today), this function still answers a
    /// 403 `hash-mismatch` refusal with a `DownloadOutcome::Refused`
    /// that `npm_download_handler` can turn into a `refused` audit
    /// line — never a silent `DownloadOutcome::Silent` the way the
    /// 404/upstream-outage arms correctly do. Mirrors
    /// `crate::http::cargo_download`'s own identical fix and test for
    /// the gate where this branch *is* the only check (cargo's
    /// `download_crate` performs no self-verification).
    #[tokio::test]
    async fn download_and_verify_reports_a_mismatch_as_a_refused_hash_mismatch() {
        use crate::artifact_cache::ArtifactCache;
        use crate::audit::AuditLog;
        use crate::config::{
            AuditConfig, Config, ConfigHandle, CveLine, NpmRegistryConfig, UnknownSeverity,
        };
        use crate::db::advisory::AdvisoryStore;
        use crate::db::review::ReviewStore;
        use crate::db::Db;
        use crate::ecosystem::npm::upstream::NpmUpstream;
        use crate::plugin::{PluginRunner, SandboxOutcome, SandboxRunner, SandboxSpec};
        use crate::policy::Policy;
        use crate::scan::coordinator::ScanCoordinator;
        use crate::scan::npm::NpmScanner;
        use std::path::PathBuf;
        use std::time::Duration;
        use url::Url;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        struct NeverCalledSandbox;
        impl SandboxRunner for NeverCalledSandbox {
            fn run(&self, _spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
                panic!("no plugin run is expected in this whitebox test");
            }
        }

        let server = MockServer::start().await;
        let real_bytes = b"the actual tarball bytes upstream serves".to_vec();
        let real_sha1 = {
            use sha1::{Digest, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(&real_bytes);
            hex::encode(hasher.finalize())
        };
        Mock::given(method("GET"))
            .and(wm_path("/demo/-/demo-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(real_bytes))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).expect("valid base url");
        let dist = Dist {
            tarball: format!("{base}demo/-/demo-1.0.0.tgz"),
            integrity: None,
            shasum: Some(real_sha1.clone()),
        };

        let db_dir = tempfile::tempdir().expect("create db temp dir");
        let db = Db::open(&db_dir.path().join("scanner.db")).expect("open db");
        let cache_dir = tempfile::tempdir().expect("create cache temp dir");
        let artifact_cache = ArtifactCache::new(db.clone(), cache_dir.path().join("artifacts"))
            .expect("create artifact cache");

        let cfg = Config {
            bind: "127.0.0.1:8080".parse().unwrap(),
            db_path: PathBuf::from("data/scanner.db"),
            cache_dir: PathBuf::from("data/cache"),
            upstream_url: "https://registry.npmjs.org/".parse().unwrap(),
            public_url: "http://proxy.example:8080".parse().unwrap(),
            scan_budget: Duration::from_secs(10),
            cache_ttl: Duration::from_secs(24 * 60 * 60),
            advisory_sync_interval: Duration::from_secs(60 * 60),
            advisory_source_url: "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
                .parse()
                .unwrap(),
            cve: CveLine {
                min_severity: 7.0,
                require_fix_available: false,
                unknown_severity: UnknownSeverity::Allow,
            },
            min_release_age_days: None,
            download: Default::default(),
            allowlist: Vec::new(),
            plugins: Vec::new(),
            max_concurrent_scans: None,
            ai_review: None,
            cargo_registry: None,
            npm_registry: Some(NpmRegistryConfig {
                upstream_registry_url: base.clone(),
                scan_budget: Duration::from_secs(10),
                max_packument_bytes: 67_108_864,
                min_release_age_days: None,
            }),
            audit: AuditConfig::default(),
        };
        let policy = Arc::new(Policy::build(Arc::new(cfg.clone())).expect("build policy"));
        let config_handle = Arc::new(ConfigHandle::new(cfg));

        let upstream = NpmUpstream::with_limits(base.clone(), 67_108_864, &Default::default())
            .expect("npm upstream");
        let scanner = NpmScanner::new(
            upstream,
            AdvisoryStore::new(db.clone()),
            VerdictStore::new(db.clone()),
            Arc::clone(&policy),
            None,
            Arc::clone(&config_handle),
            Arc::new(ScanCoordinator::new()),
            Arc::new(artifact_cache),
        );
        let state = NpmAppState {
            npm_scanner: Arc::new(scanner),
            config: config_handle,
            upstream: Arc::new(
                NpmUpstream::with_limits(base, 67_108_864, &Default::default())
                    .expect("npm download upstream"),
            ),
            verdicts: Arc::new(VerdictStore::new(db.clone())),
            plugins: Arc::new(PluginRunner::new(Arc::new(NeverCalledSandbox))),
            artifact_cache: Arc::new(
                ArtifactCache::new(db.clone(), cache_dir.path().join("download-artifacts"))
                    .expect("create download artifact cache"),
            ),
            reviews: Arc::new(ReviewStore::new(db.clone())),
            plugin_run_coordinator: Arc::new(ScanCoordinator::new()),
            audit: Arc::new(AuditLog::with_writer(std::io::sink())),
        };

        // The key this test deliberately disagrees with the real,
        // correctly-verified digest: the only way to exercise this
        // function's own defensive check, since every live call site
        // keeps the two in agreement by construction (see the doc
        // comment above).
        let key = ArtifactKey {
            ecosystem: "npm".to_string(),
            package: "demo".to_string(),
            version: "1.0.0".to_string(),
            filename: "demo-1.0.0.tgz".to_string(),
            sha256: "0".repeat(40),
        };
        let target = Target {
            key: &key,
            name: "demo",
            version: "1.0.0",
            dist: &dist,
        };
        let dest_dir = tempfile::tempdir().expect("create download dest dir");
        let dest = dest_dir.path().join("demo-1.0.0.tgz");

        let result = download_and_verify(&state, &target, &dest).await;
        let Err((response, outcome)) = result else {
            panic!("a disagreeing key must be refused, not served");
        };
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        match outcome {
            DownloadOutcome::Refused {
                package,
                version,
                filename,
                reason,
                why_id,
            } => {
                assert_eq!(package, "demo");
                assert_eq!(version, "1.0.0");
                assert_eq!(filename, Some("demo-1.0.0.tgz".to_string()));
                assert_eq!(reason.code, "hash-mismatch");
                assert_eq!(why_id, None);
            }
            DownloadOutcome::Served { .. } => panic!("expected Refused, got Served"),
            DownloadOutcome::Silent => panic!("expected Refused, got Silent"),
        }
    }
}

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
use super::{bad_request_response, not_found_response, why_url};

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

/// The tarball handler. `path` is the whole catch-all path, already
/// percent-decoded by axum.
pub async fn npm_download_handler(state: &NpmAppState, path: &str) -> Response {
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
                serve_with_plugin_dedup(state, &target, &fingerprint).await
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
            if plugin_checked(&state.verdicts, &key, &fingerprint).await {
                serve_verified_bytes(state, &target).await
            } else {
                serve_with_plugin_dedup(state, &target, &fingerprint).await
            }
        }
        DownloadApproval::Refused(reason, why_id) => {
            let link = why_id.and_then(|id| why_url(&state.config.current(), &id));
            refusal_response(&reason, link.as_deref())
        }
        // The packument gate never admitted this version. Refuse without
        // fetching anything, and never review inline.
        DownloadApproval::NotApproved => {
            refusal_response(&not_packument_approved_reason(&name, &version), None)
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
async fn serve_verified_bytes(state: &NpmAppState, target: &Target<'_>) -> Response {
    match cache_get(state, target.key).await {
        Ok(Some(path)) => match tokio::fs::read(&path).await {
            Ok(bytes) => tarball_response(bytes),
            Err(err) => unverifiable_response(&internal_reason(&format!(
                "reading the cached artifact: {err}"
            ))),
        },
        Ok(None) => {
            // The cache entry is gone. Re-download and re-verify, but no
            // plugin needs to see bytes an earlier run already admitted
            // for this exact digest.
            let temp = match tempfile::tempdir() {
                Ok(dir) => dir,
                Err(err) => {
                    return unverifiable_response(&internal_reason(&format!(
                        "creating a temporary download directory: {err}"
                    )))
                }
            };
            let dest = temp.path().join(&target.key.filename);
            match download_and_verify(state, target, &dest).await {
                Ok(local) => serve_cached(state, &local, target).await,
                Err(response) => response,
            }
        }
        Err(err) => unverifiable_response(&internal_reason(&format!(
            "reading the artifact cache: {err:#}"
        ))),
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
) -> Response {
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
            let (response, verdict) = run_plugin_gate(state, target, fingerprint).await;
            let _ = tx.send(verdict);
            response
        }
        Err(rx) => match coordinator::wait_for_verdict(rx).await {
            Some(Verdict::Clean) => serve_verified_bytes(state, target).await,
            Some(Verdict::Blocked(reason)) => {
                let link = stored_why_id(&state.verdicts, target.key, fingerprint)
                    .await
                    .and_then(|id| why_url(&state.config.current(), &id));
                refusal_response(&reason, link.as_deref())
            }
            None => unverifiable_response(&scan_incomplete_reason()),
        },
    }
}

/// Downloads, verifies, unpacks and runs every configured plugin over
/// `target` once. Returns the owner's response plus the verdict to
/// broadcast, which is `Some` only when that verdict was stored durably.
async fn run_plugin_gate(
    state: &NpmAppState,
    target: &Target<'_>,
    fingerprint: &str,
) -> (Response, Option<Verdict>) {
    let temp = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(err) => {
            return (
                unverifiable_response(&internal_reason(&format!(
                    "creating a temporary download directory: {err}"
                ))),
                None,
            )
        }
    };
    let dest = temp.path().join(&target.key.filename);
    let local = match download_and_verify(state, target, &dest).await {
        Ok(local) => local,
        Err(response) => return (response, None),
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
            )
        }
        Err(join_error) => {
            return (
                unverifiable_response(&internal_reason(&format!(
                    "the unpack task did not complete: {join_error}"
                ))),
                None,
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
                );
            }
            if let Err(err) = mark_plugin_checked(state, target.key, fingerprint).await {
                return (
                    unverifiable_response(&internal_reason(&format!(
                        "marking the verdict plugin-checked: {err:#}"
                    ))),
                    None,
                );
            }
            let response = serve_cached(state, &local, target).await;
            (response, Some(Verdict::Clean))
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
                return (unverifiable_response(&reason), None);
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
            let link = why_id.and_then(|id| why_url(&state.config.current(), &id));
            tracing::warn!(
                package = %target.key.package,
                version = %target.key.version,
                code = %reason.code,
                "an npm plugin blocked this artifact"
            );
            (refusal_response(&reason, link.as_deref()), broadcast)
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
async fn download_and_verify(
    state: &NpmAppState,
    target: &Target<'_>,
    dest: &std::path::Path,
) -> Result<std::path::PathBuf, Response> {
    let actual = match state
        .upstream
        .download_tarball(target.name, target.version, target.dist, dest)
        .await
    {
        Ok(digest) => digest.hex.to_lowercase(),
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

    if actual != target.key.sha256 {
        tracing::warn!(
            package = %target.key.package,
            version = %target.key.version,
            expected = %target.key.sha256,
            actual = %actual,
            "the downloaded npm tarball did not match the declared digest; refusing it"
        );
        return Err(refusal_response(
            &RefusalReason {
                code: "hash-mismatch".to_string(),
                detail: sanitize(&format!(
                    "downloaded artifact digest {actual} does not match the \
                     registry-declared digest {}",
                    target.key.sha256
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
/// a performance feature, and this file was digest-verified a moment ago.
async fn serve_cached(
    state: &NpmAppState,
    local: &std::path::Path,
    target: &Target<'_>,
) -> Response {
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
        Ok(bytes) => tarball_response(bytes),
        Err(err) => unverifiable_response(&internal_reason(&format!(
            "reading the verified artifact: {err}"
        ))),
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
}

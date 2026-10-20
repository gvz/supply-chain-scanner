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
//! - **No verdict, or a verdict not yet plugin-checked** — download the
//!   `.crate`, verify it against the index's `cksum`, unpack it, run every
//!   configured plugin, then store and serve the outcome.
//! - **A stored `Clean` verdict already marked plugin-checked** — serve
//!   the bytes without running a plugin. The artifact cache holds them. If
//!   an operator emptied the cache directory, the bytes are downloaded and
//!   hash-verified again, because a cache hit is only as good as the hash
//!   that admitted it.
//! - **A stored `Blocked` verdict** — refuse, with the stored reason and
//!   its `/why/<id>` link.
//!
//! `plugin_checked` is a separate flag from the verdict on purpose. The
//! index cascade stores `Verdict::Clean` for a crate-vet-covered version
//! it never unpacked, and [`VerdictStore::put`] resets the flag whenever
//! it rewrites a verdict. A `Clean` row alone therefore does not mean the
//! plugins have seen this artifact; only the flag does. See
//! [`crate::db::verdict`].
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

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::Response;

use crate::db::verdict::VerdictStore;
use crate::ecosystem::cargo::index::{validate_name, CargoIndexEntry};
use crate::ecosystem::cargo::normalize_name;
use crate::ecosystem::cargo::upstream::UpstreamError;
use crate::model::{ArtifactKey, RefusalReason, Verdict};
use crate::plugin::{is_check_failure, unpack};
use crate::scan::is_allowlisted;

use super::cargo_index::CargoAppState;
use super::refusal::{refusal_response, unverifiable_response};
use super::{bad_request_response, not_found_response, why_url};

/// The `Content-Type` sent for a `.crate` body. See the module docs.
const CRATE_CONTENT_TYPE: &str = "application/gzip";

/// The longest version string this handler accepts, in bytes. A SemVer
/// version with build metadata is far shorter than this. The cap exists so
/// an absurd path segment cannot reach a log line or an error message
/// unbounded.
const MAX_VERSION_LEN: usize = 128;

/// `GET /crates/{crate}/{version}/download`: the `.crate` bytes, gated on
/// the organization's plugins.
pub async fn cargo_download_handler(
    State(state): State<CargoAppState>,
    Path((raw_name, raw_version)): Path<(String, String)>,
) -> Response {
    let name = match validate_name(&raw_name) {
        Ok(name) => name,
        Err(err) => return bad_request_response(&format!("invalid crate name: {err}")),
    };

    // Documented in the module docs: the version is only checked for being
    // non-empty, short, and printable. It is never used as a path.
    if let Err(detail) = validate_version_segment(&raw_version) {
        return bad_request_response(&detail);
    }

    let entries = match state.upstream.index_entries(&name).await {
        Ok(entries) => entries,
        Err(UpstreamError::NotFound) => return not_found_response(),
        Err(err) => {
            return unverifiable_response(&RefusalReason {
                code: "unverifiable:upstream".to_string(),
                detail: sanitize(&format!(
                    "could not read the cargo sparse index right now: {err:#}"
                )),
            })
        }
    };

    let Some(entry) = entries.iter().find(|entry| entry.vers == raw_version) else {
        return not_found_response();
    };

    let key = crate::scan::cargo::artifact_key(&normalize_name(&name), entry);
    let fingerprint = state.cargo_scanner.fingerprint();

    // The allowlist is consulted before the stored verdict, matching
    // `Scanner::decide_inner` on the PyPI path: an operator who
    // allowlisted this crate and version has overridden the judgement
    // checks, and that override has to reach the stored block too. It
    // never overrides the integrity check — the bytes still have to match
    // the index `cksum`, which `download_and_verify` enforces on every
    // path this branches to.
    if is_allowlisted_crate(&state.config.current(), &name, &entry.vers) {
        return serve_gated(&state, &key, entry, true).await;
    }

    match stored_verdict(&state.verdicts, &key, &fingerprint).await {
        Ok(Some(Verdict::Blocked(reason))) => {
            // A stored block carries its own `/why` id, fetched the same
            // way the PyPI path fetches it.
            let link = stored_why_id(&state.verdicts, &key, &fingerprint)
                .await
                .and_then(|id| why_url(&state.config.current(), &id));
            return refusal_response(&reason, link.as_deref());
        }
        Ok(Some(Verdict::Clean)) => {
            let checked = plugin_checked(&state.verdicts, &key, &fingerprint).await;
            if checked {
                return serve_gated(&state, &key, entry, false).await;
            }
        }
        Ok(None) => {}
        Err(err) => {
            return unverifiable_response(&internal_reason(&format!(
                "looking up the stored verdict: {err:#}"
            )))
        }
    }

    serve_gated(&state, &key, entry, true).await
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
) -> Response {
    let fingerprint = state.cargo_scanner.fingerprint();

    if !run_plugins {
        match cache_get(state, key).await {
            Ok(Some(path)) => match tokio::fs::read(&path).await {
                Ok(bytes) => return crate_response(bytes),
                Err(err) => {
                    return unverifiable_response(&internal_reason(&format!(
                        "reading the cached artifact: {err}"
                    )))
                }
            },
            Ok(None) => {
                // The cache entry is gone. Re-download and re-verify, but
                // no plugin needs to see bytes an earlier run already
                // admitted for this exact hash.
                let temp = match tempfile::tempdir() {
                    Ok(dir) => dir,
                    Err(err) => {
                        return unverifiable_response(&internal_reason(&format!(
                            "creating a temporary download directory: {err}"
                        )))
                    }
                };
                let dest = temp.path().join(&key.filename);
                return match download_and_verify(state, entry, key, &dest).await {
                    Ok(local) => serve_cached(state, key, &local).await,
                    Err(response) => response,
                };
            }
            Err(err) => {
                return unverifiable_response(&internal_reason(&format!(
                    "reading the artifact cache: {err:#}"
                )))
            }
        }
    }

    // The full path: download, verify, unpack, run the plugins.
    let temp = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(err) => {
            return unverifiable_response(&internal_reason(&format!(
                "creating a temporary download directory: {err}"
            )))
        }
    };
    let dest = temp.path().join(&key.filename);
    let local = match download_and_verify(state, entry, key, &dest).await {
        Ok(local) => local,
        Err(response) => return response,
    };

    let unpacked = temp.path().join("unpacked");
    let unpack_source = local.clone();
    let unpack_dest = unpacked.clone();
    match tokio::task::spawn_blocking(move || unpack(&unpack_source, &unpack_dest)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            return unverifiable_response(&internal_reason(&format!(
                "unpacking the downloaded .crate: {err:#}"
            )))
        }
        Err(join_error) => {
            return unverifiable_response(&internal_reason(&format!(
                "the unpack task did not complete: {join_error}"
            )))
        }
    }

    let plugins = state.config.current().plugins.clone();
    match state.plugins.run_all(&plugins, key, &unpacked).await {
        None => {
            // Every plugin ran and passed: store the clean verdict, mark
            // it plugin-checked, then cache and serve the bytes.
            if let Err(err) = store_verdict(state, key, &Verdict::Clean, &fingerprint).await {
                // A verdict that cannot be stored is not a verdict. Serve
                // nothing rather than bytes whose record does not exist.
                return unverifiable_response(&internal_reason(&format!(
                    "storing the clean verdict: {err:#}"
                )));
            }
            if let Err(err) = mark_plugin_checked(state, key, &fingerprint).await {
                return unverifiable_response(&internal_reason(&format!(
                    "marking the verdict plugin-checked: {err:#}"
                )));
            }
            serve_cached(state, key, &local).await
        }
        Some(reason) => {
            if is_check_failure(&reason) {
                // The plugin never reached a verdict. Nothing is stored,
                // so a retry runs the plugins again rather than serving a
                // durable block about an artifact nothing examined.
                tracing::warn!(
                    package = %key.package,
                    version = %key.version,
                    code = %reason.code,
                    "a cargo plugin could not run; answering unverifiable and storing nothing"
                );
                return unverifiable_response(&reason);
            }
            let stored =
                store_verdict(state, key, &Verdict::Blocked(reason.clone()), &fingerprint).await;
            let why_id = match stored {
                Ok(why_id) => Some(why_id),
                Err(err) => {
                    tracing::warn!(
                        package = %key.package,
                        version = %key.version,
                        error = %format!("{err:#}"),
                        "a cargo plugin block could not be stored; refusing without a /why link"
                    );
                    None
                }
            };
            let link = why_id.and_then(|id| why_url(&state.config.current(), &id));
            tracing::warn!(
                package = %key.package,
                version = %key.version,
                code = %reason.code,
                "a cargo plugin blocked this artifact"
            );
            refusal_response(&reason, link.as_deref())
        }
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
) -> Response {
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
        Ok(bytes) => crate_response(bytes),
        Err(err) => unverifiable_response(&internal_reason(&format!(
            "reading the verified artifact: {err}"
        ))),
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

async fn stored_verdict(
    store: &Arc<VerdictStore>,
    key: &ArtifactKey,
    fingerprint: &str,
) -> anyhow::Result<Option<Verdict>> {
    let store = Arc::clone(store);
    let key = key.clone();
    let fingerprint = fingerprint.to_string();
    tokio::task::spawn_blocking(move || store.get(&key, &fingerprint))
        .await
        .map_err(|join_error| anyhow::anyhow!("the verdict lookup task panicked: {join_error}"))?
        .map(|stored| stored.map(|stored| stored.verdict))
}

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

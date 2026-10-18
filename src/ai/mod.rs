//! The AI reviewer: collect a package's reviewable source, judge it
//! with a language model, and record the review.
//!
//! This module owns the two seams between the proxy and its own
//! collector subcommand. [`collector_spec`] builds the sandbox
//! invocation that runs this binary's `collect` subcommand over a
//! package. [`parse_collector_output`] turns what came back into a
//! [`collect::CollectedPayload`] or an error. [`AiReviewer`] ties all of
//! it together: it runs the collector under the sandbox, makes one
//! provider call, parses the reply, stores a row and decides the
//! outcome.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use serde_json::json;

use crate::config::{AiReviewConfig, BlockOn};
use crate::model::ArtifactKey;
use crate::plugin::sandbox::{SandboxOutcome, SandboxSpec, SANDBOX_PACKAGE_DIR};

pub mod collect;
pub mod prompt;
pub mod provider;

use collect::CollectedPayload;
use provider::ChatProvider;

use crate::db::review::{NewReview, ReviewStore};
use crate::model::RefusalReason;
use crate::plugin::SandboxRunner;

/// Fixed allowance, in bytes, added to `max_payload_bytes` when the spec
/// sizes the sandbox's stdout cap.
///
/// [`collect::collect`] caps only the sum of file-content bytes. A
/// payload at exactly the cap is therefore bigger on the wire, because
/// it carries a JSON envelope and JSON string escaping can grow a
/// file's text. The allowance covers that envelope and typical
/// escaping overhead. A payload that fills the cap is never cut off by
/// the output limit mid-document.
///
/// Escaping grows with the content. Attacker-controlled content can
/// exceed any fixed allowance. A payload that overflows the output cap
/// arrives truncated and fails to parse. The review then reports an
/// unverifiable collector failure. That path fails closed. It never
/// produces a clean verdict.
pub const COLLECTOR_JSON_ALLOWANCE_BYTES: usize = 16 * 1024;

/// Builds the spec that runs this binary's own collector subcommand
/// under the sandbox. `binary` is the proxy's own executable path.
///
/// The collector runs as `<binary> collect --package-dir /pkg
/// --ecosystem <id> --max-payload-bytes <n>`. Every path in `args` names
/// a location *inside* the sandbox. So `--package-dir` is
/// [`SANDBOX_PACKAGE_DIR`], not the host cache path. [`SandboxSpec`]'s
/// `package_dir` field is what the sandbox binds read-only onto `/pkg`.
/// The host path never reaches argv, where the collector could quote it
/// back out.
///
/// `max_output_bytes` is `max_payload_bytes` plus
/// [`COLLECTOR_JSON_ALLOWANCE_BYTES`], so a payload at exactly the cap
/// still arrives whole.
pub fn collector_spec(
    binary: &Path,
    package_dir: &Path,
    key: &ArtifactKey,
    max_payload_bytes: usize,
    timeout: Duration,
) -> SandboxSpec {
    SandboxSpec {
        binary: binary.to_path_buf(),
        package_dir: package_dir.to_path_buf(),
        args: vec![
            "collect".to_string(),
            "--package-dir".to_string(),
            SANDBOX_PACKAGE_DIR.to_string(),
            "--ecosystem".to_string(),
            key.ecosystem.clone(),
            "--max-payload-bytes".to_string(),
            max_payload_bytes.to_string(),
        ],
        timeout,
        max_output_bytes: max_payload_bytes + COLLECTOR_JSON_ALLOWANCE_BYTES,
    }
}

/// Turns one collector run into a payload.
///
/// Rejects every outcome that is not a clean exit with valid
/// [`CollectedPayload`] JSON on stdout: a non-zero exit, a timeout, a
/// death by signal, or output the JSON parser cannot read whole. The
/// caller treats each of those as an unverifiable collector failure.
/// That is what keeps a truncated or hostile payload from ever becoming
/// a clean verdict.
pub fn parse_collector_output(outcome: &SandboxOutcome) -> anyhow::Result<CollectedPayload> {
    if outcome.timed_out {
        bail!("the collector timed out before it produced a payload");
    }
    match outcome.exit_code {
        Some(0) => {}
        Some(code) => bail!(
            "the collector exited {code} without producing a payload: {}",
            first_line(&outcome.output)
        ),
        None => match outcome.signal {
            Some(signal) => {
                bail!("the collector died on signal {signal} before producing a payload")
            }
            None => bail!("the collector died without an exit code before producing a payload"),
        },
    }
    serde_json::from_str(&outcome.output)
        .context("parsing the collector stdout as a collected payload")
}

/// The first line of `text`, capped, for error messages. The collector's
/// stdout is JSON, so anything non-empty here is a broken run. Its
/// first line is the most a refusal or a log line should carry.
fn first_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or("").trim();
    line.chars().take(200).collect()
}

// ---------------------------------------------------------------------------
// The reviewer
// ---------------------------------------------------------------------------

/// The outcome of one review.
///
/// `Clean` means the review ran to completion and did not block. It
/// stores a review row like every other completed review. `Blocked`
/// means a check the operator opted into refused the artifact. Its
/// verdict is durable. `Unverifiable` means the review never happened:
/// a collector, provider, reply or store failure. It stores nothing, so
/// a later request retries.
#[derive(Debug, Clone, PartialEq)]
pub enum ReviewOutcome {
    Clean,
    Blocked(RefusalReason),
    Unverifiable(RefusalReason),
}

/// The refusal codes the reviewer owns.
///
/// The `ai:` prefix marks durable blocks: the review ran and the
/// artifact failed a check. The `unverifiable:` prefix marks a review
/// that never produced a verdict, so nothing was recorded.
pub mod code {
    pub const MALICIOUS: &str = "ai:malicious";
    pub const SUSPICIOUS: &str = "ai:suspicious";
    pub const COVERAGE: &str = "ai:coverage";
    pub const OPAQUE_EXECUTABLE: &str = "ai:opaque-executable";
    pub const COLLECTOR: &str = "unverifiable:ai-collector";
    pub const PROVIDER: &str = "unverifiable:ai-provider";
    pub const REPLY: &str = "unverifiable:ai-reply";
    pub const STORE: &str = "unverifiable:ai-store";
}

/// The cap, in bytes, on a refusal detail this module builds: the same
/// reason-phrase budget `http::refusal` enforces. Package content and
/// model output are attacker-influenced text, so a detail is stripped
/// and capped before it can reach a reason phrase.
const DETAIL_MAX_BYTES: usize = 120;

/// Strips ASCII control characters (CR and LF included, the bytes a
/// response-splitting attack needs) and non-ASCII characters, then caps
/// at [`DETAIL_MAX_BYTES`]. This is the same discipline [`crate::scan`],
/// [`crate::plugin`] and [`crate::advisory::matching`] apply to their own
/// detail text, independently of the downstream sanitizing in
/// `http::refusal`.
fn sanitize_detail(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .take(DETAIL_MAX_BYTES)
        .collect()
}

/// Builds a refusal out of one of [`code`]'s constants and a sanitized
/// detail. Every block and every unverifiable outcome goes through
/// here, so no path can choose a code the constants do not name, and no
/// path can skip the detail sanitizing.
fn refusal(code: &'static str, detail: &str) -> RefusalReason {
    RefusalReason {
        code: code.to_string(),
        detail: sanitize_detail(detail),
    }
}

/// Orchestrates one review: collect under the sandbox, call the
/// Orchestrates one review: collect under the sandbox, call the
/// provider, parse the reply, decide, then store the row.
///
/// Every completed review stores a row, blocked or clean alike. Every
/// failure before the store step stores nothing: no review happened,
/// so there is nothing to record, and a later request retries.
pub struct AiReviewer {
    cfg: AiReviewConfig,
    sandbox: Arc<dyn SandboxRunner>,
    provider: Arc<dyn ChatProvider>,
    store: Arc<ReviewStore>,
    collector_binary: PathBuf,
}

impl AiReviewer {
    pub fn new(
        cfg: AiReviewConfig,
        sandbox: Arc<dyn SandboxRunner>,
        provider: Arc<dyn ChatProvider>,
        store: Arc<ReviewStore>,
        collector_binary: PathBuf,
    ) -> Self {
        Self {
            cfg,
            sandbox,
            provider,
            store,
            collector_binary,
        }
    }

    /// Reviews one artifact from its unpacked tree.
    ///
    /// `fingerprint` is the policy fingerprint the scan started under.
    /// The stored row carries it, so a review made under one policy is
    /// never attributed to another.
    pub async fn review(
        &self,
        key: &ArtifactKey,
        package_dir: &Path,
        fingerprint: &str,
    ) -> ReviewOutcome {
        let started = Instant::now();

        // The sandbox is synchronous, so the collector run goes to the
        // blocking pool, exactly as `PluginRunner::run_one` runs it.
        let payload = match self.collect(key, package_dir).await {
            Ok(payload) => payload,
            Err(reason) => return unverifiable(key, &reason, "the collector could not run"),
        };

        let request =
            prompt::build_request(&self.cfg.model, self.cfg.max_output_tokens, key, &payload);
        let body = match self.provider.complete(&request).await {
            Ok(body) => body,
            Err(error) => {
                // The provider error text goes to the log, not the detail:
                // a hostile provider can echo anything, including
                // key-shaped text, back in an error body, and the
                // reviewer has no way to recognize its own key.
                tracing::warn!(
                    package = %key.package,
                    version = %key.version,
                    error = %error,
                    "the model provider call failed"
                );
                return unverifiable(
                    key,
                    &refusal(
                        code::PROVIDER,
                        &format!(
                            "the model provider call for {} {} failed",
                            key.package, key.version
                        ),
                    ),
                    "the provider call failed",
                );
            }
        };

        let reply = match prompt::parse_reply(&body) {
            Ok(reply) => reply,
            Err(error) => {
                // Same discipline as the provider error: the reply error
                // chain can quote model text, so the log carries it and
                // the detail names only what happened.
                tracing::warn!(
                    package = %key.package,
                    version = %key.version,
                    error = %error,
                    "the model reply could not be read"
                );
                return unverifiable(
                    key,
                    &refusal(
                        code::REPLY,
                        &format!(
                            "the model reply for {} {} is not readable",
                            key.package, key.version
                        ),
                    ),
                    "the model reply is not readable",
                );
            }
        };

        // Decide in the fixed order the plan pins: the model verdict
        // first, then the install surface, then coverage, then opaque
        // executables.
        let blocked = self.decide(&payload, &reply);

        // Store. A store failure is unverifiable rather than clean: a
        // clean-looking outcome without its row would deny /why any
        // record of what was reviewed this time.
        let review = NewReview {
            key: key.clone(),
            fingerprint: fingerprint.to_string(),
            verdict: verdict_str(reply.verdict),
            blocked: blocked.is_some(),
            summary: reply.summary.clone(),
            findings_json: findings_json(&reply),
            coverage: payload.coverage(),
            reviewable_bytes_total: payload.reviewable_bytes_total as i64,
            reviewable_bytes_sent: payload.reviewable_bytes_sent as i64,
            opaque_json: opaque_json(&payload),
            reviewed_paths_json: reviewed_paths_json(&payload),
            model: self.cfg.model.clone(),
            prompt_version: prompt::PROMPT_VERSION,
            collector_version: payload.collector_version.clone(),
        };
        let stored = tokio::task::spawn_blocking({
            let store = Arc::clone(&self.store);
            move || store.put(&review)
        })
        .await;
        let put_error = match stored {
            Ok(Ok(_id)) => None,
            Ok(Err(error)) => Some(format!("{error:#}")),
            Err(join_error) => Some(format!("the store task did not complete: {join_error}")),
        };
        if let Some(detail) = put_error {
            return unverifiable(
                key,
                &refusal(
                    code::STORE,
                    &format!(
                        "storing the review of {} {} failed: {detail}",
                        key.package, key.version
                    ),
                ),
                "storing the review failed",
            );
        }

        let elapsed = started.elapsed();
        match blocked {
            Some(reason) => {
                warn_block(key, &reason);
                ReviewOutcome::Blocked(reason)
            }
            None => {
                info_complete(
                    key,
                    payload.coverage(),
                    verdict_str(reply.verdict),
                    &self.cfg.model,
                    elapsed,
                );
                ReviewOutcome::Clean
            }
        }
    }

    /// Runs the collector under the sandbox and parses its payload.
    /// Every collector failure maps to the unverifiable collector code.
    async fn collect(
        &self,
        key: &ArtifactKey,
        package_dir: &Path,
    ) -> Result<CollectedPayload, RefusalReason> {
        let spec = collector_spec(
            &self.collector_binary,
            package_dir,
            key,
            self.cfg.max_payload_bytes,
            self.cfg.timeout,
        );
        let sandbox = Arc::clone(&self.sandbox);
        let outcome = tokio::task::spawn_blocking(move || sandbox.run(&spec))
            .await
            .map_err(|join_error| {
                refusal(
                    code::COLLECTOR,
                    &format!("the collector task did not complete: {join_error}"),
                )
            })?;
        let outcome = outcome.map_err(|error| {
            refusal(
                code::COLLECTOR,
                &format!("the sandbox could not run the collector: {error:#}"),
            )
        })?;
        parse_collector_output(&outcome).map_err(|error| {
            refusal(
                code::COLLECTOR,
                &format!(
                    "the collector run for {} {} failed: {error:#}",
                    key.package, key.version
                ),
            )
        })
    }

    /// Applies the blocking rules to one parsed reply.
    fn decide(
        &self,
        payload: &CollectedPayload,
        reply: &prompt::ModelReply,
    ) -> Option<RefusalReason> {
        // 1. The model verdict against the operator's blocking level.
        // The code comes from the mapped verdict alone, and the model's
        // own text never reaches the detail: it is attacker-influenced
        // text (a hostile model could quote a key or plant a fake code
        // there), so the detail states the verdict in our words and
        // the summary lives on in the stored row and the log.
        match (reply.verdict, self.cfg.block_on) {
            (prompt::ModelVerdict::Malicious, _) => {
                return Some(refusal(
                    code::MALICIOUS,
                    "the model judged this package malicious",
                ));
            }
            (prompt::ModelVerdict::Suspicious, BlockOn::Suspicious) => {
                return Some(refusal(
                    code::SUSPICIOUS,
                    "the model judged this package suspicious",
                ));
            }
            _ => {}
        }

        // 2. An install surface that could not be sent whole: the
        // review did not see what runs at install time, so it can never
        // be enough, whatever the coverage figure says.
        if !payload.install_surface_complete {
            return Some(refusal(
                code::COVERAGE,
                "an install surface file was too large to send to the model",
            ));
        }

        // 3. Coverage below the threshold.
        if let Some(coverage) = payload.coverage() {
            if coverage < self.cfg.coverage_threshold {
                return Some(refusal(
                    code::COVERAGE,
                    &format!(
                        "the review covered {:.3} of reviewable bytes, below the threshold of {:.3}",
                        coverage, self.cfg.coverage_threshold
                    ),
                ));
            }
        }

        // 4. Opaque executables.
        if self.cfg.block_opaque_executables && !payload.opaque_executables.is_empty() {
            return Some(refusal(
                code::OPAQUE_EXECUTABLE,
                &format!(
                    "the package carries opaque executables the model cannot review: {}",
                    payload
                        .opaque_executables
                        .iter()
                        .map(|exe| exe.path.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }

        None
    }
}

/// Maps the model verdict to its row-verb string.
fn verdict_str(verdict: prompt::ModelVerdict) -> &'static str {
    match verdict {
        prompt::ModelVerdict::Clean => "clean",
        prompt::ModelVerdict::Suspicious => "suspicious",
        prompt::ModelVerdict::Malicious => "malicious",
    }
}

/// The findings, serialized once, exactly as the row stores them. A
/// serialization failure falls back to an empty array rather than
/// failing the store step: the verdict and coverage are what the block
/// turns on, and `findings_json`'s readers already tolerate an empty
/// list.
fn findings_json(reply: &prompt::ModelReply) -> String {
    json!(reply
        .findings
        .iter()
        .map(|f| json!({
            "path": f.path,
            "lines": f.lines,
            "behavior": f.behavior,
            "severity": f.severity,
        }))
        .collect::<Vec<_>>())
    .to_string()
}

/// The opaque content figures, serialized once.
fn opaque_json(payload: &CollectedPayload) -> String {
    serde_json::json!({
        "opaque_data_bytes": payload.opaque_data_bytes,
        "opaque_executables": payload.opaque_executables,
    })
    .to_string()
}

/// The paths the model actually received, serialized once.
fn reviewed_paths_json(payload: &CollectedPayload) -> String {
    serde_json::to_string(
        &payload
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".to_string())
}

/// Logs one unverifiable outcome and returns it.
fn unverifiable(key: &ArtifactKey, reason: &RefusalReason, cause: &'static str) -> ReviewOutcome {
    tracing::warn!(
        code = %reason.code,
        package = %key.package,
        version = %key.version,
        detail = %reason.detail,
        cause,
        "ai review could not run"
    );
    ReviewOutcome::Unverifiable(reason.clone())
}

/// Logs one completed review that passed.
fn info_complete(
    key: &ArtifactKey,
    coverage: Option<f32>,
    verdict: &str,
    model: &str,
    elapsed: Duration,
) {
    tracing::info!(
        package = %key.package,
        version = %key.version,
        verdict,
        coverage = coverage.map_or_else(|| "undefined".to_string(), |c| format!("{c:.3}")),
        model,
        elapsed = ?elapsed,
        "ai review complete"
    );
}

/// Logs one block.
fn warn_block(key: &ArtifactKey, reason: &RefusalReason) {
    tracing::warn!(
        code = %reason.code,
        package = %key.package,
        version = %key.version,
        detail = %reason.detail,
        "ai review blocked the artifact"
    );
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use crate::model::ArtifactKey;
    use crate::plugin::{SandboxOutcome, SANDBOX_PACKAGE_DIR};

    use super::{collect, collector_spec, parse_collector_output};

    fn key() -> ArtifactKey {
        ArtifactKey {
            ecosystem: "pypi".to_string(),
            package: "demo-package".to_string(),
            version: "1.0.0".to_string(),
            filename: "demo_package-1.0.0-py3-none-any.whl".to_string(),
            sha256: "a".repeat(64),
        }
    }

    #[test]
    fn collector_spec_passes_the_in_sandbox_package_dir() {
        let spec = collector_spec(
            Path::new("/proxy/supply-chain-scanner"),
            Path::new("/host/cache/unpacked"),
            &key(),
            8_192,
            Duration::from_secs(5),
        );

        // The collector sees the sandbox mount, not the host cache path.
        // Any path in `args` must name a location inside the sandbox.
        assert_eq!(
            spec.args,
            vec![
                "collect",
                "--package-dir",
                SANDBOX_PACKAGE_DIR,
                "--ecosystem",
                "pypi",
                "--max-payload-bytes",
                "8192",
            ]
        );
        assert!(
            !spec.args.iter().any(|arg| arg.contains("/host/cache")),
            "a host path reached the sandbox argv: {:?}",
            spec.args
        );
    }

    #[test]
    fn collector_spec_runs_the_proxys_own_binary() {
        let spec = collector_spec(
            Path::new("/proxy/supply-chain-scanner"),
            Path::new("/host/cache/unpacked"),
            &key(),
            8_192,
            Duration::from_secs(5),
        );
        assert_eq!(spec.binary, Path::new("/proxy/supply-chain-scanner"));
        // The host package directory stays the host-side mount source. It
        // is the sandbox, not this spec, that maps it onto /pkg.
        assert_eq!(spec.package_dir, Path::new("/host/cache/unpacked"));
        assert_eq!(spec.timeout, Duration::from_secs(5));
    }

    #[test]
    fn collector_spec_allows_more_output_than_the_payload_cap() {
        let spec = collector_spec(
            Path::new("/proxy/supply-chain-scanner"),
            Path::new("/host/cache/unpacked"),
            &key(),
            8_192,
            Duration::from_secs(5),
        );
        assert!(
            spec.max_output_bytes > 8_192,
            "the output limit {} must exceed the payload cap 8192, or a \
             payload at exactly the cap loses bytes to the JSON envelope",
            spec.max_output_bytes
        );
    }

    /// Builds a sandbox outcome for `parse_collector_output`.
    fn outcome(exit_code: Option<i32>, output: &str, timed_out: bool) -> SandboxOutcome {
        SandboxOutcome {
            exit_code,
            output: output.to_string(),
            timed_out,
            signal: None,
        }
    }

    #[test]
    fn parse_collector_output_rejects_a_nonzero_exit() {
        // The payload text is valid JSON. The exit code alone must reject it.
        assert!(parse_collector_output(&outcome(Some(1), "{}", false)).is_err());
    }

    #[test]
    fn parse_collector_output_rejects_a_timeout() {
        assert!(parse_collector_output(&outcome(None, "", true)).is_err());
    }

    #[test]
    fn parse_collector_output_rejects_truncated_json() {
        let truncated = "{\"collector_version\":\"1\",\"files\":";
        assert!(
            parse_collector_output(&outcome(Some(0), truncated, false)).is_err(),
            "a payload cut off mid-document must not parse"
        );
        assert!(parse_collector_output(&outcome(Some(0), "not json", false)).is_err());
    }

    #[test]
    fn parse_collector_output_accepts_a_valid_payload() {
        let payload = collect::CollectedPayload {
            collector_version: collect::COLLECTOR_VERSION.to_string(),
            files: vec![collect::CollectedFile {
                path: "setup.py".to_string(),
                install_surface: true,
                content: "from setuptools import setup\n".to_string(),
            }],
            reviewable_bytes_total: 28,
            reviewable_bytes_sent: 28,
            skipped_reviewable: Vec::new(),
            opaque_executables: Vec::new(),
            opaque_data_bytes: 0,
            install_surface_complete: true,
        };
        let json = serde_json::to_string(&payload).expect("serialize the fixture payload");

        let parsed = parse_collector_output(&outcome(Some(0), &json, false))
            .expect("a valid payload must parse");
        assert_eq!(parsed, payload);
    }
}

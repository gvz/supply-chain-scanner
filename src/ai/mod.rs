//! The AI reviewer: collect a package's reviewable source, judge it
//! with a language model, and record the review.
//!
//! This module owns the two seams between the proxy and its own
//! collector subcommand. [`collector_spec`] builds the sandbox
//! invocation that runs this binary's `collect` subcommand over a
//! package. [`parse_collector_output`] turns what came back into a
//! [`collect::CollectedPayload`] or an error. Tasks 5 through 8 build
//! the reviewer that calls them.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};

use crate::model::ArtifactKey;
use crate::plugin::sandbox::{SandboxOutcome, SandboxSpec, SANDBOX_PACKAGE_DIR};

pub mod collect;

use collect::CollectedPayload;

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

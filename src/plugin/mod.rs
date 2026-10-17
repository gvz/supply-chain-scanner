//! Org-supplied plugin checks: unpacking an artifact, running each
//! configured binary over it under confinement, and turning the result
//! into a verdict.
//!
//! [`PluginRunner::run_all`] is the last gate of a scan. Its contract is
//! that it only ever returns `None` when every configured plugin actually
//! ran and actually exited zero. There is no path through this module
//! where a check that failed to run produces a clean result: an
//! unreadable binary, a failed spawn, a namespace that could not be
//! created, a timeout, a process killed by a signal — each one is a
//! refusal. Failing open here would mean an organization believing it has
//! six checks in front of its developers while actually having five, which
//! is the quietest way this project could fail even after it ships.
//!
//! The plugin contract itself is an organization-facing API:
//!
//! ```text
//! <binary> --package-dir <dir> --name <pkg> --version <ver> --filename <file>
//! ```
//!
//! Exit 0 means clean, any non-zero exit means bad, and the first line of
//! stdout becomes the refusal's human-readable detail. `<dir>` is the path
//! inside the sandbox, not on the host.

pub mod sandbox;
pub mod unpack;

use std::path::Path;
use std::sync::Arc;

pub use sandbox::{
    BubblewrapSandbox, SandboxOutcome, SandboxRunner, SandboxSpec, SANDBOX_PACKAGE_DIR,
};
pub use unpack::{unpack, UnpackError};

use crate::config::PluginConfig;
use crate::model::{ArtifactKey, RefusalReason};

/// The cap, in bytes, on a plugin-supplied refusal detail.
///
/// A plugin's stdout is attacker-influenced — the package it is scanning
/// can provoke what it prints — and the detail ends up in an HTTP reason
/// phrase that task 11 renders. 200 bytes is the documented contract and
/// also the ceiling task 11's own budget can use.
const PLUGIN_DETAIL_MAX_BYTES: usize = 200;

/// Code suffix for a plugin that could not be run at all (an unreadable
/// binary, a sandbox that would not start, a task that did not complete).
pub const CODE_SUFFIX_ERROR: &str = ":error";

/// Code suffix for a plugin killed at its timeout without reaching a
/// verdict.
pub const CODE_SUFFIX_TIMEOUT: &str = ":timeout";

/// Whether `reason` means "this check could not be performed" rather than
/// "this check ran and the artifact failed it".
///
/// Both still refuse — nothing here ever fails open — but they must not
/// look the same, and in particular a check that never ran must not be
/// stored as a durable `Blocked` verdict: that would outlive the broken
/// plugin and leave a developer reading "we found malware" about an
/// artifact nothing ever examined. See
/// [`crate::scan::Scanner::run_full_scan`], the only caller.
pub fn is_check_failure(reason: &RefusalReason) -> bool {
    reason.code.starts_with("plugin:")
        && (reason.code.ends_with(CODE_SUFFIX_ERROR) || reason.code.ends_with(CODE_SUFFIX_TIMEOUT))
}

/// Runs the organization's configured plugin binaries over an unpacked
/// artifact.
pub struct PluginRunner {
    sandbox: Arc<dyn SandboxRunner>,
}

impl PluginRunner {
    pub fn new(sandbox: Arc<dyn SandboxRunner>) -> Self {
        Self { sandbox }
    }

    /// Runs every plugin in `plugins` against the package unpacked at
    /// `package_dir`, returning `None` only if all of them ran and exited
    /// zero.
    ///
    /// Plugins run sequentially, in configuration order, and the first
    /// block ends the scan. The order is the organization's: cheap checks
    /// are placed first so an obvious block costs an entropy scan rather
    /// than a full YARA sweep. Running them concurrently would throw that
    /// away, and continuing past a block would spend the remaining scan
    /// budget producing a decision that has already been made.
    pub async fn run_all(
        &self,
        plugins: &[PluginConfig],
        key: &ArtifactKey,
        package_dir: &Path,
    ) -> Option<RefusalReason> {
        for plugin in plugins {
            if let Some(reason) = self.run_one(plugin, key, package_dir).await {
                return Some(reason);
            }
        }
        None
    }

    /// Runs one plugin, mapping every outcome — clean, bad, or broken — to
    /// a verdict.
    async fn run_one(
        &self,
        plugin: &PluginConfig,
        key: &ArtifactKey,
        package_dir: &Path,
    ) -> Option<RefusalReason> {
        let spec = SandboxSpec {
            binary: plugin.binary.clone(),
            package_dir: package_dir.to_path_buf(),
            args: vec![
                "--package-dir".to_string(),
                SANDBOX_PACKAGE_DIR.to_string(),
                "--name".to_string(),
                key.package.clone(),
                "--version".to_string(),
                key.version.clone(),
                "--filename".to_string(),
                key.filename.clone(),
            ],
            timeout: plugin.timeout,
            max_output_bytes: PLUGIN_DETAIL_MAX_BYTES,
        };

        // The sandbox is blocking (it spawns a process and waits on it),
        // so it goes to the blocking pool rather than stalling a runtime
        // worker for the whole of the plugin's timeout.
        let sandbox = Arc::clone(&self.sandbox);
        let outcome = match tokio::task::spawn_blocking(move || sandbox.run(&spec)).await {
            Ok(Ok(outcome)) => outcome,
            // The sandbox could not run the plugin at all.
            Ok(Err(error)) => return Some(error_refusal(&plugin.name, &format!("{error:#}"))),
            // The blocking task panicked or was cancelled, so no plugin
            // verdict exists. Still not clean.
            Err(join_error) => {
                return Some(error_refusal(
                    &plugin.name,
                    &format!("plugin task did not complete: {join_error}"),
                ))
            }
        };

        if outcome.timed_out {
            return Some(RefusalReason {
                code: format!(
                    "plugin:{}{CODE_SUFFIX_TIMEOUT}",
                    sanitize_detail(&plugin.name)
                ),
                detail: sanitize_detail(&format!(
                    "plugin {} exceeded its {:?} timeout",
                    plugin.name, plugin.timeout
                )),
            });
        }

        match outcome.exit_code {
            Some(0) => None,
            Some(code) => Some(RefusalReason {
                code: format!("plugin:{}", sanitize_detail(&plugin.name)),
                detail: block_detail(&plugin.name, code, &outcome.output),
            }),
            // Killed by a signal without timing out: the plugin crashed
            // before reaching a verdict, so there is no verdict to trust.
            // Naming the signal (when the sandbox could determine one)
            // is what lets an operator tell a `SIGXCPU`/`SIGSEGV`/OOM
            // `SIGKILL` death apart from an uninformative "no exit code" —
            // the first is often a plugin bug or a resource limit, the
            // second two usually are not.
            None => Some(error_refusal(
                &plugin.name,
                &match outcome.signal {
                    Some(signal) => format!(
                        "plugin terminated by signal {signal} ({})",
                        signal_name(signal)
                    ),
                    None => "plugin terminated without an exit code".to_string(),
                },
            )),
        }
    }
}

/// The refusal for a plugin that could not be run or could not finish.
fn error_refusal(name: &str, cause: &str) -> RefusalReason {
    RefusalReason {
        code: format!("plugin:{}{CODE_SUFFIX_ERROR}", sanitize_detail(name)),
        detail: sanitize_detail(&format!("plugin {name} could not run: {cause}")),
    }
}

/// A human-readable name for a Linux signal number, for the handful an
/// operator is actually likely to see from a killed plugin. Falls back to
/// just the number for anything else rather than guessing.
fn signal_name(signal: i32) -> &'static str {
    match signal {
        libc::SIGXCPU => "SIGXCPU, CPU time limit exceeded",
        libc::SIGKILL => "SIGKILL",
        libc::SIGSEGV => "SIGSEGV, segmentation fault",
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGILL => "SIGILL, illegal instruction",
        libc::SIGFPE => "SIGFPE",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGTRAP => "SIGTRAP",
        libc::SIGSYS => "SIGSYS, bad system call",
        _ => "unknown signal",
    }
}

/// The detail for a plugin that ran and reported the package as bad.
///
/// The plugin's own first line of stdout is preferred, since it is the only
/// part of this system that knows *why*. A plugin that says nothing still
/// has to yield something an operator can act on, hence the fallback — and
/// "nothing" is judged *after* sanitizing, because a line of emoji or raw
/// control bytes says exactly as much as an empty one and would otherwise
/// leave the `/why` page with a blank reason.
fn block_detail(name: &str, exit_code: i32, output: &str) -> String {
    let reported = sanitize_detail(output.lines().next().unwrap_or(""));
    let reported = reported.trim();
    if reported.is_empty() {
        sanitize_detail(&format!("plugin {name} exited {exit_code}"))
    } else {
        reported.to_string()
    }
}

/// Strips everything that could make `text` dangerous or malformed inside
/// an HTTP reason phrase, then caps it at [`PLUGIN_DETAIL_MAX_BYTES`].
///
/// Non-ASCII characters and ASCII control characters both go — CR and LF
/// in particular, which are the bytes a response-splitting attack needs.
/// Filtering to ASCII first makes the character cap a byte cap. This
/// mirrors what [`crate::advisory::matching`] does to advisory summaries;
/// the two are deliberately independent, because neither should rely on
/// the other (or on task 11's own sanitizing) to stay safe.
fn sanitize_detail(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .take(PLUGIN_DETAIL_MAX_BYTES)
        .collect()
}

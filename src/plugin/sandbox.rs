//! Running an untrusted binary over an untrusted package.
//!
//! Both sides of a plugin run are hostile from the proxy's point of view.
//! The *package* was downloaded from a public registry minutes ago and the
//! whole reason it is being scanned is that it might be an attack. The
//! *plugin* is a third-party binary an organization dropped into its
//! config; the proxy did not write it and does not vouch for it. This
//! module is the containment boundary for both, built on `bubblewrap`.
//!
//! [`SandboxRunner`] is a trait rather than a concrete type so the plugin
//! runner's fail-closed behavior can be tested exhaustively against a
//! scripted fake. [`BubblewrapSandbox`] is the only implementation that
//! ships.
//!
//! # What this sandbox does and does not contain
//!
//! Contained: the host filesystem (only the plugin binary and the package
//! directory are visible, and the package directory read-only — no `/etc`,
//! no `/home`, no `/sys`, no other package's cache); the network
//! (`--unshare-all` leaves a fresh namespace with nothing but a down
//! loopback, so a plugin can neither exfiltrate the package nor fetch a
//! second stage); the host process table (a PID namespace, so the plugin
//! cannot signal or inspect the proxy); host privileges (an unprivileged
//! user namespace); and the plugin's lifetime (`--die-with-parent` plus a
//! `SIGKILL` to the whole process group at the timeout).
//!
//! Not contained:
//!
//! - **Resource consumption.** There is no cgroup, no rlimit and no CPU
//!   quota. `/` and `/tmp` inside the sandbox are writable tmpfs, which is
//!   RAM, so a plugin can exhaust memory, and it can spin a core for the
//!   whole of its timeout. The timeout is the only bound on a plugin's
//!   appetite.
//! - **Kernel attack surface.** No seccomp filter is installed, so the
//!   plugin reaches the full syscall table from inside the namespace.
//! - **Dynamically linked plugins.** Only the binary itself is bound — no
//!   loader, no `/lib`, no `/usr`. A plugin that is not statically linked
//!   cannot `exec` in here, and gets a refusal rather than a clean result.
//!   Supporting one means widening the bind set, which widens the
//!   boundary; that is a deliberate decision not taken here.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{bail, Context};

/// Where the package directory is mounted inside the sandbox.
///
/// Plugins are told about this path, not the host one: the host path is
/// not reachable from inside the namespace, and leaking it would hand a
/// plugin a cache layout it has no business knowing.
pub const SANDBOX_PACKAGE_DIR: &str = "/pkg";

/// How much of a plugin's stderr is kept, for diagnosing a sandbox that
/// failed to start. Never reaches a refusal detail; it is only logged.
const STDERR_CAPTURE_BYTES: usize = 512;

/// `bwrap` prefixes its own setup failures with this. Used to tell "the
/// sandbox could not be built" apart from "the plugin ran and said no".
const BWRAP_ERROR_PREFIX: &str = "bwrap: ";

/// How long to wait for a `SIGKILL`ed process group to actually die before
/// giving up and reporting a sandbox error. A hard bound: the scan must
/// never hang past its budget waiting on a wedged plugin.
const KILL_GRACE: Duration = Duration::from_secs(2);

/// One plugin invocation.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    /// Host path to the plugin binary.
    pub binary: PathBuf,
    /// Host path to the unpacked package, mounted read-only at
    /// [`SANDBOX_PACKAGE_DIR`].
    pub package_dir: PathBuf,
    /// Arguments after the binary. Any path in here must already be a
    /// path *inside* the sandbox.
    pub args: Vec<String>,
    pub timeout: Duration,
    /// How much stdout to keep. Anything past this is drained and dropped
    /// rather than left in the pipe, so a chatty plugin cannot wedge
    /// itself on a full buffer and burn its whole timeout.
    pub max_output_bytes: usize,
}

/// What came back from one plugin invocation.
///
/// Carries no verdict of its own: deciding what an exit code means is the
/// plugin runner's job, which is where the fail-closed mapping lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxOutcome {
    /// `None` if the process was killed by a signal or timed out.
    pub exit_code: Option<i32>,
    /// Captured stdout, truncated to `max_output_bytes`. Unsanitized.
    pub output: String,
    pub timed_out: bool,
}

/// Runs a plugin binary under confinement.
pub trait SandboxRunner: Send + Sync {
    /// Runs `spec` to completion, to its timeout, or to a failure.
    ///
    /// `Ok` means the sandbox did its job and is reporting what the plugin
    /// did — including that it timed out. `Err` means the sandbox itself
    /// could not run the plugin, which the caller must treat as a refusal.
    fn run(&self, spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome>;
}

/// Confinement via `bubblewrap`.
pub struct BubblewrapSandbox {
    bwrap: PathBuf,
}

impl BubblewrapSandbox {
    /// Resolves `bwrap` on `PATH` once, at startup.
    ///
    /// Errors if it is missing, so a proxy configured with plugins refuses
    /// to boot without a sandbox rather than quietly running fewer checks
    /// than the organization asked for — or, worse, running plugins
    /// unconfined.
    pub fn detect() -> anyhow::Result<Self> {
        let path =
            std::env::var_os("PATH").context("PATH is not set, so bwrap cannot be located")?;

        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("bwrap");
            let Ok(metadata) = std::fs::metadata(&candidate) else {
                continue;
            };
            if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
                return Ok(Self { bwrap: candidate });
            }
        }

        bail!(
            "bwrap (bubblewrap) was not found on PATH; it is required to run plugin \
             binaries under confinement"
        )
    }

    /// Builds the `bwrap` command line for `spec`.
    ///
    /// `--unshare-all` drops the network along with everything else: a
    /// plugin must not be able to exfiltrate the package it was handed or
    /// pull down a second stage. `--die-with-parent` means the sandbox
    /// cannot outlive the proxy. The package directory is bound read-only,
    /// so a plugin cannot alter the artifact between being scanned and
    /// being served.
    fn command(&self, binary: &Path, package_dir: &Path, args: &[String]) -> Command {
        let mut command = Command::new(&self.bwrap);
        command
            .arg("--unshare-all")
            .arg("--die-with-parent")
            .arg("--ro-bind")
            .arg(binary)
            .arg(binary)
            .arg("--ro-bind")
            .arg(package_dir)
            .arg(SANDBOX_PACKAGE_DIR)
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            .arg("--tmpfs")
            .arg("/tmp")
            .arg("--chdir")
            .arg(SANDBOX_PACKAGE_DIR)
            .arg("--")
            .arg(binary)
            .args(args);
        command
    }
}

impl SandboxRunner for BubblewrapSandbox {
    fn run(&self, spec: &SandboxSpec) -> anyhow::Result<SandboxOutcome> {
        // Resolve both host paths before handing them to bwrap: a relative
        // or symlinked binary path would otherwise be resolved inside the
        // sandbox, where it does not exist.
        let binary = spec
            .binary
            .canonicalize()
            .with_context(|| format!("resolving plugin binary {}", spec.binary.display()))?;
        let package_dir = spec.package_dir.canonicalize().with_context(|| {
            format!("resolving package directory {}", spec.package_dir.display())
        })?;

        let mut command = self.command(&binary, &package_dir, &spec.args);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Put the sandbox in its own process group so the timeout can kill
        // every process it spawned, not just `bwrap` itself.
        command.process_group(0);

        let mut child = command
            .spawn()
            .with_context(|| format!("spawning {}", self.bwrap.display()))?;
        // `process_group(0)` makes the child its own group leader, so its
        // pid is the group id.
        let process_group = child.id() as i32;

        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");
        let stdout_cap = spec.max_output_bytes;
        let stdout_reader = std::thread::spawn(move || read_capped(stdout, stdout_cap));
        let stderr_reader = std::thread::spawn(move || read_capped(stderr, STDERR_CAPTURE_BYTES));

        // Wait for the child on a helper thread so the timeout needs no
        // polling, and so the child is always reaped by whoever owns it.
        let (status_tx, status_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = status_tx.send(child.wait());
        });

        let (exit_code, timed_out) = match status_rx.recv_timeout(spec.timeout) {
            Ok(Ok(status)) => (status.code(), false),
            // `wait` failed, so the plugin's fate is unknown. Make it
            // certain rather than leaving something running behind a scan
            // that has already given up on it.
            Ok(Err(wait_error)) => {
                kill_process_group(process_group);
                return Err(
                    anyhow::Error::new(wait_error).context("waiting for the sandboxed plugin")
                );
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // SIGKILL, not SIGTERM: a plugin that traps or ignores
                // SIGTERM must not be able to outlive its limit, and the
                // whole group goes so that children die with it.
                kill_process_group(process_group);
                match status_rx.recv_timeout(KILL_GRACE) {
                    Ok(_) => (None, true),
                    // A refusal rather than a hang. The reader threads are
                    // left behind with it; they end when the wedged process
                    // finally releases the pipes.
                    Err(_) => bail!(
                        "sandboxed plugin {} did not die within {KILL_GRACE:?} of SIGKILL",
                        binary.display()
                    ),
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                kill_process_group(process_group);
                bail!("the thread waiting on the sandboxed plugin died")
            }
        };

        // Both pipes are at EOF by now: the process group is gone either
        // way, so nothing is still holding the write end.
        let stdout_bytes = join_reader(stdout_reader, "stdout")?;
        let stderr_bytes = join_reader(stderr_reader, "stderr")?;
        let output = String::from_utf8_lossy(&stdout_bytes).into_owned();
        let stderr_text = String::from_utf8_lossy(&stderr_bytes).into_owned();

        // Tell "bwrap could not build the sandbox" apart from "the plugin
        // ran and reported a problem". bwrap exits non-zero after writing
        // its own `bwrap: ...` diagnostic to stderr; a plugin that exits
        // non-zero has not produced one. Getting this wrong in either
        // direction still yields a refusal — only the refusal code's
        // precision is at stake — but an operator whose kernel denies user
        // namespaces needs to see a sandbox error, not "your packages are
        // all malicious".
        if !timed_out && exit_code != Some(0) && stderr_text.starts_with(BWRAP_ERROR_PREFIX) {
            bail!(
                "bubblewrap could not run the plugin: {}",
                stderr_text.lines().next().unwrap_or("").trim()
            );
        }
        if !stderr_text.is_empty() {
            tracing::debug!(
                binary = %binary.display(),
                stderr = %stderr_text.trim(),
                "sandboxed plugin wrote to stderr"
            );
        }

        Ok(SandboxOutcome {
            exit_code,
            output,
            timed_out,
        })
    }
}

/// Reads `reader` to EOF, keeping only the first `cap` bytes.
///
/// The rest is read and dropped rather than left unread: an unread pipe
/// blocks the writer, which would turn a verbose plugin into a timeout.
fn read_capped(mut reader: impl Read, cap: usize) -> std::io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Ok(kept);
        }
        if kept.len() < cap {
            let room = (cap - kept.len()).min(read);
            kept.extend_from_slice(&chunk[..room]);
        }
    }
}

fn join_reader(
    handle: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
) -> anyhow::Result<Vec<u8>> {
    match handle.join() {
        Ok(result) => result.with_context(|| format!("reading sandboxed plugin {stream}")),
        Err(_) => bail!("the thread reading sandboxed plugin {stream} panicked"),
    }
}

/// `SIGKILL`s every process in `process_group`.
fn kill_process_group(process_group: i32) {
    // SAFETY: `killpg` takes a process group id and a signal number and
    // touches no memory of ours. A failure (the group already being gone,
    // which is the common race) is deliberately ignored: the caller is
    // about to confirm the group is dead by waiting for it.
    unsafe {
        libc::killpg(process_group, libc::SIGKILL);
    }
}

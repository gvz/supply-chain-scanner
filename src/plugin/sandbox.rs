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
//! The bind set also includes the standard read-only OS paths (`/usr`,
//! `/lib`, `/lib64`, `/bin`, `/sbin`, the dynamic loader's cache and config,
//! and — this host being NixOS — `/nix/store`) so that an ordinary
//! dynamically linked binary can `exec` at all. See
//! [`RUNTIME_RO_BIND_PATHS`] for what that gives up and what it does not.
//!
//! Not contained:
//!
//! - **Resource consumption beyond a hard tmpfs cap.** There is no cgroup,
//!   no rlimit and no CPU quota. The writable tmpfs mounted at `/` and
//!   `/tmp` is capped at [`TMPFS_SIZE_BYTES`] (RAM-backed storage is bounded
//!   so a plugin cannot fill host memory through either mount), but nothing
//!   bounds CPU use or the number of processes a plugin forks within its
//!   timeout — the timeout remains the only bound on those.
//! - **Kernel attack surface.** No seccomp filter is installed, so the
//!   plugin reaches the full syscall table from inside the namespace.
//! - **Read access to the host's installed software.** A plugin can read
//!   anything under the paths in [`RUNTIME_RO_BIND_PATHS`] — which, on this
//!   host, includes the entire Nix store. This is not new exposure: the
//!   plugin is a binary the organization installed and runs as this same
//!   user, so it could already read all of that before being sandboxed.
//!   What stays denied is unchanged: the network, writing anywhere on the
//!   host, the rest of the filesystem (no `/etc` secrets, no `/home`, no
//!   other package's cache), and modifying the package under scan.

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

/// Read-only host paths an ordinary dynamically linked ELF binary needs in
/// order to `exec` at all: the shared library directories, the dynamic
/// loader's cache and config, and — this host being NixOS, where `bwrap`
/// itself and any plugin built here live — `/nix/store`.
///
/// Each is bound only if [`Path::exists`] says so, so a deployment missing
/// `/lib64` or `/nix/store` (i.e. not NixOS) still boots; the brief is
/// explicit that an absent path must never fail sandbox startup.
///
/// What this gives up: a plugin can now *read* host files under these
/// paths. That is not new exposure — the plugin is a binary the
/// organization installed and already runs as this same user, so it could
/// read all of this before it was ever sandboxed. What stays denied is
/// unchanged: the network (`--unshare-all`), writing anywhere on the host
/// (every entry here is `--ro-bind`), the rest of the filesystem (no
/// `/etc` secrets, no `/home`, no other package's cache — only the paths
/// listed here, `/proc`, `/dev`, and the package directory are visible),
/// and modifying the package under scan (`/pkg` stays read-only).
const RUNTIME_RO_BIND_PATHS: &[&str] = &[
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/nix/store",
];

/// Hard cap, in bytes, on each writable tmpfs mounted inside the sandbox
/// (the implicit root and the explicit `/tmp`).
///
/// This does not close the resource-limit gap described in this module's
/// doc comment — there is still no cgroup, no rlimit, no CPU quota, and a
/// plugin can still spin a core for the whole of its timeout. It removes
/// only the cheapest host-memory-exhaustion path available through a
/// single flag: without a `--size`, both tmpfs mounts are backed by RAM
/// and unbounded, so a plugin could fill host memory just by writing to
/// its own scratch space. 64 MiB is generous for a plugin's working files
/// and small enough that even several plugins' worth of it does not
/// threaten the host.
const TMPFS_SIZE_BYTES: u64 = 64 * 1024 * 1024;

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
    ///
    /// The explicit, size-capped `--tmpfs /` comes first and only first:
    /// bwrap's default root is already an unbounded tmpfs, and mounting a
    /// capped one in its place must happen before anything else is bound
    /// under `/`, or the later mount would hide those binds rather than
    /// contain them. Everything that follows — the binary, the runtime
    /// paths in [`RUNTIME_RO_BIND_PATHS`], and the package directory —
    /// nests inside that capped root.
    fn command(&self, binary: &Path, package_dir: &Path, args: &[String]) -> Command {
        let mut command = Command::new(&self.bwrap);
        command
            .arg("--unshare-all")
            .arg("--die-with-parent")
            .arg("--size")
            .arg(TMPFS_SIZE_BYTES.to_string())
            .arg("--tmpfs")
            .arg("/")
            .arg("--ro-bind")
            .arg(binary)
            .arg(binary);

        for path in RUNTIME_RO_BIND_PATHS {
            let path = Path::new(path);
            // Skip anything absent rather than failing: a deployment
            // without, say, `/lib64` or `/nix/store` must still boot.
            if path.exists() {
                command.arg("--ro-bind").arg(path).arg(path);
            }
        }

        command
            .arg("--ro-bind")
            .arg(package_dir)
            .arg(SANDBOX_PACKAGE_DIR)
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            .arg("--size")
            .arg(TMPFS_SIZE_BYTES.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Extracts the argument vector `command()` builds, as plain strings,
    /// without invoking `bwrap` at all. This is the fast, deterministic
    /// counterpart to the `#[ignore]`d real-sandbox tests: it proves the
    /// *shape* of the command line (what gets bound, in what order, with
    /// what size cap) on every `cargo test`, not only where `bwrap` and
    /// usable namespaces happen to be available.
    fn built_args() -> Vec<String> {
        let sandbox = BubblewrapSandbox {
            bwrap: PathBuf::from("bwrap"),
        };
        let command = sandbox.command(
            Path::new("/plugins/demo"),
            Path::new("/pkgs/demo-1.0"),
            &["--flag".to_string()],
        );
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn runtime_paths_are_bound_only_when_present_on_the_host() {
        let args = built_args();
        for path in RUNTIME_RO_BIND_PATHS {
            let bound = args
                .windows(3)
                .any(|w| w[0] == "--ro-bind" && w[1] == *path && w[2] == *path);
            assert_eq!(
                bound,
                Path::new(path).exists(),
                "{path} bind presence did not match whether it exists on this host"
            );
        }
    }

    #[test]
    fn root_and_tmp_tmpfs_are_both_size_capped() {
        let args = built_args();
        let size_arg = TMPFS_SIZE_BYTES.to_string();

        let root_capped = args
            .windows(4)
            .any(|w| w[0] == "--size" && w[1] == size_arg && w[2] == "--tmpfs" && w[3] == "/");
        assert!(root_capped, "root tmpfs was not size-capped: {args:?}");

        let tmp_capped = args
            .windows(4)
            .any(|w| w[0] == "--size" && w[1] == size_arg && w[2] == "--tmpfs" && w[3] == "/tmp");
        assert!(tmp_capped, "/tmp tmpfs was not size-capped: {args:?}");
    }

    #[test]
    fn root_tmpfs_is_mounted_before_any_other_bind() {
        // The capped root must be the very first mount, or later binds
        // under `/` would be hidden rather than contained (verified
        // against real bwrap during implementation).
        let args = built_args();
        assert_eq!(args[0], "--unshare-all");
        assert_eq!(args[1], "--die-with-parent");
        assert_eq!(args[2], "--size");
        assert_eq!(args[4], "--tmpfs");
        assert_eq!(args[5], "/");
    }

    #[test]
    fn package_dir_binary_and_chdir_are_still_present() {
        let args = built_args();
        assert!(args
            .windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1] == "/plugins/demo" && w[2] == "/plugins/demo"));
        assert!(args.windows(3).any(|w| w[0] == "--ro-bind"
            && w[1] == "/pkgs/demo-1.0"
            && w[2] == SANDBOX_PACKAGE_DIR));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--chdir" && w[1] == SANDBOX_PACKAGE_DIR));
        // The trailing `-- <binary> <args...>`.
        let tail = &args[args.len() - 3..];
        assert_eq!(tail, ["--", "/plugins/demo", "--flag"]);
    }
}

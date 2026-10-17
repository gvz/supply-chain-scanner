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
//! Resource use is bounded by POSIX rlimits set in `pre_exec` and
//! inherited across `exec` into the namespace — see [`apply_rlimits`] for
//! each limit and the reasoning behind its value. Without them, `--size
//! 64MiB` capped only the tmpfs: anonymous memory, `fork` and CPU were all
//! unbounded, and the timeout is wall-clock only, so a plugin that
//! `malloc`ed 10 GB or fork-bombed the host succeeded *within* its
//! timeout.
//!
//! Also cleared: the proxy's environment (`--clearenv`), so a third-party
//! plugin cannot read whatever the operator exported — which matters
//! because a plugin's first line of stdout becomes `reason.detail` and is
//! rendered on `/why/<id>` to anyone who can reach the proxy, i.e. it was
//! a working exfiltration path for every secret in the proxy's
//! environment. And the controlling terminal (`--new-session`, which
//! bubblewrap's own docs recommend against `TIOCSTI` injection while
//! `--dev` does bind a `/dev/tty`).
//!
//! Not contained:
//!
//! - **Resource consumption beyond those per-process rlimits.** There is
//!   still no cgroup, so the limits are per *process*, not per sandbox: a
//!   plugin may hold many processes (bounded by `RLIMIT_NPROC`, see
//!   [`apply_rlimits`]) each with its own
//!   [`PLUGIN_MAX_ADDRESS_SPACE_BYTES`] of address space. That bounds the
//!   blast radius rather than making it small. There is deliberately no
//!   CPU-time rlimit at all — see the comment on why `RLIMIT_CPU` is
//!   absent, near `PLUGIN_MAX_FILE_BYTES` — so CPU consumption is bounded
//!   only by the wall-clock timeout, not by a separate allowance.
//!   `RLIMIT_AS` also bounds *virtual* address space, not resident memory,
//!   which is the only portable handle Linux offers (`RLIMIT_RSS` is a
//!   no-op) — a plugin can still touch a lot of real memory under a
//!   generous virtual cap.
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
use std::os::unix::process::{CommandExt, ExitStatusExt};
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

/// `RLIMIT_AS`: per-process virtual address space.
///
/// Closes the cheapest denial-of-service a plugin had: `malloc` 10 GB and
/// take the host down inside a timeout it never exceeds. 2 GiB is
/// generous for a scanner working over at most 512 MiB of unpacked
/// content (the unpacker's own hard cap) plus its own rule database.
///
/// Note two things an operator may need to know. `RLIMIT_AS` bounds
/// *virtual* address space, not resident memory — it is the only limit
/// Linux actually enforces for anonymous memory (`RLIMIT_RSS` has been a
/// no-op for years, and `RLIMIT_DATA` misses much of what `mmap`
/// provides). And a plugin whose runtime reserves a large virtual arena
/// up front — a JVM, a Go binary with a big heap target, anything built
/// with a sanitizer — can fail to start under a limit like this even
/// though it would never touch that much memory.
const PLUGIN_MAX_ADDRESS_SPACE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// How many tasks beyond the host's current count the sandbox may create
/// — the headroom `RLIMIT_NPROC` is set to, via
/// [`nproc_limit_for_this_host`].
///
/// `RLIMIT_NPROC` cannot be a flat constant here, and getting that wrong
/// is a live hazard rather than a theoretical one. The kernel charges it
/// per `(user namespace, uid)` and counts *threads*, not processes; this
/// limit is set before `bwrap` clones into its new user namespace, so
/// `bwrap`'s own first `clone` is checked against the proxy user's
/// existing thread count on the host. A flat 1024 was tried first and
/// `bwrap` failed immediately with `Creating new namespace failed:
/// Resource temporarily unavailable` on a developer machine whose uid
/// already held 1066 threads — which, shipped, would have refused *every
/// artifact* on any busy host: the false-positive anti-goal, triggered by
/// nothing more than the machine being in use.
///
/// So the limit is measured-plus-headroom instead. The *value* set is
/// inherited from outside the sandbox, but the *count* charged against
/// it restarts near zero once `bwrap` clones into its fresh user
/// namespace — so the real ceiling a fork bomb hits inside the sandbox
/// is approximately host-threads-at-launch-time + 512 (on the machine
/// this comment was written against, which carried roughly 1,066 threads
/// for this uid, that is about 1,578), not 512 tasks outright. That is
/// still a large improvement over the ~125,000 the kernel's own default
/// ceiling would otherwise allow. They also live in a PID namespace torn
/// down with the sandbox, so none outlive the run.
const PLUGIN_PROCESS_HEADROOM: u64 = 512;

/// `RLIMIT_FSIZE`: largest single file the plugin may create.
///
/// Matched to [`TMPFS_SIZE_BYTES`] on purpose: the writable space inside
/// the sandbox is that one tmpfs, so a per-file cap above it would be
/// meaningless, and one below it would arbitrarily forbid a plugin from
/// using the scratch space it was given.
const PLUGIN_MAX_FILE_BYTES: u64 = TMPFS_SIZE_BYTES;

// `RLIMIT_CPU` is deliberately **not** one of the limits this sandbox
// applies.
//
// Linux enforces `RLIMIT_CPU` against the thread-*group's* total CPU
// time, not wall-clock time: an N-threaded plugin burns the allowance
// in roughly `limit / N` wall seconds, not `limit`. A single-threaded
// plugin would only ever hit this a moment before the wall-clock
// timeout fires anyway, so the limit buys that case nothing; a
// multithreaded one — threaded YARA, anything using `rayon`, `clamscan`
// — gets killed by `SIGXCPU` at a small fraction of its real timeout,
// well before doing any work. That is the false-positive anti-goal
// firing on an entirely legitimate plugin: the runner has no way to
// tell "killed by `SIGXCPU` partway through" apart from "actually
// malicious," so it refuses the artifact and stores nothing, forever,
// on every retry.
//
// The wall-clock timeout in `SandboxSpec::timeout` is what actually
// bounds how long any plugin — single- or multi-threaded — may run, and
// it does so correctly regardless of thread count. `RLIMIT_NPROC` below
// separately bounds how many threads/processes a plugin may create at
// all, which is the real defense against a CPU-burning fork bomb.
// Between the two, a CPU-only limit measured in the wrong clock adds no
// coverage and only costs correctness, so it is left out.

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
    /// The signal that killed the process, if `exit_code` is `None` and
    /// it was *not* this sandbox's own timeout kill (that case already
    /// has `timed_out: true` to explain it, and carries no signal here).
    /// E.g. `SIGXCPU`, `SIGSEGV`, or an OOM killer's `SIGKILL` — distinct
    /// from a plain "no exit code" for the operator reading `/why`.
    pub signal: Option<i32>,
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
            // The plugin is third-party and its first line of stdout is
            // published on `/why/<id>`, so it must not inherit the
            // proxy's environment: that was a working exfiltration path
            // for anything the operator exported. Everything a plugin
            // needs arrives in argv (see `crate::plugin`'s contract).
            .arg("--clearenv")
            // Recommended by bubblewrap's own documentation against
            // TIOCSTI terminal-injection, and `--dev` does bind a
            // `/dev/tty`. The timeout kill path does not depend on
            // process groups surviving this: `kill_process_group` kills
            // `bwrap` itself (which stays in the group this `Command`
            // created), `--die-with-parent` SIGKILLs the sandbox init
            // when `bwrap` dies, and that init is PID 1 of the
            // `--unshare-all` PID namespace, so the kernel reaps
            // everything else in it.
            .arg("--new-session")
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

        // The rlimits are constants (see `apply_rlimits`; `RLIMIT_CPU` is
        // deliberately not among them). Set in the forked child just
        // before `exec`, so they apply to `bwrap` and are inherited by
        // everything it starts inside the namespace.
        let nproc = nproc_limit_for_this_host();
        if nproc.is_none() {
            tracing::warn!(
                "could not read this host's thread count from /proc, so the \
                 sandbox's RLIMIT_NPROC is left at whatever this process \
                 inherited: a plugin's fork count is unbounded for this run. \
                 Every other limit (address space, file size) still applies."
            );
        }
        // SAFETY: `pre_exec` runs in the forked child between `fork` and
        // `exec`, where only async-signal-safe work is permitted.
        // `apply_rlimits` does nothing but issue `getrlimit`/`setrlimit`
        // syscalls and construct `libc::rlimit` values on the stack: no
        // allocation, no locks, no inherited mutex, nothing that could
        // deadlock against a thread that existed in the parent. The
        // `/proc` walk that produced `nproc` happened above, in the
        // parent, precisely so it is not done here.
        unsafe {
            command.pre_exec(move || apply_rlimits(nproc));
        }

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

        let (exit_code, timed_out, signal) = match status_rx.recv_timeout(spec.timeout) {
            // `signal()` (from `ExitStatusExt`) is `Some` exactly when
            // `code()` is `None` — the process died from a signal this
            // sandbox did not send, e.g. `SIGXCPU`, `SIGSEGV`, an `OOM`
            // kill's `SIGKILL`. Surfacing it is what lets an operator
            // tell that apart from a plain "no exit code".
            Ok(Ok(status)) => (status.code(), false, status.signal()),
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
                    // `timed_out` already says why this one ended; no
                    // separate signal is reported for it.
                    Ok(_) => (None, true, None),
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
            signal,
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

/// Applies every per-process resource limit to the calling process,
/// between `fork` and `exec`, so `bwrap` and everything it starts inside
/// the namespace inherit them.
///
/// Each limit is **clamped to the existing hard limit** rather than set
/// outright. Raising a hard limit requires `CAP_SYS_RESOURCE`, so an
/// unconditional `setrlimit` would return `EPERM` — and therefore refuse
/// every artifact — on any host whose operator had already set a hard
/// limit tighter than the value here. Clamping means this can only ever
/// tighten, never fail for trying to loosen.
///
/// Returns `Err` if a limit genuinely cannot be applied, which fails the
/// spawn and therefore refuses the artifact: a plugin running with fewer
/// limits than this module promises is not something to proceed with
/// quietly.
fn apply_rlimits(nproc: Option<u64>) -> std::io::Result<()> {
    set_limit(libc::RLIMIT_AS, PLUGIN_MAX_ADDRESS_SPACE_BYTES)?;
    set_limit(libc::RLIMIT_FSIZE, PLUGIN_MAX_FILE_BYTES)?;
    // `RLIMIT_CPU` is intentionally not set here; see the "deliberately
    // not one of the limits" comment above, near `PLUGIN_MAX_FILE_BYTES`.
    // `None` means the host's thread count could not be read, so any
    // value chosen here could be *below* it and would make `bwrap` fail
    // to clone at all — refusing every artifact. Leaving the inherited
    // limit in place is the lesser evil, and the caller logs it.
    if let Some(nproc) = nproc {
        set_limit(libc::RLIMIT_NPROC, nproc)?;
    }
    Ok(())
}

/// The `RLIMIT_NPROC` value to use on this host right now: the number of
/// threads currently charged to this uid, plus
/// [`PLUGIN_PROCESS_HEADROOM`]. `None` if `/proc` could not be read well
/// enough to be sure.
///
/// Computed per run, before the fork (so it may allocate freely), because
/// the host's count moves and a value below it makes `bwrap` fail to
/// start. The walk reads one small `status` file per process — a few
/// milliseconds against a plugin timeout measured in seconds.
fn nproc_limit_for_this_host() -> Option<u64> {
    // SAFETY: `geteuid` takes no arguments, touches no memory of ours,
    // and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let mut threads: u64 = 0;
    let mut saw_any = false;

    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // A process can exit between the readdir and this read; that is
        // normal and simply means it no longer counts.
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };

        let mut matches_uid = false;
        let mut count = 1u64;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                // "Uid:\t<real>\t<effective>\t<saved>\t<fs>"
                matches_uid = rest
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u32>().ok())
                    .map(|real| real == uid)
                    .unwrap_or(false);
            } else if let Some(rest) = line.strip_prefix("Threads:") {
                count = rest.trim().parse::<u64>().unwrap_or(1);
            }
        }
        if matches_uid {
            saw_any = true;
            threads = threads.saturating_add(count);
        }
    }

    // This process itself is charged to this uid, so finding nothing at
    // all means the walk did not work, not that the count is zero.
    if !saw_any {
        return None;
    }
    Some(threads.saturating_add(PLUGIN_PROCESS_HEADROOM))
}

/// Lowers `resource`'s soft and hard limits to `value`, or leaves them
/// alone if they are already tighter. See [`apply_rlimits`].
fn set_limit(resource: u32, value: u64) -> std::io::Result<()> {
    let resource = resource as libc::c_int;

    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes only into `current`, which is a live,
    // correctly typed, stack-allocated `libc::rlimit`.
    if unsafe { libc::getrlimit(resource as _, &mut current) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let capped = value.min(current.rlim_max) as libc::rlim_t;
    let limit = libc::rlimit {
        rlim_cur: capped,
        rlim_max: capped,
    };
    // SAFETY: `setrlimit` reads only from `limit`, which is a live,
    // correctly typed, stack-allocated `libc::rlimit`, and `capped` is by
    // construction no greater than the current hard limit, so this can
    // only tighten.
    if unsafe { libc::setrlimit(resource as _, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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
        // against real bwrap during implementation). The flags ahead of
        // it are namespace/env/session settings, not mounts.
        let args = built_args();
        assert_eq!(args[0], "--unshare-all");
        assert_eq!(args[1], "--die-with-parent");
        assert_eq!(args[2], "--clearenv");
        assert_eq!(args[3], "--new-session");
        assert_eq!(args[4], "--size");
        assert_eq!(args[6], "--tmpfs");
        assert_eq!(args[7], "/");
    }

    #[test]
    fn the_environment_is_cleared_and_the_terminal_session_is_new() {
        let args = built_args();
        assert!(
            args.iter().any(|a| a == "--clearenv"),
            "without --clearenv a third-party plugin inherits the proxy's \
             whole environment, and its first stdout line is published on \
             /why/<id>: {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--new-session"),
            "--new-session is bubblewrap's own recommendation against \
             TIOCSTI injection, and --dev does bind a /dev/tty: {args:?}"
        );
    }

    #[test]
    fn rlimits_are_clamped_rather_than_raised() {
        // The real `apply_rlimits` runs only in a forked child, so test
        // `set_limit`'s clamping contract directly in this process: ask
        // for an absurdly high `RLIMIT_NPROC` and confirm it did not
        // raise the hard limit (which would have returned EPERM and so
        // failed every plugin spawn).
        let mut before = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: writes only into the live local above.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NPROC as _, &mut before) },
            0
        );

        set_limit(libc::RLIMIT_NPROC, u64::MAX).expect("asking for more must clamp, not fail");

        let mut after = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: as above.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NPROC as _, &mut after) },
            0
        );
        assert_eq!(
            after.rlim_max, before.rlim_max,
            "set_limit must never raise a hard limit"
        );
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

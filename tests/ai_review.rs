//! Task 4: the sandboxed collector subcommand, against the real
//! `bubblewrap` sandbox.
//!
//! Every test here is `#[ignore]`d. It follows the pattern
//! `tests/plugin.rs` uses for its real-sandbox tests: the tests need
//! `bwrap` on `PATH` and usable user namespaces. `cargo test` may
//! assume neither. Run them with `cargo test --test ai_review --
//! --ignored` on a host that has both. Task 8 adds the reviewer tests
//! to this file.
//!
//! The collector runs as a subcommand of this crate's own binary, so
//! these tests use `CARGO_BIN_EXE_supply-chain-scanner`: the binary
//! under confinement is the one this repo builds.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use tempfile::TempDir;

use supply_chain_scanner::ai::collector_spec;
use supply_chain_scanner::model::ArtifactKey;
use supply_chain_scanner::plugin::{BubblewrapSandbox, SandboxRunner};

fn key() -> ArtifactKey {
    ArtifactKey {
        ecosystem: "pypi".to_string(),
        package: "demo-package".to_string(),
        version: "1.0.0".to_string(),
        filename: "demo_package-1.0.0-py3-none-any.whl".to_string(),
        sha256: "a".repeat(64),
    }
}

/// The proxy's own executable, as `cargo` built it for these tests.
fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_supply-chain-scanner"))
}

/// Builds a small package tree under a fresh temp directory: one
/// install-surface file and one ordinary module, both plain text.
fn small_package() -> (TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let package_dir = root.path().join("unpacked");
    let write = |rel: &str, content: &str| {
        let path = package_dir.join(rel);
        fs::create_dir_all(path.parent().expect("rel has a parent")).unwrap();
        fs::write(&path, content).unwrap();
    };
    fs::create_dir(&package_dir).unwrap();
    write("setup.py", "from setuptools import setup\n");
    write("demo/__init__.py", "VERSION = '1.0.0'\n");
    (root, package_dir)
}

#[test]
#[ignore = "requires bwrap and usable namespaces"]
fn the_collector_runs_under_a_real_sandbox_and_returns_a_payload() {
    let (_root, package_dir) = small_package();
    let sandbox = BubblewrapSandbox::detect().expect("bwrap must be on PATH");

    let spec = collector_spec(
        &binary(),
        &package_dir,
        &key(),
        8_192,
        Duration::from_secs(15),
    );
    let outcome = sandbox
        .run(&spec)
        .expect("the collector must run under the sandbox");

    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the collector did not succeed: output {:?}",
        outcome.output
    );

    let payload = supply_chain_scanner::ai::parse_collector_output(&outcome)
        .expect("the collected output must parse as a payload");
    assert!(
        payload.files.iter().any(|file| file.path == "setup.py"),
        "setup.py is missing from the payload: {:?}",
        payload
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
#[ignore = "requires bwrap and usable namespaces"]
fn the_collector_cannot_reach_the_network_from_inside_the_sandbox() {
    let (_root, package_dir) = small_package();
    let sandbox = BubblewrapSandbox::detect().expect("bwrap must be on PATH");

    let timeout = Duration::from_secs(10);
    let spec = collector_spec(&binary(), &package_dir, &key(), 8_192, timeout);

    // The collector's own code opens no socket, so the run must succeed
    // inside a sandbox that has no network at all. The wall-clock check
    // is the actual no-network proof. Nothing in this collection tree
    // waits on a connection, so a run near the whole timeout would mean
    // the collector was blocked on the outside world.
    let started = std::time::Instant::now();
    let outcome = sandbox
        .run(&spec)
        .expect("the collector must run under the sandbox");
    let elapsed = started.elapsed();

    assert!(
        elapsed < timeout.saturating_sub(Duration::from_secs(5)),
        "the run took {elapsed:?} of a {timeout:?} budget: nothing in the \
         collector waits on the network, so the time went somewhere else"
    );
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "a network-less sandbox still let the collector finish, which it \
         must, because it never talks to the network: output {:?}",
        outcome.output
    );

    // The spec grants no network of its own. `--unshare-all` is the
    // sandbox's own flag. This checks only that the collector spec adds
    // nothing on top of it.
    assert!(
        !spec.args.iter().any(|arg| arg.contains("net")),
        "the collector spec must not weaken the sandbox's network isolation"
    );
}

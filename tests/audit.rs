//! Integration tests for the fail-closed JSON Lines audit writer.
//!
//! These exercise `AuditLog`, `AuditContext`, `AuditRecord`, `VersionDecision`
//! and `ListingAudit` entirely through `AuditLog::with_writer`, over an
//! in-memory buffer or a deliberately failing writer — nothing here opens a
//! real HTTP handler, because Task 2 wires no emission. `AuditLog::open`
//! itself is covered separately against real paths on disk, since that is
//! where "fails closed" and "names the path" actually have to hold.

use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::Value;

use supply_chain_scanner::audit::{
    AuditContext, AuditLog, AuditRecord, ListingAudit, VersionDecision,
};
use supply_chain_scanner::config::{AuditConfig, AuditRotation};
use supply_chain_scanner::model::RefusalReason;

/// A `Write` over a `Vec<u8>` shared with the test, so assertions can
/// inspect what was written after the fact.
#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("buffer mutex").write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().expect("buffer mutex").flush()
    }
}

/// A `Write` that always fails, to prove a write error is returned rather
/// than swallowed.
struct AlwaysErrors;

impl Write for AlwaysErrors {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("disk is full"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("disk is full"))
    }
}

fn lines_of(buf: &Arc<Mutex<Vec<u8>>>) -> Vec<String> {
    let contents = buf.lock().expect("buffer mutex").clone();
    String::from_utf8(contents)
        .expect("valid utf8")
        .lines()
        .map(str::to_string)
        .collect()
}

fn parse(line: &str) -> Value {
    serde_json::from_str(line).expect("each line is valid JSON")
}

#[test]
fn a_served_record_is_one_json_line_with_the_fetch_identified() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let log = AuditLog::with_writer(SharedBuf(buf.clone()));

    let client: SocketAddr = "10.1.2.3:51234".parse().expect("valid socket addr");
    let ctx = AuditContext::new("pypi", client);
    let sha256 = "ab".repeat(32);
    let record = AuditRecord::served(
        &ctx,
        "requests",
        "2.31.0",
        "requests-2.31.0-py3-none-any.whl",
        &sha256,
    );

    log.write(&[record]).expect("write succeeds");

    let lines = lines_of(&buf);
    assert_eq!(lines.len(), 1);
    let value = parse(&lines[0]);

    assert_eq!(value["event"], "served");
    assert_eq!(value["ecosystem"], "pypi");
    assert_eq!(value["client_ip"], "10.1.2.3");
    assert_eq!(value["client_port"], 51234);
    assert_eq!(value["package"], "requests");
    assert_eq!(value["version"], "2.31.0");
    assert_eq!(value["filename"], "requests-2.31.0-py3-none-any.whl");
    assert_eq!(value["sha256"], sha256);
    assert!(
        value.get("reason_code").is_none(),
        "no reason on a served line"
    );
}

#[test]
fn a_refused_record_carries_the_reason_code_detail_and_why_id() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let log = AuditLog::with_writer(SharedBuf(buf.clone()));

    let client: SocketAddr = "10.1.2.3:51234".parse().expect("valid socket addr");
    let ctx = AuditContext::new("pypi", client);
    let reason = RefusalReason {
        code: "cve:high".to_string(),
        detail: "CVE-2024-0001 affects this version".to_string(),
    };
    let record = AuditRecord::refused(
        &ctx,
        "requests",
        "2.31.0",
        Some("requests-2.31.0-py3-none-any.whl"),
        &reason,
        Some("abc23xyz"),
    );

    log.write(&[record]).expect("write succeeds");

    let lines = lines_of(&buf);
    assert_eq!(lines.len(), 1);
    let value = parse(&lines[0]);

    assert_eq!(value["event"], "refused");
    assert_eq!(value["reason_code"], "cve:high");
    assert_eq!(value["reason_detail"], "CVE-2024-0001 affects this version");
    assert_eq!(value["why_id"], "abc23xyz");
}

fn sample_listing_audit() -> ListingAudit {
    ListingAudit {
        versions_upstream: 847,
        decisions: vec![
            VersionDecision {
                version: "4.17.21".to_string(),
                filename: None,
                allowed: true,
                reason_code: None,
                reason_detail: None,
                why_id: None,
            },
            VersionDecision {
                version: "4.17.20".to_string(),
                filename: None,
                allowed: false,
                reason_code: Some("too-new".to_string()),
                reason_detail: Some("released less than 7 days ago".to_string()),
                why_id: Some("why00000000why".to_string()),
            },
        ],
    }
}

#[test]
fn a_listing_audit_writes_one_listing_line_then_one_line_per_evaluated_version() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let log = AuditLog::with_writer(SharedBuf(buf.clone()));

    let client: SocketAddr = "10.1.2.3:51234".parse().expect("valid socket addr");
    let ctx = AuditContext::new("npm", client);
    let audit = sample_listing_audit();

    let records = audit.records(&ctx, "lodash");
    assert_eq!(audit.versions_evaluated(), 2);
    log.write(&records).expect("write succeeds");

    let lines = lines_of(&buf);
    assert_eq!(lines.len(), 3);

    let first = parse(&lines[0]);
    let second = parse(&lines[1]);
    let third = parse(&lines[2]);

    assert_eq!(first["event"], "listing");
    assert_eq!(first["versions_upstream"], 847);
    assert_eq!(first["versions_evaluated"], 2);

    assert_eq!(second["event"], "listed");
    assert_eq!(second["decision"], "allowed");

    assert_eq!(third["event"], "listed");
    assert_eq!(third["decision"], "denied");
    assert_eq!(third["reason_code"], "too-new");
}

#[test]
fn every_record_of_one_request_shares_its_request_id() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let log = AuditLog::with_writer(SharedBuf(buf.clone()));

    let client: SocketAddr = "10.1.2.3:51234".parse().expect("valid socket addr");
    let ctx = AuditContext::new("npm", client);
    let audit = sample_listing_audit();
    let records = audit.records(&ctx, "lodash");
    log.write(&records).expect("write succeeds");

    let lines = lines_of(&buf);
    let ids: Vec<String> = lines
        .iter()
        .map(|line| {
            parse(line)["request_id"]
                .as_str()
                .expect("request_id is a string")
                .to_string()
        })
        .collect();

    assert!(ids.iter().all(|id| id == &ids[0]));
    assert_eq!(ids[0].len(), 16);
}

// Review Focus 1
#[test]
fn a_reason_detail_containing_a_newline_stays_one_line() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let log = AuditLog::with_writer(SharedBuf(buf.clone()));

    let client: SocketAddr = "10.1.2.3:51234".parse().expect("valid socket addr");
    let ctx = AuditContext::new("cargo", client);
    let reason = RefusalReason {
        code: "forged".to_string(),
        detail: "line one\nnot a real record\r\n{\"event\":\"served\"}".to_string(),
    };
    let record = AuditRecord::refused(&ctx, "serde", "1.0.0", None, &reason, None);

    log.write(&[record]).expect("write succeeds");

    let lines = lines_of(&buf);
    assert_eq!(lines.len(), 1, "a forged newline must not inject a record");
    let value = parse(&lines[0]);
    assert!(value["reason_detail"].as_str().unwrap().contains('\n'));
}

// Review Focus 4
#[test]
fn concurrent_writers_never_interleave_a_partial_line() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::new(AuditLog::with_writer(SharedBuf(buf.clone())));

    let handles: Vec<_> = (0..8u16)
        .map(|t| {
            let log = Arc::clone(&log);
            thread::spawn(move || {
                let client: SocketAddr = format!("10.0.0.{}:{}", t + 1, 40000 + t)
                    .parse()
                    .expect("valid socket addr");
                let ctx = AuditContext::new("pypi", client);
                let records: Vec<AuditRecord> = (0..50)
                    .map(|i| {
                        AuditRecord::served(
                            &ctx,
                            "pkg",
                            "1.0.0",
                            "pkg-1.0.0.tar.gz",
                            &format!("{i:064x}"),
                        )
                    })
                    .collect();
                log.write(&records).expect("write succeeds");
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("writer thread panicked");
    }

    let lines = lines_of(&buf);
    assert_eq!(lines.len(), 400);
    for line in lines {
        serde_json::from_str::<Value>(&line).expect("each line parses");
    }
}

// Review Focus 5
#[test]
fn opening_an_unwritable_audit_path_fails_and_names_the_path() {
    let dir = tempfile::tempdir().expect("create tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
        .expect("set directory permissions");

    let config = AuditConfig {
        path: dir.path().join("audit.jsonl"),
        rotation: AuditRotation::Daily,
        max_files: 14,
    };

    let result = AuditLog::open(&config);

    // Restore write permission so the tempdir can clean itself up.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("restore directory permissions");

    let err = result.expect_err("an unwritable path must fail at open");
    assert!(format!("{err:#}").contains("audit.jsonl"), "{err:#}");
}

#[test]
fn an_ipv6_peer_address_serializes_as_address_and_port_separately() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let log = AuditLog::with_writer(SharedBuf(buf.clone()));

    let client: SocketAddr = "[2001:db8::1]:51234".parse().expect("valid socket addr");
    let ctx = AuditContext::new("npm", client);
    let record = AuditRecord::served(
        &ctx,
        "lodash",
        "4.17.21",
        "lodash-4.17.21.tgz",
        &"cd".repeat(32),
    );

    log.write(&[record]).expect("write succeeds");

    let lines = lines_of(&buf);
    let value = parse(&lines[0]);

    assert_eq!(value["client_ip"], "2001:db8::1");
    assert_eq!(value["client_port"], 51234);
}

#[test]
fn a_failing_writer_surfaces_its_error_rather_than_swallowing_it() {
    let log = AuditLog::with_writer(AlwaysErrors);

    let client: SocketAddr = "10.1.2.3:51234".parse().expect("valid socket addr");
    let ctx = AuditContext::new("pypi", client);
    let records = vec![AuditRecord::served(
        &ctx,
        "requests",
        "2.31.0",
        "requests-2.31.0-py3-none-any.whl",
        &"ab".repeat(32),
    )];

    let err = log
        .write(&records)
        .expect_err("a write failure must be returned");
    assert!(format!("{err:#}").contains("audit"), "{err:#}");
}

#[test]
fn open_writes_nothing_on_its_own() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let config = AuditConfig {
        path: dir.path().join("audit.jsonl"),
        rotation: AuditRotation::Daily,
        max_files: 14,
    };

    let log = AuditLog::open(&config).expect("open succeeds on a fresh path");
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let written = dir.path().join(format!("audit.jsonl.{today}"));

    drop(log);

    assert_eq!(std::fs::read(&written).unwrap_or_default().len(), 0);
}

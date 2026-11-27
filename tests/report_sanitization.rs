//! End-to-end CLI tests for report export and sanitization.
//!
//! The binary is driven as a subprocess via `CARGO_BIN_EXE_STREAMCRACK`; all
//! fixtures are synthetic.

use std::env;
use std::process::Command;

use serde_json::Value;

mod fixtures;
use fixtures::{pcap, pcapng, write_fixture};

fn streamcrack_bin() -> &'static str {
    env!("CARGO_BIN_EXE_STREAMCRACK")
}

fn run(args: &[impl AsRef<std::ffi::OsStr>]) -> std::process::Output {
    Command::new(streamcrack_bin())
        .args(args)
        .output()
        .expect("streamcrack binary ran")
}

#[test]
fn valid_pcap_exits_success_and_prints_summary() {
    let fixture = write_fixture("cli-pcap", &pcap(1, &[(vec![0x00u8; 12], 12)]));
    let output = run(&[fixture.to_str().unwrap()]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("packets: 1"));
    assert!(stdout.contains("format: Pcap"));
}

#[test]
fn valid_pcapng_exits_success() {
    let fixture = write_fixture("cli-pcapng", &pcapng(105, &[(vec![0x00u8; 12], 12)]));
    let output = run(&[fixture.to_str().unwrap()]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("format: Pcapng"));
}

#[test]
fn json_report_is_sanitized() {
    let fixture = write_fixture("cli-report", &pcapng(105, &[(vec![0x00u8; 12], 12)]));
    let report = fixture.with_extension("json");
    let output = run(&[fixture.to_str().unwrap(), "-o", report.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "streamcrack failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = std::fs::read_to_string(&report).expect("report written");
    let value: Value = serde_json::from_str(&text).expect("report is valid JSON");
    assert_no_payload(&value);

    assert_eq!(value["packet_count"], 1);
    assert_eq!(value["format"], "Pcapng");
    assert!(value.get("diagnostics").is_some());
    // No packet payload bytes may appear anywhere in the report.
    let lowered = text.to_lowercase();
    assert!(!lowered.contains("payload"));
    assert!(!lowered.contains("deadbeef"));
}

#[test]
fn malformed_input_exits_with_failure() {
    let fixture = write_fixture("cli-malformed", &[0xDE, 0xAD, 0xBE, 0xEF]);
    let output = run(&[fixture.to_str().unwrap()]);
    assert!(!output.status.success());
}

#[test]
fn oversized_file_is_rejected_via_cli() {
    let fixture = write_fixture("cli-oversized", &vec![0x00u8; 500]);
    let output = run(&[fixture.to_str().unwrap(), "--max-file-size", "1"]);
    assert!(!output.status.success());
}

/// Assert that a JSON value contains no `payload` key at any depth, so packet
/// payloads can never leak through the sanitized report.
fn assert_no_payload(value: &Value) {
    match value {
        Value::Object(map) => {
            assert!(!map.contains_key("payload"));
            for child in map.values() {
                assert_no_payload(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                assert_no_payload(child);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

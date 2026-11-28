//! End-to-end test for the `--crack` recovery path against committed synthetic
//! fixtures (see tests/fixtures/README.md for provenance).
//!
//! Drives the `streamcrack` binary as a subprocess; no real captures or
//! credentials are used.

use std::path::PathBuf;
use std::process::Command;

fn streamcrack_bin() -> String {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_STREAMCRACK") {
        return p;
    }
    let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("streamcrack");
    path.to_string_lossy().to_string()
}

fn fixture(name: &str) -> String {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
        .to_string_lossy()
        .to_string()
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(streamcrack_bin()).args(args).output().expect("streamcrack binary ran")
}

#[test]
fn crack_recovers_psk_from_synthetic_handshake() {
    let capture = fixture("smoke-handshake.pcap");
    let wordlist = fixture("smoke-wordlist.txt");
    let output = run(&["--crack", "--wordlist", &wordlist, &capture]);
    assert!(output.status.success(), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("WPA2 PSK found"), "unexpected stdout: {stdout}");
    assert!(stdout.contains("smoketest2026"), "unexpected stdout: {stdout}");
}

#[test]
fn crack_reports_not_found_when_password_absent() {
    // Wordlist that deliberately excludes the fixture password.
    let capture = fixture("smoke-handshake.pcap");
    let wordlist = fixture("smoke-wordlist.txt");
    let content = std::fs::read_to_string(&wordlist).expect("wordlist readable");
    let filtered: String = content
        .lines()
        .filter(|l| *l != "smoketest2026")
        .collect::<Vec<_>>()
        .join("\n");
    let tmp = std::env::temp_dir().join(format!("streamcrack-wl-{}.txt", std::process::id()));
    let tmp_str = tmp.to_string_lossy().to_string();
    std::fs::write(&tmp, &filtered).expect("temp wordlist written");
    let output = run(&["--crack", "--wordlist", &tmp_str, &capture]);
    assert!(!output.status.success(), "expected failure when password absent");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not found"), "unexpected stderr: {stderr}");
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn crack_requires_wordlist_or_mask() {
    let capture = fixture("smoke-handshake.pcap");
    let output = run(&["--crack", &capture]);
    assert!(!output.status.success());
}

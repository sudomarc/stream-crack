//! Regression tests for the PCAP/PCAPNG capture reader.
//!
//! Fixtures are synthetic and generated in-memory (see `tests/fixtures.rs`).

use std::fs::File;

use streamcrack::app::inspect;
use streamcrack::capture::{CaptureFormat, CaptureReader};
use streamcrack::config::Limits;
use streamcrack::domain::DiagnosticKind;
use streamcrack::error::Error;

mod fixtures;
use crate::fixtures::{pcap, pcap_be, pcap_packet_header, pcapng, write_fixture};

fn default_limits() -> Limits {
    Limits::default()
}

fn read_all(
    path: &std::path::Path,
    limits: &Limits,
) -> Vec<Result<streamcrack::capture::PacketRecord, Error>> {
    let file = File::open(path).expect("failed to open fixture");
    let mut reader = CaptureReader::new(file, limits).expect("failed to open capture reader");
    reader.by_ref().collect()
}

#[test]
fn valid_little_endian_pcap() {
    let path = write_fixture("pcap-le", &pcap(1, &[(vec![0xAAu8; 8], 8)]));
    let limits = default_limits();
    let records = read_all(&path, &limits);

    let records: Vec<_> = records
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("reader errored");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].index, 0);
    assert_eq!(records[0].caplen, 8);
    assert_eq!(records[0].orig_len, 8);
    assert_eq!(records[0].link_type, 1);
    assert_eq!(records[0].timestamp, 1_700_000_000 * 1_000_000);
    assert_eq!(records[0].payload, vec![0xAAu8; 8]);
}

#[test]
fn valid_big_endian_pcap() {
    let path = write_fixture("pcap-be", &pcap_be(105, &[(vec![0x55u8; 4], 4)]));
    let limits = default_limits();
    let records: Vec<_> = read_all(&path, &limits)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("reader errored");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].link_type, 105);
    assert_eq!(records[0].caplen, 4);
}

#[test]
fn valid_pcapng() {
    let path = write_fixture("pcapng", &pcapng(105, &[(vec![0x01u8; 6], 256)]));
    let limits = default_limits();
    let records: Vec<_> = read_all(&path, &limits)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("reader errored");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].link_type, 105);
    assert_eq!(records[0].caplen, 6);
    assert_eq!(records[0].orig_len, 256);
}

#[test]
fn empty_pcap_is_valid() {
    let path = write_fixture("pcap-empty", &pcap(1, &[]));
    let limits = default_limits();
    let records: Vec<_> = read_all(&path, &limits)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("reader errored");

    assert!(records.is_empty());
}

#[test]
fn unknown_magic_is_rejected() {
    let path = write_fixture("bad-magic", &[0xDE, 0xAD, 0xBE, 0xEF]);
    let limits = default_limits();
    let file = File::open(&path).unwrap();
    let err = CaptureReader::new(file, &limits).unwrap_err();
    assert!(matches!(err, Error::HeaderValidation { .. }));
}

#[test]
fn truncated_file_header_is_rejected() {
    let path = write_fixture("truncated-header", &[0xD4u8, 0xC3, 0xB2, 0xA1, 0x02, 0x00]);
    let limits = default_limits();
    let file = File::open(&path).unwrap();
    let err = CaptureReader::new(file, &limits).unwrap_err();
    assert!(matches!(err, Error::MalformedCapture { .. }));
}

#[test]
fn truncated_packet_header_is_rejected() {
    let header = pcap_file_header_fields();
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(&[0xDEu8; 8]); // partial packet header
    let path = write_fixture("truncated-packet-header", &bytes);
    let limits = default_limits();
    let records = read_all(&path, &limits);
    assert!(
        records
            .into_iter()
            .any(|r| matches!(r, Err(Error::MalformedCapture { .. })))
    );
}

#[test]
fn packet_larger_than_limit_is_rejected() {
    let path = write_fixture("oversized-packet", &pcap(1, &[(vec![0x00u8; 100], 100)]));
    let mut limits = default_limits();
    limits.max_packet_size = 10;
    let records = read_all(&path, &limits);
    assert!(
        records
            .into_iter()
            .any(|r| matches!(r, Err(Error::LimitExceeded { .. })))
    );
}

#[test]
fn record_count_limit_is_enforced() {
    let packets: Vec<(Vec<u8>, u32)> = std::iter::repeat_n((vec![0x00u8; 0], 0), 4).collect();
    let path = write_fixture("many-packets", &pcap(1, &packets));

    // The application layer enforces the record limit while streaming.
    let mut limits = default_limits();
    limits.max_record_count = 2;
    let err = inspect(&streamcrack::config::Config {
        input: path.clone(),
        output: None,
        limits: limits.clone(),
    })
    .unwrap_err();
    assert!(matches!(err, Error::LimitExceeded { .. }));

    // A limit at or above the record count succeeds.
    limits.max_record_count = 4;
    let summary = inspect(&streamcrack::config::Config {
        input: path,
        output: None,
        limits,
    })
    .unwrap();
    assert_eq!(summary.packet_count, 4);
}

#[test]
fn unknown_block_is_skipped_with_diagnostic() {
    // SHB, IDB(link 1), unknown block 0x00000017, then an EPB.
    let mut out = pcapng_shb_vec();
    out.extend_from_slice(&crate::fixtures::pcapng_idb(1));
    out.extend_from_slice(&crate::fixtures::block(0x00000017, &[0x00u8; 8]));
    out.extend_from_slice(&crate::fixtures::pcapng_epb(0, 0, &[0x02u8; 2], 2));
    let path = write_fixture("unknown-block", &out);
    let limits = default_limits();
    let file = File::open(&path).unwrap();
    let mut reader = CaptureReader::new(file, &limits).unwrap();
    let records: Vec<_> = reader
        .by_ref()
        .collect::<Result<Vec<_>, _>>()
        .expect("reader errored");
    assert_eq!(records.len(), 1);

    let kind = reader.diagnostics().iter().any(|d| {
        matches!(
            d.kind,
            DiagnosticKind::UnknownBlock {
                block_type: 0x00000017
            }
        )
    });
    assert!(
        kind,
        "expected UnknownBlock diagnostic, got {:?}",
        reader.diagnostics()
    );
}

#[test]
fn pcap_inconsistent_lengths_is_a_diagnostic_not_an_error() {
    let mut bytes = pcap_file_header_fields().to_vec();
    // caplen 100 > orig_len 50.
    bytes.extend_from_slice(&pcap_packet_header(0, 0, 100, 50, false));
    bytes.extend_from_slice(&[0x00u8; 100]);
    let path = write_fixture("inconsistent-lengths", &bytes);
    let limits = default_limits();
    let file = File::open(&path).unwrap();
    let mut reader = CaptureReader::new(file, &limits).unwrap();
    let _records: Vec<_> = reader
        .by_ref()
        .collect::<Result<Vec<_>, _>>()
        .expect("reader errored");

    assert!(
        reader
            .diagnostics()
            .iter()
            .any(|d| matches!(d.kind, DiagnosticKind::InconsistentLengths))
    );
}

#[test]
fn reader_reports_format_and_link_types() {
    let path = write_fixture("meta", &pcap(105, &[(vec![1u8], 1)]));
    let limits = default_limits();
    let file = File::open(&path).unwrap();
    let reader = CaptureReader::new(file, &limits).unwrap();
    assert_eq!(reader.format(), CaptureFormat::Pcap);
    assert_eq!(reader.link_types(), vec![105]);

    let path = write_fixture("meta-ng", &pcapng(105, &[(vec![1u8], 1)]));
    let limits = default_limits();
    let file = File::open(&path).unwrap();
    let mut reader = CaptureReader::new(file, &limits).unwrap();
    let records: Vec<_> = reader
        .by_ref()
        .collect::<Result<Vec<_>, _>>()
        .expect("reader errored");
    assert_eq!(records.len(), 1);
    assert_eq!(reader.format(), CaptureFormat::Pcapng);
    // PCAPNG link types are announced by Interface Description Blocks, which
    // are discovered while records are read, so they trail the first record.
    assert_eq!(reader.link_types(), vec![105]);
}

#[test]
fn inspect_rejects_oversized_file() {
    let path = write_fixture("oversized-file", &vec![0x00u8; 500]);
    let mut limits = default_limits();
    limits.max_file_size = 256;
    let err = inspect(&streamcrack::config::Config {
        input: path,
        output: None,
        limits,
    })
    .unwrap_err();
    assert!(matches!(err, Error::LimitExceeded { .. }));
}

/// Build a minimal valid PCAP file header (little-endian, Ethernet).
fn pcap_file_header_fields() -> [u8; 24] {
    pcap(1, &[])[..24]
        .try_into()
        .expect("pcap header is 24 bytes")
}

fn pcapng_shb_vec() -> Vec<u8> {
    crate::fixtures::pcapng_shb()
}

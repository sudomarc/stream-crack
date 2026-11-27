//! Synthetic PCAP and PCAPNG fixtures for regression tests.
//!
//! All fixtures are generated in memory. They have documented, synthetic
//! provenance and are never real user captures (see `AGENTS.md` and
//! `docs/FORMATS.md`). Timestamps and byte patterns are fixed so tests are
//! deterministic.

use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_id() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Path for a synthetic fixture in the OS temp directory.
pub fn fixture_path(suffix: &str) -> PathBuf {
    env::temp_dir()
        .join(format!(
            "streamcrack-test-{}-{}",
            std::process::id(),
            next_id()
        ))
        .with_extension(suffix)
}

/// Write `bytes` to a uniquely named synthetic fixture and return its path.
pub fn write_fixture(suffix: &str, bytes: &[u8]) -> PathBuf {
    let path = fixture_path(suffix);
    std::fs::write(&path, bytes).expect("failed to write synthetic fixture");
    path
}

/// PCAP file header (24 bytes) in the file's own byte order.
fn pcap_file_header(network: u32, snaplen: u32, big_endian: bool) -> [u8; 24] {
    // The magic is stored in the file's own byte order: little-endian files
    // start with bytes D4 C3 B2 A1, big-endian files with A1 B2 C3 D4.
    let magic = 0xA1B2C3D4u32;
    let magic_bytes = if big_endian {
        magic.to_be_bytes()
    } else {
        magic.to_le_bytes()
    };
    let version = if big_endian {
        2u16.to_be_bytes()
    } else {
        2u16.to_le_bytes()
    };
    let snap = if big_endian {
        snaplen.to_be_bytes()
    } else {
        snaplen.to_le_bytes()
    };
    let net = if big_endian {
        network.to_be_bytes()
    } else {
        network.to_le_bytes()
    };

    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&magic_bytes);
    h[4..6].copy_from_slice(&version);
    h[6..8].copy_from_slice(&version); // minor version equals major in our fixtures
    // thiszone (8..12) and sigfigs (12..16) are not interpreted by the reader.
    h[16..20].copy_from_slice(&snap);
    h[20..24].copy_from_slice(&net);
    h
}

/// PCAP packet header (16 bytes).
pub fn pcap_packet_header(
    ts_sec: u32,
    ts_frac: u32,
    incl_len: u32,
    orig_len: u32,
    big_endian: bool,
) -> [u8; 16] {
    let (ts, frac, incl, orig) = if big_endian {
        (
            ts_sec.to_be_bytes(),
            ts_frac.to_be_bytes(),
            incl_len.to_be_bytes(),
            orig_len.to_be_bytes(),
        )
    } else {
        (
            ts_sec.to_le_bytes(),
            ts_frac.to_le_bytes(),
            incl_len.to_le_bytes(),
            orig_len.to_le_bytes(),
        )
    };
    let mut h = [0u8; 16];
    h[0..4].copy_from_slice(&ts);
    h[4..8].copy_from_slice(&frac);
    h[8..12].copy_from_slice(&incl);
    h[12..16].copy_from_slice(&orig);
    h
}

/// Build a PCAP byte vector with the given link type and packets.
///
/// Each packet is `(payload, original_length)`; `caplen` is `payload.len()`.
pub fn pcap(network: u32, packets: &[(Vec<u8>, u32)]) -> Vec<u8> {
    pcap_with_order(network, false, packets)
}

/// Build a big-endian PCAP byte vector.
#[allow(dead_code)]
pub fn pcap_be(network: u32, packets: &[(Vec<u8>, u32)]) -> Vec<u8> {
    pcap_with_order(network, true, packets)
}

fn pcap_with_order(network: u32, big_endian: bool, packets: &[(Vec<u8>, u32)]) -> Vec<u8> {
    let mut out: Vec<u8> = pcap_file_header(network, 65_535, big_endian).to_vec();
    for (payload, orig_len) in packets {
        out.extend_from_slice(&pcap_packet_header(
            1_700_000_000,
            0,
            payload.len() as u32,
            *orig_len,
            big_endian,
        ));
        out.extend_from_slice(payload);
    }
    out
}

// PCAPNG block helpers. Block headers and the block total length trailer are
// always little-endian per the PCAPNG specification.

fn pad_to4(body: &[u8]) -> Vec<u8> {
    let remainder = body.len() % 4;
    if remainder == 0 {
        return body.to_vec();
    }
    let mut out = body.to_vec();
    out.resize(body.len() + 4 - remainder, 0);
    out
}

pub fn block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let body = pad_to4(body);
    let total = (8 + body.len() + 4) as u32;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&total.to_le_bytes());
    out
}

/// PCAPNG Section Header Block (little-endian byte-order magic, version 1.0).
pub fn pcapng_shb() -> Vec<u8> {
    let body = [
        0x04, 0x03, 0x02, 0x01, // byte-order magic (little-endian: 0x01020304)
        0x01, 0x00, // major version 1
        0x00, 0x00, // minor version 0
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // section length: unknown
    ];
    block(0x0A0D0D0A, &body)
}

/// PCAPNG Interface Description Block advertising `link_type`.
pub fn pcapng_idb(link_type: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(link_type as u16).to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // reserved
    body.extend_from_slice(&65_535u32.to_le_bytes()); // snaplen (not interpreted)
    block(0x00000001, &body)
}

/// PCAPNG Enhanced Packet Block for `interface_id` at tick timestamp `ts`.
pub fn pcapng_epb(interface_id: u32, ts: u64, payload: &[u8], orig_len: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&interface_id.to_le_bytes());
    body.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
    body.extend_from_slice(&(ts as u32).to_le_bytes());
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(&orig_len.to_le_bytes());
    body.extend_from_slice(payload);
    block(0x00000006, &body)
}

/// Build a PCAPNG byte vector: SHB, one IDB, then `packets`.
pub fn pcapng(interface_link_type: u32, packets: &[(Vec<u8>, u32)]) -> Vec<u8> {
    let mut out = pcapng_shb();
    out.extend_from_slice(&pcapng_idb(interface_link_type));
    for (index, (payload, orig_len)) in packets.iter().enumerate() {
        out.extend_from_slice(&pcapng_epb(0, index as u64 * 1_000_000, payload, *orig_len));
    }
    out
}

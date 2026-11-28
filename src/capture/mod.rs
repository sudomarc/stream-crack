//! Streaming capture-file readers for PCAP and PCAPNG.
//!
//! All capture data is treated as untrusted. Lengths and offsets are validated
//! with checked arithmetic before any indexing or allocation, and resource
//! limits are enforced before allocation. Payload bytes are never interpreted
//! beyond the metadata this crate is designed to expose.

mod eapol;
mod pcap;
mod pcapng;
mod reader;

pub use eapol::{
    extract_beacon_bssid_ssid, extract_from_packet, extract_handshakes, EapolCandidate,
};
pub use reader::{CaptureFormat, CaptureReader, PacketRecord};

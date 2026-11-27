//! Streaming capture-file readers for PCAP and PCAPNG.
//!
//! All capture data is treated as untrusted. Lengths and offsets are validated
//! with checked arithmetic before any indexing or allocation, and resource
//! limits are enforced before allocation. Payload bytes are never interpreted
//! beyond the metadata this crate is designed to expose.

mod pcap;
mod pcapng;
mod reader;

pub use reader::{CaptureFormat, CaptureReader, PacketRecord};

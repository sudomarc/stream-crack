//! Per-frame metadata classification.
//!
//! Classifications depend only on frame headers; payload bytes are never
//! inspected or retained here.

use serde::{Deserialize, Serialize};

/// Metadata for one frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameMetadata {
    /// Zero-based index of the record in the file.
    pub index: u64,
    /// Timestamp: microseconds for PCAP, raw ticks for PCAPNG.
    pub timestamp: u64,
    /// Captured length (`caplen`) in bytes.
    pub caplen: u32,
    /// Original length on the wire (`orig_len`) in bytes.
    pub orig_len: u32,
    /// Link type the frame was captured with.
    pub link_type: u32,
    /// Classification of the frame.
    pub classification: FrameClassification,
}

/// How a frame was classified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameClassification {
    /// The link type is not one this release decodes.
    UnknownLinkType { link_type: u32 },
    /// The link type is known, but no decoder exists for it in this release.
    DecoderPending { link_type: u32 },
    /// The frame was decoded to the extent supported by this release.
    Decoded { frame: DecodedFrame },
}

/// Partially decoded frame metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedFrame {
    pub link_type: u32,
    pub kind: FrameKind,
}

/// Broad frame kind, once a decoder produces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameKind {
    Unknown,
}

/// Classify a link type announced by a capture file.
///
/// Only link types with a tested decoder are `DecoderPending`; everything
/// else is `UnknownLinkType`. In this release only IEEE 802.11 (105) has a
/// tested decoder path pending Phase 2 implementation.
pub fn classify_link_type(link_type: u32) -> FrameClassification {
    match link_type {
        105 => FrameClassification::DecoderPending { link_type: 105 },
        other => FrameClassification::UnknownLinkType { link_type: other },
    }
}

/// Human-readable name for a link type value (metadata only).
pub fn link_type_name(link_type: u32) -> &'static str {
    match link_type {
        1 => "Ethernet",
        105 => "IEEE 802.11",
        127 => "Radiotap",
        _ => "unknown",
    }
}

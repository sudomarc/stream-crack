//! Capture summary: the top-level metadata of one inspected file.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::diagnostics::Diagnostic;
use super::frame::{FrameMetadata, link_type_name};

/// Format of a parsed capture file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureFormat {
    Pcap,
    Pcapng,
}

/// Metadata about one capture interface (PCAPNG Interface Description Block;
/// PCAP has a single implicit interface from its file header).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceSummary {
    /// Link type of the interface (see [`link_type_name`]).
    pub link_type: u32,
}

/// Top-level, sanitized summary of one capture inspection.
///
/// Every field is metadata: no payload bytes, no keys, no credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureSummary {
    /// Path of the inspected file.
    pub source: PathBuf,
    /// File format.
    pub format: CaptureFormat,
    /// Link types announced by the capture.
    pub link_types: Vec<u32>,
    /// Number of packet records read.
    pub packet_count: u64,
    /// Total captured bytes across all records (`caplen`).
    pub captured_bytes: u64,
    /// Total original bytes on the wire (`orig_len`).
    pub offered_bytes: u64,
    /// First record timestamp, units depend on format (see `FrameMetadata`).
    pub first_timestamp: Option<u64>,
    /// Last record timestamp.
    pub last_timestamp: Option<u64>,
    /// Non-fatal warnings emitted while parsing.
    pub diagnostics: Vec<Diagnostic>,
    /// Per-frame metadata classifications.
    pub frames: Vec<FrameMetadata>,
}

impl CaptureSummary {
    /// Link type of the primary interface, if any was announced.
    pub fn primary_link_type(&self) -> Option<u32> {
        self.link_types.first().copied()
    }
}

/// One-line, human-readable summary of an inspection (metadata only).
impl std::fmt::Display for CaptureSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let link = self
            .primary_link_type()
            .map(link_type_name)
            .unwrap_or("<none>");
        writeln!(f, "StreamCrack inspection summary")?;
        writeln!(f, "  source: {}", self.source.display())?;
        writeln!(f, "  format: {:?}", self.format)?;
        writeln!(f, "  link type: {link}")?;
        writeln!(f, "  packets: {}", self.packet_count)?;
        writeln!(f, "  captured bytes: {}", self.captured_bytes)?;
        writeln!(f, "  offered bytes: {}", self.offered_bytes)?;
        match (self.first_timestamp, self.last_timestamp) {
            (Some(first), Some(last)) => {
                writeln!(f, "  timestamps: {first} .. {last}")
            }
            _ => writeln!(f, "  timestamps: <none>"),
        }?;
        if !self.diagnostics.is_empty() {
            writeln!(f, "  diagnostics: {} entries", self.diagnostics.len())?;
        }
        Ok(())
    }
}

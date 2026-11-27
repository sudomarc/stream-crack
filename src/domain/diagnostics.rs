//! Non-fatal diagnostics produced while parsing untrusted captures.
//!
//! Diagnostics describe the file, never its payload bytes.

use serde::{Deserialize, Serialize};

/// One diagnostic associated with a byte offset (when known).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Byte offset of the offending construct, when known.
    pub offset: Option<u64>,
    /// Kind of diagnostic.
    pub kind: DiagnosticKind,
    /// Human-readable description.
    pub message: String,
}

/// Kind of diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticKind {
    /// A record header or payload was truncated mid-stream.
    TruncatedRecord,
    /// Captured length exceeded original length for a record.
    InconsistentLengths,
    /// A packet referenced an interface that was never described.
    UnknownInterface { interface_id: u32 },
    /// A capture announced a link type this release does not decode.
    UnknownLinkType { link_type: u32 },
    /// A block type this release does not interpret was skipped.
    UnknownBlock { block_type: u32 },
}

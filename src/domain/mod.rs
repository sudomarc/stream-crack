//! Domain model: sanitized capture summaries, frame metadata, diagnostics.
//!
//! The domain model contains no packet payloads and no secrets: it is the
//! only layer the TUI and reporting layers may consume.

mod capture;
mod diagnostics;
mod frame;

pub use capture::{CaptureFormat, CaptureSummary, InterfaceSummary};
pub use diagnostics::{Diagnostic, DiagnosticKind};
pub use frame::{
    FrameClassification, FrameKind, FrameMetadata, classify_link_type, link_type_name,
};

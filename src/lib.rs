//! StreamCrack: offline capture metadata inspector and synthetic protocol lab.
//!
//! StreamCrack is not a password-recovery tool. It parses PCAP and PCAPNG
//! capture files for metadata only, with bounded memory and explicit resource
//! limits. See `docs/` and `AGENTS.md` for scope and safety constraints.

pub mod app;
pub mod capture;
pub mod cli;
pub mod config;
pub mod domain;
pub mod error;

pub use app::{inspect, run};
pub use cli::Cli;
pub use config::{Config, Limits};
pub use domain::{
    CaptureFormat, CaptureSummary, Diagnostic, DiagnosticKind, FrameClassification, FrameKind,
    FrameMetadata, classify_link_type, link_type_name,
};
pub use error::{Error, Result};

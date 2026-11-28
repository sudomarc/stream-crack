//! StreamCrack: WPA2 Wi-Fi password auditing and recovery.
//!
//! StreamCrack implements offline PCAP/PCAPNG capture metadata inspection
//! (bounded parsing, link-type classification, sanitized reports,
//! keyboard-driven TUI), EAPOL handshake extraction, and offline WPA2 PSK
//! verification (PBKDF2-HMAC-SHA1, IEEE 802.11 PTK/KCK, MIC verification),
//! plus dictionary/mask cracking engines. See AGENTS.md for the product scope
//! and authorized-use boundaries.

pub mod app;
pub mod capture;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod engine;
pub mod error;
pub mod tui;

pub use app::{inspect, run};
pub use cli::Cli;
pub use config::{Config, Limits};
pub use domain::{
    CaptureFormat, CaptureSummary, Diagnostic, DiagnosticKind, FrameClassification, FrameKind,
    FrameMetadata, classify_link_type, link_type_name,
};
pub use error::{Error, Result};
pub use engine::{
    CandidateSource, CrackConfig, CrackEngine, CrackOutcome, MaskSource, StdinSource,
    WordlistSource,
};

//! Typed error model for StreamCrack.
//!
//! All capture data is treated as untrusted. Malformed input must yield an
//! error or diagnostic, never a panic.

use thiserror::Error;

/// Top-level error type for StreamCrack operations.
#[derive(Error, Debug)]
pub enum Error {
    /// I/O error while reading a capture file or writing a report.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A capture file is malformed and could not be parsed.
    #[error("malformed capture: {message}")]
    MalformedCapture { message: String },

    /// A record exceeded a configured resource limit.
    #[error("resource limit exceeded: {message}")]
    LimitExceeded { message: String },

    /// Byte-order or header validation failed.
    #[error("header validation failed: {message}")]
    HeaderValidation { message: String },

    /// The link type is not supported by any tested decoder.
    #[error("unsupported link type: {link_type}")]
    UnsupportedLinkType { link_type: u32 },

    /// A frame type is not classified by the protocol layer.
    #[error("unsupported frame type: {frame_type}")]
    UnsupportedFrameType { frame_type: u16 },

    /// Serialization error when exporting a report.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Configuration error.
    #[error("configuration error: {message}")]
    Configuration { message: String },
}

pub type Result<T> = std::result::Result<T, Error>;

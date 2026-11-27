//! Application configuration.
//!
//! Duration and size limits are expressed as primitive types so they can be
//! validated before any allocation.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Resource limits enforced before any allocation during capture parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum capture file size in bytes.
    pub max_file_size: u64,
    /// Maximum size of a single block in bytes.
    pub max_block_size: u64,
    /// Maximum size of a single packet in bytes.
    pub max_packet_size: u64,
    /// Maximum number of records to retain.
    pub max_record_count: u64,
    /// Maximum memory budget in bytes.
    pub max_memory: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_size: 256 * 1024 * 1024, // 256 MiB
            max_block_size: 64 * 1024 * 1024, // 64 MiB
            max_packet_size: 64 * 1024,       // 64 KiB
            max_record_count: 1_000_000,      // 1M records
            max_memory: 256 * 1024 * 1024,    // 256 MiB
        }
    }
}

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Input capture path.
    pub input: std::path::PathBuf,
    /// Optional output path for sanitized JSON report.
    pub output: Option<std::path::PathBuf>,
    /// Resource limits.
    pub limits: Limits,
}

impl Config {
    /// Validate the configuration before use.
    pub fn validate(&self) -> Result<()> {
        if self.limits.max_file_size == 0 {
            return Err(Error::Configuration {
                message: "max_file_size must be non-zero".to_string(),
            });
        }
        if self.limits.max_memory == 0 {
            return Err(Error::Configuration {
                message: "max_memory must be non-zero".to_string(),
            });
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            input: std::path::PathBuf::new(),
            output: None,
            limits: Limits::default(),
        }
    }
}

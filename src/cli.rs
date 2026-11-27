//! Command-line interface.
//!
//! The CLI is intentionally small and parsed by hand to keep the dependency
//! surface minimal: one positional capture path, an optional report output,
//! and two resource-limit overrides. StreamCrack does not recover passwords,
//! guess candidates, or interact with live networks.

use std::env;
use std::path::PathBuf;

use crate::config::{Config, Limits};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "Usage: streamcrack [OPTIONS] <FILE>

Inspect a local PCAP or PCAPNG capture file and print a sanitized metadata
summary.

Options:
  -o, --output FILE     Export a sanitized JSON report to FILE instead of
                        printing the human-readable summary.
  --max-file-size BYTES Maximum capture file size in bytes (default: 256 MiB).
  --max-memory BYTES    Maximum memory budget in bytes (default: 256 MiB).
  -h, --help            Print this help.
  -V, --version         Print version information.
";

/// Command-line arguments parsed from `std::env::args`.
pub struct Cli {
    /// Path to the local PCAP or PCAPNG capture file to inspect.
    pub input: PathBuf,

    /// Export a sanitized JSON report to this path.
    pub output: Option<PathBuf>,

    /// Maximum capture file size in bytes (default: 256 MiB).
    pub max_file_size: Option<u64>,

    /// Maximum memory budget in bytes (default: 256 MiB).
    pub max_memory: Option<usize>,
}

impl Cli {
    /// Parse command-line arguments from `std::env::args`.
    pub fn parse() -> Result<Self, String> {
        Self::parse_from(env::args().skip(1))
    }

    /// Parse command-line arguments from an iterator of strings. Used by
    /// tests (and reusable by other embedders).
    pub fn parse_from(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut args = args.into_iter().peekable();

        let mut input: Option<PathBuf> = None;
        let mut output: Option<PathBuf> = None;
        let mut max_file_size: Option<u64> = None;
        let mut max_memory: Option<usize> = None;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-o" | "--output" => {
                    output = Some(PathBuf::from(take_value(&mut args, "--output")?))
                }
                s if s.starts_with("--output=") => output = Some(PathBuf::from(&s[7..])),
                "--max-file-size" => {
                    max_file_size = Some(parse_size(&take_value(&mut args, "--max-file-size")?)?)
                }
                s if s.starts_with("--max-file-size=") => {
                    max_file_size = Some(parse_size(&s[16..])?)
                }
                "--max-memory" => {
                    max_memory = Some(parse_size(&take_value(&mut args, "--max-memory")?)? as usize)
                }
                s if s.starts_with("--max-memory=") => {
                    max_memory = Some(parse_size(&s[15..])? as usize)
                }
                "-h" | "--help" => {
                    print!("{USAGE}");
                    std::process::exit(0);
                }
                "-V" | "--version" => {
                    println!("streamcrack {VERSION}");
                    std::process::exit(0);
                }
                s if s.starts_with('-') => return Err(format!("unrecognized argument: {arg}")),
                _ => {
                    if input.is_some() {
                        return Err("unexpected positional argument".to_string());
                    }
                    input = Some(PathBuf::from(arg));
                }
            }
        }

        let input = input.ok_or_else(|| "missing input FILE".to_string())?;

        Ok(Self {
            input,
            output,
            max_file_size,
            max_memory,
        })
    }

    /// Convert the parsed CLI arguments into a [`Config`].
    pub fn into_config(self) -> Config {
        let mut limits = Limits::default();
        if let Some(max_file_size) = self.max_file_size {
            limits.max_file_size = max_file_size;
        }
        if let Some(max_memory) = self.max_memory {
            limits.max_memory = max_memory;
        }

        Config {
            input: self.input,
            output: self.output,
            limits,
        }
    }
}

/// Consume the next argument as a value for `flag`, or report an error.
fn take_value<I: Iterator<Item = String>>(
    args: &mut std::iter::Peekable<I>,
    flag: &str,
) -> Result<String, String> {
    args.next()
        .map(|value| {
            if value.starts_with('-') {
                return Err(format!("{flag} requires a value"));
            }
            Ok(value)
        })
        .unwrap_or_else(|| Err(format!("{flag} requires a value")))
}

/// Parse a decimal byte count from `text`.
fn parse_size(text: &str) -> Result<u64, String> {
    text.parse::<u64>()
        .map_err(|_| format!("invalid byte count: {text}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_requires_positional_input() {
        assert!(Cli::parse_from(vec![]).is_err());
    }

    #[test]
    fn parsing_accepts_input_and_flags() {
        let cli = Cli::parse_from(vec![
            "capture.pcap".to_string(),
            "-o".to_string(),
            "report.json".to_string(),
        ])
        .unwrap();
        assert_eq!(cli.input, PathBuf::from("capture.pcap"));
        assert_eq!(cli.output, Some(PathBuf::from("report.json")));
    }

    #[test]
    fn parsing_accepts_equals_form() {
        let cli = Cli::parse_from(vec![
            "capture.pcap".to_string(),
            "--max-file-size=2048".to_string(),
        ])
        .unwrap();
        assert_eq!(cli.max_file_size, Some(2048));
    }

    #[test]
    fn parsing_rejects_unrecognized_flags() {
        assert!(Cli::parse_from(vec!["capture.pcap".to_string(), "--bogus".to_string(),]).is_err());
    }

    #[test]
    fn parsing_rejects_missing_flag_values() {
        assert!(Cli::parse_from(vec!["capture.pcap".to_string(), "-o".to_string(),]).is_err());
    }
}

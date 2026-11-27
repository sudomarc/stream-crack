//! Application lifecycle and orchestration.
//!
//! The application ties together the CLI, configuration, capture reader,
//! protocol layer, domain model, TUI, and reporting. Layers remain decoupled:
//! capture and protocol layers do not depend on the TUI.

use std::fs::File;
use std::io::Write;
use std::process::ExitCode;

use crate::capture::CaptureReader;
use crate::cli::Cli;
use crate::config::Config;
use crate::domain::classify_link_type;
use crate::domain::{CaptureFormat, CaptureSummary, FrameMetadata};
use crate::error::{Error, Result};

/// Run the application from a parsed [`Cli`].
///
/// Returns an [`ExitCode`] suitable for the process exit status.
pub fn run(cli: Cli) -> ExitCode {
    let config = cli.into_config();
    if let Err(err) = config.validate() {
        eprintln!("configuration error: {err}");
        return ExitCode::FAILURE;
    }

    match inspect(&config) {
        Ok(summary) => {
            if let Some(output) = &config.output {
                if let Err(err) = write_report(&summary, output) {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            } else {
                print!("{summary}");
            }
            ExitCode::SUCCESS
        }
        Err(Error::Io(err)) => {
            eprintln!("I/O error: {err}");
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Inspect a capture file according to [`Config`].
///
/// This is the top-level entry point for the data flow:
/// local path -> bounded reader -> validated records -> metadata classifier ->
/// sanitized domain model -> TUI and/or JSON report.
pub fn inspect(config: &Config) -> Result<CaptureSummary> {
    let metadata = std::fs::metadata(&config.input)?;
    if metadata.len() > config.limits.max_file_size {
        return Err(Error::LimitExceeded {
            message: format!(
                "capture file {} is {} bytes, exceeds max_file_size {}",
                config.input.display(),
                metadata.len(),
                config.limits.max_file_size
            ),
        });
    }

    let file = File::open(&config.input)?;
    let mut reader = CaptureReader::new(file, &config.limits)?;

    let format = match reader.format() {
        crate::capture::CaptureFormat::Pcap => CaptureFormat::Pcap,
        crate::capture::CaptureFormat::Pcapng => CaptureFormat::Pcapng,
    };
    let link_types = reader.link_types();

    let mut summary = CaptureSummary {
        source: config.input.clone(),
        format,
        link_types: link_types.clone(),
        packet_count: 0,
        captured_bytes: 0,
        offered_bytes: 0,
        first_timestamp: None,
        last_timestamp: None,
        diagnostics: Vec::new(),
        frames: Vec::new(),
    };

    for record in &mut reader {
        let record = record?;

        if summary.packet_count >= config.limits.max_record_count {
            return Err(Error::LimitExceeded {
                message: format!(
                    "record count exceeds max_record_count {}",
                    config.limits.max_record_count
                ),
            });
        }

        summary.packet_count += 1;
        summary.captured_bytes += u64::from(record.caplen);
        summary.offered_bytes += u64::from(record.orig_len);
        summary.first_timestamp = summary.first_timestamp.or(Some(record.timestamp));
        summary.last_timestamp = Some(record.timestamp);

        summary.frames.push(FrameMetadata {
            index: record.index,
            timestamp: record.timestamp,
            caplen: record.caplen,
            orig_len: record.orig_len,
            link_type: record.link_type,
            classification: classify_link_type(record.link_type),
        });
    }

    summary.diagnostics = reader.diagnostics().to_vec();
    Ok(summary)
}

/// Write a sanitized JSON report of `summary` to `output`.
///
/// Only metadata is serialized: no packet payloads, keys, or credentials.
fn write_report(summary: &CaptureSummary, output: &std::path::Path) -> Result<()> {
    let mut file = File::create(output)?;
    serde_json::to_writer_pretty(&mut file, summary)?;
    file.write_all(b"\n")?;
    Ok(())
}

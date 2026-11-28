//! Application entry point for the `streamcrack` binary.
//!
//! StreamCrack is an offline WPA2 Wi-Fi password auditing and recovery tool.
//! It inspects PCAP/PCAPNG capture files for metadata, extracts WPA2 4-way
//! handshakes, and performs authorized offline PSK recovery (dictionary/mask
//! cracking) against captured handshakes. It does not perform live capture,
//! packet injection, or deauthentication.

use std::process::ExitCode;

use streamcrack::app;
use streamcrack::cli::Cli;

fn main() -> ExitCode {
    // Tracing is initialized here once the logging story lands (Phase 5).
    let cli = match Cli::parse() {
        Ok(cli) => cli,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    app::run(cli)
}

//! Application entry point for the `streamcrack` binary.
//!
//! StreamCrack is an offline capture-metadata inspector. It does not implement
//! password recovery, wordlists, brute force, candidate generation against real
//! captures, GPU cracking, live capture, packet injection, or deauthentication.

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

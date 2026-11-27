# StreamCrack

StreamCrack is a Rust TUI project focused on WPA2 Wi-Fi password auditing and recovery.

Its product objective is to help authorized users assess the security of their own wireless networks and recover access credentials in legitimate, controlled contexts. It is not merely a capture-metadata viewer.

## Product direction
- WPA2-focused wireless security auditing and password recovery.
- Offline workflows and local processing.
- A keyboard-driven terminal interface (TUI).
- Efficient operation on resource-constrained computers.
- Clear reporting, predictable resource usage, and safe handling of input files.

## Technology
- Language: Rust
- Target protocol: WPA2
- Interface: TUI

Exact implementation choices and supported workflows are tracked in the technical specification and roadmap.

## Development checks
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --all-targets
    cargo build --release

## Documentation
- Technical specification: docs/SPECIFICATION.md
- Architecture: docs/ARCHITECTURE.md
- Roadmap: docs/ROADMAP.md
- Supported formats: docs/FORMATS.md
- Threat model: docs/THREAT_MODEL.md
- Testing strategy: docs/TESTING.md
- Contributing: CONTRIBUTING.md
- Security: SECURITY.md
- Agent instructions: AGENTS.md

## License
No license has been selected yet. All rights are reserved by default until a license is added.

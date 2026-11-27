# StreamCrack

Rust TUI for offline inspection of WPA2-related capture metadata and controlled, synthetic protocol experiments.

**Safety boundary:** StreamCrack is not a password-recovery tool. It will not implement dictionary attacks, brute force, candidate generation against real captures, GPU cracking, live capture, packet injection, or deauthentication. Real captures are parsed for metadata only; cryptographic known-answer tests use synthetic fixtures.

## Goals
- Parse PCAP and PCAPNG with bounded memory.
- Validate records and safely handle malformed input.
- Classify supported 802.11/EAPOL metadata without recovering credentials.
- Browse captures in a Ratatui TUI.
- Run deterministic synthetic protocol tests.
- Export sanitized JSON summaries.

## Planned stack
Rust 2024, Clap, Ratatui, Crossterm, a maintained PCAP parser, Serde, thiserror, tracing, and narrowly scoped zeroization where applicable. Dependency versions will be selected during bootstrap.

## Status
Initial project setup. See [specification](docs/SPECIFICATION.md), [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md), and [security policy](SECURITY.md).

## Development checks
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release
```

## Documentation
- [Technical specification](docs/SPECIFICATION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [Supported formats](docs/FORMATS.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Testing strategy](docs/TESTING.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Agent instructions](AGENTS.md)

## License
No license has been selected yet. All rights are reserved by default until a license is added.

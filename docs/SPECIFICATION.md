# Technical Specification

## Product
A local Rust TUI for inspecting WPA2-related capture metadata and running controlled synthetic protocol experiments. It does not recover passwords or verify guesses against real captures.

## Functional requirements
- FR-01: Open explicit local PCAP and PCAPNG paths.
- FR-02: Enforce configurable file, record, packet, block, and memory limits.
- FR-03: Validate headers, lengths, byte order, timestamps, link types, and truncation.
- FR-04: Decode supported 802.11/EAPOL metadata safely.
- FR-05: Classify handshake-related frame sequences as metadata only.
- FR-06: Display summaries, timelines, warnings, and diagnostics in a keyboard-driven TUI.
- FR-07: Export sanitized JSON.
- FR-08: Provide deterministic synthetic fixtures and known-answer tests.
- FR-09: Exit cleanly on malformed input, cancellation, and terminal resize.

## Non-functional requirements
- No runtime network access.
- Bounded memory and streaming parsing.
- No panics on malformed input.
- No sensitive payloads or secrets in logs/reports.
- Deterministic tests without private captures.
- Unknown formats and frame types are reported explicitly.

## Initial defaults
- Rust edition 2024; Linux x86_64 as first validation target.
- Ratatui + Crossterm TUI; Clap CLI.
- PCAP and PCAPNG input.
- Initial memory budget: 256 MiB, configurable and enforced.
- JSON reporting.
- Offline operation only.

## Acceptance criteria
A release candidate must inspect supported files, reject malformed input safely, enforce resource limits, classify supported metadata, pass synthetic tests, provide usable keyboard navigation, and emit sanitized reports. Credential recovery is explicitly excluded.

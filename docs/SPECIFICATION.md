# Technical Specification

## Product definition
StreamCrack is a Rust terminal application whose intended product objective is WPA2 Wi-Fi password auditing and recovery in authorized environments. Capture inspection is a supporting capability, not the product's end goal.

## Product requirements
- PR-01: Provide a keyboard-driven terminal interface.
- PR-02: Support local, offline workflows.
- PR-03: Treat input files and protocol data as untrusted.
- PR-04: Provide clear status, diagnostics, and results reporting.
- PR-05: Operate predictably on resource-constrained computers.
- PR-06: Keep protocol handling, application logic, and presentation decoupled.
- PR-07: Document supported inputs, limitations, and resource requirements.
- PR-08: Include deterministic automated tests and reproducible test fixtures.
- PR-09: Handle malformed input and cancellation without crashing.
- PR-10: Make authorization and responsible-use expectations explicit.

## Non-functional requirements
- Local-first operation; no network dependency required for ordinary use.
- Bounded memory and explicit resource limits.
- Robust error handling and no panics on malformed input.
- No unnecessary disclosure of sensitive data in logs or reports.
- Maintainable Rust code and a reviewed dependency set.
- Tests must be reproducible and must not contain private user data.

## Initial technical decisions
- Language: Rust.
- Target protocol: WPA2.
- Interface: TUI.
- Initial platform: Linux x86_64; portability to be evaluated.
- Input formats and detailed compatibility matrix: to be finalized during implementation planning.

## Acceptance criteria
A release candidate must have a usable TUI, documented compatibility, robust input handling, bounded resource use, reproducible tests, and clear reporting. Product scope is WPA2 password auditing and recovery; it must not be redefined as metadata inspection alone.

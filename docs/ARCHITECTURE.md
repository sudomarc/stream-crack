# Architecture

## Product objective
StreamCrack is intended for WPA2 Wi-Fi password auditing and recovery in authorized environments. The architecture must support a local-first Rust application with a terminal UI and efficient resource use.

## Architectural components
1. CLI/application: argument parsing, configuration, lifecycle, and error propagation.
2. Input layer: local file access, format identification, validation, and resource limits.
3. Protocol domain: typed WPA2-related data structures and protocol-level validation.
4. Core domain: workflow state, results, diagnostics, and application policies.
5. Execution layer: isolated processing components with explicit resource budgets and cancellation.
6. TUI: Ratatui screens, keyboard navigation, progress, and event handling.
7. Reporting: structured summaries with deliberate handling of sensitive information.

## Dependency direction
The core domain must not depend on the TUI. Input and protocol layers expose validated types to application workflows. TUI and reporting consume application state and domain results.

## Proposed layout
    src/
      main.rs
      app.rs
      cli.rs
      config.rs
      error.rs
      domain/
      input/
      protocol/
      engine/
      tui/
      report/
    tests/
      fixtures/
      input_validation.rs
      protocol_validation.rs
      resource_limits.rs
      report_sanitization.rs

## Engineering constraints
- Validate lengths and offsets with checked arithmetic.
- Enforce explicit file, record, and memory limits.
- Support cancellation and report progress for long-running work.
- Keep sensitive values out of routine logs.
- Use typed errors and avoid panics on malformed input.
- Keep tests deterministic and free of private captures.

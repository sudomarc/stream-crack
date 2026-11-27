# Architecture

## Components
1. **CLI/application:** arguments, configuration, lifecycle, error propagation.
2. **Capture reader:** streaming PCAP/PCAPNG parsing, validation, resource limits.
3. **Protocol layer:** bounded decoding and classification of supported 802.11/EAPOL metadata.
4. **Domain model:** capture summaries, frame metadata, warnings, diagnostics.
5. **Laboratory:** synthetic fixtures and known-answer tests only.
6. **TUI:** Ratatui screens and keyboard event handling.
7. **Reporting:** sanitized JSON serialization.

## Dependency direction
Capture and protocol layers must not depend on the TUI. TUI and reporting consume sanitized domain models. The synthetic laboratory remains separate from real-capture inspection.

## Proposed layout
```text
src/
  main.rs
  app.rs
  cli.rs
  config.rs
  error.rs
  domain/{mod.rs,capture.rs,frame.rs,diagnostics.rs}
  capture/{mod.rs,reader.rs,pcap.rs,pcapng.rs,limits.rs}
  protocol/{mod.rs,ieee80211.rs,eapol.rs,classifier.rs}
  laboratory/{mod.rs,fixtures.rs,vectors.rs}
  tui/{mod.rs,app.rs,events.rs,screens/}
  report/{mod.rs,json.rs}
tests/
  fixtures/
  capture_parser.rs
  protocol_classifier.rs
  memory_limits.rs
  report_sanitization.rs
```

## Data flow
Local path -> bounded reader -> validated records -> metadata classifier -> sanitized domain model -> TUI and/or JSON report.

## Error model
Use typed errors for I/O, malformed files, unsupported link types, resource limits, unsupported frame types, and serialization. Malformed input must yield an error or diagnostic, never a panic.

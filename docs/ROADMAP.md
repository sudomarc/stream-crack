# Roadmap

Dates are intentionally omitted until implementation velocity is known.

## Phase 0 — Foundation
- [x] Rust crate, CLI skeleton, toolchain policy.
- [x] Formatting, Clippy, tests, and CI.
- [x] Configuration and typed error model.

## Phase 1 — Capture ingestion
- [ ] PCAP reader with byte-order and header validation.
- [ ] PCAPNG reader with section/interface/block validation.
- [ ] Streaming iteration and explicit resource limits.
- [ ] Malformed/truncated-input regression fixtures.

## Phase 2 — Protocol metadata
- [ ] Safe 802.11 header decoding.
- [ ] EAPOL metadata extraction.
- [ ] Handshake-related frame classification without credential verification.
- [ ] Document supported and unsupported frame/link types.

## Phase 3 — Synthetic laboratory
- [ ] Synthetic fixture schema and provenance.
- [ ] Deterministic known-answer tests.
- [ ] Strict separation from real-capture workflows.

## Phase 4 — TUI and reports
- [ ] Dashboard and capture browser.
- [ ] Frame timeline and diagnostics views.
- [ ] Keyboard navigation and resize handling.
- [ ] Sanitized JSON export.

## Phase 5 — Hardening and release
- [ ] Parser fuzzing.
- [ ] Memory/resource-limit tests.
- [ ] Logging and report-redaction audit.
- [ ] Release workflow and user documentation.

## Definition of done
Implementation, tests, docs, formatting, Clippy, and relevant resource/security checks are complete. PRs report exact commands and outcomes.

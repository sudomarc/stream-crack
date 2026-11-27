# Roadmap

StreamCrack's product objective is WPA2 Wi-Fi password auditing and recoverys. The phases below organize the project foundation and supporting engineering work; they do not redefine the product as a metadata-only inspector.

## Phase 0 — Project foundation
- [x] Rust project and repository documentation.
- [x] Initial technical direction: Rust, WPA2, TUI.
- [ ] Confirm supported operating systems and toolchain.
- [ ] Establish CI, formatting, linting, and test baselines.

## Phase 1 — Application foundation
- [ ] CLI, configuration, and typed error model.
- [ ] TUI shell, navigation, and application state.
- [ ] Progress reporting and cancellation.
- [ ] Resource-budget configuration.

## Phase 2 — Input and protocol foundations
- [ ] Define supported input formats and compatibility matrix.
- [ ] Implement robust format identification and validation.
- [ ] Add protocol-domain types and validation tests.
- [ ] Add malformed-input and resource-exhaustion tests.

## Phase 3 — Core workflow integration
- [ ] Define workflow interfaces and lifecycle.
- [ ] Integrate core processing with the application state.
- [ ] Add clear progress, diagnostics, and result presentation.
- [ ] Document operational assumptions and authorized-use expectations.

## Phase 4 — Quality and performance
- [ ] Benchmark general application overhead and input processing.
- [ ] Profile memory use on constrained hardware.
- [ ] Add regression and fuzz testing for parsers.
- [ ] Audit logging and sensitive-data handling.

## Phase 5 — Release readiness
- [ ] Complete user documentation.
- [ ] Validate supported platforms.
- [ ] Establish reproducible release builds.
- [ ] Publish known limitations and security reporting guidance.

## Definition of done
Each change includes tests appropriate to its behavior, updated documentation, formatting and lint checks, and a report of commands actually run.

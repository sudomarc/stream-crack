# Testing Strategy

Testing must support StreamCrack's WPA2 auditing and recovery product direction.

## Test layers
- Unit: configuration, validation, typed errors, protocol-domain types, state transitions, and redaction.
- Input integration: valid, empty, truncated, malformed, unsupported, and oversized files.
- Protocol validation: documented protocol fixtures and boundary conditions.
- Resource: file, record, packet, and memory limits; cancellation; adversarial length fields.
- TUI: navigation, resize handling, progress, error states, and result presentation.
- Regression: every confirmed defect receives a focused regression test.
- CI: formatting, Clippy with warnings denied, tests, and release build.

## Fixture policy
Use synthetic or redistributable fixtures with documented provenance. Never commit private captures, credentials, or personal traffic.

## Reporting
Record the exact commands run and their outcomes. Do not describe unexecuted checks as passing.

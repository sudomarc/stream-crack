# Security Policy

## In-scope reports
Parser crashes, memory-safety defects, malformed-input handling, resource exhaustion, unsafe logging, report-redaction failures, and vulnerable dependencies.

## Reporting
Do not publish sensitive details in public issues. Use GitHub private vulnerability reporting if enabled; otherwise contact the maintainers privately through the repository profile.

## Data handling
Capture files are untrusted. Never upload private traffic, credentials, keys, or sensitive payloads to public issues or CI. Only synthetic or redistributable fixtures may be committed. Reports and logs must avoid payload and secret disclosure.

StreamCrack is not a credential-recovery tool. Security fixes must not add password guessing or attack automation.

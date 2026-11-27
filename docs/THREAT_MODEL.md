# Threat Model

## Product context
StreamCrack is intended for WPA2 Wi-Fi password auditing and recovery in authorized environments. Its local processing model and handling of potentially sensitive wireless data create security and privacy risks that must be addressed.

## Assets
- User-provided capture and input files.
- Recovered or otherwise sensitive credential material.
- Process availability and memory safety.
- Integrity of protocol interpretation and reported results.
- Local configuration and generated reports.

## Trust boundaries
Input files, filenames, timestamps, packet fields, and external fixtures are untrusted. They may be malformed, adversarial, oversized, or contain private information.

## Threats and mitigations
- Malformed input: checked arithmetic, bounds validation, typed errors, and regression tests.
- Resource exhaustion: streaming where appropriate, explicit limits, cancellation, and bounded buffers.
- Parser vulnerabilities: fuzzing and malformed-input tests.
- Sensitive-data leakage: minimize logging, protect generated output, and document retention behavior.
- Misleading results: explicit status and error states; avoid claiming certainty beyond validated evidence.
- Dependency compromise: minimize dependencies, review updates, and audit the lockfile.
- Unauthorized use: document that users are responsible for having authorization to assess the networks and data they use.

## Data handling
Do not commit private captures, credentials, or sensitive payloads. Tests and CI fixtures must be synthetic or redistributable. Reports should disclose only information needed by the user.

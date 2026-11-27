# Threat Model

## Assets
Capture confidentiality, process availability, memory safety, metadata integrity, report confidentiality, and CI integrity.

## Trust boundaries
Capture bytes, filenames, timestamps, packet fields, and external fixture files are untrusted and may be malformed, adversarial, or oversized.

## Threats and mitigations
- Integer overflow/out-of-bounds: checked arithmetic and bounds validation.
- Resource exhaustion: streaming, explicit limits, bounded buffers.
- Parser crashes: fuzzing and malformed-input tests.
- Sensitive-data leakage: metadata-only display, sanitized reports, no payload logging.
- Misclassification: explicit support matrix and unknown classifications.
- Dependency compromise: minimal dependencies, lockfile review, CI auditing.

Credential recovery, live network attacks, and packet injection are out of scope.

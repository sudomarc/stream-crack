# Testing Strategy

- **Unit:** byte order, header validation, checked lengths, timestamps, frame classification, redaction.
- **Integration:** synthetic valid, empty, truncated, malformed, unsupported-link, and mixed-record PCAP/PCAPNG files.
- **Fuzzing:** file headers, block/packet iteration, and bounded frame-header decoders.
- **Resource:** maximum file, block, packet, record, and memory limits; adversarial length fields.
- **Protocol lab:** synthetic known-answer vectors with documented provenance only.
- **CI:** format, Clippy with warnings denied, tests, and release build.

No private captures or credential-guessing test targets are permitted.

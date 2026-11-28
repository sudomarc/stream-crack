# Agent Instructions

Read this file and relevant `docs/` before every task. This file is the project's authoritative agent policy.

## Scope

StreamCrack is a Rust TUI project for WPA2 Wi-Fi password auditing and recovery, operating locally and offline.

Product purpose (decided): WPA2 password auditing and password recovery. Offline PCAP/PCAPNG capture inspection (bounded metadata parsing, link-type classification, sanitized reporting, keyboard-driven TUI) is the implemented foundation and a supporting capability, not the product's end goal.

Current state vs. plans:
- Implemented: PCAP and PCAPNG reading with checked arithmetic, bounded memory, and explicit resource limits; typed error model; sanitized metadata-only reports (JSON and human-readable); keyboard TUI with summary, frames, and help screens; CLI with `--tui` mode; WPA2 4-way-handshake extraction from 802.11 data frames (link types 105/127); offline PSK verification (PBKDF2-HMAC-SHA1 PMK, IEEE 802.11 PTK/KCK, SHA-1 MIC verification) and offline dictionary/mask cracking with candidate caps, progress reporting, and cancellation.
- Not yet implemented: rule-based candidate generation (masks are supported), PMKID attack paths, WPA3. Live capture, injection, and deauthentication remain out of scope and will never be added.

Boundaries that always apply (authorized, local, offline use only):
- Never implement live capture, injection, or deauthentication.
- Never perform candidate generation or cracking against real user captures; use synthetic fixtures with documented provenance only.
- Never log credentials, keys, or packet payloads unnecessarily.
- Users are responsible for having authorization to assess the networks and data they assess.

## Engineering requirements
1. Inspect existing code, tests, and git status before editing.
2. Treat capture files and all parsed fields as untrusted input.
3. Validate lengths and offsets with checked arithmetic before indexing or allocating.
4. Enforce explicit file, block, packet, record-count, and memory limits.
5. Keep parsing, protocol classification, domain models, TUI, and reporting decoupled.
6. Never log credentials, keys, or packet payloads unnecessarily.
7. Use synthetic fixtures only; document vector provenance.
8. Add regression tests for bugs and boundary conditions.
9. Minimize dependencies and explain additions.
10. Keep documentation synchronized with behavior.

## Validation
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
git diff --check
```

Report exactly which commands were run and their outcomes. Never claim unrun checks passed. Before completion inspect the diff and ensure no secrets, private captures, or generated build artifacts were committed.

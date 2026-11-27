# Agent Instructions

Read this file and relevant `docs/` before every task. This file is the project's authoritative agent policy.

## Scope
StreamCrack is an offline capture-inspection tool and synthetic-only protocol laboratory. Do not implement password recovery, wordlists, dictionary attacks, brute force, masks, cracking rules, candidate generation against real captures, GPU cracking, live capture, injection, or deauthentication.

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

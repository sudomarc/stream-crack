# Contributing

StreamCrack is a Rust TUI project focused on WPA2 Wi-Fi password auditing and recovery. Contributions should preserve this product direction rather than recasting the project as a metadata-only capture viewer.

## Workflow
1. Read AGENTS.md, SECURITY.md, and the relevant specification.
2. Check existing issues before starting substantial work.
3. Keep pull requests focused and include regression tests.
4. Explain design choices, resource implications, and dependency additions.
5. Update documentation whenever behavior or supported formats change.
6. Do not submit private captures, credentials, or sensitive traffic.

## Required checks
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --all-targets

## Pull request requirements
Describe the problem, implementation, linked issue, tests, commands actually run, compatibility implications, and security/resource impact. State any limitations clearly and do not claim checks passed unless they were run.

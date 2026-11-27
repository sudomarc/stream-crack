# Contributing

1. Read `AGENTS.md`, `SECURITY.md`, and the relevant specification.
2. Check existing issues before starting substantial work.
3. Keep pull requests focused and include regression tests.
4. Explain design choices, resource implications, and dependency additions.
5. Update documentation whenever behavior or supported formats change.

## Required checks
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

## Pull request requirements
Describe the problem, implementation, linked issue, tests, commands actually run, compatibility implications, and security/resource impact. Do not attach private capture files.

## Out of scope
Credential recovery, dictionary/candidate generation against real captures, brute force, masks, GPU cracking, live capture, packet injection, and deauthentication are not accepted contributions.

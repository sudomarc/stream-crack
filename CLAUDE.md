# Claude Code Instructions

Read `AGENTS.md` first; it is authoritative. Read the relevant documents in `docs/` before implementation.

Keep StreamCrack within its defined scope: offline capture metadata inspection and synthetic-only protocol tests. Never implement credential recovery, password guessing, candidate generation against real captures, wordlists, brute force, GPU cracking, live capture, packet injection, or deauthentication.

Prioritize parser safety, bounded memory, deterministic tests, sanitized reports, and maintainable Rust. Treat all capture data as untrusted. Run the validation commands in AGENTS.md and report actual results.

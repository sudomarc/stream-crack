# Claude Code Instructions

Read `AGENTS.md` first; it is authoritative. Read the relevant documents in `docs/` before implementation.

StreamCrack is a Rust TUI project for WPA2 Wi-Fi password auditing and recovery, operating locally and offline.

Implemented: bounded PCAP/PCAPNG metadata inspection, link-type classification, sanitized reporting, keyboard-driven TUI, WPA2 4-way-handshake extraction (802.11 link types 105/127), offline PSK verification (PBKDF2-HMAC-SHA1 PMK, IEEE 802.11 PTK/KCK, SHA-1 MIC), and offline dictionary/mask cracking with candidate caps, progress reporting, and cancellation.

Offline dictionary/mask cracking against captured handshakes is within scope only when performed on stations you own or are explicitly authorized to test — per the engagement mandate on disk at /home/marco/Downloads/wpa2_password_recovery_engagement_scope.md.

Never perform cracking against real user captures without written authorization; use synthetic fixtures for tests. Never implement live capture, injection, or deauthentication. Never log credentials, keys, or packet payloads unnecessarily.

Prioritize parser safety, bounded memory, deterministic tests, sanitized reports, and maintainable Rust. Treat all capture data as untrusted. Run the validation commands in AGENTS.md and report actual results.

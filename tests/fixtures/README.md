//! Synthetic WPA2 handshake fixture and wordlist for recovery tests.
//!
//! Provenance (synthetic, not real user data):
//!   * smoke-handshake.pcap: generated programmatically for StreamCrack testing.
//!     Contains one 802.11 beacon (SSID "SmokeNet") plus two EAPOL-Key frames
//!     (ANonce = 0xAA*32, SNonce = 0xBB*32, MIC computed with KCK derived from
//!     PSK "smoketest2026"). No real capture, no real password, no real network.
//!   * smoke-wordlist.txt: three dummy candidates (aaaa, smoketest2026, zzzz).
//!
//! These fixtures exist solely to exercise the --crack path deterministically.
//! Never commit private captures, credentials, or personal traffic here.

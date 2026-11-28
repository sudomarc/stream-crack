//! WPA2 protocol domain: handshakes, nonces, MIC verification primitives.
//!
//! Everything here is protocol-level: candidate passwords are tested against
//! extracted WPA2 metadata (SSID, MACs, nonces, MIC), never against live
//! traffic.

use serde::{Deserialize, Serialize};
use std::fmt;

/// WPA2 pre-shared key candidate (the password under test).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PskCandidate {
    pub password: Vec<u8>,
}

/// MAC address (Ethernet / 802.11 station or AP address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xFF; 6]);

    pub fn from_bytes(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5]
        )
    }
}

/// 32-byte nonce used in the 4-way handshake (ANonce / SNonce).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce([u8; 32]);

impl Nonce {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// One captured EAPOL-Key message (M1..M4 of the WPA2 4-way handshake).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EapolFrame {
    /// 802.1X key descriptor version: 1 = WPA1 (TKIP), 2 = WPA2/RSN (AES-CCMP).
    pub descriptor_type: u8,
    /// Key information field (key type, key MIC, secure, error, request…).
    pub key_info: u16,
    /// Key length.
    pub key_length: u16,
    /// Replay counter (8 bytes).
    pub replay_counter: [u8; 8],
    /// Key nonce (32 bytes).
    pub key_nonce: Nonce,
    /// Key MIC (16 bytes) as captured, ready for verification.
    pub key_mic: [u8; 16],
    /// Offset of key_mic within `raw` for zeroing before MIC recomputation.
    pub mic_offset_within_raw: usize,
    /// Raw EAPOL packet bytes (EAPOL header + key descriptor body), MIC included.
    pub raw: Vec<u8>,
}

/// WPA2 4-way handshake metadata sufficient to verify a PSK candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    pub ssid: Vec<u8>,
    pub ap_mac: MacAddr,
    pub sta_mac: MacAddr,
    pub a_nonce: Nonce,
    pub s_nonce: Nonce,
    /// EAPOL M2 (authenticator -> supplicant) carries the MIC we verify against.
    pub m2: EapolFrame,
}

/// Outcome of testing one candidate against one handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrackResult {
    Success { password: Vec<u8> },
    Failed,
}

//! WPA2 cryptography primitives.
//!
//! IEEE 802.11-2012 / 802.1X-2001 constructions, offline use only:
//!   PMK  = PBKDF2-HMAC-SHA1(password, SSID, 4096, 32)
//!   PTK  = PRF-512(PMK, "Pairwise key expansion", sorted(AA,SPA)+sorted(ANonce,SNonce), 64)
//!   KCK  = PTK[0..16]
//!   MIC  = first 16 bytes of HMAC-SHA1(KCK, EAPOL frame with Key MIC zeroed)
//!
//! Sorting addresses and nonces before the PRF makes verification identical
//! whichever side of the handshake is the authenticator or supplicant.

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha1::Sha1;

use crate::domain::wpa2::{
    CrackResult, Handshake, MacAddr, Nonce, PskCandidate,
};

type HmacSha1 = Hmac<Sha1>;

const PBKDF2_ITERATIONS: u32 = 4096;
const PMK_LEN: usize = 32;
const PTK_LEN: usize = 64;
const KCK_LEN: usize = 16;
const MIC_LEN: usize = 16;
const PRF_LABEL: &[u8] = b"Pairwise key expansion";

/// PMK from a candidate PSK and the network SSID (salt).
pub fn pmk_from_psk(password: &[u8], ssid: &[u8]) -> [u8; PMK_LEN] {
    let mut pmk = [0u8; PMK_LEN];
    pbkdf2::<HmacSha1>(password, ssid, PBKDF2_ITERATIONS, &mut pmk);
    pmk
}

/// IEEE 802.11 SHA1-PRF.
///
/// A_0 = HMAC-SHA1(K, label || 0x00 || message)
/// A_i = HMAC-SHA1(K, A_{i-1}) for i >= 1
/// result = A_0 || A_1 || ... truncated to `out_len` bytes.
fn sha1_prf(key: &[u8], label: &[u8], message: &[u8], out_len: usize) -> Vec<u8> {
    let mut header = Vec::with_capacity(label.len() + 1 + message.len());
    header.extend_from_slice(label);
    header.push(0x00);
    header.extend_from_slice(message);

    let mut a = {
        let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&header);
        mac.finalize().into_bytes().to_vec()
    };

    let mut out = Vec::with_capacity(out_len);
    while out.len() < out_len {
        let remaining = out_len - out.len();
        let take = remaining.min(a.len());
        out.extend_from_slice(&a[..take]);
        if out.len() < out_len {
            let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(&a);
            a = mac.finalize().into_bytes().to_vec();
        }
    }
    out
}

/// Concatenate `a` and `b` in ascending lexicographic order.
fn sorted_concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    if a <= b {
        out.extend_from_slice(a);
        out.extend_from_slice(b);
    } else {
        out.extend_from_slice(b);
        out.extend_from_slice(a);
    }
    out
}

/// Pairwise Transient Key (64 bytes): KCK(16) || KEK(16) || TK(32).
pub fn compute_ptk(
    pmk: &[u8; PMK_LEN],
    aa: &MacAddr,
    spa: &MacAddr,
    a_nonce: &Nonce,
    s_nonce: &Nonce,
) -> [u8; PTK_LEN] {
    let mut message = sorted_concat(&aa.as_bytes(), &spa.as_bytes());
    message.extend_from_slice(&sorted_concat(&a_nonce.as_bytes(), &s_nonce.as_bytes()));

    let out = sha1_prf(pmk, PRF_LABEL, &message, PTK_LEN);
    let mut ptk = [0u8; PTK_LEN];
    ptk.copy_from_slice(&out.as_slice());
    ptk
}

/// Key Confirmation Key: PTK[0..16].
pub fn kck_for_ptk(ptk: &[u8; PTK_LEN]) -> [u8; KCK_LEN] {
    let mut kck = [0u8; KCK_LEN];
    kck.copy_from_slice(&ptk[0..KCK_LEN]);
    kck
}

/// MIC over an EAPOL-Key frame whose Key MIC field has been zeroed.
///
/// `frame` covers the whole captured EAPOL packet; only `frame_len` bytes are
/// authenticated (protects against trailing padding). Malformed frames
/// (`frame_len > frame.len()`) yield an all-zero MIC rather than panicking.
pub fn compute_mic(kck: &[u8; KCK_LEN], frame: &[u8], frame_len: usize) -> [u8; MIC_LEN] {
    let len = frame_len.min(frame.len());
    let mut mac = HmacSha1::new_from_slice(kck).expect("HMAC accepts any key length");
    mac.update(&frame[..len]);
    let digest = mac.finalize().into_bytes();
    let mut mic = [0u8; MIC_LEN];
    mic.copy_from_slice(&digest[..MIC_LEN]);
    mic
}

/// Test one candidate password against a captured 4-way handshake.
///
/// Verifies the MIC carried in handshake M2. Returns [`CrackResult::Success`]
/// when a derived MIC matches the captured one. Malformed handshakes (MIC
/// offset outside the captured frame) yield [`CrackResult::Failed`].
pub fn verify_handshake(handshake: &Handshake, candidate: &PskCandidate) -> CrackResult {
    let pmk = pmk_from_psk(&candidate.password, &handshake.ssid);
    let ptk = compute_ptk(
        &pmk,
        &handshake.ap_mac,
        &handshake.sta_mac,
        &handshake.a_nonce,
        &handshake.s_nonce,
    );
    let kck = kck_for_ptk(&ptk);

    let mic_offset = handshake.m2.mic_offset_within_raw;
    if mic_offset + MIC_LEN > handshake.m2.raw.len() {
        return CrackResult::Failed;
    }

    let mut raw = handshake.m2.raw.clone();
    raw[mic_offset..mic_offset + MIC_LEN].fill(0);

    let mic = compute_mic(&kck, &raw, raw.len());
    if mic == handshake.m2.key_mic {
        CrackResult::Success {
            password: candidate.password.clone(),
        }
    } else {
        CrackResult::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::wpa2::EapolFrame;

    fn handshake(ssid: &[u8], password: &[u8]) -> (Handshake, PskCandidate) {
        let ssid = ssid.to_vec();
        let pmk = pmk_from_psk(password, &ssid);
        let ap = MacAddr::from_bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let sta = MacAddr::from_bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let a_nonce = Nonce::from_bytes([0x11u8; 32]);
        let s_nonce = Nonce::from_bytes([0x22u8; 32]);
        let ptk = compute_ptk(&pmk, &ap, &sta, &a_nonce, &s_nonce);
        let kck = kck_for_ptk(&ptk);

        // Synthetic EAPOL M2: header(4) + RSN descriptor body, MIC at offset 81.
        let mut raw = vec![0u8; 112];
        raw[0] = 2; // EAPOL version 2
        raw[1] = 3; // EAPOL-Key
        raw[4] = 2; // RSN descriptor
        let mic_offset = 81usize;
        let mic = compute_mic(&kck, &raw, raw.len());
        raw[mic_offset..mic_offset + MIC_LEN].copy_from_slice(&mic);

        let m2 = EapolFrame {
            descriptor_type: 2,
            key_info: 0,
            key_length: 0,
            replay_counter: [0; 8],
            key_nonce: s_nonce,
            key_mic: mic,
            mic_offset_within_raw: mic_offset,
            raw,
        };
        let handshake = Handshake {
            ssid,
            ap_mac: ap,
            sta_mac: sta,
            a_nonce,
            s_nonce,
            m2,
        };
        let candidate = PskCandidate {
            password: password.to_vec(),
        };
        (handshake, candidate)
    }

    #[test]
    fn pmk_derivation_is_deterministic_and_password_sensitive() {
        let ssid = b"StreamCrackTest";
        let pmk_a = pmk_from_psk(b"correct-horse-battery-staple", ssid);
        let pmk_b = pmk_from_psk(b"correct-horse-battery-staple", ssid);
        let pmk_c = pmk_from_psk(b"wrong-password", ssid);
        assert_ne!(pmk_a, [0u8; 32]);
        assert_eq!(pmk_a, pmk_b);
        assert_ne!(pmk_a, pmk_c);
    }

    #[test]
    fn pmk_with_empty_ssid_still_derives() {
        let pmk = pmk_from_psk(b"pw", &[]);
        assert_ne!(pmk, [0u8; 32]);
    }

    #[test]
    fn ptk_is_symmetric_in_endpoints() {
        let pmk = pmk_from_psk(b"sym-pwd", b"sym");
        let ap = MacAddr::from_bytes([0xAA; 6]);
        let sta = MacAddr::from_bytes([0xBB; 6]);
        let a_nonce = Nonce::from_bytes([0x33u8; 32]);
        let s_nonce = Nonce::from_bytes([0x44u8; 32]);
        let normal = compute_ptk(&pmk, &ap, &sta, &a_nonce, &s_nonce);
        let swapped = compute_ptk(&pmk, &sta, &ap, &s_nonce, &a_nonce);
        assert_eq!(normal, swapped);
        assert_ne!(normal, [0u8; 64]);
    }

    #[test]
    fn verify_handshake_accepts_correct_password() {
        let (handshake, candidate) = handshake(b"roundtrip", b"correct-horse-battery-staple");
        assert!(matches!(
            verify_handshake(&handshake, &candidate),
            CrackResult::Success { .. }
        ));
    }

    #[test]
    fn verify_handshake_rejects_wrong_password() {
        let (handshake, _) = handshake(b"roundtrip", b"correct-horse-battery-staple");
        let wrong = PskCandidate {
            password: b"wrong-password".to_vec(),
        };
        assert_eq!(verify_handshake(&handshake, &wrong), CrackResult::Failed);
    }

}

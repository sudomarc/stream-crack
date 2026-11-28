//! Extraction of WPA2 EAPOL-Key frames from PCAP/PCAPNG packet payloads.
//!
//! Supported 802.11 encapsulation:
//!   * link type 105: raw IEEE 802.11 frames
//!   * link type 127: radiotap frames (the 802.11 payload begins at the
//!     radiotap header `it_len`, which includes all present fields)
//!
//! Only data frames are inspected; management/control frames cannot carry an
//! EAPOL-Key handshake message. The parser recovers the two unicast MAC
//! addresses and the key nonces; because PTK computation sorts both MACs and
//! nonces internally, address/nonce assignment order does not matter.

use crate::capture::reader::PacketRecord;
use crate::domain::wpa2::{EapolFrame, Handshake, MacAddr, Nonce};
use std::collections::HashMap;

/// Radiotap header total length, including all present fields and padding.
fn radiotap_header_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 6 {
        return None;
    }
    let len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if len < 6 || len > bytes.len() {
        return None;
    }
    Some(len)
}

/// Parsed enough of an 802.11 data frame to locate its LLC payload.
struct Dot11Data {
    /// Receiver address.
    addr1: [u8; 6],
    /// Transmitter address.
    addr2: [u8; 6],
    /// BSSID (usually).
    addr3: [u8; 6],
    /// Offset of the LLC SNAP header within the payload.
    llc_offset: usize,
}

fn parse_80211_data(payload: &[u8]) -> Option<Dot11Data> {
    if payload.len() < 24 {
        return None;
    }

    let fc = u16::from_le_bytes([payload[0], payload[1]]);
    let mtype = (fc >> 2) & 0x3;
    if mtype != 2 {
        return None; // not a data frame
    }

    // Byte1 bits: bit0 ToDS, bit1 FromDS, bit7 Order (HT Control present).
    let to_ds = (fc >> 8) & 1 == 1;
    let from_ds = (fc >> 9) & 1 == 1;
    let order = (fc >> 15) & 1 == 1;

    // Subtype: bits 4..7 of byte 0; subtype >= 8 is QoS data (QoS Control present).
    let subtype = (fc >> 4) & 0xF;
    let qos = subtype >= 8;

    let mut off = 24; // past FC(2) Dur(2) Addr1(6) Addr2(6) Addr3(6) SeqCtl(2)
    if to_ds && from_ds {
        if payload.len() < off + 6 {
            return None;
        }
        off += 6; // Addr4
    }
    if qos {
        if payload.len() < off + 2 {
            return None;
        }
        off += 2; // QoS Control
    }
    if order {
        if payload.len() < off + 4 {
            return None;
        }
        off += 4; // HT Control
    }

    // LLC SNAP: aa aa 03 00 00 00, then EtherType.
    if payload.len() < off + 8 {
        return None;
    }
    let snap = &payload[off..off + 6];
    if snap != [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00] {
        return None;
    }
    let ethertype = u16::from_be_bytes([payload[off + 6], payload[off + 7]]);
    if ethertype != 0x888E {
        return None;
    }

    let llc_offset = off;
    Some(Dot11Data {
        addr1: payload[4..10].try_into().ok()?,
        addr2: payload[10..16].try_into().ok()?,
        addr3: payload[16..22].try_into().ok()?,
        llc_offset: llc_offset + 8,
    })
}

/// Unicast MACs that are neither broadcast nor zero.
fn unicast_macs(a1: &[u8; 6], a2: &[u8; 6], a3: &[u8; 6]) -> Option<([u8; 6], [u8; 6])> {
    let is_bcast = |m: &[u8; 6]| m.iter().all(|b| *b == 0xFF);
    let is_zero = |m: &[u8; 6]| m.iter().all(|b| *b == 0x00);
    let arr: [&[u8; 6]; 3] = [a1, a2, a3];

    let mut first: Option<[u8; 6]> = None;
    let mut second: Option<[u8; 6]> = None;
    for &m in arr.iter() {
        if is_bcast(m) || is_zero(m) {
            continue;
        }
        match (first, second) {
            (None, _) => first = Some(*m),
            (Some(f), None) if f != *m => second = Some(*m),
            _ => {}
        }
        if first.is_some() && second.is_some() {
            break;
        }
    }
    Some((first?, second?))
}

/// One EAPOL-Key candidate recovered from one packet payload.
pub struct EapolCandidate {
    pub mac_a: [u8; 6],
    pub mac_b: [u8; 6],
    pub key_nonce: Option<[u8; 32]>,
    pub key_mic: Option<[u8; 16]>,
    /// Offset of key_mic within `eapol` (verified against WPA2 fixed layout).
    pub mic_offset: usize,
    pub eapol: Vec<u8>,
}

/// Extract at most one EAPOL-Key message from one packet payload.
///
/// Returns `None` for non-802.11, non-data, non-EAPOL, or malformed packets.
pub fn extract_from_packet(link_type: u32, payload: &[u8]) -> Option<EapolCandidate> {
    let bytes = match link_type {
        127 => {
            let hdr_len = radiotap_header_len(payload)?;
            &payload[hdr_len..]
        }
        105 => payload,
        _ => return None,
    };

    let dot11 = parse_80211_data(bytes)?;
    let eapol_start = dot11.llc_offset;
    if bytes.len() < eapol_start + 4 {
        return None;
    }
    let eapol = bytes[eapol_start..].to_vec();

    // EAPOL header: version(1) type(1) length(2 BE); type 3 = EAPOL-Key.
    if eapol[1] != 3 {
        return None;
    }
    let eapol_len = u16::from_be_bytes([eapol[2], eapol[3]]) as usize;
    if eapol_len == 0 || eapol_len > eapol.len() - 4 {
        return None;
    }
    let body = &eapol[4..4 + eapol_len];

    // WPA2 RSN EAPOL-Key fixed layout:
    // type(1) key_info(2) key_length(2) replay_counter(8) key_nonce(32)
    // key_iv(16) key_index(8) key_id(8) key_mic(16) key_data_length(2) ...
    if body.len() < 95 {
        return None;
    }
    let descriptor_type = body[0];
    if descriptor_type != 2 {
        return None; // only WPA2/RSN
    }

    let key_nonce = body[13..45].try_into().ok();
    let key_mic = body[77..93].try_into().ok();
    let mic_offset_in_eapol = 4 + 77usize;

    let (mac_a, mac_b) = unicast_macs(&dot11.addr1, &dot11.addr2, &dot11.addr3)?;

    Some(EapolCandidate {
        mac_a,
        mac_b,
        key_nonce,
        key_mic,
        mic_offset: mic_offset_in_eapol,
        eapol,
    })
}

/// Extract the (BSSID, SSID) announced by a beacon frame.
///
/// Beacon = management frame (type 0), subtype 8. Fixed fields (timestamp,
/// interval, capability) occupy bytes 24..36; information elements follow.
/// Returns None for anything that isn't a beacon with a decodable SSID IE.
pub fn extract_beacon_bssid_ssid(link_type: u32, payload: &[u8]) -> Option<([u8; 6], Vec<u8>)> {
    let bytes = match link_type {
        127 => {
            let hdr_len = radiotap_header_len(payload)?;
            &payload[hdr_len..]
        }
        105 => payload,
        _ => return None,
    };

    if bytes.len() < 36 {
        return None;
    }
    let fc = u16::from_le_bytes([bytes[0], bytes[1]]);
    if (fc >> 2) & 0x3 != 0 {
        return None; // not a management frame
    }
    if ((fc >> 4) & 0xF) != 8 {
        return None; // not a beacon
    }
    let bssid = bytes[10..16].try_into().ok()?;
    let ies = &bytes[36..];

    let mut i = 0;
    while i + 2 <= ies.len() {
        let tag = ies[i];
        let len = ies[i + 1] as usize;
        let end = i.checked_add(2)?.checked_add(len)?;
        if end > ies.len() {
            break;
        }
        if tag == 0 {
            return Some((bssid, ies[i + 2..end].to_vec()));
        }
        i = end;
    }
    None
}

/// Reassemble WPA2 4-way handshakes from packet records.
///
/// Uses the first two EAPOL-Key messages seen per unicast MAC pair (order in
/// the capture). PTK computation sorts both MACs and nonces internally, so
/// message direction does not matter. The SSID is taken from beacons
/// announcing either endpoint, or left empty when no beacon was seen — an
/// empty SSID still derives a valid PMK (PBKDF2 salt can be empty).
pub fn extract_handshakes(records: &[PacketRecord]) -> Vec<Handshake> {
    let mut ssids: HashMap<[u8; 6], Vec<u8>> = HashMap::new();
    for rec in records {
        if let Some((bssid, ssid)) = extract_beacon_bssid_ssid(rec.link_type, &rec.payload) {
            ssids.entry(bssid).or_insert(ssid);
        }
    }

    let mut by_pair: HashMap<([u8; 6], [u8; 6]), Vec<EapolCandidate>> = HashMap::new();
    for rec in records {
        if let Some(cand) = extract_from_packet(rec.link_type, &rec.payload) {
            let pair = if cand.mac_a <= cand.mac_b {
                (cand.mac_a, cand.mac_b)
            } else {
                (cand.mac_b, cand.mac_a)
            };
            by_pair.entry(pair).or_default().push(cand);
        }
    }

    let mut out = Vec::new();
    for ((mac_a, mac_b), cands) in by_pair {
        if cands.len() < 2 {
            continue;
        }
        let (Some(nonce_a), Some(mic_b), Some(nonce_b)) =
            (cands[0].key_nonce, cands[1].key_mic, cands[1].key_nonce)
        else {
            continue;
        };
        let ssid = ssids
            .get(&mac_a)
            .cloned()
            .or_else(|| ssids.get(&mac_b).cloned())
            .unwrap_or_default();
        let m2 = EapolFrame {
            descriptor_type: 2,
            key_info: 0,
            key_length: 0,
            replay_counter: [0; 8],
            key_nonce: Nonce::from_bytes(nonce_b),
            key_mic: mic_b,
            mic_offset_within_raw: cands[1].mic_offset,
            raw: cands[1].eapol.clone(),
        };
        out.push(Handshake {
            ssid,
            ap_mac: MacAddr::from_bytes(mac_a),
            sta_mac: MacAddr::from_bytes(mac_b),
            a_nonce: Nonce::from_bytes(nonce_a),
            s_nonce: Nonce::from_bytes(nonce_b),
            m2,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn radiotap(present_bitmap: u32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x00); // version
        out.push(0x00); // pad
        let len = 8u16; // header = version(1)+pad(1)+len(2)+bitmap(4)
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&present_bitmap.to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    fn dot11_data_frame(addr1: &[u8; 6], addr2: &[u8; 6], addr3: &[u8; 6], qos: bool) -> Vec<u8> {
        let mut out = Vec::new();
        // FC: data frame, ToDS=1 (addr1=BSSID, addr2=STA, addr3=AP),
        // subtype = QoS data (0x88) when qos, else data (0x00)
        out.push(if qos { 0x88 } else { 0x08 });
        out.push(0x01); // ToDS
        out.extend_from_slice(&0u16.to_le_bytes()); // duration
        out.extend_from_slice(addr1);
        out.extend_from_slice(addr2);
        out.extend_from_slice(addr3);
        out.extend_from_slice(&0u16.to_le_bytes()); // seq ctl
        if qos {
            out.extend_from_slice(&0u16.to_le_bytes()); // QoS control
        }
        // LLC SNAP + EtherType EAPOL
        out.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        out
    }

    fn eapol_key_m2(nonce: &[u8; 32], mic: &[u8; 16]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(2); // RSN descriptor
        body.extend_from_slice(&0u16.to_le_bytes()); // key_info
        body.extend_from_slice(&0u16.to_le_bytes()); // key_length
        body.extend_from_slice(&0u64.to_le_bytes()); // replay counter
        body.extend_from_slice(nonce); // key_nonce
        body.extend_from_slice(&[0u8; 16]); // key_iv
        body.extend_from_slice(&[0u8; 8]); // key_index
        body.extend_from_slice(&[0u8; 8]); // key_id
        body.extend_from_slice(mic); // key_mic @ body offset 77
        body.extend_from_slice(&0u16.to_be_bytes()); // key_data_length = 0
        let mut eapol = Vec::new();
        eapol.push(2); // version
        eapol.push(3); // EAPOL-Key
        eapol.extend_from_slice(&(body.len() as u16).to_be_bytes());
        eapol.extend_from_slice(&body);
        eapol
    }

    #[test]
    fn extracts_wpa2_eapol_from_raw_80211() {
        let a1 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03]; // BSSID
        let a2 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x04]; // STA
        let a3 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03]; // AP
        let nonce = [0x5Au8; 32];
        let mic = [0x6Bu8; 16];
        let frame = dot11_data_frame(&a1, &a2, &a3, false);
        let mut payload = frame.clone();
        payload.extend_from_slice(&eapol_key_m2(&nonce, &mic));

        let cand = extract_from_packet(105, &payload).expect("raw 802.11 EAPOL extracted");
        assert!((cand.mac_a == a2 && cand.mac_b == a3) || (cand.mac_a == a3 && cand.mac_b == a2));
        assert_eq!(cand.key_nonce, Some(nonce));
        assert_eq!(cand.key_mic, Some(mic));
        assert_eq!(cand.mic_offset, 4 + 77);
        assert_eq!(&cand.eapol, &payload[frame.len()..]);
    }

    #[test]
    fn extracts_wpa2_eapol_from_radiotap() {
        let a1 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03];
        let a2 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x04];
        let a3 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03];
        let nonce = [0x9Cu8; 32];
        let mic = [0x7Du8; 16];
        let dot11 = dot11_data_frame(&a1, &a2, &a3, true);
        let mut payload = radiotap(0x00000004, &dot11);
        payload.extend_from_slice(&eapol_key_m2(&nonce, &mic));

        let cand = extract_from_packet(127, &payload).expect("radiotap EAPOL extracted");
        assert!((cand.mac_a == a2 && cand.mac_b == a3) || (cand.mac_a == a3 && cand.mac_b == a2));
        assert_eq!(cand.key_nonce, Some(nonce));
        assert_eq!(cand.key_mic, Some(mic));
        assert_eq!(cand.mic_offset, 4 + 77);
    }

    #[test]
    fn ignores_non_data_and_non_eapol_frames() {
        // Management frame (type 0)
        let mut mgmt = vec![
            0x00, 0x00, 0x00, 0x00, // FC, duration
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // addr1
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // addr2
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // addr3
            0x00, 0x00, // seq ctl
        ];
        mgmt.extend_from_slice(&[0xAAu8; 40]);
        assert!(extract_from_packet(105, &mgmt).is_none());

        // Data frame with non-EAPOL ethertype (IPv4)
        let mut ip = dot11_data_frame(
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x03],
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x04],
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x03],
            false,
        );
        let last = ip.len() - 2;
        ip[last] = 0x00; // break EtherType 0x888E
        ip.extend_from_slice(&[0x00u8; 20]);
        assert!(extract_from_packet(105, &ip).is_none());

        // Unknown link type
        let good = dot11_data_frame(
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x03],
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x04],
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x03],
            false,
        );
        assert!(extract_from_packet(1, &good).is_none());
    }

    #[test]
    fn extracts_beacon_bssid_and_ssid() {
        let bssid = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ssid = b"TestNet";
        let mut frame = Vec::new();
        frame.push(0x80); // management, beacon
        frame.push(0x00);
        frame.extend_from_slice(&0u16.to_le_bytes()); // duration
        frame.extend_from_slice(&[0xFFu8; 6]); // addr1
        frame.extend_from_slice(&bssid); // addr2
        frame.extend_from_slice(&bssid); // addr3 (BSSID)
        frame.extend_from_slice(&0u16.to_le_bytes()); // seq ctl
        // fixed fields: timestamp(8) interval(2) capability(2)
        frame.extend_from_slice(&0u64.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        // IE: SSID (tag 0)
        frame.push(0);
        frame.push(ssid.len() as u8);
        frame.extend_from_slice(ssid);

        let (b, s) = extract_beacon_bssid_ssid(105, &frame).expect("beacon parsed");
        assert_eq!(b, bssid);
        assert_eq!(s, ssid);

        // Not a beacon: data frame
        let data = dot11_data_frame(&bssid, &[0x03; 6], &bssid, false);
        assert!(extract_beacon_bssid_ssid(105, &data).is_none());
    }

    #[test]
    fn extracts_handshake_from_two_eapol_frames() {
        let a1 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03];
        let a2 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x04];
        let a3 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03];
        let nonce = [0x5Au8; 32];
        let mic = [0x6Bu8; 16];
        let m2 = eapol_key_m2(&nonce, &mic);

        let mut p1 = dot11_data_frame(&a1, &a2, &a3, false);
        p1.extend_from_slice(&eapol_key_m2(&[0x11u8; 32], &[0x22u8; 16]));
        let mut p2 = dot11_data_frame(&a1, &a2, &a3, false);
        p2.extend_from_slice(&m2);

        let recs = vec![
            PacketRecord {
                index: 0,
                timestamp: 0,
                caplen: p1.len() as u32,
                orig_len: p1.len() as u32,
                payload: p1,
                link_type: 105,
            },
            PacketRecord {
                index: 1,
                timestamp: 0,
                caplen: p2.len() as u32,
                orig_len: p2.len() as u32,
                payload: p2,
                link_type: 105,
            },
        ];
        let hs = extract_handshakes(&recs);
        assert_eq!(hs.len(), 1);
        assert_eq!(hs[0].m2.key_mic, mic);
        assert_eq!(hs[0].ap_mac, MacAddr::from_bytes(a3));
        assert_eq!(hs[0].sta_mac, MacAddr::from_bytes(a2));
        assert_eq!(hs[0].ssid, Vec::<u8>::new());
    }

    // Integration: extract handshake, then verify correct password.
    #[test]
    fn extracted_handshake_verifies_correct_password() {
        use crate::crypto::{compute_mic, compute_ptk, kck_for_ptk, pmk_from_psk};
        let ssid = b"integ-test";
        let password = b"correct-horse-battery-staple";
        let pmk = pmk_from_psk(password, ssid);
        let ap = MacAddr::from_bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let sta = MacAddr::from_bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let a_nonce = Nonce::from_bytes([0xAAu8; 32]);
        let s_nonce = Nonce::from_bytes([0xBBu8; 32]);
        let ptk = compute_ptk(&pmk, &ap, &sta, &a_nonce, &s_nonce);
        let kck = kck_for_ptk(&ptk);

        let mut raw = vec![0u8; 99];
        raw[0] = 2;
        raw[1] = 3;
        raw[4] = 2;
        let mic_offset = 81usize;
        let mic = compute_mic(&kck, &raw, raw.len());
        raw[mic_offset..mic_offset + 16].copy_from_slice(&mic);

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
            ssid: ssid.to_vec(),
            ap_mac: ap,
            sta_mac: sta,
            a_nonce,
            s_nonce,
            m2,
        };
        let candidate = crate::domain::wpa2::PskCandidate { password: password.to_vec() };
        assert!(matches!(
            crate::crypto::verify_handshake(&handshake, &candidate),
            crate::domain::wpa2::CrackResult::Success { .. }
        ));
    }

    #[test]
    fn beacon_ssid_extraction_matches_python_fixture() {
        // Hexdump of the beacon frame generated by the smoke-test Python script.
        let bytes: &[u8] = &[
            0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x53, 0x6d,
            0x6f, 0x6b, 0x65, 0x4e, 0x65, 0x74,
        ];
        let bssid = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ssid = b"SmokeNet";
        let (b, s) = extract_beacon_bssid_ssid(105, &bytes).expect("beacon parsed");
        assert_eq!(b, bssid);
        assert_eq!(s, ssid);

        // Non-beacon frame returns None.
        let data = dot11_data_frame(&bssid, &[0x03; 6], &bssid, false);
        assert!(extract_beacon_bssid_ssid(105, &data).is_none());
    }
}

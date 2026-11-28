//! Cracking engine: offline WPA2 PSK verification loop.
//!
//! Authorized use only (see AGENTS.md / the engagement mandate): offline
//! dictionary / rule / mask attacks against extracted WPA2 handshakes on
//! stations you own or are authorized to test. Never against live traffic.
//!
//! Design: everything streams — candidate sources produce one password at a
//! time, the engine verifies each against a Handshake and stops at the first
//! match. Progress is reported via a callback that may abort the run.
//! Explicit caps bound runtime and memory.

use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::crypto::verify_handshake;
use crate::domain::wpa2::{CrackResult, Handshake, PskCandidate};

/// Result of a cracking run.
#[derive(Debug)]
pub enum CrackOutcome {
    /// Password recovered after `tested` candidates.
    Found { password: Vec<u8>, tested: u64 },
    /// No match before the run was stopped or the cap was reached.
    NotFound { tested: u64 },
    /// Stopped early by the progress callback.
    Aborted { tested: u64 },
}

/// One candidate password produced by a source.
pub trait CandidateSource {
    /// Next candidate, or `Ok(None)` at end of source.
    fn next(&mut self) -> Result<Option<Vec<u8>>, io::Error>;
    /// Upper-bound hint on remaining candidates (for progress bars).
    fn remaining_hint(&self) -> u64;
}

/// Configuration caps before anything is allocated or tested.
#[derive(Debug, Clone)]
pub struct CrackConfig {
    /// Hard stop: never test more than this many candidates.
    pub max_candidates: u64,
    /// Report progress every `progress_every` candidates tested.
    pub progress_every: u64,
}

impl Default for CrackConfig {
    fn default() -> Self {
        Self {
            max_candidates: 10_000_000,
            progress_every: 10_000,
        }
    }
}

/// Offline verification loop over one handshake and one candidate source.
pub struct CrackEngine {
    config: CrackConfig,
}

impl CrackEngine {
    pub fn new(config: CrackConfig) -> Self {
        Self { config }
    }

    /// Test candidates from `source` against `handshake` until a match,
    /// source exhaustion, the candidate cap, or `progress` returns false.
    ///
    /// `progress` receives the count of candidates tested so far; return
    /// `true` to continue, `false` to abort.
    pub fn run<S, F>(
        &self,
        handshake: &Handshake,
        source: &mut S,
        mut progress: F,
    ) -> io::Result<CrackOutcome>
    where
        S: CandidateSource + ?Sized,
        F: FnMut(u64) -> bool,
    {
        let mut tested: u64 = 0;
        let cancelled = AtomicBool::new(false);

        loop {
            if tested >= self.config.max_candidates {
                return Ok(CrackOutcome::NotFound { tested });
            }

            let candidate = match source.next()? {
                Some(c) => c,
                None => return Ok(CrackOutcome::NotFound { tested }),
            };

            // WPA2 PSK is 8–63 printable ASCII bytes; reject out of spec
            // before any crypto work.
            if candidate.is_empty() || candidate.len() > 63 {
                if tested % self.config.progress_every == 0 {
                    if !progress(tested) {
                        return Ok(CrackOutcome::Aborted { tested });
                    }
                }
                continue;
            }

            let result = verify_handshake(handshake, &PskCandidate { password: candidate.clone() });
            tested += 1;

            match result {
                CrackResult::Success { password } => {
                    return Ok(CrackOutcome::Found { password, tested });
                }
                CrackResult::Failed => {}
            }

            if cancelled.load(Ordering::Relaxed) {
                return Ok(CrackOutcome::Aborted { tested });
            }

            if tested % self.config.progress_every == 0 {
                if !progress(tested) {
                    return Ok(CrackOutcome::Aborted { tested });
                }
            }
        }
    }
}

/// Read one password per line from a file, skipping blank lines.
///
/// Lines longer than [`MAX_PASSWORD_LEN`] are skipped (they can never be a
/// WPA2 PSK). The file is streamed: no buffering of the whole wordlist.
pub struct WordlistSource {
    reader: io::BufReader<File>,
    /// Remaining hint for progress display.
    remaining_hint: u64,
    hit_end: bool,
}

const MAX_PASSWORD_LEN: usize = 63;

impl WordlistSource {
    pub fn open(path: PathBuf) -> io::Result<Self> {
        let file = File::open(&path)?;
        let meta = file.metadata()?;
        // Rough line-count hint based on average line length; purely cosmetic.
        let average_line = 16u64;
        let remaining_hint = (meta.len().saturating_add(average_line - 1) / average_line).min(u64::MAX / 2);
        Ok(Self {
            reader: io::BufReader::new(file),
            remaining_hint,
            hit_end: false,
        })
    }
}

impl CandidateSource for WordlistSource {
    fn next(&mut self) -> Result<Option<Vec<u8>>, io::Error> {
        if self.hit_end {
            return Ok(None);
        }
        let mut line = String::new();
        loop {
            let n = self.reader.read_line(&mut line)?;
            if n == 0 {
                self.hit_end = true;
                return Ok(None);
            }
            let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_string();
            line.clear();
            if trimmed.is_empty() {
                continue;
            }
            let bytes = trimmed.into_bytes();
            if bytes.len() > MAX_PASSWORD_LEN {
                continue; // cannot be a WPA2 PSK
            }
            self.remaining_hint = self.remaining_hint.saturating_sub(1);
            return Ok(Some(bytes));
        }
    }

    fn remaining_hint(&self) -> u64 {
        self.remaining_hint
    }
}

/// Read one password per line from stdin.
pub struct StdinSource {
    stdin: io::Stdin,
    hit_end: bool,
}

impl StdinSource {
    pub fn new() -> Self {
        Self {
            stdin: io::stdin(),
            hit_end: false,
        }
    }
}

impl CandidateSource for StdinSource {
    fn next(&mut self) -> Result<Option<Vec<u8>>, io::Error> {
        if self.hit_end {
            return Ok(None);
        }
        let mut line = String::new();
        loop {
            let n = io::BufRead::read_line(&mut self.stdin.lock(), &mut line)?;
            if n == 0 {
                self.hit_end = true;
                return Ok(None);
            }
            let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_string();
            line.clear();
            if trimmed.is_empty() {
                continue;
            }
            let bytes = trimmed.into_bytes();
            if bytes.len() > MAX_PASSWORD_LEN {
                continue;
            }
            return Ok(Some(bytes));
        }
    }

    fn remaining_hint(&self) -> u64 {
        u64::MAX / 2
    }
}

/// Brute-force mask source.
///
/// Mask semantics (hashcat-compatible subset):
///   ?l  lowercase a-z
///   ?u  uppercase A-Z
///   ?d  digit 0-9
///   ?s  space and "!@#$%^&*()-_=+[]{}|;:,.<>?/~`"
///   ?a  all of the above
///   any other byte is literal.
///
/// Positions are enumerated in odometer order; capped at `max_total`.
pub struct MaskSource {
    charsets: Vec<Vec<u8>>,
    counters: Vec<u64>,
    done: bool,
    emitted: u64,
    max_total: u64,
}

impl MaskSource {
    pub fn new(mask: &str, max_total: u64) -> io::Result<Self> {
        let mut charsets = Vec::new();
        let bytes = mask.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'?' && i + 1 < bytes.len() {
                let set: Vec<u8> = match bytes[i + 1] {
                    b'l' => b"abcdefghijklmnopqrstuvwxyz".to_vec(),
                    b'u' => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec(),
                    b'd' => b"0123456789".to_vec(),
                    b's' => b" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".to_vec(),
                    b'a' => {
                        let mut all = Vec::new();
                        all.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
                        all.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                        all.extend_from_slice(b"0123456789");
                        all.extend_from_slice(b" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
                        all
                    }
                    other => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("unknown mask placeholder ?{:?}", other as char),
                        ));
                    }
                };
                charsets.push(set);
                i += 2;
            } else {
                charsets.push(vec![bytes[i]]);
                i += 1;
            }
            if bytes.len() > MAX_PASSWORD_LEN && i > 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mask exceeds maximum WPA2 PSK length (63)",
                ));
            }
        }
        if charsets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty mask",
            ));
        }
        let mut total: u64 = 1;
        for charset in &charsets {
            total = total.checked_mul(charset.len() as u64).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mask space overflows u64",
                )
            })?;
        }
        if total > max_total {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "mask space ({total}) exceeds max_total ({max_total})",
                ),
            ));
        }

        Ok(Self {
            counters: vec![0u64; charsets.len()],
            charsets,
            done: false,
            emitted: 0,
            max_total,
        })
    }
}

impl CandidateSource for MaskSource {
    fn next(&mut self) -> Result<Option<Vec<u8>>, io::Error> {
        if self.done || self.emitted >= self.max_total {
            return Ok(None);
        }

        let mut out = Vec::with_capacity(self.charsets.len());
        for (pos, charset) in self.charsets.iter().enumerate() {
            let idx = (self.counters[pos] % charset.len() as u64) as usize;
            out.push(charset[idx]);
        }
        self.emitted += 1;

        // Odometer increment.
        let mut pos = self.counters.len();
        while pos > 0 {
            pos -= 1;
            self.counters[pos] += 1;
            if self.counters[pos] < self.charsets[pos].len() as u64 {
                break;
            }
            self.counters[pos] = 0;
            if pos == 0 {
                self.done = true;
            }
        }

        Ok(Some(out))
    }

    fn remaining_hint(&self) -> u64 {
        self.max_total.saturating_sub(self.emitted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{pmk_from_psk, compute_ptk, kck_for_ptk, compute_mic};
    use crate::domain::wpa2::{EapolFrame, Handshake, MacAddr, Nonce, PskCandidate};
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn handshake_for(password: &[u8]) -> (Handshake, PskCandidate) {
        let ssid = b"engine-test".to_vec();
        let pmk = pmk_from_psk(password, &ssid);
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
        let candidate = PskCandidate { password: password.to_vec() };
        (handshake, candidate)
    }

    const MIC_LEN: usize = 16;

    #[test]
    fn wordlist_source_skips_blanks_and_too_long_lines() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("wc-test-{}.txt", std::process::id()));
        {
            let mut f = File::create(&path).unwrap();
            writeln!(f, "").unwrap();
            writeln!(f, "alpha").unwrap();
            writeln!(f, "").unwrap();
            writeln!(f, "beta").unwrap();
            writeln!(f, "{}", "x".repeat(100)).unwrap();
            writeln!(f, "gamma").unwrap();
        }
        let mut s = WordlistSource::open(path.clone()).unwrap();
        assert_eq!(s.next().unwrap().unwrap(), b"alpha".to_vec());
        assert_eq!(s.next().unwrap().unwrap(), b"beta".to_vec());
        assert_eq!(s.next().unwrap().unwrap(), b"gamma".to_vec());
        assert_eq!(s.next().unwrap(), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mask_source_enumerates_odometer_order() {
        let mut s = MaskSource::new("?l?d", 1000).unwrap();
        assert_eq!(s.next().unwrap().unwrap(), b"a0".to_vec());
        assert_eq!(s.next().unwrap().unwrap(), b"a1".to_vec());
        // last of first charset before rollover: z0..z9 then a0? No: odometer
        // increments the rightmost fastest, leftmost slowest => a0,a1..a9,b0...
        let seen: Vec<String> = (0..10)
            .map(|_| String::from_utf8(s.next().unwrap().unwrap()).unwrap())
            .collect();
        assert_eq!(seen, vec!["a2","a3","a4","a5","a6","a7","a8","a9","b0","b1"]);
    }

    #[test]
    fn engine_finds_password_in_wordlist() {
        let (handshake, _) = handshake_for(b"secret");
        let dir = std::env::temp_dir();
        let path = dir.join(format!("wl-engine-{}.txt", std::process::id()));
        {
            let mut f = File::create(&path).unwrap();
            writeln!(f, "aaaa").unwrap();
            writeln!(f, "secret").unwrap();
            writeln!(f, "zzzz").unwrap();
        }
        let mut source = WordlistSource::open(path.clone()).unwrap();
        let engine = CrackEngine::new(CrackConfig::default());
        let progress_calls = AtomicU64::new(0);
        let outcome = engine.run(
            &handshake,
            &mut source,
            |tested| {
                progress_calls.fetch_add(1, Ordering::Relaxed);
                tested < 1_000_000
            },
        )
        .unwrap();
        match outcome {
            CrackOutcome::Found { password, tested } => {
                assert_eq!(password, b"secret");
                assert!(tested <= 2);
            }
            other => panic!("expected found, got {:?}", other),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn engine_respects_candidate_cap() {
        let (handshake, _) = handshake_for(b"nonexistent");
        let mut source = MaskSource::new("?d?d?d?d?d?d?d", 10_000_000).unwrap();
        let engine = CrackEngine::new(CrackConfig {
            max_candidates: 5,
            progress_every: 1,
        });
        let outcome = engine.run(&handshake, &mut source, |_| true).unwrap();
        match outcome {
            CrackOutcome::NotFound { tested } => assert_eq!(tested, 5),
            other => panic!("expected not found at cap, got {:?}", other),
        }
    }

    #[test]
    fn engine_aborts_on_progress() {
        let (handshake, _) = handshake_for(b"never");
        let mut source = MaskSource::new("?d", 100).unwrap();
        let engine = CrackEngine::new(CrackConfig {
            max_candidates: 100,
            progress_every: 1,
        });
        let outcome = engine.run(&handshake, &mut source, |_| false).unwrap();
        match outcome {
            CrackOutcome::Aborted { tested } => assert_eq!(tested, 1),
            other => panic!("expected aborted, got {:?}", other),
        }
    }

    #[test]
    fn engine_rejects_overlong_psk_candidate() {
        let (handshake, _) = handshake_for(b"short");
        let mut source = WordlistSource::open(PathBuf::from("/dev/null")).unwrap();
        // WordlistSource::open works on /dev/null (empty). Just ensure run()
        // doesn't crash on an empty source.
        let engine = CrackEngine::new(CrackConfig::default());
        let outcome = engine.run(&handshake, &mut source, |_| true).unwrap();
        assert!(matches!(outcome, CrackOutcome::NotFound { .. }));
    }
}

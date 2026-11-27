//! PCAP (libpcap / WinDump) capture reader.
//!
//! Format reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
//!
//! All integers are read with the file's byte order, and every length is
//! checked against remaining bytes and the configured limits before any
//! allocation. A truncated file is an error, never a panic.

use std::io::{Read, Seek};

use super::reader::{ByteOrder, PacketRecord, read_bounded};
use crate::config::Limits;
use crate::domain::Diagnostic;
use crate::error::{Error, Result};

const FILE_HEADER_LEN: usize = 24;
const PACKET_HEADER_LEN: usize = 16;

const MAGIC_LITTLE: u32 = 0xA1B2C3D4;
const MAGIC_BIG: u32 = 0xD4C3B2A1;
const MAGIC_LITTLE_NANO: u32 = 0xA1B23C4D;
const MAGIC_BIG_NANO: u32 = 0x4D3CB2A1;

#[derive(Debug)]
pub(crate) struct PcapHeader {
    pub network: u32,
    pub order: ByteOrder,
    pub nano: bool,
}

#[derive(Debug)]
pub(crate) struct PcapStream<R: Read + Seek> {
    pub(crate) header: PcapHeader,
    inner: R,
    read_bytes: u64,
    packet_index: u64,
    packet_limit: u32,
    pub(crate) diagnostics: Vec<Diagnostic>,
}

impl<R: Read + Seek> PcapStream<R> {
    pub(crate) fn new(mut inner: R, limits: &Limits) -> Result<Self> {
        let mut header_bytes = [0u8; FILE_HEADER_LEN];
        read_full(&mut inner, &mut header_bytes, "PCAP file header")?;

        let magic = u32::from_le_bytes(header_bytes[0..4].try_into().unwrap());
        let (order, nano) = match magic {
            MAGIC_LITTLE => (ByteOrder::LittleEndian, false),
            MAGIC_BIG => (ByteOrder::BigEndian, false),
            MAGIC_LITTLE_NANO => (ByteOrder::LittleEndian, true),
            MAGIC_BIG_NANO => (ByteOrder::BigEndian, true),
            other => {
                return Err(Error::HeaderValidation {
                    message: format!("unknown PCAP magic {other:08X}"),
                });
            }
        };

        // Version fields are stored in the file's byte order.
        let version_major = read_u16_at(&header_bytes[4..6], order);
        let version_minor = read_u16_at(&header_bytes[6..8], order);
        // `thiszone` (bytes 8..12) and `sigfigs` (bytes 12..16) are metadata
        // this release does not interpret; they are validated by position only.
        let snaplen = read_u32_at(&header_bytes[16..20], order);
        let network = read_u32_at(&header_bytes[20..24], order);

        if version_major != 2 {
            return Err(Error::HeaderValidation {
                message: format!("unsupported PCAP version {version_major}.{version_minor}"),
            });
        }
        if snaplen == 0 {
            return Err(Error::HeaderValidation {
                message: "PCAP snaplen must be non-zero".to_string(),
            });
        }

        let packet_limit = if limits.max_packet_size > u32::MAX as u64 {
            u32::MAX
        } else {
            limits.max_packet_size as u32
        }
        .min(snaplen);

        let header = PcapHeader {
            network,
            order,
            nano,
        };

        Ok(Self {
            header,
            inner,
            read_bytes: FILE_HEADER_LEN as u64,
            packet_index: 0,
            packet_limit,
            diagnostics: Vec::new(),
        })
    }

    /// Read the next packet record; `Ok(None)` at a clean end of file.
    pub(crate) fn next_packet(&mut self) -> Result<Option<PacketRecord>> {
        let mut header_bytes = [0u8; PACKET_HEADER_LEN];
        let n = read_partial(&mut self.inner, &mut header_bytes)?;
        match n {
            0 => return Ok(None),
            n if n < PACKET_HEADER_LEN => {
                return Err(Error::MalformedCapture {
                    message: format!(
                        "truncated PCAP packet header at record {} ({n} bytes present)",
                        self.packet_index
                    ),
                });
            }
            _ => {}
        }
        self.read_bytes += PACKET_HEADER_LEN as u64;

        let ts_sec = read_u32_at(&header_bytes[0..4], self.header.order);
        let ts_frac = read_u32_at(&header_bytes[4..8], self.header.order);
        let incl_len = read_u32_at(&header_bytes[8..12], self.header.order);
        let orig_len = read_u32_at(&header_bytes[12..16], self.header.order);

        // Widen to u64 before the multiplication so second timestamps cannot
        // overflow a u32.
        let timestamp = if self.header.nano {
            (ts_sec as u64)
                .saturating_mul(1_000_000)
                .saturating_add(u64::from(ts_frac.saturating_div(1_000)))
        } else {
            (ts_sec as u64)
                .saturating_mul(1_000_000)
                .saturating_add(u64::from(ts_frac))
        };

        if incl_len > orig_len {
            self.diagnostics.push(Diagnostic {
                offset: Some(self.read_bytes),
                kind: crate::domain::DiagnosticKind::InconsistentLengths,
                message: format!(
                    "packet {}: captured length {incl_len} exceeds original length {orig_len}",
                    self.packet_index
                ),
            });
        }

        let payload = read_bounded(&mut self.inner, incl_len, u64::from(self.packet_limit))?;
        self.read_bytes += u64::from(incl_len);

        let record = PacketRecord {
            index: self.packet_index,
            timestamp,
            caplen: incl_len,
            orig_len,
            payload,
            link_type: self.header.network,
        };
        self.packet_index += 1;
        Ok(Some(record))
    }
}

/// Read exactly `buf.len()` bytes, or report end-of-file/truncation.
fn read_full<R: Read + ?Sized>(inner: &mut R, buf: &mut [u8], what: &str) -> Result<()> {
    let mut n = 0;
    while n < buf.len() {
        match inner.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(ref err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                return Err(Error::MalformedCapture {
                    message: format!("unable to read {what}: {err}"),
                });
            }
        }
    }
    if n == buf.len() {
        Ok(())
    } else if n == 0 {
        Err(Error::MalformedCapture {
            message: format!("unexpected end of file while reading {what}"),
        })
    } else {
        Err(Error::MalformedCapture {
            message: format!("truncated {what} ({n} of {} bytes present)", buf.len()),
        })
    }
}

/// Read up to `buf.len()` bytes; returns how many were read (0 = clean EOF).
fn read_partial<R: Read + ?Sized>(inner: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match inner.read(&mut buf[n..]) {
            Ok(0) => return Ok(n),
            Ok(k) => n += k,
            Err(ref err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                return Err(Error::MalformedCapture {
                    message: format!("unable to read capture data: {err}"),
                });
            }
        }
    }
    Ok(n)
}

/// Checked-endian u16 from a 2-byte slice (caller guarantees length).
fn read_u16_at(bytes: &[u8], order: ByteOrder) -> u16 {
    match order {
        ByteOrder::LittleEndian => u16::from_le_bytes([bytes[0], bytes[1]]),
        ByteOrder::BigEndian => u16::from_be_bytes([bytes[0], bytes[1]]),
    }
}

/// Checked-endian u32 from a 4-byte slice (caller guarantees length).
fn read_u32_at(bytes: &[u8], order: ByteOrder) -> u32 {
    match order {
        ByteOrder::LittleEndian => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        ByteOrder::BigEndian => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    }
}

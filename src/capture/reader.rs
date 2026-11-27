//! Generic capture reader that sniffs the file magic and dispatches to the
//! PCAP or PCAPNG parser below.

use std::io::{Read, Seek, SeekFrom};

use crate::config::Limits;
use crate::error::{Error, Result};

use super::pcap::PcapStream;
use super::pcapng::PcapngStream;

/// Byte order of a capture file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    LittleEndian,
    BigEndian,
}

/// Format of the capture being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFormat {
    Pcap,
    Pcapng,
}

/// One packet record as read from a capture file.
///
/// `payload` holds exactly `caplen` captured bytes and is bounded by
/// `limits.max_packet_size`, so no single record can exhaust memory.
#[derive(Debug)]
pub struct PacketRecord {
    /// Zero-based index of this record in the file.
    pub index: u64,
    /// Timestamp in microseconds (PCAP) or raw ticks (PCAPNG, see note).
    pub timestamp: u64,
    /// Number of captured bytes stored in `payload`.
    pub caplen: u32,
    /// Original length of the frame on the wire.
    pub orig_len: u32,
    /// Captured payload bytes (metadata consumers must not treat this as
    /// reliable protocol data until decoded by the protocol layer).
    pub payload: Vec<u8>,
    /// Link type this record was captured with.
    pub link_type: u32,
}

/// Streaming reader over the records of one capture file.
#[derive(Debug)]
pub struct CaptureReader<R: Read + Seek> {
    stream: Stream<R>,
}

#[derive(Debug)]
enum Stream<R: Read + Seek> {
    Pcap(PcapStream<R>),
    Pcapng(PcapngStream<R>),
}

impl<R: Read + Seek> CaptureReader<R> {
    /// Open a capture stream from `inner`, sniffing its magic number.
    ///
    /// The stream position is rewound to the start after sniffing.
    pub fn new(mut inner: R, limits: &Limits) -> Result<Self> {
        let mut magic = [0u8; 4];
        inner.read_exact(&mut magic)?;
        inner.seek(SeekFrom::Start(0))?;

        let stream = match u32::from_le_bytes(magic) {
            0xA1B2C3D4 | 0xD4C3B2A1 | 0xA1B23C4D | 0x4D3CB2A1 => {
                Stream::Pcap(PcapStream::new(inner, limits)?)
            }
            0x0A0D0D0A => Stream::Pcapng(PcapngStream::new(inner, limits)?),
            other => {
                return Err(Error::HeaderValidation {
                    message: format!("unknown capture magic {other:08X}"),
                });
            }
        };

        Ok(Self { stream })
    }

    /// Format of the capture (`Pcap` or `Pcapng`).
    pub fn format(&self) -> CaptureFormat {
        match self.stream {
            Stream::Pcap(_) => CaptureFormat::Pcap,
            Stream::Pcapng(_) => CaptureFormat::Pcapng,
        }
    }

    /// Link types announced by the capture (interface link type for PCAPNG,
    /// file header `network` for PCAP).
    pub fn link_types(&self) -> Vec<u32> {
        match &self.stream {
            Stream::Pcap(s) => vec![s.header.network],
            Stream::Pcapng(s) => s.interfaces.iter().map(|i| i.link_type).collect(),
        }
    }

    /// Read the next packet record. Returns `Ok(None)` at end of file.
    ///
    /// Any malformed record truncates iteration: subsequent calls keep
    /// returning the same error until the caller stops iterating.
    pub fn next_packet(&mut self) -> Result<Option<PacketRecord>> {
        match &mut self.stream {
            Stream::Pcap(s) => s.next_packet(),
            Stream::Pcapng(s) => s.next_packet(),
        }
    }

    /// Warnings emitted while parsing (truncated records, unknown interfaces,
    /// inconsistent length fields, …). Metadata only, never payload bytes.
    pub fn diagnostics(&self) -> &[crate::domain::Diagnostic] {
        match &self.stream {
            Stream::Pcap(s) => &s.diagnostics,
            Stream::Pcapng(s) => &s.diagnostics,
        }
    }
}

impl<R: Read + Seek> Iterator for CaptureReader<R> {
    type Item = Result<PacketRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_packet().transpose()
    }
}

/// Read exactly `count` bytes, refusing to allocate when `count` is larger
/// than the configured per-packet limit.
pub(crate) fn read_bounded<R: Read + ?Sized>(
    inner: &mut R,
    count: u32,
    max_packet_size: u64,
) -> Result<Vec<u8>> {
    if count as u64 > max_packet_size {
        return Err(Error::LimitExceeded {
            message: format!("packet of {count} bytes exceeds max_packet_size {max_packet_size}"),
        });
    }
    let mut payload = vec![0u8; count as usize];
    inner
        .read_exact(&mut payload)
        .map_err(|err| Error::MalformedCapture {
            message: format!("truncated packet payload: {err}"),
        })?;
    Ok(payload)
}

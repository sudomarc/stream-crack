//! PCAPNG capture reader.
//!
//! Format reference: https://pcapng.sourceforge.net/
//!
//! This release reads Section Header Blocks, Interface Description Blocks and
//! Enhanced Packet Blocks; every other block type is skipped after its length
//! is validated. All block-header integers are little-endian per the
//! specification; the SHB byte-order magic selects the byte order of
//! per-interface and per-packet fields.

use std::io::{Read, Seek};

use super::reader::{ByteOrder, PacketRecord};
use crate::config::Limits;
use crate::domain::Diagnostic;
use crate::error::{Error, Result};

const BLOCK_HEADER_LEN: usize = 8;

const SHB: u32 = 0x0A0D0D0A;
const IDB: u32 = 0x00000001;
const EPB: u32 = 0x00000006;

/// One interface advertised by a PCAPNG Interface Description Block.
#[derive(Debug)]
pub(crate) struct Interface {
    pub link_type: u32,
}

#[derive(Debug)]
pub(crate) struct PcapngStream<R: Read + Seek> {
    pub(crate) interfaces: Vec<Interface>,
    inner: R,
    order: ByteOrder,
    read_bytes: u64,
    packet_index: u64,
    packet_limit: u32,
    block_limit: u32,
    pub(crate) diagnostics: Vec<Diagnostic>,
}

impl<R: Read + Seek> PcapngStream<R> {
    pub(crate) fn new(mut inner: R, limits: &Limits) -> Result<Self> {
        let packet_limit = if limits.max_packet_size > u32::MAX as u64 {
            u32::MAX
        } else {
            limits.max_packet_size as u32
        };
        let block_limit = if limits.max_block_size > u32::MAX as u64 {
            u32::MAX
        } else {
            limits.max_block_size as u32
        };

        // A PCAPNG file must open with a Section Header Block.
        let Some((block_type, _total, body)) = read_block_header(&mut inner, block_limit)? else {
            return Err(Error::MalformedCapture {
                message: "empty PCAPNG file".to_string(),
            });
        };
        if block_type != SHB {
            return Err(Error::MalformedCapture {
                message: "PCAPNG file does not start with a Section Header Block".to_string(),
            });
        }
        let (order, _section_len) = parse_shb(&body)?;

        let read_bytes = BLOCK_HEADER_LEN as u64 + body.len() as u64;

        Ok(Self {
            interfaces: Vec::new(),
            inner,
            order,
            read_bytes,
            packet_index: 0,
            packet_limit,
            block_limit,
            diagnostics: Vec::new(),
        })
    }

    /// Read the next packet record; `Ok(None)` at a clean end of file.
    pub(crate) fn next_packet(&mut self) -> Result<Option<PacketRecord>> {
        loop {
            let Some((block_type, total, body)) =
                read_block_header(&mut self.inner, self.block_limit)?
            else {
                return Ok(None);
            };
            self.read_bytes += total;

            match block_type {
                SHB => {
                    // Additional sections are not supported; skip the block.
                    self.diagnostics.push(Diagnostic {
                        offset: None,
                        kind: crate::domain::DiagnosticKind::UnknownBlock { block_type },
                        message: "second Section Header Block ignored".to_string(),
                    });
                }
                IDB => {
                    if let Some(iface) = parse_idb(&body, self.order) {
                        self.interfaces.push(iface);
                    }
                }
                EPB => return self.parse_epb(&body),
                other => {
                    self.diagnostics.push(Diagnostic {
                        offset: None,
                        kind: crate::domain::DiagnosticKind::UnknownBlock { block_type: other },
                        message: format!("skipped block type {other}"),
                    });
                }
            }
        }
    }

    fn parse_epb(&mut self, body: &[u8]) -> Result<Option<PacketRecord>> {
        if body.len() < 24 {
            return Err(Error::MalformedCapture {
                message: format!(
                    "Enhanced Packet Block body too small ({} bytes, need 24)",
                    body.len()
                ),
            });
        }

        let interface_id = read_u32(&body[0..4], self.order);
        let ts_high = read_u32(&body[4..8], self.order);
        let ts_low = read_u32(&body[8..12], self.order);
        let caplen = read_u32(&body[12..16], self.order);
        let orig_len = read_u32(&body[16..20], self.order);

        let link_type = self
            .interfaces
            .get(interface_id as usize)
            .map(|iface| iface.link_type)
            .unwrap_or(0);
        if link_type == 0 {
            self.diagnostics.push(Diagnostic {
                offset: None,
                kind: crate::domain::DiagnosticKind::UnknownInterface { interface_id },
                message: format!(
                    "packet {} references unknown interface {interface_id}",
                    self.packet_index
                ),
            });
        }

        // Fixed prefix, then the captured packet, then options/padding, then
        // the trailing copy of `block_total_length` (4 bytes).
        const PREFIX: usize = 20;
        let payload_end =
            PREFIX
                .checked_add(caplen as usize)
                .ok_or_else(|| Error::MalformedCapture {
                    message: "Enhanced Packet Block packet length overflow".to_string(),
                })?;
        if body.len() < payload_end + 4 {
            return Err(Error::MalformedCapture {
                message: format!(
                    "Enhanced Packet Block truncates packet payload (have {} bytes, need {})",
                    body.len().saturating_sub(PREFIX),
                    caplen
                ),
            });
        }
        // Enforce the per-packet limit before extracting the payload bytes.
        if caplen > self.packet_limit {
            return Err(Error::LimitExceeded {
                message: format!(
                    "packet of {caplen} bytes exceeds max_packet_size {}",
                    self.packet_limit
                ),
            });
        }
        let payload = body[PREFIX..payload_end].to_vec();

        let timestamp = ((ts_high as u64) << 32) | (ts_low as u64);
        self.packet_index += 1;
        // `orig_len` is retained as metadata; the payload itself is capped
        // by `packet_limit`, so `orig_len` is never used for allocation.
        let _ = orig_len;
        Ok(Some(PacketRecord {
            index: self.packet_index - 1,
            timestamp,
            caplen,
            orig_len,
            payload,
            link_type,
        }))
    }
}

/// Read one block header plus its full body, validating `block_total_length`
/// (and the block-size limit) before any allocation.
///
/// Block headers (type and total length) are always little-endian.
fn read_block_header<R: Read + ?Sized>(
    inner: &mut R,
    block_limit: u32,
) -> Result<Option<(u32, u64, Vec<u8>)>> {
    let mut header = [0u8; BLOCK_HEADER_LEN];
    let n = read_partial(inner, &mut header)?;
    match n {
        0 => return Ok(None),
        n if n < BLOCK_HEADER_LEN => {
            return Err(Error::MalformedCapture {
                message: format!("truncated PCAPNG block header ({n} bytes present)"),
            });
        }
        _ => {}
    }

    let block_type = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let total = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as u64;

    if total < BLOCK_HEADER_LEN as u64 || !total.is_multiple_of(4) {
        return Err(Error::MalformedCapture {
            message: format!(
                "invalid PCAPNG block total_length {total} for block type {block_type}"
            ),
        });
    }
    let total_u32 = total as u32;

    // Enforce the block-size limit before allocating the body buffer.
    if total_u32 > block_limit {
        return Err(Error::LimitExceeded {
            message: format!(
                "PCAPNG block of {total_u32} bytes exceeds max_block_size {block_limit}"
            ),
        });
    }

    let body_len = total_u32
        .checked_sub(BLOCK_HEADER_LEN as u32)
        .ok_or_else(|| Error::MalformedCapture {
            message: "PCAPNG block total_length underflow".to_string(),
        })?;

    let mut body = vec![0u8; body_len as usize];
    read_full(inner, &mut body, "PCAPNG block body")?;

    // Every block ends with a copy of block_total_length.
    if body.len() < 4 {
        return Err(Error::MalformedCapture {
            message: format!("PCAPNG block type {block_type} has no body"),
        });
    }
    let expected = u32::from_le_bytes([
        body[body.len() - 4],
        body[body.len() - 3],
        body[body.len() - 2],
        body[body.len() - 1],
    ]);
    if expected != total_u32 {
        return Err(Error::MalformedCapture {
            message: format!(
                "PCAPNG block type {block_type}: trailing total_length {expected} != {total_u32}"
            ),
        });
    }

    Ok(Some((block_type, total, body)))
}

/// Parse the Section Header Block body.
fn parse_shb(body: &[u8]) -> Result<(ByteOrder, u64)> {
    if body.len() < 16 {
        return Err(Error::MalformedCapture {
            message: format!(
                "Section Header Block body too small ({} bytes, need 16)",
                body.len()
            ),
        });
    }
    let byte_order_magic = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let order = match byte_order_magic {
        0x01020304 => ByteOrder::LittleEndian,
        0x04030201 => ByteOrder::BigEndian,
        other => {
            return Err(Error::HeaderValidation {
                message: format!("unknown PCAPNG byte-order magic {other:08X}"),
            });
        }
    };
    let major = u16::from_le_bytes([body[4], body[5]]);
    let minor = u16::from_le_bytes([body[6], body[7]]);
    if (major, minor) != (1, 0) {
        return Err(Error::HeaderValidation {
            message: format!("unsupported PCAPNG version {major}.{minor}"),
        });
    }
    let section_len = u64::from_le_bytes([
        body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
    ]);
    // SHB options (bytes 16..) are recorded but not interpreted by this
    // release; time resolution is reported as raw ticks.
    let _ = section_len;
    Ok((order, 0))
}

/// Parse an Interface Description Block body.
fn parse_idb(body: &[u8], order: ByteOrder) -> Option<Interface> {
    if body.len() < 8 {
        return None;
    }
    let link_type = read_u16(&body[0..2], order);
    // bytes 2..4: reserved; bytes 4..8: snaplen (not interpreted here).
    let _ = read_u32(&body[4..8], order);
    Some(Interface { link_type })
}

/// Read up to `buf.len()` bytes from a stream; returns the count (0 = EOF).
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

/// Read exactly `buf.len()` bytes, or report truncation.
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
    } else {
        Err(Error::MalformedCapture {
            message: format!("truncated {what} ({n} of {} bytes present)", buf.len()),
        })
    }
}

/// 4-byte value in the stream's byte order; caller guarantees `bytes.len() >= 4`.
fn read_u32(bytes: &[u8], order: ByteOrder) -> u32 {
    match order {
        ByteOrder::LittleEndian => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        ByteOrder::BigEndian => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    }
}

/// 2-byte value in the stream's byte order; caller guarantees `bytes.len() >= 2`.
fn read_u16(bytes: &[u8], order: ByteOrder) -> u32 {
    match order {
        ByteOrder::LittleEndian => u16::from_le_bytes([bytes[0], bytes[1]]) as u32,
        ByteOrder::BigEndian => u16::from_be_bytes([bytes[0], bytes[1]]) as u32,
    }
}

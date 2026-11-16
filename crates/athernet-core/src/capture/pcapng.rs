//! pcapng files.
//!
//! A sequence of length-delimited blocks. We care about four of them: the
//! section header (which sets the byte order), the interface description
//! (link type, snaplen, timestamp resolution), the packet blocks, and the
//! interface statistics - which is the only place a capture tells us how many
//! packets it dropped, and so the only reason we can say "this capture is
//! incomplete" instead of "the server never answered".

use std::io::Read;

use super::{rd_u16, rd_u32, rd_u64, ByteSource, CaptureError, LinkType, PacketRef, MAX_RECORD};

const BT_SHB: u32 = 0x0a0d_0d0a;
const BT_IDB: u32 = 0x0000_0001;
const BT_SPB: u32 = 0x0000_0003;
const BT_ISB: u32 = 0x0000_0005;
const BT_EPB: u32 = 0x0000_0006;

const OPT_END: u16 = 0;
const OPT_IF_TSRESOL: u16 = 9;
const OPT_ISB_IFDROP: u16 = 5;

#[derive(Debug, Clone, Copy)]
struct Interface {
    link_type: LinkType,
    snaplen: u32,
    /// nanoseconds = raw * ts_mul / ts_div
    ts_mul: u64,
    ts_div: u64,
}

impl Default for Interface {
    fn default() -> Self {
        // The format's default resolution is microseconds.
        Interface {
            link_type: LinkType::Ethernet,
            snaplen: 0,
            ts_mul: 1_000,
            ts_div: 1,
        }
    }
}

impl Interface {
    fn to_nanos(&self, raw: u64) -> i64 {
        let v = (raw as u128) * (self.ts_mul as u128) / (self.ts_div.max(1) as u128);
        v.min(i64::MAX as u128) as i64
    }
}

pub struct PcapNgReader<R: Read> {
    src: ByteSource<R>,
    big: bool,
    interfaces: Vec<Interface>,
    drops: u64,
    index: u64,
    pending: usize,
}

impl<R: Read> PcapNgReader<R> {
    pub fn from_source(mut src: ByteSource<R>) -> Result<Self, CaptureError> {
        let at = src.offset();
        if !src.ensure(12)? {
            return Err(CaptureError::Truncated { at });
        }
        let big = byte_order(&src.slice(12)[8..12], at)?;
        let total = rd_u32(&src.slice(12)[4..8], big) as usize;
        if !(12..=MAX_RECORD).contains(&total) {
            return Err(CaptureError::Oversized {
                at,
                len: total as u64,
            });
        }
        if !src.ensure(total)? {
            return Err(CaptureError::Truncated { at });
        }
        src.advance(total);
        Ok(Self {
            src,
            big,
            interfaces: Vec::new(),
            drops: 0,
            index: 0,
            pending: 0,
        })
    }

    pub fn snaplen(&self) -> u32 {
        self.interfaces.iter().map(|i| i.snaplen).max().unwrap_or(0)
    }

    pub fn reported_drops(&self) -> u64 {
        self.drops
    }

    pub fn link_types(&self) -> Vec<LinkType> {
        let mut seen: Vec<LinkType> = Vec::new();
        for iface in &self.interfaces {
            if !seen.contains(&iface.link_type) {
                seen.push(iface.link_type);
            }
        }
        seen
    }

    fn interface(&self, id: u32) -> Interface {
        self.interfaces
            .get(id as usize)
            .copied()
            .unwrap_or_default()
    }

    pub fn next_packet(&mut self) -> Result<Option<PacketRef<'_>>, CaptureError> {
        if self.pending > 0 {
            self.src.advance(self.pending);
            self.pending = 0;
        }
        loop {
            if !self.src.ensure(8)? {
                if self.src.available() == 0 {
                    return Ok(None);
                }
                return Err(CaptureError::Truncated {
                    at: self.src.offset(),
                });
            }
            let at = self.src.offset();
            let btype = rd_u32(&self.src.slice(8)[0..4], self.big);

            // A file may hold several sections, and a later one may even have
            // been written by a machine of the other byte order.
            if btype == BT_SHB {
                if !self.src.ensure(12)? {
                    return Err(CaptureError::Truncated { at });
                }
                let big = byte_order(&self.src.slice(12)[8..12], at)?;
                let total = rd_u32(&self.src.slice(12)[4..8], big) as usize;
                if !(12..=MAX_RECORD).contains(&total) {
                    return Err(CaptureError::Oversized {
                        at,
                        len: total as u64,
                    });
                }
                if !self.src.ensure(total)? {
                    return Err(CaptureError::Truncated { at });
                }
                self.big = big;
                self.interfaces.clear();
                self.src.advance(total);
                continue;
            }

            let blen = rd_u32(&self.src.slice(8)[4..8], self.big) as usize;
            if !(12..=MAX_RECORD).contains(&blen) || blen % 4 != 0 {
                return Err(CaptureError::Oversized {
                    at,
                    len: blen as u64,
                });
            }
            if !self.src.ensure(blen)? {
                return Err(CaptureError::Truncated { at });
            }

            match btype {
                BT_IDB => {
                    let iface = parse_idb(&self.src.slice(blen)[8..blen - 4], self.big);
                    self.interfaces.push(iface);
                    self.src.advance(blen);
                }
                BT_ISB => {
                    let drops = parse_isb_drops(&self.src.slice(blen)[8..blen - 4], self.big);
                    // Interface statistics are cumulative, so the highest
                    // figure we have seen is the count so far.
                    self.drops = self.drops.max(drops);
                    self.src.advance(blen);
                }
                BT_EPB => {
                    if blen < 32 {
                        return Err(CaptureError::Malformed {
                            at,
                            what: "enhanced packet block",
                        });
                    }
                    let (iface_id, ts_raw, caplen, orig_len) = {
                        let body = &self.src.slice(blen)[8..];
                        (
                            rd_u32(&body[0..4], self.big),
                            ((rd_u32(&body[4..8], self.big) as u64) << 32)
                                | rd_u32(&body[8..12], self.big) as u64,
                            rd_u32(&body[12..16], self.big) as usize,
                            rd_u32(&body[16..20], self.big),
                        )
                    };
                    if 28 + caplen + 4 > blen {
                        return Err(CaptureError::Malformed {
                            at,
                            what: "packet length in an enhanced packet block",
                        });
                    }
                    let iface = self.interface(iface_id);
                    let index = self.index;
                    self.index += 1;
                    self.pending = blen;
                    return Ok(Some(PacketRef {
                        index,
                        ts_nanos: iface.to_nanos(ts_raw),
                        orig_len,
                        offset: at + 28,
                        interface_id: iface_id,
                        link_type: iface.link_type,
                        data: &self.src.slice(blen)[28..28 + caplen],
                    }));
                }
                BT_SPB => {
                    if blen < 16 {
                        return Err(CaptureError::Malformed {
                            at,
                            what: "simple packet block",
                        });
                    }
                    let orig_len = rd_u32(&self.src.slice(blen)[8..12], self.big);
                    let caplen = (blen - 16).min(orig_len as usize);
                    let iface = self.interface(0);
                    let index = self.index;
                    self.index += 1;
                    self.pending = blen;
                    return Ok(Some(PacketRef {
                        index,
                        // A simple packet block carries no timestamp at all.
                        ts_nanos: 0,
                        orig_len,
                        offset: at + 12,
                        interface_id: 0,
                        link_type: iface.link_type,
                        data: &self.src.slice(blen)[12..12 + caplen],
                    }));
                }
                _ => {
                    // Name resolution, decryption secrets, custom blocks: not
                    // needed for the spike, skipped by length.
                    self.src.advance(blen);
                }
            }
        }
    }
}

fn byte_order(marker: &[u8], at: u64) -> Result<bool, CaptureError> {
    match marker {
        [0x1a, 0x2b, 0x3c, 0x4d] => Ok(true),
        [0x4d, 0x3c, 0x2b, 0x1a] => Ok(false),
        _ => Err(CaptureError::Malformed {
            at,
            what: "pcapng byte-order marker",
        }),
    }
}

fn parse_idb(body: &[u8], big: bool) -> Interface {
    let mut iface = Interface::default();
    if body.len() < 8 {
        return iface;
    }
    iface.link_type = LinkType::from_u16(rd_u16(&body[0..2], big));
    iface.snaplen = rd_u32(&body[4..8], big);
    for (code, value) in Options::new(&body[8..], big) {
        if code == OPT_IF_TSRESOL && !value.is_empty() {
            let raw = value[0];
            if raw & 0x80 != 0 {
                iface.ts_mul = 1_000_000_000;
                iface.ts_div = 1u64 << (raw & 0x3f);
            } else {
                let n = u32::from(raw.min(18));
                if n <= 9 {
                    iface.ts_mul = 10u64.pow(9 - n);
                    iface.ts_div = 1;
                } else {
                    iface.ts_mul = 1;
                    iface.ts_div = 10u64.pow(n - 9);
                }
            }
        }
    }
    iface
}

fn parse_isb_drops(body: &[u8], big: bool) -> u64 {
    if body.len() < 12 {
        return 0;
    }
    for (code, value) in Options::new(&body[12..], big) {
        if code == OPT_ISB_IFDROP && value.len() >= 8 {
            return rd_u64(&value[0..8], big);
        }
    }
    0
}

struct Options<'a> {
    bytes: &'a [u8],
    pos: usize,
    big: bool,
}

impl<'a> Options<'a> {
    fn new(bytes: &'a [u8], big: bool) -> Self {
        Options {
            bytes,
            pos: 0,
            big,
        }
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 4 > self.bytes.len() {
            return None;
        }
        let code = rd_u16(&self.bytes[self.pos..self.pos + 2], self.big);
        let len = rd_u16(&self.bytes[self.pos + 2..self.pos + 4], self.big) as usize;
        if code == OPT_END {
            return None;
        }
        let start = self.pos + 4;
        let end = start.checked_add(len)?;
        if end > self.bytes.len() {
            return None;
        }
        self.pos = start + ((len + 3) & !3);
        Some((code, &self.bytes[start..end]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureFile, Format};

    fn block(btype: u32, body: &[u8]) -> Vec<u8> {
        let total = 12 + body.len();
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&btype.to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out
    }

    fn shb() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x4d, 0x3c, 0x2b, 0x1a]);
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&(-1i64).to_le_bytes());
        block(BT_SHB, &body)
    }

    fn idb() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes()); // Ethernet
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&262_144u32.to_le_bytes());
        // if_tsresol = 6 (microseconds), padded to four bytes
        body.extend_from_slice(&OPT_IF_TSRESOL.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&[6, 0, 0, 0]);
        body.extend_from_slice(&OPT_END.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        block(BT_IDB, &body)
    }

    fn epb(ts_micros: u64, data: &[u8]) -> Vec<u8> {
        let pad = (4 - data.len() % 4) % 4;
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&(((ts_micros >> 32) as u32).to_le_bytes()));
        body.extend_from_slice(&((ts_micros as u32).to_le_bytes()));
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(data);
        body.extend_from_slice(&vec![0u8; pad]);
        block(BT_EPB, &body)
    }

    fn isb(drops: u64) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&OPT_ISB_IFDROP.to_le_bytes());
        body.extend_from_slice(&8u16.to_le_bytes());
        body.extend_from_slice(&drops.to_le_bytes());
        body.extend_from_slice(&OPT_END.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        block(BT_ISB, &body)
    }

    #[test]
    fn reads_blocks_and_keeps_the_drop_count() {
        let mut file = Vec::new();
        file.extend_from_slice(&shb());
        file.extend_from_slice(&idb());
        file.extend_from_slice(&epb(1_700_000_000_250_000, &[0x11; 54]));
        file.extend_from_slice(&epb(1_700_000_000_750_000, &[0x22; 60]));
        file.extend_from_slice(&isb(17));

        let mut capture = CaptureFile::open(&file[..]).unwrap();
        assert_eq!(capture.format(), Format::PcapNg);

        let first = capture.next_packet().unwrap().unwrap();
        assert_eq!(first.ts_nanos, 1_700_000_000_250_000_000);
        assert_eq!(first.data.len(), 54);
        assert!(!first.is_truncated());
        assert_eq!(file[first.offset as usize], 0x11);

        let second = capture.next_packet().unwrap().unwrap();
        assert_eq!(second.index, 1);
        assert_eq!(second.data.len(), 60);

        assert!(capture.next_packet().unwrap().is_none());
        assert_eq!(capture.reported_drops(), Some(17));
        assert_eq!(capture.snaplen(), 262_144);
    }

    #[test]
    fn an_unknown_block_is_skipped_not_fatal() {
        let mut file = Vec::new();
        file.extend_from_slice(&shb());
        file.extend_from_slice(&idb());
        file.extend_from_slice(&block(0x0000_0004, &[0u8; 16])); // name resolution
        file.extend_from_slice(&epb(1_000_000, &[0x33; 48]));
        let mut capture = CaptureFile::open(&file[..]).unwrap();
        let packet = capture.next_packet().unwrap().unwrap();
        assert_eq!(packet.data.len(), 48);
    }
}

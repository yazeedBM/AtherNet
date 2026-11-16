//! Classic libpcap files.
//!
//! A 24-byte file header, then a 16-byte record header before each packet.
//! Four magic numbers exist: microsecond or nanosecond timestamps, written by
//! a little-endian or a big-endian machine.

use std::io::Read;

use super::{rd_u32, ByteSource, CaptureError, LinkType, PacketRef, MAX_RECORD};

const FILE_HEADER_LEN: usize = 24;
const RECORD_HEADER_LEN: usize = 16;

pub struct PcapReader<R: Read> {
    src: ByteSource<R>,
    big: bool,
    nanos: bool,
    pub link_type: LinkType,
    pub snaplen: u32,
    index: u64,
    /// Bytes of the last packet, still borrowed by the caller. Skipped at the
    /// start of the next call.
    pending: usize,
}

impl<R: Read> PcapReader<R> {
    pub fn from_source(mut src: ByteSource<R>) -> Result<Self, CaptureError> {
        if !src.ensure(FILE_HEADER_LEN)? {
            return Err(CaptureError::Truncated { at: src.offset() });
        }
        let (big, nanos) = match src.slice(4) {
            [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
            [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
            [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
            [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
            _ => return Err(CaptureError::UnknownFormat),
        };
        let (snaplen, link_type) = {
            let h = src.slice(FILE_HEADER_LEN);
            (
                rd_u32(&h[16..20], big),
                LinkType::from_u16(rd_u32(&h[20..24], big) as u16),
            )
        };
        src.advance(FILE_HEADER_LEN);
        Ok(Self {
            src,
            big,
            nanos,
            link_type,
            snaplen,
            index: 0,
            pending: 0,
        })
    }

    pub fn next_packet(&mut self) -> Result<Option<PacketRef<'_>>, CaptureError> {
        if self.pending > 0 {
            self.src.advance(self.pending);
            self.pending = 0;
        }
        if !self.src.ensure(RECORD_HEADER_LEN)? {
            if self.src.available() == 0 {
                return Ok(None);
            }
            return Err(CaptureError::Truncated {
                at: self.src.offset(),
            });
        }
        let (ts_nanos, caplen, orig_len) = {
            let h = self.src.slice(RECORD_HEADER_LEN);
            let secs = rd_u32(&h[0..4], self.big) as i64;
            let frac = rd_u32(&h[4..8], self.big) as i64;
            let ts = secs
                .saturating_mul(1_000_000_000)
                .saturating_add(if self.nanos { frac } else { frac * 1_000 });
            (
                ts,
                rd_u32(&h[8..12], self.big) as usize,
                rd_u32(&h[12..16], self.big),
            )
        };
        if caplen > MAX_RECORD {
            return Err(CaptureError::Oversized {
                at: self.src.offset(),
                len: caplen as u64,
            });
        }
        self.src.advance(RECORD_HEADER_LEN);
        if !self.src.ensure(caplen)? {
            return Err(CaptureError::Truncated {
                at: self.src.offset(),
            });
        }
        let index = self.index;
        self.index += 1;
        self.pending = caplen;
        let offset = self.src.offset();
        let link_type = self.link_type;
        Ok(Some(PacketRef {
            index,
            ts_nanos,
            orig_len,
            offset,
            interface_id: 0,
            link_type,
            data: self.src.slice(caplen),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CaptureFile;

    /// A little-endian, microsecond pcap with the given packets.
    fn build(packets: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&262_144u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
        for (secs, usecs, data) in packets {
            out.extend_from_slice(&secs.to_le_bytes());
            out.extend_from_slice(&usecs.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32 + 8).to_le_bytes()); // on-wire length is longer
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn reads_every_packet_with_its_offset() {
        let file = build(&[
            (1_700_000_000, 500_000, vec![0xaa; 60]),
            (1_700_000_001, 0, vec![0xbb; 74]),
        ]);
        let mut capture = CaptureFile::open(&file[..]).unwrap();
        assert_eq!(capture.snaplen(), 262_144);
        assert_eq!(capture.reported_drops(), None);

        let first = capture.next_packet().unwrap().unwrap();
        assert_eq!(first.index, 0);
        assert_eq!(first.ts_nanos, 1_700_000_000_500_000_000);
        assert_eq!(first.data.len(), 60);
        assert_eq!(first.orig_len, 68);
        assert!(first.is_truncated());
        assert_eq!(first.offset, 24 + 16);
        assert_eq!(file[first.offset as usize], 0xaa);

        let second = capture.next_packet().unwrap().unwrap();
        assert_eq!(second.index, 1);
        assert_eq!(second.data.len(), 74);
        assert_eq!(second.offset, 24 + 16 + 60 + 16);

        assert!(capture.next_packet().unwrap().is_none());
    }

    #[test]
    fn a_cut_short_file_is_an_error_not_an_empty_capture() {
        let mut file = build(&[(1, 0, vec![0xcc; 100])]);
        file.truncate(24 + 16 + 40);
        let mut capture = CaptureFile::open(&file[..]).unwrap();
        match capture.next_packet() {
            Err(CaptureError::Truncated { .. }) => {}
            other => panic!("expected a truncation error, got {other:?}"),
        }
    }

    #[test]
    fn a_text_file_is_rejected_by_format() {
        let file = b"this is not a capture file".to_vec();
        match CaptureFile::open(&file[..]) {
            Err(CaptureError::UnknownFormat) => {}
            Err(e) => panic!("expected UnknownFormat, got {e:?}"),
            Ok(_) => panic!("expected UnknownFormat, but it opened as a capture"),
        }
    }
}

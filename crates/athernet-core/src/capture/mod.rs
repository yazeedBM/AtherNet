//! Capture file readers.
//!
//! One entry point, [`CaptureFile::open`], which sniffs the format and hands
//! back a reader. Both readers are lending iterators: `next_packet` borrows the
//! reader's buffer, so a packet is valid until the next call and never copied.

mod source;
pub mod pcap;
pub mod pcapng;

pub use source::ByteSource;

use std::fmt;
use std::io::Read;

/// Largest single record or block we will accept, as a guard against a corrupt
/// length field asking us to allocate a gigabyte.
pub const MAX_RECORD: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum CaptureError {
    Io(std::io::Error),
    /// The file is not a capture file we recognise.
    UnknownFormat,
    /// The file ends in the middle of a record.
    Truncated { at: u64 },
    Malformed { at: u64, what: &'static str },
    Oversized { at: u64, len: u64 },
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::Io(e) => write!(f, "could not read the file: {e}"),
            CaptureError::UnknownFormat => write!(
                f,
                "this is not a .pcap or .pcapng capture file (its first bytes match neither format)"
            ),
            CaptureError::Truncated { at } => write!(
                f,
                "the file ends in the middle of a record at byte {at}; it was probably cut short while being written"
            ),
            CaptureError::Malformed { at, what } => {
                write!(f, "unreadable {what} at byte {at}")
            }
            CaptureError::Oversized { at, len } => write!(
                f,
                "a record at byte {at} claims to be {len} bytes, which is past what we accept; the file is probably damaged"
            ),
        }
    }
}

impl std::error::Error for CaptureError {}

impl From<std::io::Error> for CaptureError {
    fn from(e: std::io::Error) -> Self {
        CaptureError::Io(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pcap,
    PcapNg,
}

impl Format {
    pub fn name(&self) -> &'static str {
        match self {
            Format::Pcap => "pcap",
            Format::PcapNg => "pcapng",
        }
    }
}

/// Link layer of a capture, as a LINKTYPE_ value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Null,
    Ethernet,
    RawIp,
    RawIpv4,
    RawIpv6,
    LinuxSll,
    Unsupported(u16),
}

impl LinkType {
    pub fn from_u16(v: u16) -> LinkType {
        match v {
            0 => LinkType::Null,
            1 => LinkType::Ethernet,
            101 => LinkType::RawIp,
            113 => LinkType::LinuxSll,
            228 => LinkType::RawIpv4,
            229 => LinkType::RawIpv6,
            other => LinkType::Unsupported(other),
        }
    }

    /// Plain-language name, for the import screen's error messages.
    pub fn name(&self) -> &'static str {
        match self {
            LinkType::Null => "loopback",
            LinkType::Ethernet => "Ethernet",
            LinkType::RawIp => "raw IP",
            LinkType::RawIpv4 => "raw IPv4",
            LinkType::RawIpv6 => "raw IPv6",
            LinkType::LinuxSll => "Linux cooked capture",
            LinkType::Unsupported(105) => "802.11 wireless",
            LinkType::Unsupported(127) => "802.11 with radiotap",
            LinkType::Unsupported(_) => "an unsupported link type",
        }
    }

    pub fn is_supported(&self) -> bool {
        !matches!(self, LinkType::Unsupported(_))
    }

    /// Whether this link layer carries MAC addresses at all. The addressing
    /// screen needs this to say "not available in this capture" rather than
    /// showing an empty table.
    pub fn has_mac_addresses(&self) -> bool {
        matches!(self, LinkType::Ethernet)
    }
}

/// One packet, borrowed from the reader's buffer.
#[derive(Debug, Clone, Copy)]
pub struct PacketRef<'a> {
    /// Zero-based position in the file.
    pub index: u64,
    /// Nanoseconds since the Unix epoch.
    pub ts_nanos: i64,
    /// Length on the wire, which may exceed `data.len()` if the capture was
    /// taken with a snaplen.
    pub orig_len: u32,
    /// Byte offset of the packet data within the file. This is what a finding
    /// stores so the UI can seek back to the bytes.
    pub offset: u64,
    pub interface_id: u32,
    pub link_type: LinkType,
    pub data: &'a [u8],
}

impl PacketRef<'_> {
    /// True when the capture holds less than the packet's full length.
    pub fn is_truncated(&self) -> bool {
        (self.data.len() as u32) < self.orig_len
    }
}

pub enum CaptureFile<R: Read> {
    Pcap(pcap::PcapReader<R>),
    PcapNg(pcapng::PcapNgReader<R>),
}

impl<R: Read> CaptureFile<R> {
    pub fn open(inner: R) -> Result<Self, CaptureError> {
        let mut src = ByteSource::new(inner, 1 << 20);
        if !src.ensure(4)? {
            return Err(CaptureError::UnknownFormat);
        }
        // A pcapng Section Header Block starts 0A 0D 0D 0A whichever way round
        // the file was written, which is why it was chosen.
        let is_pcapng = matches!(src.slice(4), [0x0a, 0x0d, 0x0d, 0x0a]);
        if is_pcapng {
            Ok(CaptureFile::PcapNg(pcapng::PcapNgReader::from_source(src)?))
        } else {
            Ok(CaptureFile::Pcap(pcap::PcapReader::from_source(src)?))
        }
    }

    pub fn format(&self) -> Format {
        match self {
            CaptureFile::Pcap(_) => Format::Pcap,
            CaptureFile::PcapNg(_) => Format::PcapNg,
        }
    }

    pub fn next_packet(&mut self) -> Result<Option<PacketRef<'_>>, CaptureError> {
        match self {
            CaptureFile::Pcap(r) => r.next_packet(),
            CaptureFile::PcapNg(r) => r.next_packet(),
        }
    }

    pub fn snaplen(&self) -> u32 {
        match self {
            CaptureFile::Pcap(r) => r.snaplen,
            CaptureFile::PcapNg(r) => r.snaplen(),
        }
    }

    /// Packets the capture tool itself reported dropping. Only pcapng carries
    /// this; a pcap file cannot tell us, which is its own limitation.
    pub fn reported_drops(&self) -> Option<u64> {
        match self {
            CaptureFile::Pcap(_) => None,
            CaptureFile::PcapNg(r) => Some(r.reported_drops()),
        }
    }

    pub fn link_types(&self) -> Vec<LinkType> {
        match self {
            CaptureFile::Pcap(r) => vec![r.link_type],
            CaptureFile::PcapNg(r) => r.link_types(),
        }
    }
}

#[inline]
pub(crate) fn rd_u16(b: &[u8], big: bool) -> u16 {
    let v = [b[0], b[1]];
    if big {
        u16::from_be_bytes(v)
    } else {
        u16::from_le_bytes(v)
    }
}

#[inline]
pub(crate) fn rd_u32(b: &[u8], big: bool) -> u32 {
    let v = [b[0], b[1], b[2], b[3]];
    if big {
        u32::from_be_bytes(v)
    } else {
        u32::from_le_bytes(v)
    }
}

#[inline]
pub(crate) fn rd_u64(b: &[u8], big: bool) -> u64 {
    let v = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
    if big {
        u64::from_be_bytes(v)
    } else {
        u64::from_le_bytes(v)
    }
}

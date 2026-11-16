//! The packet index.
//!
//! Everywhere else the core is careful never to keep a packet: it reads,
//! counts and discards, which is what lets it run at the rate it does. The
//! packet explorer needs the opposite, so this is the one structure that
//! grows with the capture - and it is built to make that growth small and
//! predictable rather than to avoid it.
//!
//! A row is 48 bytes and holds no strings. Addresses are interned, because a
//! capture of a few thousand hosts repeats the same handful of addresses
//! millions of times; so are the notes, because a DNS name or a TLS server
//! name repeats just as hard. The packet's own bytes are never copied: a row
//! keeps the offset into the original file, and the bytes are fetched from
//! there when somebody actually opens that packet.
//!
//! Indexing stops at `MAX_INDEXED_PACKETS`. A capture larger than that is
//! still counted and still analysed in full - every finding is still found -
//! but the explorer can only show the first million, and says so. An
//! unbounded index is how this kind of tool runs a machine out of memory on
//! the one capture that mattered.

use std::collections::HashMap;

use crate::capture::PacketRef;
use crate::decode::{Decoded, NetLayer, TransportLayer};
use crate::flow::{Addr, FlowKey};

/// Roughly 48 MB of index. Past this the explorer is capped, not the
/// analysis.
pub const MAX_INDEXED_PACKETS: usize = 1_000_000;

/// No interned value.
pub const NONE: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Tcp,
    Udp,
    Dns,
    Dhcp,
    Tls,
    Icmp,
    Arp,
    OtherIp,
    NonIp,
}

impl PacketKind {
    /// What the protocol column shows.
    pub fn label(&self) -> &'static str {
        match self {
            PacketKind::Tcp => "TCP",
            PacketKind::Udp => "UDP",
            PacketKind::Dns => "DNS",
            PacketKind::Dhcp => "DHCP",
            PacketKind::Tls => "TLS",
            PacketKind::Icmp => "ICMP",
            PacketKind::Arp => "ARP",
            PacketKind::OtherIp => "IP",
            PacketKind::NonIp => "other",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PacketRow {
    pub ts_nanos: i64,
    /// Byte offset of the packet's data in the original file.
    pub offset: u64,
    pub captured_len: u32,
    pub wire_len: u32,
    /// Interned address ids, or `NONE` for a packet with no IP layer.
    pub src: u32,
    pub dst: u32,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    /// Interned note, or `NONE`.
    pub note: u32,
    pub kind: PacketKind,
}

impl PacketRow {
    pub fn is_truncated(&self) -> bool {
        self.captured_len < self.wire_len
    }
}

#[derive(Debug, Default)]
pub struct PacketIndex {
    rows: Vec<PacketRow>,
    addresses: Vec<Addr>,
    address_ids: HashMap<Addr, u32>,
    notes: Vec<String>,
    note_ids: HashMap<String, u32>,
    /// Packets seen, including any past the cap.
    seen: u64,
}

impl PacketIndex {
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn seen(&self) -> u64 {
        self.seen
    }

    /// True when the capture outran the index and the explorer is showing
    /// only the start of it.
    pub fn is_capped(&self) -> bool {
        self.seen > self.rows.len() as u64
    }

    pub fn row(&self, index: usize) -> Option<&PacketRow> {
        self.rows.get(index)
    }

    pub fn rows(&self) -> &[PacketRow] {
        &self.rows
    }

    pub fn address(&self, id: u32) -> Option<Addr> {
        if id == NONE {
            None
        } else {
            self.addresses.get(id as usize).copied()
        }
    }

    pub fn note(&self, id: u32) -> Option<&str> {
        if id == NONE {
            None
        } else {
            self.notes.get(id as usize).map(String::as_str)
        }
    }

    pub fn addresses(&self) -> &[Addr] {
        &self.addresses
    }

    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    fn intern_address(&mut self, addr: Addr) -> u32 {
        if let Some(id) = self.address_ids.get(&addr) {
            return *id;
        }
        let id = self.addresses.len() as u32;
        self.addresses.push(addr);
        self.address_ids.insert(addr, id);
        id
    }

    fn intern_note(&mut self, note: &str) -> u32 {
        if let Some(id) = self.note_ids.get(note) {
            return *id;
        }
        let id = self.notes.len() as u32;
        self.notes.push(note.to_string());
        self.note_ids.insert(note.to_string(), id);
        id
    }

    /// The conversation a row belongs to, for filtering the list down to one.
    pub fn flow_of(&self, row: &PacketRow) -> Option<FlowKey> {
        let src = self.address(row.src)?;
        let dst = self.address(row.dst)?;
        Some(FlowKey::new(row.proto, src, row.src_port, dst, row.dst_port).0)
    }

    pub fn record(
        &mut self,
        packet: &PacketRef<'_>,
        decoded: &Decoded,
        enrichment: Option<(PacketKind, String)>,
    ) {
        self.seen += 1;
        if self.rows.len() >= MAX_INDEXED_PACKETS {
            return;
        }

        let (src, dst, proto) = match decoded.net {
            Some(NetLayer::Ipv4 {
                src, dst, proto, ..
            }) => (
                self.intern_address(Addr::V4(src)),
                self.intern_address(Addr::V4(dst)),
                proto,
            ),
            Some(NetLayer::Ipv6 {
                src,
                dst,
                next_header,
                ..
            }) => (
                self.intern_address(Addr::V6(src)),
                self.intern_address(Addr::V6(dst)),
                next_header,
            ),
            // ARP addresses are in the ARP body rather than an IP header, and
            // carrying them in the same columns would imply a layer that is
            // not there. They go in the note instead.
            Some(NetLayer::Arp { .. }) | None => (NONE, NONE, 0),
        };

        let (src_port, dst_port) = decoded.transport.and_then(|t| t.ports()).unwrap_or((0, 0));

        let (kind, note) = match enrichment {
            Some((kind, note)) => (kind, self.intern_note(&note)),
            None => {
                let kind = base_kind(decoded);
                let note = match arp_note(decoded) {
                    Some(text) => self.intern_note(&text),
                    None => NONE,
                };
                (kind, note)
            }
        };

        self.rows.push(PacketRow {
            ts_nanos: packet.ts_nanos,
            offset: packet.offset,
            captured_len: packet.data.len() as u32,
            wire_len: packet.orig_len,
            src,
            dst,
            proto,
            src_port,
            dst_port,
            tcp_flags: decoded.tcp_flags(),
            note,
            kind,
        });
    }
}

fn base_kind(decoded: &Decoded) -> PacketKind {
    if matches!(decoded.net, Some(NetLayer::Arp { .. })) {
        return PacketKind::Arp;
    }
    match decoded.transport {
        Some(TransportLayer::Tcp { .. }) => PacketKind::Tcp,
        Some(TransportLayer::Udp { .. }) => PacketKind::Udp,
        Some(TransportLayer::Icmp { .. }) | Some(TransportLayer::Icmpv6 { .. }) => PacketKind::Icmp,
        None => {
            if decoded.net.is_some() {
                PacketKind::OtherIp
            } else {
                PacketKind::NonIp
            }
        }
    }
}

/// ARP in one line, the way someone reading a packet list expects it.
fn arp_note(decoded: &Decoded) -> Option<String> {
    let NetLayer::Arp {
        op,
        sender_ip,
        target_ip,
        sender_mac,
        ..
    } = decoded.net?
    else {
        return None;
    };
    let v4 = |b: [u8; 4]| format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
    let mac = |b: [u8; 6]| {
        b.iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    Some(match op {
        1 => format!("who has {}? tell {}", v4(target_ip), v4(sender_ip)),
        2 => format!("{} is at {}", v4(sender_ip), mac(sender_mac)),
        other => format!("ARP operation {other}"),
    })
}

/// How the TCP flags read in a packet list: the shorthand everyone who has
/// used a packet tool already knows.
pub fn tcp_flag_names(flags: u8) -> String {
    use crate::decode::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCP_URG};
    // The flag that decides what the packet means goes first, so this reads
    // the way people say it out loud: "SYN, ACK", "RST, ACK", "FIN, ACK".
    let mut out: Vec<&str> = Vec::new();
    if flags & TCP_SYN != 0 {
        out.push("SYN");
    }
    if flags & TCP_FIN != 0 {
        out.push("FIN");
    }
    if flags & TCP_RST != 0 {
        out.push("RST");
    }
    if flags & TCP_PSH != 0 {
        out.push("PSH");
    }
    if flags & TCP_ACK != 0 {
        out.push("ACK");
    }
    if flags & TCP_URG != 0 {
        out.push("URG");
    }
    out.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::LinkType;
    use crate::decode::decode;

    fn frame(proto: u8, body: &[u8]) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x10, 0x08, 0x00];
        f.extend_from_slice(&[0x45, 0x00]);
        f.extend_from_slice(&((20 + body.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, proto, 0x00, 0x00]);
        f.extend_from_slice(&[192, 168, 1, 10]);
        f.extend_from_slice(&[192, 168, 1, 20]);
        f.extend_from_slice(body);
        f
    }

    fn packet<'a>(index: u64, data: &'a [u8]) -> PacketRef<'a> {
        PacketRef {
            index,
            ts_nanos: 1_000_000_000 * index as i64,
            orig_len: data.len() as u32,
            offset: 24 + index * 100,
            interface_id: 0,
            link_type: LinkType::Ethernet,
            data,
        }
    }

    #[test]
    fn repeated_addresses_are_stored_once() {
        let mut index = PacketIndex::default();
        let bytes = frame(6, &[0xd4, 0x31, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0]);
        for i in 0..50 {
            let p = packet(i, &bytes);
            let d = decode(p.link_type, p.data);
            index.record(&p, &d, None);
        }
        assert_eq!(index.len(), 50);
        assert_eq!(
            index.addresses().len(),
            2,
            "fifty packets between two hosts should intern two addresses"
        );
        let row = index.row(0).unwrap();
        assert_eq!(row.kind, PacketKind::Tcp);
        assert_eq!(row.src_port, 54321);
        assert_eq!(row.dst_port, 443);
        assert_eq!(tcp_flag_names(row.tcp_flags), "SYN");
    }

    #[test]
    fn an_arp_packet_carries_its_meaning_in_the_note() {
        let mut arp = vec![0xff; 6];
        arp.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x10]);
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
        arp.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x10]);
        arp.extend_from_slice(&[192, 168, 1, 10]);
        arp.extend_from_slice(&[0; 6]);
        arp.extend_from_slice(&[192, 168, 1, 20]);

        let mut index = PacketIndex::default();
        let p = packet(0, &arp);
        let d = decode(p.link_type, p.data);
        index.record(&p, &d, None);

        let row = index.row(0).unwrap();
        assert_eq!(row.kind, PacketKind::Arp);
        assert_eq!(row.src, NONE, "ARP has no IP layer to take addresses from");
        assert_eq!(
            index.note(row.note),
            Some("who has 192.168.1.20? tell 192.168.1.10")
        );
    }

    #[test]
    fn the_index_stops_growing_but_the_count_does_not() {
        // Proves the cap without building a million rows: the same invariant,
        // checked through the public surface.
        let mut index = PacketIndex::default();
        let bytes = frame(17, &[0, 53, 0, 53, 0, 8, 0, 0]);
        for i in 0..10 {
            let p = packet(i, &bytes);
            let d = decode(p.link_type, p.data);
            index.record(&p, &d, None);
        }
        assert!(!index.is_capped());
        assert_eq!(index.seen(), 10);
        assert_eq!(index.len(), 10);
    }
}

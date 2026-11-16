//! Header decoding: link, network and transport only.
//!
//! This is pass 2 of the pipeline in the design proposal. It reads the headers
//! every packet has and stops there - application-layer dissection (DNS, DHCP,
//! TLS, HTTP) runs later, over the few percent of packets that need it.
//!
//! Nothing here allocates, and nothing copies: a `Decoded` is plain data and
//! payload is reported as an offset and length into the packet.

use crate::capture::LinkType;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;
pub const IP_PROTO_ICMPV6: u8 = 58;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetLayer {
    Ipv4 {
        src: [u8; 4],
        dst: [u8; 4],
        proto: u8,
        ttl: u8,
        total_len: u16,
        /// True when this is a fragment other than the first, so the transport
        /// header is not in this packet.
        fragmented: bool,
    },
    Ipv6 {
        src: [u8; 16],
        dst: [u8; 16],
        next_header: u8,
        hop_limit: u8,
    },
    Arp {
        op: u16,
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportLayer {
    Tcp {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        length: u16,
    },
    Icmp {
        kind: u8,
        code: u8,
    },
    Icmpv6 {
        kind: u8,
        code: u8,
    },
}

impl TransportLayer {
    pub fn ports(&self) -> Option<(u16, u16)> {
        match self {
            TransportLayer::Tcp {
                src_port, dst_port, ..
            } => Some((*src_port, *dst_port)),
            TransportLayer::Udp {
                src_port, dst_port, ..
            } => Some((*src_port, *dst_port)),
            _ => None,
        }
    }

    pub fn protocol_number(&self) -> u8 {
        match self {
            TransportLayer::Tcp { .. } => IP_PROTO_TCP,
            TransportLayer::Udp { .. } => IP_PROTO_UDP,
            TransportLayer::Icmp { .. } => IP_PROTO_ICMP,
            TransportLayer::Icmpv6 { .. } => IP_PROTO_ICMPV6,
        }
    }
}

/// The TCP options this app has a use for.
///
/// Everything else in the option space is stepped over. Three of them matter
/// here: the window scale, because without it the window field on a modern
/// connection means nothing; the maximum segment size, because it is the
/// clearest statement of what each end thinks the path can carry; and
/// whether selective acknowledgement was offered, because its absence
/// changes how a connection recovers from loss.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpOptions {
    /// Shift to apply to every window field after the handshake. Offered in
    /// the SYN and only in the SYN, which is why a capture that starts
    /// mid-connection cannot interpret window sizes at all.
    pub window_scale: Option<u8>,
    pub mss: Option<u16>,
    pub sack_permitted: bool,
}

impl TcpOptions {
    pub fn is_empty(&self) -> bool {
        *self == TcpOptions::default()
    }
}

/// Read the option space that follows a TCP header.
///
/// Anything malformed stops the walk rather than being guessed past: options
/// are length-prefixed, and a wrong length walked through would turn the
/// rest of the space into nonsense that happens to parse.
fn parse_tcp_options(options: &[u8]) -> TcpOptions {
    let mut out = TcpOptions::default();
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            // End of the list.
            0 => break,
            // A single byte of padding.
            1 => i += 1,
            kind => {
                if i + 1 >= options.len() {
                    break;
                }
                let len = options[i + 1] as usize;
                if len < 2 || i + len > options.len() {
                    break;
                }
                let value = &options[i + 2..i + len];
                match (kind, value.len()) {
                    (2, 2) => out.mss = Some(be16(value)),
                    // The standard caps the shift at 14; anything larger is
                    // a sender being wrong, and is treated as the cap.
                    (3, 1) => out.window_scale = Some(value[0].min(14)),
                    (4, 0) => out.sack_permitted = true,
                    _ => {}
                }
                i += len;
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Decoded {
    pub eth_src: Option<[u8; 6]>,
    pub eth_dst: Option<[u8; 6]>,
    pub vlan: Option<u16>,
    pub net: Option<NetLayer>,
    pub transport: Option<TransportLayer>,
    /// Offset and length of the application payload within the packet.
    pub payload: Option<(usize, usize)>,
    /// A header ran past the captured bytes. Usually snaplen truncation, and
    /// the reason a detector downgrades its confidence rather than guessing.
    pub short: bool,
    /// The TCP options, where the packet carried any.
    pub tcp_options: TcpOptions,
}

impl Decoded {
    pub fn is_tcp(&self) -> bool {
        matches!(self.transport, Some(TransportLayer::Tcp { .. }))
    }

    pub fn tcp_flags(&self) -> u8 {
        match self.transport {
            Some(TransportLayer::Tcp { flags, .. }) => flags,
            _ => 0,
        }
    }
}

#[inline]
fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[inline]
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
fn mac(b: &[u8]) -> [u8; 6] {
    [b[0], b[1], b[2], b[3], b[4], b[5]]
}

#[inline]
fn v4(b: &[u8]) -> [u8; 4] {
    [b[0], b[1], b[2], b[3]]
}

fn v6(b: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&b[0..16]);
    out
}

/// Decode one packet's headers.
pub fn decode(link: LinkType, bytes: &[u8]) -> Decoded {
    let mut out = Decoded::default();
    match link {
        LinkType::Ethernet => decode_ethernet(bytes, &mut out),
        LinkType::LinuxSll => {
            if bytes.len() < 16 {
                out.short = true;
                return out;
            }
            let ethertype = be16(&bytes[14..16]);
            decode_network(ethertype, bytes, 16, &mut out);
        }
        LinkType::Null => {
            if bytes.len() < 4 {
                out.short = true;
                return out;
            }
            // Host byte order family: 2 is AF_INET either way round.
            let family = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let ethertype = match family {
                2 => ETHERTYPE_IPV4,
                24 | 28 | 30 => ETHERTYPE_IPV6,
                _ => ETHERTYPE_IPV4,
            };
            decode_network(ethertype, bytes, 4, &mut out);
        }
        LinkType::RawIp | LinkType::RawIpv4 | LinkType::RawIpv6 => {
            if bytes.is_empty() {
                out.short = true;
                return out;
            }
            let ethertype = match bytes[0] >> 4 {
                6 => ETHERTYPE_IPV6,
                _ => ETHERTYPE_IPV4,
            };
            decode_network(ethertype, bytes, 0, &mut out);
        }
        LinkType::Unsupported(_) => {}
    }
    out
}

fn decode_ethernet(bytes: &[u8], out: &mut Decoded) {
    if bytes.len() < 14 {
        out.short = true;
        return;
    }
    out.eth_dst = Some(mac(&bytes[0..6]));
    out.eth_src = Some(mac(&bytes[6..12]));
    let mut offset = 12;
    let mut ethertype = be16(&bytes[offset..offset + 2]);
    offset += 2;
    // Up to two stacked VLAN tags.
    for _ in 0..2 {
        if ethertype != ETHERTYPE_VLAN && ethertype != ETHERTYPE_QINQ {
            break;
        }
        if bytes.len() < offset + 4 {
            out.short = true;
            return;
        }
        out.vlan = Some(be16(&bytes[offset..offset + 2]) & 0x0fff);
        ethertype = be16(&bytes[offset + 2..offset + 4]);
        offset += 4;
    }
    decode_network(ethertype, bytes, offset, out);
}

fn decode_network(ethertype: u16, bytes: &[u8], offset: usize, out: &mut Decoded) {
    match ethertype {
        ETHERTYPE_IPV4 => decode_ipv4(bytes, offset, out),
        ETHERTYPE_IPV6 => decode_ipv6(bytes, offset, out),
        ETHERTYPE_ARP => decode_arp(bytes, offset, out),
        _ => {}
    }
}

fn decode_ipv4(bytes: &[u8], offset: usize, out: &mut Decoded) {
    if bytes.len() < offset + 20 {
        out.short = true;
        return;
    }
    let b = &bytes[offset..];
    let ihl = ((b[0] & 0x0f) as usize) * 4;
    if ihl < 20 || bytes.len() < offset + ihl {
        out.short = true;
        return;
    }
    let frag_field = be16(&b[6..8]);
    let fragmented = (frag_field & 0x1fff) != 0;
    let total_len = be16(&b[2..4]);
    let proto = b[9];
    out.net = Some(NetLayer::Ipv4 {
        src: v4(&b[12..16]),
        dst: v4(&b[16..20]),
        proto,
        ttl: b[8],
        total_len,
        fragmented,
    });
    if fragmented {
        return;
    }
    // Trust the header's own length where the capture holds it, so trailing
    // Ethernet padding is not counted as payload.
    let end = if total_len as usize >= ihl {
        (offset + total_len as usize).min(bytes.len())
    } else {
        bytes.len()
    };
    decode_transport(proto, bytes, offset + ihl, end, out);
}

fn decode_ipv6(bytes: &[u8], offset: usize, out: &mut Decoded) {
    if bytes.len() < offset + 40 {
        out.short = true;
        return;
    }
    let b = &bytes[offset..];
    let payload_len = be16(&b[4..6]) as usize;
    let mut next = b[6];
    out.net = Some(NetLayer::Ipv6 {
        src: v6(&b[8..24]),
        dst: v6(&b[24..40]),
        next_header: next,
        hop_limit: b[7],
    });
    let mut cursor = offset + 40;
    let end = (offset + 40 + payload_len).min(bytes.len());
    // Walk the common extension headers. Four is plenty in practice.
    for _ in 0..4 {
        let is_extension = matches!(next, 0 | 43 | 60 | 135);
        if !is_extension {
            break;
        }
        if bytes.len() < cursor + 2 {
            out.short = true;
            return;
        }
        let ext_len = (bytes[cursor + 1] as usize + 1) * 8;
        next = bytes[cursor];
        cursor += ext_len;
        if cursor > bytes.len() {
            out.short = true;
            return;
        }
    }
    if next == 44 {
        // A fragment header: the transport header is only in the first piece.
        return;
    }
    decode_transport(next, bytes, cursor, end, out);
}

fn decode_arp(bytes: &[u8], offset: usize, out: &mut Decoded) {
    if bytes.len() < offset + 28 {
        out.short = true;
        return;
    }
    let b = &bytes[offset..];
    // Only Ethernet-over-IPv4 ARP carries the mapping we care about.
    if be16(&b[0..2]) != 1 || be16(&b[2..4]) != ETHERTYPE_IPV4 || b[4] != 6 || b[5] != 4 {
        return;
    }
    out.net = Some(NetLayer::Arp {
        op: be16(&b[6..8]),
        sender_mac: mac(&b[8..14]),
        sender_ip: v4(&b[14..18]),
        target_mac: mac(&b[18..24]),
        target_ip: v4(&b[24..28]),
    });
}

fn decode_transport(proto: u8, bytes: &[u8], offset: usize, end: usize, out: &mut Decoded) {
    let end = end.min(bytes.len());
    if offset > end {
        out.short = true;
        return;
    }
    match proto {
        IP_PROTO_TCP => {
            if end < offset + 20 {
                out.short = true;
                return;
            }
            let b = &bytes[offset..end];
            let data_offset = ((b[12] >> 4) as usize) * 4;
            if data_offset < 20 {
                out.short = true;
                return;
            }
            out.transport = Some(TransportLayer::Tcp {
                src_port: be16(&b[0..2]),
                dst_port: be16(&b[2..4]),
                seq: be32(&b[4..8]),
                ack: be32(&b[8..12]),
                flags: b[13],
                window: be16(&b[14..16]),
            });
            if b.len() >= data_offset {
                out.payload = Some((offset + data_offset, b.len() - data_offset));
                if data_offset > 20 {
                    out.tcp_options = parse_tcp_options(&b[20..data_offset]);
                }
            } else {
                out.short = true;
            }
        }
        IP_PROTO_UDP => {
            if end < offset + 8 {
                out.short = true;
                return;
            }
            let b = &bytes[offset..end];
            out.transport = Some(TransportLayer::Udp {
                src_port: be16(&b[0..2]),
                dst_port: be16(&b[2..4]),
                length: be16(&b[4..6]),
            });
            out.payload = Some((offset + 8, b.len() - 8));
        }
        IP_PROTO_ICMP => {
            if end < offset + 4 {
                out.short = true;
                return;
            }
            out.transport = Some(TransportLayer::Icmp {
                kind: bytes[offset],
                code: bytes[offset + 1],
            });
            out.payload = Some((offset + 8, end.saturating_sub(offset + 8)));
        }
        IP_PROTO_ICMPV6 => {
            if end < offset + 4 {
                out.short = true;
                return;
            }
            out.transport = Some(TransportLayer::Icmpv6 {
                kind: bytes[offset],
                code: bytes[offset + 1],
            });
            out.payload = Some((offset + 8, end.saturating_sub(offset + 8)));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet_ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
        frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let total_len = 20 + payload.len();
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&(total_len as u16).to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, proto, 0x00, 0x00]);
        frame.extend_from_slice(&[192, 168, 1, 10]);
        frame.extend_from_slice(&[192, 168, 1, 1]);
        frame.extend_from_slice(payload);
        frame
    }

    fn tcp(src: u16, dst: u16, flags: u8) -> Vec<u8> {
        let mut seg = Vec::new();
        seg.extend_from_slice(&src.to_be_bytes());
        seg.extend_from_slice(&dst.to_be_bytes());
        seg.extend_from_slice(&1000u32.to_be_bytes());
        seg.extend_from_slice(&0u32.to_be_bytes());
        seg.push(0x50); // data offset 5 words
        seg.push(flags);
        seg.extend_from_slice(&64240u16.to_be_bytes());
        seg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        seg
    }

    #[test]
    fn decodes_a_tcp_syn() {
        let frame = ethernet_ipv4(IP_PROTO_TCP, &tcp(51514, 443, TCP_SYN));
        let d = decode(LinkType::Ethernet, &frame);
        assert_eq!(d.eth_src, Some([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]));
        assert!(!d.short);
        match d.net {
            Some(NetLayer::Ipv4 { src, dst, proto, .. }) => {
                assert_eq!(src, [192, 168, 1, 10]);
                assert_eq!(dst, [192, 168, 1, 1]);
                assert_eq!(proto, IP_PROTO_TCP);
            }
            other => panic!("expected IPv4, got {other:?}"),
        }
        assert_eq!(d.transport.and_then(|t| t.ports()), Some((51514, 443)));
        assert_eq!(d.tcp_flags() & TCP_SYN, TCP_SYN);
        assert_eq!(d.payload, Some((54, 0)));
    }

    #[test]
    fn reads_the_options_that_change_what_a_window_means() {
        // A SYN with maximum segment size, selective acknowledgement, a
        // no-op for alignment, and a window scale.
        let mut seg = tcp(51514, 443, TCP_SYN);
        seg[12] = 0xa0; // data offset of ten words: twenty bytes of options
        seg.extend_from_slice(&[2, 4, 0x05, 0xb4]); // MSS 1460
        seg.extend_from_slice(&[4, 2]); // SACK permitted
        seg.extend_from_slice(&[1]); // no-op
        seg.extend_from_slice(&[3, 3, 7]); // window scale, shift of seven
        seg.extend_from_slice(&[0]); // end of options
        seg.extend_from_slice(&[0; 9]); // padding out to the data offset

        let frame = ethernet_ipv4(IP_PROTO_TCP, &seg);
        let d = decode(LinkType::Ethernet, &frame);
        assert_eq!(d.tcp_options.mss, Some(1460));
        assert_eq!(d.tcp_options.window_scale, Some(7));
        assert!(d.tcp_options.sack_permitted);
        assert_eq!(d.payload, Some((34 + 40, 0)), "options are not payload");
    }

    #[test]
    fn an_option_with_a_wrong_length_stops_the_walk() {
        let mut seg = tcp(51514, 443, TCP_SYN);
        seg[12] = 0x70; // seven words: eight bytes of options
        seg.extend_from_slice(&[3, 3, 7]); // a good window scale first
        seg.extend_from_slice(&[2, 40, 0, 0]); // then a length that runs off
        seg.extend_from_slice(&[0]);

        let frame = ethernet_ipv4(IP_PROTO_TCP, &seg);
        let d = decode(LinkType::Ethernet, &frame);
        // What was read before the bad length stands; nothing after it is
        // invented.
        assert_eq!(d.tcp_options.window_scale, Some(7));
        assert_eq!(d.tcp_options.mss, None);
    }

    #[test]
    fn a_truncated_packet_is_flagged_not_guessed() {
        let frame = ethernet_ipv4(IP_PROTO_TCP, &tcp(1, 2, TCP_ACK));
        let d = decode(LinkType::Ethernet, &frame[..40]);
        assert!(d.short);
        assert!(d.transport.is_none());
        // The addresses we did see are still reported.
        assert!(d.net.is_some());
    }

    #[test]
    fn decodes_an_arp_reply() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&[6, 4]);
        frame.extend_from_slice(&2u16.to_be_bytes()); // reply
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[192, 168, 1, 1]);
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        frame.extend_from_slice(&[192, 168, 1, 10]);
        let d = decode(LinkType::Ethernet, &frame);
        match d.net {
            Some(NetLayer::Arp { op, sender_ip, sender_mac, .. }) => {
                assert_eq!(op, 2);
                assert_eq!(sender_ip, [192, 168, 1, 1]);
                assert_eq!(sender_mac, [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
            }
            other => panic!("expected ARP, got {other:?}"),
        }
    }

    #[test]
    fn reads_through_a_vlan_tag() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00; 6]);
        frame.extend_from_slice(&[0x01; 6]);
        frame.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        frame.extend_from_slice(&0x0065u16.to_be_bytes()); // VLAN 101
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let inner = ethernet_ipv4(IP_PROTO_UDP, &[0, 53, 0, 53, 0, 8, 0, 0]);
        frame.extend_from_slice(&inner[14..]);
        let d = decode(LinkType::Ethernet, &frame);
        assert_eq!(d.vlan, Some(101));
        assert_eq!(d.transport.and_then(|t| t.ports()), Some((53, 53)));
    }
}

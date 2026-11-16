//! Application-layer dissection: DNS, DHCP, TLS, and the headers an ICMP
//! error message quotes back at you.
//!
//! Pass 3 of the pipeline in the design proposal. It runs only over the
//! packets that carry something a detector asks about, which in a real
//! capture is a few percent of them. Every function here takes a byte slice
//! and returns plain data, so each one is testable without a capture file.
//!
//! One rule governs the whole module: **captured content is data.** Host
//! names, server names and server-supplied messages are copied out with
//! every non-printable byte replaced and a hard length cap, so nothing a
//! capture contains can be mistaken for a label, an instruction or part of a
//! prompt anywhere above this layer.

use crate::flow::Addr;

/// Longest run of captured text the app will carry. A DNS name cannot exceed
/// 253 characters, and nothing else here needs more.
const MAX_TEXT: usize = 253;

#[inline]
fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[inline]
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Append captured bytes to a string as printable ASCII. Anything else
/// becomes a full stop, so the result is safe to put in a label, a log line
/// or an answer without being re-read as syntax.
fn push_safe(out: &mut String, bytes: &[u8]) {
    for &b in bytes {
        if out.len() >= MAX_TEXT {
            out.push('~');
            return;
        }
        if b.is_ascii_graphic() || b == b' ' {
            out.push(b as char);
        } else {
            out.push('.');
        }
    }
}

fn safe_text(bytes: &[u8]) -> String {
    let mut out = String::new();
    push_safe(&mut out, bytes);
    out
}

// --------------------------------------------------------------------- DNS

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub rcode: u8,
    pub question_count: u16,
    pub answer_count: u16,
    /// The name from the first question, where the message carries one.
    pub name: Option<String>,
    /// The message ran past the captured bytes, so the counts above may
    /// describe records that are not in this file.
    pub incomplete: bool,
}

/// Plain language for a DNS response code. The protocol's own name stays in
/// brackets so someone who knows it can still search for it.
pub fn dns_rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "no error",
        1 => "the query was malformed (FORMERR)",
        2 => "the server failed while answering (SERVFAIL)",
        3 => "the name does not exist (NXDOMAIN)",
        4 => "the server does not implement that query (NOTIMP)",
        5 => "the server refused to answer (REFUSED)",
        9 => "the server is not authoritative for that zone (NOTAUTH)",
        10 => "the name is outside the zone the server serves (NOTZONE)",
        _ => "an error this app has no name for",
    }
}

/// Read a DNS name, following compression pointers. None means the name ran
/// past the captured bytes - the app says so rather than guessing the rest.
fn read_name(b: &[u8], start: usize) -> Option<String> {
    let mut out = String::new();
    let mut pos = start;
    let mut jumps = 0;
    loop {
        if pos >= b.len() {
            return None;
        }
        let len = b[pos];
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= b.len() {
                return None;
            }
            jumps += 1;
            if jumps > 8 {
                return None;
            }
            pos = (((len & 0x3f) as usize) << 8) | b[pos + 1] as usize;
            continue;
        }
        let len = len as usize;
        if pos + 1 + len > b.len() {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        push_safe(&mut out, &b[pos + 1..pos + 1 + len]);
        if out.len() >= MAX_TEXT {
            return Some(out);
        }
        pos += 1 + len;
    }
    if out.is_empty() {
        out.push('.');
    }
    Some(out)
}

pub fn parse_dns(b: &[u8]) -> Option<DnsMessage> {
    if b.len() < 12 {
        return None;
    }
    let flags = be16(&b[2..4]);
    // Standard queries only. Updates and notifies answer a different question.
    if (flags >> 11) & 0x0f != 0 {
        return None;
    }
    let question_count = be16(&b[4..6]);
    let is_response = flags & 0x8000 != 0;
    if question_count == 0 && !is_response {
        return None;
    }
    let name = if question_count > 0 {
        read_name(b, 12)
    } else {
        None
    };
    Some(DnsMessage {
        id: be16(&b[0..2]),
        is_response,
        rcode: (flags & 0x000f) as u8,
        question_count,
        answer_count: be16(&b[6..8]),
        incomplete: question_count > 0 && name.is_none(),
        name,
    })
}

// -------------------------------------------------------------------- DHCP

pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_DECLINE: u8 = 4;
pub const DHCP_ACK: u8 = 5;
pub const DHCP_NAK: u8 = 6;
pub const DHCP_RELEASE: u8 = 7;
pub const DHCP_INFORM: u8 = 8;

pub fn dhcp_type_name(t: u8) -> &'static str {
    match t {
        DHCP_DISCOVER => "DISCOVER",
        DHCP_OFFER => "OFFER",
        DHCP_REQUEST => "REQUEST",
        DHCP_DECLINE => "DECLINE",
        DHCP_ACK => "ACK",
        DHCP_NAK => "NAK",
        DHCP_RELEASE => "RELEASE",
        DHCP_INFORM => "INFORM",
        _ => "an unrecognised message",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMessage {
    /// 1 from a client, 2 from a server.
    pub op: u8,
    pub xid: u32,
    pub message_type: u8,
    pub client_mac: [u8; 6],
    /// The address the server is handing out, in an OFFER or an ACK.
    pub your_ip: [u8; 4],
    pub requested_ip: Option<[u8; 4]>,
    pub server_id: Option<[u8; 4]>,
    /// Option 56, the server's own explanation. Captured text, sanitised.
    pub server_message: Option<String>,
    pub lease_seconds: Option<u32>,
}

pub fn parse_dhcp(b: &[u8]) -> Option<DhcpMessage> {
    // The fixed BOOTP part is 236 bytes, then the magic cookie.
    if b.len() < 240 {
        return None;
    }
    if !matches!(&b[236..240], [0x63, 0x82, 0x53, 0x63]) {
        return None;
    }
    let mut out = DhcpMessage {
        op: b[0],
        xid: be32(&b[4..8]),
        message_type: 0,
        client_mac: [b[28], b[29], b[30], b[31], b[32], b[33]],
        your_ip: [b[16], b[17], b[18], b[19]],
        requested_ip: None,
        server_id: None,
        server_message: None,
        lease_seconds: None,
    };
    let mut pos = 240;
    while pos < b.len() {
        let code = b[pos];
        if code == 255 {
            break;
        }
        if code == 0 {
            pos += 1;
            continue;
        }
        if pos + 2 > b.len() {
            break;
        }
        let len = b[pos + 1] as usize;
        if pos + 2 + len > b.len() {
            break;
        }
        let value = &b[pos + 2..pos + 2 + len];
        match (code, len) {
            (53, 1) => out.message_type = value[0],
            (50, 4) => out.requested_ip = Some([value[0], value[1], value[2], value[3]]),
            (54, 4) => out.server_id = Some([value[0], value[1], value[2], value[3]]),
            (51, 4) => out.lease_seconds = Some(be32(value)),
            (56, _) => out.server_message = Some(safe_text(value)),
            _ => {}
        }
        pos += 2 + len;
    }
    if out.message_type == 0 {
        return None;
    }
    Some(out)
}

// --------------------------------------------------------------------- TLS

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsMessage {
    ClientHello { server_name: Option<String> },
    ServerHello,
    Alert { level: u8, description: u8 },
    /// A record we recognise as TLS but have no reason to look inside.
    Other,
}

/// Plain language for a TLS alert, with the protocol's own name in brackets.
pub fn tls_alert_name(description: u8) -> &'static str {
    match description {
        0 => "the other end closed the connection normally (close_notify)",
        10 => "a message arrived that did not belong there (unexpected_message)",
        20 => "a record failed its integrity check (bad_record_mac)",
        22 => "a record was larger than allowed (record_overflow)",
        40 => "the two ends could not agree how to encrypt (handshake_failure)",
        42 => "the certificate was rejected (bad_certificate)",
        43 => "the certificate was of a kind not supported (unsupported_certificate)",
        44 => "the certificate has been revoked (certificate_revoked)",
        45 => "the certificate has expired (certificate_expired)",
        46 => "the certificate was not accepted (certificate_unknown)",
        47 => "a value in the handshake was not valid (illegal_parameter)",
        48 => "the certificate authority is not trusted (unknown_ca)",
        49 => "the client's certificate was refused (access_denied)",
        50 => "a handshake message could not be read (decode_error)",
        51 => "a handshake message failed to verify (decrypt_error)",
        70 => "the two ends have no TLS version in common (protocol_version)",
        71 => "the offered security was not strong enough (insufficient_security)",
        80 => "the other end hit an internal error (internal_error)",
        86 => "a fallback to an older version was refused (inappropriate_fallback)",
        90 => "the user cancelled (user_canceled)",
        109 => "a required extension was missing (missing_extension)",
        110 => "an extension was sent that is not allowed (unsupported_extension)",
        112 => "the server does not serve the name that was asked for (unrecognized_name)",
        116 => "the server requires a client certificate (certificate_required)",
        120 => "the two ends agreed on no application protocol (no_application_protocol)",
        _ => "an alert this app has no name for",
    }
}

/// Read the first TLS record at the start of a TCP payload.
///
/// Deliberately strict: the version bytes must be a real TLS version and the
/// record length must be plausible. A payload that merely happens to begin
/// with byte 22 is not TLS, and insisting on that is the difference between
/// a detector and a guess.
pub fn parse_tls(b: &[u8]) -> Option<TlsMessage> {
    if b.len() < 5 {
        return None;
    }
    let content_type = b[0];
    if !matches!(content_type, 20..=23) {
        return None;
    }
    if b[1] != 0x03 || b[2] > 0x04 {
        return None;
    }
    let len = be16(&b[3..5]) as usize;
    if len == 0 || len > 16_640 {
        return None;
    }
    let body = &b[5..(5 + len).min(b.len())];
    match content_type {
        21 => {
            if body.len() < 2 {
                return Some(TlsMessage::Other);
            }
            Some(TlsMessage::Alert {
                level: body[0],
                description: body[1],
            })
        }
        22 => {
            if body.len() < 4 {
                return Some(TlsMessage::Other);
            }
            match body[0] {
                1 => Some(TlsMessage::ClientHello {
                    server_name: client_hello_sni(&body[4..]),
                }),
                2 => Some(TlsMessage::ServerHello),
                _ => Some(TlsMessage::Other),
            }
        }
        _ => Some(TlsMessage::Other),
    }
}

/// The server name a ClientHello asked for, where it fits inside the captured
/// bytes. None means "not readable here", never "not present".
fn client_hello_sni(b: &[u8]) -> Option<String> {
    let mut pos = 2 + 32; // version, random
    if b.len() < pos + 1 {
        return None;
    }
    pos += 1 + b[pos] as usize; // session id
    if b.len() < pos + 2 {
        return None;
    }
    pos += 2 + be16(&b[pos..pos + 2]) as usize; // cipher suites
    if b.len() < pos + 1 {
        return None;
    }
    pos += 1 + b[pos] as usize; // compression methods
    if b.len() < pos + 2 {
        return None;
    }
    let end = (pos + 2 + be16(&b[pos..pos + 2]) as usize).min(b.len());
    pos += 2;
    while pos + 4 <= end {
        let ext_type = be16(&b[pos..pos + 2]);
        let ext_len = be16(&b[pos + 2..pos + 4]) as usize;
        let start = pos + 4;
        if start + ext_len > end {
            return None;
        }
        if ext_type == 0 {
            let e = &b[start..start + ext_len];
            // list length (2), name type (1), name length (2), then the name
            if e.len() >= 5 && e[2] == 0 {
                let name_len = be16(&e[3..5]) as usize;
                if 5 + name_len <= e.len() {
                    return Some(safe_text(&e[5..5 + name_len]));
                }
            }
            return None;
        }
        pos = start + ext_len;
    }
    None
}

// -------------------------------------------------------------------- ICMP

/// The five-tuple an ICMP error message quotes from the packet it is about.
/// This is what turns "no answer" into "a device said no".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpQuote {
    pub src: Addr,
    pub dst: Addr,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

pub fn parse_icmp_quote_v4(b: &[u8]) -> Option<IcmpQuote> {
    if b.len() < 20 || b[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((b[0] & 0x0f) as usize) * 4;
    if ihl < 20 || b.len() < ihl {
        return None;
    }
    let proto = b[9];
    let (src_port, dst_port) = if matches!(proto, 6 | 17) && b.len() >= ihl + 4 {
        (be16(&b[ihl..ihl + 2]), be16(&b[ihl + 2..ihl + 4]))
    } else {
        (0, 0)
    };
    Some(IcmpQuote {
        src: Addr::V4([b[12], b[13], b[14], b[15]]),
        dst: Addr::V4([b[16], b[17], b[18], b[19]]),
        proto,
        src_port,
        dst_port,
    })
}

pub fn parse_icmp_quote_v6(b: &[u8]) -> Option<IcmpQuote> {
    if b.len() < 40 || b[0] >> 4 != 6 {
        return None;
    }
    let proto = b[6];
    let (src_port, dst_port) = if matches!(proto, 6 | 17) && b.len() >= 44 {
        (be16(&b[40..42]), be16(&b[42..44]))
    } else {
        (0, 0)
    };
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&b[8..24]);
    dst.copy_from_slice(&b[24..40]);
    Some(IcmpQuote {
        src: Addr::V6(src),
        dst: Addr::V6(dst),
        proto,
        src_port,
        dst_port,
    })
}

/// What an ICMP error means, in words, plus the finding kind it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpMeaning {
    /// Finding kind, so the UI can group and the assistant can cite it.
    pub kind: &'static str,
    pub headline: &'static str,
    pub plain: &'static str,
    /// False for the ones that are a nuisance rather than a failure.
    pub is_error: bool,
}

/// None for the ICMP types that are not error reports - echo, replies, router
/// and neighbour discovery. Those are traffic, not findings.
pub fn icmp_v4_meaning(kind: u8, code: u8) -> Option<IcmpMeaning> {
    match (kind, code) {
        (3, 0) => Some(IcmpMeaning {
            kind: "network_unreachable",
            headline: "A router could not reach that network",
            plain: "A router on the path replied that it has no way to reach the destination network.",
            is_error: true,
        }),
        (3, 1) => Some(IcmpMeaning {
            kind: "host_unreachable",
            headline: "A router could not reach that host",
            plain: "A router on the path replied that the destination host did not answer on its own local network.",
            is_error: true,
        }),
        (3, 2) => Some(IcmpMeaning {
            kind: "protocol_unreachable",
            headline: "The destination does not speak that protocol",
            plain: "The destination replied that it does not handle the IP protocol the packet carried.",
            is_error: true,
        }),
        (3, 3) => Some(IcmpMeaning {
            kind: "port_unreachable",
            headline: "Nothing is listening on that port",
            plain: "The destination itself replied that no program is listening on the port that was addressed.",
            is_error: true,
        }),
        (3, 4) => Some(IcmpMeaning {
            kind: "mtu_too_large",
            headline: "A packet was too large for the path and could not be split",
            plain: "A router had to drop the packet: it was larger than the next link allows and was marked not to be fragmented. This is the usual cause of connections that open normally and then stall on the first large transfer.",
            is_error: true,
        }),
        (3, 9) | (3, 10) | (3, 13) => Some(IcmpMeaning {
            kind: "blocked_by_device",
            headline: "A device on the path refused to carry this traffic",
            plain: "A firewall or router answered the connection attempt with an administratively prohibited message. The traffic was blocked on purpose by a rule, not lost.",
            is_error: true,
        }),
        (3, _) => Some(IcmpMeaning {
            kind: "destination_unreachable",
            headline: "The destination was reported as unreachable",
            plain: "A device on the path reported that it could not deliver the packet.",
            is_error: true,
        }),
        (11, 0) => Some(IcmpMeaning {
            kind: "ttl_exceeded",
            headline: "A packet was discarded after passing too many routers",
            plain: "The packet's hop limit ran out before it arrived. Traceroute causes this on purpose; anywhere else it usually means a routing loop.",
            is_error: false,
        }),
        (11, 1) => Some(IcmpMeaning {
            kind: "fragment_timeout",
            headline: "The pieces of a split packet never all arrived",
            plain: "The destination gave up waiting for the rest of a fragmented packet.",
            is_error: true,
        }),
        (4, _) => Some(IcmpMeaning {
            kind: "source_quench",
            headline: "A device asked the sender to slow down",
            plain: "An obsolete congestion signal. Modern equipment does not send it.",
            is_error: false,
        }),
        _ => None,
    }
}

pub fn icmp_v6_meaning(kind: u8, code: u8) -> Option<IcmpMeaning> {
    match (kind, code) {
        (1, 0) => Some(IcmpMeaning {
            kind: "network_unreachable",
            headline: "A router had no route to that address",
            plain: "A router on the path replied that it has no route to the destination.",
            is_error: true,
        }),
        (1, 1) => Some(IcmpMeaning {
            kind: "blocked_by_device",
            headline: "A device on the path refused to carry this traffic",
            plain: "A firewall or router answered with an administratively prohibited message. The traffic was blocked on purpose by a rule, not lost.",
            is_error: true,
        }),
        (1, 3) => Some(IcmpMeaning {
            kind: "host_unreachable",
            headline: "The destination address did not answer",
            plain: "A router replied that it could not match the destination address to a device on its local network.",
            is_error: true,
        }),
        (1, 4) => Some(IcmpMeaning {
            kind: "port_unreachable",
            headline: "Nothing is listening on that port",
            plain: "The destination itself replied that no program is listening on the port that was addressed.",
            is_error: true,
        }),
        (1, _) => Some(IcmpMeaning {
            kind: "destination_unreachable",
            headline: "The destination was reported as unreachable",
            plain: "A device on the path reported that it could not deliver the packet.",
            is_error: true,
        }),
        (2, _) => Some(IcmpMeaning {
            kind: "mtu_too_large",
            headline: "A packet was too large for the path",
            plain: "A router reported that the packet was bigger than the largest size the next link accepts. IPv6 routers never split packets, so the sender has to send smaller ones.",
            is_error: true,
        }),
        (3, 0) => Some(IcmpMeaning {
            kind: "ttl_exceeded",
            headline: "A packet was discarded after passing too many routers",
            plain: "The packet's hop limit ran out before it arrived. Traceroute causes this on purpose; anywhere else it usually means a routing loop.",
            is_error: false,
        }),
        (3, 1) => Some(IcmpMeaning {
            kind: "fragment_timeout",
            headline: "The pieces of a split packet never all arrived",
            plain: "The destination gave up waiting for the rest of a fragmented packet.",
            is_error: true,
        }),
        _ => None,
    }
}

/// The next-hop MTU a "fragmentation needed" message carries, which is the
/// number someone actually needs in order to fix it.
pub fn icmp_next_hop_mtu(icmp_header: &[u8]) -> Option<u16> {
    if icmp_header.len() < 8 {
        return None;
    }
    let mtu = be16(&icmp_header[6..8]);
    if mtu == 0 {
        None
    } else {
        Some(mtu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_query(id: u16, name: &str) -> Vec<u8> {
        let mut out = vec![0u8; 12];
        out[0..2].copy_from_slice(&id.to_be_bytes());
        out[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
        out[4..6].copy_from_slice(&1u16.to_be_bytes());
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&[0, 1, 0, 1]);
        out
    }

    #[test]
    fn reads_a_dns_question() {
        let m = parse_dns(&dns_query(0x1234, "files.example.com")).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(!m.is_response);
        assert_eq!(m.rcode, 0);
        assert_eq!(m.name.as_deref(), Some("files.example.com"));
    }

    #[test]
    fn a_name_with_control_bytes_cannot_smuggle_anything() {
        let mut q = vec![0u8; 12];
        q[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
        q[4..6].copy_from_slice(&1u16.to_be_bytes());
        let label: &[u8] = b"a\nIGNORE\x1b[31m";
        q.push(label.len() as u8);
        q.extend_from_slice(label);
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]);
        let name = parse_dns(&q).unwrap().name.unwrap();
        assert!(!name.contains('\n'));
        assert!(!name.contains('\u{1b}'));
        assert_eq!(name, "a.IGNORE.[31m");
    }

    #[test]
    fn a_name_that_points_at_itself_does_not_hang() {
        let mut q = vec![0u8; 12];
        q[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
        q[4..6].copy_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&[0xc0, 0x0c]); // points back at offset 12
        assert!(parse_dns(&q).unwrap().incomplete);
    }

    #[test]
    fn a_payload_that_merely_starts_with_22_is_not_tls() {
        // The clean fixture sends 517 bytes of 0x16. Byte one says handshake,
        // but the version bytes do not, and a detector must not take the bait.
        assert_eq!(parse_tls(&[0x16; 517]), None);
    }

    #[test]
    fn reads_a_fatal_tls_alert() {
        let record = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 40];
        assert_eq!(
            parse_tls(&record),
            Some(TlsMessage::Alert {
                level: 2,
                description: 40
            })
        );
    }

    #[test]
    fn reads_the_server_name_from_a_client_hello() {
        let host: &[u8] = b"intranet.example.com";
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // list length
        sni.push(0); // host_name
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);

        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes()); // server_name
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0); // no session id
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut handshake = vec![1, 0, 0, 0];
        let len = body.len();
        handshake[1] = (len >> 16) as u8;
        handshake[2] = (len >> 8) as u8;
        handshake[3] = len as u8;
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(
            parse_tls(&record),
            Some(TlsMessage::ClientHello {
                server_name: Some("intranet.example.com".to_string())
            })
        );
    }

    #[test]
    fn reads_the_flow_an_icmp_error_quotes() {
        let mut quoted = vec![0x45, 0x00, 0x00, 0x28];
        quoted.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, 6, 0x00, 0x00]);
        quoted.extend_from_slice(&[192, 168, 1, 10]);
        quoted.extend_from_slice(&[192, 168, 1, 20]);
        quoted.extend_from_slice(&51517u16.to_be_bytes());
        quoted.extend_from_slice(&3389u16.to_be_bytes());
        let quote = parse_icmp_quote_v4(&quoted).unwrap();
        assert_eq!(quote.src, Addr::V4([192, 168, 1, 10]));
        assert_eq!(quote.dst_port, 3389);
        assert_eq!(quote.proto, 6);
        assert_eq!(
            icmp_v4_meaning(3, 13).map(|m| m.kind),
            Some("blocked_by_device")
        );
        assert_eq!(icmp_v4_meaning(8, 0), None); // an echo request is not a finding
    }

    #[test]
    fn reads_a_dhcp_nak() {
        let mut m = vec![0u8; 240];
        m[0] = 2;
        m[4..8].copy_from_slice(&0xdeadbeefu32.to_be_bytes());
        m[28..34].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x10]);
        m[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        m.extend_from_slice(&[53, 1, DHCP_NAK]);
        m.extend_from_slice(&[54, 4, 192, 168, 1, 1]);
        m.extend_from_slice(&[56, 11]);
        m.extend_from_slice(b"lease\nended");
        m.push(255);
        let d = parse_dhcp(&m).unwrap();
        assert_eq!(d.message_type, DHCP_NAK);
        assert_eq!(d.xid, 0xdeadbeef);
        assert_eq!(d.server_id, Some([192, 168, 1, 1]));
        assert_eq!(d.server_message.as_deref(), Some("lease.ended"));
    }
}

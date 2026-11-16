//! The detector pass.
//!
//! One streaming pass fills an `Analysis`; `findings()` then reads it and
//! says what went wrong. Keeping the two apart matters more than it looks:
//! several detectors only know their answer at the end. A DNS query is not
//! unanswered until the file runs out, and a connection attempt is only
//! unexplained until an ICMP error turns up three packets later quoting it.
//!
//! Order inside `findings()` is deliberate. ICMP errors and the protocol
//! detectors run first and mark the conversations they have already spoken
//! for; the flow detector then skips those, so a blocked connection is
//! reported once, as a block, and not also as a silence.

use std::collections::{HashMap, HashSet};

use crate::appl::{
    dhcp_type_name, dns_rcode_name, icmp_next_hop_mtu, icmp_v4_meaning, icmp_v6_meaning, parse_dhcp,
    parse_dns, parse_icmp_quote_v4, parse_icmp_quote_v6, parse_tls, tls_alert_name, IcmpMeaning,
    TlsMessage, DHCP_ACK, DHCP_DECLINE, DHCP_DISCOVER, DHCP_NAK, DHCP_OFFER, DHCP_REQUEST,
};
use crate::capture::PacketRef;
use crate::decode::{Decoded, NetLayer, TransportLayer};
use crate::findings::{Confidence, Finding, Severity};
use crate::packets::{PacketIndex, PacketKind};
use crate::flow::{Addr, FlowKey, FlowOutcome};
use crate::summary::{CaptureSummary, Contention};

/// What the capture file says about its own completeness. The detectors need
/// this to tell "did not happen" from "was not captured".
#[derive(Debug, Clone, Copy, Default)]
pub struct CaptureLimits {
    /// None where the file has no way of recording drops at all.
    pub reported_drops: Option<u64>,
    pub snaplen: u32,
}

/// Below this many resent segments, a conversation is too small to say
/// anything about: two resends out of six is noise, not a rate.
const RESEND_MIN_COUNT: u64 = 5;

/// Retransmission is how TCP copes with an imperfect network, and a small
/// share of it is normal everywhere. This is where it stops being normal.
const RESEND_MIN_RATE: f64 = 0.02;

/// Below this, duplicated frames are not worth a finding of their own.
const CAPTURE_DUPLICATE_MIN: u64 = 5;

// ------------------------------------------------------------ bookkeeping

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DnsKey {
    client: Addr,
    server: Addr,
    id: u16,
    /// 17 for the usual UDP, 6 when the lookup went over TCP. Two exchanges
    /// can share an identifier across the two, and merging them would have
    /// one answering the other.
    proto: u8,
}

#[derive(Debug, Clone, Copy)]
struct DnsAnswer {
    rcode: u8,
    answers: u16,
    packet: u64,
    offset: u64,
}

#[derive(Debug, Clone)]
struct DnsExchange {
    name: Option<String>,
    client_port: u16,
    queries: u64,
    first_packet: u64,
    first_ts: i64,
    first_offset: u64,
    last_query_ts: i64,
    response: Option<DnsAnswer>,
    incomplete: bool,
}

#[derive(Debug, Clone)]
struct DhcpStep {
    message_type: u8,
    packet: u64,
    offset: u64,
    your_ip: [u8; 4],
    requested_ip: Option<[u8; 4]>,
    server_message: Option<String>,
}

#[derive(Debug, Clone)]
struct DhcpExchange {
    client_mac: [u8; 6],
    first_packet: u64,
    first_ts: i64,
    steps: Vec<DhcpStep>,
}

impl DhcpExchange {
    fn step(&self, message_type: u8) -> Option<&DhcpStep> {
        self.steps.iter().find(|s| s.message_type == message_type)
    }
}

#[derive(Debug, Clone, Copy)]
struct TlsAlertSeen {
    level: u8,
    description: u8,
    packet: u64,
    ts: i64,
    offset: u64,
    from: Addr,
}

#[derive(Debug, Clone, Default)]
struct TlsExchange {
    client_hello: Option<(u64, i64, u64)>,
    client: Option<Addr>,
    server: Option<Addr>,
    server_port: u16,
    server_name: Option<String>,
    server_hello: bool,
    alert: Option<TlsAlertSeen>,
}

#[derive(Debug, Clone, Copy)]
struct IcmpReport {
    meaning: IcmpMeaning,
    from: Addr,
    packet: u64,
    ts: i64,
    offset: u64,
    kind: u8,
    code: u8,
    quote: Option<(FlowKey, Addr, Addr, u16)>,
    next_hop_mtu: Option<u32>,
}

/// One capture file, read once, with everything the detectors need.
#[derive(Debug, Default)]
pub struct Analysis {
    pub summary: CaptureSummary,
    /// Row per packet, for the explorer. The only structure here that grows
    /// with the capture, and it is capped - see `packets::MAX_INDEXED_PACKETS`.
    pub packets: PacketIndex,
    dns: HashMap<DnsKey, DnsExchange>,
    dhcp: HashMap<u32, DhcpExchange>,
    tls: HashMap<FlowKey, TlsExchange>,
    icmp: Vec<IcmpReport>,
    /// Packets per flow that were themselves ICMP error reports. A flow made
    /// only of those is a notification, not a half-captured conversation.
    icmp_error_packets: HashMap<FlowKey, u64>,
    /// Packets that carried a payload and were cut short by the snaplen, so
    /// the payload detectors could not run on them.
    payload_truncated: u64,
}

impl Analysis {
    pub fn new() -> Self {
        Analysis::default()
    }

    pub fn observe(&mut self, packet: &PacketRef<'_>, decoded: &Decoded) {
        self.summary.observe(packet, decoded);

        let payload = decoded.payload.and_then(|(off, len)| {
            if len == 0 {
                None
            } else {
                packet.data.get(off..(off + len).min(packet.data.len()))
            }
        });
        if packet.is_truncated() && decoded.payload.is_some() {
            self.payload_truncated += 1;
        }

        // The protocol detectors run first, and each hands back the line the
        // packet list shows. They have already parsed the payload to do their
        // own job; parsing it again for a summary would be pure waste.
        let mut note: Option<(PacketKind, String)> = None;
        if let Some((src, dst)) = endpoints(decoded) {
            match decoded.transport {
                Some(TransportLayer::Udp {
                    src_port, dst_port, ..
                }) => {
                    if let Some(body) = payload {
                        if src_port == 53 || dst_port == 53 {
                            note =
                                self.observe_dns(packet, src, dst, src_port, dst_port, body, 17);
                        } else if matches!(src_port, 67 | 68) && matches!(dst_port, 67 | 68) {
                            note = self.observe_dhcp(packet, body);
                        }
                    }
                }
                Some(TransportLayer::Tcp {
                    src_port, dst_port, ..
                }) => {
                    if let Some(body) = payload {
                        if src_port == 53 || dst_port == 53 {
                            note = self
                                .observe_dns_over_tcp(packet, src, dst, src_port, dst_port, body);
                        } else {
                            note = self.observe_tls(packet, src, dst, src_port, dst_port, body);
                        }
                    }
                }
                Some(TransportLayer::Icmp { kind, code }) => {
                    note = self.observe_icmp(packet, decoded, src, dst, kind, code, false);
                }
                Some(TransportLayer::Icmpv6 { kind, code }) => {
                    note = self.observe_icmp(packet, decoded, src, dst, kind, code, true);
                }
                None => {}
            }
        }

        self.packets.record(packet, decoded, note);
    }

    /// A lookup that went over TCP instead of UDP.
    ///
    /// Big answers, zone transfers and anything a resolver retried after a
    /// truncated UDP reply arrive this way. The message is the same; only
    /// the framing differs, and it carries its own length in front.
    ///
    /// A long answer can be split across segments, and a segment that holds
    /// only part of a message is left alone rather than guessed at - half a
    /// DNS message parsed optimistically is how a detector invents a name
    /// nobody asked for.
    #[allow(clippy::too_many_arguments)]
    fn observe_dns_over_tcp(
        &mut self,
        packet: &PacketRef<'_>,
        src: Addr,
        dst: Addr,
        src_port: u16,
        dst_port: u16,
        body: &[u8],
    ) -> Option<(PacketKind, String)> {
        if body.len() < 2 {
            return None;
        }
        let declared = u16::from_be_bytes([body[0], body[1]]) as usize;
        // Shorter than a header, or longer than what this segment holds.
        if declared < 12 || 2 + declared > body.len() {
            return None;
        }
        self.observe_dns(
            packet,
            src,
            dst,
            src_port,
            dst_port,
            &body[2..2 + declared],
            6,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_dns(
        &mut self,
        packet: &PacketRef<'_>,
        src: Addr,
        dst: Addr,
        src_port: u16,
        dst_port: u16,
        body: &[u8],
        proto: u8,
    ) -> Option<(PacketKind, String)> {
        let msg = parse_dns(body)?;
        let display_name = msg
            .name
            .clone()
            .unwrap_or_else(|| "a name this capture does not hold in full".to_string());
        let (client, server, client_port) = if msg.is_response {
            (dst, src, dst_port)
        } else {
            (src, dst, src_port)
        };
        let entry = self
            .dns
            .entry(DnsKey {
                client,
                server,
                id: msg.id,
                proto,
            })
            .or_insert_with(|| DnsExchange {
                name: None,
                client_port,
                queries: 0,
                first_packet: packet.index,
                first_ts: packet.ts_nanos,
                first_offset: packet.offset,
                last_query_ts: packet.ts_nanos,
                response: None,
                incomplete: false,
            });
        entry.incomplete |= msg.incomplete;
        if entry.name.is_none() {
            entry.name = msg.name;
        }
        if msg.is_response {
            if entry.response.is_none() {
                entry.response = Some(DnsAnswer {
                    rcode: msg.rcode,
                    answers: msg.answer_count,
                    packet: packet.index,
                    offset: packet.offset,
                });
            }
        } else {
            entry.queries += 1;
            entry.last_query_ts = packet.ts_nanos;
        }

        Some((
            PacketKind::Dns,
            if !msg.is_response {
                format!("query {display_name}")
            } else if msg.rcode == 0 {
                format!("response {display_name}")
            } else {
                format!("response {display_name} - {}", dns_rcode_name(msg.rcode))
            },
        ))
    }

    fn observe_dhcp(
        &mut self,
        packet: &PacketRef<'_>,
        body: &[u8],
    ) -> Option<(PacketKind, String)> {
        let msg = parse_dhcp(body)?;
        let entry = self.dhcp.entry(msg.xid).or_insert_with(|| DhcpExchange {
            client_mac: msg.client_mac,
            first_packet: packet.index,
            first_ts: packet.ts_nanos,
            steps: Vec::new(),
        });
        entry.steps.push(DhcpStep {
            message_type: msg.message_type,
            packet: packet.index,
            offset: packet.offset,
            your_ip: msg.your_ip,
            requested_ip: msg.requested_ip,
            server_message: msg.server_message,
        });

        Some((
            PacketKind::Dhcp,
            dhcp_type_name(msg.message_type).to_string(),
        ))
    }

    fn observe_tls(
        &mut self,
        packet: &PacketRef<'_>,
        src: Addr,
        dst: Addr,
        src_port: u16,
        dst_port: u16,
        body: &[u8],
    ) -> Option<(PacketKind, String)> {
        let msg = parse_tls(body)?;
        let (key, _) = FlowKey::new(6, src, src_port, dst, dst_port);
        let entry = self.tls.entry(key).or_default();
        let note = match msg {
            TlsMessage::ClientHello { server_name } => {
                let line = match &server_name {
                    Some(name) => format!("ClientHello, asking for {name}"),
                    None => "ClientHello".to_string(),
                };
                if entry.client_hello.is_none() {
                    entry.client_hello = Some((packet.index, packet.ts_nanos, packet.offset));
                    entry.client = Some(src);
                    entry.server = Some(dst);
                    entry.server_port = dst_port;
                    entry.server_name = server_name;
                }
                line
            }
            TlsMessage::ServerHello => {
                entry.server_hello = true;
                if entry.server.is_none() {
                    entry.server = Some(src);
                    entry.client = Some(dst);
                    entry.server_port = src_port;
                }
                "ServerHello".to_string()
            }
            TlsMessage::Alert { level, description } => {
                if entry.alert.is_none() {
                    entry.alert = Some(TlsAlertSeen {
                        level,
                        description,
                        packet: packet.index,
                        ts: packet.ts_nanos,
                        offset: packet.offset,
                        from: src,
                    });
                }
                format!(
                    "{} alert: {}",
                    if level == 2 { "fatal" } else { "warning" },
                    tls_alert_name(description)
                )
            }
            // Everything after the handshake is encrypted, so there is
            // nothing to say about it beyond that it is there.
            TlsMessage::Other => "encrypted record".to_string(),
        };
        Some((PacketKind::Tls, note))
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_icmp(
        &mut self,
        packet: &PacketRef<'_>,
        decoded: &Decoded,
        src: Addr,
        dst: Addr,
        kind: u8,
        code: u8,
        v6: bool,
    ) -> Option<(PacketKind, String)> {
        let meaning = if v6 {
            icmp_v6_meaning(kind, code)
        } else {
            icmp_v4_meaning(kind, code)
        };
        let Some(meaning) = meaning else {
            // Not an error report. Echo and the discovery messages are
            // ordinary traffic, and the packet list should still name them.
            let line = match (v6, kind) {
                (false, 8) | (true, 128) => "echo request (ping)",
                (false, 0) | (true, 129) => "echo reply",
                (true, 133) => "router solicitation",
                (true, 134) => "router advertisement",
                (true, 135) => "neighbour solicitation",
                (true, 136) => "neighbour advertisement",
                _ => return Some((PacketKind::Icmp, format!("type {kind}, code {code}"))),
            };
            return Some((PacketKind::Icmp, line.to_string()));
        };

        let proto = if v6 { 58 } else { 1 };
        let (own_key, _) = FlowKey::new(proto, src, 0, dst, 0);
        *self.icmp_error_packets.entry(own_key).or_insert(0) += 1;

        let quoted = decoded
            .payload
            .and_then(|(off, len)| packet.data.get(off..(off + len).min(packet.data.len())));
        let quote = quoted
            .and_then(|b| {
                if v6 {
                    parse_icmp_quote_v6(b)
                } else {
                    parse_icmp_quote_v4(b)
                }
            })
            .map(|q| {
                let (key, _) = FlowKey::new(q.proto, q.src, q.src_port, q.dst, q.dst_port);
                (key, q.src, q.dst, q.dst_port)
            });

        // The 8-byte ICMP header sits just before the quoted packet.
        let header = decoded
            .payload
            .and_then(|(off, _)| if off >= 8 { packet.data.get(off - 8..off) } else { None });
        let next_hop_mtu = match (v6, kind) {
            (false, 3) if code == 4 => header.and_then(icmp_next_hop_mtu).map(u32::from),
            (true, 2) => header.map(|h| u32::from_be_bytes([h[4], h[5], h[6], h[7]])),
            _ => None,
        };

        self.icmp.push(IcmpReport {
            meaning,
            from: src,
            packet: packet.index,
            ts: packet.ts_nanos,
            offset: packet.offset,
            kind,
            code,
            quote,
            next_hop_mtu,
        });

        Some((PacketKind::Icmp, meaning.kind.replace('_', " ")))
    }

    // ------------------------------------------------------------ findings

    pub fn findings(&self, limits: CaptureLimits) -> Vec<Finding> {
        let mut out = Vec::new();
        // Conversations a detector above the flow layer has already explained.
        let mut spoken_for: HashSet<FlowKey> = HashSet::new();

        self.icmp_findings(&mut out, &mut spoken_for);
        self.dns_findings(&mut out, &mut spoken_for, &limits);
        self.dhcp_findings(&mut out, &limits);
        self.tls_findings(&mut out, &mut spoken_for, &limits);
        self.flow_findings(&mut out, &spoken_for, &limits);
        self.tcp_health_findings(&mut out);
        self.addressing_findings(&mut out);
        self.capture_findings(&mut out, &limits);

        out.sort_by(|a, b| a.rank().cmp(&b.rank()));
        out
    }

    fn icmp_findings(&self, out: &mut Vec<Finding>, spoken_for: &mut HashSet<FlowKey>) {
        for report in &self.icmp {
            let severity = if report.meaning.is_error {
                Severity::Error
            } else {
                Severity::Warning
            };
            let (title, endpoints, about) = match report.quote {
                Some((key, qsrc, qdst, qport)) => {
                    spoken_for.insert(key);
                    let service = if qport > 0 {
                        format!("{qdst} port {qport}")
                    } else {
                        qdst.to_string()
                    };
                    (
                        format!("{} could not reach {service}", report.from),
                        vec![qsrc.to_string(), service.clone()],
                        format!(
                            " The message quotes a packet {qsrc} sent to {service}, which is how we know which conversation it is about."
                        ),
                    )
                }
                None => (
                    report.meaning.headline.to_string(),
                    vec![report.from.to_string()],
                    String::new(),
                ),
            };
            let mut what = format!(
                "{} sent an ICMP {} message (type {}, code {}). {}{}",
                report.from,
                report.meaning.kind.replace('_', " "),
                report.kind,
                report.code,
                report.meaning.plain,
                about
            );
            if let Some(mtu) = report.next_hop_mtu {
                what.push_str(&format!(
                    " The device says the largest packet it will carry is {mtu} bytes."
                ));
            }
            let mut finding = Finding::new(
                report.meaning.kind,
                severity,
                // A device saying so in a packet is the strongest evidence a
                // capture can hold. Nothing missing from the file weakens it.
                Confidence::Confirmed,
                title,
                what,
            )
            .at(report.packet, report.ts)
            .between(endpoints)
            .showing(
                report.packet,
                report.offset,
                format!("ICMP type {} code {}", report.kind, report.code),
            );
            for step in next_checks_for_icmp(report.meaning.kind) {
                finding = finding.check(step);
            }
            out.push(finding);
        }
    }

    fn dns_findings(
        &self,
        out: &mut Vec<Finding>,
        spoken_for: &mut HashSet<FlowKey>,
        limits: &CaptureLimits,
    ) {
        for (key, exchange) in &self.dns {
            let flow_key =
                FlowKey::new(key.proto, key.client, exchange.client_port, key.server, 53).0;
            let before = out.len();

            let name = exchange
                .name
                .clone()
                .unwrap_or_else(|| "a name this capture does not hold in full".to_string());

            match exchange.response {
                Some(answer) if answer.rcode != 0 => {
                    let severity = match answer.rcode {
                        2 | 3 | 5 => Severity::Error,
                        _ => Severity::Warning,
                    };
                    out.push(
                        Finding::new(
                            "dns_error",
                            severity,
                            Confidence::Confirmed,
                            format!("The name {name} could not be looked up"),
                            format!(
                                "{} asked {} for {name}, and the server answered that {}. The lookup failed at the DNS server, before anything tried to connect.",
                                key.client,
                                key.server,
                                dns_rcode_name(answer.rcode)
                            ),
                        )
                        .at(exchange.first_packet, exchange.first_ts)
                        .between(vec![key.client.to_string(), key.server.to_string()])
                        .showing(exchange.first_packet, exchange.first_offset, "the query")
                        .showing(
                            answer.packet,
                            answer.offset,
                            format!("the answer, response code {}", answer.rcode),
                        )
                        .check("Check the name is spelled as the device expects.")
                        .check(format!(
                            "Ask {} whether it is meant to serve that name, or forward it on.",
                            key.server
                        )),
                    );
                }
                Some(answer) if answer.answers == 0 => {
                    // Answered, with nothing in it. Common and usually fine -
                    // an AAAA lookup for a v4-only name looks exactly like
                    // this - so it is informational and never an error.
                    out.push(
                        Finding::new(
                            "dns_no_records",
                            Severity::Info,
                            Confidence::Confirmed,
                            format!("The lookup for {name} succeeded but returned no addresses"),
                            format!(
                                "{} answered {} without an error and without any records. This is normal when a device asks for a kind of record the name does not have.",
                                key.server, key.client
                            ),
                        )
                        .at(exchange.first_packet, exchange.first_ts)
                        .between(vec![key.client.to_string(), key.server.to_string()])
                        .showing(answer.packet, answer.offset, "the empty answer"),
                    );
                }
                Some(_) => {}
                None if exchange.queries > 0 => {
                    let waited = (exchange.last_query_ts - exchange.first_ts).max(0) as f64 / 1e9;
                    let tries = if exchange.queries > 1 {
                        format!(
                            " It asked {} times over {:.1} s.",
                            exchange.queries, waited
                        )
                    } else {
                        String::new()
                    };
                    let finding = Finding::new(
                        "dns_unanswered",
                        Severity::Warning,
                        Confidence::Suspected,
                        format!("A lookup for {name} got no answer"),
                        format!(
                            "{} asked {} for {name} and no response appears in this capture.{tries} Name resolution stalling like this is usually what a user notices as a slow or dead application.",
                            key.client, key.server
                        ),
                    )
                    .at(exchange.first_packet, exchange.first_ts)
                    .between(vec![key.client.to_string(), key.server.to_string()])
                    .showing(exchange.first_packet, exchange.first_offset, "the first query")
                    .check(format!("Check {} is reachable and answering other clients.", key.server))
                    .check("Capture next to the resolver as well: the answer may exist and not pass this point.");
                    out.push(weaken_for_absence(finding, limits));
                }
                None => {}
            }

            if out.len() > before {
                spoken_for.insert(flow_key);
            }
        }
    }

    fn dhcp_findings(&self, out: &mut Vec<Finding>, limits: &CaptureLimits) {
        for exchange in self.dhcp.values() {
            let who = format_mac(&exchange.client_mac);
            if let Some(nak) = exchange.step(DHCP_NAK) {
                let asked = exchange
                    .step(DHCP_REQUEST)
                    .and_then(|s| s.requested_ip)
                    .map(|ip| format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))
                    .unwrap_or_else(|| "the address it was using".to_string());
                let reason = nak
                    .server_message
                    .as_deref()
                    .map(|m| format!(" The server's own explanation was \"{m}\"."))
                    .unwrap_or_default();
                out.push(
                    Finding::new(
                        "dhcp_nak",
                        Severity::Error,
                        Confidence::Confirmed,
                        format!("The DHCP server refused {who} the address it asked for"),
                        format!(
                            "{who} asked to keep or take {asked}, and the server answered NAK - a refusal.{reason} A device that is refused this way has no working address until it starts again from scratch."
                        ),
                    )
                    .at(exchange.first_packet, exchange.first_ts)
                    .between(vec![who.clone()])
                    .showing(nak.packet, nak.offset, "the NAK")
                    .check("Check whether the device moved to a different network or VLAN while keeping its old lease.")
                    .check("Check the scope on the DHCP server still covers that address."),
                );
                continue;
            }
            if let Some(decline) = exchange.step(DHCP_DECLINE) {
                let addr = exchange
                    .step(DHCP_OFFER)
                    .map(|s| s.your_ip)
                    .map(|ip| format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))
                    .unwrap_or_else(|| "the offered address".to_string());
                out.push(
                    Finding::new(
                        "dhcp_declined",
                        Severity::Error,
                        Confidence::Confirmed,
                        format!("{who} rejected the address it was offered"),
                        format!(
                            "{who} was offered {addr}, tested it, found something else already answering for it, and sent DECLINE. Two devices want the same address."
                        ),
                    )
                    .at(exchange.first_packet, exchange.first_ts)
                    .between(vec![who.clone()])
                    .showing(decline.packet, decline.offset, "the DECLINE")
                    .check("Look for a device configured with a static address inside the DHCP range.")
                    .check("Check the addressing screen for an address claimed by more than one MAC."),
                );
                continue;
            }
            let answered = exchange.step(DHCP_ACK).is_some();
            if !answered {
                if let Some(discover) = exchange.step(DHCP_DISCOVER) {
                    if exchange.step(DHCP_OFFER).is_none() {
                        let finding = Finding::new(
                            "dhcp_no_offer",
                            Severity::Warning,
                            Confidence::Suspected,
                            format!("{who} asked for an address and no offer appears"),
                            format!(
                                "{who} broadcast a DHCP DISCOVER and no OFFER follows it in this capture. A device in this state ends up with no address at all, or falls back to a 169.254 one."
                            ),
                        )
                        .at(exchange.first_packet, exchange.first_ts)
                        .between(vec![who.clone()])
                        .showing(discover.packet, discover.offset, "the DISCOVER")
                        .check("Check the DHCP server is running and its scope is not exhausted.")
                        .check("Check the DHCP relay on this VLAN, if the server is on another one.")
                        .check("Capture next to the server as well: broadcasts do not always reach this point.");
                        out.push(weaken_for_absence(finding, limits));
                    } else if exchange.step(DHCP_REQUEST).is_some() {
                        let request = exchange.step(DHCP_REQUEST).unwrap();
                        let finding = Finding::new(
                            "dhcp_no_ack",
                            Severity::Warning,
                            Confidence::Suspected,
                            format!("{who} was offered an address but never confirmed"),
                            format!(
                                "{who} was offered an address and sent a REQUEST for it, and no ACK or NAK follows in this capture."
                            ),
                        )
                        .at(exchange.first_packet, exchange.first_ts)
                        .between(vec![who.clone()])
                        .showing(request.packet, request.offset, "the REQUEST")
                        .check("Check whether two DHCP servers are offering on this network.");
                        out.push(weaken_for_absence(finding, limits));
                    }
                } else if let Some(request) = exchange.step(DHCP_REQUEST) {
                    if exchange.step(DHCP_NAK).is_none() {
                        let finding = Finding::new(
                            "dhcp_no_ack",
                            Severity::Warning,
                            Confidence::Suspected,
                            format!("{who} asked to renew its address and got no answer"),
                            format!(
                                "{who} sent a DHCP {} and neither an ACK nor a NAK follows in this capture. A renewal that never completes ends with the device losing its address when the lease runs out.",
                                dhcp_type_name(DHCP_REQUEST)
                            ),
                        )
                        .at(exchange.first_packet, exchange.first_ts)
                        .between(vec![who.clone()])
                        .showing(request.packet, request.offset, "the REQUEST")
                        .check("Check the DHCP server is reachable from this VLAN.");
                        out.push(weaken_for_absence(finding, limits));
                    }
                }
            }
        }
    }

    fn tls_findings(
        &self,
        out: &mut Vec<Finding>,
        spoken_for: &mut HashSet<FlowKey>,
        limits: &CaptureLimits,
    ) {
        for (key, exchange) in &self.tls {
            let server = exchange
                .server_name
                .clone()
                .or_else(|| exchange.server.map(|a| a.to_string()))
                .unwrap_or_else(|| key.b.to_string());

            if let Some(alert) = exchange.alert {
                // A close_notify is how a healthy connection ends.
                if alert.description == 0 {
                    continue;
                }
                let severity = if alert.level == 2 {
                    Severity::Error
                } else {
                    Severity::Warning
                };
                let fatal = if alert.level == 2 {
                    "fatal"
                } else {
                    "warning-level"
                };
                out.push(
                    Finding::new(
                        "tls_alert",
                        severity,
                        Confidence::Confirmed,
                        format!("The encrypted connection to {server} was rejected"),
                        format!(
                            "{} ended the TLS handshake with a {fatal} alert: {}. The connection itself worked - the two ends reached each other and then disagreed about encryption, so this is a certificate or configuration problem rather than a network one.",
                            alert.from,
                            tls_alert_name(alert.description)
                        ),
                    )
                    .at(alert.packet, alert.ts)
                    .between(vec![key.a.to_string(), format!("{}:{}", key.b, key.b_port)])
                    .showing(
                        alert.packet,
                        alert.offset,
                        format!("TLS alert, level {}, description {}", alert.level, alert.description),
                    )
                    .check("Check the certificate on the server: its dates, its name, and who signed it.")
                    .check("Check the client trusts the certificate authority that signed it.")
                    .check("Check both ends have a TLS version and cipher in common."),
                );
                // The alert explains the reset that usually follows it, so the
                // flow detector should not report that reset separately.
                spoken_for.insert(*key);
                continue;
            }

            if let Some((packet, ts, offset)) = exchange.client_hello {
                if exchange.server_hello {
                    continue;
                }
                // Only worth reporting where the connection itself opened: a
                // ClientHello on a connection that never completed is already
                // covered by the flow detector.
                let established = self
                    .summary
                    .flows
                    .get(key)
                    .map(|s| s.syn_ack > 0 || s.packets_rev > 0)
                    .unwrap_or(false);
                if !established {
                    continue;
                }
                let finding = Finding::new(
                    "tls_no_server_hello",
                    Severity::Warning,
                    Confidence::Suspected,
                    format!("The encrypted connection to {server} opened and then stalled"),
                    format!(
                        "The connection to {server} was established and {} sent its ClientHello, but no ServerHello and no alert follow in this capture. A handshake that stops here is what a user sees as a page that never loads after connecting.",
                        exchange.client.map(|a| a.to_string()).unwrap_or_else(|| key.a.to_string())
                    ),
                )
                .at(packet, ts)
                .between(vec![key.a.to_string(), format!("{}:{}", key.b, key.b_port)])
                .showing(packet, offset, "the ClientHello")
                .check("Check whether a device in the middle is inspecting or blocking TLS.")
                .check("Check the server's own logs for a handshake it started and abandoned.");
                out.push(weaken_for_absence(finding, limits));
                spoken_for.insert(*key);
            }
        }
    }

    fn flow_findings(
        &self,
        out: &mut Vec<Finding>,
        spoken_for: &HashSet<FlowKey>,
        limits: &CaptureLimits,
    ) {
        for (key, stats, outcome) in self.summary.flows.troubled() {
            if spoken_for.contains(&key) {
                continue;
            }
            if outcome == FlowOutcome::OneSided {
                // A flow made only of ICMP error reports is a notification,
                // not half a conversation.
                if self
                    .icmp_error_packets
                    .get(&key)
                    .is_some_and(|n| *n >= stats.packets())
                {
                    continue;
                }
                // Nothing answers a broadcast or a multicast, by design.
                if is_broadcast_or_multicast(key.b) || is_broadcast_or_multicast(key.a) {
                    continue;
                }
            }

            let finding = match outcome {
                FlowOutcome::Refused => Finding::new(
                    "connection_refused",
                    Severity::Error,
                    Confidence::Confirmed,
                    format!("Nothing is listening on {} port {}", key.b, key.b_port),
                    format!(
                        "{} tried to open a connection to {} on port {} and was answered with a reset. The host is up and reachable: it refused the connection rather than ignoring it.",
                        key.a, key.b, key.b_port
                    ),
                )
                .showing(stats.first_packet, 0, "the connection attempt")
                .check("Check the service is running on that host and listening on that port.")
                .check("Check the host's own firewall for a reject rule covering that port."),

                FlowOutcome::Unanswered => weaken_for_absence(
                    Finding::new(
                        "connection_unanswered",
                        Severity::Warning,
                        Confidence::Suspected,
                        format!("Connection attempts to {} port {} got no answer", key.b, key.b_port),
                        format!(
                            "{} sent {} packets to {} on port {} and nothing came back in this capture - no answer and no error. Silence like this is what a firewall that drops rather than rejects looks like, but it is also what a capture taken on the wrong side of the problem looks like.",
                            key.a,
                            stats.packets(),
                            key.b,
                            key.b_port
                        ),
                    )
                    .showing(stats.first_packet, 0, "the first attempt")
                    .check("Capture at the other end as well; this file shows only one side.")
                    .check("Check whether a firewall between them drops rather than rejects."),
                    limits,
                ),

                FlowOutcome::ResetMidSession => Finding::new(
                    "reset_mid_session",
                    Severity::Warning,
                    Confidence::Suspected,
                    "A connection was reset after it was established".to_string(),
                    format!(
                        "The conversation between {} and {} ended in a reset rather than a normal close. Some applications close this way on purpose, so this is worth reading alongside the application's own logs rather than on its own.",
                        key.a, key.b
                    ),
                )
                .showing(stats.first_packet, 0, "the start of the conversation")
                .check("Check the application's logs at both ends for the same moment.")
                .check("Check for an idle timeout on a firewall or load balancer in between."),

                FlowOutcome::OneSided => Finding::new(
                    "one_sided",
                    Severity::Info,
                    Confidence::IncompleteEvidence,
                    "Only one direction of this conversation was captured".to_string(),
                    format!(
                        "Packets from {} to {} are here, but nothing coming back. The replies may well exist and simply not pass the point this capture was taken at.",
                        key.a, key.b
                    ),
                )
                .showing(stats.first_packet, 0, "the first packet")
                .check("Capture closer to the other endpoint before drawing any conclusion."),

                FlowOutcome::Completed => continue,
            };

            out.push(
                finding
                    .at(stats.first_packet, stats.first_ts)
                    .between(vec![key.a.to_string(), format!("{}:{}", key.b, key.b_port)]),
            );
        }
    }

    /// Resent data, and the capture artefact that imitates it.
    ///
    /// These two have to be read together. A mirrored switch port delivers
    /// every frame twice, and a detector that counts those as retransmissions
    /// reports a network problem that exists only in the capture rig. The
    /// duplicates are separated out before anything is counted, and then
    /// reported in their own right - because a capture that doubles its own
    /// packets is worth knowing about before anyone trusts a number from it.
    fn tcp_health_findings(&self, out: &mut Vec<Finding>) {
        let mut flows: Vec<(FlowKey, crate::flow::FlowStats)> =
            self.summary.flows.iter().map(|(k, v)| (*k, *v)).collect();
        flows.sort_by_key(|(_, stats)| stats.first_packet);

        for (key, stats) in &flows {
            if key.proto != 6 {
                continue;
            }
            for (which, direction) in stats.tcp.iter().enumerate() {
                if direction.resent < RESEND_MIN_COUNT {
                    continue;
                }
                let rate = direction.resend_rate();
                if rate < RESEND_MIN_RATE {
                    continue;
                }
                let (from, to) = if which == 0 {
                    (key.a, key.b)
                } else {
                    (key.b, key.a)
                };
                out.push(
                    Finding::new(
                        "retransmissions",
                        Severity::Warning,
                        // The packets are in the file, so the repetition
                        // itself is not in doubt. The limit below is what
                        // brings this down to suspected.
                        Confidence::Confirmed,
                        format!(
                            "{:.0}% of the data from {from} to {to} was sent more than once",
                            rate * 100.0
                        ),
                        format!(
                            "{} of {} data segments in that direction covered data the sender had already sent. Retransmission is how TCP copes with an imperfect network, so a small share of it is normal everywhere and is not a fault on its own. At this rate something between the two ends is losing data - and this capture shows one point on the path, so it can say that it happened but not where.",
                            direction.resent, direction.payload_segments
                        ),
                    )
                    .at(stats.first_packet, stats.first_ts)
                    .between(vec![from.to_string(), format!("{to}:{}", key.b_port)])
                    .showing(
                        stats.first_packet,
                        0,
                        format!("the start of the conversation, {} packets in total", stats.packets()),
                    )
                    .limited_by(vec![
                        "A segment that arrived out of order looks exactly like one that was sent again, from a single capture point. This count includes both.".to_string(),
                    ])
                    .check("Capture at the other end as well: whichever end is missing the data tells you which side of the capture point the loss is on.")
                    .check("Check the interfaces along the path for errors and discards.")
                    .check("Check for a duplex mismatch or a failing link if the rate is high and steady."),
                );
            }
        }

        let duplicated: u64 = flows.iter().map(|(_, s)| s.duplicated_by_capture()).sum();
        if duplicated >= CAPTURE_DUPLICATE_MIN {
            let first = flows
                .iter()
                .find(|(_, s)| s.duplicated_by_capture() > 0)
                .map(|(_, s)| (s.first_packet, s.first_ts))
                .unwrap_or((0, 0));
            out.push(
                Finding::new(
                    "capture_duplicates",
                    Severity::Info,
                    Confidence::Confirmed,
                    format!("The capture recorded {duplicated} packets twice"),
                    format!(
                        "{duplicated} segments appear twice with the same sequence number and length, less than a millisecond apart. No sender retransmits that fast - the quickest real resend waits for three duplicate acknowledgements to arrive first. This is what a mirrored switch port looks like when it copies both directions of a link to the same place, and it is a property of the capture rather than of the network. They have been left out of the retransmission counts."
                    ),
                )
                .at(first.0, first.1)
                .showing(first.0, 0, "the first conversation with duplicated frames")
                .check("Check how the capture was taken. A mirror copying both directions to one port doubles every frame that crosses it.")
                .check("Any tool that counts retransmissions on this file without allowing for this will report loss that is not there."),
            );
        }
    }

    fn addressing_findings(&self, out: &mut Vec<Finding>) {
        for contested in self.summary.contested_addresses() {
            let address = contested.address;
            let first = contested.claims.first().map(|(_, b)| *b);
            let gap_seconds = contested.closest_gap_nanos as f64 / 1e9;

            let mut finding = match contested.contention {
                Contention::Simultaneous => Finding::new(
                    "duplicate_address",
                    Severity::Error,
                    Confidence::Confirmed,
                    format!("More than one device claims {address}"),
                    format!(
                        "Two or more hardware addresses answered for {address} within {} of each other. Traffic meant for it reaches one device or the other depending on which claim each sender happened to cache, which looks to a user like a service that works intermittently for no reason.",
                        if contested.closest_gap_nanos == 0 {
                            "the same moment".to_string()
                        } else {
                            format!("{gap_seconds:.1} seconds")
                        }
                    ),
                )
                .check("Find both devices by their hardware address on the switch.")
                .check("Check for a device with a static address inside the DHCP range."),

                // The same two claims, far enough apart to be a handover.
                // Reporting this as a duplicate is the false positive this
                // detector exists to avoid: an address changing hands after
                // a lease expires looks identical until you look at when.
                Contention::Sequential => Finding::new(
                    "address_moved",
                    Severity::Info,
                    Confidence::Confirmed,
                    format!("{address} changed hands during this capture"),
                    format!(
                        "{address} answered from one hardware address and then, {gap_seconds:.0} seconds later, from another, with no overlap. That is what a renewed lease or a swapped device looks like. It is only a problem if nothing was meant to move."
                    ),
                )
                .check("Check the DHCP server's lease log for that address at that time.")
                .check("If nothing was meant to move, treat it as two devices wanting one address."),
            }
            .between(vec![address.to_string()]);

            for (mac, binding) in &contested.claims {
                finding = finding.showing(
                    binding.first_packet,
                    0,
                    format!(
                        "{}: {address} is at {}",
                        binding.evidence.label(),
                        format_mac(mac)
                    ),
                );
            }
            out.push(finding.at(
                first.map(|b| b.first_packet).unwrap_or(0),
                first.map(|b| b.first_ts).unwrap_or(0),
            ));
        }
    }

    fn capture_findings(&self, out: &mut Vec<Finding>, limits: &CaptureLimits) {
        if let Some(dropped) = limits.reported_drops {
            if dropped > 0 {
                out.push(
                    Finding::new(
                        "capture_incomplete",
                        Severity::Info,
                        Confidence::IncompleteEvidence,
                        format!("The capture tool dropped {}", plural(dropped, "packet")),
                        format!(
                            "This file records that the interface could not keep up and {} never written. Anything that looks missing here might have been on the wire, so every \"no response\" in this capture is reported as unproven.",
                            was_were(dropped)
                        ),
                    )
                    .showing(0, 0, "from the capture file's own interface statistics")
                    .check("Capture again with a larger buffer, or with a narrower capture filter.")
                    .check("Treat every missing response in this file as unproven."),
                );
            }
        }
        if self.summary.truncated_packets > 0 {
            let payloads = if self.payload_truncated > 0 {
                format!(
                    " Of those, {} carried a payload, so the DNS, DHCP and TLS checks could not run there and report themselves as unavailable rather than as passing.",
                    plural(self.payload_truncated, "packet")
                )
            } else {
                String::new()
            };
            out.push(
                Finding::new(
                    "capture_incomplete",
                    Severity::Info,
                    Confidence::IncompleteEvidence,
                    format!(
                        "{} cut short by the capture's snaplen",
                        plural(self.summary.truncated_packets, "packet")
                    ),
                    format!(
                        "The capture was taken with a snaplen of {} bytes, so {} longer than that stored with the tail cut off.{payloads}",
                        limits.snaplen,
                        if self.summary.truncated_packets == 1 { "the packet" } else { "packets" }
                    ),
                )
                .showing(0, 0, "from the capture file's own header")
                .check("Capture again with no snaplen, or with one large enough for a full frame."),
            );
        }
        if self.summary.short_headers > 0 {
            out.push(
                Finding::new(
                    "capture_incomplete",
                    Severity::Info,
                    Confidence::IncompleteEvidence,
                    format!(
                        "{} had headers this app could not read to the end",
                        plural(self.summary.short_headers, "packet")
                    ),
                    "The headers ran past the bytes the file holds, so those packets were counted but not assigned to a conversation.".to_string(),
                )
                .showing(0, 0, "counted while reading the file"),
            );
        }
    }
}

// --------------------------------------------------------------- helpers

fn endpoints(decoded: &Decoded) -> Option<(Addr, Addr)> {
    match decoded.net {
        Some(NetLayer::Ipv4 { src, dst, .. }) => Some((Addr::V4(src), Addr::V4(dst))),
        Some(NetLayer::Ipv6 { src, dst, .. }) => Some((Addr::V6(src), Addr::V6(dst))),
        _ => None,
    }
}

/// "1 packet", "412 packets". Small thing; a product that says "1 packets"
/// reads as one nobody finished.
fn plural(n: u64, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

fn was_were(n: u64) -> &'static str {
    if n == 1 {
        "it was"
    } else {
        "they were"
    }
}

fn is_broadcast_or_multicast(addr: Addr) -> bool {
    match addr {
        Addr::V4(b) => b == [255, 255, 255, 255] || (224..=239).contains(&b[0]),
        Addr::V6(b) => b[0] == 0xff,
    }
}

fn format_mac(mac: &[u8; 6]) -> String {
    let mut out = String::with_capacity(17);
    for (i, b) in mac.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Apply what the capture file says about itself to a finding whose evidence
/// is a packet that is *not* there. Never applied to a finding built from a
/// packet that is: a reset, an ICMP error or a DNS response code says what it
/// says whatever else the capture missed.
fn weaken_for_absence(mut finding: Finding, limits: &CaptureLimits) -> Finding {
    match limits.reported_drops {
        Some(dropped) if dropped > 0 => {
            finding.confidence = finding.confidence.weakest(Confidence::IncompleteEvidence);
            finding.limits.push(format!(
                "The capture tool reports {dropped} dropped packets, so the response may have been sent and never written to this file."
            ));
        }
        None => {
            finding.limits.push(
                "This file has no way of recording packets the capture tool dropped, so it cannot show whether the capture kept up."
                    .to_string(),
            );
        }
        _ => {}
    }
    finding.limits.push(
        "A response may also exist and not pass the point this capture was taken at.".to_string(),
    );
    finding
}

fn next_checks_for_icmp(kind: &str) -> Vec<&'static str> {
    match kind {
        "blocked_by_device" => vec![
            "Find the device that sent the message - it is the one with the rule.",
            "Check the firewall rule covering that destination and port.",
        ],
        "port_unreachable" => vec![
            "Check the service is running on that host and listening on that port.",
            "Check the port number the client is configured with.",
        ],
        "mtu_too_large" => vec![
            "Check the MTU on the tunnel or link the message came from.",
            "Check that ICMP is not being filtered elsewhere, or senders will never learn this.",
        ],
        "ttl_exceeded" => vec![
            "Ignore this if someone was running traceroute at the time.",
            "Otherwise look for a routing loop between the two devices.",
        ],
        "host_unreachable" | "network_unreachable" => vec![
            "Check the route to that network from the device that sent the message.",
            "Check the destination is powered on and on the network it is expected to be on.",
        ],
        _ => vec!["Look at the device that sent the message for the reason it could not deliver."],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureFile, LinkType};
    use crate::decode::decode;

    fn analyse(bytes: &[u8]) -> (Analysis, CaptureLimits) {
        let mut capture = CaptureFile::open(bytes).unwrap();
        let mut analysis = Analysis::new();
        while let Some(packet) = capture.next_packet().unwrap() {
            let decoded = decode(packet.link_type, packet.data);
            analysis.observe(&packet, &decoded);
        }
        let limits = CaptureLimits {
            reported_drops: capture.reported_drops(),
            snaplen: capture.snaplen(),
        };
        (analysis, limits)
    }

    /// A little-endian pcap holding the given Ethernet frames.
    fn pcap(frames: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&262_144u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        for (i, frame) in frames.iter().enumerate() {
            out.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(frame);
        }
        out
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, body: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x10, 0x08, 0x00];
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&((20 + body.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, proto, 0x00, 0x00]);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(body);
        frame
    }

    fn tcp(sp: u16, dp: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut seg = Vec::new();
        seg.extend_from_slice(&sp.to_be_bytes());
        seg.extend_from_slice(&dp.to_be_bytes());
        seg.extend_from_slice(&1u32.to_be_bytes());
        seg.extend_from_slice(&1u32.to_be_bytes());
        seg.push(0x50);
        seg.push(flags);
        seg.extend_from_slice(&64240u16.to_be_bytes());
        seg.extend_from_slice(&[0, 0, 0, 0]);
        seg.extend_from_slice(payload);
        seg
    }

    const CLIENT: [u8; 4] = [192, 168, 1, 10];
    const SERVER: [u8; 4] = [192, 168, 1, 20];
    const ROUTER: [u8; 4] = [192, 168, 1, 1];

    #[test]
    fn an_icmp_error_turns_silence_into_a_confirmed_block() {
        let syn = ipv4(CLIENT, SERVER, 6, &tcp(51517, 3389, 0x02, &[]));
        // The ICMP body: header, then the IP header and first 8 bytes it quotes.
        let mut icmp = vec![3, 13, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&syn[14..14 + 28]);
        let err = ipv4(ROUTER, CLIENT, 1, &icmp);

        let (analysis, limits) = analyse(&pcap(&[&syn, &err]));
        let findings = analysis.findings(limits);

        let kinds: Vec<&str> = findings.iter().map(|f| f.kind).collect();
        assert!(
            kinds.contains(&"blocked_by_device"),
            "expected a block, got {kinds:?}"
        );
        assert!(
            !kinds.contains(&"connection_unanswered"),
            "the ICMP explains the silence, so it must not also be reported as silence: {kinds:?}"
        );
        assert!(
            !kinds.contains(&"one_sided"),
            "an ICMP error report is not half a conversation: {kinds:?}"
        );
        let block = findings.iter().find(|f| f.kind == "blocked_by_device").unwrap();
        assert_eq!(block.severity, Severity::Error);
        assert_eq!(block.confidence, Confidence::Confirmed);
    }

    #[test]
    fn the_same_attempt_without_the_icmp_is_only_suspected() {
        let syn = ipv4(CLIENT, SERVER, 6, &tcp(51517, 3389, 0x02, &[]));
        let (analysis, limits) = analyse(&pcap(&[&syn]));
        let findings = analysis.findings(limits);
        let f = findings
            .iter()
            .find(|f| f.kind == "connection_unanswered")
            .expect("expected an unanswered connection");
        assert_eq!(f.confidence, Confidence::Suspected);
        assert_eq!(f.severity, Severity::Warning);
        assert!(!f.limits.is_empty(), "it must say why it is not confirmed");
    }

    #[test]
    fn a_payload_that_looks_like_tls_but_is_not_raises_nothing() {
        // 517 bytes of 0x16, exactly as the clean fixture sends.
        let push = ipv4(CLIENT, SERVER, 6, &tcp(51514, 443, 0x18, &[0x16; 517]));
        let back = ipv4(SERVER, CLIENT, 6, &tcp(443, 51514, 0x10, &[]));
        let (analysis, limits) = analyse(&pcap(&[&push, &back]));
        let findings = analysis.findings(limits);
        assert!(findings.is_empty(), "expected silence, got {findings:?}");
    }

    #[test]
    fn a_healthy_dns_round_trip_raises_nothing() {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["example", "com"] {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&[0, 1, 0, 1]);

        let mut answer = query.clone();
        answer[2] = 0x81;
        answer[3] = 0x80;
        answer[7] = 1; // one answer record
        answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, 34]);

        let mut udp_out = Vec::new();
        udp_out.extend_from_slice(&51000u16.to_be_bytes());
        udp_out.extend_from_slice(&53u16.to_be_bytes());
        udp_out.extend_from_slice(&((8 + query.len()) as u16).to_be_bytes());
        udp_out.extend_from_slice(&[0, 0]);
        udp_out.extend_from_slice(&query);

        let mut udp_back = Vec::new();
        udp_back.extend_from_slice(&53u16.to_be_bytes());
        udp_back.extend_from_slice(&51000u16.to_be_bytes());
        udp_back.extend_from_slice(&((8 + answer.len()) as u16).to_be_bytes());
        udp_back.extend_from_slice(&[0, 0]);
        udp_back.extend_from_slice(&answer);

        let out = ipv4(CLIENT, ROUTER, 17, &udp_out);
        let back = ipv4(ROUTER, CLIENT, 17, &udp_back);
        let (analysis, limits) = analyse(&pcap(&[&out, &back]));
        assert!(
            analysis.findings(limits).is_empty(),
            "a successful lookup is not a finding"
        );
    }

    /// An ARP reply, as a frame.
    fn arp_reply(mac: [u8; 6], claiming: [u8; 4]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x10]);
        f.extend_from_slice(&mac);
        f.extend_from_slice(&[0x08, 0x06]);
        f.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 2]);
        f.extend_from_slice(&mac);
        f.extend_from_slice(&claiming);
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x10]);
        f.extend_from_slice(&[192, 168, 1, 10]);
        f
    }

    /// A pcap whose packets land at the given times, in seconds.
    fn timed(frames: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&262_144u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        for (seconds, frame) in frames {
            out.extend_from_slice(&(1_763_000_000u32 + seconds).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(frame);
        }
        out
    }

    #[test]
    fn two_claims_on_one_address_are_read_by_when_they_happened() {
        const A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x20];
        const B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x66];
        const CONTESTED: [u8; 4] = [192, 168, 1, 60];

        // Close together: both devices believed it at once.
        let together = timed(&[(0, arp_reply(A, CONTESTED)), (1, arp_reply(B, CONTESTED))]);
        let (analysis, limits) = analyse(&together);
        let kinds: Vec<&str> = analysis.findings(limits).iter().map(|f| f.kind).collect();
        assert!(
            kinds.contains(&"duplicate_address"),
            "a second claim one second later is a clash: {kinds:?}"
        );

        // Far apart: the address changed hands. Reporting this as a
        // duplicate is the false positive the detector exists to avoid - a
        // renewed lease looks identical until you look at when.
        let apart = timed(&[(0, arp_reply(A, CONTESTED)), (45, arp_reply(B, CONTESTED))]);
        let (analysis, limits) = analyse(&apart);
        let findings = analysis.findings(limits);
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind).collect();
        assert!(
            kinds.contains(&"address_moved"),
            "forty-five seconds apart is a handover: {kinds:?}"
        );
        assert!(
            !kinds.contains(&"duplicate_address"),
            "and it must not also be reported as a clash: {kinds:?}"
        );

        let moved = findings.iter().find(|f| f.kind == "address_moved").unwrap();
        assert_eq!(moved.severity, Severity::Info);
        // Both claims are in the file, so the move itself is not in doubt.
        assert_eq!(moved.confidence, Confidence::Confirmed);
        assert_eq!(moved.evidence.len(), 2, "both claims are the evidence");
    }

    #[test]
    fn the_decoder_still_reports_link_types_it_cannot_read() {
        assert!(!LinkType::Unsupported(999).is_supported());
    }
}

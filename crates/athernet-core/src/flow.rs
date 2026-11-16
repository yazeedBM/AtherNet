//! Flow assembly.
//!
//! A flow is one conversation, keyed by a canonical five-tuple so that both
//! directions land on the same row. The counters here are what the
//! conversation list and the first detectors are built on.

use std::collections::HashMap;
use std::fmt;

use crate::decode::{Decoded, NetLayer, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addr::V4(b) => write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
            Addr::V6(b) => {
                let groups: Vec<String> = (0..8)
                    .map(|i| format!("{:x}", u16::from_be_bytes([b[i * 2], b[i * 2 + 1]])))
                    .collect();
                write!(f, "{}", groups.join(":"))
            }
        }
    }
}

/// Canonical five-tuple. The lower endpoint always sits in `a`, so both
/// directions of a conversation produce the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: u8,
    pub a: Addr,
    pub a_port: u16,
    pub b: Addr,
    pub b_port: u16,
}

impl FlowKey {
    /// Returns the key and whether the packet ran in the key's own direction.
    pub fn new(proto: u8, src: Addr, src_port: u16, dst: Addr, dst_port: u16) -> (FlowKey, bool) {
        let forward = (src, src_port) <= (dst, dst_port);
        if forward {
            (
                FlowKey {
                    proto,
                    a: src,
                    a_port: src_port,
                    b: dst,
                    b_port: dst_port,
                },
                true,
            )
        } else {
            (
                FlowKey {
                    proto,
                    a: dst,
                    a_port: dst_port,
                    b: src,
                    b_port: src_port,
                },
                false,
            )
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proto = match self.proto {
            1 => "icmp",
            6 => "tcp",
            17 => "udp",
            58 => "icmpv6",
            other => return write!(f, "ip-proto-{other} {} <-> {}", self.a, self.b),
        };
        write!(
            f,
            "{proto} {}:{} <-> {}:{}",
            self.a, self.a_port, self.b, self.b_port
        )
    }
}

/// What the capture shows happened to a conversation. This is the seed of the
/// detector set: severity and confidence are kept apart, and nothing here
/// claims more than the packets show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOutcome {
    Completed,
    /// A connection attempt answered with a reset.
    Refused,
    /// A connection attempt with no answer of any kind in this capture.
    Unanswered,
    /// Reset after the connection was established.
    ResetMidSession,
    /// Only one direction was captured, so nothing can be confirmed.
    OneSided,
}

impl FlowOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            FlowOutcome::Completed => "completed",
            FlowOutcome::Refused => "connection refused",
            FlowOutcome::Unanswered => "connection unanswered",
            FlowOutcome::ResetMidSession => "reset mid-session",
            FlowOutcome::OneSided => "one direction only",
        }
    }

    /// Confidence is a separate axis from severity - see the design proposal.
    pub fn confidence(&self) -> &'static str {
        match self {
            FlowOutcome::Completed => "confirmed",
            FlowOutcome::Refused => "confirmed",
            FlowOutcome::Unanswered => "suspected",
            FlowOutcome::ResetMidSession => "suspected",
            FlowOutcome::OneSided => "incomplete evidence",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FlowStats {
    pub packets_fwd: u64,
    pub packets_rev: u64,
    pub bytes_fwd: u64,
    pub bytes_rev: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub first_packet: u64,
    pub syn: u32,
    pub syn_ack: u32,
    pub rst: u32,
    pub fin: u32,
}

impl FlowStats {
    fn new(ts: i64, packet_index: u64) -> Self {
        FlowStats {
            packets_fwd: 0,
            packets_rev: 0,
            bytes_fwd: 0,
            bytes_rev: 0,
            first_ts: ts,
            last_ts: ts,
            first_packet: packet_index,
            syn: 0,
            syn_ack: 0,
            rst: 0,
            fin: 0,
        }
    }

    fn update(&mut self, ts: i64, forward: bool, wire_len: u32, tcp_flags: u8) {
        if forward {
            self.packets_fwd += 1;
            self.bytes_fwd += wire_len as u64;
        } else {
            self.packets_rev += 1;
            self.bytes_rev += wire_len as u64;
        }
        if ts < self.first_ts {
            self.first_ts = ts;
        }
        if ts > self.last_ts {
            self.last_ts = ts;
        }
        if tcp_flags != 0 {
            let syn = tcp_flags & TCP_SYN != 0;
            let ack = tcp_flags & TCP_ACK != 0;
            if syn && ack {
                self.syn_ack += 1;
            } else if syn {
                self.syn += 1;
            }
            if tcp_flags & TCP_RST != 0 {
                self.rst += 1;
            }
            if tcp_flags & TCP_FIN != 0 {
                self.fin += 1;
            }
        }
    }

    pub fn packets(&self) -> u64 {
        self.packets_fwd + self.packets_rev
    }

    pub fn bytes(&self) -> u64 {
        self.bytes_fwd + self.bytes_rev
    }

    pub fn duration_nanos(&self) -> i64 {
        (self.last_ts - self.first_ts).max(0)
    }

    pub fn outcome(&self, proto: u8) -> FlowOutcome {
        if proto != 6 {
            return if self.packets_fwd == 0 || self.packets_rev == 0 {
                FlowOutcome::OneSided
            } else {
                FlowOutcome::Completed
            };
        }
        if self.syn > 0 && self.syn_ack == 0 {
            if self.rst > 0 {
                return FlowOutcome::Refused;
            }
            return FlowOutcome::Unanswered;
        }
        if self.rst > 0 {
            return FlowOutcome::ResetMidSession;
        }
        if self.packets_fwd == 0 || self.packets_rev == 0 {
            return FlowOutcome::OneSided;
        }
        FlowOutcome::Completed
    }
}

#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowStats>,
}

impl FlowTable {
    pub fn new() -> Self {
        FlowTable::default()
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FlowKey, &FlowStats)> {
        self.flows.iter()
    }

    pub fn get(&self, key: &FlowKey) -> Option<&FlowStats> {
        self.flows.get(key)
    }

    pub fn observe(
        &mut self,
        ts: i64,
        packet_index: u64,
        decoded: &Decoded,
        wire_len: u32,
    ) -> Option<FlowKey> {
        let (src, dst, proto) = match decoded.net {
            Some(NetLayer::Ipv4 {
                src, dst, proto, ..
            }) => (Addr::V4(src), Addr::V4(dst), proto),
            Some(NetLayer::Ipv6 {
                src,
                dst,
                next_header,
                ..
            }) => (Addr::V6(src), Addr::V6(dst), next_header),
            _ => return None,
        };
        let (src_port, dst_port) = decoded
            .transport
            .and_then(|t| t.ports())
            .unwrap_or((0, 0));
        let (key, forward) = FlowKey::new(proto, src, src_port, dst, dst_port);
        let stats = self
            .flows
            .entry(key)
            .or_insert_with(|| FlowStats::new(ts, packet_index));
        stats.update(ts, forward, wire_len, decoded.tcp_flags());
        Some(key)
    }

    /// Flows sorted by bytes, busiest first.
    pub fn busiest(&self, n: usize) -> Vec<(FlowKey, FlowStats)> {
        let mut all: Vec<(FlowKey, FlowStats)> = self.flows.iter().map(|(k, v)| (*k, *v)).collect();
        all.sort_by(|x, y| y.1.bytes().cmp(&x.1.bytes()).then(x.0.a.cmp(&y.0.a)));
        all.truncate(n);
        all
    }

    /// Flows whose outcome is anything but a completed conversation.
    pub fn troubled(&self) -> Vec<(FlowKey, FlowStats, FlowOutcome)> {
        let mut out: Vec<(FlowKey, FlowStats, FlowOutcome)> = self
            .flows
            .iter()
            .map(|(k, v)| (*k, *v, v.outcome(k.proto)))
            .filter(|(_, _, outcome)| *outcome != FlowOutcome::Completed)
            .collect();
        out.sort_by_key(|(_, stats, _)| stats.first_packet);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::TransportLayer;

    fn tcp_packet(src: [u8; 4], sp: u16, dst: [u8; 4], dp: u16, flags: u8) -> Decoded {
        Decoded {
            net: Some(NetLayer::Ipv4 {
                src,
                dst,
                proto: 6,
                ttl: 64,
                total_len: 40,
                fragmented: false,
            }),
            transport: Some(TransportLayer::Tcp {
                src_port: sp,
                dst_port: dp,
                seq: 1,
                ack: 0,
                flags,
                window: 64240,
            }),
            ..Default::default()
        }
    }

    const CLIENT: [u8; 4] = [192, 168, 1, 10];
    const SERVER: [u8; 4] = [192, 168, 1, 20];

    #[test]
    fn both_directions_share_one_flow() {
        let mut table = FlowTable::new();
        table.observe(0, 0, &tcp_packet(CLIENT, 51514, SERVER, 443, TCP_SYN), 74);
        table.observe(
            1_000_000,
            1,
            &tcp_packet(SERVER, 443, CLIENT, 51514, TCP_SYN | TCP_ACK),
            74,
        );
        assert_eq!(table.len(), 1);
        let (key, stats) = table.iter().next().unwrap();
        assert_eq!(stats.packets(), 2);
        assert_eq!(stats.outcome(key.proto), FlowOutcome::Completed);
    }

    #[test]
    fn a_reset_answer_is_a_confirmed_refusal() {
        let mut table = FlowTable::new();
        table.observe(0, 0, &tcp_packet(CLIENT, 51515, SERVER, 445, TCP_SYN), 74);
        table.observe(
            500_000,
            1,
            &tcp_packet(SERVER, 445, CLIENT, 51515, TCP_RST | TCP_ACK),
            60,
        );
        let troubled = table.troubled();
        assert_eq!(troubled.len(), 1);
        assert_eq!(troubled[0].2, FlowOutcome::Refused);
        assert_eq!(troubled[0].2.confidence(), "confirmed");
    }

    #[test]
    fn silence_is_only_ever_suspected() {
        let mut table = FlowTable::new();
        for i in 0..3 {
            table.observe(
                i * 1_000_000_000,
                i as u64,
                &tcp_packet(CLIENT, 51516, SERVER, 8080, TCP_SYN),
                74,
            );
        }
        let troubled = table.troubled();
        assert_eq!(troubled[0].2, FlowOutcome::Unanswered);
        assert_eq!(troubled[0].2.confidence(), "suspected");
    }
}

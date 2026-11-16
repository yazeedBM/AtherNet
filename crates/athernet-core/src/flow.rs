//! Flow assembly.
//!
//! A flow is one conversation, keyed by a canonical five-tuple so that both
//! directions land on the same row. The counters here are what the
//! conversation list and the first detectors are built on.

use std::collections::HashMap;
use std::fmt;

use crate::decode::{Decoded, NetLayer, TransportLayer, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

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

/// Is `a` at or before `b` in sequence space?
///
/// Sequence numbers wrap, so they are compared by the sign of the
/// difference rather than by size. A connection that has moved 3 GB has
/// wrapped, and a comparison that forgot would call every later segment a
/// retransmission.
fn seq_at_or_before(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) >= 0
}

/// One direction of a TCP conversation, as far as resent data goes.
///
/// Deliberately tiny - four words and two counters - because this is per
/// direction per flow, and a capture can hold hundreds of thousands of
/// flows. Keeping a window of recent segments would be more precise and
/// would also mean a megabyte of memory for every thousand conversations.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpDirection {
    /// Segments that carried data. Pure acknowledgements say nothing here.
    pub payload_segments: u64,
    /// Segments covering data already seen.
    pub resent: u64,
    /// Segments the capture itself recorded twice.
    pub duplicated_by_capture: u64,
    highest_end: u32,
    started: bool,
    last_seq: u32,
    last_len: u32,
    last_ts: i64,
}

/// Two identical segments this close together were recorded twice, not sent
/// twice: no sender retransmits inside a millisecond.
const CAPTURE_DUPLICATE_NANOS: i64 = 1_000_000;

impl TcpDirection {
    fn observe(&mut self, ts: i64, seq: u32, len: u32) {
        if len == 0 {
            return;
        }

        // A mirrored switch port delivers the same frame twice, microseconds
        // apart. Counting those as retransmissions is the classic way to
        // report a network problem that only exists in the capture rig. A
        // sender cannot retransmit that fast: the fastest real resend waits
        // for three duplicate acknowledgements to arrive first.
        //
        // Matching on the IP identification field as well would make this
        // stronger still; the sequence number, the length and the gap are
        // enough to be safe without decoding one more field per packet.
        if self.started
            && seq == self.last_seq
            && len == self.last_len
            && (ts - self.last_ts).abs() < CAPTURE_DUPLICATE_NANOS
        {
            self.duplicated_by_capture += 1;
            return;
        }

        self.payload_segments += 1;
        let end = seq.wrapping_add(len);
        if self.started && seq_at_or_before(end, self.highest_end) {
            self.resent += 1;
        } else {
            self.highest_end = end;
        }
        self.started = true;
        self.last_seq = seq;
        self.last_len = len;
        self.last_ts = ts;
    }

    /// Resent segments as a share of the data segments in this direction.
    pub fn resend_rate(&self) -> f64 {
        if self.payload_segments == 0 {
            0.0
        } else {
            self.resent as f64 / self.payload_segments as f64
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
    /// Resent and duplicated data, forward then reverse.
    pub tcp: [TcpDirection; 2],
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
            tcp: [TcpDirection::default(); 2],
        }
    }

    fn update(&mut self, ts: i64, forward: bool, wire_len: u32, decoded: &Decoded) {
        let tcp_flags = decoded.tcp_flags();
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

        if let Some(TransportLayer::Tcp { seq, .. }) = decoded.transport {
            let len = decoded.payload.map(|(_, len)| len as u32).unwrap_or(0);
            self.tcp[usize::from(!forward)].observe(ts, seq, len);
        }
    }

    /// Data segments across both directions.
    pub fn payload_segments(&self) -> u64 {
        self.tcp[0].payload_segments + self.tcp[1].payload_segments
    }

    /// Segments the capture recorded twice, across both directions.
    pub fn duplicated_by_capture(&self) -> u64 {
        self.tcp[0].duplicated_by_capture + self.tcp[1].duplicated_by_capture
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
        stats.update(ts, forward, wire_len, decoded);
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

    fn data(src: [u8; 4], sp: u16, dst: [u8; 4], dp: u16, seq: u32, len: usize) -> Decoded {
        let mut decoded = tcp_packet(src, sp, dst, dp, TCP_ACK);
        if let Some(TransportLayer::Tcp { seq: s, .. }) = &mut decoded.transport {
            *s = seq;
        }
        // The payload is reported as an offset and a length, never copied.
        decoded.payload = Some((54, len));
        decoded
    }

    #[test]
    fn data_sent_again_is_counted_and_data_sent_once_is_not() {
        let mut table = FlowTable::new();
        let ms = 1_000_000;
        // Four fresh segments.
        for i in 0..4u32 {
            table.observe(
                i as i64 * 10 * ms,
                i as u64,
                &data(CLIENT, 51540, SERVER, 445, 1 + i * 1460, 1460),
                1514,
            );
        }
        // Then two of them again, a third of a second later.
        table.observe(400 * ms, 10, &data(CLIENT, 51540, SERVER, 445, 1, 1460), 1514);
        table.observe(700 * ms, 11, &data(CLIENT, 51540, SERVER, 445, 1461, 1460), 1514);

        let (_, stats) = table.iter().next().unwrap();
        assert_eq!(stats.tcp[0].payload_segments, 6);
        assert_eq!(stats.tcp[0].resent, 2);
        assert_eq!(stats.tcp[0].duplicated_by_capture, 0);
        assert!((stats.tcp[0].resend_rate() - 2.0 / 6.0).abs() < 1e-9);
    }

    #[test]
    fn a_frame_the_capture_recorded_twice_is_not_a_retransmission() {
        let mut table = FlowTable::new();
        // The same segment forty microseconds apart, which is what a
        // mirrored port does and what no sender does.
        for i in 0..2 {
            table.observe(
                i * 40_000,
                i as u64,
                &data(CLIENT, 51541, SERVER, 445, 1, 1460),
                1514,
            );
        }
        let (_, stats) = table.iter().next().unwrap();
        assert_eq!(stats.tcp[0].duplicated_by_capture, 1);
        assert_eq!(
            stats.tcp[0].resent, 0,
            "a doubled capture must not look like loss on the wire"
        );
        assert_eq!(stats.tcp[0].payload_segments, 1);
    }

    #[test]
    fn sequence_numbers_that_wrap_do_not_become_retransmissions() {
        let mut table = FlowTable::new();
        let ms = 1_000_000;
        // Just below the wrap, then over it. A size comparison would call
        // the second segment old data and report a connection that resent
        // everything after 4 GB.
        table.observe(0, 0, &data(CLIENT, 51542, SERVER, 445, u32::MAX - 1000, 1000), 1514);
        table.observe(10 * ms, 1, &data(CLIENT, 51542, SERVER, 445, u32::MAX, 1000), 1514);
        table.observe(20 * ms, 2, &data(CLIENT, 51542, SERVER, 445, 999, 1000), 1514);

        let (_, stats) = table.iter().next().unwrap();
        assert_eq!(stats.tcp[0].payload_segments, 3);
        assert_eq!(stats.tcp[0].resent, 0, "wrapping is not repeating");
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

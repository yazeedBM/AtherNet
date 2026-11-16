//! What one pass over a capture leaves behind.
//!
//! The counters the dashboard reads, the flow table the conversation list
//! reads, and the IP-to-MAC bindings the addressing screen reads - each
//! binding carrying the evidence it came from, never a bare lookup.

use std::collections::{HashMap, HashSet};

use crate::capture::{LinkType, PacketRef};
use crate::decode::{Decoded, NetLayer, TransportLayer};
use crate::flow::{Addr, FlowTable};

/// How many buckets the traffic strip on the dashboard is drawn from.
pub const TIMELINE_BUCKETS: usize = 120;

/// Packets over time, built in one pass without keeping a single timestamp.
///
/// Start with a fine bucket. Whenever a packet lands past the last one, merge
/// the buckets pairwise and double their width until it fits. The resolution
/// ends up only as coarse as the capture's own span requires, and the memory
/// is a fixed 120 counters however long the capture runs.
#[derive(Debug, Clone)]
pub struct Timeline {
    width_nanos: i64,
    buckets: Vec<u64>,
    base_ts: i64,
    started: bool,
}

impl Default for Timeline {
    fn default() -> Self {
        Timeline {
            width_nanos: 1_000_000, // one millisecond
            buckets: vec![0; TIMELINE_BUCKETS],
            base_ts: 0,
            started: false,
        }
    }
}

impl Timeline {
    fn observe(&mut self, ts: i64) {
        if !self.started {
            self.started = true;
            self.base_ts = ts;
        }
        if ts < self.base_ts {
            // Out of order, or a clock that stepped backwards. Count it at
            // the start rather than dropping it or moving the whole scale.
            self.buckets[0] += 1;
            return;
        }
        let mut index = ((ts - self.base_ts) / self.width_nanos) as usize;
        while index >= TIMELINE_BUCKETS {
            self.coarsen();
            index = ((ts - self.base_ts) / self.width_nanos) as usize;
        }
        self.buckets[index] += 1;
    }

    fn coarsen(&mut self) {
        for i in 0..TIMELINE_BUCKETS / 2 {
            self.buckets[i] = self.buckets[i * 2] + self.buckets[i * 2 + 1];
        }
        for slot in self.buckets.iter_mut().skip(TIMELINE_BUCKETS / 2) {
            *slot = 0;
        }
        self.width_nanos = self.width_nanos.saturating_mul(2);
    }

    pub fn buckets(&self) -> &[u64] {
        &self.buckets
    }

    /// How much time one bucket covers. The dashboard needs this to label the
    /// strip honestly rather than implying a resolution it does not have.
    pub fn bucket_nanos(&self) -> i64 {
        self.width_nanos
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProtocolCounts {
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub arp: u64,
    pub other_ip: u64,
    pub non_ip: u64,
}

/// How an IP-to-MAC claim was learned. Ranked, because an ARP reply is a host
/// answering for itself while an Ethernet header only proves which MAC carried
/// the packet - which for anything off-segment is the router's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingEvidence {
    ArpReply,
    ArpRequestSender,
    GratuitousArp,
}

impl BindingEvidence {
    pub fn label(&self) -> &'static str {
        match self {
            BindingEvidence::ArpReply => "ARP reply",
            BindingEvidence::ArpRequestSender => "ARP request, sender fields",
            BindingEvidence::GratuitousArp => "gratuitous ARP",
        }
    }

    pub fn strength(&self) -> &'static str {
        "strong"
    }
}

/// How many distinct addresses the app will remember behind one hardware
/// address. Enough to tell a host from a router; bounded, because the answer
/// for a router is "the internet".
pub const MAX_ADDRESSES_PER_MAC: usize = 64;

/// What one hardware address was seen doing.
///
/// This is how the app distinguishes a device from a way out. It matters more
/// than it sounds: for anything off the local segment, the hardware address
/// on the packet belongs to the router, not to the host - so an address-to-
/// hardware table that does not say which is which is actively misleading.
#[derive(Debug, Default, Clone)]
pub struct MacProfile {
    pub packets: u64,
    /// Source addresses seen behind this hardware address, up to the cap.
    pub addresses: HashSet<Addr>,
    /// True when there were more than the cap, so `addresses` is a sample.
    pub capped: bool,
    /// The last address seen behind it.
    ///
    /// Almost every packet repeats the pair before it - a host sends from
    /// one address for as long as anyone is watching - so remembering the
    /// last one turns a hash lookup per packet into a comparison. Measured
    /// back to back over the corpus: about 90 M packets a minute without it,
    /// about 100 M with it, on a machine whose readings vary by a fifth
    /// either way. It changes no answer, because a repeated pair adds
    /// nothing to a set it is already in.
    last_address: Option<Addr>,
}

impl MacProfile {
    pub fn distinct_addresses(&self) -> usize {
        self.addresses.len()
    }

    /// Several addresses behind one hardware address is what a router looks
    /// like from where the capture was taken. A plain host speaks for itself
    /// and, at most, for one or two addresses it also holds.
    pub fn is_next_hop(&self) -> bool {
        self.capped || self.addresses.len() >= 4
    }

    pub fn role(&self) -> &'static str {
        if self.is_next_hop() {
            "a way out of this network"
        } else {
            "a device on this network"
        }
    }
}

/// How close together two claims on one address were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contention {
    /// Overlapping, or close enough that both devices believed it at once.
    Simultaneous,
    /// One after the other, with a gap. Usually a handover rather than a row.
    Sequential,
}

/// Two claims this far apart are a handover, not an argument.
pub const CONTENTION_WINDOW_NANOS: i64 = 10_000_000_000;

#[derive(Debug, Clone)]
pub struct ContestedAddress {
    pub address: Addr,
    /// Every hardware address that claimed it, in the order they first did.
    pub claims: Vec<([u8; 6], Binding)>,
    pub contention: Contention,
    /// Nanoseconds between the two closest claims. Zero when they overlap.
    pub closest_gap_nanos: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct Binding {
    pub evidence: BindingEvidence,
    pub first_ts: i64,
    pub last_ts: i64,
    pub observations: u64,
    /// Packet index of the first observation, so the UI can show the evidence.
    pub first_packet: u64,
}

#[derive(Debug, Default)]
pub struct CaptureSummary {
    pub packets: u64,
    pub captured_bytes: u64,
    pub wire_bytes: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    /// Packets whose captured length is less than their length on the wire.
    pub truncated_packets: u64,
    /// Packets whose headers ran past the captured bytes.
    pub short_headers: u64,
    pub protocols: ProtocolCounts,
    pub timeline: Timeline,
    pub link_types: Vec<LinkType>,
    pub flows: FlowTable,
    pub endpoints: HashMap<Addr, u64>,
    pub macs: HashMap<[u8; 6], MacProfile>,
    pub bindings: HashMap<(Addr, [u8; 6]), Binding>,
}

impl CaptureSummary {
    pub fn observe(&mut self, packet: &PacketRef<'_>, decoded: &Decoded) {
        if self.packets == 0 {
            self.first_ts = packet.ts_nanos;
            self.last_ts = packet.ts_nanos;
        }
        self.packets += 1;
        self.captured_bytes += packet.data.len() as u64;
        self.wire_bytes += packet.orig_len as u64;
        if packet.ts_nanos != 0 {
            // A packet with no timestamp at all is left out of the strip
            // rather than being drawn at the epoch.
            self.timeline.observe(packet.ts_nanos);
            if packet.ts_nanos < self.first_ts || self.first_ts == 0 {
                self.first_ts = packet.ts_nanos;
            }
            if packet.ts_nanos > self.last_ts {
                self.last_ts = packet.ts_nanos;
            }
        }
        if packet.is_truncated() {
            self.truncated_packets += 1;
        }
        if decoded.short {
            self.short_headers += 1;
        }
        if !self.link_types.contains(&packet.link_type) {
            self.link_types.push(packet.link_type);
        }

        // One lookup per hardware address, not two: the source profile is
        // reached once and both its counter and its addresses updated there.
        let src_addr = source_address(decoded);
        for (which, mac) in [decoded.eth_src, decoded.eth_dst].into_iter().enumerate() {
            let Some(mac) = mac else { continue };
            let profile = self.macs.entry(mac).or_default();
            profile.packets += 1;
            // Only the source pair says anything: the hardware address a
            // packet came from is the one that carried this source address.
            if which != 0 {
                continue;
            }
            let Some(addr) = src_addr else { continue };
            if profile.last_address == Some(addr) {
                continue;
            }
            profile.last_address = Some(addr);
            if profile.addresses.len() < MAX_ADDRESSES_PER_MAC {
                profile.addresses.insert(addr);
            } else if !profile.addresses.contains(&addr) {
                profile.capped = true;
            }
        }

        match decoded.net {
            Some(NetLayer::Ipv4 { src, dst, .. }) => {
                *self.endpoints.entry(Addr::V4(src)).or_insert(0) += 1;
                *self.endpoints.entry(Addr::V4(dst)).or_insert(0) += 1;
            }
            Some(NetLayer::Ipv6 { src, dst, .. }) => {
                *self.endpoints.entry(Addr::V6(src)).or_insert(0) += 1;
                *self.endpoints.entry(Addr::V6(dst)).or_insert(0) += 1;
            }
            Some(NetLayer::Arp {
                op,
                sender_mac,
                sender_ip,
                target_ip,
                ..
            }) => {
                self.protocols.arp += 1;
                let evidence = if op == 2 {
                    if sender_ip == target_ip {
                        BindingEvidence::GratuitousArp
                    } else {
                        BindingEvidence::ArpReply
                    }
                } else {
                    BindingEvidence::ArpRequestSender
                };
                // A sender of all zeroes is a probe, not a claim.
                if sender_ip != [0, 0, 0, 0] {
                    self.record_binding(
                        Addr::V4(sender_ip),
                        sender_mac,
                        evidence,
                        packet.ts_nanos,
                        packet.index,
                    );
                }
            }
            None => {
                self.protocols.non_ip += 1;
            }
        }

        match decoded.transport {
            Some(TransportLayer::Tcp { .. }) => self.protocols.tcp += 1,
            Some(TransportLayer::Udp { .. }) => self.protocols.udp += 1,
            Some(TransportLayer::Icmp { .. }) | Some(TransportLayer::Icmpv6 { .. }) => {
                self.protocols.icmp += 1
            }
            None => {
                if matches!(
                    decoded.net,
                    Some(NetLayer::Ipv4 { .. }) | Some(NetLayer::Ipv6 { .. })
                ) {
                    self.protocols.other_ip += 1;
                }
            }
        }

        self.flows
            .observe(packet.ts_nanos, packet.index, decoded, packet.orig_len);
    }

    fn record_binding(
        &mut self,
        addr: Addr,
        mac: [u8; 6],
        evidence: BindingEvidence,
        ts: i64,
        packet_index: u64,
    ) {
        let entry = self.bindings.entry((addr, mac)).or_insert(Binding {
            evidence,
            first_ts: ts,
            last_ts: ts,
            observations: 0,
            first_packet: packet_index,
        });
        entry.observations += 1;
        entry.last_ts = ts;
        // Keep the strongest evidence we have seen for this pair.
        if evidence == BindingEvidence::ArpReply {
            entry.evidence = evidence;
        }
    }

    pub fn duration_nanos(&self) -> i64 {
        (self.last_ts - self.first_ts).max(0)
    }

    pub fn duration_seconds(&self) -> f64 {
        self.duration_nanos() as f64 / 1e9
    }

    /// Addresses claimed by more than one hardware address, and which of the
    /// two stories the timing tells.
    ///
    /// This used to return a bare list and leave the judgement to the
    /// detector, which then did not make it: every address with two claims
    /// was reported as a duplicate. On a real network that is a false
    /// positive waiting to happen, because an address changing hands after a
    /// lease expires looks identical until you look at when.
    pub fn contested_addresses(&self) -> Vec<ContestedAddress> {
        let mut by_address: HashMap<Addr, Vec<([u8; 6], Binding)>> = HashMap::new();
        for ((addr, mac), binding) in &self.bindings {
            by_address.entry(*addr).or_default().push((*mac, *binding));
        }

        let mut out: Vec<ContestedAddress> = by_address
            .into_iter()
            .filter(|(_, claims)| claims.len() > 1)
            .map(|(address, mut claims)| {
                claims.sort_by_key(|(mac, binding)| (binding.first_ts, *mac));
                let mut closest = i64::MAX;
                for i in 0..claims.len() {
                    for j in (i + 1)..claims.len() {
                        closest = closest.min(gap_between(&claims[i].1, &claims[j].1));
                    }
                }
                let closest_gap_nanos = if closest == i64::MAX { 0 } else { closest };
                ContestedAddress {
                    address,
                    claims,
                    contention: if closest_gap_nanos < CONTENTION_WINDOW_NANOS {
                        Contention::Simultaneous
                    } else {
                        Contention::Sequential
                    },
                    closest_gap_nanos,
                }
            })
            .collect();
        out.sort_by_key(|c| c.address);
        out
    }

    pub fn busiest_endpoints(&self, n: usize) -> Vec<(Addr, u64)> {
        let mut all: Vec<(Addr, u64)> = self.endpoints.iter().map(|(a, c)| (*a, *c)).collect();
        all.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
        all.truncate(n);
        all
    }

    /// Hardware addresses that carried several addresses, busiest first.
    pub fn next_hops(&self) -> Vec<([u8; 6], &MacProfile)> {
        let mut out: Vec<([u8; 6], &MacProfile)> = self
            .macs
            .iter()
            .filter(|(_, profile)| profile.is_next_hop())
            .map(|(mac, profile)| (*mac, profile))
            .collect();
        out.sort_by(|a, b| b.1.packets.cmp(&a.1.packets).then(a.0.cmp(&b.0)));
        out
    }

    /// True when this capture cannot answer questions about missing responses.
    pub fn evidence_is_incomplete(&self) -> bool {
        self.truncated_packets > 0 || self.short_headers > 0
    }
}

/// The source address of a packet, where it has one.
fn source_address(decoded: &Decoded) -> Option<Addr> {
    match decoded.net {
        Some(NetLayer::Ipv4 { src, .. }) => Some(Addr::V4(src)),
        Some(NetLayer::Ipv6 { src, .. }) => Some(Addr::V6(src)),
        _ => None,
    }
}

/// Nanoseconds between two claim windows, or zero when they overlap.
fn gap_between(a: &Binding, b: &Binding) -> i64 {
    if a.first_ts <= b.last_ts && b.first_ts <= a.last_ts {
        return 0;
    }
    (b.first_ts - a.last_ts).max(a.first_ts - b.last_ts).max(0)
}

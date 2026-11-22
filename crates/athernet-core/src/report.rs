//! The report the UI reads, and the one place it is produced.
//!
//! The desktop shell and the headless tool both call `capture_json`, so there
//! is exactly one mapping from the core's types onto the shape the front end
//! expects. An earlier draft had the Tauri command build this itself, which
//! meant two mappings that could drift apart and only one of them under test.
//!
//! It is written by hand rather than with serde because the core has no
//! dependencies, and that is worth keeping: this crate is the part that reads
//! untrusted files.

use crate::capture::LinkType;
use crate::decode::{decode, NetLayer, TransportLayer};
use crate::assistant::{
    answer, check_citations, evidence_pack, CitationKind, PrivacyMode, Redactor,
};
use crate::detect::{Analysis, CaptureLimits};
use crate::filter::Filter;
use crate::flow::{FlowKey, FlowStats};
use crate::packets::{tcp_flag_names, PacketIndex, PacketKind, PacketRow};

/// Append a JSON string, escaped. Captured text has already been stripped to
/// printable ASCII by `appl`, but titles and explanations are ours and do
/// contain quotation marks.
fn push_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_field(out: &mut String, name: &str, first: &mut bool) {
    if !*first {
        out.push(',');
    }
    *first = false;
    push_string(out, name);
    out.push(':');
}

fn push_str_list(out: &mut String, items: impl IntoIterator<Item = String>) {
    out.push('[');
    let mut first = true;
    for item in items {
        if !first {
            out.push(',');
        }
        first = false;
        push_string(out, &item);
    }
    out.push(']');
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

/// One capture, as a JSON object, for `ui/src/report.ts`.
///
/// `id` is stable for one file within one analysis, which is all a citation
/// needs: the UI and the assistant both resolve it against the same report.
pub fn capture_json(
    file_name: &str,
    path: &str,
    analysis: &Analysis,
    limits: CaptureLimits,
) -> String {
    let summary = &analysis.summary;
    let findings = analysis.findings(limits);
    let id = file_name.replace('.', "-");

    let mut out = String::with_capacity(4096);
    let mut first = true;
    out.push('{');

    push_field(&mut out, "id", &mut first);
    push_string(&mut out, &id);
    push_field(&mut out, "file", &mut first);
    push_string(&mut out, file_name);
    push_field(&mut out, "path", &mut first);
    push_string(&mut out, path);
    push_field(&mut out, "packets", &mut first);
    out.push_str(&summary.packets.to_string());
    push_field(&mut out, "bytes", &mut first);
    out.push_str(&summary.captured_bytes.to_string());
    push_field(&mut out, "wireBytes", &mut first);
    out.push_str(&summary.wire_bytes.to_string());
    push_field(&mut out, "durationSeconds", &mut first);
    out.push_str(&format!("{:.6}", summary.duration_seconds()));
    push_field(&mut out, "startedAtUnixMs", &mut first);
    out.push_str(&(summary.first_ts / 1_000_000).to_string());

    push_field(&mut out, "linkType", &mut first);
    push_string(
        &mut out,
        summary
            .link_types
            .first()
            .map(|l| l.name())
            .unwrap_or("unknown"),
    );
    push_field(&mut out, "snaplen", &mut first);
    out.push_str(&limits.snaplen.to_string());
    push_field(&mut out, "reportedDrops", &mut first);
    out.push_str(&limits.reported_drops.unwrap_or(0).to_string());
    // Not the same as "nothing was dropped": classic pcap has nowhere to
    // record it. The dashboard says which of the two this is.
    push_field(&mut out, "dropsUnknown", &mut first);
    out.push_str(if limits.reported_drops.is_none() {
        "true"
    } else {
        "false"
    });
    push_field(&mut out, "truncatedPackets", &mut first);
    out.push_str(&summary.truncated_packets.to_string());

    push_field(&mut out, "protocols", &mut first);
    out.push_str(&format!(
        "{{\"tcp\":{},\"udp\":{},\"icmp\":{},\"arp\":{},\"other\":{}}}",
        summary.protocols.tcp,
        summary.protocols.udp,
        summary.protocols.icmp,
        summary.protocols.arp,
        summary.protocols.other_ip + summary.protocols.non_ip
    ));

    push_field(&mut out, "timeline", &mut first);
    out.push('[');
    for (i, value) in summary.timeline.buckets().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&value.to_string());
    }
    out.push(']');
    push_field(&mut out, "timelineBucketMs", &mut first);
    out.push_str(&format!(
        "{:.3}",
        summary.timeline.bucket_nanos() as f64 / 1e6
    ));

    // The conversation list, busiest first. Capped, because a capture can
    // hold hundreds of thousands of flows and nobody scrolls that far - the
    // explorer's own filter is the way to reach the rest.
    let mut flows: Vec<(FlowKey, FlowStats)> =
        summary.flows.iter().map(|(k, v)| (*k, *v)).collect();
    flows.sort_by(|a, b| {
        b.1.bytes()
            .cmp(&a.1.bytes())
            .then(a.1.first_packet.cmp(&b.1.first_packet))
    });
    let shown = flows.len().min(200);
    push_field(&mut out, "conversationCount", &mut first);
    out.push_str(&flows.len().to_string());
    push_field(&mut out, "conversations", &mut first);
    out.push('[');
    for (i, (key, stats)) in flows.iter().take(shown).enumerate() {
        if i > 0 {
            out.push(',');
        }
        let outcome = stats.outcome(key.proto);
        let mut c = true;
        out.push('{');
        push_field(&mut out, "firstPacket", &mut c);
        out.push_str(&stats.first_packet.to_string());
        push_field(&mut out, "protocol", &mut c);
        push_string(&mut out, protocol_name(key.proto));
        push_field(&mut out, "a", &mut c);
        push_string(&mut out, &key.a.to_string());
        push_field(&mut out, "aPort", &mut c);
        out.push_str(&key.a_port.to_string());
        push_field(&mut out, "b", &mut c);
        push_string(&mut out, &key.b.to_string());
        push_field(&mut out, "bPort", &mut c);
        out.push_str(&key.b_port.to_string());
        push_field(&mut out, "packets", &mut c);
        out.push_str(&stats.packets().to_string());
        push_field(&mut out, "bytes", &mut c);
        out.push_str(&stats.bytes().to_string());
        push_field(&mut out, "startUnixMs", &mut c);
        out.push_str(&(stats.first_ts / 1_000_000).to_string());
        push_field(&mut out, "durationSeconds", &mut c);
        out.push_str(&format!("{:.6}", stats.duration_nanos() as f64 / 1e9));
        push_field(&mut out, "outcome", &mut c);
        push_string(&mut out, outcome.label());
        push_field(&mut out, "confidence", &mut c);
        push_string(&mut out, outcome.confidence());
        out.push('}');
    }
    out.push(']');

    push_field(&mut out, "indexedPackets", &mut first);
    out.push_str(&analysis.packets.len().to_string());
    // True when the capture outran the packet index, so the explorer shows
    // only its beginning. The findings are still from the whole file.
    push_field(&mut out, "packetIndexCapped", &mut first);
    out.push_str(if analysis.packets.is_capped() {
        "true"
    } else {
        "false"
    });

    push_field(&mut out, "findings", &mut first);
    out.push('[');
    for (i, finding) in findings.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let mut f = true;
        out.push('{');
        push_field(&mut out, "id", &mut f);
        push_string(&mut out, &format!("{id}-{}-{i}", finding.kind));
        push_field(&mut out, "kind", &mut f);
        push_string(&mut out, finding.kind);
        push_field(&mut out, "title", &mut f);
        push_string(&mut out, &finding.title);
        push_field(&mut out, "severity", &mut f);
        push_string(&mut out, finding.severity.slug());
        push_field(&mut out, "confidence", &mut f);
        push_string(&mut out, finding.confidence.slug());
        push_field(&mut out, "what", &mut f);
        push_string(&mut out, &finding.what);
        push_field(&mut out, "endpoints", &mut f);
        push_str_list(&mut out, finding.endpoints.iter().cloned());
        push_field(&mut out, "at", &mut f);
        push_string(&mut out, &format!("packet {}", finding.first_packet));
        push_field(&mut out, "atUnixMs", &mut f);
        out.push_str(&(finding.first_ts / 1_000_000).to_string());
        // The packet the explorer jumps to when someone asks to see this.
        push_field(&mut out, "firstPacket", &mut f);
        out.push_str(&finding.first_packet.to_string());
        // The packet the explorer jumps to when someone asks to see this.
        push_field(&mut out, "firstPacket", &mut f);
        out.push_str(&finding.first_packet.to_string());
        push_field(&mut out, "evidence", &mut f);
        out.push('[');
        for (j, e) in finding.evidence.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            let mut g = true;
            out.push('{');
            push_field(&mut out, "file", &mut g);
            push_string(&mut out, file_name);
            push_field(&mut out, "frame", &mut g);
            out.push_str(&e.packet.to_string());
            push_field(&mut out, "offset", &mut g);
            out.push_str(&e.offset.to_string());
            push_field(&mut out, "note", &mut g);
            push_string(&mut out, &e.note);
            out.push('}');
        }
        out.push(']');
        push_field(&mut out, "limits", &mut f);
        push_str_list(&mut out, finding.limits.iter().cloned());
        push_field(&mut out, "nextChecks", &mut f);
        push_str_list(&mut out, finding.next_checks.iter().cloned());
        out.push('}');
    }
    out.push(']');

    push_field(&mut out, "bindings", &mut first);
    let mut bindings: Vec<_> = summary.bindings.iter().collect();
    bindings.sort_by_key(|((addr, mac), _)| (*addr, *mac));
    out.push('[');
    for (i, ((addr, mac), binding)) in bindings.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let mut b = true;
        out.push('{');
        push_field(&mut out, "address", &mut b);
        push_string(&mut out, &addr.to_string());
        push_field(&mut out, "mac", &mut b);
        push_string(&mut out, &format_mac(mac));
        push_field(&mut out, "evidence", &mut b);
        push_string(&mut out, binding.evidence.label());
        push_field(&mut out, "strength", &mut b);
        push_string(&mut out, binding.evidence.strength());
        push_field(&mut out, "firstPacket", &mut b);
        out.push_str(&binding.first_packet.to_string());
        push_field(&mut out, "observations", &mut b);
        out.push_str(&binding.observations.to_string());
        push_field(&mut out, "firstSeenUnixMs", &mut b);
        out.push_str(&(binding.first_ts / 1_000_000).to_string());
        push_field(&mut out, "lastSeenUnixMs", &mut b);
        out.push_str(&(binding.last_ts / 1_000_000).to_string());
        // Whether this hardware address is a device or the way out matters:
        // for anything off the local segment, the hardware address on the
        // packet is the router's, not the host's.
        let profile = summary.macs.get(mac);
        push_field(&mut out, "role", &mut b);
        push_string(
            &mut out,
            profile.map(|p| p.role()).unwrap_or("a device on this network"),
        );
        push_field(&mut out, "addressesBehindMac", &mut b);
        out.push_str(&profile.map(|p| p.distinct_addresses()).unwrap_or(0).to_string());
        push_field(&mut out, "macPackets", &mut b);
        out.push_str(&profile.map(|p| p.packets).unwrap_or(0).to_string());
        out.push('}');
    }
    out.push(']');

    push_field(&mut out, "nextHops", &mut first);
    out.push('[');
    for (i, (mac, profile)) in summary.next_hops().iter().take(20).enumerate() {
        if i > 0 {
            out.push(',');
        }
        let mut n = true;
        out.push('{');
        push_field(&mut out, "mac", &mut n);
        push_string(&mut out, &format_mac(mac));
        push_field(&mut out, "addresses", &mut n);
        out.push_str(&profile.distinct_addresses().to_string());
        push_field(&mut out, "capped", &mut n);
        out.push_str(if profile.capped { "true" } else { "false" });
        push_field(&mut out, "packets", &mut n);
        out.push_str(&profile.packets.to_string());
        out.push('}');
    }
    out.push(']');

    out.push('}');
    out
}

// -------------------------------------------------------------- the explorer

pub(crate) fn protocol_name(proto: u8) -> &'static str {
    match proto {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "ip",
    }
}

/// Which packets the explorer is asking for.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketQuery<'a> {
    pub start: usize,
    pub count: usize,
    /// Show only the conversation this packet belongs to. A packet index
    /// rather than a flow key, so the UI can hand back something it already
    /// has - a finding's first packet, or a conversation's - without anyone
    /// having to parse an address out of a string.
    pub flow_of_packet: Option<usize>,
    /// Matched against addresses, ports, the protocol name and the summary.
    pub text: &'a str,
    /// The built filter, in the wire format `crate::filter` documents. Empty
    /// for no filter. It is kept separate from `text` because the two answer
    /// different questions: the box is for "where is that address", the
    /// filter is for "show me only this".
    pub filter: &'a str,
}

/// The one line a packet gets in the list.
fn summary_line(index: &PacketIndex, row: &PacketRow) -> String {
    let note = index.note(row.note);
    match row.kind {
        PacketKind::Tcp => {
            let flags = tcp_flag_names(row.tcp_flags);
            if flags.is_empty() {
                format!("{} -> {}", row.src_port, row.dst_port)
            } else {
                format!("{} -> {} [{flags}]", row.src_port, row.dst_port)
            }
        }
        PacketKind::Udp => format!("{} -> {}", row.src_port, row.dst_port),
        PacketKind::Dns | PacketKind::Dhcp | PacketKind::Tls => match note {
            Some(note) => format!("{} -> {}  {note}", row.src_port, row.dst_port),
            None => format!("{} -> {}", row.src_port, row.dst_port),
        },
        _ => note
            .map(str::to_string)
            .unwrap_or_else(|| row.kind.label().to_string()),
    }
}

/// Rows the query selects. Scanning every row is deliberate: a filter that
/// quietly searched only the page on screen would be worse than no filter.
fn matching(analysis: &Analysis, query: &PacketQuery<'_>) -> (Vec<usize>, usize) {
    let index = &analysis.packets;
    let wanted_flow = query
        .flow_of_packet
        .and_then(|n| index.row(n))
        .and_then(|row| index.flow_of(row));

    let text = query.text.trim().to_lowercase();
    // Addresses and notes are interned, so each distinct one is tested once
    // rather than once per packet that carries it.
    let address_hit: Vec<bool> = if text.is_empty() {
        Vec::new()
    } else {
        index
            .addresses()
            .iter()
            .map(|a| a.to_string().to_lowercase().contains(&text))
            .collect()
    };
    let note_hit: Vec<bool> = if text.is_empty() {
        Vec::new()
    } else {
        index
            .notes()
            .iter()
            .map(|n| n.to_lowercase().contains(&text))
            .collect()
    };
    let port: Option<u16> = text.parse().ok();

    let filter = Filter::parse(query.filter, index);
    let base_ts = analysis.summary.first_ts;

    let mut matched = Vec::new();
    let mut total = 0usize;
    for (i, row) in index.rows().iter().enumerate() {
        if wanted_flow.is_some() && index.flow_of(row) != wanted_flow {
            continue;
        }
        if !text.is_empty() {
            let hit = (row.src != crate::packets::NONE
                && address_hit.get(row.src as usize).copied().unwrap_or(false))
                || (row.dst != crate::packets::NONE
                    && address_hit.get(row.dst as usize).copied().unwrap_or(false))
                || (row.note != crate::packets::NONE
                    && note_hit.get(row.note as usize).copied().unwrap_or(false))
                || row.kind.label().to_lowercase().contains(&text)
                || port.is_some_and(|p| row.src_port == p || row.dst_port == p);
            if !hit {
                continue;
            }
        }
        if !filter.is_empty() {
            // The summary line is the only part of this that costs real work,
            // so it is built only when a condition actually asks about it.
            let summary = if filter.needs_summary() {
                summary_line(index, row)
            } else {
                String::new()
            };
            let seconds = (row.ts_nanos - base_ts).max(0) as f64 / 1e9;
            if !filter.matches(index, row, seconds, &summary) {
                continue;
            }
        }
        total += 1;
        if total > query.start && matched.len() < query.count {
            matched.push(i);
        }
    }
    (matched, total)
}

/// One page of the packet list.
pub fn packets_json(analysis: &Analysis, query: PacketQuery<'_>) -> String {
    let index = &analysis.packets;
    let (page, total) = matching(analysis, &query);
    let base_ts = analysis.summary.first_ts;

    let mut out = String::with_capacity(256 + page.len() * 220);
    let mut first = true;
    out.push('{');
    push_field(&mut out, "start", &mut first);
    out.push_str(&query.start.to_string());
    push_field(&mut out, "matching", &mut first);
    out.push_str(&total.to_string());
    push_field(&mut out, "indexed", &mut first);
    out.push_str(&index.len().to_string());
    push_field(&mut out, "seen", &mut first);
    out.push_str(&index.seen().to_string());
    push_field(&mut out, "capped", &mut first);
    out.push_str(if index.is_capped() { "true" } else { "false" });

    push_field(&mut out, "rows", &mut first);
    out.push('[');
    for (n, i) in page.iter().enumerate() {
        let row = match index.row(*i) {
            Some(row) => row,
            None => continue,
        };
        if n > 0 {
            out.push(',');
        }
        let mut f = true;
        out.push('{');
        push_field(&mut out, "index", &mut f);
        out.push_str(&i.to_string());
        push_field(&mut out, "tsUnixMs", &mut f);
        out.push_str(&(row.ts_nanos / 1_000_000).to_string());
        push_field(&mut out, "sinceStartSeconds", &mut f);
        out.push_str(&format!(
            "{:.6}",
            (row.ts_nanos - base_ts).max(0) as f64 / 1e9
        ));
        push_field(&mut out, "source", &mut f);
        push_string(
            &mut out,
            &index
                .address(row.src)
                .map(|a| a.to_string())
                .unwrap_or_default(),
        );
        push_field(&mut out, "destination", &mut f);
        push_string(
            &mut out,
            &index
                .address(row.dst)
                .map(|a| a.to_string())
                .unwrap_or_default(),
        );
        push_field(&mut out, "protocol", &mut f);
        push_string(&mut out, row.kind.label());
        push_field(&mut out, "length", &mut f);
        out.push_str(&row.wire_len.to_string());
        push_field(&mut out, "truncated", &mut f);
        out.push_str(if row.is_truncated() { "true" } else { "false" });
        push_field(&mut out, "summary", &mut f);
        push_string(&mut out, &summary_line(index, row));
        out.push('}');
    }
    out.push(']');
    out.push('}');
    out
}

fn layer(out: &mut String, first: &mut bool, name: &str, fields: &[(&str, String)]) {
    if !*first {
        out.push(',');
    }
    *first = false;
    out.push_str("{\"name\":");
    push_string(out, name);
    out.push_str(",\"fields\":[");
    for (i, (key, value)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        push_string(out, key);
        out.push_str(",\"value\":");
        push_string(out, value);
        out.push('}');
    }
    out.push_str("]}");
}

fn mac_text(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn v4_text(b: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// One packet, decoded layer by layer, with its bytes.
///
/// `file` is the capture's own bytes. The index kept an offset rather than a
/// copy, so this is where the packet is actually read - which is why opening
/// a packet costs nothing until somebody does it.
pub fn packet_detail_json(analysis: &Analysis, file: &[u8], index: usize) -> String {
    let Some(row) = analysis.packets.row(index) else {
        return format!("{{\"error\":\"packet {index} is not in this capture\"}}");
    };
    let start = row.offset as usize;
    let end = start.saturating_add(row.captured_len as usize).min(file.len());
    let bytes: &[u8] = if start <= end { &file[start..end] } else { &[] };
    packet_detail_from(analysis, index, bytes)
}

/// The same, given only that packet's own bytes.
///
/// The browser holds the whole capture, so it slices. Anything reading from
/// a disk can seek to the offset the index kept and read `captured_len`
/// bytes instead, which is the difference between opening a packet in a two
/// gigabyte file and loading two gigabytes to do it.
pub fn packet_detail_from(analysis: &Analysis, index: usize, bytes: &[u8]) -> String {
    let Some(row) = analysis.packets.row(index) else {
        return format!("{{\"error\":\"packet {index} is not in this capture\"}}");
    };
    let link = analysis
        .summary
        .link_types
        .first()
        .copied()
        .unwrap_or(LinkType::Ethernet);
    let decoded = decode(link, bytes);

    let mut out = String::with_capacity(512 + bytes.len() * 2);
    let mut first = true;
    out.push('{');
    push_field(&mut out, "index", &mut first);
    out.push_str(&index.to_string());
    push_field(&mut out, "tsUnixMs", &mut first);
    out.push_str(&(row.ts_nanos / 1_000_000).to_string());
    push_field(&mut out, "offset", &mut first);
    out.push_str(&row.offset.to_string());
    push_field(&mut out, "capturedLength", &mut first);
    out.push_str(&row.captured_len.to_string());
    push_field(&mut out, "wireLength", &mut first);
    out.push_str(&row.wire_len.to_string());
    push_field(&mut out, "truncated", &mut first);
    out.push_str(if row.is_truncated() { "true" } else { "false" });
    push_field(&mut out, "summary", &mut first);
    push_string(&mut out, &summary_line(&analysis.packets, row));

    push_field(&mut out, "layers", &mut first);
    out.push('[');
    let mut layer_first = true;

    let since = (row.ts_nanos - analysis.summary.first_ts).max(0) as f64 / 1e9;
    let mut frame = vec![
        ("Packet number", (index + 1).to_string()),
        ("Time since the capture started", format!("{since:.6} s")),
        (
            "Captured",
            format!("{} bytes of {} on the wire", row.captured_len, row.wire_len),
        ),
        ("Offset in the file", format!("{} bytes", row.offset)),
        ("Link layer", link.name().to_string()),
    ];
    if row.is_truncated() {
        frame.push((
            "Cut short",
            "the capture's snaplen stopped short of the whole packet".to_string(),
        ));
    }
    if decoded.short {
        frame.push((
            "Headers incomplete",
            "a header runs past the bytes this file holds, so the layers below stop early"
                .to_string(),
        ));
    }
    layer(&mut out, &mut layer_first, "Frame", &frame);

    if let (Some(src), Some(dst)) = (decoded.eth_src, decoded.eth_dst) {
        let mut fields = vec![
            ("Source", mac_text(src)),
            ("Destination", mac_text(dst)),
        ];
        if let Some(vlan) = decoded.vlan {
            fields.push(("VLAN", vlan.to_string()));
        }
        layer(&mut out, &mut layer_first, "Ethernet", &fields);
    }

    match decoded.net {
        Some(NetLayer::Ipv4 {
            src,
            dst,
            proto,
            ttl,
            total_len,
            fragmented,
        }) => {
            let mut fields = vec![
                ("Source", v4_text(src)),
                ("Destination", v4_text(dst)),
                ("Protocol", format!("{} ({proto})", protocol_name(proto))),
                ("Time to live", ttl.to_string()),
                ("Total length", format!("{total_len} bytes")),
            ];
            if fragmented {
                fields.push((
                    "Fragment",
                    "not the first piece, so there is no transport header here".to_string(),
                ));
            }
            layer(&mut out, &mut layer_first, "IPv4", &fields);
        }
        Some(NetLayer::Ipv6 {
            src,
            dst,
            next_header,
            hop_limit,
        }) => {
            use crate::flow::Addr;
            layer(
                &mut out,
                &mut layer_first,
                "IPv6",
                &[
                    ("Source", Addr::V6(src).to_string()),
                    ("Destination", Addr::V6(dst).to_string()),
                    (
                        "Next header",
                        format!("{} ({next_header})", protocol_name(next_header)),
                    ),
                    ("Hop limit", hop_limit.to_string()),
                ],
            );
        }
        Some(NetLayer::Arp {
            op,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }) => {
            layer(
                &mut out,
                &mut layer_first,
                "ARP",
                &[
                    (
                        "Operation",
                        match op {
                            1 => "request (who has this address?)".to_string(),
                            2 => "reply (this address is at this MAC)".to_string(),
                            other => format!("operation {other}"),
                        },
                    ),
                    ("Sender address", v4_text(sender_ip)),
                    ("Sender hardware", mac_text(sender_mac)),
                    ("Target address", v4_text(target_ip)),
                    ("Target hardware", mac_text(target_mac)),
                ],
            );
        }
        None => {}
    }

    match decoded.transport {
        Some(TransportLayer::Tcp {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
        }) => {
            let names = tcp_flag_names(flags);
            let mut fields = vec![
                ("Source port", src_port.to_string()),
                ("Destination port", dst_port.to_string()),
                ("Sequence number", seq.to_string()),
                ("Acknowledgement", ack.to_string()),
                (
                    "Flags",
                    if names.is_empty() {
                        "none".to_string()
                    } else {
                        names
                    },
                ),
                (
                    "Window",
                    if window == 0 {
                        "0 - this end is telling the other to stop sending".to_string()
                    } else {
                        window.to_string()
                    },
                ),
            ];
            // The options are only on the handshake, and they are what makes
            // the window field above mean anything.
            let options = decoded.tcp_options;
            if let Some(scale) = options.window_scale {
                fields.push((
                    "Window scale",
                    format!(
                        "shift of {scale}, so every later window is multiplied by {}",
                        1u32 << scale
                    ),
                ));
            }
            if let Some(mss) = options.mss {
                fields.push((
                    "Largest segment accepted",
                    format!("{mss} bytes"),
                ));
            }
            if options.sack_permitted {
                fields.push((
                    "Selective acknowledgement",
                    "offered, so a single loss need not resend everything after it".to_string(),
                ));
            }
            layer(&mut out, &mut layer_first, "TCP", &fields);
        }
        Some(TransportLayer::Udp {
            src_port,
            dst_port,
            length,
        }) => {
            layer(
                &mut out,
                &mut layer_first,
                "UDP",
                &[
                    ("Source port", src_port.to_string()),
                    ("Destination port", dst_port.to_string()),
                    ("Length", format!("{length} bytes")),
                ],
            );
        }
        Some(TransportLayer::Icmp { kind, code }) | Some(TransportLayer::Icmpv6 { kind, code }) => {
            layer(
                &mut out,
                &mut layer_first,
                "ICMP",
                &[
                    ("Type", kind.to_string()),
                    ("Code", code.to_string()),
                    (
                        "Meaning",
                        analysis
                            .packets
                            .note(row.note)
                            .unwrap_or("not a message this app recognises")
                            .to_string(),
                    ),
                ],
            );
        }
        None => {}
    }

    if let Some(note) = analysis.packets.note(row.note) {
        if matches!(
            row.kind,
            PacketKind::Dns | PacketKind::Dhcp | PacketKind::Tls
        ) {
            layer(
                &mut out,
                &mut layer_first,
                row.kind.label(),
                &[("Summary", note.to_string())],
            );
        }
    }

    if let Some((offset, length)) = decoded.payload {
        if length > 0 {
            layer(
                &mut out,
                &mut layer_first,
                "Payload",
                &[
                    ("Length", format!("{length} bytes")),
                    ("Starts at", format!("byte {offset} of this packet")),
                ],
            );
        }
    }
    out.push(']');

    // Hex, for the one person in ten who wants to see the bytes themselves.
    push_field(&mut out, "bytes", &mut first);
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    push_string(&mut out, &hex);

    out.push('}');
    out
}

// --------------------------------------------------------------- assistant

fn citation_kind_name(kind: CitationKind) -> &'static str {
    match kind {
        CitationKind::Finding => "finding",
        CitationKind::Packet => "packet",
        CitationKind::Conversation => "conversation",
    }
}

/// An answer, the evidence behind it, and exactly what would leave the
/// machine if it were sent.
///
/// The pack in this JSON is the same string the assistant would send, not a
/// description of it. Showing a summary of what would be shared, rather than
/// the thing itself, is how a privacy control becomes a promise instead of a
/// fact somebody can check.
pub fn assistant_json(
    analysis: &Analysis,
    limits: CaptureLimits,
    file_name: &str,
    question: &str,
    mode: PrivacyMode,
) -> String {
    let reply = answer(analysis, limits, question);
    let mut redactor = Redactor::new(mode);
    let pack = evidence_pack(analysis, limits, file_name, question, &mut redactor);

    // The answer's own citations go through the same check a model's would.
    // It should never fail - but a check that only runs against output you
    // do not control is a check nobody has ever seen pass.
    let cited: String = reply
        .observations
        .iter()
        .flat_map(|s| s.citations.iter())
        .map(|c| format!("[{}:{}]", citation_kind_name(c.kind), c.id))
        .collect();
    let checks = check_citations(&cited, analysis, limits);
    let valid_of = |kind: CitationKind, id: &str| {
        checks
            .iter()
            .find(|c| c.citation.kind == kind && c.citation.id == id)
            .map(|c| c.valid)
            .unwrap_or(false)
    };

    let mut out = String::with_capacity(pack.len() + 2048);
    let mut first = true;
    out.push('{');

    push_field(&mut out, "understood", &mut first);
    out.push_str(if reply.understood { "true" } else { "false" });
    push_field(&mut out, "mode", &mut first);
    push_string(&mut out, mode.slug());
    push_field(&mut out, "modeLabel", &mut first);
    push_string(&mut out, mode.label());
    push_field(&mut out, "modeExplanation", &mut first);
    push_string(&mut out, mode.explanation());
    // Nothing here calls a model. The UI has to be able to say so, rather
    // than letting someone assume an answer came from one.
    push_field(&mut out, "source", &mut first);
    push_string(&mut out, "local-analysis");

    push_field(&mut out, "observations", &mut first);
    out.push('[');
    for (i, statement) in reply.observations.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let mut f = true;
        out.push('{');
        push_field(&mut out, "text", &mut f);
        push_string(&mut out, &statement.text);
        push_field(&mut out, "citations", &mut f);
        out.push('[');
        for (j, citation) in statement.citations.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            let mut g = true;
            out.push('{');
            push_field(&mut out, "kind", &mut g);
            push_string(&mut out, citation_kind_name(citation.kind));
            push_field(&mut out, "id", &mut g);
            push_string(&mut out, &citation.id);
            push_field(&mut out, "valid", &mut g);
            out.push_str(if valid_of(citation.kind, &citation.id) {
                "true"
            } else {
                "false"
            });
            out.push('}');
        }
        out.push(']');
        out.push('}');
    }
    out.push(']');

    push_field(&mut out, "explanations", &mut first);
    push_str_list(&mut out, reply.explanations.iter().cloned());
    push_field(&mut out, "limits", &mut first);
    push_str_list(&mut out, reply.limits.iter().cloned());

    push_field(&mut out, "evidencePack", &mut first);
    push_string(&mut out, &pack);
    push_field(&mut out, "redactions", &mut first);
    out.push('[');
    for (i, (from, to)) in redactor.pairs().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"from\":");
        push_string(&mut out, from);
        out.push_str(",\"to\":");
        push_string(&mut out, to);
        out.push('}');
    }
    out.push(']');

    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CaptureFile;
    use crate::decode::decode;

    /// A two-packet capture: a connection attempt and the ICMP that explains
    /// it. Enough to exercise strings with quotation marks in them.
    fn sample() -> Vec<u8> {
        let mut frame = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x10, 0x08, 0x00];
        frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);
        frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, 6, 0x00, 0x00]);
        frame.extend_from_slice(&[192, 168, 1, 10]);
        frame.extend_from_slice(&[192, 168, 1, 20]);
        frame.extend_from_slice(&51517u16.to_be_bytes());
        frame.extend_from_slice(&3389u16.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xfa, 0xf0, 0, 0, 0, 0]);

        let mut out = Vec::new();
        out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&262_144u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&1_763_000_000u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&frame);
        out
    }

    #[test]
    fn produces_json_that_parses_and_carries_the_finding() {
        let bytes = sample();
        let mut capture = CaptureFile::open(&bytes[..]).unwrap();
        let mut analysis = Analysis::new();
        while let Some(packet) = capture.next_packet().unwrap() {
            let decoded = decode(packet.link_type, packet.data);
            analysis.observe(&packet, &decoded);
        }
        let limits = CaptureLimits {
            reported_drops: capture.reported_drops(),
            snaplen: capture.snaplen(),
        };
        let json = capture_json("one.pcap", "/tmp/one.pcap", &analysis, limits);

        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains("\"id\":\"one-pcap\""));
        assert!(json.contains("\"connection_unanswered\""));
        assert!(json.contains("\"dropsUnknown\":true"));
        assert!(json.contains("\"timeline\":["));
        // Braces and brackets must balance, which is the cheap way to catch a
        // comma or a nesting mistake in a hand-written emitter.
        let opens = json.matches('{').count() + json.matches('[').count();
        let closes = json.matches('}').count() + json.matches(']').count();
        assert_eq!(opens, closes, "unbalanced JSON: {json}");
    }

    #[test]
    fn the_packet_list_describes_the_packet_in_one_line() {
        let bytes = sample();
        let mut capture = CaptureFile::open(&bytes[..]).unwrap();
        let mut analysis = Analysis::new();
        while let Some(packet) = capture.next_packet().unwrap() {
            let decoded = decode(packet.link_type, packet.data);
            analysis.observe(&packet, &decoded);
        }

        let json = packets_json(
            &analysis,
            PacketQuery {
                start: 0,
                count: 50,
                ..Default::default()
            },
        );
        assert!(json.contains("\"matching\":1"), "got {json}");
        assert!(json.contains("\"source\":\"192.168.1.10\""), "got {json}");
        assert!(json.contains("\"protocol\":\"TCP\""), "got {json}");
        assert!(
            json.contains("\"summary\":\"51517 -> 3389 [SYN]\""),
            "the list should read the way a packet list reads: {json}"
        );

        // Filtering by a packet's own conversation keeps that packet.
        let same = packets_json(
            &analysis,
            PacketQuery {
                start: 0,
                count: 50,
                flow_of_packet: Some(0),
                ..Default::default()
            },
        );
        assert!(same.contains("\"matching\":1"), "got {same}");

        // Filtering by something absent keeps nothing, and says so rather
        // than silently showing everything.
        let none = packets_json(
            &analysis,
            PacketQuery {
                start: 0,
                count: 50,
                text: "10.9.9.9",
                ..Default::default()
            },
        );
        assert!(none.contains("\"matching\":0"), "got {none}");
    }

    /// A four-packet capture across two subnets and three ports, which is the
    /// smallest thing that can tell an AND from an OR.
    fn mixed() -> Vec<u8> {
        fn frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
            let mut f = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x10, 0x08, 0x00];
            f.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);
            f.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, 6, 0x00, 0x00]);
            f.extend_from_slice(&src);
            f.extend_from_slice(&dst);
            f.extend_from_slice(&sport.to_be_bytes());
            f.extend_from_slice(&dport.to_be_bytes());
            f.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xfa, 0xf0, 0, 0, 0, 0]);
            f
        }

        let frames = [
            frame([10, 4, 12, 88], [93, 184, 216, 34], 50001, 443),
            frame([10, 4, 12, 88], [93, 184, 216, 34], 50002, 80),
            frame([192, 168, 1, 10], [93, 184, 216, 34], 50003, 443),
            frame([192, 168, 1, 10], [10, 4, 30, 15], 50004, 22),
        ];

        let mut out = Vec::new();
        out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&262_144u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        for (i, f) in frames.iter().enumerate() {
            out.extend_from_slice(&(1_763_000_000u32 + i as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    fn analysed(bytes: &[u8]) -> Analysis {
        let mut capture = CaptureFile::open(bytes).unwrap();
        let mut analysis = Analysis::new();
        while let Some(packet) = capture.next_packet().unwrap() {
            let decoded = decode(packet.link_type, packet.data);
            analysis.observe(&packet, &decoded);
        }
        analysis
    }

    fn matching_count(analysis: &Analysis, filter: &str) -> usize {
        let json = packets_json(
            analysis,
            PacketQuery {
                start: 0,
                count: 50,
                filter,
                ..Default::default()
            },
        );
        let marker = "\"matching\":";
        let at = json.find(marker).expect("no matching field") + marker.len();
        let rest = &json[at..];
        let end = rest.find(',').unwrap_or(rest.len());
        rest[..end].parse().expect("matching was not a number")
    }

    #[test]
    fn the_filter_tells_an_and_from_an_or() {
        let bytes = mixed();
        let analysis = analysed(&bytes);
        assert_eq!(matching_count(&analysis, ""), 4, "no filter shows everything");

        // One condition.
        assert_eq!(
            matching_count(&analysis, "C\tdst_port\tis\t443\t0"),
            2
        );

        // Two conditions in one group, matching ALL: nothing is both.
        assert_eq!(
            matching_count(
                &analysis,
                "G\tall\nC\tdst_port\tis\t443\t0\nC\tdst_port\tis\t80\t0"
            ),
            0,
            "a packet cannot go to two ports at once"
        );

        // The same two, matching ANY.
        assert_eq!(
            matching_count(
                &analysis,
                "G\tany\nC\tdst_port\tis\t443\t0\nC\tdst_port\tis\t80\t0"
            ),
            3
        );

        // Two groups, combined with ALL: (443 or 80) and from 10.4.0.0/16.
        assert_eq!(
            matching_count(
                &analysis,
                "F\tall\nG\tany\nC\tdst_port\tis\t443\t0\nC\tdst_port\tis\t80\t0\nG\tall\nC\tsrc\tin\t10.4.0.0/16\t0"
            ),
            2
        );

        // The same, with the subnet condition negated.
        assert_eq!(
            matching_count(
                &analysis,
                "F\tall\nG\tany\nC\tdst_port\tis\t443\t0\nC\tdst_port\tis\t80\t0\nG\tall\nC\tsrc\tin\t10.4.0.0/16\t1"
            ),
            1
        );

        // An address anywhere in the packet, source or destination.
        assert_eq!(
            matching_count(&analysis, "C\tany_addr\tin\t10.4.0.0/16\t0"),
            3,
            "two packets from that subnet and one to it"
        );

        // A flag, and the summary line the list shows.
        assert_eq!(matching_count(&analysis, "C\tflag\thas\tSYN\t0"), 4);
        assert_eq!(matching_count(&analysis, "C\tflag\thas\tRST\t0"), 0);
        assert_eq!(matching_count(&analysis, "C\tsummary\tcontains\t-> 22\t0"), 1);

        // A filter nobody can read narrows nothing, rather than hiding
        // everything and looking like an empty capture.
        assert_eq!(matching_count(&analysis, "C\tnope\tis\tx\t0"), 4);
    }

    #[test]
    fn one_packet_comes_back_decoded_and_in_hex() {
        let bytes = sample();
        let mut capture = CaptureFile::open(&bytes[..]).unwrap();
        let mut analysis = Analysis::new();
        while let Some(packet) = capture.next_packet().unwrap() {
            let decoded = decode(packet.link_type, packet.data);
            analysis.observe(&packet, &decoded);
        }

        let json = packet_detail_json(&analysis, &bytes, 0);
        for layer in ["Frame", "Ethernet", "IPv4", "TCP"] {
            assert!(json.contains(&format!("\"name\":\"{layer}\"")), "missing {layer}: {json}");
        }
        assert!(json.contains("\"Sequence number\""), "got {json}");

        // The bytes are read from the offset the index kept, not from a copy
        // taken during the pass, so they must match the file exactly.
        let row = analysis.packets.row(0).unwrap();
        let start = row.offset as usize;
        let expected: String = bytes[start..start + row.captured_len as usize]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(json.contains(&format!("\"bytes\":\"{expected}\"")), "got {json}");

        let missing = packet_detail_json(&analysis, &bytes, 99);
        assert!(missing.contains("\"error\""), "got {missing}");
    }

    #[test]
    fn escapes_a_quotation_mark() {
        let mut out = String::new();
        push_string(&mut out, "every \"no response\"\tis\nunproven");
        assert_eq!(out, "\"every \\\"no response\\\"\\tis\\nunproven\"");
    }
}

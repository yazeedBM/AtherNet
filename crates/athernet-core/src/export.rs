//! Exportable summaries.
//!
//! The point of this screen is somebody pasting the answer into a ticket, or
//! sending it to a vendor who will never see the capture. Three things follow
//! from that, and all three are easy to get wrong.
//!
//! **An export leaves the machine by definition.** So it offers the same
//! redaction the assistant does, out of the same `Redactor`, and when it is
//! on the document says so at the top - otherwise the recipient reads
//! `host-1` as a name somebody chose.
//!
//! **The limits travel with the findings.** A list of problems pasted into a
//! ticket without "the capture tool dropped 412 packets, so absence proves
//! nothing" is worse than no list: it reads as certainty and arrived as a
//! suspicion. Confidence, and the reasons behind it, are part of the export
//! rather than a footnote.
//!
//! **Captured text ends up inside somebody else's document.** A host name of
//! `[click here](http://example.invalid)` is a working link once it is in a
//! ticket, and a name containing `|` quietly breaks the table around it.
//! Every value that came off the wire goes through `code_span`, which wraps
//! it in a backtick fence long enough to contain it. A code span cannot be a
//! link, a heading or a table row.

use crate::assistant::Redactor;
use crate::detect::{Analysis, CaptureLimits};
use crate::flow::FlowKey;
use crate::summary::Contention;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// For a ticket, a pull request, or anything that renders markdown.
    Markdown,
    /// For an email, a chat window, or a terminal.
    Text,
}

impl ExportFormat {
    pub fn parse(text: &str) -> ExportFormat {
        match text {
            "text" => ExportFormat::Text,
            _ => ExportFormat::Markdown,
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            ExportFormat::Markdown => "md",
            ExportFormat::Text => "txt",
        }
    }
}

/// Wrap a captured value so that nothing inside it can be read as markup.
///
/// CommonMark lets a code span be delimited by any run of backticks, as long
/// as the run is longer than any inside it - so a value is never altered to
/// make it safe, only fenced well enough to hold it.
pub fn code_span(value: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in value.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let fence = "`".repeat(longest + 1);
    // A value that begins or ends with a backtick needs a space inside the
    // fence, which the renderer then strips again.
    let pad = if value.starts_with('`') || value.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{value}{pad}{fence}")
}

/// The same value for a plain-text export, where there is no markup to
/// escape but a line break would still wreck the layout.
fn plain(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}

struct Writer {
    out: String,
    markdown: bool,
}

impl Writer {
    fn line(&mut self, text: &str) {
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn blank(&mut self) {
        self.out.push('\n');
    }

    fn heading(&mut self, level: usize, text: &str) {
        if self.markdown {
            self.line(&format!("{} {text}", "#".repeat(level)));
        } else if level == 1 {
            // Left as written: this line carries the file name, and a file
            // name in capitals is a different file name on half the systems
            // somebody might paste it into.
            self.line(text);
            self.line(&"=".repeat(text.chars().count()));
        } else if level == 2 {
            self.line(&text.to_uppercase());
            self.line(&"-".repeat(text.chars().count()));
        } else {
            self.line(&format!("{text}:"));
        }
        self.blank();
    }

    fn bullet(&mut self, text: &str) {
        self.line(&format!("- {text}"));
    }

    fn numbered(&mut self, n: usize, text: &str) {
        if self.markdown {
            self.line(&format!("{n}. {text}"));
        } else {
            self.line(&format!("  {n}. {text}"));
        }
    }

    /// A captured value, fenced in markdown and left alone in plain text.
    fn value(&self, text: &str) -> String {
        if self.markdown {
            code_span(text)
        } else {
            plain(text)
        }
    }
}

/// One capture, written out for somebody who will read it somewhere else.
pub fn export(
    analysis: &Analysis,
    limits: CaptureLimits,
    file_name: &str,
    format: ExportFormat,
    redactor: &mut Redactor,
) -> String {
    redactor.learn(analysis);
    let summary = &analysis.summary;
    let findings = analysis.findings(limits);
    let mut w = Writer {
        out: String::with_capacity(4096),
        markdown: format == ExportFormat::Markdown,
    };

    let title = if redactor.is_enabled() {
        "Capture summary".to_string()
    } else {
        format!("Capture summary: {file_name}")
    };
    w.heading(1, &title);

    w.line(&format!(
        "{} packets over {:.3} seconds, {} on the wire. Link layer: {}.",
        summary.packets,
        summary.duration_seconds(),
        summary.wire_bytes,
        summary
            .link_types
            .first()
            .map(|l| l.name())
            .unwrap_or("unknown"),
    ));
    w.line(&format!(
        "Snaplen {} bytes. Produced by AtherNet from the capture file itself.",
        limits.snaplen
    ));
    w.blank();

    if redactor.is_enabled() {
        let note = "Addresses in this summary have been replaced. Names like host-1 and device-2 are labels, not anything somebody chose, and the same label always means the same device. The mapping stays on the machine the capture was read on.";
        if w.markdown {
            w.line(&format!("> **{note}**"));
        } else {
            w.line(&format!("NOTE: {note}"));
        }
        w.blank();
    }

    // The limits come before the findings on purpose. Somebody skimming a
    // ticket should meet what the capture cannot settle before they meet a
    // list that looks like certainty.
    w.heading(2, "What this capture cannot settle");
    let mut said_anything = false;
    match limits.reported_drops {
        Some(n) if n > 0 => {
            w.bullet(&format!(
                "The capture tool dropped {n} packets. Anything missing from this file might still have been on the wire."
            ));
            said_anything = true;
        }
        None => {
            w.bullet(
                "This file has no way of recording packets the capture tool dropped, so it cannot show whether the capture kept up.",
            );
            said_anything = true;
        }
        _ => {}
    }
    if summary.truncated_packets > 0 {
        w.bullet(&format!(
            "{} packets were cut short by the snaplen, so the checks that read payloads could not run on them.",
            summary.truncated_packets
        ));
        said_anything = true;
    }
    if analysis.packets.is_capped() {
        w.bullet(&format!(
            "Only the first {} packets are indexed, out of {}. The findings are from the whole file; the packet numbers below stop there.",
            analysis.packets.len(),
            analysis.packets.seen()
        ));
        said_anything = true;
    }
    w.bullet(
        "A capture only ever shows what passed the point it was taken at. Nothing here can prove a packet was never sent.",
    );
    let _ = said_anything;
    w.blank();

    w.heading(2, "Findings");
    if findings.is_empty() {
        w.line("None. Every check this app runs came back clean on this capture, which is a result rather than an empty screen.");
        w.blank();
    }
    for (i, finding) in findings.iter().enumerate() {
        let title = redactor.redact_text(&finding.title);
        w.heading(3, &format!("{}. {}", i + 1, w.value(&title)));
        if w.markdown {
            w.line(&format!(
                "**{} · {}**",
                finding.severity.label(),
                finding.confidence.label()
            ));
        } else {
            w.line(&format!(
                "{} {} · {}",
                finding.severity.marker(),
                finding.severity.label(),
                finding.confidence.label()
            ));
        }
        w.blank();
        w.line(&w.value(&redactor.redact_text(&finding.what)));
        w.blank();

        if !finding.limits.is_empty() {
            w.line(if w.markdown {
                "**Why this is not confirmed**"
            } else {
                "Why this is not confirmed:"
            });
            for limit in &finding.limits {
                let limit = redactor.redact_text(limit);
                w.bullet(&limit);
            }
            w.blank();
        }

        if !finding.evidence.is_empty() {
            w.line(if w.markdown {
                "**The packets that show it**"
            } else {
                "The packets that show it:"
            });
            for evidence in &finding.evidence {
                let note = redactor.redact_text(&evidence.note);
                w.bullet(&format!("packet {} - {}", evidence.packet + 1, w.value(&note)));
            }
            w.blank();
        }

        if !finding.next_checks.is_empty() {
            w.line(if w.markdown {
                "**What to check next**"
            } else {
                "What to check next:"
            });
            for (n, check) in finding.next_checks.iter().enumerate() {
                // These name addresses: "Ask 192.168.1.1 whether it is meant
                // to serve that name". A redacted export that redacted the
                // finding and not its advice would leak on the last line.
                let check = redactor.redact_text(check);
                w.numbered(n + 1, &check);
            }
            w.blank();
        }
    }

    // Conversations, busiest first, as a table in markdown.
    let mut flows: Vec<(FlowKey, _)> = summary.flows.iter().map(|(k, v)| (*k, *v)).collect();
    flows.sort_by(|a, b| b.1.bytes().cmp(&a.1.bytes()));
    if !flows.is_empty() {
        w.heading(2, "Conversations");
        if w.markdown {
            w.line("| Conversation | Packets | Bytes | How it ended |");
            w.line("| --- | ---: | ---: | --- |");
        }
        for (key, stats) in flows.iter().take(15) {
            let outcome = stats.outcome(key.proto);
            let a = redactor.address(&key.a.to_string());
            let b = redactor.address(&key.b.to_string());
            let label = if key.a_port == 0 && key.b_port == 0 {
                format!("{a} to {b}")
            } else {
                format!("{a}:{} to {b}:{}", key.a_port, key.b_port)
            };
            let ending = if outcome.label() == "completed" {
                "completed".to_string()
            } else {
                format!("{} ({})", outcome.label(), outcome.confidence())
            };
            if w.markdown {
                w.line(&format!(
                    "| {} | {} | {} | {ending} |",
                    code_span(&label),
                    stats.packets(),
                    stats.bytes()
                ));
            } else {
                w.line(&format!(
                    "  {label}  -  {} packets, {} bytes, {ending}",
                    stats.packets(),
                    stats.bytes()
                ));
            }
        }
        if flows.len() > 15 {
            w.blank();
            w.line(&format!(
                "{} more conversations are in the capture.",
                flows.len() - 15
            ));
        }
        w.blank();
    }

    // Addressing, and whether each hardware address is a device or a way out.
    if !summary.bindings.is_empty() {
        w.heading(2, "Addressing");
        w.line("Every row here is something the capture states outright, from ARP. An address that is not listed was never claimed in front of this capture point.");
        w.blank();
        if w.markdown {
            w.line("| Address | Hardware address | What proves it | That hardware address |");
            w.line("| --- | --- | --- | --- |");
        }
        let mut bindings: Vec<_> = summary.bindings.iter().collect();
        bindings.sort_by_key(|((addr, mac), _)| (*addr, *mac));
        for ((addr, mac), binding) in bindings {
            let address = redactor.address(&addr.to_string());
            let hardware = redactor.address(&format_mac(mac));
            let role = summary
                .macs
                .get(mac)
                .map(|p| p.role())
                .unwrap_or("a device on this network");
            if w.markdown {
                w.line(&format!(
                    "| {} | {} | {} | {role} |",
                    code_span(&address),
                    code_span(&hardware),
                    binding.evidence.label()
                ));
            } else {
                w.line(&format!(
                    "  {address} is at {hardware} - {} - {role}",
                    binding.evidence.label()
                ));
            }
        }
        w.blank();

        for contested in summary.contested_addresses() {
            let address = redactor.address(&contested.address.to_string());
            w.line(&match contested.contention {
                Contention::Simultaneous => format!(
                    "{} was claimed by more than one hardware address at the same time.",
                    w.value(&address)
                ),
                Contention::Sequential => format!(
                    "{} changed hands during this capture, with no overlap.",
                    w.value(&address)
                ),
            });
        }
        w.blank();
    }

    w.out
}

fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assistant::PrivacyMode;
    use crate::capture::CaptureFile;
    use crate::decode::decode;

    /// A capture whose DNS name is a markdown link.
    fn hostile() -> Vec<u8> {
        let labels: [&[u8]; 3] = [b"[click-here](http:", b"example.invalid)|x`y", b"test"];
        let mut dns = vec![0x5a, 0x5b, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in labels {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label);
        }
        dns.push(0);
        dns.extend_from_slice(&[0, 1, 0, 1]);

        let mut udp = Vec::new();
        udp.extend_from_slice(&51000u16.to_be_bytes());
        udp.extend_from_slice(&53u16.to_be_bytes());
        udp.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(&dns);

        let mut frame = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x10, 0x08, 0x00];
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, 17, 0x00, 0x00]);
        frame.extend_from_slice(&[192, 168, 1, 10]);
        frame.extend_from_slice(&[192, 168, 1, 1]);
        frame.extend_from_slice(&udp);

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

    /// Remove every code span, the way a markdown renderer would read them.
    /// Whatever is left is text the document itself put there - so if a
    /// captured value appears in it, that value escaped its fence.
    fn outside_code_spans(md: &str) -> String {
        let mut out = String::new();
        let bytes = md.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'`' {
                out.push(bytes[i] as char);
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && bytes[i] == b'`' {
                i += 1;
            }
            let fence = &md[start..i];
            match md[i..].find(fence) {
                Some(end) => i = i + end + fence.len(),
                None => out.push_str(fence),
            }
        }
        out
    }

    #[test]
    fn a_fence_is_always_longer_than_what_it_holds() {
        assert_eq!(code_span("plain"), "`plain`");
        assert_eq!(code_span("has `one` inside"), "``has `one` inside``");
        // Ends with a backtick, so it is padded on both sides and fenced
        // with one more backtick than the longest run inside it.
        assert_eq!(code_span("two ``here``"), "``` two ``here`` ```");
        assert_eq!(code_span("`edge"), "`` `edge ``");
        // Whatever goes in, nothing comes back out.
        for value in ["[a](b)", "| x |", "## not a heading", "``tricky`", "`"] {
            assert_eq!(
                outside_code_spans(&code_span(value)),
                "",
                "{value} escaped its fence"
            );
        }
    }

    #[test]
    fn a_host_name_cannot_become_a_link_in_somebody_elses_ticket() {
        let bytes = hostile();
        let (analysis, limits) = analyse(&bytes);
        let mut open = Redactor::new(PrivacyMode::Full);
        let md = export(&analysis, limits, "odd.pcap", ExportFormat::Markdown, &mut open);

        // The name is in the export - it is the finding, and hiding it
        // would be its own kind of dishonesty.
        assert!(md.contains("click-here"), "the name should be there: {md}");
        assert!(md.contains("|x`y"), "and it should survive intact: {md}");

        // But every part of it is inside a code span. Strip the spans the
        // way a renderer reads them, and nothing from the wire is left -
        // so none of it can be a link, a heading or a table row.
        let document = outside_code_spans(&md);
        for fragment in ["click-here", "http:", "example.invalid", "|x"] {
            assert!(
                !document.contains(fragment),
                "{fragment} escaped its fence into the document: {document}"
            );
        }
    }

    #[test]
    fn the_export_carries_the_limits_with_the_findings() {
        let bytes = hostile();
        let (analysis, limits) = analyse(&bytes);
        let mut open = Redactor::new(PrivacyMode::Full);
        let md = export(&analysis, limits, "odd.pcap", ExportFormat::Markdown, &mut open);

        assert!(md.contains("What this capture cannot settle"));
        assert!(md.contains("cannot show whether the capture kept up"));
        // The confidence of each finding travels with it.
        assert!(md.contains("suspected"), "got {md}");
        assert!(md.contains("Why this is not confirmed"));
        // And the packets, so a reader can open the same file and look.
        assert!(md.contains("packet 1 -"), "got {md}");
    }

    #[test]
    fn a_redacted_export_says_so_and_holds_no_addresses() {
        let bytes = hostile();
        let (analysis, limits) = analyse(&bytes);
        let mut hidden = Redactor::new(PrivacyMode::Redacted);
        let md = export(&analysis, limits, "odd.pcap", ExportFormat::Markdown, &mut hidden);

        assert!(
            md.contains("have been replaced"),
            "a redacted export must say so at the top: {md}"
        );
        assert!(!md.contains("192.168.1.10"), "an address survived: {md}");
        assert!(md.contains("host-"), "the labels are there instead");
        // The file name is identifying too.
        assert!(!md.contains("odd.pcap"), "the file name survived: {md}");
    }

    #[test]
    fn plain_text_has_no_markup_in_it() {
        let bytes = hostile();
        let (analysis, limits) = analyse(&bytes);
        let mut open = Redactor::new(PrivacyMode::Full);
        let text = export(&analysis, limits, "odd.pcap", ExportFormat::Text, &mut open);
        assert!(!text.contains("##"), "got {text}");
        assert!(!text.contains("**"), "got {text}");
        assert!(text.contains("WHAT THIS CAPTURE CANNOT SETTLE"), "got {text}");
    }
}

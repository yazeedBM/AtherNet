//! The headless analyser, as a command line tool.
//!
//! It serves both gates in the build order at once. Phase 1: read capture
//! files as fast as we can and report the rate, so the million packets a
//! minute per core the architecture rests on is a measured number rather
//! than an assumption. Phase 2: print what the detectors found, so the
//! labelled corpus in `fixtures/` can be checked by eye and by script.
//!
//!     athernet-bench fixtures/
//!     athernet-bench capture.pcapng --top 5

use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use athernet_core::assistant::{
    answer, check_citations, evidence_pack, CitationKind, PrivacyMode, Redactor,
};
use athernet_core::export::{code_span, export, ExportFormat, Scope};
use athernet_core::{capture_json, decode, Analysis, CaptureFile, CaptureLimits, Finding};

/// The gate from the design proposal, in packets per minute per core.
const GATE_PACKETS_PER_MINUTE: f64 = 1_000_000.0;

fn main() -> ExitCode {
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut top = 5usize;
    let mut kinds_only = false;
    let mut json_only = false;
    let mut assistant_only = false;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            "--kinds" => kinds_only = true,
            "--json" => json_only = true,
            "--assistant" => assistant_only = true,
            "--top" => {
                top = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(5);
            }
            other => paths.push(PathBuf::from(other)),
        }
    }
    if paths.is_empty() {
        print_help();
        return ExitCode::FAILURE;
    }

    let mut files: Vec<PathBuf> = Vec::new();
    for path in &paths {
        if let Err(e) = collect(path, &mut files) {
            eprintln!("could not read {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    }
    files.sort();
    if files.is_empty() {
        eprintln!("no .pcap or .pcapng files found in what you gave me");
        return ExitCode::FAILURE;
    }

    if assistant_only {
        return assistant_gate(&files);
    }
    if json_only {
        return emit_json(&files);
    }
    if kinds_only {
        return list_kinds(&files);
    }

    let mut total_packets = 0u64;
    let mut total_bytes = 0u64;
    let mut total_time = Duration::ZERO;
    let mut failures = 0usize;

    for path in &files {
        match analyse(path) {
            Ok((analysis, limits, elapsed)) => {
                total_packets += analysis.summary.packets;
                total_bytes += analysis.summary.captured_bytes;
                total_time += elapsed;
                report(path, &analysis, limits, elapsed, top);
            }
            Err(message) => {
                failures += 1;
                println!("\n{}", path.display());
                println!("  could not be analysed: {message}");
            }
        }
    }

    println!("\n{}", "-".repeat(72));
    let seconds = total_time.as_secs_f64().max(1e-9);
    let per_minute = total_packets as f64 / seconds * 60.0;
    println!(
        "{} files, {} packets, {:.1} MB in {:.3} s",
        files.len(),
        thousands(total_packets),
        total_bytes as f64 / 1e6,
        seconds
    );
    println!(
        "{:.2} M packets/minute on one core, {:.0} MB/s",
        per_minute / 1e6,
        total_bytes as f64 / 1e6 / seconds
    );
    if total_packets < 50_000 {
        println!(
            "gate: not measured - {} packets is too few to mean anything. Run it over a real capture.",
            thousands(total_packets)
        );
    } else if per_minute >= GATE_PACKETS_PER_MINUTE {
        println!(
            "gate: PASSED - {:.1}x the million packets a minute the design assumes",
            per_minute / GATE_PACKETS_PER_MINUTE
        );
    } else {
        println!(
            "gate: FAILED - {:.0}% of the million packets a minute the design assumes",
            per_minute / GATE_PACKETS_PER_MINUTE * 100.0
        );
    }

    if failures > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn print_help() {
    println!("athernet-bench - read capture files and report the rate");
    println!();
    println!("  athernet-bench <file or folder>... [--top N]");
    println!();
    println!("  --top N   how many busy conversations to list (default 5)");
    println!("  --kinds   one line per file: kind:severity:confidence, for the corpus check");
    println!("  --json    the full report for every file, as the UI reads it");
    println!("  --assistant  the phase 5 gates: citations and prompt injection");
}

/// The full report, as a JSON array. Exactly the shape the desktop app hands
/// the web view, from exactly the same function, so what the UI renders here
/// is what it will render once the app itself builds.
fn emit_json(files: &[PathBuf]) -> ExitCode {
    let mut out = String::from("[");
    for (i, path) in files.iter().enumerate() {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        match analyse(path) {
            Ok((analysis, limits, _)) => {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&capture_json(
                    name,
                    &path.display().to_string(),
                    &analysis,
                    limits,
                ));
            }
            Err(message) => {
                eprintln!("{name}: {message}");
                return ExitCode::FAILURE;
            }
        }
    }
    out.push(']');
    println!("{out}");
    ExitCode::SUCCESS
}


/// The phase 5 gates, over every capture given.
///
/// Two properties, both of them about the assistant being unable to be lied
/// to by a capture or to lie about one:
///
///   1. **Nothing a capture contains can become structure.** The evidence
///      pack is built, then every tag this app writes is stripped out. What
///      is left must contain no angle bracket at all - if it does, something
///      from the wire is being read as markup.
///   2. **Every citation resolves.** The answer's own citations are checked
///      against the analysis, the same way a model's would be.
///
/// And one more that matters just as much in practice: in redacted mode, no
/// address may appear in the pack. That is checked by looking for one, rather
/// than by trusting the redactor to have been called.
fn assistant_gate(files: &[PathBuf]) -> ExitCode {
    const QUESTIONS: [&str; 3] = [
        "what went wrong?",
        "why is it slow?",
        "what can you tell me about 192.168.1.10?",
    ];

    let mut failures = 0usize;
    for path in files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        let Ok((analysis, limits, _)) = analyse(path) else {
            println!("FAIL  {name:<32} could not be analysed");
            failures += 1;
            continue;
        };

        let mut problems: Vec<String> = Vec::new();

        for question in QUESTIONS {
            let mut open = Redactor::new(PrivacyMode::Full);
            let pack = evidence_pack(&analysis, limits, &name, question, &mut open);

            let leftover = strip_known_tags(&pack);
            if leftover.contains('<') || leftover.contains('>') {
                let at = leftover.find(['<', '>']).unwrap_or(0);
                let from = at.saturating_sub(40);
                problems.push(format!(
                    "a captured value reached the pack as markup: ...{}...",
                    &leftover[from..(at + 40).min(leftover.len())]
                ));
            }

            let reply = answer(&analysis, limits, question);
            let cited: String = reply
                .observations
                .iter()
                .flat_map(|s| s.citations.iter())
                .map(|c| {
                    format!(
                        "[{}:{}]",
                        match c.kind {
                            CitationKind::Finding => "finding",
                            CitationKind::Packet => "packet",
                            CitationKind::Conversation => "conversation",
                        },
                        c.id
                    )
                })
                .collect();
            for check in check_citations(&cited, &analysis, limits) {
                if !check.valid {
                    problems.push(format!(
                        "the answer cited {:?} {}, which {}",
                        check.citation.kind, check.citation.id, check.note
                    ));
                }
            }

            let mut hidden = Redactor::new(PrivacyMode::Redacted);
            let redacted = evidence_pack(&analysis, limits, &name, question, &mut hidden);
            if let Some(found) = first_address(&redacted) {
                problems.push(format!("an address survived redaction: {found}"));
            }
        }

        // The export is a different document with the same rule. It ends up
        // inside somebody else's ticket, where a host name that renders as a
        // link is a working link - so every captured value has to be inside
        // a code fence, and this checks each one by name rather than
        // trusting that the fencing was applied.
        let mut open = Redactor::new(PrivacyMode::Full);
        let md = export(&analysis, limits, &name, ExportFormat::Markdown, &mut open, &Scope::none());
        for finding in analysis.findings(limits) {
            if !md.contains(&code_span(&finding.title)) {
                problems.push(format!(
                    "a finding title is not fenced in the export: {}",
                    finding.title
                ));
            }
            for evidence in &finding.evidence {
                if !md.contains(&code_span(&evidence.note)) {
                    problems.push(format!(
                        "an evidence note is not fenced in the export: {}",
                        evidence.note
                    ));
                }
            }
        }

        let mut hidden_export = Redactor::new(PrivacyMode::Redacted);
        let redacted_md = export(
            &analysis,
            limits,
            &name,
            ExportFormat::Markdown,
            &mut hidden_export,
            &Scope::none(),
        );
        if let Some(found) = first_address(&redacted_md) {
            problems.push(format!("an address survived into a redacted export: {found}"));
        }
        if !redacted_md.contains("have been replaced") {
            problems.push("a redacted export does not say that it is redacted".to_string());
        }

        if problems.is_empty() {
            println!("ok    {name:<32} nothing captured became markup, every citation resolved, the export is fenced");
        } else {
            failures += 1;
            for problem in problems.iter().take(3) {
                println!("FAIL  {name:<32} {problem}");
            }
        }
    }

    println!();
    if failures > 0 {
        println!("assistant gate: FAILED - {failures} of {} captures", files.len());
        return ExitCode::FAILURE;
    }
    println!(
        "assistant gate: PASSED - {} captures, no captured text became structure in an answer or an export, no citation was invented, no address survived redaction",
        files.len()
    );
    ExitCode::SUCCESS
}

/// Remove every tag this app writes, so that anything left is something the
/// capture put there.
fn strip_known_tags(pack: &str) -> String {
    let mut out = String::with_capacity(pack.len());
    let bytes = pack.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if let Some(end) = pack[i..].find('>') {
                let tag = &pack[i..=i + end];
                let name = tag
                    .trim_start_matches('<')
                    .trim_start_matches('/')
                    .split([' ', '>'])
                    .next()
                    .unwrap_or("");
                const OURS: [&str; 5] = [
                    "question",
                    "capture",
                    "observed",
                    "finding",
                    "conversation",
                ];
                // "finding-none" shares its prefix with "finding", so match
                // the whole name rather than the start of it.
                if OURS.contains(&name) || name == "finding-none" {
                    i += end + 1;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// The first thing in this text that looks like an address, if any.
fn first_address(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    for start in 0..bytes.len() {
        if !bytes[start].is_ascii_digit() && !bytes[start].is_ascii_hexdigit() {
            continue;
        }
        if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'.') {
            continue;
        }
        let rest = &text[start..];
        if let Some(found) = looks_like_v4(rest).or_else(|| looks_like_mac(rest)) {
            return Some(found);
        }
    }
    None
}

fn looks_like_v4(text: &str) -> Option<String> {
    let mut end = 0;
    let mut groups = 0;
    let bytes = text.as_bytes();
    while groups < 4 {
        let mut digits = 0;
        while end + digits < bytes.len() && bytes[end + digits].is_ascii_digit() && digits < 3 {
            digits += 1;
        }
        if digits == 0 {
            return None;
        }
        end += digits;
        groups += 1;
        if groups < 4 {
            if end >= bytes.len() || bytes[end] != b'.' {
                return None;
            }
            end += 1;
        }
    }
    Some(text[..end].to_string())
}

fn looks_like_mac(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.len() < 17 {
        return None;
    }
    for (i, b) in bytes.iter().take(17).enumerate() {
        let ok = if i % 3 == 2 {
            *b == b':'
        } else {
            b.is_ascii_hexdigit()
        };
        if !ok {
            return None;
        }
    }
    Some(text[..17].to_string())
}

/// One machine-readable line per file, for `tools/check-corpus.mjs`. Keeping
/// this in the same binary means the corpus is checked against exactly the
/// code the app runs, not against a second implementation of it.
fn list_kinds(files: &[PathBuf]) -> ExitCode {
    let mut failed = false;
    for path in files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        match analyse(path) {
            Ok((analysis, limits, _)) => {
                let line: Vec<String> = analysis
                    .findings(limits)
                    .iter()
                    .map(|f| {
                        format!(
                            "{}:{}:{}",
                            f.kind,
                            f.severity.slug(),
                            f.confidence.label()
                        )
                    })
                    .collect();
                println!("{name}	{}", line.join(","));
            }
            Err(message) => {
                failed = true;
                println!("{name}	ERROR {message}");
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            collect(&entry?.path(), out)?;
        }
        return Ok(());
    }
    let is_capture = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("pcap") || e.eq_ignore_ascii_case("pcapng"))
        .unwrap_or(false);
    if is_capture {
        out.push(path.to_path_buf());
    }
    Ok(())
}

fn analyse(path: &Path) -> Result<(Analysis, CaptureLimits, Duration), String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let mut capture = CaptureFile::open(file).map_err(|e| e.to_string())?;
    let mut analysis = Analysis::new();
    loop {
        match capture.next_packet() {
            Ok(Some(packet)) => {
                let decoded = decode(packet.link_type, packet.data);
                analysis.observe(&packet, &decoded);
            }
            Ok(None) => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    // The clock stops before the detectors run: the gate is about reading
    // speed, and findings are drawn from state the pass already built.
    let elapsed = started.elapsed();
    let limits = CaptureLimits {
        reported_drops: capture.reported_drops(),
        snaplen: capture.snaplen(),
    };
    Ok((analysis, limits, elapsed))
}

fn report(path: &Path, analysis: &Analysis, limits: CaptureLimits, elapsed: Duration, top: usize) {
    let summary = &analysis.summary;
    let drops = limits.reported_drops;
    let seconds = elapsed.as_secs_f64().max(1e-9);
    println!("\n{}", path.display());
    println!(
        "  {} packets, {:.1} MB captured, {:.3} s of traffic, read in {:.0} ms",
        thousands(summary.packets),
        summary.captured_bytes as f64 / 1e6,
        summary.duration_seconds(),
        seconds * 1000.0
    );
    println!(
        "  {:.2} M packets/minute   tcp {} · udp {} · icmp {} · arp {} · other {}",
        summary.packets as f64 / seconds * 60.0 / 1e6,
        thousands(summary.protocols.tcp),
        thousands(summary.protocols.udp),
        thousands(summary.protocols.icmp),
        thousands(summary.protocols.arp),
        thousands(summary.protocols.other_ip + summary.protocols.non_ip)
    );
    println!(
        "  {} conversations, {} addresses, {} MAC addresses",
        thousands(summary.flows.len() as u64),
        thousands(summary.endpoints.len() as u64),
        thousands(summary.macs.len() as u64)
    );

    // Anything that limits what this capture can prove is said out loud.
    let mut notes: Vec<String> = Vec::new();
    if summary.truncated_packets > 0 {
        notes.push(format!(
            "{} packets truncated by snaplen",
            thousands(summary.truncated_packets)
        ));
    }
    if summary.short_headers > 0 {
        notes.push(format!(
            "{} packets whose headers were cut short",
            thousands(summary.short_headers)
        ));
    }
    match drops {
        Some(n) if n > 0 => notes.push(format!("{} packets dropped by the capture tool", thousands(n))),
        None => notes.push("this file cannot record packets the capture tool dropped".to_string()),
        _ => {}
    }
    if !notes.is_empty() {
        println!("  limits: {}", notes.join("; "));
    }

    let busiest = summary.flows.busiest(top);
    if !busiest.is_empty() {
        println!("  busiest conversations");
        for (key, stats) in busiest {
            println!(
                "    {:<52} {:>9} pkts {:>8.1} kB",
                key.to_string(),
                thousands(stats.packets()),
                stats.bytes() as f64 / 1e3
            );
        }
    }

    let findings = analysis.findings(limits);
    if findings.is_empty() {
        println!("  findings: none");
    } else {
        println!("  {} findings", thousands(findings.len() as u64));
        for finding in &findings {
            print_finding(finding);
        }
    }

    if !summary.bindings.is_empty() {
        println!("  IP to MAC, from ARP evidence");
        let mut bindings: Vec<_> = summary.bindings.iter().collect();
        bindings.sort_by_key(|((addr, _), _)| *addr);
        for ((addr, mac), binding) in bindings.iter().take(top) {
            println!(
                "    {:<18} {}  {} ({} observations)",
                addr.to_string(),
                format_mac(mac),
                binding.evidence.label(),
                binding.observations
            );
        }
    }
}

/// Severity is a word and a marker, never a colour on its own - the same rule
/// the UI follows, for the same reason.
fn print_finding(finding: &Finding) {
    println!(
        "    {} {:<13} {:<20} {}",
        finding.severity.marker(),
        finding.severity.label(),
        finding.confidence.label(),
        finding.title
    );
    println!("        kind {} - {}", finding.kind, finding.what);
    for evidence in &finding.evidence {
        println!("        packet {}: {}", evidence.packet, evidence.note);
    }
    for limit in &finding.limits {
        println!("        limit: {limit}");
    }
    for check in &finding.next_checks {
        println!("        next:  {check}");
    }
}

fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

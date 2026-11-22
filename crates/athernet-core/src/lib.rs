//! AtherNet analysis core.
//!
//! The core reads capture files (`.pcap`, `.pcapng`) in one streaming pass and
//! turns them into the things the rest of the app works with: a packet index,
//! flows, and counters. Nothing here allocates per packet, and nothing here
//! copies packet bytes - a decoded packet borrows the reader's buffer, and a
//! finding stores a byte offset back into the original file.
//!
//! ```no_run
//! use std::fs::File;
//! use athernet_core::{Analysis, CaptureFile, CaptureLimits, decode};
//!
//! let mut capture = CaptureFile::open(File::open("capture.pcapng")?)?;
//! let mut analysis = Analysis::new();
//! while let Some(packet) = capture.next_packet()? {
//!     let decoded = decode(packet.link_type, packet.data);
//!     analysis.observe(&packet, &decoded);
//! }
//! let limits = CaptureLimits {
//!     reported_drops: capture.reported_drops(),
//!     snaplen: capture.snaplen(),
//! };
//! for finding in analysis.findings(limits) {
//!     println!("{} ({}) {}", finding.severity, finding.confidence, finding.title);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod appl;
pub mod assistant;
pub mod capture;
pub mod decode;
pub mod detect;
pub mod export;
pub mod filter;
pub mod findings;
pub mod flow;
pub mod packets;
pub mod report;
pub mod summary;

pub use assistant::{answer, check_citations, evidence_pack, PrivacyMode, Redactor};
pub use capture::{CaptureError, CaptureFile, Format, LinkType, PacketRef};
pub use decode::{decode, Decoded, NetLayer, TcpOptions, TransportLayer, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
pub use detect::{Analysis, CaptureLimits};
pub use export::{export, export_tables, ExportFormat};
pub use filter::Filter;
pub use findings::{Confidence, Evidence, Finding, Severity};
pub use flow::{Addr, FlowKey, FlowStats, FlowTable};
pub use packets::{PacketIndex, PacketKind, PacketRow};
pub use report::{
    assistant_json, capture_json, packet_detail_from, packet_detail_json, packets_json,
    PacketQuery,
};
pub use summary::CaptureSummary;

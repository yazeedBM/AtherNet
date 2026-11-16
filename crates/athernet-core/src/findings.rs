//! What a detector produces.
//!
//! The two rules of the design proposal live in this file's types rather than
//! in anyone's discipline:
//!
//! - **Severity and confidence are separate axes.** `Severity` says how much
//!   it matters; `Confidence` says how sure the evidence makes us. A warning
//!   can be confirmed and an error can be merely suspected, so neither type
//!   can be derived from the other.
//! - **A finding carries its evidence.** Every `Finding` points at the
//!   packets it was built from, by index and by byte offset into the original
//!   file, so the UI can show them and the assistant can cite them.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "informational",
        }
    }

    /// A short text marker, because colour alone is never the signal.
    pub fn marker(&self) -> &'static str {
        match self {
            Severity::Error => "[!]",
            Severity::Warning => "[~]",
            Severity::Info => "[i]",
        }
    }

    /// The word the UI and the JSON bridge use.
    pub fn slug(&self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// The capture contains a packet that states the problem: a reset, an
    /// ICMP error, a DNS response code, a DHCP NAK, a TLS alert.
    Confirmed,
    /// The pattern fits, but the proof would be a packet that is absent, and
    /// absence has other explanations.
    Suspected,
    /// Something about the capture itself - dropped packets, truncation, one
    /// direction only - means this cannot be settled from this file.
    IncompleteEvidence,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed",
            Confidence::Suspected => "suspected",
            Confidence::IncompleteEvidence => "incomplete evidence",
        }
    }

    pub fn slug(&self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed",
            Confidence::Suspected => "suspected",
            Confidence::IncompleteEvidence => "incomplete",
        }
    }

    /// The sentence the UI puts under the badge.
    pub fn help(&self) -> &'static str {
        match self {
            Confidence::Confirmed => {
                "A packet in this capture states this outright."
            }
            Confidence::Suspected => {
                "This fits what the capture shows, but the proof would be a packet that is not here, and there are other reasons a packet might be missing."
            }
            Confidence::IncompleteEvidence => {
                "This capture cannot settle the question. What is missing is listed with the finding."
            }
        }
    }

    /// Never let a limit raise confidence - only lower it.
    pub fn weakest(self, other: Confidence) -> Confidence {
        self.max(other)
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One packet that supports a finding, with enough to find it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Packet index within its capture file, counting from zero.
    pub packet: u64,
    /// Byte offset of the packet's data in the original file.
    pub offset: u64,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable machine name, e.g. "blocked_by_device". The UI groups on it and
    /// the assistant cites it.
    pub kind: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    /// One line, in plain language, that names the problem and not the
    /// protocol mechanism.
    pub title: String,
    /// What the capture shows. Observation only - no cause is asserted here.
    pub what: String,
    pub endpoints: Vec<String>,
    pub first_packet: u64,
    pub first_ts: i64,
    pub evidence: Vec<Evidence>,
    /// Why confidence is not higher. Empty when it is confirmed.
    pub limits: Vec<String>,
    /// What someone should look at next. Suggestions, never conclusions.
    pub next_checks: Vec<String>,
}

impl Finding {
    pub fn new(
        kind: &'static str,
        severity: Severity,
        confidence: Confidence,
        title: impl Into<String>,
        what: impl Into<String>,
    ) -> Self {
        Finding {
            kind,
            severity,
            confidence,
            title: title.into(),
            what: what.into(),
            endpoints: Vec::new(),
            first_packet: 0,
            first_ts: 0,
            evidence: Vec::new(),
            limits: Vec::new(),
            next_checks: Vec::new(),
        }
    }

    pub fn at(mut self, packet: u64, ts: i64) -> Self {
        self.first_packet = packet;
        self.first_ts = ts;
        self
    }

    pub fn between(mut self, endpoints: Vec<String>) -> Self {
        self.endpoints = endpoints;
        self
    }

    pub fn showing(mut self, packet: u64, offset: u64, note: impl Into<String>) -> Self {
        self.evidence.push(Evidence {
            packet,
            offset,
            note: note.into(),
        });
        self
    }

    pub fn limited_by(mut self, limits: Vec<String>) -> Self {
        // A limit can only ever weaken a claim.
        if !limits.is_empty() && self.confidence == Confidence::Confirmed {
            self.confidence = Confidence::Suspected;
        }
        self.limits.extend(limits);
        self
    }

    pub fn check(mut self, step: impl Into<String>) -> Self {
        self.next_checks.push(step.into());
        self
    }

    /// Sort key: worst first, then in capture order.
    pub fn rank(&self) -> (Severity, Confidence, u64) {
        (self.severity, self.confidence, self.first_packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_can_only_weaken_a_finding() {
        let f = Finding::new(
            "connection_refused",
            Severity::Error,
            Confidence::Confirmed,
            "t",
            "w",
        )
        .limited_by(vec!["the capture tool dropped 412 packets".to_string()]);
        assert_eq!(f.confidence, Confidence::Suspected);
        assert_eq!(f.severity, Severity::Error, "severity is a separate axis");
    }

    #[test]
    fn confidence_orders_from_sure_to_unsure() {
        assert!(Confidence::Confirmed < Confidence::Suspected);
        assert_eq!(
            Confidence::Suspected.weakest(Confidence::IncompleteEvidence),
            Confidence::IncompleteEvidence
        );
        assert_eq!(
            Confidence::IncompleteEvidence.weakest(Confidence::Confirmed),
            Confidence::IncompleteEvidence
        );
    }
}

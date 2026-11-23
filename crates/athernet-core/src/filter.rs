//! The packet filter.
//!
//! Two levels, not an arbitrary tree: a filter matches all or any of its
//! groups, and each group matches all or any of its conditions. That covers
//! `(A and B) or (C and D)`, which is what people actually write, and it is
//! something a person who has never used a packet tool can still read off the
//! screen. A freely nested boolean tree is more expressive and - for the
//! audience this app is for - unusable.
//!
//! ## The wire format
//!
//! A filter crosses from the browser as lines of tab-separated fields:
//!
//! ```text
//! F<TAB>all
//! G<TAB>any
//! C<TAB>any_port<TAB>is<TAB>443<TAB>0
//! C<TAB>any_port<TAB>is<TAB>80<TAB>0
//! G<TAB>all
//! C<TAB>src<TAB>in<TAB>10.4.0.0/16<TAB>1
//! ```
//!
//! `F` sets how groups combine, `G` opens a group, `C` is a condition with
//! its field, operator, value and a negate flag. JSON would be the obvious
//! choice and would mean writing a JSON *parser* here; the core has no
//! dependencies and intends to keep none, and this is thirty lines against
//! two hundred. Anything malformed is skipped rather than rejected: a filter
//! is a question, and a question that cannot be read should narrow nothing.

use crate::flow::Addr;
use crate::packets::{PacketIndex, PacketRow, NONE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    AnyAddress,
    Source,
    Destination,
    AnyPort,
    SourcePort,
    DestinationPort,
    Protocol,
    Length,
    /// Seconds since the first packet in the capture.
    Seconds,
    /// The line the packet list shows.
    Summary,
    /// A TCP flag by name: SYN, ACK, RST, FIN, PSH, URG.
    TcpFlag,
    Truncated,
}

impl Field {
    fn parse(text: &str) -> Option<Field> {
        Some(match text {
            "any_addr" => Field::AnyAddress,
            "src" => Field::Source,
            "dst" => Field::Destination,
            "any_port" => Field::AnyPort,
            "src_port" => Field::SourcePort,
            "dst_port" => Field::DestinationPort,
            "protocol" => Field::Protocol,
            "length" => Field::Length,
            "seconds" => Field::Seconds,
            "summary" => Field::Summary,
            "flag" => Field::TcpFlag,
            "truncated" => Field::Truncated,
            _ => return None,
        })
    }

    fn is_address(&self) -> bool {
        matches!(self, Field::AnyAddress | Field::Source | Field::Destination)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Is,
    Contains,
    /// Inside a CIDR range, e.g. 10.4.0.0/16.
    InSubnet,
    GreaterThan,
    LessThan,
    Has,
}

impl Op {
    fn parse(text: &str) -> Option<Op> {
        Some(match text {
            "is" => Op::Is,
            "contains" => Op::Contains,
            "in" => Op::InSubnet,
            "gt" => Op::GreaterThan,
            "lt" => Op::LessThan,
            "has" => Op::Has,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
struct Condition {
    field: Field,
    op: Op,
    value: String,
    negate: bool,
    /// For address fields: whether each interned address matches. Addresses
    /// repeat across millions of packets, so each distinct one is tested
    /// once here instead of once per packet that carries it.
    address_hits: Vec<bool>,
    /// The value as a number, where the field is one.
    number: f64,
}

#[derive(Debug, Clone)]
struct Group {
    match_all: bool,
    conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Default)]
pub struct Filter {
    match_all: bool,
    groups: Vec<Group>,
    /// True when any condition needs the summary line built, which is the one
    /// thing here that costs real work per packet.
    needs_summary: bool,
}

impl Filter {
    /// True when this filter would not narrow anything.
    pub fn is_empty(&self) -> bool {
        self.groups.iter().all(|g| g.conditions.is_empty())
    }

    pub fn needs_summary(&self) -> bool {
        self.needs_summary
    }

    /// Read a filter from the wire format, resolving address conditions
    /// against this capture's interned addresses as it goes.
    pub fn parse(text: &str, index: &PacketIndex) -> Filter {
        let mut filter = Filter {
            match_all: true,
            groups: Vec::new(),
            needs_summary: false,
        };
        for line in text.lines() {
            let mut parts = line.split('\t');
            match parts.next() {
                Some("F") => {
                    filter.match_all = parts.next() != Some("any");
                }
                Some("G") => {
                    filter.groups.push(Group {
                        match_all: parts.next() != Some("any"),
                        conditions: Vec::new(),
                    });
                }
                Some("C") => {
                    let (Some(field), Some(op), Some(value)) =
                        (parts.next(), parts.next(), parts.next())
                    else {
                        continue;
                    };
                    let (Some(field), Some(op)) = (Field::parse(field), Op::parse(op)) else {
                        continue;
                    };
                    let negate = parts.next() == Some("1");
                    // A condition before any group opens its own, so a filter
                    // that forgets the G line still means something.
                    if filter.groups.is_empty() {
                        filter.groups.push(Group {
                            match_all: true,
                            conditions: Vec::new(),
                        });
                    }
                    if field == Field::Summary {
                        filter.needs_summary = true;
                    }
                    let address_hits = if field.is_address() {
                        compile_addresses(index, op, value)
                    } else {
                        Vec::new()
                    };
                    let group = filter.groups.last_mut().expect("just ensured");
                    group.conditions.push(Condition {
                        field,
                        op,
                        value: value.to_lowercase(),
                        negate,
                        address_hits,
                        number: value.trim().parse().unwrap_or(f64::NAN),
                    });
                }
                _ => {}
            }
        }
        filter.groups.retain(|g| !g.conditions.is_empty());
        filter
    }

    /// Does this packet pass?
    ///
    /// `summary` is only built by the caller when `needs_summary` says so.
    pub fn matches(
        &self,
        index: &PacketIndex,
        row: &PacketRow,
        seconds: f64,
        summary: &str,
    ) -> bool {
        if self.groups.is_empty() {
            return true;
        }
        let mut any = false;
        for group in &self.groups {
            let passed = if group.match_all {
                group
                    .conditions
                    .iter()
                    .all(|c| c.matches(index, row, seconds, summary))
            } else {
                group
                    .conditions
                    .iter()
                    .any(|c| c.matches(index, row, seconds, summary))
            };
            if self.match_all {
                if !passed {
                    return false;
                }
            } else if passed {
                any = true;
            }
        }
        if self.match_all {
            true
        } else {
            any
        }
    }
}

impl Condition {
    fn matches(&self, index: &PacketIndex, row: &PacketRow, seconds: f64, summary: &str) -> bool {
        let hit = self.test(index, row, seconds, summary);
        hit != self.negate
    }

    fn test(&self, _index: &PacketIndex, row: &PacketRow, seconds: f64, summary: &str) -> bool {
        match self.field {
            Field::AnyAddress => self.address(row.src) || self.address(row.dst),
            Field::Source => self.address(row.src),
            Field::Destination => self.address(row.dst),
            Field::AnyPort => self.port(row.src_port) || self.port(row.dst_port),
            Field::SourcePort => self.port(row.src_port),
            Field::DestinationPort => self.port(row.dst_port),
            Field::Protocol => {
                let label = row.kind.label().to_lowercase();
                match self.op {
                    Op::Contains => label.contains(&self.value),
                    _ => label == self.value,
                }
            }
            Field::Length => self.number_test(row.wire_len as f64),
            Field::Seconds => self.number_test(seconds),
            Field::Summary => summary.to_lowercase().contains(&self.value),
            Field::TcpFlag => {
                use crate::decode::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCP_URG};
                let bit = match self.value.as_str() {
                    "syn" => TCP_SYN,
                    "ack" => TCP_ACK,
                    "rst" => TCP_RST,
                    "fin" => TCP_FIN,
                    "psh" => TCP_PSH,
                    "urg" => TCP_URG,
                    _ => return false,
                };
                row.tcp_flags & bit != 0
            }
            Field::Truncated => {
                let wanted = self.value != "false" && self.value != "0";
                row.is_truncated() == wanted
            }
        }
    }

    fn address(&self, id: u32) -> bool {
        if id == NONE {
            return false;
        }
        self.address_hits.get(id as usize).copied().unwrap_or(false)
    }

    fn port(&self, port: u16) -> bool {
        if port == 0 {
            return false;
        }
        match self.op {
            Op::GreaterThan | Op::LessThan => self.number_test(port as f64),
            _ => self.value.trim() == port.to_string(),
        }
    }

    fn number_test(&self, value: f64) -> bool {
        if self.number.is_nan() {
            return false;
        }
        match self.op {
            Op::GreaterThan => value > self.number,
            Op::LessThan => value < self.number,
            _ => (value - self.number).abs() < f64::EPSILON,
        }
    }
}

// ------------------------------------------- the same filter, bigger things
//
// A filter is written against packets, and the parts of this app that are not
// packets still have to honour it: a findings list, a map of conversations,
// an export. Those are not packets, so some questions have no answer about
// them - a conversation is many packets and has no single length or TCP flag.
//
// Hence three values rather than two. A subject the filter rules out is
// dropped; one it cannot decide is kept, and the view says it could not
// decide. Folding Unknown into No would quietly empty a map or an export the
// moment somebody filtered on a per-packet field, and a report that silently
// loses rows is the worst thing this project could ship.
//
// ui/src/display-filter.ts does the same job for the live screen, which needs
// an answer without calling into the core. The two must agree; this one is
// authoritative, because it is the one the exports go through.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truth {
    Yes,
    No,
    Unknown,
}

impl Truth {
    fn and(self, other: Truth) -> Truth {
        match (self, other) {
            (Truth::No, _) | (_, Truth::No) => Truth::No,
            (Truth::Unknown, _) | (_, Truth::Unknown) => Truth::Unknown,
            _ => Truth::Yes,
        }
    }

    fn or(self, other: Truth) -> Truth {
        match (self, other) {
            (Truth::Yes, _) | (_, Truth::Yes) => Truth::Yes,
            (Truth::Unknown, _) | (_, Truth::Unknown) => Truth::Unknown,
            _ => Truth::No,
        }
    }

    /// What a view should do with it: keep anything not ruled out.
    pub fn keeps(self) -> bool {
        self != Truth::No
    }
}

/// What a non-packet thing can say about itself.
///
/// A conversation knows both its ends and both its ports. A finding knows the
/// addresses it involves but has no direction, so it puts them on both sides:
/// `ip.src == x` then matches a finding about x, which is what somebody
/// filtering by an address means.
#[derive(Default)]
pub struct Subject {
    pub src: Vec<String>,
    pub dst: Vec<String>,
    pub src_ports: Vec<u16>,
    pub dst_ports: Vec<u16>,
    pub protocol: Option<String>,
}

impl Subject {
    pub fn from_endpoints(endpoints: &[String]) -> Subject {
        let mut subject = Subject::default();
        for endpoint in endpoints {
            // "10.0.0.1:443", a bare address, or a hardware address - which
            // is full of colons and must not be split on the last one.
            match endpoint.rsplit_once(':') {
                Some((head, tail)) if tail.chars().all(|c| c.is_ascii_digit()) && !tail.is_empty() => {
                    subject.src.push(head.to_string());
                    if let Ok(port) = tail.parse() {
                        subject.src_ports.push(port);
                    }
                }
                _ => subject.src.push(endpoint.clone()),
            }
        }
        subject.dst = subject.src.clone();
        subject.dst_ports = subject.src_ports.clone();
        subject
    }
}

impl Filter {
    /// Does this conversation, finding or binding pass?
    pub fn judge(&self, subject: &Subject) -> Truth {
        if self.is_empty() {
            return Truth::Yes;
        }
        let mut overall = if self.match_all { Truth::Yes } else { Truth::No };
        for group in &self.groups {
            let mut inner = if group.match_all { Truth::Yes } else { Truth::No };
            for condition in &group.conditions {
                let one = condition.judge(subject);
                inner = if group.match_all { inner.and(one) } else { inner.or(one) };
            }
            overall = if self.match_all { overall.and(inner) } else { overall.or(inner) };
        }
        overall
    }
}

impl Condition {
    fn judge(&self, subject: &Subject) -> Truth {
        match self.field {
            Field::AnyAddress => {
                let mut all: Vec<&String> = subject.src.iter().collect();
                all.extend(subject.dst.iter());
                self.address_truth(&all)
            }
            Field::Source => self.address_truth(&subject.src.iter().collect::<Vec<_>>()),
            Field::Destination => self.address_truth(&subject.dst.iter().collect::<Vec<_>>()),
            Field::AnyPort => {
                let mut all = subject.src_ports.clone();
                all.extend(subject.dst_ports.iter());
                self.port_truth(&all)
            }
            Field::SourcePort => self.port_truth(&subject.src_ports),
            Field::DestinationPort => self.port_truth(&subject.dst_ports),
            Field::Protocol => match &subject.protocol {
                Some(protocol) => {
                    let same = protocol.to_lowercase() == self.value.trim();
                    yes_no(if self.negate { !same } else { same })
                }
                None => Truth::Unknown,
            },
            // Length, seconds, the summary line, a TCP flag, truncation: all
            // properties of one packet. A conversation has many and a finding
            // has none, so there is no answer to give.
            _ => Truth::Unknown,
        }
    }

    fn address_truth(&self, addresses: &[&String]) -> Truth {
        if addresses.is_empty() {
            return Truth::Unknown;
        }
        let needle = self.value.trim();
        let subnet = if self.op == Op::InSubnet {
            parse_cidr(needle)
        } else {
            None
        };
        let mut unknown = false;
        for address in addresses {
            let text = address.to_lowercase();
            let hit = match self.op {
                Op::InSubnet => match (subnet, parse_address(&text)) {
                    (Some((base, bits)), Some(addr)) => in_subnet(addr, base, bits),
                    // An address the core cannot parse cannot be placed in or
                    // out of a subnet, and guessing either way would be a
                    // claim the capture does not support.
                    _ => {
                        unknown = true;
                        continue;
                    }
                },
                Op::Contains => text.contains(needle),
                _ => text == needle || parse_address(needle).is_some_and(|a| Some(a) == parse_address(&text)),
            };
            if hit {
                return yes_no(!self.negate);
            }
        }
        if unknown {
            return Truth::Unknown;
        }
        // Negated and nothing matched means every end is something else,
        // which is what "not this address" is asked to mean.
        yes_no(self.negate)
    }

    fn port_truth(&self, ports: &[u16]) -> Truth {
        // Zero is how the core says "no port here" - ARP and ICMP have none.
        // That is not a port that fails the test, it is the absence of one,
        // so there is nothing to answer.
        let real: Vec<u16> = ports.iter().copied().filter(|p| *p != 0).collect();
        if real.is_empty() {
            return Truth::Unknown;
        }
        let any = real.iter().any(|p| self.port(*p));
        yes_no(if self.negate { !any } else { any })
    }
}

fn yes_no(value: bool) -> Truth {
    if value {
        Truth::Yes
    } else {
        Truth::No
    }
}

/// Resolve an address condition against every address this capture holds.
fn compile_addresses(index: &PacketIndex, op: Op, value: &str) -> Vec<bool> {
    let needle = value.trim().to_lowercase();
    let subnet = if op == Op::InSubnet {
        parse_cidr(&needle)
    } else {
        None
    };
    index
        .addresses()
        .iter()
        .map(|addr| {
            let text = addr.to_string().to_lowercase();
            match op {
                Op::InSubnet => subnet.is_some_and(|(base, bits)| in_subnet(*addr, base, bits)),
                Op::Contains => text.contains(&needle),
                _ => text == needle || parse_address(&needle).is_some_and(|a| a == *addr),
            }
        })
        .collect()
}

/// `10.4.0.0/16`, or an IPv6 prefix.
pub fn parse_cidr(text: &str) -> Option<(Addr, u8)> {
    let (addr, bits) = text.split_once('/')?;
    let addr = parse_address(addr.trim())?;
    let bits: u8 = bits.trim().parse().ok()?;
    let max = match addr {
        Addr::V4(_) => 32,
        Addr::V6(_) => 128,
    };
    if bits > max {
        return None;
    }
    Some((addr, bits))
}

pub fn in_subnet(addr: Addr, base: Addr, bits: u8) -> bool {
    let (a, b): (&[u8], &[u8]) = match (&addr, &base) {
        (Addr::V4(a), Addr::V4(b)) => (a, b),
        (Addr::V6(a), Addr::V6(b)) => (a, b),
        // An IPv4 address is not inside an IPv6 prefix, and saying so is
        // better than quietly matching nothing for a different reason.
        _ => return false,
    };
    let whole = (bits / 8) as usize;
    if a[..whole] != b[..whole] {
        return false;
    }
    let spare = bits % 8;
    if spare == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - spare);
    a[whole] & mask == b[whole] & mask
}

/// Parse a written address. IPv6 is accepted in full or with one `::`,
/// because that is how people type it.
pub fn parse_address(text: &str) -> Option<Addr> {
    let text = text.trim();
    if text.contains(':') {
        return parse_v6(text);
    }
    let mut octets = [0u8; 4];
    let mut seen = 0;
    for part in text.split('.') {
        if seen == 4 {
            return None;
        }
        octets[seen] = part.parse().ok()?;
        seen += 1;
    }
    if seen != 4 {
        return None;
    }
    Some(Addr::V4(octets))
}

fn parse_v6(text: &str) -> Option<Addr> {
    let (head, tail) = match text.split_once("::") {
        Some((head, tail)) => (head, Some(tail)),
        None => (text, None),
    };

    let parse_groups = |s: &str| -> Option<Vec<u16>> {
        if s.is_empty() {
            return Some(Vec::new());
        }
        s.split(':')
            .map(|g| u16::from_str_radix(g, 16).ok())
            .collect()
    };

    let head = parse_groups(head)?;
    let tail = match tail {
        Some(tail) => parse_groups(tail)?,
        None => Vec::new(),
    };

    let total = head.len() + tail.len();
    if total > 8 {
        return None;
    }
    // Without a "::" every group must be written out.
    if text.find("::").is_none() && total != 8 {
        return None;
    }

    let mut groups = [0u16; 8];
    groups[..head.len()].copy_from_slice(&head);
    groups[8 - tail.len()..].copy_from_slice(&tail);

    let mut out = [0u8; 16];
    for (i, group) in groups.iter().enumerate() {
        out[i * 2] = (group >> 8) as u8;
        out[i * 2 + 1] = *group as u8;
    }
    Some(Addr::V6(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_an_address_written_the_way_people_write_it() {
        assert_eq!(parse_address("10.4.12.88"), Some(Addr::V4([10, 4, 12, 88])));
        assert_eq!(parse_address("10.4.12"), None);
        assert_eq!(parse_address("10.4.12.256"), None);

        let loopback = parse_address("::1").unwrap();
        match loopback {
            Addr::V6(b) => {
                assert_eq!(b[15], 1);
                assert_eq!(b[..15], [0u8; 15]);
            }
            other => panic!("expected IPv6, got {other:?}"),
        }
        assert!(parse_address("fe80::1").is_some());
        assert!(parse_address("2001:db8:0:0:0:0:0:1").is_some());
        // Without a "::" every group has to be there.
        assert_eq!(parse_address("2001:db8:1"), None);
    }

    #[test]
    fn a_subnet_holds_the_addresses_inside_it_and_no_others() {
        let (base, bits) = parse_cidr("10.4.0.0/16").unwrap();
        assert!(in_subnet(Addr::V4([10, 4, 12, 88]), base, bits));
        assert!(in_subnet(Addr::V4([10, 4, 255, 1]), base, bits));
        assert!(!in_subnet(Addr::V4([10, 5, 0, 1]), base, bits));

        // A prefix that does not land on a byte boundary is the one that
        // catches a lazy implementation.
        let (base, bits) = parse_cidr("192.168.1.128/25").unwrap();
        assert!(in_subnet(Addr::V4([192, 168, 1, 200]), base, bits));
        assert!(!in_subnet(Addr::V4([192, 168, 1, 100]), base, bits));

        // Mixing families matches nothing rather than panicking.
        let (v6, bits6) = parse_cidr("2001:db8::/32").unwrap();
        assert!(!in_subnet(Addr::V4([10, 0, 0, 1]), v6, bits6));
        assert!(in_subnet(parse_address("2001:db8::5").unwrap(), v6, bits6));
    }

    #[test]
    fn a_filter_that_cannot_be_read_narrows_nothing() {
        let index = PacketIndex::default();
        let filter = Filter::parse("nonsense\nC\tnot_a_field\tis\tx\t0\n", &index);
        assert!(filter.is_empty());
    }
}

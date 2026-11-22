// Wireshark display filter syntax, parsed into the filter the core already
// understands.
//
// Why accept it at all, in a tool whose point is that you should not need to
// know a query language: because the people most likely to be handed this app
// are the ones who already have Wireshark muscle memory, and making them learn
// a second syntax to do the thing they can already type is a tax for no gain.
// The builder stays the way in for everyone else. Neither is the "real" one.
//
// What this does NOT do is pretend to be Wireshark. It supports the fields
// AtherNet actually dissects and says plainly when a filter asks for one it
// does not, rather than silently matching nothing - a filter that quietly
// returns an empty list is the single most expensive failure mode a packet
// tool has, because an empty list is also a real answer.
//
// The output is a `Filter` from ./filter, which is the same structure the
// builder produces and the same line format crates/athernet-core/src/filter.rs
// reads. So the packet list gets display-filter support for free, and there is
// exactly one matching implementation rather than two that can disagree.

import type { FieldId, Filter, OpId } from './filter';
import type { Conversation, Finding } from './report';

/** One comparison, after negation has been pushed down to the leaves. */
export interface Leaf {
  field: FieldId;
  op: OpId;
  value: string;
  negate: boolean;
}

/**
 * Disjunctive normal form: OR of ANDs.
 *
 * This is not an optimisation, it is what makes the whole thing fit. The core
 * filter is two levels deep on purpose - groups combine one way, conditions
 * inside a group the other - and every boolean expression can be written that
 * way. So an arbitrarily nested display filter still lands in the structure
 * the builder shows, which means a typed filter can be opened in the builder
 * and read back as a sentence.
 */
export type Dnf = Leaf[][];

export interface ParsedFilter {
  dnf: Dnf;
  /** The text this came from, for round-tripping into the builder. */
  source: string;
}

export type ParseOutcome =
  | { kind: 'empty' }
  | { kind: 'filter'; parsed: ParsedFilter }
  /** Not display-filter syntax at all. The caller falls back to a word search. */
  | { kind: 'text' }
  /** Recognised as a filter, but wrong. Worth saying out loud. */
  | { kind: 'error'; message: string };

// --------------------------------------------------------------- the fields

/**
 * Protocol labels are exclusive in the core: a DNS packet is labelled DNS, not
 * UDP. Wireshark's are cumulative - `udp` there matches DNS too, because DNS
 * rides on UDP. Expanding to the set a user means keeps that expectation,
 * which matters more than matching our own internal naming.
 */
const PROTOCOL_SETS: Record<string, string[]> = {
  tcp: ['TCP', 'TLS'],
  udp: ['UDP', 'DNS', 'DHCP'],
  ip: ['TCP', 'UDP', 'DNS', 'DHCP', 'TLS', 'ICMP', 'IP'],
  ipv4: ['TCP', 'UDP', 'DNS', 'DHCP', 'TLS', 'ICMP', 'IP'],
  ipv6: ['TCP', 'UDP', 'DNS', 'DHCP', 'TLS', 'ICMP', 'IP'],
  dns: ['DNS'],
  dhcp: ['DHCP'],
  bootp: ['DHCP'],
  tls: ['TLS'],
  ssl: ['TLS'],
  icmp: ['ICMP'],
  arp: ['ARP'],
};

/** Fields we dissect, by every spelling worth accepting. */
const FIELD_ALIASES: Record<string, FieldId> = {
  'ip.addr': 'any_addr',
  'ipv6.addr': 'any_addr',
  'eth.addr': 'any_addr',
  addr: 'any_addr',
  address: 'any_addr',
  'ip.src': 'src',
  'ipv6.src': 'src',
  src: 'src',
  source: 'src',
  'ip.dst': 'dst',
  'ipv6.dst': 'dst',
  dst: 'dst',
  destination: 'dst',
  'tcp.port': 'any_port',
  'udp.port': 'any_port',
  port: 'any_port',
  'tcp.srcport': 'src_port',
  'udp.srcport': 'src_port',
  srcport: 'src_port',
  'tcp.dstport': 'dst_port',
  'udp.dstport': 'dst_port',
  dstport: 'dst_port',
  'frame.len': 'length',
  'ip.len': 'length',
  len: 'length',
  length: 'length',
  'frame.time_relative': 'seconds',
  time: 'seconds',
  'frame.protocols': 'protocol',
  proto: 'protocol',
  protocol: 'protocol',
  '_ws.col.info': 'summary',
  info: 'summary',
  summary: 'summary',
};

/**
 * A port field spelled `tcp.port` means a TCP port, not "either protocol's".
 * Carrying that constraint is the difference between `tcp.port == 53` meaning
 * what it says and quietly including every DNS lookup.
 */
const PORT_PROTOCOL: Record<string, string[]> = {
  'tcp.port': PROTOCOL_SETS.tcp,
  'tcp.srcport': PROTOCOL_SETS.tcp,
  'tcp.dstport': PROTOCOL_SETS.tcp,
  'udp.port': PROTOCOL_SETS.udp,
  'udp.srcport': PROTOCOL_SETS.udp,
  'udp.dstport': PROTOCOL_SETS.udp,
};

const FLAG_FIELDS: Record<string, string> = {
  'tcp.flags.syn': 'SYN',
  'tcp.flags.ack': 'ACK',
  'tcp.flags.reset': 'RST',
  'tcp.flags.rst': 'RST',
  'tcp.flags.fin': 'FIN',
  'tcp.flags.push': 'PSH',
  'tcp.flags.psh': 'PSH',
  'tcp.flags.urg': 'URG',
};

/**
 * Protocols Wireshark knows and we do not. Named individually so the message
 * can say which one, because "unknown field" sends somebody hunting for a typo
 * that is not there. These are real gaps in the dissector, not syntax errors.
 */
const NOT_DISSECTED = new Set([
  'http', 'http2', 'https', 'ssh', 'ftp', 'smtp', 'imap', 'pop', 'snmp', 'sip',
  'rtp', 'smb', 'smb2', 'ldap', 'kerberos', 'ntp', 'quic', 'mdns', 'nbns',
  'llmnr', 'stp', 'cdp', 'lldp', 'vlan', 'gre', 'ospf', 'bgp', 'rip',
]);

// ------------------------------------------------------------- the tokeniser

type Token =
  | { t: 'id'; v: string }
  | { t: 'value'; v: string }
  | { t: 'op'; v: string }
  | { t: 'and' }
  | { t: 'or' }
  | { t: 'not' }
  | { t: '(' }
  | { t: ')' };

class ParseError extends Error {}

const COMPARATORS: Record<string, OpId | 'ne' | 'ge' | 'le'> = {
  '==': 'is',
  eq: 'is',
  '!=': 'ne',
  ne: 'ne',
  '>': 'gt',
  gt: 'gt',
  '<': 'lt',
  lt: 'lt',
  '>=': 'ge',
  ge: 'ge',
  '<=': 'le',
  le: 'le',
  contains: 'contains',
  matches: 'contains',
  in: 'in',
};

function tokenise(input: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < input.length) {
    const c = input[i];
    if (/\s/.test(c)) {
      i += 1;
      continue;
    }
    if (c === '(') {
      out.push({ t: '(' });
      i += 1;
      continue;
    }
    if (c === ')') {
      out.push({ t: ')' });
      i += 1;
      continue;
    }
    if (c === '"' || c === "'") {
      const end = input.indexOf(c, i + 1);
      if (end === -1) throw new ParseError('A quote is left open.');
      out.push({ t: 'value', v: input.slice(i + 1, end) });
      i = end + 1;
      continue;
    }
    // Two-character comparators first, so >= is never read as > then =.
    const pair = input.slice(i, i + 2);
    if (pair === '&&') {
      out.push({ t: 'and' });
      i += 2;
      continue;
    }
    if (pair === '||') {
      out.push({ t: 'or' });
      i += 2;
      continue;
    }
    if (pair === '==' || pair === '!=' || pair === '>=' || pair === '<=') {
      out.push({ t: 'op', v: pair });
      i += 2;
      continue;
    }
    if (c === '!') {
      out.push({ t: 'not' });
      i += 1;
      continue;
    }
    if (c === '>' || c === '<' || c === '=') {
      // A lone `=` is Wireshark-legal in some builds and harmless to accept.
      out.push({ t: 'op', v: c === '=' ? '==' : c });
      i += 1;
      continue;
    }
    // A bareword: field names, protocol names, addresses, numbers, CIDRs.
    const word = /^[A-Za-z0-9_.:/%-]+/.exec(input.slice(i));
    if (!word) throw new ParseError(`"${c}" is not something a filter can contain.`);
    const v = word[0];
    const lower = v.toLowerCase();
    if (lower === 'and') out.push({ t: 'and' });
    else if (lower === 'or') out.push({ t: 'or' });
    else if (lower === 'not') out.push({ t: 'not' });
    else if (lower in COMPARATORS && !/^[0-9]/.test(v)) out.push({ t: 'op', v: lower });
    else out.push({ t: 'id', v });
    i += v.length;
  }
  return out;
}

// ----------------------------------------------------------------- the parse

type Ast =
  | { k: 'and'; l: Ast; r: Ast }
  | { k: 'or'; l: Ast; r: Ast }
  | { k: 'not'; n: Ast }
  | { k: 'leaf'; leaf: Leaf };

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV4_CIDR = /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/;
const looksLikeIpv6 = (s: string) => s.includes(':') && /^[0-9A-Fa-f:.%/]+$/.test(s);

const isAddressy = (s: string) =>
  IPV4.test(s) || IPV4_CIDR.test(s) || (looksLikeIpv6(s) && s.split(':').length > 2);

class Parser {
  private at = 0;

  constructor(private readonly tokens: Token[]) {}

  parse(): Ast {
    const node = this.or();
    if (this.at < this.tokens.length) {
      throw new ParseError('There is something after the end of the filter.');
    }
    return node;
  }

  private peek(): Token | undefined {
    return this.tokens[this.at];
  }

  private or(): Ast {
    let left = this.and();
    while (this.peek()?.t === 'or') {
      this.at += 1;
      left = { k: 'or', l: left, r: this.and() };
    }
    return left;
  }

  private and(): Ast {
    let left = this.unary();
    for (;;) {
      const next = this.peek();
      if (next?.t === 'and') {
        this.at += 1;
        left = { k: 'and', l: left, r: this.unary() };
        continue;
      }
      // Wireshark lets you juxtapose terms with no operator in a few places.
      // Treating a run of bare terms as "and" is what people expect when they
      // type `tcp 10.0.0.1`, and it never changes the meaning of a filter that
      // did spell the operator out.
      if (next?.t === 'id' || next?.t === '(' || next?.t === 'not') {
        left = { k: 'and', l: left, r: this.unary() };
        continue;
      }
      return left;
    }
  }

  private unary(): Ast {
    const next = this.peek();
    if (next?.t === 'not') {
      this.at += 1;
      return { k: 'not', n: this.unary() };
    }
    if (next?.t === '(') {
      this.at += 1;
      const inner = this.or();
      if (this.peek()?.t !== ')') throw new ParseError('A bracket is left open.');
      this.at += 1;
      return inner;
    }
    return this.comparison();
  }

  private comparison(): Ast {
    const head = this.peek();
    if (head?.t !== 'id') throw new ParseError('A filter has to start with a field or a protocol.');
    this.at += 1;
    const name = head.v;
    const lower = name.toLowerCase();

    const next = this.peek();
    if (next?.t === 'op') {
      this.at += 1;
      const valueToken = this.peek();
      if (valueToken?.t !== 'id' && valueToken?.t !== 'value') {
        throw new ParseError(`${name} ${next.v} what? The comparison has no value.`);
      }
      this.at += 1;
      return this.compare(name, next.v, valueToken.v);
    }

    // A bare term: a protocol name, an address, or a flag used as a truth test.
    if (lower in FLAG_FIELDS) return flagLeaf(FLAG_FIELDS[lower], false);
    if (lower in PROTOCOL_SETS) return protocolAst(PROTOCOL_SETS[lower], false);
    if (NOT_DISSECTED.has(lower)) {
      throw new ParseError(
        `AtherNet does not dissect ${lower}, so it cannot filter on it. It reads Ethernet, ARP, IP, TCP, UDP, ICMP, DNS, DHCP and TLS.`,
      );
    }
    if (isAddressy(name)) {
      return {
        k: 'leaf',
        leaf: { field: 'any_addr', op: name.includes('/') ? 'in' : 'is', value: name, negate: false },
      };
    }
    if (lower in FIELD_ALIASES) {
      throw new ParseError(`${name} needs something to compare against, like ${name} == 10.0.0.1.`);
    }
    throw new ParseError(`"${name}" is not a field AtherNet knows.`);
  }

  private compare(name: string, comparator: string, raw: string): Ast {
    const lower = name.toLowerCase();
    const cmp = COMPARATORS[comparator];
    if (!cmp) throw new ParseError(`"${comparator}" is not a comparison.`);
    const negate = cmp === 'ne';

    if (lower in FLAG_FIELDS) {
      const on = raw !== '0' && raw.toLowerCase() !== 'false';
      return flagLeaf(FLAG_FIELDS[lower], negate ? on : !on);
    }

    if (NOT_DISSECTED.has(lower.split('.')[0])) {
      throw new ParseError(
        `AtherNet does not dissect ${lower.split('.')[0]}, so it cannot filter on ${name}.`,
      );
    }

    const field = FIELD_ALIASES[lower];
    if (!field) throw new ParseError(`"${name}" is not a field AtherNet knows.`);

    // `>=` and `<=` have no core operator. Rather than add two that only this
    // parser would ever emit, they are written as the strict comparison on the
    // neighbouring integer, which is exact for ports and byte counts.
    let op: OpId;
    let value = raw;
    if (cmp === 'ge' || cmp === 'le') {
      const n = Number(raw);
      if (!Number.isFinite(n)) throw new ParseError(`${name} ${comparator} ${raw} is not a number.`);
      op = cmp === 'ge' ? 'gt' : 'lt';
      value = String(cmp === 'ge' ? n - 1 : n + 1);
    } else if (cmp === 'ne') {
      op = 'is';
    } else {
      op = cmp as OpId;
    }

    if (field === 'protocol' && op === 'is') {
      const set = PROTOCOL_SETS[value.toLowerCase()];
      if (set) return protocolAst(set, negate);
    }

    // An address compared against a CIDR is a subnet test whichever operator
    // was typed: `ip.addr == 10.0.0.0/8` is what everybody writes, and reading
    // it as a string comparison would match nothing at all.
    if ((field === 'any_addr' || field === 'src' || field === 'dst') && value.includes('/') && op === 'is') {
      op = 'in';
    }

    const leaf: Ast = { k: 'leaf', leaf: { field, op, value, negate } };

    const constraint = PORT_PROTOCOL[lower];
    if (constraint) return { k: 'and', l: leaf, r: protocolAst(constraint, false) };
    return leaf;
  }
}

function flagLeaf(flag: string, negate: boolean): Ast {
  return { k: 'leaf', leaf: { field: 'flag', op: 'has', value: flag, negate } };
}

/** A protocol set is an OR of equalities; negating it is an AND of inequalities. */
function protocolAst(set: string[], negate: boolean): Ast {
  const leaves: Ast[] = set.map((p) => ({
    k: 'leaf' as const,
    leaf: { field: 'protocol' as FieldId, op: 'is' as OpId, value: p, negate },
  }));
  return leaves.reduce((l, r) => ({ k: negate ? 'and' : 'or', l, r }));
}

// ------------------------------------------------------ negation and the DNF

/** De Morgan, down to the leaves, so the DNF below only ever sees and/or. */
function pushNot(node: Ast, negated: boolean): Ast {
  switch (node.k) {
    case 'not':
      return pushNot(node.n, !negated);
    case 'and':
      return negated
        ? { k: 'or', l: pushNot(node.l, true), r: pushNot(node.r, true) }
        : { k: 'and', l: pushNot(node.l, false), r: pushNot(node.r, false) };
    case 'or':
      return negated
        ? { k: 'and', l: pushNot(node.l, true), r: pushNot(node.r, true) }
        : { k: 'or', l: pushNot(node.l, false), r: pushNot(node.r, false) };
    case 'leaf':
      return negated
        ? { k: 'leaf', leaf: { ...node.leaf, negate: !node.leaf.negate } }
        : node;
  }
}

/** Past this, the filter has stopped being something a person reads back. */
const MAX_GROUPS = 64;

function toDnf(node: Ast): Dnf {
  switch (node.k) {
    case 'leaf':
      return [[node.leaf]];
    case 'or':
      return [...toDnf(node.l), ...toDnf(node.r)];
    case 'and': {
      const left = toDnf(node.l);
      const right = toDnf(node.r);
      if (left.length * right.length > MAX_GROUPS) {
        throw new ParseError('That filter has too many alternatives to show. Try splitting it.');
      }
      return left.flatMap((a) => right.map((b) => [...a, ...b]));
    }
    case 'not':
      // pushNot has already run; a `not` here would be a bug in this file.
      throw new ParseError('The filter could not be rearranged.');
  }
}

// ------------------------------------------------------------- the front door

/**
 * Does this look like someone meant a filter, rather than words to search for?
 *
 * Deliberately generous about punctuation and strict about words. Anything
 * holding a comparator or a bracket was typed as a filter, and if it is
 * malformed the person wants to hear that - falling back to a word search
 * would hide the mistake behind an empty list. A line of ordinary words, on
 * the other hand, is a search, and has been since before this parser existed.
 */
function looksDeliberate(text: string): boolean {
  if (/[=<>!()]|&&|\|\|/.test(text)) return true;
  const words = text.trim().split(/\s+/);
  return words.every((word) => {
    const w = word.toLowerCase();
    return (
      w in PROTOCOL_SETS ||
      w in FLAG_FIELDS ||
      w in FIELD_ALIASES ||
      w in COMPARATORS ||
      NOT_DISSECTED.has(w) ||
      isAddressy(word) ||
      w === 'and' ||
      w === 'or' ||
      w === 'not'
    );
  });
}

/**
 * Parse, or say why not.
 *
 * The `text` outcome is the important one: plain words typed into the box are
 * not a broken filter, they are a word search, and the box has always done
 * that. Only something that was clearly meant as a filter gets an error.
 */
export function parseDisplayFilter(text: string): ParseOutcome {
  const trimmed = text.trim();
  if (!trimmed) return { kind: 'empty' };
  if (!looksDeliberate(trimmed)) return { kind: 'text' };
  try {
    const ast = pushNot(new Parser(tokenise(trimmed)).parse(), false);
    const dnf = toDnf(ast);
    if (dnf.length === 0 || dnf.every((g) => g.length === 0)) return { kind: 'text' };
    return { kind: 'filter', parsed: { dnf, source: trimmed } };
  } catch (e) {
    if (e instanceof ParseError) return { kind: 'error', message: e.message };
    return { kind: 'error', message: 'That filter could not be read.' };
  }
}

/**
 * A builder filter, read back as a DNF.
 *
 * Needed because the two ways of asking a question have to be able to hold
 * each other: a capture-wide filter typed in the bar and a refinement built in
 * the packets tab are both true at once, and combining them means putting both
 * in the same form first. A group that matches *any* of its conditions is a
 * disjunction, so it becomes one conjunct per condition.
 */
export function dnfOfFilter(filter: Filter): Dnf {
  const groups: Dnf[] = [];
  for (const group of filter.groups) {
    const conditions = group.conditions.filter((c) => c.value.trim() !== '');
    if (conditions.length === 0) continue;
    const leaves: Leaf[] = conditions.map((c) => ({
      field: c.field,
      op: c.op,
      value: c.value.trim(),
      negate: c.negate,
    }));
    groups.push(group.matchAll ? [leaves] : leaves.map((leaf) => [leaf]));
  }
  if (groups.length === 0) return [];
  return filter.matchAll ? groups.reduce(andDnf) : groups.flat();
}

/** Both filters at once. Empty means "no filter", so it never narrows anything. */
export function andDnf(a: Dnf, b: Dnf): Dnf {
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  if (a.length * b.length > MAX_GROUPS) {
    // Rather than refuse, keep the one the person is looking at. The packets
    // tab says which filters are in force, so this cannot pass unnoticed.
    return a;
  }
  return a.flatMap((x) => b.map((y) => [...x, ...y]));
}

/** The DNF as the structure the builder edits and the core matches. */
export function toFilter(parsed: ParsedFilter): Filter {
  return {
    matchAll: false,
    groups: parsed.dnf.map((conjunct, i) => ({
      key: `df${i}`,
      matchAll: true,
      conditions: conjunct.map((leaf, j) => ({
        key: `df${i}-${j}`,
        field: leaf.field,
        op: leaf.op,
        value: leaf.value,
        negate: leaf.negate,
      })),
    })),
  };
}

// --------------------------------------------------- matching what we can see

/**
 * Three-valued, and that is the whole point.
 *
 * The packet list can answer any of these, because it has the packets. The map
 * and the issues list cannot: a conversation has no per-packet length, and a
 * finding has no TCP flags. Collapsing "I cannot tell" into "no" would quietly
 * empty the map whenever somebody filtered on something it does not hold,
 * which is exactly the lie this app exists to avoid. So unknown stays unknown,
 * the view keeps what it cannot rule out, and it says that it did.
 */
export type Truth = true | false | 'unknown';

function and(a: Truth, b: Truth): Truth {
  if (a === false || b === false) return false;
  if (a === 'unknown' || b === 'unknown') return 'unknown';
  return true;
}

function or(a: Truth, b: Truth): Truth {
  if (a === true || b === true) return true;
  if (a === 'unknown' || b === 'unknown') return 'unknown';
  return false;
}

function evaluate(dnf: Dnf, leafTest: (leaf: Leaf) => Truth): Truth {
  return dnf
    .map((conjunct) => conjunct.map(leafTest).reduce(and, true as Truth))
    .reduce(or, false as Truth);
}

const ipv4ToInt = (s: string): number | null => {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    const b = Number(part);
    if (!Number.isInteger(b) || b < 0 || b > 255) return null;
    n = n * 256 + b;
  }
  return n;
};

/** IPv4 only. An IPv6 subnet test is left to the core, which has a real one. */
function inSubnet(address: string, cidr: string): Truth {
  const [net, bitsText] = cidr.split('/');
  const bits = Number(bitsText);
  const a = ipv4ToInt(address);
  const n = ipv4ToInt(net);
  if (a === null || n === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return 'unknown';
  if (bits === 0) return true;
  const mask = bits === 32 ? -1 : ~(2 ** (32 - bits) - 1);
  return (a & mask) === (n & mask);
}

function testAddress(leaf: Leaf, addresses: string[]): Truth {
  if (addresses.length === 0) return 'unknown';
  let hit: Truth = false;
  for (const address of addresses) {
    let one: Truth;
    if (leaf.op === 'in') one = inSubnet(address, leaf.value);
    else if (leaf.op === 'contains') one = address.includes(leaf.value);
    else one = address.toLowerCase() === leaf.value.toLowerCase();
    if (one === true) return leaf.negate ? false : true;
    if (one === 'unknown') hit = 'unknown';
  }
  // Negation here means "neither end is this", which is what people mean and
  // not what Wireshark's `ip.addr != x` actually does - there it means "some
  // field differs", so it is true for nearly every packet. Matching the
  // intention beats matching the footgun.
  if (hit === 'unknown') return 'unknown';
  return leaf.negate ? true : false;
}

function testNumber(leaf: Leaf, values: number[]): Truth {
  if (values.length === 0) return 'unknown';
  const want = Number(leaf.value);
  if (!Number.isFinite(want)) return 'unknown';
  const any = values.some((v) =>
    leaf.op === 'gt' ? v > want : leaf.op === 'lt' ? v < want : v === want,
  );
  return leaf.negate ? !any : any;
}

/** What a conversation can answer about itself. */
export function conversationTruth(parsed: ParsedFilter, c: Conversation): Truth {
  return evaluate(parsed.dnf, (leaf) => {
    switch (leaf.field) {
      case 'any_addr':
        return testAddress(leaf, [c.a, c.b]);
      case 'src':
        return testAddress(leaf, [c.a]);
      case 'dst':
        return testAddress(leaf, [c.b]);
      case 'any_port':
        return testNumber(leaf, [c.aPort, c.bPort]);
      case 'src_port':
        return testNumber(leaf, [c.aPort]);
      case 'dst_port':
        return testNumber(leaf, [c.bPort]);
      case 'protocol': {
        const same = c.protocol.toLowerCase() === leaf.value.toLowerCase();
        return leaf.negate ? !same : same;
      }
      default:
        // length, seconds, summary, flag, truncated: per packet, not per
        // conversation. The map cannot answer and does not guess.
        return 'unknown';
    }
  });
}

/**
 * A conversation runs in both directions, so "source" and "destination" are
 * labels for which end opened it, not a claim about any one packet. A filter
 * naming one side is honoured as written; `ip.addr` covers both.
 */
export function findingTruth(parsed: ParsedFilter, finding: Finding): Truth {
  const addresses: string[] = [];
  const ports: number[] = [];
  for (const endpoint of finding.endpoints) {
    // "10.0.0.1:443", or a bare address, or an IPv6 address which is all
    // colons and must not be split on the last one unless a port follows.
    const match = /^(.*?):(\d+)$/.exec(endpoint);
    if (match && (!endpoint.includes('::') || match[1].endsWith(']'))) {
      addresses.push(match[1].replace(/^\[|\]$/g, ''));
      ports.push(Number(match[2]));
    } else {
      addresses.push(endpoint);
    }
  }
  return evaluate(parsed.dnf, (leaf) => {
    switch (leaf.field) {
      case 'any_addr':
      case 'src':
      case 'dst':
        return testAddress(leaf, addresses);
      case 'any_port':
      case 'src_port':
      case 'dst_port':
        return testNumber(leaf, ports);
      default:
        return 'unknown';
    }
  });
}

/** True when any term in the filter is one the view above could not decide. */
export function hasUndecidable(parsed: ParsedFilter, decidable: Set<FieldId>): boolean {
  return parsed.dnf.some((conjunct) => conjunct.some((leaf) => !decidable.has(leaf.field)));
}

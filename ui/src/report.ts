// The shape of an analysed capture, and the small helpers that render it.
//
// Every type here has a counterpart in crates/athernet-core/src/report.rs,
// which is the only place a report is produced. Nothing in this file is
// sample data: the captures on screen are always the output of the real core
// over a real file, the examples included.

import exampleData from './example-captures.json';

export type Severity = 'error' | 'warning' | 'info';
export type Confidence = 'confirmed' | 'suspected' | 'incomplete';

export interface Evidence {
  file: string;
  /** Packet index within its file, counting from zero. */
  frame: number;
  /** Byte offset of the packet in the original file. */
  offset: number;
  note: string;
}

export interface Finding {
  id: string;
  kind: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  what: string;
  endpoints: string[];
  at: string;
  atUnixMs: number;
  /** Packet this finding starts at, for jumping to it in the explorer. */
  firstPacket: number;
  evidence: Evidence[];
  /** Why the confidence is not higher. Empty when the finding is confirmed. */
  limits: string[];
  nextChecks: string[];
}

export interface Binding {
  address: string;
  mac: string;
  evidence: string;
  strength: string;
  firstPacket: number;
  observations: number;
  firstSeenUnixMs: number;
  lastSeenUnixMs: number;
  /** "a device on this network" or "a way out of this network". */
  role: string;
  /** How many source addresses were seen behind that hardware address. */
  addressesBehindMac: number;
  macPackets: number;
}

export interface NextHop {
  mac: string;
  addresses: number;
  /** True when more addresses were seen than the app keeps. */
  capped: boolean;
  packets: number;
}

export interface Conversation {
  /** Doubles as its identity, and as the handle the explorer filters by. */
  firstPacket: number;
  protocol: string;
  a: string;
  aPort: number;
  b: string;
  bPort: number;
  packets: number;
  bytes: number;
  startUnixMs: number;
  durationSeconds: number;
  outcome: string;
  confidence: string;
}

export interface Capture {
  id: string;
  file: string;
  /** Fixture metadata. A capture someone drops in will not have one. */
  description?: string;
  packets: number;
  bytes: number;
  wireBytes: number;
  durationSeconds: number;
  startedAtUnixMs: number;
  linkType: string;
  snaplen: number;
  reportedDrops: number;
  /**
   * The file has no way of recording drops, which classic pcap does not.
   * Not the same as "nothing was dropped", and the dashboard says which.
   */
  dropsUnknown: boolean;
  truncatedPackets: number;
  protocols: { tcp: number; udp: number; icmp: number; arp: number; other: number };
  /** Packets per bucket, for the traffic strip. */
  timeline: number[];
  /** How much time one bucket covers, so the strip is not mislabelled. */
  timelineBucketMs: number;
  conversationCount: number;
  conversations: Conversation[];
  indexedPackets: number;
  /** True when the capture outran the packet index and the explorer is capped. */
  packetIndexCapped: boolean;
  findings: Finding[];
  bindings: Binding[];
  /** Hardware addresses that carried traffic for several addresses. */
  nextHops: NextHop[];
  /** Set when the file stopped partway through but what came before is good. */
  readError?: string;
}

export interface PacketRow {
  index: number;
  tsUnixMs: number;
  sinceStartSeconds: number;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  truncated: boolean;
  summary: string;
}

export interface PacketPage {
  start: number;
  /** How many packets the current filter selects, not how many are shown. */
  matching: number;
  indexed: number;
  seen: number;
  capped: boolean;
  rows: PacketRow[];
}

export interface PacketLayer {
  name: string;
  fields: { name: string; value: string }[];
}

export interface PacketDetail {
  index: number;
  tsUnixMs: number;
  offset: number;
  capturedLength: number;
  wireLength: number;
  truncated: boolean;
  summary: string;
  layers: PacketLayer[];
  /** The packet itself, as hex. */
  bytes: string;
}

export type PrivacyMode = 'local' | 'redacted' | 'full';

export interface AssistantCitation {
  kind: 'finding' | 'packet' | 'conversation';
  id: string;
  /** Checked against this capture before it is shown. */
  valid: boolean;
}

export interface AssistantStatement {
  text: string;
  citations: AssistantCitation[];
}

export interface AssistantReply {
  /** False when the question was not one the assistant can answer. */
  understood: boolean;
  mode: PrivacyMode;
  modeLabel: string;
  modeExplanation: string;
  /** "local-analysis" while no model is connected. */
  source: string;
  /** What the capture shows. */
  observations: AssistantStatement[];
  /** What might explain it, always as possibilities. */
  explanations: string[];
  /** What this capture cannot settle. */
  limits: string[];
  /** The exact text that would leave the machine in this mode. */
  evidencePack: string;
  redactions: { from: string; to: string }[];
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  error: 'Error',
  warning: 'Warning',
  info: 'For information',
};

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  confirmed: 'Confirmed',
  suspected: 'Suspected',
  incomplete: 'Incomplete evidence',
};

export const CONFIDENCE_HELP: Record<Confidence, string> = {
  confirmed: 'A packet in this capture states this outright.',
  suspected:
    'This fits what the capture shows, but the proof would be a packet that is not here, and there are other reasons a packet might be missing.',
  incomplete:
    'This capture cannot settle the question. What is missing is listed with the finding.',
};

/**
 * The project's own fixture captures, as files.
 *
 * They go through the same picker a dropped file goes through, so the
 * examples exercise the real reader rather than demonstrating a snapshot of
 * what it once produced.
 */
export function exampleFiles(): File[] {
  return (exampleData as { file: string; base64: string }[]).map(({ file, base64 }) => {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return new File([bytes], file);
  });
}

/**
 * Bytes at a scale a person reads without counting digits. The first version
 * of this screen always said kB, which looked fine against hand-written
 * sample numbers and said "39350.0 kB" the moment a real capture arrived.
 */
export function formatBytes(bytes: number): string {
  if (bytes < 1_000) return `${bytes} B`;
  if (bytes < 1_000_000) return `${(bytes / 1_000).toFixed(1)} kB`;
  if (bytes < 1_000_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  return `${(bytes / 1_000_000_000).toFixed(2)} GB`;
}

/** A span of seconds, in units that suit its size. */
export function formatDuration(seconds: number): string {
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 90) return `${seconds.toFixed(2)} s`;
  if (seconds < 5400) return `${(seconds / 60).toFixed(1)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

/** The clock in a capture file, as a local time someone can read. */
export function formatTime(unixMs: number): string {
  if (!unixMs) return 'no timestamp';
  return new Date(unixMs).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  });
}

/** Just the clock, for a packet list where every row shares the same date. */
export function formatClock(unixMs: number): string {
  if (!unixMs) return '-';
  return new Date(unixMs).toLocaleTimeString(undefined, { hour12: false });
}

/** A conversation in one line: "tcp 10.4.12.88:54322 <-> 10.4.30.15:445". */
export function conversationLabel(c: Conversation): string {
  if (c.aPort === 0 && c.bPort === 0) return `${c.protocol} ${c.a} <-> ${c.b}`;
  return `${c.protocol} ${c.a}:${c.aPort} <-> ${c.b}:${c.bPort}`;
}

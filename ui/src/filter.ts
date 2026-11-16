// The packet filter, as the builder edits it and as the core reads it.
//
// Two levels rather than a free tree: the filter matches all or any of its
// groups, and each group matches all or any of its conditions. That covers
// "(A and B) or (C and D)", which is what people write, and it stays legible
// on screen. A freely nested boolean tree is more expressive and, for someone
// who has never used a packet tool, unusable.
//
// The same shape exists in crates/athernet-core/src/filter.rs, which does the
// actual matching. `encode` below writes the line format it reads.

export type FieldId =
  | 'any_addr'
  | 'src'
  | 'dst'
  | 'any_port'
  | 'src_port'
  | 'dst_port'
  | 'protocol'
  | 'length'
  | 'seconds'
  | 'summary'
  | 'flag'
  | 'truncated';

export type OpId = 'is' | 'contains' | 'in' | 'gt' | 'lt' | 'has';

export interface Condition {
  /** Stable key for React, never sent to the core. */
  key: string;
  field: FieldId;
  op: OpId;
  value: string;
  negate: boolean;
}

export interface Group {
  key: string;
  matchAll: boolean;
  conditions: Condition[];
}

export interface Filter {
  matchAll: boolean;
  groups: Group[];
}

interface FieldSpec {
  id: FieldId;
  label: string;
  ops: OpId[];
  /** What goes in the value box. */
  placeholder: string;
  /** Fixed choices, where the field has them. */
  choices?: string[];
  hint?: string;
}

export const FIELDS: FieldSpec[] = [
  {
    id: 'any_addr',
    label: 'Address (either end)',
    ops: ['is', 'in', 'contains'],
    placeholder: '10.4.12.88 or 10.4.0.0/16',
    hint: 'Matches the source or the destination.',
  },
  { id: 'src', label: 'Source address', ops: ['is', 'in', 'contains'], placeholder: '10.4.12.88' },
  {
    id: 'dst',
    label: 'Destination address',
    ops: ['is', 'in', 'contains'],
    placeholder: '10.4.30.15',
  },
  {
    id: 'any_port',
    label: 'Port (either end)',
    ops: ['is', 'gt', 'lt'],
    placeholder: '443',
  },
  { id: 'src_port', label: 'Source port', ops: ['is', 'gt', 'lt'], placeholder: '54321' },
  { id: 'dst_port', label: 'Destination port', ops: ['is', 'gt', 'lt'], placeholder: '443' },
  {
    id: 'protocol',
    label: 'Protocol',
    ops: ['is'],
    placeholder: 'TCP',
    choices: ['TCP', 'UDP', 'DNS', 'DHCP', 'TLS', 'ICMP', 'ARP', 'IP', 'other'],
  },
  {
    id: 'flag',
    label: 'TCP flag',
    ops: ['has'],
    placeholder: 'SYN',
    choices: ['SYN', 'ACK', 'RST', 'FIN', 'PSH', 'URG'],
  },
  { id: 'length', label: 'Length in bytes', ops: ['gt', 'lt', 'is'], placeholder: '1000' },
  {
    id: 'seconds',
    label: 'Seconds into the capture',
    ops: ['gt', 'lt'],
    placeholder: '2.5',
  },
  {
    id: 'summary',
    label: 'What the packet says',
    ops: ['contains'],
    placeholder: 'NXDOMAIN',
    hint: 'Searches the line the packet list shows.',
  },
  {
    id: 'truncated',
    label: 'Cut short by the snaplen',
    ops: ['is'],
    placeholder: 'true',
    choices: ['true', 'false'],
  },
];

export const OP_LABEL: Record<OpId, string> = {
  is: 'is',
  contains: 'contains',
  in: 'is inside',
  gt: 'is more than',
  lt: 'is less than',
  has: 'includes',
};

/**
 * Negation has to be written per operator, not stuck on the front. Putting a
 * bare "not" before the operator gives "address not is inside 10.0.0.0/8",
 * which is the sort of line that makes a reader stop trusting the screen.
 */
const NEGATED_OP_LABEL: Record<OpId, string> = {
  is: 'is not',
  contains: 'does not contain',
  in: 'is not inside',
  gt: 'is not more than',
  lt: 'is not less than',
  has: 'does not include',
};

export const fieldSpec = (id: FieldId): FieldSpec => FIELDS.find((f) => f.id === id) ?? FIELDS[0];

let counter = 0;
const key = () => `k${(counter += 1)}`;

export function newCondition(field: FieldId = 'any_addr'): Condition {
  const spec = fieldSpec(field);
  return { key: key(), field, op: spec.ops[0], value: '', negate: false };
}

export function newGroup(matchAll = true): Group {
  return { key: key(), matchAll, conditions: [newCondition()] };
}

export const EMPTY_BUILDER: Filter = { matchAll: true, groups: [] };

/** Conditions with nothing typed in them are ignored rather than matching nothing. */
const usable = (c: Condition) => c.value.trim() !== '';

export function isEmpty(filter: Filter): boolean {
  return filter.groups.every((g) => g.conditions.filter(usable).length === 0);
}

export function conditionCount(filter: Filter): number {
  return filter.groups.reduce((n, g) => n + g.conditions.filter(usable).length, 0);
}

/**
 * Write the filter in the line format the core reads.
 *
 * Tabs and newlines are the format's own separators, so they are stripped
 * from values here. A value cannot contain either in practice - these are
 * addresses, ports and short words - and silently dropping them is better
 * than letting a stray character shift every field one along.
 */
export function encode(filter: Filter): string {
  const clean = (s: string) => s.replace(/[\t\r\n]/g, ' ').trim();
  const lines: string[] = [`F\t${filter.matchAll ? 'all' : 'any'}`];
  for (const group of filter.groups) {
    const conditions = group.conditions.filter(usable);
    if (conditions.length === 0) continue;
    lines.push(`G\t${group.matchAll ? 'all' : 'any'}`);
    for (const c of conditions) {
      lines.push(`C\t${c.field}\t${c.op}\t${clean(c.value)}\t${c.negate ? '1' : '0'}`);
    }
  }
  return lines.length > 1 ? lines.join('\n') : '';
}

/**
 * The filter as a sentence.
 *
 * Worth the code: a builder that shows only dropdowns leaves people unsure
 * what they have built, and this is the line they read back to check. It is
 * also what makes a saved filter recognisable a week later.
 */
export function describe(filter: Filter): string {
  const parts = filter.groups
    .map((group) => {
      const conditions = group.conditions.filter(usable).map(describeCondition);
      if (conditions.length === 0) return '';
      if (conditions.length === 1) return conditions[0];
      const joined = conditions.join(group.matchAll ? ' and ' : ' or ');
      return filter.groups.length > 1 ? `(${joined})` : joined;
    })
    .filter(Boolean);
  if (parts.length === 0) return 'Everything in the capture.';
  return `${parts.join(filter.matchAll ? ' and ' : ' or ')}.`;
}

function describeCondition(c: Condition): string {
  const spec = fieldSpec(c.field);
  const label = spec.label.toLowerCase();
  const value = c.value.trim();
  switch (c.field) {
    case 'truncated':
      return value === 'false' ? 'the packet is whole' : `the packet was ${c.negate ? 'not ' : ''}cut short`;
    case 'flag':
      return `${c.negate ? 'not ' : ''}flagged ${value.toUpperCase()}`;
    case 'summary':
      return `what it says does ${c.negate ? 'not ' : ''}contain "${value}"`;
    default:
      return `${label} ${c.negate ? NEGATED_OP_LABEL[c.op] : OP_LABEL[c.op]} ${value}`;
  }
}

// ------------------------------------------------------------ saved filters

const STORE = 'athernet.filters.v1';

export interface SavedFilter {
  name: string;
  filter: Filter;
}

/**
 * Saved filters live in this browser only. There is no account and no
 * server, so there is nowhere else for them to live - and a filter is a
 * question about your own network, which is nobody else's business anyway.
 */
export function loadSaved(): SavedFilter[] {
  try {
    const raw = localStorage.getItem(STORE);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as SavedFilter[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    // Private windows, blocked site data, a half-written value from an older
    // build: none of these are worth an error on screen.
    return [];
  }
}

export function saveFilter(name: string, filter: Filter): SavedFilter[] {
  const next = [...loadSaved().filter((s) => s.name !== name), { name, filter }].slice(-20);
  try {
    localStorage.setItem(STORE, JSON.stringify(next));
  } catch {
    // Nothing to do, and nothing worth saying: the filter still works, it
    // just will not be here next time.
  }
  return next;
}

export function deleteSaved(name: string): SavedFilter[] {
  const next = loadSaved().filter((s) => s.name !== name);
  try {
    localStorage.setItem(STORE, JSON.stringify(next));
  } catch {
    /* as above */
  }
  return next;
}

/** One-click filters for the things people look for most often. */
export const SHORTCUTS: { name: string; hint: string; build: () => Filter }[] = [
  {
    name: 'Connection attempts',
    hint: 'Every TCP packet that opens a connection',
    build: () => ({
      matchAll: true,
      groups: [{ key: key(), matchAll: true, conditions: [{ ...newCondition('flag'), op: 'has', value: 'SYN' }] }],
    }),
  },
  {
    name: 'Resets',
    hint: 'Connections refused or torn down',
    build: () => ({
      matchAll: true,
      groups: [{ key: key(), matchAll: true, conditions: [{ ...newCondition('flag'), op: 'has', value: 'RST' }] }],
    }),
  },
  {
    name: 'Name lookups',
    hint: 'DNS queries and answers',
    build: () => ({
      matchAll: true,
      groups: [
        { key: key(), matchAll: true, conditions: [{ ...newCondition('protocol'), op: 'is', value: 'DNS' }] },
      ],
    }),
  },
  {
    name: 'Encrypted setup',
    hint: 'TLS handshakes and alerts',
    build: () => ({
      matchAll: true,
      groups: [
        { key: key(), matchAll: true, conditions: [{ ...newCondition('protocol'), op: 'is', value: 'TLS' }] },
      ],
    }),
  },
  {
    name: 'Large packets',
    hint: 'Over 1,000 bytes on the wire',
    build: () => ({
      matchAll: true,
      groups: [
        { key: key(), matchAll: true, conditions: [{ ...newCondition('length'), op: 'gt', value: '1000' }] },
      ],
    }),
  },
  {
    name: 'Cut short',
    hint: 'Packets the snaplen truncated',
    build: () => ({
      matchAll: true,
      groups: [
        { key: key(), matchAll: true, conditions: [{ ...newCondition('truncated'), op: 'is', value: 'true' }] },
      ],
    }),
  },
];

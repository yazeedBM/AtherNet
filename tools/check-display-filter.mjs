// The display-filter gate.
//
// The other gates check that the core reads captures correctly. This one
// checks the layer above: that what somebody types into the filter bar turns
// into the filter they meant.
//
// It earns its place because of one failure mode in particular. A filter
// language that misreads a line and matches nothing looks exactly like a
// capture in which nothing matched, and those two call for opposite next
// moves - fix your filter, or believe the result. Several of the cases below
// are there only to pin down which of the two the app says.
//
// The parser is TypeScript in the front end, and node runs it directly: since
// 22.18 it strips type annotations rather than needing them compiled away.
// That keeps this gate a plain script with no build step, no bundler and no
// dependency on ui/node_modules, so it can run beside the other gates instead
// of waiting for an install.
//
// It costs one constraint, which display-filter.ts is written to meet: only
// syntax that can be *erased*, so no enums, no namespaces, and no constructor
// parameter properties. Its imports from ./filter and ./report are type-only
// and disappear with the annotations, so nothing else is loaded.

import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const source = join(root, 'ui', 'src', 'display-filter.ts');

let parseDisplayFilter;
let toFilter;
let dnfOfFilter;
let andDnf;
let conversationTruth;
let findingTruth;

try {
  ({ parseDisplayFilter, toFilter, dnfOfFilter, andDnf, conversationTruth, findingTruth } =
    await import(pathToFileURL(source).href));
} catch (e) {
  console.error(`could not load ${source}`);
  console.error(e?.message ?? e);
  console.error(
    '\nIf this says the syntax is unsupported, node is older than 22.18 or the\n' +
      'parser has grown syntax that cannot be erased - see the note at the top\n' +
      'of this file.',
  );
  process.exit(1);
}

let pass = 0;
const failures = [];

function check(name, got, want) {
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g === w) {
    pass += 1;
    return;
  }
  failures.push(`${name}\n       got  ${g}\n       want ${w}`);
}

/** A filter as one readable string per group, which is terse enough to assert on. */
const show = (dnf) =>
  dnf.map((group) =>
    group.map((l) => `${l.field} ${l.op} ${l.value}${l.negate ? ' !' : ''}`).join(' & '),
  );

function shape(text) {
  const outcome = parseDisplayFilter(text);
  if (outcome.kind !== 'filter') {
    return outcome.kind === 'error' ? `error: ${outcome.message}` : outcome.kind;
  }
  return show(outcome.parsed.dnf);
}

// ------------------------------------------------- addresses, the common case

check('ip.addr ==', shape('ip.addr == 192.168.1.20'), ['any_addr is 192.168.1.20']);
check('a bare address', shape('192.168.1.20'), ['any_addr is 192.168.1.20']);
check('ip.src', shape('ip.src == 10.0.0.1'), ['src is 10.0.0.1']);
check('ip.dst with a word operator', shape('ip.dst eq 10.0.0.2'), ['dst is 10.0.0.2']);
check('a subnet', shape('ip.addr == 10.0.0.0/8'), ['any_addr in 10.0.0.0/8']);
check('a bare subnet', shape('10.4.0.0/16'), ['any_addr in 10.4.0.0/16']);
check('not an address', shape('ip.addr != 192.168.1.20'), ['any_addr is 192.168.1.20 !']);

// ------------------------------------------- protocols, expanded as meant

// Wireshark's `udp` includes DNS because DNS rides on UDP. The core's labels
// are exclusive, so the set has to be written out or the filter surprises you.
check('tcp', shape('tcp'), ['protocol is TCP', 'protocol is TLS']);
check('udp', shape('udp'), ['protocol is UDP', 'protocol is DNS', 'protocol is DHCP']);
check('dns', shape('dns'), ['protocol is DNS']);
check('not tcp', shape('!tcp'), ['protocol is TCP ! & protocol is TLS !']);

// A port spelled `tcp.port` means a TCP port, not either protocol's.
check('tcp.port', shape('tcp.port == 443'), [
  'any_port is 443 & protocol is TCP',
  'any_port is 443 & protocol is TLS',
]);
check('a bare port field', shape('port == 53'), ['any_port is 53']);
check('tcp.dstport', shape('tcp.dstport == 80'), [
  'dst_port is 80 & protocol is TCP',
  'dst_port is 80 & protocol is TLS',
]);

// ------------------------------------------------------ booleans and brackets

check('and', shape('ip.addr == 10.0.0.1 && dns'), ['any_addr is 10.0.0.1 & protocol is DNS']);
check('or', shape('ip.addr == 10.0.0.1 || ip.addr == 10.0.0.2'), [
  'any_addr is 10.0.0.1',
  'any_addr is 10.0.0.2',
]);
check('brackets distribute', shape('(dns || arp) && ip.addr == 10.0.0.1'), [
  'protocol is DNS & any_addr is 10.0.0.1',
  'protocol is ARP & any_addr is 10.0.0.1',
]);
check('de morgan', shape('!(dns || arp)'), ['protocol is DNS ! & protocol is ARP !']);
check('two terms side by side', shape('tcp 10.0.0.1'), [
  'protocol is TCP & any_addr is 10.0.0.1',
  'protocol is TLS & any_addr is 10.0.0.1',
]);
check('the word and', shape('dns and 10.0.0.1'), ['protocol is DNS & any_addr is 10.0.0.1']);

// ----------------------------------------------------------------- numbers

check('frame.len', shape('frame.len > 1000'), ['length gt 1000']);
// The core has no >=, so it is written as the strict comparison next door.
// Exact for ports and byte counts, which are the only things this applies to.
check('>= becomes >', shape('frame.len >= 1000'), ['length gt 999']);
check('<= becomes <', shape('tcp.port <= 1024'), [
  'any_port lt 1025 & protocol is TCP',
  'any_port lt 1025 & protocol is TLS',
]);

// ------------------------------------------------------------------- flags

check('a flag', shape('tcp.flags.syn == 1'), ['flag has SYN']);
check('a bare flag', shape('tcp.flags.syn'), ['flag has SYN']);
check('a flag set to zero', shape('tcp.flags.syn == 0'), ['flag has SYN !']);

// ------------------------------- words are a search, not a broken filter

check('one word', shape('nxdomain'), 'text');
check('a sentence', shape('could not be looked up'), 'text');
check('nothing', parseDisplayFilter('   ').kind, 'empty');

// ------------------------- and a real gap is named, never silently empty

check(
  'a protocol we do not dissect',
  shape('http'),
  'error: AtherNet does not dissect http, so it cannot filter on it. It reads Ethernet, ARP, IP, TCP, UDP, ICMP, DNS, DHCP and TLS.',
);
check(
  'a field of one',
  shape('http.host == "x"'),
  'error: AtherNet does not dissect http, so it cannot filter on http.host.',
);
check('an unknown field', shape('ip.bogus == 1'), 'error: "ip.bogus" is not a field AtherNet knows.');
check('an open bracket', shape('(dns'), 'error: A bracket is left open.');
check('a comparison with no value', shape('ip.addr =='), 'error: ip.addr == what? The comparison has no value.');

// ------------------------------------------- what a conversation can answer

const conversation = (a, b, aPort, bPort, protocol) => ({
  a, b, aPort, bPort, protocol,
  firstPacket: 0, packets: 1, bytes: 1,
  startUnixMs: 0, durationSeconds: 0,
  outcome: 'completed', confidence: 'confirmed',
});
const parsed = (text) => parseDisplayFilter(text).parsed;
const lookup = conversation('192.168.1.20', '10.0.0.1', 5000, 53, 'UDP');

check('an address at one end', conversationTruth(parsed('ip.addr == 192.168.1.20'), lookup), true);
check('an address at neither', conversationTruth(parsed('ip.addr == 192.168.1.99'), lookup), false);
check('inside a subnet', conversationTruth(parsed('ip.addr == 192.168.0.0/16'), lookup), true);
check('outside a subnet', conversationTruth(parsed('ip.addr == 172.16.0.0/12'), lookup), false);
check('a port', conversationTruth(parsed('port == 53'), lookup), true);
// "not this address" has to mean neither end, which is what people mean and
// not what Wireshark's != actually does.
check('neither end', conversationTruth(parsed('ip.addr != 192.168.1.20'), lookup), false);

// The three-valued part, and the reason for it: a conversation is many
// packets, so a per-packet question has no answer here. Unknown must not
// collapse into "no", or filtering on a packet length would empty the map.
check('a per-packet question', conversationTruth(parsed('frame.len > 1000'), lookup), 'unknown');
check(
  'unknown does not rescue a definite no',
  conversationTruth(parsed('frame.len > 1000 && ip.addr == 10.9.9.9'), lookup),
  false,
);
check(
  'unknown survives a definite yes',
  conversationTruth(parsed('frame.len > 1000 && ip.addr == 10.0.0.1'), lookup),
  'unknown',
);

// ------------------------------------------------ what a finding can answer

const finding = (endpoints) => ({
  endpoints, id: 'x', kind: 'k', title: 't',
  severity: 'error', confidence: 'confirmed',
  what: '', at: '', atUnixMs: 0, firstPacket: 0,
  evidence: [], limits: [], nextChecks: [],
});

check('an endpoint', findingTruth(parsed('ip.addr == 192.168.1.20'), finding(['192.168.1.20', '10.0.0.1'])), true);
check('an endpoint with a port', findingTruth(parsed('ip.addr == 192.168.1.20'), finding(['192.168.1.20:445'])), true);
check('the port of one', findingTruth(parsed('port == 445'), finding(['192.168.1.20:445'])), true);
check('neither endpoint', findingTruth(parsed('ip.addr == 10.9.9.9'), finding(['192.168.1.20:445'])), false);
check('a protocol, which a finding does not carry', findingTruth(parsed('dns'), finding(['192.168.1.20'])), 'unknown');

// --------------------------- the builder's filter, in the same form

const condition = (field, op, value) => ({ key: 'k', field, op, value, negate: false });

check(
  'a group matching all of its conditions',
  show(dnfOfFilter({ matchAll: true, groups: [
    { key: 'g', matchAll: true, conditions: [condition('src', 'is', '10.0.0.1'), condition('protocol', 'is', 'TCP')] },
  ] })),
  ['src is 10.0.0.1 & protocol is TCP'],
);
check(
  'a group matching any of them',
  show(dnfOfFilter({ matchAll: true, groups: [
    { key: 'g', matchAll: false, conditions: [condition('src', 'is', '10.0.0.1'), condition('src', 'is', '10.0.0.2')] },
  ] })),
  ['src is 10.0.0.1', 'src is 10.0.0.2'],
);
check(
  'two any-groups combine by cross product, not concatenation',
  show(dnfOfFilter({ matchAll: true, groups: [
    { key: 'g1', matchAll: false, conditions: [condition('src', 'is', 'a'), condition('src', 'is', 'b')] },
    { key: 'g2', matchAll: false, conditions: [condition('dst', 'is', 'c'), condition('dst', 'is', 'd')] },
  ] })),
  ['src is a & dst is c', 'src is a & dst is d', 'src is b & dst is c', 'src is b & dst is d'],
);
check(
  'a blank condition is dropped, not matched against nothing',
  show(dnfOfFilter({ matchAll: true, groups: [
    { key: 'g', matchAll: true, conditions: [condition('src', 'is', '10.0.0.1'), condition('dst', 'is', '  ')] },
  ] })),
  ['src is 10.0.0.1'],
);

// Both filters are true at once, so both are applied - and an absent one
// must never narrow the other.
const typed = parsed('dns').dnf;
const built = dnfOfFilter({
  matchAll: true,
  groups: [{ key: 'g', matchAll: true, conditions: [condition('flag', 'has', 'SYN')] }],
});
check('no builder filter', show(andDnf(typed, [])), ['protocol is DNS']);
check('no typed filter', show(andDnf([], typed)), ['protocol is DNS']);
check('neither', andDnf([], []), []);
check(
  'typed and built together',
  show(andDnf(parsed('ip.addr == 93.184.216.34').dnf, built)),
  ['any_addr is 93.184.216.34 & flag has SYN'],
);
check('a filter survives the round trip', show(dnfOfFilter(toFilter({ dnf: typed, source: '' }))), show(typed));

for (const failure of failures) console.log(`  FAIL ${failure}`);
console.log(
  failures.length === 0
    ? `\ngate: PASSED - ${pass} display filters read the way they are written.`
    : `\ngate: FAILED - ${failures.length} of ${pass + failures.length} display filters misread.`,
);
process.exit(failures.length === 0 ? 0 : 1);

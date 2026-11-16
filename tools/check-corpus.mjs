#!/usr/bin/env node
// The phase 2 gate, as a command.
//
//   node tools/check-corpus.mjs
//
// Runs the analysis core over every capture in fixtures/ and compares what it
// found against fixtures/manifest.json, which was written before the
// detectors were. Two things have to hold, and the second is the harder one:
//
//   1. Every planted fault is found, with the severity and the confidence the
//      manifest says - a confirmed error reported as a suspicion is a miss,
//      and so is a suspicion reported as confirmed.
//   2. The files marked clean produce nothing at all.
//
// Exits non-zero when either fails, so it can sit in front of a commit.

import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const fixtures = join(root, 'fixtures');

const bench = ['target/release/athernet-bench.exe', 'target/release/athernet-bench']
  .map((p) => join(root, p))
  .find(existsSync);

if (!bench) {
  console.error('No athernet-bench build found. Build it first:');
  console.error('  cargo build --release -p athernet-core --bin athernet-bench');
  process.exit(2);
}

const manifestPath = join(fixtures, 'manifest.json');
if (!existsSync(manifestPath)) {
  console.error('No fixtures/manifest.json. Generate the corpus first:');
  console.error('  node tools/make-fixtures.mjs');
  process.exit(2);
}

const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

// A finding is identified by what it is, how much it matters, and how sure we
// are - all three, because the whole design rests on the last two being
// separate axes.
const asKey = (type, severity, confidence) => `${type}:${severity}:${confidence}`;

const expectedFor = (entry) =>
  entry.expect
    // "none" is the absence of findings, and "binding" is an IP-to-MAC claim
    // rather than a finding, so neither belongs in this comparison.
    .filter((e) => e.type !== 'none' && e.type !== 'binding')
    .map((e) => asKey(e.type, e.severity, e.confidence));

const output = execFileSync(bench, ['--kinds', fixtures], { encoding: 'utf8' });
const found = new Map();
for (const line of output.split(/\r?\n/)) {
  if (!line.trim()) continue;
  const [file, rest = ''] = line.split('\t');
  found.set(
    file,
    rest
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

/** Errors arrive multi-line; only the first line belongs in a gate report. */
const firstLine = (message) => String(message).split(String.fromCharCode(10))[0];

let failures = 0;
let clean = 0;

for (const entry of manifest.captures) {
  const actual = found.get(entry.file);
  if (!actual) {
    console.log(`FAIL  ${entry.file.padEnd(32)} the core did not report on this file at all`);
    failures += 1;
    continue;
  }
  if (actual.length === 1 && actual[0].startsWith('ERROR')) {
    console.log(`FAIL  ${entry.file.padEnd(32)} ${actual[0]}`);
    failures += 1;
    continue;
  }

  const expected = expectedFor(entry);
  const isClean = entry.expect.some((e) => e.type === 'none');

  if (isClean) {
    if (actual.length === 0) {
      console.log(`ok    ${entry.file.padEnd(32)} silent, as a clean capture must be`);
      clean += 1;
    } else {
      console.log(`FAIL  ${entry.file.padEnd(32)} false positives: ${actual.join(', ')}`);
      failures += 1;
    }
    continue;
  }

  const missing = expected.filter((e) => !actual.includes(e));
  // Extra findings are not automatically wrong - a file can legitimately show
  // more than the one fault it was built for - but anything the manifest does
  // not mention is printed so a person decides, rather than the script.
  const extra = actual.filter((a) => !expected.includes(a));

  if (missing.length === 0) {
    const note = extra.length ? `  (also found: ${extra.join(', ')})` : '';
    console.log(`ok    ${entry.file.padEnd(32)} ${expected.join(', ')}${note}`);
  } else {
    console.log(`FAIL  ${entry.file.padEnd(32)} missing: ${missing.join(', ')}`);
    console.log(`      ${' '.repeat(32)} found:   ${actual.join(', ') || '(nothing)'}`);
    failures += 1;
  }
}

// The report the UI reads has to be valid JSON with the fields the front end
// relies on. It is written by hand in Rust, without serde, so nothing in the
// compiler checks that - and a key emitted with no value still balances its
// braces, which is exactly the bug that got through once.
console.log();
try {
  const reports = JSON.parse(
    execFileSync(bench, ['--json', fixtures], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }),
  );
  const required = ['id', 'file', 'packets', 'protocols', 'timeline', 'conversations', 'findings', 'bindings'];
  for (const report of reports) {
    for (const field of required) {
      if (!(field in report)) {
        console.log(`FAIL  ${String(report.file).padEnd(32)} the report has no "${field}"`);
        failures += 1;
      }
    }
  }
  console.log(`ok    ${'the JSON report'.padEnd(32)} parses, ${reports.length} captures, every field present`);
} catch (e) {
  console.log(`FAIL  ${'the JSON report'.padEnd(32)} ${firstLine(e.message)}`);
  failures += 1;
}

// The phase 5 gates: nothing a capture holds may become structure in the
// assistant's evidence, no citation may point at something that is not there,
// and in redacted mode no address may leave. Run here so one command covers
// every gate the project has.
console.log();
try {
  const output = execFileSync(bench, ['--assistant', fixtures], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  const failed = output.split(String.fromCharCode(10)).filter((l) => l.startsWith('FAIL'));
  for (const line of failed.slice(0, 6)) console.log(line);
  if (failed.length > 0) {
    failures += failed.length;
  } else {
    console.log(`ok    ${'the assistant'.padEnd(32)} no captured text became structure, every citation resolved`);
  }
} catch (e) {
  console.log(`FAIL  ${'the assistant'.padEnd(32)} ${firstLine(e.message)}`);
  failures += 1;
}

console.log();
if (failures > 0) {
  console.log(`${failures} of ${manifest.captures.length} captures did not match the manifest.`);
  process.exit(1);
}
console.log(
  `gate: PASSED - ${manifest.captures.length} captures match the manifest, ${clean} of them clean and silent.`,
);

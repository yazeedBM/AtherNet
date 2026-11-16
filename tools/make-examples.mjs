#!/usr/bin/env node
// Packs the small fixture captures into the UI bundle, so the empty screen
// can offer "load the example captures" to someone who has none of their own.
//
//   node tools/make-fixtures.mjs
//   node tools/make-examples.mjs
//
// It ships the capture *files*, not a pre-computed report. The examples then
// go through the file picker, the worker, the wasm core and the explorer
// exactly as a capture you drop in does - one code path, and an example that
// cannot quietly drift away from what the app really does. The previous
// version of this generated a JSON report instead, which meant the examples
// were demonstrating a snapshot rather than the app.
//
// bulk-transfer.pcap is left out: it is 40 MB and exists to time the reader,
// not to look at.

import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const fixtures = join(root, 'fixtures');
const target = join(root, 'ui', 'src', 'example-captures.json');

/** Anything larger belongs on disk, not in a JavaScript bundle. */
const LIMIT = 256 * 1024;

if (!existsSync(fixtures)) {
  console.error('No fixtures/. Generate them first:  node tools/make-fixtures.mjs');
  process.exit(2);
}

const descriptions = new Map();
const manifestPath = join(fixtures, 'manifest.json');
if (existsSync(manifestPath)) {
  for (const entry of JSON.parse(readFileSync(manifestPath, 'utf8')).captures) {
    descriptions.set(entry.file, entry.description);
  }
}

const examples = [];
let skipped = 0;

for (const name of readdirSync(fixtures).sort()) {
  if (!/\.(pcap|pcapng|cap)$/i.test(name)) continue;
  const path = join(fixtures, name);
  const size = statSync(path).size;
  if (size > LIMIT) {
    skipped += 1;
    console.log(`  skipping ${name.padEnd(32)} ${(size / 1e6).toFixed(1)} MB, too big to bundle`);
    continue;
  }
  examples.push({
    file: name,
    description: descriptions.get(name) ?? '',
    base64: readFileSync(path).toString('base64'),
  });
}

writeFileSync(target, `${JSON.stringify(examples, null, 2)}\n`);

const bytes = examples.reduce((n, e) => n + Buffer.from(e.base64, 'base64').length, 0);
console.log(
  `wrote ui/src/example-captures.json - ${examples.length} captures, ${(bytes / 1024).toFixed(1)} kB of packets${
    skipped ? `, ${skipped} skipped` : ''
  }`,
);

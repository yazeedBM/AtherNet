#!/usr/bin/env node
// Compiles the analysis core to WebAssembly and puts it where the UI can
// import it.
//
//   node tools/build-wasm.mjs
//
// This is what lets the browser build open a capture file you chose. The
// desktop app reads files through Tauri, which on Windows needs the MSVC
// toolchain; the wasm build needs only `rustup target add
// wasm32-unknown-unknown` and runs the identical reader and detectors.
//
// The release profile carries debug info for profiling the native build,
// which would quintuple the download here, so it is turned off for this one
// target rather than for the workspace.

import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, statSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const built = join(
  root,
  'target',
  'wasm32-unknown-unknown',
  'release',
  'athernet_wasm.wasm',
);
const target = join(root, 'ui', 'src', 'athernet.wasm');

try {
  execFileSync(
    'cargo',
    [
      'build',
      '--release',
      '-p',
      'athernet-wasm',
      '--target',
      'wasm32-unknown-unknown',
      '--config',
      'profile.release.strip="symbols"',
      '--config',
      'profile.release.debug=false',
    ],
    { cwd: root, stdio: 'inherit' },
  );
} catch {
  console.error('\nThe wasm build failed. If the target is missing:');
  console.error('  rustup target add wasm32-unknown-unknown');
  process.exit(1);
}

if (!existsSync(built)) {
  console.error(`cargo reported success but ${built} is not there`);
  process.exit(1);
}

mkdirSync(dirname(target), { recursive: true });
copyFileSync(built, target);
console.log(
  `wrote ui/src/athernet.wasm - ${(statSync(target).size / 1024).toFixed(0)} kB`,
);

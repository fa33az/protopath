#!/usr/bin/env node
// Runs the compiled test suite.
//
// Node 20 does not expand globs in `node --test`, and newer releases dropped the implicit
// directory search, so the file list is built here instead of being left to the shell. This
// keeps `npm test` identical on every supported release and on every operating system.
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = 'dist-test/tests';

function collect(directory) {
  const entries = readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...collect(path));
    else if (entry.name.endsWith('.test.js')) files.push(path);
  }
  return files;
}

const files = collect(root);
if (files.length === 0) {
  console.error(`no test files under ${root}; run "npm run build:test" first`);
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit' });
process.exit(result.status ?? 1);

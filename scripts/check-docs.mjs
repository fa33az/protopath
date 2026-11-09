#!/usr/bin/env node
// Documentation drift gate.
//
// The README makes numeric claims: how many algorithms the catalogue holds, how many captures
// ship, how many tests pass, which MCP tools exist. Every one of those is derived from the code,
// so every one of them can be checked against the code. This script does that and fails CI when a
// document claims something the repository no longer does.
//
// It reads source files as text on purpose: it must run before a build, and a parser dependency
// for seven assertions would be worse than a regex.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const failures = [];
const passes = [];

function check(name, fn) {
  try {
    fn();
    passes.push(name);
  } catch (error) {
    failures.push(`${name}: ${error.message}`);
  }
}

const read = (path) => readFileSync(path, 'utf8');

const ONES = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten',
  'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen'];
const TENS = { twenty: 20, thirty: 30, forty: 40, fifty: 50, sixty: 60, seventy: 70, eighty: 80, ninety: 90 };

/** Reads a count written as a digit, a word, or a hyphenated word ("thirty", "twenty-six"). */
function numberOf(word) {
  const value = word.toLowerCase();
  if (/^\d+$/.test(value)) return Number(value);
  if (ONES.includes(value)) return ONES.indexOf(value);
  const [tens, ones] = value.split('-');
  if (tens !== undefined && tens in TENS) {
    if (ones === undefined) return TENS[tens];
    if (ONES.includes(ones)) return TENS[tens] + ONES.indexOf(ones);
  }
  return NaN;
}

function failing(actual, expected, what) {
  const missing = expected.filter((item) => !actual.includes(item));
  const extra = actual.filter((item) => !expected.includes(item));
  if (missing.length === 0 && extra.length === 0) return '';
  const parts = [];
  if (missing.length > 0) parts.push(`missing ${missing.join(', ')}`);
  if (extra.length > 0) parts.push(`unexpected ${extra.join(', ')}`);
  return `${what} disagree: ${parts.join('; ')}`;
}

// --- facts, read from source -------------------------------------------------------------

const checksumSource = read(join('src', 'core', 'infer', 'checksum.ts'));
const catalogueBlock = checksumSource.slice(checksumSource.indexOf('export const ALGORITHMS'));
const catalogue = [...catalogueBlock.matchAll(/\b(?:crc|simple)\('([^']+)'/g)].map((match) => match[1]);
// crc() takes a bit width, simple() takes a byte width. Both are checked and cross-mapped.
const widths = [
  ...[...catalogueBlock.matchAll(/\bcrc\('([^']+)',\s*(\d+)/g)].map((match) => ({ name: match[1], bits: Number(match[2]) })),
  ...[...catalogueBlock.matchAll(/\bsimple\('([^']+)',\s*(\d+)/g)].map((match) => ({ name: match[1], bytes: Number(match[2]) })),
];

const serverSource = read(join('src', 'mcp', 'server.ts'));
const mcpTools = [...serverSource.matchAll(/registerTool\(\s*'([a-z_]+)'/g)].map((match) => match[1]);

const cliSource = read(join('src', 'cli', 'index.ts'));
const cliCommands = [...cliSource.matchAll(/case '([a-z]+)':/g)].map((match) => match[1]);

const testFiles = readdirSync('tests').filter((name) => name.endsWith('.test.ts'));
const testCount = testFiles.reduce((total, name) => total + (read(join('tests', name)).match(/^test\(/gm) ?? []).length, 0);

const captureFiles = readdirSync('captures').filter((name) => name.endsWith('.pcap') || name.endsWith('.pcapng'));
// A pcapng copy of a pcap is the same protocol in another container, not a second protocol.
const protocols = captureFiles.filter((name) => !name.endsWith('.pcapng'));

const readme = read('README.md');
const design = read(join('docs', 'design.md'));
const capturesDoc = read(join('docs', 'captures.md'));
const crcDoc = read(join('docs', 'crc-recovery.md'));
const showcase = read(join('docs', 'showcase-modbus.md'));

// --- checks ------------------------------------------------------------------------------

check('the MCP server registers at least one tool', () => {
  if (mcpTools.length === 0) throw new Error('no registerTool call was found in src/mcp/server.ts');
});

check('every MCP tool is documented in the README', () => {
  const undocumented = mcpTools.filter((tool) => !readme.includes(`\`${tool}\``));
  if (undocumented.length > 0) throw new Error(`undocumented: ${undocumented.join(', ')}`);
});

check('the README documents no MCP tool that does not exist', () => {
  const start = readme.indexOf('## MCP tools');
  const end = readme.indexOf('## Limits', start);
  const table = start === -1 || end === -1 ? '' : readme.slice(start, end);
  if (table === '') throw new Error('the MCP tools section is missing from the README');
  const documented = [...table.matchAll(/^\|\s*`([a-z_]+)`/gm)].map((match) => match[1]);
  if (documented.length === 0) throw new Error('the MCP tools table is missing from the README');
  const invented = documented.filter((tool) => !mcpTools.includes(tool));
  if (invented.length > 0) throw new Error(`documented but not registered: ${invented.join(', ')}`);
  if (documented.length !== mcpTools.length) {
    throw new Error(`the table lists ${documented.length} tools, the server registers ${mcpTools.length}`);
  }
});

check('the README states the real MCP tool count', () => {
  // "mcp smoke test passed: nine tools" style claims in the smoke script.
  const mention = /mcp smoke test passed[^.]*?(\w+) tools/i.exec(read(join('.github', 'scripts', 'mcp-smoke.mjs')));
  if (mention) {
    const claimed = numberOf(mention[1]);
    if (claimed !== mcpTools.length) throw new Error(`the smoke test claims ${mention[1]} tools, the server has ${mcpTools.length}`);
  }
});

check('the checksum catalogue count matches the README', () => {
  const match = /([A-Za-z][a-z-]*|\d+)\s+algorithms/i.exec(readme);
  if (!match) throw new Error('the README no longer states how many algorithms the catalogue holds');
  const claimed = numberOf(match[1]);
  if (Number.isNaN(claimed)) throw new Error(`cannot read "${match[1]}" as a count`);
  if (claimed !== catalogue.length) throw new Error(`README says ${match[1]} (${claimed}), the catalogue has ${catalogue.length}`);
});

check('the checksum list in the README matches the catalogue', () => {
  const section = readme.slice(readme.indexOf('| Checksum family |'), readme.indexOf('| Value domain |'));
  const listed = [...section.matchAll(/`([a-z0-9]+(?:\/[\w-]+)?)`/g)].map((match) => match[1]);
  if (listed.length === 0) throw new Error('the checksum table is missing from the README');
  if (failing(listed, catalogue, 'README checksum table and catalogue')) throw new Error(failing(listed, catalogue, 'README checksum table and catalogue'));
});

check('the checksum list in docs/design.md matches the catalogue', () => {
  const start = design.indexOf('algorithms across three widths:');
  if (start === -1) throw new Error('the algorithm block is missing from docs/design.md');
  const block = design.slice(start, design.indexOf('```', design.indexOf('```', start) + 3));
  const listed = [...block.matchAll(/\b([a-z0-9]+(?:\/[\w-]+)?)\b/g)]
    .map((match) => match[1])
    .filter((token) => catalogue.includes(token));
  if (listed.length === 0) throw new Error('the algorithm block is missing from docs/design.md');
  if (failing(listed, catalogue, 'design.md algorithm block and catalogue')) {
    throw new Error(failing(listed, catalogue, 'design.md algorithm block and catalogue'));
  }
});

check('every checksum registration has a legal width', () => {
  const bad = [];
  for (const entry of widths) {
    if ('bits' in entry) {
      if (![8, 16, 32].includes(entry.bits)) bad.push(`${entry.name}: ${entry.bits} bits`);
    } else if (![1, 2, 4].includes(entry.bytes)) {
      bad.push(`${entry.name}: ${entry.bytes} bytes`);
    }
  }
  if (bad.length > 0) throw new Error(bad.join(', '));
  if (widths.length !== catalogue.length) {
    throw new Error(`${catalogue.length} algorithms registered, ${widths.length} widths found`);
  }
});

check('the README states the real test count', () => {
  const badge = /badge\/tests-(\d+)%20passing/.exec(readme);
  if (!badge) throw new Error('the test badge is missing from the README');
  if (Number(badge[1]) !== testCount) throw new Error(`the badge says ${badge[1]}, ${testCount} test declarations exist`);

  const prose = /and (\d+) tests that fail when the inference changes/.exec(readme);
  if (!prose) throw new Error('the README no longer states the test count in prose');
  if (Number(prose[1]) !== testCount) throw new Error(`prose says ${prose[1]}, ${testCount} test declarations exist`);

  const command = /npm test\s+# build and run (\d+) tests/.exec(readme);
  if (!command) throw new Error('the development section no longer states the test count');
  if (Number(command[1]) !== testCount) throw new Error(`the run line says ${command[1]}, ${testCount} test declarations exist`);
});

check('every capture file is documented', () => {
  const undocumented = captureFiles.filter((name) => !capturesDoc.includes(name));
  if (undocumented.length > 0) throw new Error(`missing from docs/captures.md: ${undocumented.join(', ')}`);
});

check('every capture named in the docs exists', () => {
  const mentioned = new Set([...capturesDoc.matchAll(/`([\w-]+\.(?:pcap|pcapng))`/g)].map((match) => match[1]));
  const invented = [...mentioned].filter((name) => !captureFiles.includes(name));
  if (invented.length > 0) throw new Error(`documented but absent from captures/: ${invented.join(', ')}`);
});

check('the README states the real capture count', () => {
  const match = /(\w+) captures ship with the repository/i.exec(readme);
  if (!match) throw new Error('the README no longer states how many captures ship');
  const claimed = numberOf(match[1]);
  if (claimed !== captureFiles.length) throw new Error(`README says ${match[1]} (${claimed}), captures/ holds ${captureFiles.length}`);
});

check('the README states the real protocol count', () => {
  const match = /(\w+) protocols with documented layouts/i.exec(readme);
  if (!match) throw new Error('the README no longer states how many protocols are documented');
  const claimed = numberOf(match[1]);
  if (claimed !== protocols.length) throw new Error(`README says ${match[1]} (${claimed}), ${protocols.length} pcap fixtures exist`);
});

check('the ground-truth table lists every capture', () => {
  const table = capturesDoc.slice(capturesDoc.indexOf('## Ground truth table'));
  const rows = [...table.matchAll(/^\|\s*([\w-]+\.(?:pcap|pcapng))\s*\|/gm)].map((match) => match[1]);
  const missing = captureFiles.filter((name) => !rows.includes(name));
  if (missing.length > 0) throw new Error(`no ground-truth row for: ${missing.join(', ')}`);
});

check('every CLI command is documented in the README', () => {
  const block = readme.slice(readme.indexOf('## CLI'), readme.indexOf('## MCP tools'));
  const missing = cliCommands.filter((command) => !new RegExp(`protopath ${command}\\b`).test(block));
  if (missing.length > 0) throw new Error(`missing from the README: ${missing.join(', ')}`);
});

check('every CLI command is documented in the help text', () => {
  const help = cliSource.slice(cliSource.indexOf('const HELP'), cliSource.indexOf('function main'));
  const missing = cliCommands.filter((command) => !new RegExp(`protopath ${command}\\b`).test(help));
  if (missing.length > 0) throw new Error(`missing from HELP: ${missing.join(', ')}`);
});

check('the documents agree on the fixture that proves CRC recovery', () => {
  for (const [name, text] of [
    ['README.md', readme],
    ['docs/captures.md', capturesDoc],
    ['docs/crc-recovery.md', crcDoc],
  ]) {
    if (!text.includes('custom-crc.pcap')) throw new Error(`${name} does not mention custom-crc.pcap`);
    if (!text.includes('0x8f57')) throw new Error(`${name} does not state the recovered polynomial`);
  }
});

check('the showcase and the capture doc agree on the real capture', () => {
  for (const [name, text] of [
    ['README.md', readme],
    ['docs/captures.md', capturesDoc],
  ]) {
    if (!text.includes('modbus-session.pcap')) throw new Error(`${name} does not mention modbus-session.pcap`);
  }
  if (!showcase.includes('0x84')) throw new Error('docs/showcase-modbus.md no longer shows the exception response');
});

// --- benchmark ------------------------------------------------------------------------------

const benchmarkDoc = read(join('docs', 'benchmark.md'));
const corpusDir = join('bench', 'corpus');
const recordedDir = join('bench', 'recorded');
const corpusFiles = readdirSync(corpusDir).filter((name) => name.endsWith('.pcap'));
const recordedFiles = readdirSync(recordedDir).filter((name) => name.endsWith('.pcap'));
const benchmarkFiles = [...corpusFiles, ...recordedFiles];
const corpusManifest = JSON.parse(read(join(corpusDir, 'manifest.json')));
const recordedManifest = JSON.parse(read(join(recordedDir, 'manifest.json')));

check('the benchmark manifests cover every capture', () => {
  const declared = new Set([...corpusManifest, ...recordedManifest].map((entry) => entry.file));
  const missing = benchmarkFiles.filter((name) => !declared.has(name));
  if (missing.length > 0) throw new Error(`no manifest entry for: ${missing.join(', ')}`);
  const invented = [...declared].filter((name) => !benchmarkFiles.includes(name));
  if (invented.length > 0) throw new Error(`manifest names absent captures: ${invented.join(', ')}`);
});

check('every benchmark capture is documented', () => {
  const undocumented = benchmarkFiles.filter((name) => !benchmarkDoc.includes(`\`${name}\``));
  if (undocumented.length > 0) throw new Error(`missing from docs/benchmark.md: ${undocumented.join(', ')}`);
});

check('the benchmark document names no capture that does not exist', () => {
  const mentioned = new Set([...benchmarkDoc.matchAll(/`([\w-]+\.(?:pcap|pcapng))`/g)].map((match) => match[1]));
  const invented = [...mentioned].filter((name) => !benchmarkFiles.includes(name));
  if (invented.length > 0) throw new Error(`documented but absent from bench/: ${invented.join(', ')}`);
});

check('the recorded captures say what produced them', () => {
  for (const entry of recordedManifest) {
    if (!entry.basis || entry.basis.length < 8) throw new Error(`${entry.file} has no specification basis`);
    if (!entry.note) throw new Error(`${entry.file} has no note about its known approximation`);
  }
});

check('the README documents the benchmark and profile commands', () => {
  for (const command of ['npm run bench', 'npm run profile']) {
    if (!readme.includes(command)) throw new Error(`README does not mention "${command}"`);
  }
});

// --- report ------------------------------------------------------------------------------

for (const name of passes) console.log(`ok    ${name}`);
for (const failure of failures) console.error(`FAIL  ${failure}`);

console.log('');
if (failures.length > 0) {
  console.error(`${failures.length} documentation claim(s) do not match the code.`);
  process.exit(1);
}
console.log(`${passes.length} documentation claims match the code.`);

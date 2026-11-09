#!/usr/bin/env node
// Benchmark against protocols the inference code has never seen.
//
// `bench/corpus/manifest.json` is written by `bench/make-bench.ts` from the specifications, and
// `bench/recorded/manifest.json` describes captures recorded from real libraries by
// `bench/record/record_all.py`. Neither is written from protopath's output.
//
// This script runs the tool over each capture and scores three inferences independently:
//
//   framing    did it find the message boundaries, and did it name the right field shape
//   checksum   did it find a real trailer, and did it invent one where none exists
//   family     did it name the right protocol family, and did it invent one elsewhere
//
// False positives (a claim that is not true) and false negatives (a real claim that was missed)
// are counted separately, because a tool that claims nothing scores perfectly on false
// positives and is useless.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeFile, isConfident } from '../dist/index.js';

function loadManifest(dir, file, extra) {
  const entries = JSON.parse(readFileSync(join(dir, file), 'utf8'));
  return entries.map((entry) => ({ ...entry, directory: dir, ...extra }));
}

const manifest = [
  ...loadManifest(join('bench', 'corpus'), 'manifest.json', { kind: 'written from the specification' }),
  ...loadManifest(join('bench', 'recorded'), 'manifest.json', { kind: 'recorded from a real implementation' }),
];

const totals = {
  framing: { tp: 0, fp: 0, fn: 0, exact: 0, approximate: 0 },
  checksum: { tp: 0, fp: 0, fn: 0 },
  family: { tp: 0, fp: 0, fn: 0 },
};

const rows = [];

function offsetsFrom(lengths) {
  const offsets = [0];
  for (const length of lengths) offsets.push(offsets[offsets.length - 1] + length);
  offsets.pop();
  return offsets;
}

function sameNumbers(a, b) {
  if (a.length !== b.length) return false;
  return a.every((value, index) => value === b[index]);
}

function describeShape(hypothesis) {
  if (!hypothesis) return 'none';
  if (hypothesis.lengthPrefix) {
    const s = hypothesis.lengthPrefix;
    return `length-prefix ${s.size}B ${s.endian} @${s.lenOffset} bias ${s.bias}`;
  }
  if (hypothesis.startMarker) return `start-marker ${hypothesis.startMarker.marker.toString('hex')}`;
  if (hypothesis.delimiter) return `delimiter ${hypothesis.delimiter.terminator.toString('hex')}`;
  if (hypothesis.fixed) return `fixed ${hypothesis.fixed.size}`;
  return hypothesis.kind;
}

/** Compares the declared field shape with the specification's. */
function declaredMatch(expected, hypothesis) {
  if (!hypothesis) return false;
  if (expected.kind !== hypothesis.kind) return false;
  if (expected.kind === 'length-prefix') {
    const s = hypothesis.lengthPrefix;
    if (!s) return false;
    return s.lenOffset === expected.lenOffset && s.size === expected.size && s.endian === expected.endian && s.bias === expected.bias;
  }
  if (expected.kind === 'delimiter') {
    return hypothesis.delimiter?.terminator.toString('hex') === expected.terminator;
  }
  if (expected.kind === 'start-marker') {
    // A marker may legitimately be reported wider than the specification's constant (MLLP's
    // 0x0b is followed by 'M' in every message of this capture), as long as it starts with it.
    return hypothesis.startMarker !== undefined && hypothesis.startMarker.marker.toString('hex').startsWith(expected.marker);
  }
  return true;
}

for (const entry of manifest) {
  const analysis = analyzeFile(join(entry.directory, entry.file), { maxFlows: 1 });
  const flow = analysis.flows[0];
  if (!flow) {
    rows.push({ file: entry.file, direction: '-', framing: 'no flow decoded', checksum: '', family: '' });
    totals.framing.fn += 1;
    continue;
  }

  const directions = entry.directions ? ['forward', 'reverse'] : ['forward'];
  for (const direction of directions) {
    const expected = entry.directions?.[direction];
    if (entry.directions && (!expected || expected.messages === 0)) continue;
    const actual = flow[direction];
    const best = actual.best;
    const confident = isConfident(best);
    let framingCell;

    if (entry.framing.kind === 'none') {
      if (confident) {
        totals.framing.fp += 1;
        framingCell = `FALSE POSITIVE: ${describeShape(best)}`;
      } else {
        totals.framing.tp += 1;
        framingCell = 'no claim (correct)';
      }
    } else if (!confident) {
      totals.framing.fn += 1;
      framingCell = `MISSED: best was ${describeShape(best)}`;
    } else if (entry.directions) {
      const boundaries = sameNumbers(offsetsFrom(expected.lengths), best.offsets);
      if (!boundaries) {
        totals.framing.fp += 1;
        framingCell = `WRONG BOUNDARIES: ${describeShape(best)} (${best.messages.length} vs ${expected.messages})`;
      } else if (declaredMatch(entry.framing, best)) {
        totals.framing.tp += 1;
        totals.framing.exact += 1;
        framingCell = `exact: ${describeShape(best)}`;
      } else {
        totals.framing.tp += 1;
        totals.framing.approximate += 1;
        framingCell = `boundaries exact, field ${describeShape(best)}`;
      }
    } else if (declaredMatch(entry.framing, best)) {
      totals.framing.tp += 1;
      totals.framing.exact += 1;
      framingCell = `exact: ${describeShape(best)}`;
    } else {
      totals.framing.fp += 1;
      framingCell = `WRONG SHAPE: ${describeShape(best)}`;
    }

    let checksumCell;
    if (entry.checksum === null) {
      if (actual.checksums.length > 0) {
        totals.checksum.fp += 1;
        checksumCell = `FALSE POSITIVE: ${actual.checksums.map((match) => match.algorithm).join(', ')}`;
      } else {
        checksumCell = 'none (correct)';
      }
    } else {
      const found = actual.checksums.find(
        (match) => match.algorithm === entry.checksum.algorithm && match.offsetFromEnd === entry.checksum.offsetFromEnd && match.width === entry.checksum.width,
      );
      if (found) {
        totals.checksum.tp += 1;
        checksumCell = `found ${found.algorithm} ${found.matches}/${found.total}`;
      } else {
        totals.checksum.fn += 1;
        checksumCell = `MISSED: ${actual.checksums.map((match) => match.algorithm).join(', ') || 'no candidate'}`;
      }
    }

    rows.push({ file: entry.file, direction, framing: framingCell, checksum: checksumCell, family: '' });
  }

  // A fingerprint names a known protocol family. The manifest says which family each capture
  // belongs to (null for protocols outside the rule set), so a label is checked, not trusted.
  if (entry.family) {
    if (flow.fingerprint?.family === entry.family) totals.family.tp += 1;
    else totals.family.fn += 1;
    rows.push({ file: entry.file, direction: '-', framing: '', checksum: '', family: flow.fingerprint ? `${flow.fingerprint.family} ${flow.fingerprint.confidence.toFixed(2)}` : `MISSED: ${entry.family}` });
  } else if (flow.fingerprint) {
    totals.family.fp += 1;
    rows.push({ file: entry.file, direction: '-', framing: '', checksum: '', family: `FALSE POSITIVE: ${flow.fingerprint.family}` });
  }
}

const header = ['capture', 'direction', 'framing', 'checksum', 'family'];
const widths = header.map((cell, index) => Math.max(cell.length, ...rows.map((row) => String(Object.values(row)[index]).length)) + 2);
console.log(header.map((cell, index) => cell.padEnd(widths[index])).join(''));
console.log(widths.map((width) => '-'.repeat(width)).join(''));
for (const row of rows) {
  console.log(
    Object.values(row)
      .map((cell, index) => String(cell).padEnd(widths[index]))
      .join('')
      .trimEnd(),
  );
}

console.log('');
console.log(`framing   true positives ${totals.framing.tp}  false positives ${totals.framing.fp}  false negatives ${totals.framing.fn}`);
console.log(`          exact field shape ${totals.framing.exact}, boundaries right with a different field ${totals.framing.approximate}`);
console.log(`checksum  true positives ${totals.checksum.tp}  false positives ${totals.checksum.fp}  false negatives ${totals.checksum.fn}`);
console.log(`family    true positives ${totals.family.tp}  false positives ${totals.family.fp}  false negatives ${totals.family.fn}`);

const failures = totals.framing.fp + totals.framing.fn + totals.checksum.fp + totals.checksum.fn + totals.family.fp + totals.family.fn;
if (failures > 0) {
  console.error(`\n${failures} claim(s) are wrong or missing.`);
  process.exit(1);
}
console.log('\nevery claim matches the specification.');

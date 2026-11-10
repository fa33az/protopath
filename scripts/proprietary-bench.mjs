#!/usr/bin/env node
// Scores the inference against protocols drawn from a parameter space, not written by hand.
//
// `bench/proprietary/corpus/manifest.json` is written by the generator before this script runs. Six
// independent questions are asked per capture, and each is scored separately, because a tool that
// finds the boundaries and then mislabels every field has not succeeded.
//
//   boundaries   message count and byte offsets
//   family       which of the five framing families
//   lengthfield  offset, width, endianness and bias of the length field
//   header       how many leading bytes are structure rather than payload
//   counter      the stepping field, at the right offset, named as a counter
//   checksum     a real check field found, or silence where there is none
//
// Every miss is then sorted into one of two bins, and the distinction is the point of this
// script:
//
//   ambiguous  the bytes cannot separate the reported answer from the truth. A four-byte
//              big-endian length 00 00 00 33 is also a two-byte length at offset +2, and a
//              message that starts with a constant marker and ends with a terminator reads as
//              either family. Reporting one of them is not an error; what matters is that the
//              tool says the other is still standing.
//   wrong      the truth's own rule does not reproduce the reported answer. This is the number
//              worth driving down.
//
// Usage:
//   node scripts/proprietary-bench.mjs            score, print a table
//   node scripts/proprietary-bench.mjs --verbose  print one line per capture
//   node scripts/proprietary-bench.mjs --misses   print every miss with its bin
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Buffer } from 'node:buffer';
import { analyzeFile, isConfident } from '../dist/index.js';

const corpus = join('bench', 'proprietary', 'corpus');
const manifest = JSON.parse(readFileSync(join(corpus, 'manifest.json'), 'utf8'));
const verbose = process.argv.includes('--verbose');
const showMisses = process.argv.includes('--misses');

const keys = ['boundaries', 'family', 'lengthField', 'header', 'counter', 'checksum'];
const totals = Object.fromEntries(keys.map((key) => [key, { hit: 0, ambiguous: 0, wrong: 0, skipped: 0 }]));
const misses = Object.fromEntries(keys.map((key) => [key, []]));

function sameNumbers(a, b) {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function offsets(lengths) {
  const out = [0];
  for (let i = 0; i < lengths.length - 1; i++) out.push(out[i] + lengths[i]);
  return out;
}

function record(key, outcome, detail) {
  totals[key][outcome] += 1;
  if (outcome !== 'hit' && misses[key].length < 40) misses[key].push(`${outcome === 'ambiguous' ? '~' : '!'} ${detail}`);
}

function readValue(data, at, size, endian) {
  if (size === 1) return data[at];
  if (size === 2) return endian === 'le' ? data.readUInt16LE(at) : data.readUInt16BE(at);
  return endian === 'le' ? data.readUInt32LE(at) : data.readUInt32BE(at);
}

/** Does the truth's own framing rule reproduce these boundaries on this stream? */
function truthExplains(stream, framing, reportedOffsets) {
  const offsetsOut = [];
  if (framing.kind === 'length-prefix') {
    const { lenOffset, size, endian, bias } = framing;
    let cursor = 0;
    while (cursor < stream.length) {
      if (cursor + lenOffset + size > stream.length) return false;
      const total = readValue(stream, cursor + lenOffset, size, endian) + bias;
      if (total < lenOffset + size || cursor + total > stream.length) return false;
      offsetsOut.push(cursor);
      cursor += total;
    }
    return cursor === stream.length && sameNumbers(offsetsOut, reportedOffsets);
  }
  if (framing.kind === 'start-marker') {
    const marker = Buffer.from(framing.marker, 'hex');
    for (let at = stream.indexOf(marker); at !== -1; at = stream.indexOf(marker, at + 1)) offsetsOut.push(at);
    if (offsetsOut[0] !== 0) return false;
    return sameNumbers(offsetsOut, reportedOffsets);
  }
  if (framing.kind === 'delimiter') {
    const terminator = Buffer.from(framing.terminator, 'hex');
    let cursor = 0;
    while (cursor < stream.length) {
      const found = stream.indexOf(terminator, cursor);
      if (found === -1) return false;
      offsetsOut.push(cursor);
      cursor = found + terminator.length;
    }
    return cursor === stream.length && sameNumbers(offsetsOut, reportedOffsets);
  }
  return false;
}

for (const entry of manifest) {
  let analysis;
  try {
    analysis = analyzeFile(join(corpus, `${entry.name}.pcap`), { maxFlows: 1, deep: false });
  } catch (error) {
    for (const key of keys) record(key, 'wrong', `${entry.name}: threw ${error.message}`);
    continue;
  }

  const flow = analysis.flows[0];
  const direction = flow?.forward;
  const best = direction?.best;
  const confident = isConfident(best);
  const truthOffsets = offsets(entry.messages.lengths);

  // --- framing family ---------------------------------------------------------------------
  if (entry.framing.kind === 'unframed') {
    // Nothing to find. A confident claim here is a false positive.
    record('family', confident ? 'wrong' : 'hit', `${entry.name}: claimed ${best?.kind} at ${best?.score?.toFixed(2)}`);
    for (const key of ['boundaries', 'lengthField', 'header', 'counter', 'checksum']) totals[key].skipped += 1;
    continue;
  }

  if (!best || !confident) {
    record('family', 'wrong', `${entry.name}: no confident claim (best ${best?.kind ?? 'none'} at ${best?.score?.toFixed(2) ?? '-'})`);
    for (const key of ['boundaries', 'lengthField', 'header', 'counter', 'checksum']) totals[key].skipped += 1;
    continue;
  }

  const familyOk =
    best.kind === entry.framing.kind &&
    (entry.framing.kind !== 'length-prefix' || best.lengthPrefix !== undefined) &&
    (entry.framing.kind !== 'start-marker' || best.startMarker?.marker.toString('hex').startsWith(entry.framing.marker)) &&
    (entry.framing.kind !== 'delimiter' || best.delimiter?.terminator.toString('hex') === entry.framing.terminator);

  if (familyOk) {
    record('family', 'hit', `${entry.name}: ${best.kind}`);
  } else {
    const stream = Buffer.concat(best.messages);
    const explained = truthExplains(stream, entry.framing, best.offsets);
    record(
      'family',
      explained ? 'ambiguous' : 'wrong',
      `${entry.name}: expected ${entry.framing.kind}, reported ${best.kind}${explained ? ' (the truth rule reproduces these boundaries)' : ''}`,
    );
  }

  // --- boundaries -------------------------------------------------------------------------
  record(
    'boundaries',
    sameNumbers(best.offsets, truthOffsets) ? 'hit' : 'wrong',
    `${entry.name}: ${best.messages.length} messages vs ${entry.messages.count}, first offsets ${best.offsets.slice(0, 3).join(',')} vs ${truthOffsets.slice(0, 3).join(',')}`,
  );

  // --- length field -----------------------------------------------------------------------
  if (entry.framing.kind !== 'length-prefix') {
    totals.lengthField.skipped += 1;
  } else {
    const spec = best.lengthPrefix;
    const exact =
      spec !== undefined &&
      spec.lenOffset === entry.framing.lenOffset &&
      spec.size === entry.framing.size &&
      spec.endian === entry.framing.endian &&
      spec.bias === entry.framing.bias;
    if (exact) {
      record('lengthField', 'hit', `${entry.name}: exact`);
    } else {
      // Same boundaries means the reading differs only where the bytes are silent.
      const stream = Buffer.concat(best.messages);
      const explained = truthExplains(stream, entry.framing, best.offsets);
      record(
        'lengthField',
        explained ? 'ambiguous' : 'wrong',
        `${entry.name}: expected @${entry.framing.lenOffset} ${entry.framing.size}B ${entry.framing.endian} bias ${entry.framing.bias}, reported ${spec ? `@${spec.lenOffset} ${spec.size}B ${spec.endian} bias ${spec.bias}` : 'none'}`,
      );
    }
  }

  // --- header length ----------------------------------------------------------------------
  const body = direction.fields.find((field) => field.role === 'payload' || field.role === 'text');
  const reportedHeader = body?.offset ?? -1;
  record('header', reportedHeader === entry.headerLength ? 'hit' : 'wrong', `${entry.name}: header ${reportedHeader} vs ${entry.headerLength}`);

  // --- counter ----------------------------------------------------------------------------
  const counters = direction.fields.filter((field) => field.role === 'counter');
  if (!entry.counter) {
    record('counter', counters.length === 0 ? 'hit' : 'wrong', `${entry.name}: no counter in the protocol, reported ${counters.map((f) => `${f.offset}:${f.length}`).join(',')}`);
  } else {
    const exact = counters.some((field) => field.offset === entry.counter.offset && field.length === entry.counter.width);
    if (exact) {
      record('counter', 'hit', `${entry.name}: counter at ${entry.counter.offset}`);
    } else {
      // A counter found at the right offset with a different width, or at a different offset with
      // the right width, is the same evidence read at a different granularity.
      const near = counters.some(
        (field) =>
          (field.offset <= entry.counter.offset && field.offset + field.length >= entry.counter.offset + entry.counter.width) ||
          (entry.counter.offset <= field.offset && entry.counter.offset + entry.counter.width >= field.offset + field.length),
      );
      record(
        'counter',
        near ? 'ambiguous' : 'wrong',
        `${entry.name}: counter at ${entry.counter.offset} (${entry.counter.width}B) -> ${counters.map((f) => `${f.offset}:${f.length}`).join(',') || 'none'}`,
      );
    }
  }

  // --- checksum ---------------------------------------------------------------------------
  if (!entry.checksum) {
    const invented = direction.checksums.length > 0 || direction.crcRecovery.length > 0;
    record('checksum', invented ? 'wrong' : 'hit', `${entry.name}: no checksum exists, reported ${direction.checksums.map((c) => c.algorithm).join(',') || (direction.crcRecovery.length ? 'a recovered set' : 'nothing')}`);
  } else {
    const found = direction.checksums.some(
      (match) =>
        match.width === entry.checksum.width &&
        match.offsetFromEnd === entry.checksum.offsetFromEnd &&
        (entry.checksum.family.startsWith('crc-private') || match.algorithm === entry.checksum.family),
    );
    const recovered =
      !found &&
      direction.crcRecovery.some(
        (candidate) => candidate.params.width === entry.checksum.width && candidate.matches === candidate.total,
      );
    if (found || recovered) {
      record('checksum', 'hit', `${entry.name}: ${entry.checksum.family}`);
    } else {
      const anything = direction.checksums.length > 0 || direction.crcRecovery.length > 0;
      record(
        'checksum',
        anything ? 'ambiguous' : 'wrong',
        `${entry.name}: expected ${entry.checksum.family} ${entry.checksum.width}B at -${entry.checksum.offsetFromEnd}, got ${direction.checksums.map((c) => `${c.algorithm}@-${c.offsetFromEnd}`).join(',') || 'nothing'}`,
      );
    }
  }

  if (verbose) {
    console.log(
      `${entry.name}  ${entry.transport}  ${entry.framing.kind.padEnd(13)} report ${best.kind.padEnd(13)} ${confident ? 'confident' : 'unsure   '}  header ${reportedHeader}/${entry.headerLength}  chk ${direction.checksums.length}`,
    );
  }
}

// --- report ---------------------------------------------------------------------------------

const pad = (value, width) => String(value).padStart(width);
console.log('\nquestion      scored   hit   amb  wrong  skipped   strict    wrong');
console.log('------------------------------------------------------------------');
for (const key of keys) {
  const { hit, ambiguous, wrong, skipped } = totals[key];
  const scored = hit + ambiguous + wrong;
  const strict = scored === 0 ? '-' : `${((100 * hit) / scored).toFixed(1)}%`;
  const wrongRate = scored === 0 ? '-' : `${((100 * wrong) / scored).toFixed(1)}%`;
  console.log(`${key.padEnd(13)}${pad(scored, 6)}${pad(hit, 6)}${pad(ambiguous, 6)}${pad(wrong, 6)}${pad(skipped, 8)}${pad(strict, 9)}${pad(wrongRate, 8)}`);
}

const sum = (field) => keys.reduce((total, key) => total + totals[key][field], 0);
const scored = sum('hit') + sum('ambiguous') + sum('wrong');
console.log(
  `\nall questions:  hit ${sum('hit')}   ambiguous ${sum('ambiguous')}   wrong ${sum('wrong')}   of ${scored} scored checks ` +
    `over ${manifest.length} protocols the inference was not developed on.`,
);

if (showMisses) {
  for (const key of keys) {
    const list = misses[key].filter((line) => line.startsWith('!'));
    if (list.length === 0) continue;
    console.log(`\n${key} — wrong:`);
    for (const line of list) console.log(`  ${line}`);
  }
}

// The floor is a regression guard, not a target: raise it when a rule improves.
const FLOOR = Number(process.env.PROPRIETARY_FLOOR ?? 0);
const hits = sum('hit');
if (FLOOR > 0 && hits < FLOOR) {
  console.error(`\nbelow the recorded floor of ${FLOOR} passing checks.`);
  process.exit(1);
}

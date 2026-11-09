// End to end: a capture whose CRC parameters are ambiguous, carried through to the emitted client.
//
// Builds a capture with a real private CRC, runs the full analysis, and asks three questions:
//   1. does the analysis report more than one fully verified parameter set?
//   2. which one lands in the field table and the generated client?
//   3. does that client compute the checksum the real peer computes?
import { Buffer } from 'node:buffer';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tcpFrame, writePcap } from '../../dist-test/scripts/pcap-writer.js';
import { analyzeFile } from '../../dist/core/pipeline.js';
import { crcCompute } from '../../dist/core/infer/checksum.js';
import { emitClient } from '../../dist/core/emit/client.js';
import { emitDissector } from '../../dist/core/emit/dissector.js';

const out = join('out', 'audit', 'ambiguous');
mkdirSync(out, { recursive: true });

// The parameters from the sweep that produced a tie: poly 0xb42d, init 0x2000 + trial * 61.
const poly = 0xb42d;
const init = 0x2000;
const truth = { width: 16, poly, init, refin: true, refout: true, xorout: 0 };

// Eight messages of five distinct lengths: 1-byte length-style header, a counter, a text body.
const records = [];
let seq = 1000;
for (let i = 0; i < 8; i++) {
  const body = Buffer.alloc(10 + (i % 5));
  for (let b = 0; b < body.length; b++) body[b] = (i * 31 + b * 17) & 0x61;
  const message = Buffer.concat([Buffer.from([0xa5, 0x5a, 6 + body.length, i]), body]);
  const field = Buffer.alloc(2);
  field.writeUInt16LE(crcCompute(message, truth), 0);
  const payload = Buffer.concat([message, field]);
  records.push({ ts: 1760000000 + i * 0.01, data: tcpFrame('10.9.0.10', 42000, '10.9.0.20', 7777, seq, 5000, payload) });
  seq += payload.length;
}
const path = join(out, 'ambiguous-crc.pcap');
writePcap(path, records);

const analysis = analyzeFile(path, { maxFlows: 1 });
const direction = analysis.flows[0]?.forward;
if (!direction) throw new Error('no flow');

console.log('captured message lengths:', direction.messages.map((m) => m.bytes.length).join(', '));
console.log(`recovery candidates: ${direction.crcRecovery.length}`);
for (const candidate of direction.crcRecovery) {
  const p = candidate.params;
  const isTruth = p.poly === poly && p.init === init && p.refin === truth.refin && p.refout === truth.refout;
  console.log(
    `  poly 0x${p.poly.toString(16).padStart(4, '0')} init 0x${p.init.toString(16).padStart(4, '0')} ` +
      `refin ${p.refin} refout ${p.refout} xorout 0x${p.xorout.toString(16)} ` +
      `${candidate.matches}/${candidate.total}${isTruth ? '  <- the real one' : ''}`,
  );
}

const field = direction.fields.find((f) => f.role === 'checksum');
console.log(`\nfield table embeds: ${field ? `${field.name} poly 0x${field.spec.params.poly.toString(16)} init 0x${field.spec.params.init.toString(16)}` : 'nothing'}`);

// The generated client, run against a body the capture never contained.
const source = emitClient(analysis.flows[0], 'python');
writeFileSync(join(out, 'client.py'), source);
const spec = field.spec.params;
console.log('\nchecksums on bodies that were not captured:');
console.log('  length  real      generated  agree');
let wrong = 0;
for (const length of [10, 11, 12, 13, 14, 20, 40, 64]) {
  const body = Buffer.alloc(length);
  for (let b = 0; b < length; b++) body[b] = (length * 89 + b * 41) & 0x61;
  const real = crcCompute(body, truth);
  const generated = crcCompute(body, spec);
  const agree = real === generated;
  if (!agree) wrong += 1;
  console.log(`  ${String(length).padStart(6)}  0x${real.toString(16).padStart(4, '0')}  0x${generated.toString(16).padStart(4, '0')}     ${agree ? 'yes' : 'NO'}`);
}
console.log(`\n${wrong} of 8 unseen bodies get the wrong checksum from the generated client.`);

// Does the report say anything about the ambiguity?
const lines = JSON.stringify(analysis, null, 1).split('\n');
const mentions = lines.filter((line) => /ambiguous|multiple|equivalent/i.test(line));
console.log(`\nlines in analysis.json mentioning ambiguity: ${mentions.length}`);
for (const line of mentions.slice(0, 6)) console.log(`  ${line.trim()}`);

const dissector = emitDissector(analysis.flows[0]);
writeFileSync(join(out, 'dissector.lua'), dissector);
console.log(`\nartifacts written to ${out}`);

// When the reported parameter set is degenerate, is the true one also in the list?
import { Buffer } from 'node:buffer';
import { recoverCrc } from '../../dist/core/infer/crc-recovery.js';
import { crcCompute } from '../../dist/core/infer/checksum.js';

const trials = 60;
let truthPresent = 0;
let truthFirst = 0;
let truthAbsent = 0;
let multi = 0;
const rows = [];

for (let trial = 0; trial < trials; trial++) {
  const p = (0x8100 + trial * 397) | 1;
  const i0 = (0x2000 + trial * 61) & 0xffff;
  const t = { width: 16, poly: p, init: i0, refin: true, refout: true, xorout: 0 };
  const set = [];
  for (let i = 0; i < 8; i++) {
    const body = Buffer.alloc(10 + (i % 5));
    for (let b = 0; b < body.length; b++) body[b] = (i * 31 + b * 17) & 0xff;
    const field = Buffer.alloc(2);
    field.writeUInt16LE(crcCompute(body, t), 0);
    set.push(Buffer.concat([body, field]));
  }
  const verified = recoverCrc(set).filter((f) => f.matches === f.total);
  if (verified.length > 1) multi += 1;

  const exactIndex = verified.findIndex((f) => f.params.poly === p);
  if (exactIndex === -1) {
    truthAbsent += 1;
    if (rows.length < 4) rows.push(`poly 0x${p.toString(16)}: absent, ${verified.length} other set(s), first poly 0x${verified[0]?.params.poly.toString(16)}`);
  } else {
    truthPresent += 1;
    if (exactIndex === 0) truthFirst += 1;
    else if (rows.length < 8) rows.push(`poly 0x${p.toString(16)}: present at index ${exactIndex} of ${verified.length}; first is poly 0x${verified[0].params.poly.toString(16)}`);
  }
}

console.log(`fully verified sets returned, over ${trials} private polynomials:`);
console.log(`  the true set appears first   : ${truthFirst}`);
console.log(`  the true set appears later   : ${truthPresent - truthFirst}`);
console.log(`  the true set is not returned : ${truthAbsent}`);
console.log(`  more than one fully verified : ${multi}`);
for (const row of rows) console.log(`  ${row}`);

// Which set does the pipeline hand to the field table and the generated client?
const { analyzeFile } = await import('../../dist/core/pipeline.js');
const analysis = analyzeFile('captures/custom-crc.pcap', { maxFlows: 1 }).flows[0];
const chosen = analysis.forward.fields.find((f) => f.role === 'checksum');
console.log('\nthe fixture that ships with the repository:');
console.log(`  recovery candidates: ${analysis.forward.crcRecovery.length}`);
for (const candidate of analysis.forward.crcRecovery) {
  console.log(
    `    poly 0x${candidate.params.poly.toString(16)} init 0x${candidate.params.init.toString(16)} ` +
      `refin ${candidate.params.refin} refout ${candidate.params.refout} xorout 0x${candidate.params.xorout.toString(16)} ` +
      `${candidate.matches}/${candidate.total} ambiguous=${candidate.initAmbiguous ?? false}`,
  );
}
console.log(`  the field table embeds: ${chosen?.name} ${chosen?.spec ? JSON.stringify(chosen.spec.params) : 'no spec'}`);

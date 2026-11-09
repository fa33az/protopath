// Does an equivalent-on-this-capture parameter set still work on the next message?
//
// Recovery guarantees "reproduces every message in this capture". If the reported set differs
// from the protocol's real set, the generated client will disagree with the peer as soon as a
// message is longer or different from the ones that were captured. This measures that gap.
import { Buffer } from 'node:buffer';
import { recoverCrc } from '../../dist/core/infer/crc-recovery.js';
import { crcCompute } from '../../dist/core/infer/checksum.js';

const poly = 0x8b75; // the case that came back as poly 0x3b
const init = 0x1094;
const truth = { width: 16, poly, init, refin: true, refout: true, xorout: 0 };

function capturedBody(i) {
  const body = Buffer.alloc(10 + (i % 5));
  for (let b = 0; b < body.length; b++) body[b] = (i * 31 + b * 17) & 0xff;
  return body;
}

const messages = [];
for (let i = 0; i < 8; i++) {
  const body = capturedBody(i);
  const field = Buffer.alloc(2);
  field.writeUInt16LE(crcCompute(body, truth), 0);
  messages.push(Buffer.concat([body, field]));
}

const found = recoverCrc(messages);
const reported = found.find((f) => f.matches === f.total);
console.log('real parameter set  :', `poly 0x${poly.toString(16)} init 0x${init.toString(16)} xorout 0x0`);
console.log(
  'reported set        :',
  `poly 0x${reported.params.poly.toString(16)} init 0x${reported.params.init.toString(16)} ` +
    `refin ${reported.params.refin} refout ${reported.params.refout} xorout 0x${reported.params.xorout.toString(16)} ` +
    `verified ${reported.matches}/${reported.total}`,
);

console.log('\nagreement on messages that were not captured:');
console.log('  body length  real value  reported value  agree');
let disagreements = 0;
for (const length of [10, 11, 12, 13, 14, 15, 20, 32, 64]) {
  const body = Buffer.alloc(length);
  for (let b = 0; b < length; b++) body[b] = (length * 97 + b * 29) & 0xff;
  const real = crcCompute(body, truth);
  const claimed = crcCompute(body, { ...reported.params, xorout: reported.params.xorout ?? 0 });
  const agree = real === claimed;
  if (!agree) disagreements += 1;
  console.log(`  ${String(length).padStart(11)}  0x${real.toString(16).padStart(4, '0')}     0x${claimed.toString(16).padStart(4, '0')}     ${agree ? 'yes' : 'NO'}`);
}
console.log(`\n${disagreements} of 9 unseen bodies disagree with the real protocol.`);

// How often does the reported set diverge on a longer body, across many private polynomials?
console.log('\n=== across 60 private polynomials: does the reported set survive an unseen message? ===');
let survives = 0;
let diverges = 0;
let missing = 0;
for (let trial = 0; trial < 60; trial++) {
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
  const res = recoverCrc(set).find((f) => f.matches === f.total);
  if (!res) {
    missing += 1;
    continue;
  }
  const body = Buffer.alloc(48);
  for (let b = 0; b < body.length; b++) body[b] = (b * 173 + 11) & 0xff;
  const real = crcCompute(body, t);
  const claimed = crcCompute(body, { ...res.params, xorout: res.params.xorout ?? 0 });
  if (real === claimed) survives += 1;
  else diverges += 1;
}
console.log(`  reported set still correct on a 48-byte body: ${survives}`);
console.log(`  reported set wrong on a 48-byte body        : ${diverges}`);
console.log(`  nothing reported                            : ${missing}`);

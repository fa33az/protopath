// Why does recovery miss a genuine private CRC in roughly one case out of ten?
import { Buffer } from 'node:buffer';
import { recoverCrc } from '../../dist/core/infer/crc-recovery.js';
import { crcCompute } from '../../dist/core/infer/checksum.js';

function build(poly, init, refin, refout, xorout, refinBytes = true) {
  const messages = [];
  for (let i = 0; i < 8; i++) {
    const body = Buffer.alloc(10 + (i % 5));
    for (let b = 0; b < body.length; b++) body[b] = (i * 31 + b * 17) & 0xff;
    const field = Buffer.alloc(2);
    field.writeUInt16LE(crcCompute(body, { width: 16, poly, init, refin, refout, xorout }), 0);
    messages.push(Buffer.concat([body, field]));
  }
  void refinBytes;
  return messages;
}

function equivalent(a, b, messages) {
  // Two parameter sets are equivalent on this evidence when both reproduce every message.
  const check = (p) =>
    messages.every((m) => {
      const body = m.subarray(0, m.length - 2);
      const field = m.readUInt16LE(m.length - 2);
      return crcCompute(body, p) === field;
    });
  return check(a) && check(b);
}

let exact = 0;
let equivalentOnly = 0;
let genuineMiss = 0;
const misses = [];

for (let trial = 0; trial < 40; trial++) {
  const poly = (0x8001 + ((trial * 733) % 0x7ffe)) | 1;
  const init = (0x1000 + trial * 37) & 0xffff;
  const truth = { width: 16, poly, init, refin: true, refout: true, xorout: 0 };
  const messages = build(poly, init, true, true, 0);
  const found = recoverCrc(messages);

  const exactHit = found.some((f) => f.params.poly === poly && f.params.init === init && f.matches === f.total);
  const equivalentHit = found.some(
    (f) => f.matches === f.total && equivalent(truth, { ...f.params, xorout: f.params.xorout ?? 0 }, messages),
  );

  if (exactHit) exact += 1;
  else if (equivalentHit) {
    equivalentOnly += 1;
    const alt = found.find((f) => f.matches === f.total);
    misses.push(
      `poly 0x${poly.toString(16)} init 0x${init.toString(16)} not named; ` +
        `an equivalent set was: poly 0x${alt.params.poly.toString(16)} init 0x${alt.params.init.toString(16)} ` +
        `refin ${alt.params.refin} refout ${alt.params.refout} xorout 0x${alt.params.xorout.toString(16)}`,
    );
  } else {
    genuineMiss += 1;
    misses.push(
      `poly 0x${poly.toString(16)} init 0x${init.toString(16)} MISSED entirely (${found.length} candidates, ` +
        `${found.filter((f) => f.matches === f.total).length} fully verified)`,
    );
  }
}

console.log(`exact parameter set returned : ${exact}/40`);
console.log(`an equivalent set returned   : ${equivalentOnly}/40`);
console.log(`no usable answer at all      : ${genuineMiss}/40`);
for (const line of misses) console.log(`  ${line}`);

// A case the docs say is out of scope: refout differs from refin.
console.log('\n=== refin != refout with a private polynomial ===');
const poly = 0x8f57;
const messages = build(poly, 0x1234, true, false, 0);
const found = recoverCrc(messages);
console.log(`  recovered ${found.length} set(s); ${found.filter((f) => f.matches === f.total).length} verified on every message`);

// A case the docs also exclude: a 32-bit private polynomial.
console.log('\n=== 32-bit private polynomial ===');
const m32 = [];
for (let i = 0; i < 8; i++) {
  const body = Buffer.alloc(12 + i);
  for (let b = 0; b < body.length; b++) body[b] = (i * 53 + b * 11) & 0xff;
  const field = Buffer.alloc(4);
  field.writeUInt32BE(crcCompute(body, { width: 32, poly: 0x04c11db7, init: 0x12345678, refin: true, refout: true, xorout: 0 }), 0);
  m32.push(Buffer.concat([body, field]));
}
const started = Date.now();
const f32 = recoverCrc(m32, { widths: [16, 8] });
console.log(`  with the default widths: ${f32.length} set(s) in ${Date.now() - started} ms (documented: not searched)`);

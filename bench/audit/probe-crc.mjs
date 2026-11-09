// Is CRC parameter recovery exact, or does it find parameters that are not there?
//
// The documented claim is "100% verification or discard, no threshold to tune". A recovery that
// reports a parameter set for data containing no checksum would falsify that claim. The test
// feeds pure random messages with a random tail and counts how often something is reported.
import { Buffer } from 'node:buffer';
import { recoverCrc } from '../../dist/core/infer/crc-recovery.js';
import { crcCompute } from '../../dist/core/infer/checksum.js';

function rng(seed) {
  let x = (seed * 2654435761) >>> 0 || 1;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >> 17;
    x ^= x << 5;
    x >>>= 0;
    return x & 0xff;
  };
}

function randomMessages(seed, count, length) {
  const next = rng(seed);
  const out = [];
  for (let i = 0; i < count; i++) {
    const message = Buffer.alloc(length);
    for (let b = 0; b < length; b++) message[b] = next();
    out.push(message);
  }
  return out;
}

console.log('=== recovery on random data with no checksum ===');
console.log('messages  length  trials  reported  examples');
for (const [count, length] of [
  [5, 8],
  [5, 10],
  [6, 12],
  [6, 20],
  [8, 16],
  [10, 24],
]) {
  let reported = 0;
  const examples = [];
  const trials = 60;
  for (let trial = 0; trial < trials; trial++) {
    const messages = randomMessages(1000 + trial * 7 + count + length, count, length);
    const found = recoverCrc(messages);
    if (found.length > 0) {
      reported += 1;
      if (examples.length < 2) {
        const f = found[0];
        examples.push(`poly 0x${f.params.poly.toString(16)} init 0x${f.params.init.toString(16)} ${f.matches}/${f.total}`);
      }
    }
  }
  console.log(
    `${String(count).padStart(8)}  ${String(length).padStart(6)}  ${String(trials).padStart(6)}  ${String(reported).padStart(8)}  ${examples.join('; ')}`,
  );
}

console.log('\n=== recovery when a genuine private CRC is present ===');
let recovered = 0;
const trials = 40;
for (let trial = 0; trial < trials; trial++) {
  const poly = (0x8001 + ((trial * 733) % 0x7ffe)) | 1; // odd, 16-bit, private
  const init = (0x1000 + trial * 37) & 0xffff;
  const params = { width: 16, poly, init, refin: true, refout: true, xorout: 0 };
  const messages = [];
  for (let i = 0; i < 8; i++) {
    const body = Buffer.alloc(10 + (i % 5));
    for (let b = 0; b < body.length; b++) body[b] = (i * 31 + b * 17) & 0xff;
    const field = Buffer.alloc(2);
    field.writeUInt16LE(crcCompute(body, params), 0);
    messages.push(Buffer.concat([body, field]));
  }
  const found = recoverCrc(messages);
  const hit = found.some(
    (f) => f.params.poly === poly && f.params.init === init && f.matches === f.total,
  );
  if (hit) recovered += 1;
  else if (trial < 3) {
    console.log(`  miss: poly 0x${poly.toString(16)} init 0x${init.toString(16)} -> ${found.length} candidates`);
  }
}
console.log(`  recovered exactly ${recovered}/${trials}`);

console.log('\n=== recovery cost on a realistic message count ===');
const big = [];
for (let i = 0; i < 200; i++) {
  const body = Buffer.alloc(40 + (i % 17));
  for (let b = 0; b < body.length; b++) body[b] = (i * 13 + b * 7) & 0xff;
  const field = Buffer.alloc(2);
  field.writeUInt16BE(crcCompute(body, { width: 16, poly: 0x8f57, init: 0x1234, refin: true, refout: true, xorout: 0 }), 0);
  big.push(Buffer.concat([body, field]));
}
const started = Date.now();
const result = recoverCrc(big);
console.log(`  200 messages, 40-56 bytes each: ${Date.now() - started} ms, ${result.length} parameter set(s), best ${result[0]?.matches}/${result[0]?.total}`);

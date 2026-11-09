import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { ALGORITHMS, detectChecksum } from '../src/core/infer/checksum.js';

function crc16Modbus(data: Buffer): number {
  let crc = 0xffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? (crc >>> 1) ^ 0xa001 : crc >>> 1;
  }
  return crc & 0xffff;
}

function frame(sequence: number, body: string): Buffer {
  const header = Buffer.from([0xa5, 0x5a, sequence & 0xff]);
  const payload = Buffer.from(body, 'latin1');
  const message = Buffer.concat([header, payload]);
  const trailer = Buffer.alloc(2);
  trailer.writeUInt16LE(crc16Modbus(message), 0);
  return Buffer.concat([message, trailer]);
}

const messages = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta'].map((body, i) => frame(i, body));

test('crc16/modbus is found at the tail with full agreement', () => {
  const matches = detectChecksum(messages);
  const match = matches.find((candidate) => candidate.algorithm === 'crc16/modbus');
  assert.ok(match, `candidates were ${matches.map((m) => m.algorithm).join(', ')}`);
  assert.equal(match.offsetFromEnd, 0);
  assert.equal(match.width, 2);
  assert.equal(match.matches, match.total);
  assert.equal(match.confidence, 1);
});

test('a checksum is not invented for data that has none', () => {
  const random: Buffer[] = [];
  for (let i = 0; i < 40; i++) {
    const message = Buffer.alloc(16);
    for (let j = 0; j < message.length; j++) message[j] = (Math.floor(Math.random() * 256) + j * 7 + i) & 0xff;
    random.push(message);
  }
  // A 100% match over 40 random messages would be a false positive.
  assert.deepEqual(detectChecksum(random), []);
});

test('the algorithm table covers the common widths', () => {
  const widths = new Set(ALGORITHMS.map((algorithm) => algorithm.width));
  assert.deepEqual([...widths].sort(), [1, 2, 4]);
  assert.ok(ALGORITHMS.some((algorithm) => algorithm.name === 'crc32/ieee'));
});

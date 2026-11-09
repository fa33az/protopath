import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { inferFraming, isConfident } from '../src/core/infer/framing.js';
import { ALGORITHMS, crcCompute, detectChecksum } from '../src/core/infer/checksum.js';
import { inferSemantics } from '../src/core/infer/semantics.js';
import type { Field } from '../src/core/infer/fields.js';
import { analyzeFile } from '../src/core/pipeline.js';
import { capture, root } from './helpers.js';

/**
 * False positives and false negatives, per inference.
 *
 * A benchmark on protocols the tool has never seen (scripts/benchmark.mjs) measures how often it
 * is right. These tests measure the two ways it can be wrong: claiming something that is not
 * there, and staying silent about something that is. Both are failures, and the first is worse:
 * a wrong field model sends its reader down a blind alley, while silence leaves them where they
 * started.
 */

const ascii = (value: string): Buffer => Buffer.from(value, 'latin1');

// --- framing -------------------------------------------------------------------------------

test('random bytes rarely produce a confident framing claim', () => {
  // A tiling only proves the length byte happened to walk to the end. The structural-column
  // requirement is what separates that from a header, and this sweep measures the residue:
  // over 50 deterministic random buffers, no more than a tenth may clear the confidence bar.
  let confident = 0;
  for (let seed = 1; seed <= 50; seed++) {
    const stream = Buffer.alloc(600);
    let state = (seed * 2654435761) >>> 0 || 1;
    for (let i = 0; i < stream.length; i++) {
      state ^= state << 13;
      state >>>= 0;
      state ^= state >> 17;
      state ^= state << 5;
      state >>>= 0;
      stream[i] = state & 0xff;
    }
    if (isConfident(inferFraming(stream)[0])) confident += 1;
  }
  assert.ok(confident <= 5, `${confident} of 50 random streams were given a confident framing`);
});

test('prose without delimiters is not sold as length-prefixed', () => {
  const sentences = [
    'the gateway forwarded the packet to the collector and waited for an answer',
    'pressure readings arrived every two hundred and fifty milliseconds from channel two',
    'the operator restarted the service after the firmware update completed on the device',
  ];
  const stream = ascii(sentences.join('. ') + '. ');
  const best = inferFraming(stream)[0];
  assert.notEqual(best?.kind, 'length-prefix');
  if (best?.kind === 'length-prefix') assert.equal(isConfident(best), false);
});

test('a length field that does not describe its messages is rejected', () => {
  const parts: Buffer[] = [];
  for (let i = 0; i < 8; i++) {
    const body = ascii(`event-${i}-payload`);
    const header = Buffer.from([0x40, body.length + 40 + i]); // claims a length that is too large
    parts.push(Buffer.concat([header, body]));
  }
  const best = inferFraming(Buffer.concat(parts))[0];
  assert.equal(isConfident(best), false, `claimed ${best?.kind} at ${best?.score}`);
});

test('a two-byte final message does not hide a correct length framing', () => {
  const parts: Buffer[] = [];
  const bodies = ['reading-0', 'reading-01', 'reading-002', 'reading-1003', 'reading-20004', 'reading-300005'];
  bodies.forEach((body) => parts.push(Buffer.concat([Buffer.from([0x30, body.length]), ascii(body)])));
  parts.push(Buffer.from([0xe0, 0x00])); // the two-byte message that must not kill the parse
  const best = inferFraming(Buffer.concat(parts))[0];
  assert.equal(best?.kind, 'length-prefix');
  assert.deepEqual(best?.lengthPrefix, { lenOffset: 1, size: 1, endian: 'be', bias: 2 });
  assert.equal(best?.messages.length, 7);
});

test('a stream made of tiny fragments is not accepted as length-prefixed', () => {
  // Every byte here is a plausible one-byte length, which is exactly the trap: a tiling, not a
  // framing. The capture that exposed it was syslog over UDP.
  const stream = ascii('<13>1 2026-01-01T00:00:01Z host app 1 - hello <14>1 2026-01-01T00:00:02Z host app 1 - bye <11>1 2026-01-01T00:00:03Z host app 1 - ok');
  const lengthHypotheses = inferFraming(stream, { maxHypotheses: 20 }).filter((hypothesis) => hypothesis.kind === 'length-prefix');
  assert.equal(lengthHypotheses.some(isConfident), false, `claimed ${lengthHypotheses.map((h) => h.score.toFixed(2)).join(', ')}`);
});

// --- checksums -----------------------------------------------------------------------------

function trailer(messages: Buffer[], algorithm: string): Buffer[] {
  const compute = ALGORITHMS.find((entry) => entry.name === algorithm)!.compute;
  return messages.map((message) => {
    const field = Buffer.alloc(4);
    field.writeUInt32BE(compute(message), 0);
    return Buffer.concat([message, field]);
  });
}

test('a constant trailer byte is not reported as a checksum', () => {
  // Five equal-length messages whose bodies xor to a constant: the shape that produced a false
  // xor8 claim on a real HL7 capture.
  const messages: Buffer[] = [];
  for (let i = 0; i < 5; i++) {
    const body = Buffer.alloc(16, 0x41);
    body[10] = 0x40 + i;
    let xor = 0;
    for (let j = 0; j < 8; j++) xor ^= body[j]!;
    const filler = Buffer.alloc(8, xor); // keeps xor(body) constant while the body changes
    messages.push(Buffer.concat([body, filler, Buffer.from([0x0d])]));
  }
  assert.deepEqual(detectChecksum(messages), []);
});

test('five messages are not enough evidence for a checksum claim', () => {
  const messages = ['alpha', 'beta', 'gamma', 'delta', 'epsilon'].map((body) => ascii(body));
  assert.deepEqual(detectChecksum(trailer(messages, 'crc32/ieee')), []);
});

test('a 32-bit CRC at the tail is found with full agreement', () => {
  const messages = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta'].map((body) => ascii(body + '-payload'));
  const matches = detectChecksum(trailer(messages, 'crc32/ieee'));
  const match = matches.find((candidate) => candidate.algorithm === 'crc32/ieee');
  assert.ok(match, `candidates were ${matches.map((candidate) => candidate.algorithm).join(', ')}`);
  assert.equal(match.offsetFromEnd, 0);
  assert.equal(match.width, 4);
  assert.equal(match.matches, match.total);
});

test('a checksum over a range past byte eight is a documented miss, not a wrong answer', () => {
  const messages: Buffer[] = [];
  for (let i = 0; i < 8; i++) {
    const header = Buffer.alloc(12, 0x20 + i);
    const body = ascii(`body-${i}`);
    const message = Buffer.concat([header, body]);
    const field = Buffer.alloc(2);
    field.writeUInt16BE(crcCompute(message.subarray(10), { width: 16, poly: 0x1021, init: 0xffff, refin: false, refout: false, xorout: 0 }), 0);
    messages.push(Buffer.concat([message, field]));
  }
  const matches = detectChecksum(messages);
  assert.equal(
    matches.some((candidate) => candidate.algorithm === 'crc16/ccitt-false'),
    false,
    'a checksum outside the search window must not be reported',
  );
});

// --- semantics -----------------------------------------------------------------------------

test('a three-byte field does not throw, wherever it sits', () => {
  // A 24-bit counter is ordinary in binary protocols. The reader used to dispatch on width and
  // crashed on anything that was not 1, 2 or 4 bytes.
  const messages: Buffer[] = [];
  for (let i = 0; i < 6; i++) {
    const message = Buffer.alloc(20);
    message.writeUIntBE(i * 7, 8, 3);
    messages.push(message);
  }
  const fields: Field[] = [
    { name: 'counter24', role: 'counter', offset: 8, length: 3, anchor: 'head', stats: { distinct: 6 }, confidence: 0.8, evidence: ['test'] },
    { name: 'far', role: 'counter', offset: 18, length: 3, anchor: 'head', stats: { distinct: 6 }, confidence: 0.8, evidence: ['test'] },
  ];
  const semantics = inferSemantics(messages, fields);
  assert.ok(semantics.domains.some((domain) => domain.field === 'counter24'));
});

// --- protocol family -----------------------------------------------------------------------

test('a length-prefixed protocol outside the rule set gets no family label', () => {
  const analysis = analyzeFile(join(root, 'bench', 'corpus', 'dns-tcp.pcap'));
  assert.equal(analysis.flows[0]?.fingerprint, undefined);
});

test('real MQTT recorded from amqtt and paho is named MQTT', () => {
  const analysis = analyzeFile(join(root, 'bench', 'recorded', 'real-mqtt.pcap'));
  assert.equal(analysis.flows[0]?.fingerprint?.family, 'MQTT');
});

// --- no crashes on anything that ships ------------------------------------------------------

test('every shipped capture analyses without throwing', () => {
  const directories = [join(root, 'captures'), join(root, 'bench', 'corpus'), join(root, 'bench', 'recorded')];
  for (const directory of directories) {
    for (const name of readdirSync(directory).filter((file) => file.endsWith('.pcap') || file.endsWith('.pcapng'))) {
      assert.doesNotThrow(() => analyzeFile(join(directory, name), { maxFlows: 3 }), `${directory}/${name}`);
    }
  }
});

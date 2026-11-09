import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { inferFraming, isConfident } from '../src/core/infer/framing.js';

function lengthPrefixed(messages: string[]): Buffer {
  const parts: Buffer[] = [];
  for (const message of messages) {
    const body = Buffer.from(message, 'latin1');
    const total = body.length + 3;
    parts.push(Buffer.from([0xa5, 0x5a, total]), body);
  }
  return Buffer.concat(parts);
}

test('a length field with a constant header is recovered exactly', () => {
  const stream = lengthPrefixed(['hello', 'world', 'protopath', 'lengths', 'vary']);
  const best = inferFraming(stream)[0]!;

  assert.equal(best.kind, 'length-prefix');
  assert.deepEqual(best.lengthPrefix, { lenOffset: 2, size: 1, endian: 'be', bias: 0 });
  assert.equal(best.messages.length, 5);
  assert.equal(best.messages[2]!.subarray(3).toString('latin1'), 'protopath');
  assert.ok(isConfident(best));
});

test('a delimiter protocol is preferred over fixed-size guesses', () => {
  const stream = Buffer.from('PING\nGET temp\nSET led on\nACK 0\nDATA 23.5\n');
  const best = inferFraming(stream)[0]!;

  assert.equal(best.kind, 'delimiter');
  assert.equal(best.delimiter!.terminator.toString('hex'), '0a');
  assert.equal(best.messages.length, 5);
});

test('a repeating start marker segments the stream', () => {
  const parts = ['alpha', 'beta', 'gamma', 'delta'].map((word) => Buffer.from(`\x7e\x7e${word}`, 'latin1'));
  const best = inferFraming(Buffer.concat(parts))[0]!;

  assert.equal(best.kind, 'start-marker');
  assert.equal(best.startMarker!.marker.toString('hex'), '7e7e');
  assert.equal(best.messages.length, 4);
});

test('a single repeating byte is not accepted as a boundary', () => {
  const parts = ['alpha', 'beta', 'gamma', 'delta'].map((word) => Buffer.from(`\x7e${word}`, 'latin1'));
  const hypotheses = inferFraming(Buffer.concat(parts));
  // One byte carries too little evidence: it must never win outright.
  assert.notEqual(hypotheses[0]?.kind, 'start-marker');
});

test('noisy input is reported as unframed instead of being forced into a shape', () => {
  const noise = Buffer.alloc(97);
  for (let i = 0; i < noise.length; i++) noise[i] = (i * 37 + 11) & 0xff;

  const hypotheses = inferFraming(noise);
  const best = hypotheses[0]!;
  assert.ok(best.score <= 0.9, `unexpected confidence ${best.score} for noise`);
  if (best.kind !== 'unframed') {
    assert.ok(hypotheses.some((hypothesis) => hypothesis.kind === 'unframed'));
  }
});

test('every hypothesis explains the whole stream: no hypothesis leaves a residue', () => {
  const stream = lengthPrefixed(['one', 'two', 'three', 'four']);
  for (const hypothesis of inferFraming(stream)) {
    const covered = hypothesis.messages.reduce((sum, message) => sum + message.length, 0);
    assert.equal(covered, stream.length, `${hypothesis.kind} left bytes unexplained`);
  }
});

test('a stream shorter than any message yields nothing confident', () => {
  const hypotheses = inferFraming(Buffer.from([0x01, 0x02, 0x03]));
  assert.ok(hypotheses.every((hypothesis) => !isConfident(hypothesis)));
});

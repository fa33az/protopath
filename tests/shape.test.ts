import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { inferFields } from '../src/core/infer/fields.js';
import { inferFraming } from '../src/core/infer/framing.js';

/**
 * The header model, on inputs the fixtures do not contain.
 *
 * Every case here is a defect the proprietary benchmark found: a clock that jitters, a field that
 * steps by a stride other than one, a patterned payload that looks like a column of counters, and
 * two framing families that split a stream at the same offsets. Each one is locked down so a later
 * rule cannot quietly undo it.
 */

function rampPayload(messageCount: number, offset: number, length: number, messages: Buffer[]): void {
  for (let i = 0; i < messageCount; i++) {
    for (let b = offset; b < offset + length; b++) messages[i]![b] = (i * 31 + b * 7) & 0xff;
  }
}

test('a clock that jitters is a timestamp, not a magic plus one unknown byte', () => {
  const messages: Buffer[] = [];
  for (let i = 0; i < 10; i++) {
    const message = Buffer.alloc(20);
    // Epoch seconds, advancing by a varying amount: what a sender actually writes.
    message.writeUInt32BE(1_760_000_000 + i * 17 + (i % 3) * 5, 0);
    messages.push(message);
  }
  rampPayload(10, 4, 16, messages);

  const { fields, headerLength } = inferFields({ messages, framing: 'fixed' });
  const [first] = fields;

  assert.equal(first?.role, 'timestamp', `the first field was ${first?.role}`);
  assert.equal(first?.offset, 0);
  assert.equal(first?.length, 4);
  assert.equal(headerLength, 4, 'the clock is the whole header');
  assert.equal(fields[1]?.role, 'payload');
  assert.equal(fields[1]?.offset, 4);
});

test('a clock that advances by a constant amount is still a timestamp', () => {
  const messages: Buffer[] = [];
  for (let i = 0; i < 10; i++) {
    const message = Buffer.alloc(16);
    message.writeUInt32BE(1_760_000_000 + i * 250, 0);
    messages.push(message);
  }
  rampPayload(10, 4, 12, messages);

  const { fields } = inferFields({ messages, framing: 'fixed' });
  assert.equal(fields[0]?.role, 'timestamp');
  assert.equal(fields[0]?.stats.step, 250);
});

test('a field that steps by a stride is a sequence, and the header continues past it', () => {
  const messages: Buffer[] = [];
  for (let i = 0; i < 12; i++) {
    const message = Buffer.alloc(16);
    message[0] = 0xa5;
    message[1] = 0x5a;
    message.writeUInt16BE(i * 24, 2); // a byte offset into a file, as a block format has
    message[4] = 0x10 + (i % 3); // a message type
    for (let b = 5; b < 16; b++) message[b] = (i % 4) * 37 + b * 11;
    messages.push(message);
  }

  const { fields, headerLength } = inferFields({ messages, framing: 'fixed' });
  const counter = fields.find((field) => field.role === 'counter');

  assert.ok(counter, `no counter in ${fields.map((field) => `${field.role}@${field.offset}`).join(' ')}`);
  assert.equal(counter.offset, 2);
  assert.equal(counter.length, 2);
  assert.equal(counter.endian, 'be', 'the reading whose value advances by the smaller amount is the field');
  assert.equal(counter.stats.step, 24);
  assert.equal(fields.find((field) => field.role === 'opcode')?.offset, 4);
  assert.equal(headerLength, 5);
});

test('a payload that advances by a fixed stride is not a column of counters', () => {
  const messages: Buffer[] = [];
  for (let i = 0; i < 12; i++) {
    const message = Buffer.alloc(20);
    message[0] = 0xaa;
    message[1] = 0x55;
    message[2] = 20;
    messages.push(message);
  }
  rampPayload(12, 3, 17, messages);

  const { fields, headerLength } = inferFields({ messages, framing: 'length-prefix', lengthPrefix: { lenOffset: 2, size: 1, endian: 'be', bias: 0 } });

  assert.equal(fields.filter((field) => field.role === 'counter').length, 0, 'a ramp is data, not a header');
  assert.equal(headerLength, 3);
  assert.equal(fields.find((field) => field.role === 'payload')?.offset, 3);
});

test('a big-endian counter is not read little-endian just because that also steps', () => {
  const messages: Buffer[] = [];
  for (let i = 0; i < 10; i++) {
    const message = Buffer.alloc(12);
    message.writeUInt16BE(400 + i, 0);
    for (let b = 2; b < 12; b++) message[b] = (i % 5) * 13 + b;
    messages.push(message);
  }

  const counter = inferFields({ messages, framing: 'fixed' }).fields.find((field) => field.role === 'counter');
  assert.ok(counter);
  assert.equal(counter.endian, 'be');
  assert.equal(counter.stats.step, 1);
});

test('two families that split at the same offsets say so instead of choosing silently', () => {
  // Every message opens with aa55 and ends with 03, and neither byte pair occurs anywhere else.
  const stream = Buffer.concat(
    Array.from({ length: 5 }, (_, i) => Buffer.from([0xaa, 0x55, 0x10 + i, 0x20 + i, 0x30, 0x03])),
  );

  const hypotheses = inferFraming(stream);
  const kinds = new Set(hypotheses.map((hypothesis) => hypothesis.kind));
  assert.ok(kinds.has('start-marker'), `family list was ${[...kinds].join(', ')}`);
  assert.ok(kinds.has('delimiter'), 'the terminator parse was lost');

  const noted = hypotheses.some((hypothesis) =>
    hypothesis.limitations.some((limitation) => limitation.includes('same offsets')),
  );
  assert.ok(noted, 'a competing parse split at identical offsets and nothing said so');
});

test('0x0a on its own does not beat the 0x0d0a it belongs to', () => {
  const bodies: Buffer[] = [];
  for (let i = 0; i < 6; i++) {
    // A newline inside the text makes the 0x0a parse find more boundaries than the 0x0d0a one.
    bodies.push(Buffer.from(`STATUS ${i}\nreading nominal\r\n`, 'latin1'));
  }
  const stream = Buffer.concat(bodies);

  const hypotheses = inferFraming(stream);
  const delimiters = hypotheses.filter((hypothesis) => hypothesis.kind === 'delimiter');
  const best = delimiters.sort((a, b) => b.score - a.score)[0];

  assert.ok(best, `no delimiter parse at all; families were ${hypotheses.map((h) => h.kind).join(', ')}`);
  assert.equal(best.delimiter?.terminator.toString('hex'), '0d0a', `reported 0x${best.delimiter?.terminator.toString('hex')}`);
  assert.equal(best.messages.length, 6, 'the shorter terminator split the stream at the newlines inside the text');
});

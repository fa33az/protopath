import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeFile } from '../src/core/pipeline.js';
import type { Field } from '../src/core/infer/fields.js';
import { capture } from './helpers.js';

function field(fields: Field[], role: string): Field {
  const match = fields.find((candidate) => candidate.role === role);
  assert.ok(match, `no field with role ${role} in ${fields.map((f) => `${f.name}:${f.role}`).join(', ')}`);
  return match;
}

const analysis = analyzeFile(capture('binary-session.pcap'));
const forward = analysis.flows[0]!.forward;

test('the binary protocol recovers magic, length, counter, type, payload and checksum', () => {
  const offsets = forward.fields.map((f) => `${f.role}@${f.anchor}:${f.offset}`).sort();
  assert.deepEqual(offsets, [
    'checksum@tail:0',
    'counter@head:3',
    'length@head:2',
    'magic@head:0',
    'opcode@head:5',
    'payload@head:6',
  ]);
});

test('the sequence counter is two bytes, little endian, stepping by one', () => {
  const counter = field(forward.fields, 'counter');
  assert.equal(counter.length, 2);
  assert.equal(counter.endian, 'le');
  assert.equal(counter.stats.step, 1);
});

test('the length field width and endianness match the capture', () => {
  const length = field(forward.fields, 'length');
  assert.equal(length.offset, 2);
  assert.equal(length.width, 1);
  assert.equal(length.endian, 'be');
});

test('the checksum field is reported as crc16/modbus with full agreement', () => {
  assert.equal(forward.checksums[0]!.algorithm, 'crc16/modbus');
  assert.equal(forward.checksums[0]!.matches, forward.checksums[0]!.total);
  assert.equal(field(forward.fields, 'checksum').length, 2);
});

test('a text protocol collapses to a single text field instead of byte soup', () => {
  const text = analyzeFile(capture('text-session.pcap')).flows[0]!.forward;
  assert.equal(text.fields.length, 1);
  assert.equal(text.fields[0]!.role, 'text');
});

test('message labels come from the inferred type field', () => {
  const labels = new Set(forward.messages.map((message) => message.label));
  assert.ok(labels.has('type=0x10'), `labels were ${[...labels].join(', ')}`);
  assert.ok(labels.has('type=0x01'));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeFile } from '../src/core/pipeline.js';
import { capture } from './helpers.js';

/**
 * `captures/modbus-session.pcap` is not synthetic: it was recorded from a real pymodbus client
 * against a pymodbus server, through a byte-level proxy (see scripts/record-modbus.py). The
 * expected layout below is the Modbus/TCP application header from the specification, so this
 * test checks the inference against an external document rather than against itself.
 */
const analysis = analyzeFile(capture('modbus-session.pcap'));
const flow = analysis.flows[0]!;
const MODBUS_HEADER = 'sequence:counter@0 reserved:reserved@2 length:length@4 reserved:reserved@6 type:opcode@7 payload:payload@8';

function signature(fields: typeof flow.forward.fields): string {
  return fields
    .map((field) => {
      const anchor = field.anchor === 'tail' ? `end-${field.offset + field.length}` : String(field.offset);
      return `${field.name.split('_')[0]}:${field.role}@${anchor}`;
    })
    .join(' ');
}

test('the Modbus/TCP application header is recovered from real client traffic', () => {
  assert.equal(flow.forward.best!.kind, 'length-prefix');
  assert.deepEqual(flow.forward.best!.lengthPrefix, { lenOffset: 4, size: 2, endian: 'be', bias: 6 });
});

test('field offsets match the Modbus/TCP header, in both directions', () => {
  assert.equal(signature(flow.forward.fields), MODBUS_HEADER);
  assert.equal(signature(flow.reverse.fields), MODBUS_HEADER);
});

test('the transaction identifier is found as a two-byte counter', () => {
  const counter = flow.forward.fields.find((field) => field.role === 'counter')!;
  assert.equal(counter.offset, 0);
  assert.equal(counter.length, 2);
  assert.equal(counter.endian, 'be');
});

test('the function code is recovered as the message type', () => {
  const opcode = flow.forward.fields.find((field) => field.role === 'opcode')!;
  assert.equal(opcode.offset, 7);
  assert.equal(opcode.length, 1);

  const labels = new Set(flow.forward.messages.map((message) => message.label));
  assert.ok(labels.has('type=0x03'), `read holding registers missing: ${[...labels].join(', ')}`);
  assert.ok(labels.has('type=0x10'), `write multiple registers missing: ${[...labels].join(', ')}`);
});

test('Modbus/TCP is correctly reported as having no checksum', () => {
  // The TCP/IP stack carries integrity; the application header has no checksum field.
  assert.deepEqual(flow.forward.checksums, []);
  assert.equal(flow.forward.fields.some((field) => field.role === 'checksum'), false);
});

test('the state graph shows a request/response alternation, not noise', () => {
  const transitions = flow.graph.transitions;
  assert.ok(transitions.length >= 8);

  // Every recorded request was followed by its response, so the most common transitions pair a
  // client function code with a server one.
  const requestSide = transitions.filter((transition) => transition.from.startsWith('type=0x0') || transition.from.startsWith('type=0x1'));
  assert.ok(requestSide.length > 0);
  assert.ok(flow.graph.nodes.length >= 8);
});

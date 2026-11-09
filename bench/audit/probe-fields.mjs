// Field, semantics and grammar behaviour on inputs the fixture suite does not cover.
import { Buffer } from 'node:buffer';
import { inferFields, fieldSpan, fieldValue } from '../../dist/core/infer/fields.js';
import { inferSemantics } from '../../dist/core/infer/semantics.js';
import { inferGrammar } from '../../dist/core/infer/grammar.js';
import { inferFraming } from '../../dist/core/infer/framing.js';
import { labelMessage, buildStateGraph } from '../../dist/core/infer/state.js';

const show = (label, fields) =>
  console.log(
    `  ${label.padEnd(40)} ${fields.map((f) => `${f.name}:${f.role}@${f.offset}:${f.length === -1 ? 'var' : f.length}`).join(' ')}`,
  );

console.log('=== field inference ===');

// A header whose first byte is a constant, second a counter starting at 7 with step 3.
{
  const messages = [];
  for (let i = 0; i < 8; i++) {
    const m = Buffer.alloc(12);
    m[0] = 0x42;
    m[1] = (7 + i * 3) & 0xff;
    m[2] = i % 3;
    m[3] = i % 5;
    for (let b = 4; b < 12; b++) m[b] = (i * 13 + b) & 0xff;
    messages.push(m);
  }
  show('constant, +3 step, two small sets', inferFields({ messages, framing: 'fixed' }).fields);
}

// A 4-byte field that climbs by 250 each message: a counter, not a timestamp.
{
  const messages = [];
  for (let i = 0; i < 8; i++) {
    const m = Buffer.alloc(16);
    m.writeUInt32BE(1760000000 + i * 250, 0);
    for (let b = 4; b < 16; b++) m[b] = (i * 7 + b) & 0xff;
    messages.push(m);
  }
  const fields = inferFields({ messages, framing: 'fixed' }).fields;
  show('unix seconds climbing by 250', fields);
  const semantics = inferSemantics(messages, fields);
  for (const domain of semantics.domains) console.log(`    ${domain.field}: ${domain.domain} (${domain.confidence}) ${domain.note.slice(0, 70)}`);
}

// Two messages only: the minimum the field layer will consider.
{
  const messages = [Buffer.from([1, 2, 3, 4, 5, 6]), Buffer.from([1, 9, 3, 4, 5, 6])];
  try {
    show('two messages', inferFields({ messages, framing: 'fixed' }).fields);
  } catch (error) {
    console.log(`  two messages: THREW ${error.message}`);
  }
}

// One message.
{
  try {
    show('one message', inferFields({ messages: [Buffer.from([1, 2, 3, 4])], framing: 'fixed' }).fields);
  } catch (error) {
    console.log(`  one message: THREW ${error.message}`);
  }
}

// Message lengths that differ by a lot, with a tail-anchored field.
{
  const messages = [Buffer.alloc(20), Buffer.alloc(120), Buffer.alloc(64)];
  for (let i = 0; i < messages.length; i++) messages[i].writeUInt16BE(i, messages[i].length - 2);
  const fields = inferFields({ messages, framing: 'length-prefix', lengthPrefix: { lenOffset: 0, size: 1, endian: 'be', bias: 0 } }).fields;
  show('lengths 20, 120, 64 with a tail field', fields);
  for (const field of fields) {
    const span = fieldSpan(messages[0], field);
    console.log(`    ${field.name} anchored ${field.anchor} offset ${field.offset} len ${field.length} -> span ${JSON.stringify(span)} of ${messages[0].length} bytes`);
  }
}

// A tail-anchored field that cannot fit the shortest message.
{
  const field = { name: 'tail', role: 'checksum', anchor: 'tail', offset: 2, length: 2, stats: { distinct: 1 }, confidence: 1, evidence: [] };
  const short = Buffer.from([0, 1]);
  console.log(`    tail field in a 2-byte message: span ${JSON.stringify(fieldSpan(short, field))}, value ${fieldValue(short, field)}`);
}

console.log('\n=== grammar on one-sided traffic ===');
{
  const requests = [];
  for (let i = 0; i < 6; i++) {
    const body = `GET /x${i} HTTP/1.1\r\n`;
    requests.push(Buffer.from(body, 'latin1'));
  }
  const grammar = inferGrammar([{ direction: 'forward', messages: requests, timestamps: requests.map((_, i) => 1760000000 + i) }]);
  console.log(`  requests only: ${JSON.stringify(grammar).slice(0, 200)}`);
}
{
  const grammar = inferGrammar([{ direction: 'forward', messages: [], timestamps: [] }]);
  console.log(`  empty direction: ${JSON.stringify(grammar).slice(0, 160)}`);
}

console.log('\n=== state graph ===');
{
  const messages = [];
  for (let i = 0; i < 6; i++) {
    const m = Buffer.alloc(8);
    m[0] = i % 2 === 0 ? 0x01 : 0x02;
    m[1] = i;
    messages.push(m);
  }
  const fields = inferFields({ messages, framing: 'fixed' }).fields;
  const records = messages.map((bytes, i) => ({
    direction: i % 2 === 0 ? 'forward' : 'reverse',
    offset: i * 8,
    ts: 1760000000 + i,
    bytes,
    label: labelMessage(bytes, i % 2 === 0 ? 'forward' : 'reverse', fields),
  }));
  const graph = buildStateGraph(records, fields);
  console.log(`  nodes ${graph.nodes.length}, edges ${graph.edges.length}`);
  for (const edge of graph.edges.slice(0, 6)) console.log(`    ${edge.from} -> ${edge.to} x${edge.count}`);
}

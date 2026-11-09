// The documented value domains include `timestamp`. Does a real timestamp ever get there?
import { Buffer } from 'node:buffer';
import { inferFields } from '../../dist/core/infer/fields.js';
import { inferSemantics } from '../../dist/core/infer/semantics.js';

function build(deltas) {
  const messages = [];
  let clock = 1760000000;
  for (let i = 0; i < 10; i++) {
    const m = Buffer.alloc(20);
    m.writeUInt32BE(clock, 0);
    clock += deltas[i % deltas.length];
    m[4] = i;
    for (let b = 5; b < 20; b++) m[b] = (i * 23 + b * 11) & 0xff;
    messages.push(m);
  }
  return messages;
}

function report(label, deltas) {
  const messages = build(deltas);
  const fields = inferFields({ messages, framing: 'fixed' }).fields;
  const semantics = inferSemantics(messages, fields);
  console.log(`\n  ${label}`);
  console.log(`    fields: ${fields.map((f) => `${f.name}:${f.role}@${f.offset}:${f.length === -1 ? 'var' : f.length}`).join(' ')}`);
  const domains = semantics.domains.map((d) => `${d.field}=${d.domain}`);
  console.log(`    domains: ${domains.join(', ') || 'none'}`);
}

console.log('=== a 4-byte unix timestamp at offset 0, jittered as a real clock is ===');
report('steps 1,1,1,1 (a perfect counter)', [1]);
report('steps varying 1..6 ms as a real sender would', [1, 2, 1, 3, 1, 2, 4, 1]);
report('steps 250, 90, 1000, 30', [250, 90, 1000, 30]);
report('seconds, one per message, with gaps', [1, 1, 2, 1, 3]);

console.log('\n=== a 4-byte millisecond timestamp ===');
{
  const messages = [];
  let clock = 1760000000123;
  for (let i = 0; i < 10; i++) {
    const m = Buffer.alloc(24);
    // 1760000000123 does not fit a double bit-exactly, so write the low 32 bits.
    m.writeUInt32BE(clock % 0x100000000, 0);
    clock += 17 + (i % 5);
    for (let b = 4; b < 24; b++) m[b] = (i * 29 + b * 7) & 0xff;
    messages.push(m);
  }
  const fields = inferFields({ messages, framing: 'fixed' }).fields;
  const semantics = inferSemantics(messages, fields);
  console.log(`    fields: ${fields.map((f) => `${f.name}:${f.role}@${f.offset}:${f.length === -1 ? 'var' : f.length}`).join(' ')}`);
  console.log(`    domains: ${semantics.domains.map((d) => `${d.field}=${d.domain}`).join(', ') || 'none'}`);
}

console.log('\n=== a counter that steps by the record size, as an offset field does ===');
{
  const messages = [];
  for (let i = 0; i < 10; i++) {
    const m = Buffer.alloc(16);
    m.writeUInt16BE(i * 24, 0); // byte offset into a file
    m[2] = 0xa5;
    m[3] = i % 4;
    for (let b = 4; b < 16; b++) m[b] = (i * 17 + b * 5) & 0xff;
    messages.push(m);
  }
  const fields = inferFields({ messages, framing: 'fixed' }).fields;
  console.log(`    fields: ${fields.map((f) => `${f.name}:${f.role}@${f.offset}:${f.length === -1 ? 'var' : f.length}`).join(' ')}`);
  const semantics = inferSemantics(messages, fields);
  console.log(`    domains: ${semantics.domains.map((d) => `${d.field}=${d.domain}`).join(', ') || 'none'}`);
}

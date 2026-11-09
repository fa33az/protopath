#!/usr/bin/env node
// Measures where the time goes on a capture larger than the fixtures.
//
// Run with `npm run profile`. The numbers are printed, not asserted: the point is to have a
// measured basis for saying whether the tool needs a rewrite or a faster inner loop, and to
// notice when a change makes one stage an order of magnitude slower.
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { Buffer } from 'node:buffer';
import { tcpFrame, writePcap } from '../dist-test/scripts/pcap-writer.js';
import { analyzeFile, buildFlows, loadCapture, analyzeFlow } from '../dist/index.js';

const out = join('bench', 'profile');
mkdirSync(out, { recursive: true });

/** A stream of length-prefixed messages with a counter, a type and a CRC-free body. */
function message(index) {
  const body = Buffer.from(`reading=${index % 97};state=${index % 5 === 0 ? 'on' : 'off'};unit=C`, 'ascii');
  const total = 6 + body.length;
  const head = Buffer.alloc(6);
  head.writeUInt16BE(0xa55a, 0);
  head.writeUInt8(total, 2);
  head.writeUInt16BE(index & 0xffff, 3);
  head.writeUInt8(index % 4, 5);
  return Buffer.concat([head, body]);
}

function buildSingleStream(count) {
  const records = [];
  let seq = 1000;
  for (let i = 0; i < count; i++) {
    const payload = message(i);
    records.push({ ts: 1_760_000_000 + i * 0.001, data: tcpFrame('10.3.0.10', 40000, '10.3.0.20', 9000, seq, 5000, payload) });
    seq += payload.length;
  }
  return records;
}

function buildManyFlows(flows, perFlow) {
  const records = [];
  for (let f = 0; f < flows; f++) {
    let seq = 1000;
    for (let i = 0; i < perFlow; i++) {
      const payload = message(i + f * perFlow);
      records.push({
        ts: 1_760_000_000 + f * 10 + i * 0.001,
        data: tcpFrame('10.4.0.10', 41000 + f, '10.4.0.20', 9100, seq, 5000, payload),
      });
      seq += payload.length;
    }
  }
  return records;
}

function time(label, work) {
  const started = process.hrtime.bigint();
  const value = work();
  const millis = Number(process.hrtime.bigint() - started) / 1e6;
  console.log(`${label.padEnd(44)} ${millis.toFixed(1).padStart(9)} ms`);
  return { value, millis };
}

function report(name, records) {
  const path = join(out, `${name}.pcap`);
  writePcap(path, records);
  const bytes = records.reduce((sum, record) => sum + record.data.length, 0);
  console.log(`\n${name}: ${records.length} frames, ${(bytes / 1024 / 1024).toFixed(2)} MB on the wire`);

  const loaded = time('load and decode frames', () => loadCapture(path));
  const flows = time('group into flows', () => buildFlows(loaded.value.frames));
  const firstFlow = time('analyse one flow', () => analyzeFlow(flows.value[0]));
  const whole = time('analyse the whole capture', () => analyzeFile(path, { maxFlows: 3 }));

  const payloadBytes = records.length * 64; // rough: one message per frame
  console.log(
    `  first flow: ${firstFlow.value.forward.messageCount + firstFlow.value.reverse.messageCount} messages, ` +
      `${(payloadBytes / 1024 / 1024).toFixed(2)} MB estimated payload, ` +
      `${(payloadBytes / 1024 / 1024 / (firstFlow.millis / 1000)).toFixed(1)} MB/s`,
  );
  void whole;
}

report('single-stream', buildSingleStream(20000));
report('many-flows', buildManyFlows(200, 100));

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseCapture } from '../src/core/pcap/reader.js';
import { framesFromCapture } from '../src/core/net/decode.js';
import { capture } from './helpers.js';

test('classic pcap decodes every frame of the binary session', () => {
  const raw = parseCapture(readFileSync(capture('binary-session.pcap')));
  assert.equal(raw.format, 'pcap');
  assert.equal(raw.records.length, 62);
  assert.equal(raw.records[0]!.linkType, 1);

  const { frames, skipped } = framesFromCapture(raw.records);
  assert.equal(frames.length, 62);
  assert.equal(skipped, 0);
  assert.ok(frames.every((frame) => frame.transport === 'tcp'));
});

test('pcapng decodes to the same streams as the classic file', () => {
  const pcap = framesFromCapture(parseCapture(readFileSync(capture('binary-session.pcap'))).records);
  const pcapng = framesFromCapture(parseCapture(readFileSync(capture('binary-session.pcapng'))).records);

  assert.equal(pcapng.frames.length, pcap.frames.length);
  assert.deepEqual(
    pcapng.frames.map((frame) => frame.payload.toString('hex')),
    pcap.frames.map((frame) => frame.payload.toString('hex')),
  );

  const firstPcap = pcap.frames[0]!.ts;
  const firstPcapng = pcapng.frames[0]!.ts;
  assert.ok(Math.abs(firstPcap - firstPcapng) < 0.001, 'timestamps agree within a millisecond');
});

test('UDP captures decode the datagram payload exactly', () => {
  const { frames } = framesFromCapture(parseCapture(readFileSync(capture('sensor-udp.pcap'))).records);
  assert.equal(frames.length, 24);
  assert.equal(frames[0]!.transport, 'udp');
  assert.equal(frames[0]!.payload.length, 12);
  assert.equal(frames[0]!.payload.subarray(0, 2).toString('hex'), 'aa55');
});

test('a file that is not a capture is rejected with a clear message', () => {
  assert.throws(() => parseCapture(Buffer.from('not a capture at all')), /not a pcap/);
});

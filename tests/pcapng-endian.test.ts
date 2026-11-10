import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { parseCapture } from '../src/core/pcap/reader.js';
import { framesFromCapture } from '../src/core/net/decode.js';

/**
 * pcapng in both byte orders.
 *
 * Block types are written in the section's byte order. A big-endian section header writes an IDB
 * type as `00 00 00 01`, which is `0x01000000` when read little-endian, so a reader that assumes
 * little-endian silently skips every block in the file and returns an empty capture. Nothing
 * throws and nothing warns: the pipeline just says it found no payload. The file below is legal
 * pcapng, and these tests pin both orders to the same frames.
 */

const SHB = 0x0a0d0d0a;
const IDB = 0x00000001;
const EPB = 0x00000006;
const BOM = 0x1a2b3c4d;

function pad4(n: number): number {
  return (4 - (n % 4)) % 4;
}

/** One Ethernet frame carrying an IPv4/UDP datagram, enough for the decoder to reach the payload. */
function udpFrame(payload: Buffer): Buffer {
  const udp = Buffer.alloc(8 + payload.length);
  udp.writeUInt16BE(4000, 0);
  udp.writeUInt16BE(5000, 2);
  udp.writeUInt16BE(8 + payload.length, 4);
  payload.copy(udp, 8);

  const ip = Buffer.alloc(20 + udp.length);
  ip[0] = 0x45;
  ip.writeUInt16BE(20 + udp.length, 2);
  ip[8] = 64;
  ip[9] = 17;
  ip.writeUInt32BE(0x0a000001, 12);
  ip.writeUInt32BE(0x0a000002, 16);
  udp.copy(ip, 20);

  const ether = Buffer.alloc(14 + ip.length);
  ether.set([0x02, 0, 0, 0, 0, 0x02], 0);
  ether.set([0x02, 0, 0, 0, 0, 0x01], 6);
  ether.writeUInt16BE(0x0800, 12);
  ip.copy(ether, 14);
  return ether;
}

function writeU32(value: number, endian: 'le' | 'be'): Buffer {
  const out = Buffer.alloc(4);
  if (endian === 'le') out.writeUInt32LE(value, 0);
  else out.writeUInt32BE(value, 0);
  return out;
}

function writeU16(value: number, endian: 'le' | 'be'): Buffer {
  const out = Buffer.alloc(2);
  if (endian === 'le') out.writeUInt16LE(value, 0);
  else out.writeUInt16BE(value, 0);
  return out;
}

function block(type: number, body: Buffer, endian: 'le' | 'be'): Buffer {
  const total = 12 + body.length;
  return Buffer.concat([writeU32(type, endian), writeU32(total, endian), body, writeU32(total, endian)]);
}

function pcapng(frames: Buffer[], endian: 'le' | 'be'): Buffer {
  const section = block(
    SHB,
    Buffer.concat([
      writeU32(BOM, endian),
      writeU16(1, endian),
      writeU16(0, endian),
      writeU32(0xffffffff, endian), // section length: unknown
    ]),
    endian,
  );

  const idb = block(
    IDB,
    Buffer.concat([writeU16(1, endian), writeU16(0, endian), writeU32(262144, endian)]),
    endian,
  );

  const packets = frames.map((frame, index) => {
    const padded = Buffer.concat([frame, Buffer.alloc(pad4(frame.length))]);
    return block(
      EPB,
      Buffer.concat([
        writeU32(0, endian), // interface id
        writeU32(0, endian), // timestamp high
        writeU32(1_760_000_000 + index, endian), // timestamp low, microseconds
        writeU32(frame.length, endian),
        writeU32(frame.length, endian),
        padded,
      ]),
      endian,
    );
  });

  return Buffer.concat([section, idb, ...packets]);
}

const payloads = [Buffer.from('alpha'), Buffer.from('beta'), Buffer.from('gamma')];
const expected = payloads.map((payload) => payload.toString('hex'));

test('a big-endian pcapng is not an empty capture', () => {
  const raw = parseCapture(pcapng(payloads.map(udpFrame), 'be'));

  assert.equal(raw.format, 'pcapng');
  assert.equal(raw.records.length, payloads.length, 'the big-endian blocks were skipped');
  assert.ok(raw.records.every((record) => record.linkType === 1));
});

test('both byte orders of the same capture decode to the same payloads', () => {
  const read = (endian: 'le' | 'be'): string[] => {
    const raw = parseCapture(pcapng(payloads.map(udpFrame), endian));
    return framesFromCapture(raw.records).frames.map((frame) => frame.payload.toString('hex'));
  };

  assert.deepEqual(read('be'), expected, 'big-endian decoded to something other than the datagrams');
  assert.deepEqual(read('le'), expected);
});

test('timestamps survive the big-endian read', () => {
  const raw = parseCapture(pcapng(payloads.map(udpFrame), 'be'));
  const stamps = raw.records.map((record) => record.ts);

  // No if_tsresol option is written, so the default is microseconds: ticks / 1e6.
  assert.equal(stamps.length, 3);
  stamps.forEach((stamp, index) => {
    assert.ok(Math.abs(stamp - (1760 + index / 1e6)) < 1e-9, `record ${index} carried ${stamp}`);
  });
});

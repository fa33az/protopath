import { Buffer } from 'node:buffer';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Builds the captures that ship with the repository.
 *
 * The protocols here are synthetic and documented in docs/captures.md, so every inference
 * result in the test suite has a ground truth to be checked against. Nothing is recorded
 * from a third party, which keeps the fixtures redistributable.
 */

const CLIENT_MAC = Buffer.from('02:00:00:00:00:01'.replace(/:/g, ''), 'hex');
const SERVER_MAC = Buffer.from('02:00:00:00:00:02'.replace(/:/g, ''), 'hex');

interface PcapRecord {
  ts: number;
  data: Buffer;
}

function main(): void {
  const out = join(process.cwd(), 'captures');
  mkdirSync(out, { recursive: true });

  const binary = binarySession();
  writePcap(join(out, 'binary-session.pcap'), binary);
  writePcapng(join(out, 'binary-session.pcapng'), binary);
  writePcap(join(out, 'binary-session-v2.pcap'), binarySessionV2());
  writePcap(join(out, 'text-session.pcap'), textSession());
  writePcap(join(out, 'sensor-udp.pcap'), sensorSession());

  console.log(`wrote captures to ${out}`);
}

// ---------------------------------------------------------------------------
// synthetic protocols
// ---------------------------------------------------------------------------

const MAGIC = Buffer.from([0xa5, 0x5a]);

const OP_PING = 0x01;
const OP_PONG = 0x02;
const OP_READ = 0x10;
const OP_DATA = 0x11;
const OP_ERROR = 0x20;

const READ_KEYS = ['uptime', 'temperature', 'firmware', 'channel', 'gain', 'mode', 'led', 'threshold', 'sample_rate', 'serial'];
const DATA_VALUES = ['14203', '21.75', '1.4.7', '11', '0.5', 'auto', 'on', '0.62', '48000', 'SN-0042'];
const ERROR_VALUES = ['unknown key', 'busy', 'bad argument'];

/**
 * Layout: magic(2) length(1) sequence(2 LE) type(1) payload(n) checksum(2 LE, crc16/modbus).
 * The length byte counts the whole message, checksum included.
 */
function encodeBinary(sequence: number, type: number, payload: Buffer): Buffer {
  const total = 6 + payload.length + 2;
  const message = Buffer.alloc(total);
  MAGIC.copy(message, 0);
  message.writeUInt8(total, 2);
  message.writeUInt16LE(sequence & 0xffff, 3);
  message.writeUInt8(type, 5);
  payload.copy(message, 6);
  message.writeUInt16LE(crc16Modbus(message.subarray(0, total - 2)), total - 2);
  return message;
}

/**
 * Version 2 drops the type byte: magic(2) length(1) sequence(2 LE) payload(n) checksum(2).
 * It exists so `protopath diff` has something real to compare.
 */
function encodeBinaryV2(sequence: number, payload: Buffer): Buffer {
  const total = 5 + payload.length + 2;
  const message = Buffer.alloc(total);
  MAGIC.copy(message, 0);
  message.writeUInt8(total, 2);
  message.writeUInt16LE(sequence & 0xffff, 3);
  payload.copy(message, 5);
  message.writeUInt16LE(crc16Modbus(message.subarray(0, total - 2)), total - 2);
  return message;
}

function crc16Modbus(data: Buffer): number {
  let crc = 0xffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? (crc >>> 1) ^ 0xa001 : crc >>> 1;
  }
  return crc & 0xffff;
}

function binarySession(): PcapRecord[] {
  const frames: PcapRecord[] = [];
  let ts = 1_780_000_000.0;
  let clientSeq = 1000;
  let serverSeq = 9000;
  let clientCounter = 1;
  let serverCounter = 1;
  const advance = (): number => {
    ts += 0.004;
    return ts;
  };

  for (let round = 0; round < 8; round++) {
    const key = READ_KEYS[round % READ_KEYS.length]!;
    const read = encodeBinary(clientCounter++, OP_READ, Buffer.from(key));
    frames.push(...tcpExchange('10.0.0.10', 41000, '10.0.0.20', 7401, clientSeq, serverSeq, read, advance));
    clientSeq += read.length;

    const value = DATA_VALUES[round % DATA_VALUES.length]!;
    const data = encodeBinary(serverCounter++, OP_DATA, Buffer.from(`${key}=${value}`));
    frames.push(...tcpExchange('10.0.0.20', 7401, '10.0.0.10', 41000, serverSeq, clientSeq, data, advance));
    serverSeq += data.length;

    if (round === 3) {
      const ping = encodeBinary(clientCounter++, OP_PING, Buffer.alloc(0));
      frames.push(...tcpExchange('10.0.0.10', 41000, '10.0.0.20', 7401, clientSeq, serverSeq, ping, advance));
      clientSeq += ping.length;
      const pong = encodeBinary(serverCounter++, OP_PONG, Buffer.alloc(0));
      frames.push(...tcpExchange('10.0.0.20', 7401, '10.0.0.10', 41000, serverSeq, clientSeq, pong, advance));
      serverSeq += pong.length;
    }
    if (round === 5) {
      const bad = encodeBinary(clientCounter++, OP_READ, Buffer.from('nope'));
      frames.push(...tcpExchange('10.0.0.10', 41000, '10.0.0.20', 7401, clientSeq, serverSeq, bad, advance));
      clientSeq += bad.length;
      const err = encodeBinary(serverCounter++, OP_ERROR, Buffer.from(ERROR_VALUES[0]!));
      frames.push(...tcpExchange('10.0.0.20', 7401, '10.0.0.10', 41000, serverSeq, clientSeq, err, advance));
      serverSeq += err.length;
    }
  }

  return frames;
}

function binarySessionV2(): PcapRecord[] {
  const frames: PcapRecord[] = [];
  let ts = 1_780_100_000.0;
  let clientSeq = 5000;
  let serverSeq = 5100;

  for (let round = 0; round < 8; round++) {
    const key = READ_KEYS[round % READ_KEYS.length]!;
    const read = encodeBinaryV2(round + 1, Buffer.from(key));
    frames.push(...tcpExchange('10.0.0.10', 42000, '10.0.0.20', 7401, clientSeq, serverSeq, read, () => (ts += 0.003)));
    clientSeq += read.length;

    const value = DATA_VALUES[round % DATA_VALUES.length]!;
    const data = encodeBinaryV2(round + 101, Buffer.from(`${key}=${value}`));
    frames.push(...tcpExchange('10.0.0.20', 7401, '10.0.0.10', 42000, serverSeq, clientSeq, data, () => (ts += 0.003)));
    serverSeq += data.length;
  }

  return frames;
}

function textSession(): PcapRecord[] {
  const frames: PcapRecord[] = [];
  let ts = 1_780_200_000.0;
  let clientSeq = 700;
  let serverSeq = 1700;
  const advance = (): number => (ts += 0.005);

  const exchange = [
    ['PING', 'PONG'],
    ['GET temp', 'DATA 23.5'],
    ['SET led on', 'ACK 0'],
    ['GET uptime', 'DATA 40213'],
    ['SET mode auto', 'ACK 0'],
    ['GET serial', 'DATA SN-0042'],
    ['GET bogus', 'ERR unknown key'],
    ['PING', 'PONG'],
  ] as const;

  for (const [request, response] of exchange) {
    const outbound = Buffer.from(`${request}\n`);
    frames.push(...tcpExchange('10.0.0.10', 43000, '10.0.0.20', 7402, clientSeq, serverSeq, outbound, advance));
    clientSeq += outbound.length;

    const inbound = Buffer.from(`${response}\n`);
    frames.push(...tcpExchange('10.0.0.20', 7402, '10.0.0.10', 43000, serverSeq, clientSeq, inbound, advance));
    serverSeq += inbound.length;
  }

  return frames;
}

function sensorSession(): PcapRecord[] {
  const frames: PcapRecord[] = [];
  let ts = 1_780_300_000.0;

  for (let i = 0; i < 24; i++) {
    // origin(2 AA55) state(1) sequence(1) temperature(2 BE) humidity(2 BE) node(1) reserved(3)
    const record = Buffer.alloc(12);
    record.writeUInt16BE(0xaa55, 0);
    record.writeUInt8(i % 2 === 0 ? 0x10 : 0x11, 2);
    record.writeUInt8(i & 0xff, 3);
    record.writeInt16BE(2000 + i * 7, 4);
    record.writeUInt16BE(4100 + i * 3, 6);
    record.writeUInt8(3, 8);
    frames.push({
      ts: (ts += 0.05),
      data: udpFrame('10.0.0.30', 50000, '10.0.0.40', 7403, record),
    });
  }

  return frames;
}

// ---------------------------------------------------------------------------
// packet building
// ---------------------------------------------------------------------------

function tcpExchange(
  srcIp: string,
  srcPort: number,
  dstIp: string,
  dstPort: number,
  seq: number,
  ack: number,
  payload: Buffer,
  advance: () => number,
): PcapRecord[] {
  const records: PcapRecord[] = [];
  // One segment split in three to exercise reassembly, including one out-of-order and one
  // retransmitted segment. The first segment of each exchange is kept whole and in order so
  // the capture still looks like a normal conversation to a human reading it.
  const split = payload.length > 12 ? [0, 5, 9, payload.length] : [0, payload.length];
  const segments = split.slice(1).map((end, i) => ({ start: split[i]!, end, seq: seq + split[i]! }));

  const ordered = [] as typeof segments;
  for (let i = 0; i < segments.length; i += 2) {
    const first = segments[i];
    const second = segments[i + 1];
    if (second) ordered.push(second, first);
    else if (first) ordered.push(first);
  }

  for (const segment of ordered) {
    const slice = payload.subarray(segment.start, segment.end);
    records.push({
      ts: advance(),
      data: tcpFrame(srcIp, srcPort, dstIp, dstPort, segment.seq, ack, slice),
    });
  }

  if (payload.length > 12 && ordered[0]) {
    // A retransmission of the first segment, as a stack would send after a lost ACK.
    const first = segments[0]!;
    records.push({
      ts: advance(),
      data: tcpFrame(srcIp, srcPort, dstIp, dstPort, first.seq, ack, payload.subarray(first.start, first.end)),
    });
  }

  return records;
}

function tcpFrame(srcIp: string, srcPort: number, dstIp: string, dstPort: number, seq: number, ack: number, payload: Buffer): Buffer {
  const tcp = Buffer.alloc(20 + payload.length);
  tcp.writeUInt16BE(srcPort, 0);
  tcp.writeUInt16BE(dstPort, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(ack >>> 0, 8);
  tcp.writeUInt8(5 << 4, 12);
  tcp.writeUInt8(0x18, 13);
  tcp.writeUInt16BE(8000, 14);
  payload.copy(tcp, 20);
  tcp.writeUInt16BE(tcpChecksum(srcIp, dstIp, tcp), 16);
  return ipv4Frame(srcIp, dstIp, 6, tcp);
}

function udpFrame(srcIp: string, srcPort: number, dstIp: string, dstPort: number, payload: Buffer): Buffer {
  const udp = Buffer.alloc(8 + payload.length);
  udp.writeUInt16BE(srcPort, 0);
  udp.writeUInt16BE(dstPort, 2);
  udp.writeUInt16BE(udp.length, 4);
  payload.copy(udp, 8);
  udp.writeUInt16BE(udpChecksum(srcIp, dstIp, udp), 6);
  return ipv4Frame(srcIp, dstIp, 17, udp);
}

function ipv4Frame(srcIp: string, dstIp: string, protocol: number, payload: Buffer): Buffer {
  const ethernet = Buffer.alloc(14);
  SERVER_MAC.copy(ethernet, 6);
  CLIENT_MAC.copy(ethernet, 0);
  ethernet.writeUInt16BE(0x0800, 12);

  const ip = Buffer.alloc(20);
  ip.writeUInt8(0x45, 0);
  ip.writeUInt16BE(20 + payload.length, 2);
  ip.writeUInt16BE(0x4000, 6);
  ip.writeUInt8(64, 8);
  ip.writeUInt8(protocol, 9);
  ip.writeUInt32BE(ipToInt(srcIp), 12);
  ip.writeUInt32BE(ipToInt(dstIp), 16);
  ip.writeUInt16BE(ipChecksum(ip), 10);

  return Buffer.concat([ethernet, ip, payload]);
}

function ipv4HeaderForChecksum(ip: string): Buffer {
  const header = Buffer.alloc(12);
  ip.split('.').forEach((part, i) => header.writeUInt8(Number(part), i));
  header.writeUInt8(0, 9);
  header.writeUInt16BE(6, 10);
  return header;
}

function tcpChecksum(srcIp: string, dstIp: string, segment: Buffer): number {
  const pseudo = Buffer.concat([ipv4HeaderForChecksum(srcIp), ipv4HeaderForChecksum(dstIp), Buffer.from([0, 6])]);
  const length = Buffer.alloc(2);
  length.writeUInt16BE(segment.length, 0);
  return checksum(Buffer.concat([pseudo, length, segment]));
}

function udpChecksum(srcIp: string, dstIp: string, datagram: Buffer): number {
  const pseudo = Buffer.concat([ipv4HeaderForChecksum(srcIp), ipv4HeaderForChecksum(dstIp), Buffer.from([0, 17])]);
  const length = Buffer.alloc(2);
  length.writeUInt16BE(datagram.length, 0);
  const sum = checksum(Buffer.concat([pseudo, length, datagram]));
  return sum === 0 ? 0xffff : sum;
}

function ipChecksum(header: Buffer): number {
  return checksum(header);
}

function checksum(data: Buffer): number {
  let sum = 0;
  for (let i = 0; i + 1 < data.length; i += 2) sum += data.readUInt16BE(i);
  if (data.length % 2 === 1) sum += data[data.length - 1]! << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

function ipToInt(ip: string): number {
  return ip.split('.').reduce((value, part) => value * 256 + Number(part), 0) >>> 0;
}

// ---------------------------------------------------------------------------
// container writers
// ---------------------------------------------------------------------------

function writePcap(path: string, records: PcapRecord[]): void {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(0, 8);
  header.writeUInt32LE(0, 12);
  header.writeUInt32LE(262144, 16);
  header.writeUInt32LE(1, 20);

  const chunks: Buffer[] = [header];
  for (const record of records) {
    const buffer = Buffer.alloc(16);
    const seconds = Math.floor(record.ts);
    const micros = Math.round((record.ts - seconds) * 1_000_000);
    buffer.writeUInt32LE(seconds, 0);
    buffer.writeUInt32LE(micros, 4);
    buffer.writeUInt32LE(record.data.length, 8);
    buffer.writeUInt32LE(record.data.length, 12);
    chunks.push(buffer, record.data);
  }

  writeFileSync(path, Buffer.concat(chunks));
}

function writePcapng(path: string, records: PcapRecord[]): void {
  const blocks: Buffer[] = [];

  const shbBody = Buffer.alloc(16);
  shbBody.writeUInt32LE(0x1a2b3c4d, 0);
  shbBody.writeUInt16LE(1, 4);
  shbBody.writeUInt16LE(0, 6);
  shbBody.writeUInt32LE(0xffffffff, 8);
  shbBody.writeUInt32LE(0xffffffff, 12);
  blocks.push(block(0x0a0d0d0a, shbBody));

  const idbBody = Buffer.alloc(8);
  idbBody.writeUInt16LE(1, 0);
  idbBody.writeUInt16LE(0, 2);
  idbBody.writeUInt32LE(262144, 4);
  blocks.push(block(1, idbBody));

  for (const record of records) {
    const padded = Buffer.alloc((record.data.length + 3) & ~3);
    record.data.copy(padded, 0);
    const body = Buffer.alloc(20 + padded.length);
    body.writeUInt32LE(0, 0);
    const ticks = BigInt(Math.round(record.ts * 1_000_000));
    body.writeUInt32LE(Number(ticks >> 32n), 4);
    body.writeUInt32LE(Number(ticks & 0xffffffffn), 8);
    body.writeUInt32LE(record.data.length, 12);
    body.writeUInt32LE(record.data.length, 16);
    padded.copy(body, 20);
    blocks.push(block(6, body));
  }

  writeFileSync(path, Buffer.concat(blocks));
}

function block(type: number, body: Buffer): Buffer {
  const total = 12 + body.length;
  const header = Buffer.alloc(8);
  header.writeUInt32LE(type, 0);
  header.writeUInt32LE(total, 4);
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(total, 0);
  return Buffer.concat([header, body, trailer]);
}

main();

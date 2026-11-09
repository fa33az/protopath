import { Buffer } from 'node:buffer';
import { writeFileSync } from 'node:fs';

/**
 * Packet construction and pcap/pcapng container writing.
 *
 * Shared by the fixture generator and the benchmark corpus generator. The code is deliberately
 * plain: every byte that can vary is written explicitly, so a regenerated capture is bit-for-bit
 * identical to the committed one.
 */

export const CLIENT_MAC = Buffer.from('02:00:00:00:00:01'.replace(/:/g, ''), 'hex');
export const SERVER_MAC = Buffer.from('02:00:00:00:00:02'.replace(/:/g, ''), 'hex');

export interface PcapRecord {
  ts: number;
  data: Buffer;
}

/** One payload per TCP segment, in order, no retransmission. Used for recorded benchmarks. */
export function simpleTcpExchange(
  srcIp: string,
  srcPort: number,
  dstIp: string,
  dstPort: number,
  seq: number,
  ack: number,
  payload: Buffer,
  advance: () => number,
): PcapRecord[] {
  return [{ ts: advance(), data: tcpFrame(srcIp, srcPort, dstIp, dstPort, seq, ack, payload) }];
}

export function tcpExchange(
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

export function tcpFrame(srcIp: string, srcPort: number, dstIp: string, dstPort: number, seq: number, ack: number, payload: Buffer): Buffer {
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

export function udpFrame(srcIp: string, srcPort: number, dstIp: string, dstPort: number, payload: Buffer): Buffer {
  const udp = Buffer.alloc(8 + payload.length);
  udp.writeUInt16BE(srcPort, 0);
  udp.writeUInt16BE(dstPort, 2);
  udp.writeUInt16BE(udp.length, 4);
  payload.copy(udp, 8);
  udp.writeUInt16BE(udpChecksum(srcIp, dstIp, udp), 6);
  return ipv4Frame(srcIp, dstIp, 17, udp);
}

export function ipv4Frame(srcIp: string, dstIp: string, protocol: number, payload: Buffer): Buffer {
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

export function writePcap(path: string, records: PcapRecord[]): void {
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

export function writePcapng(path: string, records: PcapRecord[]): void {
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

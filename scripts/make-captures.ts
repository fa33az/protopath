import { Buffer } from 'node:buffer';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tcpExchange, udpFrame, writePcap, writePcapng, type PcapRecord } from './pcap-writer.js';

/**
 * Builds the captures that ship with the repository.
 *
 * The protocols here are synthetic and documented in docs/captures.md, so every inference
 * result in the test suite has a ground truth to be checked against. Nothing is recorded
 * from a third party, which keeps the fixtures redistributable.
 */

function main(): void {
  const out = join(process.cwd(), 'captures');
  mkdirSync(out, { recursive: true });

  const binary = binarySession();
  writePcap(join(out, 'binary-session.pcap'), binary);
  writePcapng(join(out, 'binary-session.pcapng'), binary);
  writePcap(join(out, 'binary-session-v2.pcap'), binarySessionV2());
  writePcap(join(out, 'text-session.pcap'), textSession());
  writePcap(join(out, 'sensor-udp.pcap'), sensorSession());
  writePcap(join(out, 'custom-crc.pcap'), customChecksumSession());

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

// The polynomial and initial value below are not in any published catalogue. That is the point
// of this fixture: nothing named matches it, so the only way to describe the check field is to
// solve for it from the messages. The parameters are still recoverable exactly.
const CUSTOM_POLY = 0x8f57;
const CUSTOM_INIT = 0x1234;

function crc16Custom(data: Buffer): number {
  let crc = CUSTOM_INIT;
  for (const byte of data) {
    let value = byte;
    let reflected = 0;
    for (let bit = 0; bit < 8; bit++) {
      reflected = (reflected << 1) | (value & 1);
      value >>= 1;
    }
    crc ^= reflected << 8;
    for (let bit = 0; bit < 8; bit++) crc = crc & 0x8000 ? ((crc << 1) ^ CUSTOM_POLY) & 0xffff : (crc << 1) & 0xffff;
  }
  let out = 0;
  for (let bit = 0; bit < 16; bit++) out = (out << 1) | ((crc >> bit) & 1);
  return out & 0xffff;
}

/** Layout: length(2 BE, total - 2) sequence(2 BE) type(1) payload(n) checksum(2 LE). */
function encodeCustom(sequence: number, type: number, payload: Buffer): Buffer {
  const total = 5 + payload.length + 2;
  const message = Buffer.alloc(total);
  message.writeUInt16BE(total - 2, 0);
  message.writeUInt16BE(sequence & 0xffff, 2);
  message.writeUInt8(type, 4);
  payload.copy(message, 5);
  message.writeUInt16LE(crc16Custom(message.subarray(0, total - 2)), total - 2);
  return message;
}

const CUSTOM_KEYS = ['uptime', 'mode', 'serial', 'gain', 'led', 'channel', 'rate', 'threshold'];
const CUSTOM_VALUES = ['40213', 'auto', 'SN-0042', '0.5', 'on', '11', '48000', '0.62'];

function customChecksumSession(): PcapRecord[] {
  const frames: PcapRecord[] = [];
  let ts = 1_780_400_000.0;
  let clientSeq = 3000;
  let serverSeq = 4000;
  const advance = (): number => (ts += 0.006);

  for (let round = 0; round < 10; round++) {
    const key = CUSTOM_KEYS[round % CUSTOM_KEYS.length]!;
    const value = CUSTOM_VALUES[round % CUSTOM_VALUES.length]!;

    const request = encodeCustom(round + 1, 0x21, Buffer.from(key));
    frames.push(...tcpExchange('10.0.0.50', 44000, '10.0.0.60', 7404, clientSeq, serverSeq, request, advance));
    clientSeq += request.length;

    const response = encodeCustom(0x400 + round, 0x22, Buffer.from(`${key}=${value}`));
    frames.push(...tcpExchange('10.0.0.60', 7404, '10.0.0.50', 44000, serverSeq, clientSeq, response, advance));
    serverSeq += response.length;
  }

  return frames;
}
main();

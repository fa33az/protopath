import { Buffer } from 'node:buffer';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tcpFrame, udpFrame, writePcap, type PcapRecord } from '../../scripts/pcap-writer.js';

/**
 * Proprietary protocol corpus.
 *
 * No protocol here was designed by hand. Each one is drawn from a parameter space — framing
 * family, header primitives and their order, checksum family and placement, payload style — and
 * serialised. That matters for one reason: a protocol written by hand to be interesting is a
 * protocol written with the inference code in mind. A protocol drawn from a seed is not.
 *
 * The generator writes both the capture and the ground truth, and it refuses to run if its own
 * CRC implementations disagree with the published check values, because a corpus whose answers are
 * wrong measures nothing.
 *
 *     npm run bench:proprietary:corpus
 *     npm run bench:proprietary
 *
 * Everything is deterministic: the same seed produces the same bytes.
 */

// ---------------------------------------------------------------------------
// deterministic random
// ---------------------------------------------------------------------------

class Random {
  private state: number;

  constructor(seed: number) {
    this.state = (seed * 2654435761) >>> 0 || 1;
  }

  next(): number {
    let x = this.state;
    x ^= x << 13;
    x >>>= 0;
    x ^= x >> 17;
    x ^= x << 5;
    x >>>= 0;
    this.state = x;
    return x;
  }

  /** Integer in [low, high]. */
  int(low: number, high: number): number {
    return low + (this.next() % (high - low + 1));
  }

  pick<T>(items: readonly T[]): T {
    return items[this.int(0, items.length - 1)]!;
  }

  chance(percent: number): boolean {
    return this.int(1, 100) <= percent;
  }

  bytes(length: number): Buffer {
    const out = Buffer.alloc(length);
    for (let i = 0; i < length; i++) out[i] = this.next() & 0xff;
    return out;
  }
}

// ---------------------------------------------------------------------------
// checksums, with a self check against published values
// ---------------------------------------------------------------------------

interface CrcParams {
  width: 8 | 16 | 32;
  poly: number;
  init: number;
  refin: boolean;
  refout: boolean;
  xorout: number;
}

function reflect(value: number, bits: number): number {
  let out = 0;
  for (let bit = 0; bit < bits; bit++) out = (out << 1) | ((value >> bit) & 1);
  return out >>> 0;
}

function crcCompute(data: Buffer, params: CrcParams): number {
  const mask = params.width === 32 ? 0xffffffff : params.width === 16 ? 0xffff : 0xff;
  const top = params.width === 32 ? 0x80000000 : params.width === 16 ? 0x8000 : 0x80;
  let crc = (params.init & mask) >>> 0;
  for (const raw of data) {
    const byte = params.refin ? reflect(raw, 8) : raw;
    if (params.width === 32) crc = (crc ^ (byte << 24)) >>> 0;
    else if (params.width === 16) crc = (crc ^ (byte << 8)) >>> 0;
    else crc = (crc ^ byte) >>> 0;
    for (let bit = 0; bit < 8; bit++) {
      const carry = (crc & top) !== 0;
      crc = (crc << 1) >>> 0;
      if (carry) crc = (crc ^ params.poly) >>> 0;
      if (params.width !== 32) crc = crc & mask;
    }
  }
  if (params.refout) crc = reflect(crc, params.width);
  return ((crc ^ params.xorout) & mask) >>> 0;
}

function sum8(data: Buffer): number {
  let sum = 0;
  for (const byte of data) sum = (sum + byte) & 0xff;
  return sum;
}

function xor8(data: Buffer): number {
  let value = 0;
  for (const byte of data) value ^= byte;
  return value;
}

function sum16(data: Buffer): number {
  let sum = 0;
  for (const byte of data) sum = (sum + byte) & 0xffff;
  return sum;
}

function fletcher16(data: Buffer): number {
  let low = 0;
  let high = 0;
  for (const byte of data) {
    low = (low + byte) % 255;
    high = (high + low) % 255;
  }
  return (high << 8) | low;
}

function fletcher32(data: Buffer): number {
  let low = 0;
  let high = 0;
  for (let i = 0; i < data.length; i += 2) {
    const word = i + 1 < data.length ? (data[i]! << 8) | data[i + 1]! : data[i]!;
    low = (low + word) % 65535;
    high = (high + low) % 65535;
  }
  return ((high << 16) | low) >>> 0;
}

/** The published check value for "123456789". A wrong CRC here would corrupt every ground truth. */
const SELF_CHECK: Array<[string, () => number, number]> = [
  ['crc32/ieee', () => crcCompute(Buffer.from('123456789'), { width: 32, poly: 0x04c11db7, init: 0xffffffff, refin: true, refout: true, xorout: 0xffffffff }), 0xcbf43926],
  ['crc16/arc', () => crcCompute(Buffer.from('123456789'), { width: 16, poly: 0x8005, init: 0x0000, refin: true, refout: true, xorout: 0 }), 0xbb3d],
  ['crc16/ccitt-false', () => crcCompute(Buffer.from('123456789'), { width: 16, poly: 0x1021, init: 0xffff, refin: false, refout: false, xorout: 0 }), 0x29b1],
  ['crc16/xmodem', () => crcCompute(Buffer.from('123456789'), { width: 16, poly: 0x1021, init: 0x0000, refin: false, refout: false, xorout: 0 }), 0x31c3],
  ['crc16/x25', () => crcCompute(Buffer.from('123456789'), { width: 16, poly: 0x1021, init: 0xffff, refin: true, refout: true, xorout: 0xffff }), 0x906e],
  ['crc16/kermit', () => crcCompute(Buffer.from('123456789'), { width: 16, poly: 0x1021, init: 0x0000, refin: true, refout: true, xorout: 0 }), 0x2189],
  ['crc8/atm', () => crcCompute(Buffer.from('123456789'), { width: 8, poly: 0x07, init: 0x00, refin: false, refout: false, xorout: 0 }), 0xf4],
];

function verifySelfCheck(): void {
  for (const [name, compute, expected] of SELF_CHECK) {
    const actual = compute();
    if (actual !== expected) {
      throw new Error(`${name} self check failed: produced 0x${actual.toString(16)}, published 0x${expected.toString(16)}`);
    }
  }
}

// ---------------------------------------------------------------------------
// the parameter space
// ---------------------------------------------------------------------------

type Endian = 'le' | 'be';

interface LengthField {
  offset: number;
  width: 1 | 2 | 4;
  endian: Endian;
  bias: number;
}

type Framing =
  | { kind: 'length-prefix'; length: LengthField }
  | { kind: 'start-marker'; marker: Buffer }
  | { kind: 'delimiter'; terminator: Buffer }
  | { kind: 'unframed' };

type HeaderPart =
  | { kind: 'magic'; bytes: Buffer }
  | { kind: 'version'; value: number }
  | { kind: 'type'; values: number[] }
  | { kind: 'counter'; width: 1 | 2 | 4; endian: Endian; step: number; start: number }
  | { kind: 'timestamp'; endian: Endian; base: number; jitter: number }
  | { kind: 'flags'; mask: number }
  | { kind: 'reserved'; width: number }
  | { kind: 'length' };

type ChecksumKind =
  | { family: 'crc'; params: CrcParams }
  | { family: 'sum8' }
  | { family: 'xor8' }
  | { family: 'sum16' }
  | { family: 'fletcher16' }
  | { family: 'fletcher32' };

interface ChecksumSpec {
  kind: ChecksumKind;
  width: 1 | 2 | 4;
  endian: Endian;
  /** Bytes between the checksum field and the end of the message. */
  offsetFromEnd: number;
  /** Where the covered range starts. */
  rangeStart: number;
}

type PayloadStyle = 'ascii-kv' | 'ascii-words' | 'binary' | 'noise';

interface ProtocolSpec {
  seed: number;
  name: string;
  transport: 'tcp' | 'udp';
  framing: Framing;
  header: HeaderPart[];
  checksum: ChecksumSpec | null;
  payload: PayloadStyle;
  messageCount: number;
}

const MARKERS = ['a55a', '7e7e', 'd5c3', 'aa55', 'cafe', '1acf'] as const;
const TERMINATORS = ['00', '0a', '0d0a', 'ff', '03'] as const;

const CRC_NAMES: Array<{ name: string; params: CrcParams }> = [
  { name: 'crc16/modbus', params: { width: 16, poly: 0x8005, init: 0xffff, refin: true, refout: true, xorout: 0 } },
  { name: 'crc16/ccitt-false', params: { width: 16, poly: 0x1021, init: 0xffff, refin: false, refout: false, xorout: 0 } },
  { name: 'crc16/xmodem', params: { width: 16, poly: 0x1021, init: 0x0000, refin: false, refout: false, xorout: 0 } },
  { name: 'crc16/arc', params: { width: 16, poly: 0x8005, init: 0x0000, refin: true, refout: true, xorout: 0 } },
  { name: 'crc32/ieee', params: { width: 32, poly: 0x04c11db7, init: 0xffffffff, refin: true, refout: true, xorout: 0xffffffff } },
  { name: 'crc8/atm', params: { width: 8, poly: 0x07, init: 0x00, refin: false, refout: false, xorout: 0 } },
];

function drawChecksum(random: Random): ChecksumSpec | null {
  if (random.chance(30)) return null;
  const family = random.int(0, 5);
  const offsetFromEnd = random.chance(85) ? 0 : 1;
  const rangeStart = random.chance(80) ? 0 : random.int(1, 4);
  if (family === 0) {
    // A private polynomial and a private seed, the case the catalogue cannot name.
    const params: CrcParams = {
      width: 16,
      poly: (0x8001 + random.int(0, 0x3ffe)) | 1,
      init: random.int(0, 0xffff),
      refin: random.chance(60),
      refout: random.chance(60),
      xorout: random.chance(50) ? random.int(0, 0xffff) : 0,
    };
    return { kind: { family: 'crc', params }, width: 2, endian: random.pick(['le', 'be'] as const), offsetFromEnd, rangeStart };
  }
  if (family === 1) {
    const named = random.pick(CRC_NAMES);
    const width = named.params.width === 32 ? 4 : named.params.width === 16 ? 2 : 1;
    // A one-byte field has no byte order; recording one would be a truth the bytes cannot show.
    return {
      kind: { family: 'crc', params: named.params },
      width,
      endian: width === 1 ? 'be' : random.pick(['le', 'be'] as const),
      offsetFromEnd,
      rangeStart,
    };
  }
  if (family === 2) return { kind: { family: 'sum8' }, width: 1, endian: 'be', offsetFromEnd, rangeStart };
  if (family === 3) return { kind: { family: 'xor8' }, width: 1, endian: 'be', offsetFromEnd, rangeStart };
  if (family === 4) return { kind: { family: 'sum16' }, width: 2, endian: random.pick(['le', 'be'] as const), offsetFromEnd, rangeStart };
  return { kind: { family: random.chance(70) ? 'fletcher16' : 'fletcher32' }, width: random.chance(70) ? 2 : 4, endian: 'be', offsetFromEnd, rangeStart };
}

function drawHeader(random: Random, framing: Framing): HeaderPart[] {
  const parts: HeaderPart[] = [];

  // The framing bytes must not also appear inside the header: a terminator that is also the
  // version byte, or a marker that is also the magic, makes a protocol that cannot be split at
  // all, and the ground truth would be describing bytes that do not exist.
  const markerHex = framing.kind === 'start-marker' ? framing.marker.toString('hex') : null;
  const terminatorHex = framing.kind === 'delimiter' ? framing.terminator.toString('hex') : null;
  const magicPool = MARKERS.filter((hex) => hex !== markerHex && (terminatorHex === null || !hex.includes(terminatorHex)));

  if (random.chance(45)) parts.push({ kind: 'magic', bytes: Buffer.from(random.pick(magicPool), 'hex') });
  if (random.chance(30)) parts.push({ kind: 'version', value: random.int(1, 4) });
  if (random.chance(70)) {
    const count = random.int(2, 6);
    const base = random.int(1, 30);
    parts.push({ kind: 'type', values: Array.from({ length: count }, (_, i) => base + i) });
  }
  if (random.chance(55)) {
    parts.push({
      kind: 'counter',
      width: random.pick([1, 2, 4] as const),
      endian: random.pick(['le', 'be'] as const),
      step: random.chance(60) ? 1 : random.int(2, 12),
      start: random.int(0, 0xffff),
    });
  }
  if (random.chance(35)) {
    parts.push({ kind: 'timestamp', endian: random.pick(['le', 'be'] as const), base: 1_760_000_000 + random.int(0, 100000), jitter: random.int(1, 900) });
  }
  if (random.chance(30)) parts.push({ kind: 'flags', mask: random.int(1, 3) });
  if (random.chance(35)) parts.push({ kind: 'reserved', width: random.int(1, 3) });

  // The length field can be anywhere, including in the middle of the other parts.
  if (framing.kind === 'length-prefix') {
    const at = random.int(0, parts.length);
    parts.splice(at, 0, { kind: 'length' });
  }

  if (parts.length === 0) parts.push({ kind: 'magic', bytes: Buffer.from('aa55', 'hex') });
  return parts;
}

function drawFraming(random: Random): Framing {
  const roll = random.int(0, 99);
  if (roll < 62) {
    const width = random.pick([1, 2, 4] as const);
    return {
      kind: 'length-prefix',
      length: {
        offset: -1, // filled in once the header order is known
        width,
        // A one-byte field has no byte order; recording one would be a truth the bytes cannot show.
        endian: width === 1 ? 'be' : random.pick(['le', 'be'] as const),
        bias: random.pick([0, 0, 0, -1, 1, 2, 4, -2, -4, 6, -6] as const),
      },
    };
  }
  if (roll < 78) return { kind: 'start-marker', marker: Buffer.from(random.pick(MARKERS), 'hex') };
  if (roll < 94) return { kind: 'delimiter', terminator: Buffer.from(random.pick(TERMINATORS), 'hex') };
  return { kind: 'unframed' };
}

function drawProtocol(seed: number): ProtocolSpec {
  const random = new Random(seed);
  const transport = random.chance(80) ? 'tcp' : 'udp';
  const framing = drawFraming(random);
  const header = drawHeader(random, framing);
  const checksum = drawChecksum(random);
  // A terminator has to be the last thing in the message, so a check field cannot sit after it:
  // the frame would contain the terminator in the middle and split into two.
  if (checksum && framing.kind === 'delimiter') checksum.offsetFromEnd = 0;
  const payload = random.pick(['ascii-kv', 'ascii-words', 'binary', 'noise'] as const);
  const messageCount = random.int(8, 18);
  return { seed, name: `proto-${String(seed).padStart(4, '0')}`, transport, framing, header, checksum, payload, messageCount };
}

// ---------------------------------------------------------------------------
// serialisation
// ---------------------------------------------------------------------------

function writeInt(value: number, width: 1 | 2 | 4, endian: Endian): Buffer {
  const out = Buffer.alloc(width);
  if (width === 1) out[0] = value & 0xff;
  else if (width === 2) endian === 'le' ? out.writeUInt16LE(value & 0xffff, 0) : out.writeUInt16BE(value & 0xffff, 0);
  else endian === 'le' ? out.writeUInt32LE(value >>> 0, 0) : out.writeUInt32BE(value >>> 0, 0);
  return out;
}

function computeChecksum(kind: ChecksumKind, data: Buffer): number {
  switch (kind.family) {
    case 'crc':
      return crcCompute(data, kind.params);
    case 'sum8':
      return sum8(data);
    case 'xor8':
      return xor8(data);
    case 'sum16':
      return sum16(data);
    case 'fletcher16':
      return fletcher16(data);
    case 'fletcher32':
      return fletcher32(data);
  }
}

/** Bytes that must never appear in a payload, or the ground truth framing would be a lie. */
function forbidden(spec: ProtocolSpec): Buffer[] {
  const out: Buffer[] = [];
  if (spec.framing.kind === 'start-marker') out.push(spec.framing.marker);
  if (spec.framing.kind === 'delimiter') out.push(spec.framing.terminator);
  for (const part of spec.header) if (part.kind === 'magic') out.push(part.bytes);
  return out;
}

function makePayload(random: Random, style: PayloadStyle, length: number, banned: Buffer[]): Buffer {
  let out: Buffer;
  if (style === 'ascii-kv') {
    const base = Buffer.from(`ch=${random.int(0, 9)};v=${(random.int(0, 5000) / 100).toFixed(2)};u=C;`, 'latin1');
    out = Buffer.alloc(length);
    for (let i = 0; i < length; i++) out[i] = base[i % base.length]!;
  } else if (style === 'ascii-words') {
    const base = Buffer.from('status ok reading nominal threshold nominal ', 'latin1');
    out = Buffer.alloc(length);
    for (let i = 0; i < length; i++) out[i] = base[i % base.length]!;
  } else if (style === 'binary') {
    out = Buffer.alloc(length);
    for (let i = 0; i < length; i++) out[i] = 0x30 + ((i * 7 + random.int(0, 3)) % 0x50);
  } else {
    out = random.bytes(length);
  }
  // Remove any byte sequence the framing would treat as a boundary.
  for (const sequence of banned) {
    if (sequence.length === 0) continue;
    for (let at = 0; at + sequence.length <= out.length; at++) {
      if (out.subarray(at, at + sequence.length).equals(sequence)) out[at] = (sequence[0]! + 1) & 0xff;
    }
  }
  return out;
}

interface Rendered {
  message: Buffer;
  headerLength: number;
  /** Bytes between the checksum field and the end of the message, as the bytes actually show. */
  checksumOffsetFromEnd: number;
  checksumFieldStart: number;
}

/**
 * Serialises one message.
 *
 * The framing has to appear in the bytes or the ground truth is fiction: a declared start marker
 * is written at the head of every message, a declared terminator at the tail. Both sit outside the
 * drawn header, exactly as they would in a real protocol. The framing bytes are also guaranteed to
 * occur exactly once per message — a terminator that also shows up in a counter or a checksum makes
 * a protocol nothing can split, and scoring the tool against it would measure nothing.
 */
function render(spec: ProtocolSpec, random: Random, index: number): Rendered {
  for (let attempt = 0; attempt < 64; attempt++) {
    const rendered = renderOnce(spec, random, index);
    const bytes = rendered.message;
    if (spec.framing.kind === 'start-marker') {
      const marker = spec.framing.marker;
      if (bytes.subarray(0, marker.length).equals(marker) && bytes.indexOf(marker, 1) === -1) return rendered;
      continue;
    }
    if (spec.framing.kind === 'delimiter') {
      const terminator = spec.framing.terminator;
      const at = bytes.length - terminator.length;
      if (bytes.subarray(at).equals(terminator) && bytes.indexOf(terminator) === at) return rendered;
      continue;
    }
    return rendered;
  }
  throw new Error(`${spec.name}: could not place the framing bytes unambiguously in message ${index}`);
}

function renderOnce(spec: ProtocolSpec, random: Random, index: number): Rendered {
  const banned = forbidden(spec);
  const payloadLength = random.int(6, 180);
  const payload = makePayload(random, spec.payload, payloadLength, banned);
  const prefix = spec.framing.kind === 'start-marker' ? spec.framing.marker : Buffer.alloc(0);
  const suffix = spec.framing.kind === 'delimiter' ? spec.framing.terminator : Buffer.alloc(0);

  const blocks: Buffer[] = [];
  let lengthSlot: { at: number; width: 1 | 2 | 4; endian: Endian } | null = null;

  for (const part of spec.header) {
    switch (part.kind) {
      case 'magic':
        blocks.push(part.bytes);
        break;
      case 'version':
        blocks.push(Buffer.from([part.value & 0xff]));
        break;
      case 'type':
        blocks.push(Buffer.from([part.values[index % part.values.length]!]));
        break;
      case 'counter': {
        const value = part.start + index * part.step;
        blocks.push(writeInt(value, part.width, part.endian));
        break;
      }
      case 'timestamp': {
        const value = part.base + index * part.jitter;
        blocks.push(writeInt(value, 4, part.endian));
        break;
      }
      case 'flags':
        blocks.push(Buffer.from([part.mask]));
        break;
      case 'reserved':
        blocks.push(Buffer.alloc(part.width));
        break;
      case 'length': {
        const width = spec.framing.kind === 'length-prefix' ? spec.framing.length.width : 2;
        const endian = spec.framing.kind === 'length-prefix' ? spec.framing.length.endian : 'be';
        lengthSlot = { at: blocks.reduce((n, b) => n + b.length, 0), width, endian };
        blocks.push(Buffer.alloc(width));
        break;
      }
    }
  }

  const header = Buffer.concat(blocks);
  const tail = spec.checksum ? Buffer.alloc(spec.checksum.offsetFromEnd) : Buffer.alloc(0);
  const head = Buffer.concat([prefix, header, payload, tail]);
  const message = Buffer.concat([head, Buffer.alloc(spec.checksum ? spec.checksum.width : 0), suffix]);

  if (spec.framing.kind === 'length-prefix' && lengthSlot) {
    const bias = spec.framing.length.bias;
    const value = message.length - bias;
    writeInt(value, lengthSlot.width, lengthSlot.endian).copy(message, lengthSlot.at);
    spec.framing.length.offset = lengthSlot.at;
  }

  const checksumFieldStart = head.length;
  if (spec.checksum) {
    const value = computeChecksum(spec.checksum.kind, message.subarray(spec.checksum.rangeStart, checksumFieldStart));
    writeInt(value, spec.checksum.width, spec.checksum.endian).copy(message, checksumFieldStart);
  }

  const checksumOffsetFromEnd = spec.checksum
    ? message.length - checksumFieldStart - spec.checksum.width
    : 0;

  return {
    message,
    headerLength: prefix.length + header.length,
    checksumOffsetFromEnd,
    checksumFieldStart,
  };
}

// ---------------------------------------------------------------------------
// manifest
// ---------------------------------------------------------------------------

interface ManifestEntry {
  name: string;
  seed: number;
  transport: 'tcp' | 'udp';
  framing: {
    kind: 'length-prefix' | 'start-marker' | 'delimiter' | 'unframed';
    lenOffset?: number;
    size?: number;
    endian?: Endian;
    bias?: number;
    marker?: string;
    terminator?: string;
  };
  headerLength: number;
  counter: { offset: number; width: number; endian: Endian } | null;
  checksum: { family: string; width: number; offsetFromEnd: number; rangeStart: number } | null;
  messages: { count: number; lengths: number[] };
}

function checksumName(kind: ChecksumKind): string {
  if (kind.family !== 'crc') return kind.family;
  const match = CRC_NAMES.find(
    (entry) =>
      entry.params.width === kind.params.width &&
      entry.params.poly === kind.params.poly &&
      entry.params.init === kind.params.init &&
      entry.params.refin === kind.params.refin &&
      entry.params.refout === kind.params.refout &&
      entry.params.xorout === kind.params.xorout,
  );
  return match ? match.name : `crc-private-${kind.params.width}/0x${kind.params.poly.toString(16)}`;
}

function main(): void {
  verifySelfCheck();

  const out = join(process.cwd(), 'bench', 'proprietary', 'corpus');
  mkdirSync(out, { recursive: true });

  const count = Number(process.argv[2] ?? 120);
  const entries: ManifestEntry[] = [];

  for (let seed = 1; seed <= count; seed++) {
    const spec = drawProtocol(seed);
    const random = new Random(seed * 7919 + 13);
    const records: PcapRecord[] = [];
    const lengths: number[] = [];

    let seq = 1000 + seed;
    const clientIp = `10.${(seed >> 8) & 0xff}.${seed & 0xff}.10`;
    const serverIp = `10.${(seed >> 8) & 0xff}.${seed & 0xff}.20`;
    const clientPort = 30000 + seed;
    const serverPort = 20000 + seed;

    let headerLength = 0;
    let checksumOffsetFromEnd = 0;
    for (let i = 0; i < spec.messageCount; i++) {
      const rendered = render(spec, random, i);
      headerLength = rendered.headerLength;
      checksumOffsetFromEnd = rendered.checksumOffsetFromEnd;
      lengths.push(rendered.message.length);

      const frame =
        spec.transport === 'tcp'
          ? tcpFrame(clientIp, clientPort, serverIp, serverPort, seq, 5000, rendered.message)
          : udpFrame(clientIp, clientPort, serverIp, serverPort, rendered.message);
      if (spec.transport === 'tcp') seq += rendered.message.length;
      records.push({ ts: 1_760_000_000 + seed * 100 + i * 0.001, data: frame });
    }

    writePcap(join(out, `${spec.name}.pcap`), records);

    const counterPart = spec.header.find((part) => part.kind === 'counter');
    let counterOffset = spec.framing.kind === 'start-marker' ? spec.framing.marker.length : 0;
    if (counterPart && counterPart.kind === 'counter') {
      for (const part of spec.header) {
        if (part === counterPart) break;
        if (part.kind === 'magic') counterOffset += part.bytes.length;
        else if (part.kind === 'counter') counterOffset += part.width;
        else if (part.kind === 'timestamp') counterOffset += 4;
        else if (part.kind === 'reserved') counterOffset += part.width;
        else if (part.kind === 'length') counterOffset += spec.framing.kind === 'length-prefix' ? spec.framing.length.width : 2;
        else counterOffset += 1;
      }
    }

    entries.push({
      name: spec.name,
      seed,
      transport: spec.transport,
      framing:
        spec.framing.kind === 'length-prefix'
          ? { kind: 'length-prefix', lenOffset: spec.framing.length.offset, size: spec.framing.length.width, endian: spec.framing.length.endian, bias: spec.framing.length.bias }
          : spec.framing.kind === 'start-marker'
            ? { kind: 'start-marker', marker: spec.framing.marker.toString('hex') }
            : spec.framing.kind === 'delimiter'
              ? { kind: 'delimiter', terminator: spec.framing.terminator.toString('hex') }
              : { kind: 'unframed' },
      headerLength,
      counter:
        counterPart && counterPart.kind === 'counter'
          ? { offset: counterOffset, width: counterPart.width, endian: counterPart.endian }
          : null,
      checksum: spec.checksum
        ? {
            family: checksumName(spec.checksum.kind),
            width: spec.checksum.width,
            offsetFromEnd: checksumOffsetFromEnd,
            rangeStart: spec.checksum.rangeStart,
          }
        : null,
      messages: { count: spec.messageCount, lengths },
    });
  }

  writeFileSync(join(out, 'manifest.json'), JSON.stringify(entries, null, 1) + '\n');
  console.log(`wrote ${entries.length} proprietary captures and manifest to ${out}`);
}

main();

import { Buffer } from 'node:buffer';
import type { Endian } from '../types.js';

export interface CrcParameters {
  width: 8 | 16 | 32;
  /** Polynomial in normal (MSB-first) form, without the implicit top bit. */
  poly: number;
  init: number;
  refin: boolean;
  refout: boolean;
  xorout: number;
}

/** Everything a generated client needs to recompute a checksum field. */
export type ChecksumSpec =
  | { kind: 'crc'; params: CrcParameters }
  | { kind: 'sum8' }
  | { kind: 'xor8' }
  | { kind: 'sum16' }
  | { kind: 'inet16' }
  | { kind: 'fletcher16' }
  | { kind: 'fletcher32' }
  | { kind: 'adler32' };

export interface ChecksumAlgorithm {
  name: string;
  width: 1 | 2 | 4;
  spec: ChecksumSpec;
  compute(data: Buffer): number;
}

const REFLECT8 = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
  let value = i;
  let out = 0;
  for (let bit = 0; bit < 8; bit++) {
    out = (out << 1) | (value & 1);
    value >>= 1;
  }
  REFLECT8[i] = out;
}

function reflect(value: number, width: 8 | 16 | 32): number {
  let out = 0;
  for (let bit = 0; bit < width; bit++) out = (out << 1) | ((value >> bit) & 1);
  return out >>> 0;
}

/**
 * Canonical CRC, in the parameterisation used by the CRC catalogue (Williams' model):
 * the polynomial is always given in normal form, `refin` reflects each input byte, `refout`
 * reflects the final register, and `xorout` is applied last. Every named algorithm below is
 * expressed through this one function so a recovered parameter set is directly comparable
 * to a published one.
 */
export function crcCompute(data: Buffer, params: CrcParameters): number {
  const { width, poly, init, refin, refout, xorout } = params;
  const mask = width === 32 ? 0xffffffff : width === 16 ? 0xffff : 0xff;
  let crc = init & mask;

  for (const byte of data) {
    const value = refin ? REFLECT8[byte]! : byte;
    if (width === 32) crc = (crc ^ (value * 0x1000000)) >>> 0;
    else if (width === 16) crc ^= value << 8;
    else crc ^= value;

    for (let bit = 0; bit < 8; bit++) {
      if (width === 32) crc = (crc & 0x80000000) !== 0 ? (((crc << 1) >>> 0) ^ poly) >>> 0 : (crc << 1) >>> 0;
      else if (width === 16) crc = crc & 0x8000 ? (((crc << 1) ^ poly) & 0xffff) : ((crc << 1) & 0xffff);
      else crc = crc & 0x80 ? (((crc << 1) ^ poly) & 0xff) : ((crc << 1) & 0xff);
    }
  }

  if (refout) crc = reflect(crc, width);
  return ((crc ^ xorout) & mask) >>> 0;
}

/** The polynomial as it appears in reflected implementations such as CRC-16/MODBUS's 0xa001. */
export function reflectedPoly(params: CrcParameters): number {
  return reflect(params.poly, params.width);
}

function adler32(data: Buffer): number {
  let a = 1;
  let b = 0;
  for (const byte of data) {
    a = (a + byte) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

function fletcher16(data: Buffer): number {
  let sum1 = 0;
  let sum2 = 0;
  for (const byte of data) {
    sum1 = (sum1 + byte) % 255;
    sum2 = (sum2 + sum1) % 255;
  }
  return ((sum2 << 8) | sum1) & 0xffff;
}

function fletcher32(data: Buffer): number {
  let sum1 = 0xffff;
  let sum2 = 0xffff;
  for (let i = 0; i < data.length; i += 2) {
    const word = (data[i]! << 8) | (i + 1 < data.length ? data[i + 1]! : 0);
    sum1 = (sum1 + word) % 65535;
    sum2 = (sum2 + sum1) % 65535;
  }
  return ((sum2 << 16) | sum1) >>> 0;
}

/** The one's-complement sum used by IP, UDP, and the protocols that copied them. */
function internetChecksum(data: Buffer): number {
  let sum = 0;
  for (let i = 0; i < data.length; i += 2) {
    sum += (data[i]! << 8) | (i + 1 < data.length ? data[i + 1]! : 0);
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return ~sum & 0xffff;
}

function crc(name: string, width: 8 | 16 | 32, params: Omit<CrcParameters, 'width'>): ChecksumAlgorithm {
  const full: CrcParameters = { width, ...params };
  return {
    name,
    width: width === 32 ? 4 : width === 16 ? 2 : 1,
    spec: { kind: 'crc', params: full },
    compute: (data) => crcCompute(data, full),
  };
}

function simple(name: string, width: 1 | 2 | 4, kind: ChecksumSpec['kind'], compute: (data: Buffer) => number): ChecksumAlgorithm {
  return { name, width, spec: { kind } as ChecksumSpec, compute };
}

/**
 * The catalogue. Coverage is the point: a protocol that copies a published CRC is found by
 * name, and one that uses a non-standard initial value is found by `crc-recovery.ts`.
 */
export const ALGORITHMS: ChecksumAlgorithm[] = [
  simple('sum8', 1, 'sum8', (d) => {
    let sum = 0;
    for (const byte of d) sum = (sum + byte) & 0xff;
    return sum;
  }),
  simple('xor8', 1, 'xor8', (d) => {
    let acc = 0;
    for (const byte of d) acc ^= byte;
    return acc;
  }),
  simple('sum16', 2, 'sum16', (d) => {
    let sum = 0;
    for (const byte of d) sum = (sum + byte) & 0xffff;
    return sum;
  }),
  simple('inet16', 2, 'inet16', internetChecksum),
  simple('fletcher16', 2, 'fletcher16', fletcher16),
  simple('fletcher32', 4, 'fletcher32', fletcher32),
  simple('adler32', 4, 'adler32', adler32),

  crc('crc8', 8, { poly: 0x07, init: 0x00, refin: false, refout: false, xorout: 0x00 }),
  crc('crc8/itu', 8, { poly: 0x07, init: 0x55, refin: false, refout: false, xorout: 0x00 }),
  crc('crc8/rohc', 8, { poly: 0x07, init: 0xff, refin: true, refout: true, xorout: 0x00 }),
  crc('crc8/maxim', 8, { poly: 0x31, init: 0x00, refin: true, refout: true, xorout: 0x00 }),
  crc('crc8/darc', 8, { poly: 0x39, init: 0x00, refin: true, refout: true, xorout: 0x00 }),
  crc('crc8/sae-j1850', 8, { poly: 0x1d, init: 0xff, refin: false, refout: false, xorout: 0xff }),
  crc('crc8/autosar', 8, { poly: 0x2f, init: 0xff, refin: false, refout: false, xorout: 0xff }),
  crc('crc8/cdma2000', 8, { poly: 0x9b, init: 0xff, refin: false, refout: false, xorout: 0x00 }),

  crc('crc16/ccitt-false', 16, { poly: 0x1021, init: 0xffff, refin: false, refout: false, xorout: 0x0000 }),
  crc('crc16/xmodem', 16, { poly: 0x1021, init: 0x0000, refin: false, refout: false, xorout: 0x0000 }),
  crc('crc16/aug-ccitt', 16, { poly: 0x1021, init: 0x1d0f, refin: false, refout: false, xorout: 0x0000 }),
  crc('crc16/genibus', 16, { poly: 0x1021, init: 0xffff, refin: false, refout: false, xorout: 0xffff }),
  crc('crc16/t10-dif', 16, { poly: 0x8bb7, init: 0x0000, refin: false, refout: false, xorout: 0x0000 }),
  crc('crc16/profibus', 16, { poly: 0x1dcf, init: 0xffff, refin: false, refout: false, xorout: 0xffff }),
  crc('crc16/kermit', 16, { poly: 0x1021, init: 0x0000, refin: true, refout: true, xorout: 0x0000 }),
  crc('crc16/x25', 16, { poly: 0x1021, init: 0xffff, refin: true, refout: true, xorout: 0xffff }),
  crc('crc16/modbus', 16, { poly: 0x8005, init: 0xffff, refin: true, refout: true, xorout: 0x0000 }),
  crc('crc16/arc', 16, { poly: 0x8005, init: 0x0000, refin: true, refout: true, xorout: 0x0000 }),
  crc('crc16/dnp', 16, { poly: 0x3d65, init: 0x0000, refin: true, refout: true, xorout: 0xffff }),

  crc('crc32/ieee', 32, { poly: 0x04c11db7, init: 0xffffffff, refin: true, refout: true, xorout: 0xffffffff }),
  crc('crc32/c', 32, { poly: 0x1edc6f41, init: 0xffffffff, refin: true, refout: true, xorout: 0xffffffff }),
  crc('crc32/mpeg2', 32, { poly: 0x04c11db7, init: 0xffffffff, refin: false, refout: false, xorout: 0x00000000 }),
  crc('crc32/bzip2', 32, { poly: 0x04c11db7, init: 0xffffffff, refin: false, refout: false, xorout: 0xffffffff }),
];

export function algorithmByName(name: string): ChecksumAlgorithm | undefined {
  return ALGORITHMS.find((entry) => entry.name === name);
}

export interface ChecksumMatch {
  algorithm: string;
  width: 1 | 2 | 4;
  endian: Endian;
  /** Byte offset of the checksum field, counted from the end of the message. */
  offsetFromEnd: number;
  /** Message bytes the checksum was computed over: [rangeStart, len - offsetFromEnd - width). */
  rangeStart: number;
  matches: number;
  total: number;
  confidence: number;
  evidence: string;
}

export interface ChecksumSearchOptions {
  /** How far into the message a checksum range may start. */
  maxRangeStart?: number;
  /** How many bytes before the message end the checksum field may sit. */
  maxOffsetFromEnd?: number;
  /** Minimum share of messages that must agree for a match to survive. */
  minAgreement?: number;
  /** Messages examined per algorithm before the winner is re-verified on all of them. */
  sampleSize?: number;
}

/** Spread a sample across the stream so short and long messages are both represented. */
function sample(messages: Buffer[], size: number): Buffer[] {
  if (messages.length <= size) return messages;
  const step = messages.length / size;
  const picked: Buffer[] = [];
  for (let i = 0; i < size; i++) {
    const message = messages[Math.floor(i * step)];
    if (message && !picked.includes(message)) picked.push(message);
  }
  return picked;
}

/**
 * Searches for a field that equals a standard checksum of an earlier byte range.
 *
 * The search space is fully enumerated — algorithm x width x position x range start x
 * endianness. The catalogue is large, so the first pass runs on a spread sample; every
 * surviving candidate is then re-verified on every message, and the returned agreement
 * figure is over the whole direction rather than the sample.
 */
export function detectChecksum(messages: Buffer[], options: ChecksumSearchOptions = {}): ChecksumMatch[] {
  const maxRangeStart = options.maxRangeStart ?? 8;
  const maxOffsetFromEnd = options.maxOffsetFromEnd ?? 4;
  const minAgreement = options.minAgreement ?? 0.95;
  const sampleSize = options.sampleSize ?? 32;
  const usable = messages.filter((m) => m.length >= 4);
  if (usable.length < 3) return [];

  const probe = sample(usable, sampleSize);
  const preliminary: Array<Omit<ChecksumMatch, 'evidence' | 'matches' | 'total' | 'confidence'>> = [];

  for (const algorithm of ALGORITHMS) {
    const width = algorithm.width;
    for (let offsetFromEnd = 0; offsetFromEnd <= maxOffsetFromEnd; offsetFromEnd++) {
      for (let rangeStart = 0; rangeStart <= maxRangeStart; rangeStart++) {
        for (const endian of ['le', 'be'] as const) {
          let hits = 0;
          let considered = 0;
          for (const message of probe) {
            const fieldStart = message.length - offsetFromEnd - width;
            if (fieldStart <= rangeStart) continue;
            considered++;
            const expected = readWidth(message, fieldStart, width, endian);
            if (algorithm.compute(message.subarray(rangeStart, fieldStart)) === expected) hits++;
          }
          if (considered < 3 || hits / considered < minAgreement) continue;
          preliminary.push({ algorithm: algorithm.name, width, endian, offsetFromEnd, rangeStart });
        }
      }
    }
  }

  const verified: ChecksumMatch[] = [];
  for (const candidate of preliminary) {
    const algorithm = algorithmByName(candidate.algorithm)!;
    let hits = 0;
    let considered = 0;
    for (const message of usable) {
      const fieldStart = message.length - candidate.offsetFromEnd - candidate.width;
      if (fieldStart <= candidate.rangeStart) continue;
      considered++;
      if (algorithm.compute(message.subarray(candidate.rangeStart, fieldStart)) === readWidth(message, fieldStart, candidate.width, candidate.endian)) {
        hits += 1;
      }
    }
    if (considered < 3 || hits / considered < minAgreement) continue;
    verified.push({
      ...candidate,
      matches: hits,
      total: considered,
      confidence: hits / considered,
      evidence:
        `${algorithm.name} over bytes [${candidate.rangeStart}, len-${candidate.offsetFromEnd + candidate.width}) ` +
        `equals the ${candidate.width}-byte ${candidate.endian} field at len-${candidate.offsetFromEnd + candidate.width} ` +
        `in ${hits}/${considered} messages`,
    });
  }

  return verified
    .sort((a, b) => b.confidence - a.confidence || a.width - b.width || b.matches - a.matches)
    .filter((match, index, all) => {
      // Keep one entry per (algorithm, field position): weaker duplicates add noise.
      const key = `${match.algorithm}:${match.offsetFromEnd}:${match.width}`;
      return all.findIndex((m) => `${m.algorithm}:${m.offsetFromEnd}:${m.width}` === key) === index;
    });
}

function readWidth(data: Buffer, at: number, width: number, endian: Endian): number {
  if (width === 1) return data[at]!;
  if (width === 2) return endian === 'le' ? data.readUInt16LE(at) : data.readUInt16BE(at);
  return endian === 'le' ? data.readUInt32LE(at) : data.readUInt32BE(at);
}

// ---------------------------------------------------------------------------------------
// Field-level helpers shared by the pipeline, the emitters and the tests.
// ---------------------------------------------------------------------------------------

/** Reads the checksum field a match describes out of one message. */
export function readChecksumField(message: Buffer, match: Pick<ChecksumMatch, 'width' | 'offsetFromEnd' | 'endian'>): number | null {
  const position = message.length - match.offsetFromEnd - match.width;
  if (position < 0) return null;
  return readWidth(message, position, match.width, match.endian);
}

/** Recomputes the digest a match describes over one message. */
export function computeChecksumField(message: Buffer, match: Pick<ChecksumMatch, 'width' | 'offsetFromEnd' | 'rangeStart'>, spec: ChecksumSpec): number | null {
  const fieldStart = message.length - match.offsetFromEnd - match.width;
  if (fieldStart <= match.rangeStart) return null;
  return computeWithSpec(message.subarray(match.rangeStart, fieldStart), spec);
}

export function computeWithSpec(data: Buffer, spec: ChecksumSpec): number {
  switch (spec.kind) {
    case 'crc':
      return crcCompute(data, spec.params);
    case 'sum8':
      return ALGORITHMS.find((a) => a.name === 'sum8')!.compute(data);
    case 'xor8':
      return ALGORITHMS.find((a) => a.name === 'xor8')!.compute(data);
    case 'sum16':
      return ALGORITHMS.find((a) => a.name === 'sum16')!.compute(data);
    case 'inet16':
      return internetChecksum(data);
    case 'fletcher16':
      return fletcher16(data);
    case 'fletcher32':
      return fletcher32(data);
    case 'adler32':
      return adler32(data);
  }
}

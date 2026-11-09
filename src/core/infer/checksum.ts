import { Buffer } from 'node:buffer';
import type { Endian } from '../types.js';

export interface ChecksumAlgorithm {
  name: string;
  width: 1 | 2 | 4;
  compute(data: Buffer): number;
}

function crc16Reflected(poly: number, init: number) {
  const table = new Uint16Array(256);
  for (let i = 0; i < 256; i++) {
    let value = i;
    for (let bit = 0; bit < 8; bit++) {
      value = value & 1 ? (value >>> 1) ^ poly : value >>> 1;
    }
    table[i] = value;
  }
  return (data: Buffer): number => {
    let crc = init;
    for (const byte of data) crc = (crc >>> 8) ^ table[(crc ^ byte) & 0xff]!;
    return crc & 0xffff;
  };
}

function crc16Forward(poly: number, init: number) {
  const table = new Uint16Array(256);
  for (let i = 0; i < 256; i++) {
    let value = i << 8;
    for (let bit = 0; bit < 8; bit++) {
      value = value & 0x8000 ? ((value << 1) ^ poly) & 0xffff : (value << 1) & 0xffff;
    }
    table[i] = value;
  }
  return (data: Buffer): number => {
    let crc = init;
    for (const byte of data) crc = ((crc << 8) ^ table[((crc >> 8) ^ byte) & 0xff]!) & 0xffff;
    return crc;
  };
}

function crc32Ieee(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export const ALGORITHMS: ChecksumAlgorithm[] = [
  {
    name: 'sum8',
    width: 1,
    compute: (d) => {
      let sum = 0;
      for (const byte of d) sum = (sum + byte) & 0xff;
      return sum;
    },
  },
  {
    name: 'xor8',
    width: 1,
    compute: (d) => {
      let acc = 0;
      for (const byte of d) acc ^= byte;
      return acc;
    },
  },
  { name: 'crc8', width: 1, compute: crc8(0x07, 0x00) },
  { name: 'crc8/itu', width: 1, compute: crc8(0x07, 0x55) },
  { name: 'crc16/ccitt-false', width: 2, compute: crc16Forward(0x1021, 0xffff) },
  { name: 'crc16/xmodem', width: 2, compute: crc16Forward(0x1021, 0x0000) },
  { name: 'crc16/modbus', width: 2, compute: crc16Reflected(0xa001, 0xffff) },
  { name: 'crc16/arc', width: 2, compute: crc16Reflected(0xa001, 0x0000) },
  {
    name: 'sum16',
    width: 2,
    compute: (d) => {
      let sum = 0;
      for (const byte of d) sum = (sum + byte) & 0xffff;
      return sum;
    },
  },
  { name: 'crc32/ieee', width: 4, compute: crc32Ieee },
];

function crc8(poly: number, init: number) {
  const table = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    let value = i;
    for (let bit = 0; bit < 8; bit++) value = value & 0x80 ? ((value << 1) ^ poly) & 0xff : (value << 1) & 0xff;
    table[i] = value;
  }
  return (data: Buffer): number => {
    let crc = init;
    for (const byte of data) crc = table[(crc ^ byte) & 0xff]!;
    return crc;
  };
}

export interface ChecksumMatch {
  algorithm: string;
  width: 1 | 2 | 4;
  endian: Endian;
  /** Byte offset of the checksum field counted from the end of the message. */
  offsetFromEnd: number;
  /** Message bytes the checksum was computed over: [start, end). */
  rangeStart: number;
  rangeEndFromEnd: number;
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
}

/**
 * Searches for a field that equals a standard checksum of an earlier byte range.
 *
 * The search space is deliberately small and fully enumerated: width x position x range
 * start x endianness. Every returned match is verified against every message, so a match
 * is either exact for all of them or it is not reported.
 */
export function detectChecksum(messages: Buffer[], options: ChecksumSearchOptions = {}): ChecksumMatch[] {
  const maxRangeStart = options.maxRangeStart ?? 8;
  const maxOffsetFromEnd = options.maxOffsetFromEnd ?? 4;
  const minAgreement = options.minAgreement ?? 0.95;
  const usable = messages.filter((m) => m.length >= 4);
  if (usable.length < 3) return [];

  const matches: ChecksumMatch[] = [];

  for (const algorithm of ALGORITHMS) {
    const width = algorithm.width;
    for (let offsetFromEnd = 0; offsetFromEnd <= maxOffsetFromEnd; offsetFromEnd++) {
      for (let rangeStart = 0; rangeStart <= maxRangeStart; rangeStart++) {
        for (const endian of ['le', 'be'] as const) {
          let hits = 0;
          let considered = 0;
          for (const message of usable) {
            const fieldStart = message.length - offsetFromEnd - width;
            if (fieldStart <= rangeStart) continue;
            considered++;
            const expected = readWidth(message, fieldStart, width, endian);
            const digest = algorithm.compute(message.subarray(rangeStart, fieldStart));
            if (digest === expected) hits++;
          }
          if (considered < 3 || hits / considered < minAgreement) continue;

          matches.push({
            algorithm: algorithm.name,
            width,
            endian,
            offsetFromEnd,
            rangeStart,
            rangeEndFromEnd: offsetFromEnd + width,
            matches: hits,
            total: considered,
            confidence: hits / considered,
            evidence: `${algorithm.name} over bytes [${rangeStart}, len-${offsetFromEnd + width}) equals the ${width}-byte ${endian} field at len-${offsetFromEnd + width} in ${hits}/${considered} messages`,
          });
        }
      }
    }
  }

  return matches
    .sort((a, b) => b.confidence - a.confidence || a.width - b.width || b.matches - a.matches)
    .filter((match, index, all) => {
      // Keep one entry per (algorithm, field position): the weaker duplicates add noise.
      const key = `${match.algorithm}:${match.offsetFromEnd}:${match.width}`;
      return all.findIndex((m) => `${m.algorithm}:${m.offsetFromEnd}:${m.width}` === key) === index;
    });
}

function readWidth(data: Buffer, at: number, width: number, endian: Endian): number {
  if (width === 1) return data[at]!;
  if (width === 2) return endian === 'le' ? data.readUInt16LE(at) : data.readUInt16BE(at);
  return endian === 'le' ? data.readUInt32LE(at) : data.readUInt32BE(at);
}

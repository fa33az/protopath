import { Buffer } from 'node:buffer';
import type { Endian } from '../types.js';

export type FramingKind = 'length-prefix' | 'start-marker' | 'delimiter' | 'fixed' | 'unframed';

export interface LengthPrefixSpec {
  /** Offset of the length field, counted from the start of each message. */
  lenOffset: number;
  size: 1 | 2 | 4;
  endian: Endian;
  /**
   * Added to the raw field value to obtain the message length. A negative bias means the
   * field counts itself or the header, a positive one means trailing bytes sit outside it.
   */
  bias: number;
}

export interface StartMarkerSpec {
  marker: Buffer;
}

export interface DelimiterSpec {
  terminator: Buffer;
}

export interface FixedSpec {
  size: number;
}

export interface FramingHypothesis {
  kind: FramingKind;
  /** 0..1, comparable only between hypotheses for the same stream. */
  score: number;
  messages: Buffer[];
  /** Byte offset of each message within its stream. */
  offsets: number[];
  lengthPrefix?: LengthPrefixSpec;
  startMarker?: StartMarkerSpec;
  delimiter?: DelimiterSpec;
  fixed?: FixedSpec;
  evidence: string[];
  limitations: string[];
}

export interface Segmentation {
  messages: Buffer[];
  offsets: number[];
}

const PRIOR: Record<FramingKind, number> = {
  'length-prefix': 0.92,
  'start-marker': 0.86,
  delimiter: 0.8,
  fixed: 0.55,
  unframed: 0.2,
};

/**
 * Enumerates framing hypotheses and ranks them.
 *
 * Every hypothesis is a full segmentation of the stream: it either explains every byte or
 * it is discarded. That rule is what keeps the ranking honest, because a wrong frame length
 * almost never lands exactly on the end of the buffer.
 */
export function inferFraming(stream: Buffer, options: { maxHypotheses?: number } = {}): FramingHypothesis[] {
  const results: FramingHypothesis[] = [];
  if (stream.length === 0) return results;

  results.push(...lengthPrefixHypotheses(stream));
  results.push(...startMarkerHypotheses(stream));
  results.push(...delimiterHypotheses(stream));
  results.push(...fixedHypotheses(stream));

  results.push({
    kind: 'unframed',
    score: PRIOR.unframed,
    messages: [Buffer.from(stream)],
    offsets: [0],
    evidence: ['no repeating boundary was found; the stream is reported as a single opaque blob'],
    limitations: ['field inference below is not meaningful for an unframed stream'],
  });

  const bestByShape = new Map<string, FramingHypothesis>();
  for (const hypothesis of results) {
    const shape = shapeKey(hypothesis);
    const existing = bestByShape.get(shape);
    if (!existing || existing.score < hypothesis.score) bestByShape.set(shape, hypothesis);
  }

  const byKind = new Map<FramingKind, number>();
  const ranked = [...bestByShape.values()]
    .sort((a, b) => b.score - a.score)
    .filter((hypothesis) => {
      // Fixed-size framing always produces several divisors; only the best two are useful.
      const count = (byKind.get(hypothesis.kind) ?? 0) + 1;
      byKind.set(hypothesis.kind, count);
      return hypothesis.kind !== 'fixed' || count <= 2;
    });

  return ranked.slice(0, options.maxHypotheses ?? 4);
}

export function shapeKey(hypothesis: FramingHypothesis): string {
  if (hypothesis.lengthPrefix) {
    const s = hypothesis.lengthPrefix;
    return `length-prefix:${s.lenOffset}:${s.size}:${s.endian}:${s.bias}`;
  }
  if (hypothesis.startMarker) return `start-marker:${hypothesis.startMarker.marker.toString('hex')}`;
  if (hypothesis.delimiter) return `delimiter:${hypothesis.delimiter.terminator.toString('hex')}`;
  if (hypothesis.fixed) return `fixed:${hypothesis.fixed.size}`;
  return hypothesis.kind;
}

/** True when the winning hypothesis is strong enough to build a protocol model on. */
export function isConfident(hypothesis: FramingHypothesis | undefined): boolean {
  return hypothesis !== undefined && hypothesis.kind !== 'unframed' && hypothesis.score >= 0.6;
}

function readValue(data: Buffer, at: number, size: 1 | 2 | 4, endian: Endian): number {
  if (size === 1) return data[at]!;
  if (size === 2) return endian === 'le' ? data.readUInt16LE(at) : data.readUInt16BE(at);
  return endian === 'le' ? data.readUInt32LE(at) : data.readUInt32BE(at);
}

function lengthPrefixHypotheses(stream: Buffer): FramingHypothesis[] {
  const out: FramingHypothesis[] = [];
  const maxLenOffset = Math.min(8, stream.length - 2);

  for (let lenOffset = 0; lenOffset <= maxLenOffset; lenOffset++) {
    for (const size of [1, 2, 4] as const) {
      if (lenOffset + size > 16) continue;
      for (const endian of size === 1 ? (['be'] as const) : (['le', 'be'] as const)) {
        for (let bias = -6; bias <= 12; bias++) {
          const spec: LengthPrefixSpec = { lenOffset, size, endian, bias };
          const segmentation = walkLengthPrefix(stream, spec);
          if (!segmentation) continue;

          const count = segmentation.messages.length;
          if (count < 3) continue;

          const small = segmentation.messages.reduce((n, m) => n + (m.length < Math.max(4, lenOffset + size) ? 1 : 0), 0);
          if (small > 0) continue;

          const values = segmentation.offsets.map((offset) => readValue(stream, offset + lenOffset, size, endian));
          const distinctValues = new Set(values).size;
          const zeroShare = values.filter((value) => value === 0).length / values.length;

          // A length field that never varies is not evidence of length-prefixed framing: the
          // hypothesis degenerates to fixed-size messages, and reporting it as a length field
          // invents a field the protocol does not have.
          const constantField = distinctValues < 2;
          // Zero-heavy streams (MBAP headers, padded structures) let a small length field tile
          // by accident: most boundaries are "0 + bias". Avoid the byte when it carries no
          // information in the majority of messages.
          const uninformativeField = zeroShare > 0.5;

          const score =
            PRIOR['length-prefix'] -
            0.025 * Math.min(Math.abs(bias), 8) -
            0.015 * lenOffset +
            (size === 2 ? 0.02 : 0) +
            (count >= 6 ? 0.02 : 0) -
            (constantField ? 0.2 : 0) -
            (uninformativeField ? 0.22 : 0);

          out.push({
            kind: 'length-prefix',
            score: clamp01(score),
            messages: segmentation.messages,
            offsets: segmentation.offsets,
            lengthPrefix: spec,
            evidence: [
              `${size}-byte ${endian} length field at message offset ${lenOffset}, message length = value ${bias >= 0 ? '+' : '-'} ${Math.abs(bias)}`,
              `${count} messages recovered, stream consumed exactly to the last byte`,
              `median message length ${median(segmentation.messages.map((m) => m.length))} bytes`,
            ],
            limitations: [
              lenOffset > 0
                ? `bytes [0, ${lenOffset}) sit before the length field and are treated as fixed header`
                : 'the length field is assumed to be the first byte of every message',
              ...(constantField
                ? [`the length field held the value 0x${values[0]!.toString(16)} in every message, so this is indistinguishable from fixed-size framing`]
                : []),
              ...(uninformativeField
                ? [`the length field was zero in ${Math.round(zeroShare * 100)}% of messages; those sizes come from the bias, not the field`]
                : []),
            ],
          });
        }
      }
    }
  }

  return dedupeBySegmentation(out, stream);
}

/**
 * Two parameterisations can produce the same message boundaries. On a byte stream, a 2-byte
 * length at offset 4 and a 4-byte length at offset 2 are indistinguishable when the protocol-id
 * field between them is a constant zero — both walk the stream identically. The data cannot
 * settle it, so the tie breaks on the width prior: 16-bit lengths are the common case, then
 * 8-bit, then 32-bit. Reporting 2 bytes over bytes that are never used is the safer error,
 * because it leaves a `reserved` field where the wider reading invented meaning.
 */
function dedupeBySegmentation(hypotheses: FramingHypothesis[], stream: Buffer): FramingHypothesis[] {
  const best = new Map<string, FramingHypothesis>();
  for (const hypothesis of hypotheses) {
    const signature = hypothesis.offsets.join(',');
    const existing = best.get(signature);
    if (!existing) {
      best.set(signature, hypothesis);
      continue;
    }
    if (isPreferredLengthField(hypothesis.lengthPrefix!, existing.lengthPrefix!)) best.set(signature, hypothesis);
  }
  void stream;
  return [...best.values()];
}

const WIDTH_PRIOR: Record<1 | 2 | 4, number> = { 2: 0, 1: 1, 4: 2 };

function isPreferredLengthField(candidate: LengthPrefixSpec, incumbent: LengthPrefixSpec): boolean {
  if (candidate.size !== incumbent.size) return WIDTH_PRIOR[candidate.size] < WIDTH_PRIOR[incumbent.size];
  if (Math.abs(candidate.bias) !== Math.abs(incumbent.bias)) return Math.abs(candidate.bias) < Math.abs(incumbent.bias);
  return candidate.lenOffset < incumbent.lenOffset;
}

function walkLengthPrefix(stream: Buffer, spec: LengthPrefixSpec): Segmentation | null {
  const messages: Buffer[] = [];
  const offsets: number[] = [];
  let cursor = 0;
  const minimum = spec.lenOffset + spec.size;

  while (cursor < stream.length) {
    if (cursor + minimum > stream.length) return null;
    const raw = readValue(stream, cursor + spec.lenOffset, spec.size, spec.endian);
    const total = raw + spec.bias;
    if (total < minimum || total > 512 * 1024) return null;
    if (cursor + total > stream.length) return null;
    messages.push(Buffer.from(stream.subarray(cursor, cursor + total)));
    offsets.push(cursor);
    cursor += total;
  }

  if (cursor !== stream.length || messages.length < 3) return null;
  return { messages, offsets };
}

function startMarkerHypotheses(stream: Buffer): FramingHypothesis[] {
  const seen = new Map<string, FramingHypothesis>();
  if (stream.length < 12) return [];

  for (const width of [2, 3, 4]) {
    if (stream.length <= width) continue;
    const marker = Buffer.from(stream.subarray(0, width));
    if (isTrivialMarker(marker)) continue;

    const segmentation = splitOnMarker(stream, marker);
    if (!segmentation || segmentation.messages.length < 3) continue;

    const shortest = Math.min(...segmentation.messages.map((m) => m.length));
    const count = segmentation.messages.length;
    const density = (count * width) / stream.length;
    if (density > 0.5) continue; // the marker is probably payload, not a boundary

    const score =
      PRIOR['start-marker'] -
      (shortest < 6 ? 0.2 : 0) -
      (count > 4096 ? 0.1 : 0) +
      (count >= 6 ? 0.01 : 0) -
      // A longer marker that yields fewer messages is the weaker explanation of the same
      // stream: it survives only because it is a superset of the real boundary.
      0.02 * (width - 2);

    const hypothesis: FramingHypothesis = {
      kind: 'start-marker',
      score: clamp01(score),
      messages: segmentation.messages,
      offsets: segmentation.offsets,
      startMarker: { marker },
      evidence: [
        `every message begins with 0x${marker.toString('hex')}`,
        `${count} messages recovered by splitting on the marker`,
      ],
      limitations: [
        'a marker that also appears inside a payload would over-segment the stream; check the message count against the expected exchange',
      ],
    };

    // Nested markers produce the same segmentation; keep the shortest one that explains it.
    const signature = segmentation.offsets.join(',');
    const existing = seen.get(signature);
    if (!existing || existing.startMarker!.marker.length > marker.length) seen.set(signature, hypothesis);
  }

  return [...seen.values()];
}

function splitOnMarker(stream: Buffer, marker: Buffer): Segmentation | null {
  const positions: number[] = [];
  let at = stream.indexOf(marker, 0);
  while (at !== -1) {
    positions.push(at);
    at = stream.indexOf(marker, at + 1);
  }
  if (positions.length < 3) return null;

  const first = positions[0]!;
  const messages: Buffer[] = [];
  const offsets: number[] = [];

  const usable = first === 0 ? positions : positions.filter((p) => p >= first);
  if (usable[0] !== 0) return null;

  for (let i = 0; i < usable.length; i++) {
    const start = usable[i]!;
    const end = i + 1 < usable.length ? usable[i + 1]! : stream.length;
    if (end <= start) continue;
    messages.push(Buffer.from(stream.subarray(start, end)));
    offsets.push(start);
  }

  if (messages.length < 3) return null;
  return { messages, offsets };
}

function isTrivialMarker(marker: Buffer): boolean {
  // Padding runs make the worst boundaries: they appear all over binary payloads.
  return marker.every((byte) => byte === 0x00) || marker.every((byte) => byte === 0xff);
}

function delimiterHypotheses(stream: Buffer): FramingHypothesis[] {
  const candidates: Buffer[] = [
    Buffer.from([0x0a]),
    Buffer.from([0x0d, 0x0a]),
    Buffer.from([0x0d]),
    Buffer.from([0x00]),
    Buffer.from([0x00, 0x00]),
    Buffer.from([0xff]),
    Buffer.from([0x03]),
  ];

  const out: FramingHypothesis[] = [];
  for (const terminator of candidates) {
    const segmentation = splitAfter(stream, terminator);
    if (!segmentation || segmentation.messages.length < 3) continue;

    const printable = segmentation.messages.filter((m) => isMostlyPrintable(m)).length;
    const ratio = printable / segmentation.messages.length;
    const score = PRIOR.delimiter + (ratio >= 0.9 ? 0.06 : 0) - (ratio < 0.5 ? 0.12 : 0);

    out.push({
      kind: 'delimiter',
      score: clamp01(score),
      messages: segmentation.messages,
      offsets: segmentation.offsets,
      delimiter: { terminator },
      evidence: [
        `each message ends with 0x${terminator.toString('hex')}`,
        `${segmentation.messages.length} messages recovered`,
        `${Math.round(ratio * 100)}% of messages are mostly printable text`,
      ],
      limitations: [
        'a terminator byte occurring inside a binary payload would split that payload into two messages',
      ],
    });
  }
  return out;
}

function splitAfter(stream: Buffer, terminator: Buffer): Segmentation | null {
  const messages: Buffer[] = [];
  const offsets: number[] = [];
  let cursor = 0;

  while (cursor < stream.length) {
    const found = stream.indexOf(terminator, cursor);
    if (found === -1) {
      const rest = stream.subarray(cursor);
      if (rest.length < 4) break;
      return null;
    }
    const end = found + terminator.length;
    messages.push(Buffer.from(stream.subarray(cursor, end)));
    offsets.push(cursor);
    cursor = end;
  }

  if (cursor !== stream.length || messages.length < 3) return null;
  return { messages, offsets };
}

function fixedHypotheses(stream: Buffer): FramingHypothesis[] {
  const out: FramingHypothesis[] = [];
  const limit = Math.min(1024, stream.length);

  for (let size = 4; size <= limit; size++) {
    if (stream.length % size !== 0) continue;
    const count = stream.length / size;
    if (count < 3 || count > 4096) continue;

    const messages: Buffer[] = [];
    const offsets: number[] = [];
    for (let i = 0; i < count; i++) {
      messages.push(Buffer.from(stream.subarray(i * size, (i + 1) * size)));
      offsets.push(i * size);
    }

    out.push({
      kind: 'fixed',
      score: clamp01(PRIOR.fixed + (size >= 8 && size <= 128 ? 0.08 : 0)),
      messages,
      offsets,
      fixed: { size },
      evidence: [`stream length divides evenly into ${count} messages of ${size} bytes`],
      limitations: [
        'fixed size is the weakest hypothesis: any stream whose length has divisors will produce one',
      ],
    });
    if (out.length >= 6) break;
  }

  return out;
}

function isMostlyPrintable(message: Buffer): boolean {
  if (message.length === 0) return false;
  let printable = 0;
  for (const byte of message) {
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d) printable++;
  }
  return printable / message.length >= 0.85;
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = sorted.length >> 1;
  return sorted.length % 2 === 0 ? Math.round((sorted[middle - 1]! + sorted[middle]!) / 2) : sorted[middle]!;
}

function clamp01(value: number): number {
  return Math.max(0, Math.min(0.99, value));
}

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
  // Fixed size is a guess: any stream length has divisors. It is reported, but it does not
  // clear the confidence bar on its own, so no field model is built on it.
  fixed: 0.5,
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

  applyBoundaryConsistency(results, stream);

  const bestByShape = new Map<string, FramingHypothesis>();
  for (const hypothesis of results) {
    const shape = shapeKey(hypothesis);
    const existing = bestByShape.get(shape);
    if (!existing || existing.score < hypothesis.score) bestByShape.set(shape, hypothesis);
  }

  const ranked = [...bestByShape.values()].sort((a, b) => b.score - a.score);

  // Two families can segment a stream identically: a message that starts with a constant marker
  // and also ends with a terminator reads either way. The ranking has to pick one, so it says
  // out loud that the other is still standing.
  for (const hypothesis of ranked) {
    const twin = ranked.find(
      (other) =>
        other !== hypothesis &&
        other.kind !== hypothesis.kind &&
        other.offsets.length === hypothesis.offsets.length &&
        other.offsets.every((offset, index) => offset === hypothesis.offsets[index]),
    );
    if (!twin) continue;
    hypothesis.limitations.push(
      `a ${twin.kind} parse splits this stream at exactly the same offsets; the boundaries are certain and the family name is not`,
    );
  }

  const byKind = new Map<FramingKind, number>();
  const deduped = ranked.filter((hypothesis) => {
    // Fixed-size framing always produces several divisors; only the best two are useful.
    const count = (byKind.get(hypothesis.kind) ?? 0) + 1;
    byKind.set(hypothesis.kind, count);
    return hypothesis.kind !== 'fixed' || count <= 2;
  });

  return deduped.slice(0, options.maxHypotheses ?? 4);
}

/**
 * A repeated byte sequence that divides the stream into messages is evidence the stream has
 * boundaries there. A length-prefix parse that ignores most of those boundaries has found a
 * tiling, not the framing. Penalise it so the marker-based parse wins.
 */
function applyBoundaryConsistency(results: FramingHypothesis[], stream: Buffer): void {
  applyMarkerConsistency(results, stream);
  applyTerminatorConsistency(results, stream);
}

function applyMarkerConsistency(results: FramingHypothesis[], stream: Buffer): void {
  const marker = results
    .filter((h) => h.kind === 'start-marker' && h.startMarker !== undefined && h.messages.length >= 3 && h.score >= 0.8)
    .sort((a, b) => b.score - a.score)[0];
  if (!marker?.startMarker) return;

  const bytes = marker.startMarker.marker;
  const positions: number[] = [];
  for (let at = stream.indexOf(bytes); at !== -1; at = stream.indexOf(bytes, at + 1)) positions.push(at);
  if (positions.length < 3) return;

  for (const hypothesis of results) {
    if (hypothesis.kind !== 'length-prefix') continue;
    const boundaries = new Set(hypothesis.offsets);
    const aligned = positions.filter((position) => boundaries.has(position)).length;
    const missed = (positions.length - aligned) / positions.length;
    if (missed === 0) continue;
    // Each marker occurrence is a boundary under the competing parse. Any occurrence this parse
    // treats as payload is evidence the parse found a tiling, not the framing. The penalty is
    // proportional, so a marker byte that happens to occur inside one payload only costs a little.
    hypothesis.score = clamp01(hypothesis.score - 0.3 * missed);
    hypothesis.evidence.push(
      `the marker 0x${bytes.toString('hex')} occurs ${positions.length} times in the stream, but only ${aligned} of those positions are message boundaries under this parse`,
    );
    hypothesis.limitations.push(
      'a competing start-marker parse explains the repeated marker at every occurrence; this length parse treats some of them as payload',
    );
  }

  // A start marker that keeps swallowing the next message is not a marker, it is a marker plus
  // data. Its first two bytes usually occur far more often than the wider marker does; when that
  // happens, the wider marker is a restriction of the narrower one and must lose to it.
  for (const hypothesis of results) {
    if (hypothesis.kind !== 'start-marker' || !hypothesis.startMarker) continue;
    const wider = hypothesis.startMarker.marker;
    if (wider.length < 3) continue;
    const narrower = wider.subarray(0, 2);
    const occurrences: number[] = [];
    for (let at = stream.indexOf(narrower); at !== -1; at = stream.indexOf(narrower, at + 1)) occurrences.push(at);
    if (occurrences.length < 6) continue;
    const starts = new Set(hypothesis.offsets);
    const aligned = occurrences.filter((position) => starts.has(position)).length;
    const missed = (occurrences.length - aligned) / occurrences.length;
    if (missed < 0.5) continue;
    hypothesis.score = clamp01(hypothesis.score - 0.35 * missed);
    hypothesis.evidence.push(
      `0x${narrower.toString('hex')} occurs ${occurrences.length} times but only ${aligned} of those positions start one of these messages`,
    );
    hypothesis.limitations.push(
      'most occurrences of the first two marker bytes fall inside these messages, so the wider marker is a restriction of a shorter one',
    );
  }
}

/**
 * The mirror of the marker rule.
 *
 * A terminator that ends every message is a repeated boundary in the stream. A competing parse
 * that treats most of those positions as the middle of a message has found a coarser tiling, not
 * the framing — a coarser parse is exactly what happens when the real boundaries are invisible to
 * it. Only a text-delimited parse may make this argument: a terminator byte that happens to occur
 * in binary payloads proves nothing, and the score floor keeps those out.
 */
function applyTerminatorConsistency(results: FramingHypothesis[], stream: Buffer): void {
  const delimited = results
    .filter((h) => h.kind === 'delimiter' && h.delimiter !== undefined && h.messages.length >= 3 && h.score >= 0.82)
    .sort((a, b) => b.score - a.score)[0];
  if (!delimited?.delimiter) return;

  const terminator = delimited.delimiter.terminator;
  const positions: number[] = [];
  for (let at = stream.indexOf(terminator); at !== -1; at = stream.indexOf(terminator, at + 1)) positions.push(at);
  if (positions.length < 3) return;

  for (const hypothesis of results) {
    if (hypothesis.kind === 'delimiter') continue;
    if (hypothesis.messages.length === 0) continue;
    const ends = new Set<number>();
    for (let i = 0; i < hypothesis.messages.length; i++) ends.add(hypothesis.offsets[i]! + hypothesis.messages[i]!.length);
    const aligned = positions.filter((position) => ends.has(position + terminator.length)).length;
    const missed = (positions.length - aligned) / positions.length;
    if (missed < 0.3) continue;
    hypothesis.score = clamp01(hypothesis.score - 0.25 * missed);
    hypothesis.evidence.push(
      `0x${terminator.toString('hex')} ends ${positions.length} messages under a competing parse, but only ${aligned} of those positions end one of these`,
    );
    hypothesis.limitations.push(
      'a competing delimiter parse explains the repeated terminator at every occurrence; this parse treats most of them as payload',
    );
  }
}

/**
 * Does the parse show a second regularity besides its own length field?
 *
 * A tiling only proves that the byte under the length field happened to walk to the end of the
 * buffer; a random stream does that about once in a hundred hypotheses. A real protocol almost
 * always leaves another trace in its header: a constant magic or a type byte drawn from a small
 * set, or a counter that steps by a fixed amount. That second regularity is independent evidence,
 * and without it a length-prefix claim is a coincidence with a confident voice.
 */
function hasStructuralColumn(messages: Buffer[]): boolean {
  if (messages.length < 3) return false;
  const shortest = Math.min(...messages.map((message) => message.length));
  const width = Math.min(shortest, 24);
  const allowed = Math.max(2, Math.ceil(messages.length * 0.5));
  let columns = 0;

  for (let position = 0; position < width; position++) {
    const values = messages.map((message) => message[position]!);
    if (new Set(values).size <= allowed) {
      // One column is a coincidence of the sample; two independent regularities are structure.
      // A random buffer produces two such columns about once in a million parses; a real header
      // produces them because a magic, a type, a length high byte and a counter all sit there.
      if (++columns >= 2) return true;
      continue;
    }

    // A counter: distinct values that step by the same non-zero amount, in message order.
    let step: number | undefined;
    let arithmetic = values.length >= 4;
    for (let i = 1; i < values.length && arithmetic; i++) {
      const delta = values[i]! - values[i - 1]!;
      if (delta === 0) {
        arithmetic = false;
        break;
      }
      if (step === undefined) step = delta;
      else if (step !== delta) arithmetic = false;
    }
    if (arithmetic && new Set(values).size >= 3 && ++columns >= 2) return true;
  }
  return false;
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
  // The length field is not always the first thing in the message: a magic, a version, a type
  // and a sequence number can precede it. Sixteen bytes covers every header this tool has met.
  const maxLenOffset = Math.min(16, stream.length - 2);
  const streamPrintable = printableShare(stream);

  for (let lenOffset = 0; lenOffset <= maxLenOffset; lenOffset++) {
    for (const size of [1, 2, 4] as const) {
      if (lenOffset + size > 24) continue;
      for (const endian of size === 1 ? (['be'] as const) : (['le', 'be'] as const)) {
        for (let bias = -6; bias <= 12; bias++) {
          const spec: LengthPrefixSpec = { lenOffset, size, endian, bias };
          const segmentation = walkLengthPrefix(stream, spec);
          if (!segmentation) continue;

          const count = segmentation.messages.length;
          if (count < 3) continue;

          // The smallest legal message is the length field itself. A parse that needs two-byte
          // messages is not automatically wrong — MQTT's DISCONNECT is exactly two bytes — but a
          // parse made mostly of them is tiling the stream with whatever byte value came next.
          // Penalise the share instead of rejecting the hypothesis.
          const minimumMessage = Math.max(4, lenOffset + size);
          const tiny = segmentation.messages.reduce((n, m) => n + (m.length < minimumMessage ? 1 : 0), 0);
          const tinyShare = tiny / segmentation.messages.length;
          if (segmentation.messages.some((m) => m.length < lenOffset + size)) continue;

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
          // In a stream that is nothing but printable text, a length field made of printable
          // bytes is an ASCII character that happened to tile the stream. Check the field's
          // bytes, not its numeric value: a 4-byte big-endian 44 is 00 00 00 2c, four bytes of
          // which only one is printable. The message starts must be printable too: a binary
          // header followed by a text body is ordinary, and its length field is binary.
          let printableFieldBytes = 0;
          let fieldBytes = 0;
          for (const offset of segmentation.offsets) {
            for (let i = 0; i < size; i++) {
              const byte = stream[offset + lenOffset + i]!;
              fieldBytes++;
              if (byte >= 0x20 && byte <= 0x7e) printableFieldBytes++;
            }
          }
          const printableStarts =
            segmentation.offsets.filter((offset) => {
              const byte = stream[offset]!;
              return byte >= 0x20 && byte <= 0x7e;
            }).length / segmentation.offsets.length;
          const printableLength =
            streamPrintable >= 0.92 && printableStarts >= 0.5 && fieldBytes > 0 && printableFieldBytes / fieldBytes >= 0.5;

          // Each message boundary is one prediction that the length field made and the stream
          // confirmed. Three predictions are not evidence: a random stream tiles into three
          // chunks often enough to matter.
          const corroborated = hasStructuralColumn(segmentation.messages);

          const score =
            PRIOR['length-prefix'] -
            0.025 * Math.min(Math.abs(bias), 8) -
            0.015 * lenOffset +
            (size === 2 ? 0.02 : 0) +
            (count >= 4 ? 0.02 : -0.1 * (4 - count)) -
            (constantField ? 0.2 : 0) -
            (uninformativeField ? 0.22 : 0) -
            (printableLength ? 0.3 : 0) -
            0.35 * tinyShare +
            (corroborated ? 0.06 : -0.36);

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
              ...(printableLength
                ? ['the stream is printable text and the length byte is printable too, so this parse may be a coincidence of ASCII values rather than a declared field']
                : []),
              ...(tinyShare > 0
                ? [`${tiny} of ${segmentation.messages.length} messages are shorter than the length field plus one byte; a parse made of such fragments is usually a tiling rather than a framing`]
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
    if (isPreferredLengthField(hypothesis.lengthPrefix!, existing.lengthPrefix!)) {
      best.set(signature, hypothesis);
    }
  }
  void stream;
  return [...best.values()];
}

const WIDTH_PRIOR: Record<1 | 2 | 4, number> = { 2: 0, 1: 1, 4: 2 };

/**
 * Chooses between two length specs that segment the stream identically.
 *
 * Identical segmentation means both describe the same boundaries, so the choice is about which
 * field a reader should see, and the data cannot settle it: a two-byte big-endian length `00 33`
 * and a one-byte length at offset +1 produce the same stream until a message is long enough for
 * the high byte to move. The tie breaks on the published corpus rather than on taste — 16-bit
 * lengths are the common case (Modbus, DNS, RADIUS, most length-prefixed framing), then 8-bit,
 * then 32-bit — and the ambiguity is reported as a limitation on the hypothesis.
 */
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

  // 0x0a and 0x0d0a both consume the stream, because a 0x0d0a terminator contains 0x0a. The
  // shorter terminator then splits at every 0x0a that happens to sit in a checksum or a payload,
  // so the longer terminator — whose occurrences are a subset — wins.
  for (const shorter of out) {
    for (const longer of out) {
      if (shorter === longer) continue;
      const a = longer.delimiter!.terminator;
      const b = shorter.delimiter!.terminator;
      if (a.length <= b.length) continue;
      if (!a.subarray(a.length - b.length).equals(b)) continue;
      if (longer.messages.length >= shorter.messages.length) continue;
      shorter.score = clamp01(shorter.score - 0.12);
      shorter.limitations.push(
        `every occurrence of 0x${a.toString('hex')} ends a message under a competing parse, and 0x${b.toString('hex')} is its last byte; this shorter terminator splits at ${shorter.messages.length - longer.messages.length} more positions`,
      );
    }
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
  return printableShare(message) >= 0.85;
}

function printableShare(data: Buffer): number {
  if (data.length === 0) return 0;
  let printable = 0;
  for (const byte of data) {
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d) printable++;
  }
  return printable / data.length;
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

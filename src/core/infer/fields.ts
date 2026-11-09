import { Buffer } from 'node:buffer';
import type { Endian } from '../types.js';
import type { ChecksumMatch } from './checksum.js';
import type { FramingKind, LengthPrefixSpec } from './framing.js';

export type FieldRole = 'magic' | 'length' | 'counter' | 'opcode' | 'checksum' | 'text' | 'reserved' | 'payload' | 'unknown';

export type FieldAnchor = 'head' | 'tail';

export interface Field {
  name: string;
  role: FieldRole;
  anchor: FieldAnchor;
  /**
   * Head-anchored fields: byte offset from the message start.
   * Tail-anchored fields: bytes that follow this field, counted from the message end.
   */
  offset: number;
  /** Byte width, or -1 when the field runs to the message end. */
  length: number;
  width?: number;
  endian?: Endian;
  stats: {
    distinct: number;
    constant?: string;
    min?: number;
    max?: number;
    step?: number;
  };
  /** For checksum fields: the algorithm whose inverse the generated client embeds. */
  algorithm?: string;
  confidence: number;
  evidence: string[];
}

export interface FieldInferenceInput {
  messages: Buffer[];
  framing: FramingKind;
  lengthPrefix?: LengthPrefixSpec;
  checksum?: ChecksumMatch;
}

export interface FieldInference {
  fields: Field[];
  /** Bytes classified as head-anchored structure. */
  headerLength: number;
  notes: string[];
}

type Primitive = 'const' | 'counter' | 'length' | 'printable' | 'var';

/** Wide counters are searched only in the first bytes of a message, where headers live. */
const MAX_HEADER_SCAN = 24;

export function inferFields(input: FieldInferenceInput): FieldInference {
  const { messages, framing, lengthPrefix, checksum } = input;
  const notes: string[] = [];

  if (messages.length < 3) {
    return {
      fields: [payloadField(0, 'fewer than three messages; field boundaries cannot be established', 0.2)],
      headerLength: 0,
      notes: ['not enough messages for field inference'],
    };
  }

  const shortest = Math.min(...messages.map((m) => m.length));
  const longest = Math.max(...messages.map((m) => m.length));
  const constantLength = shortest === longest;

  if (framing === 'delimiter' && mostlyPrintable(messages)) {
    return {
      fields: [
        {
          name: 'text',
          role: 'text',
          anchor: 'head',
          offset: 0,
          length: -1,
          stats: { distinct: messages.length },
          confidence: 0.85,
          evidence: [
            'the framing is a terminator-delimited text protocol, so the message body is a single text field',
          ],
        },
      ],
      headerLength: 0,
      notes: ['text protocol: structure lives inside the text, not in byte offsets'],
    };
  }

  const prefixLength = shortest;
  const lengthSpan: [number, number] | null = lengthPrefix
    ? [lengthPrefix.lenOffset, lengthPrefix.lenOffset + lengthPrefix.size]
    : null;

  const primitive: Primitive[] = [];
  for (let offset = 0; offset < prefixLength; offset++) {
    const values = messages.map((m) => m[offset]!);
    if (lengthSpan && offset >= lengthSpan[0] && offset < lengthSpan[1]) {
      primitive.push('length');
    } else if (isStepping(values)) {
      primitive.push('counter');
    } else if (values.every((v) => v === values[0])) {
      primitive.push('const');
    } else if (values.every(isPrintable)) {
      primitive.push('printable');
    } else {
      primitive.push('var');
    }
  }

  const wideCounters = findWideCounters(messages, Math.min(prefixLength, MAX_HEADER_SCAN), lengthSpan);
  for (const counter of wideCounters) {
    for (let offset = counter.offset; offset < counter.offset + counter.width; offset++) primitive[offset] = 'counter';
  }

  const fields: Field[] = [];
  const used = new Set<string>();

  const leadingConstant = countLeading(primitive, 'const', prefixLength);
  const magicWidth = Math.min(leadingConstant, 4);

  if (magicWidth > 0) {
    const constant = messages[0]!.subarray(0, magicWidth).toString('hex');
    fields.push({
      name: 'magic',
      role: 'magic',
      anchor: 'head',
      offset: 0,
      length: magicWidth,
      stats: { distinct: 1, constant },
      confidence: magicWidth >= 2 ? 0.95 : 0.65,
      evidence: [
        `bytes 0..${magicWidth} are 0x${constant} in all ${messages.length} messages`,
        magicWidth >= 2
          ? 'a repeated multi-byte prefix is a framing marker'
          : 'a single constant byte is weaker evidence; it may be a message type that happens never to vary',
      ],
    });
  }

  let cursor = magicWidth;
  while (cursor < prefixLength) {
    if (lengthSpan && cursor >= lengthSpan[0] && cursor < lengthSpan[1]) {
      fields.push({
        name: unique('length', used),
        role: 'length',
        anchor: 'head',
        offset: cursor,
        length: lengthSpan[1] - cursor,
        width: lengthPrefix!.size,
        endian: lengthPrefix!.endian,
        stats: { distinct: messages.length },
        confidence: 0.97,
        evidence: [
          `a ${lengthPrefix!.size}-byte ${lengthPrefix!.endian} integer here reproduces every message length when ${lengthPrefix!.bias >= 0 ? 'added' : 'subtracted'} ${Math.abs(lengthPrefix!.bias)}`,
        ],
      });
      cursor = lengthSpan[1];
      continue;
    }

    const wide = wideCounters.find((c) => c.offset === cursor);
    if (wide) {
      const decoded = messages.map((m) => readAt(m, cursor, wide.width, wide.endian));
      fields.push({
        name: unique('sequence', used),
        role: 'counter',
        anchor: 'head',
        offset: cursor,
        length: wide.width,
        width: wide.width,
        endian: wide.endian,
        stats: { distinct: decoded.length, min: Math.min(...decoded), max: Math.max(...decoded), step: 1 },
        confidence: 0.95,
        evidence: [`read as a ${wide.width}-byte ${wide.endian} integer the value increases by exactly 1 per message`],
      });
      cursor += wide.width;
      continue;
    }

    const cls = primitive[cursor]!;

    if (cls === 'counter') {
      const decoded = messages.map((m) => m[cursor]!);
      fields.push({
        name: unique('sequence', used),
        role: 'counter',
        anchor: 'head',
        offset: cursor,
        length: 1,
        width: 1,
        endian: 'be',
        stats: { distinct: decoded.length, min: Math.min(...decoded), max: Math.max(...decoded), step: 1 },
        confidence: 0.88,
        evidence: ['the byte increases by exactly 1 for every consecutive message, wrapping at 0xff'],
      });
      cursor += 1;
      continue;
    }

    if (cls === 'const') {
      const end = runEnd(primitive, cursor, prefixLength, 'const', lengthSpan, wideCounters);
      const constant = messages[0]!.subarray(cursor, end).toString('hex');
      fields.push({
        name: unique('reserved', used),
        role: 'reserved',
        anchor: 'head',
        offset: cursor,
        length: end - cursor,
        stats: { distinct: 1, constant },
        confidence: 0.9,
        evidence: [`identical 0x${constant} in all ${messages.length} messages`],
      });
      cursor = end;
      continue;
    }

    if (cls === 'printable') {
      const end = runEnd(primitive, cursor, prefixLength, 'printable', lengthSpan, wideCounters);
      const distinct = new Set(messages.map((m) => m.subarray(cursor, end).toString('latin1'))).size;
      fields.push({
        name: unique('text', used),
        role: 'text',
        anchor: 'head',
        offset: cursor,
        length: end - cursor,
        stats: { distinct },
        confidence: 0.75,
        evidence: ['every byte in this run is printable ASCII across all messages'],
      });
      cursor = end;
      continue;
    }

    const opcode = tryOpcode(messages, cursor, prefixLength);
    if (opcode) {
      const decoded = messages.map((m) => readAt(m, cursor, opcode.width, 'be'));
      fields.push({
        name: unique('type', used),
        role: 'opcode',
        anchor: 'head',
        offset: cursor,
        length: opcode.width,
        width: opcode.width,
        endian: 'be',
        stats: { distinct: new Set(decoded).size, min: Math.min(...decoded), max: Math.max(...decoded) },
        confidence: opcode.width === 1 ? 0.8 : 0.7,
        evidence: [
          `${new Set(decoded).size} distinct values across ${messages.length} messages: the shape of a message type, not data`,
        ],
      });
      cursor += opcode.width;
      // One message type is expected. A second low-cardinality byte in the header is data that
      // happens to repeat in this session, not another type field.
      break;
    }

    // Anything left is data that happens to sit inside the common prefix.
    break;
  }

  const headerLength = cursor;
  const tailBytes = checksum ? checksum.offsetFromEnd + checksum.width : 0;
  const trailingStructure = constantLength ? longest - tailBytes : 0;
  const hasBody = headerLength < prefixLength || !constantLength || trailingStructure > headerLength;

  if (hasBody) {
    fields.push(
      payloadField(
        headerLength,
        constantLength
          ? `unclassified bytes between the header and the ${tailBytes > 0 ? 'checksum' : 'message end'}`
          : `message lengths range from ${shortest} to ${longest} bytes; this region absorbs the difference`,
        0.6,
      ),
    );
  }

  if (checksum) {
    fields.push({
      name: unique(`checksum_${checksum.algorithm.replace(/[^a-z0-9]+/gi, '_')}`, used),
      role: 'checksum',
      anchor: 'tail',
      offset: checksum.offsetFromEnd,
      length: checksum.width,
      width: checksum.width,
      endian: checksum.endian,
      algorithm: checksum.algorithm,
      stats: { distinct: messages.length },
      confidence: checksum.confidence,
      evidence: [checksum.evidence],
    });
  }

  if (!constantLength) {
    notes.push(
      `message length varies between ${shortest} and ${longest} bytes; head fields come from the common prefix of ${prefixLength} bytes`,
    );
  }
  if (checksum && !constantLength) {
    notes.push('the checksum is located from the end of each message, so it stays valid across variable lengths');
  }

  return { fields, headerLength, notes };
}

function payloadField(offset: number, evidence: string, confidence: number): Field {
  return {
    name: 'payload',
    role: 'payload',
    anchor: 'head',
    offset,
    length: -1,
    stats: { distinct: Infinity },
    confidence,
    evidence: [evidence],
  };
}

/**
 * A message type is a small field with few distinct values. Two signals are used, in order:
 *
 * - cardinality: the value must repeat across messages, otherwise it is data
 * - collapse: a two-byte reading is only preferred when pairing the bytes actually reduces
 *   the alphabet, which is what a 16-bit type does and what "type plus the first data byte"
 *   does not
 */
function tryOpcode(messages: Buffer[], cursor: number, prefixLength: number): { width: 1 | 2 } | null {
  const cap = Math.max(6, Math.ceil(messages.length * 0.75));
  const singles = new Set(messages.map((m) => m[cursor]!));
  if (singles.size < 2 || singles.size > cap) return null;

  if (cursor + 2 <= prefixLength) {
    const pairs = new Set(messages.map((m) => readAt(m, cursor, 2, 'be')));
    if (pairs.size >= 2 && pairs.size <= cap && pairs.size <= Math.ceil(singles.size * 0.6)) return { width: 2 };
  }

  return { width: 1 };
}

function runEnd(
  primitive: Primitive[],
  start: number,
  limit: number,
  cls: Primitive,
  lengthSpan: [number, number] | null,
  wideCounters: Array<{ offset: number; width: number }>,
): number {
  let end = start + 1;
  while (end < limit) {
    if (primitive[end] !== cls) break;
    if (lengthSpan && end >= lengthSpan[0] && end < lengthSpan[1]) break;
    if (wideCounters.some((c) => end >= c.offset && end < c.offset + c.width)) break;
    end++;
  }
  return end;
}

function countLeading(primitive: Primitive[], cls: Primitive, limit: number): number {
  let count = 0;
  while (count < limit && primitive[count] === cls) count++;
  return count;
}

function findWideCounters(
  messages: Buffer[],
  limit: number,
  lengthSpan: [number, number] | null,
): Array<{ offset: number; width: 2 | 4; endian: Endian }> {
  const found: Array<{ offset: number; width: 2 | 4; endian: Endian }> = [];
  if (messages.length < 4) return found;

  // Lowest offset first, then narrower width: the low bytes of a counter are the ones that
  // step, so the smaller reading is the one the data actually supports.
  for (let offset = 0; offset < limit; offset++) {
    for (const width of [2, 4] as const) {
      if (offset + width > limit) continue;
      if (lengthSpan && offset < lengthSpan[1] && offset + width > lengthSpan[0]) continue;
      if (found.some((c) => offset < c.offset + c.width && offset + width > c.offset)) continue;

      for (const endian of ['le', 'be'] as const) {
        const decoded = messages.map((m) => readAt(m, offset, width, endian));
        if (new Set(decoded).size !== decoded.length) continue;
        const modulo = width === 2 ? 0x10000 : 0x1_0000_0000;
        let steps = true;
        for (let i = 1; i < decoded.length; i++) {
          if ((decoded[i - 1]! + 1) % modulo !== decoded[i]) {
            steps = false;
            break;
          }
        }
        if (!steps) continue;
        found.push({ offset, width, endian });
        break;
      }
    }
  }

  return found;
}

function isStepping(values: number[]): boolean {
  if (values.length < 4) return false;
  for (let i = 1; i < values.length; i++) {
    const previous = values[i - 1]!;
    if (previous === values[i]!) return false;
    if ((previous + 1) % 256 !== values[i]!) return false;
  }
  return true;
}

function readAt(message: Buffer, at: number, width: number, endian: Endian): number {
  if (at + width > message.length) return -1;
  if (width === 1) return message[at]!;
  if (width === 2) return endian === 'le' ? message.readUInt16LE(at) : message.readUInt16BE(at);
  return endian === 'le' ? message.readUInt32LE(at) : message.readUInt32BE(at);
}

function isPrintable(byte: number): boolean {
  return (byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d;
}

function mostlyPrintable(messages: Buffer[]): boolean {
  let printable = 0;
  let total = 0;
  for (const message of messages) {
    for (const byte of message) {
      total++;
      if (isPrintable(byte)) printable++;
    }
  }
  return total > 0 && printable / total >= 0.9;
}

function unique(name: string, used: Set<string>): string {
  if (!used.has(name)) {
    used.add(name);
    return name;
  }
  let n = 2;
  while (used.has(`${name}_${n}`)) n++;
  const final = `${name}_${n}`;
  used.add(final);
  return final;
}

/** Byte span of a field inside one message, or null when it does not fit. */
export function fieldSpan(message: Buffer, field: Field): [number, number] | null {
  if (field.length < 0) return [field.offset, message.length];
  const start = field.anchor === 'head' ? field.offset : message.length - field.offset - field.length;
  const end = start + field.length;
  if (start < 0 || end > message.length) return null;
  return [start, end];
}

/** Numeric value of a field, or a latin1 string for text fields. */
export function fieldValue(message: Buffer, field: Field): number | string | undefined {
  const span = fieldSpan(message, field);
  if (!span) return undefined;
  const bytes = message.subarray(span[0], span[1]);
  if (field.role === 'text') return bytes.toString('latin1');
  let value = 0;
  for (const byte of bytes) value = value * 256 + byte;
  return value;
}

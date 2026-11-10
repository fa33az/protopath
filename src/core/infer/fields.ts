import { Buffer } from 'node:buffer';
import type { Endian } from '../types.js';
import type { ChecksumMatch, ChecksumSpec } from './checksum.js';
import type { FramingKind, LengthPrefixSpec } from './framing.js';

export type FieldRole =
  | 'magic'
  | 'length'
  | 'counter'
  | 'timestamp'
  | 'opcode'
  | 'checksum'
  | 'text'
  | 'reserved'
  | 'payload'
  | 'unknown';

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
  /** For checksum fields recovered from the data: the exact parameter set to embed. */
  spec?: ChecksumSpec;
  confidence: number;
  evidence: string[];
}

export interface FieldInferenceInput {
  messages: Buffer[];
  framing: FramingKind;
  lengthPrefix?: LengthPrefixSpec;
  checksum?: ChecksumMatch;
  /** Parameter set for `checksum` when it was recovered rather than named. */
  spec?: ChecksumSpec;
}

export interface FieldInference {
  fields: Field[];
  /** Bytes classified as head-anchored structure. */
  headerLength: number;
  notes: string[];
}

/** Wide counters are searched only in the first bytes of a message, where headers live. */
const MAX_HEADER_SCAN = 24;

/**
 * How many unnamed bytes may sit inside a header before the walk gives up and calls the region
 * payload. A request id or a random nonce is ordinary; a run longer than this is content.
 */
const MAX_UNKNOWN_GAP = 8;

export function inferFields(input: FieldInferenceInput): FieldInference {
  const { messages, framing, lengthPrefix, checksum, spec } = input;
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
  const textBody = mostlyPrintable(messages);

  const prefixLength = shortest;
  const lengthSpan: [number, number] | null = lengthPrefix
    ? [lengthPrefix.lenOffset, lengthPrefix.lenOffset + lengthPrefix.size]
    : null;
  const tailBytes = checksum ? checksum.offsetFromEnd + checksum.width : 0;

  // Only the common prefix of every message can hold a head field: past it, the shortest message
  // has no byte to read. Each column of that prefix gets a class, and the header model is built
  // from the classes. Classifying columns first, then naming runs, is what keeps one unnameable
  // byte from ending the header and throwing the rest of it into the payload.
  const columns: number[][] = [];
  for (let at = 0; at < prefixLength; at++) columns.push(messages.map((message) => message[at]!));

  const inLength = (at: number): boolean => lengthSpan !== null && at >= lengthSpan[0] && at < lengthSpan[1];
  const inChecksum = (at: number): boolean =>
    constantLength && checksum !== undefined && at >= prefixLength - tailBytes && at < prefixLength;
  const classes: ColumnClass[] = columns.map((values, at) =>
    inLength(at) ? 'length' : classifyColumn(values, messages.length),
  );

  const fields: Field[] = [];
  const used = new Set<string>();

  /** Four columns that are printable in every message are the opening of a text body. */
  const opensText = (at: number): boolean => {
    if (at + 4 > prefixLength) return false;
    for (let i = at; i < at + 4; i++) if (!columns[i]!.every((value) => isPrintable(value))) return false;
    return true;
  };

  /**
   * Where a constant run ends, and where its bytes stop being structure and start being text.
   * `0x09 0x01` followed by "status ok" is a two-byte header on a text body, not an eight-byte
   * header that happens to contain a word.
   */
  const constRun = (start: number): { end: number; textStart: number } => {
    let end = start;
    while (end < prefixLength && classes[end] === 'const') end++;
    let textStart = end;
    for (let at = start + 1; at + 3 <= end; at++) {
      let printable = true;
      for (let i = at; i < at + 3; i++) {
        if (!columns[i]!.every((value) => isPrintable(value))) {
          printable = false;
          break;
        }
      }
      if (printable) {
        textStart = at;
        break;
      }
    }
    return { end, textStart };
  };

  const leading = classes[0] === 'const' && !detectWideField(messages, 0, Math.min(prefixLength, MAX_HEADER_SCAN), inLength)
    ? constRun(0)
    : null;
  const magicWidth = leading ? Math.min(leading.textStart, 4) : 0;

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
  let smallSets = 0;
  const scanLimit = Math.min(prefixLength, MAX_HEADER_SCAN);

  while (cursor < scanLimit) {
    if (inLength(cursor)) {
      fields.push({
        name: unique('length', used),
        role: 'length',
        anchor: 'head',
        offset: cursor,
        length: lengthSpan![1] - cursor,
        width: lengthPrefix!.size,
        endian: lengthPrefix!.endian,
        stats: { distinct: messages.length },
        confidence: 0.97,
        evidence: [
          `a ${lengthPrefix!.size}-byte ${lengthPrefix!.endian} integer here reproduces every message length when ${lengthPrefix!.bias >= 0 ? 'added' : 'subtracted'} ${Math.abs(lengthPrefix!.bias)}`,
        ],
      });
      cursor = lengthSpan![1];
      continue;
    }

    if (inChecksum(cursor)) break;

    // A run of stepping columns is a header only when it is short. A patterned payload advances
    // by a fixed stride in every column — a ramp written by the sender looks exactly like this —
    // and seventeen consecutive counters are a body, not a header. This has to be checked before
    // the wide-field test, or a 2-byte pairing of two ramped columns is named a counter.
    if (classes[cursor] === 'step') {
      let runEndAt = cursor;
      while (runEndAt < prefixLength && classes[runEndAt] === 'step') runEndAt++;
      if (runEndAt - cursor > 4) break;
    }

    // A field wider than one byte is invisible to the column classes: its low byte steps while
    // its high byte sits still, which reads as a counter followed by a constant. Try the wide
    // readings first, before the byte walk gets to pick them apart.
    const wide = detectWideField(messages, cursor, scanLimit, inLength);
    if (wide) {
      const decoded = messages.map((message) => readAt(message, cursor, wide.width, wide.endian));
      const isClock = wide.role === 'timestamp';
      fields.push({
        name: unique(isClock ? 'timestamp' : 'sequence', used),
        role: wide.role,
        anchor: 'head',
        offset: cursor,
        length: wide.width,
        width: wide.width,
        endian: wide.endian,
        stats: { distinct: decoded.length, min: Math.min(...decoded), max: Math.max(...decoded), step: wide.step },
        confidence: isClock ? 0.85 : 0.92,
        evidence: [
          isClock
            ? `read as a ${wide.width}-byte ${wide.endian} integer the value lands in the epoch range and climbs by ${wide.step} per message`
            : `read as a ${wide.width}-byte ${wide.endian} integer the value climbs by exactly ${wide.step} per message`,
        ],
      });
      cursor += wide.width;
      continue;
    }

    if (opensText(cursor)) break;

    const cls = classes[cursor]!;

    // After the message type, only a length or a stepping value is still structure, and a short
    // constant run is allowed only when it leads straight into one of those. Modbus answers begin
    // with a constant register high byte that runs into data, and naming it `reserved` pushes the
    // body two bytes late; a flags byte followed by a length field is still header.
    if (smallSets > 0) {
      if (cls !== 'const' && cls !== 'step') break;
      if (cls === 'const') {
        const run = constRun(cursor);
        const end = Math.min(run.end, run.textStart);
        const continues =
          inLength(end) || detectWideField(messages, end, scanLimit, inLength) !== null;
        // A short constant run that leaves a body too small to be a body belongs to that body.
        const leavesBody = prefixLength - end >= 8;
        if (end - cursor > 2 || (!continues && !leavesBody)) break;
      }
    }

    if (cls === 'const') {
      const run = constRun(cursor);
      const end = Math.min(run.end, run.textStart);
      const width = end - cursor;
      // A constant run longer than this is padding or repeated text, not a header field.
      if (width > 8) break;
      const constant = messages[0]!.subarray(cursor, end).toString('hex');
      fields.push({
        name: unique('reserved', used),
        role: 'reserved',
        anchor: 'head',
        offset: cursor,
        length: width,
        stats: { distinct: 1, constant },
        confidence: 0.9,
        evidence: [`identical 0x${constant} in all ${messages.length} messages`],
      });
      cursor = end;
      continue;
    }

    if (cls === 'step') {
      const decoded = messages.map((message) => message[cursor]!);
      const step = byteStep(decoded);
      fields.push({
        name: unique('sequence', used),
        role: 'counter',
        anchor: 'head',
        offset: cursor,
        length: 1,
        width: 1,
        endian: 'be',
        stats: { distinct: decoded.length, min: Math.min(...decoded), max: Math.max(...decoded), step },
        confidence: 0.88,
        evidence: [`the byte advances by exactly ${step} for every consecutive message, wrapping at 0xff`],
      });
      cursor += 1;
      continue;
    }

    if (cls === 'set' && smallSets < 2) {
      const opcode = tryOpcode(messages, cursor, prefixLength);
      if (opcode) {
        const decoded = messages.map((message) => readAt(message, cursor, opcode.width, 'be'));
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
        smallSets += 1;
        continue;
      }
    }

    if (cls === 'set') break;

    // A short run of bytes that match nothing is still part of the header, and naming it
    // `unknown` is what lets the length field and a later counter still be found. A long run is
    // the payload, and the header ends before it.
    let end = cursor;
    while (end < prefixLength && classes[end] === 'var') end++;
    if (end - cursor > MAX_UNKNOWN_GAP) break;
    fields.push({
      name: unique('unknown', used),
      role: 'unknown',
      anchor: 'head',
      offset: cursor,
      length: end - cursor,
      stats: { distinct: new Set(columns[cursor]!).size },
      confidence: 0.4,
      evidence: [`${end - cursor} byte(s) here vary without a model: neither a constant, a stepping value, nor a small alphabet`],
    });
    cursor = end;
  }

  const headerLength = cursor;
  const trailingStructure = constantLength ? longest - tailBytes : 0;
  const hasBody = headerLength < prefixLength || !constantLength || trailingStructure > headerLength;

  if (hasBody) {
    fields.push(
      payloadField(
        headerLength,
        textBody
          ? 'the bytes after the header are printable text in every message: the structure from here lives inside the text, not at fixed offsets'
          : constantLength
            ? `unclassified bytes between the header and the ${tailBytes > 0 ? 'checksum' : 'message end'}`
            : `message lengths range from ${shortest} to ${longest} bytes; this region absorbs the difference`,
        textBody ? 0.85 : 0.6,
        textBody ? 'text' : 'payload',
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
      ...(spec ? { spec } : {}),
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

function payloadField(offset: number, evidence: string, confidence: number, role: 'payload' | 'text' = 'payload'): Field {
  return {
    name: role === 'text' ? 'text' : 'payload',
    role,
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

  // A byte that is printable in every message is a letter, not a code. Binary protocols do use
  // ASCII in message types, but then the field is constant or the framing is textual, and
  // calling the first letter of a command word an opcode invents a boundary one byte too late.
  if (messages.every((m) => isPrintable(m[cursor]!))) return null;

  if (cursor + 2 <= prefixLength) {
    const pairs = new Set(messages.map((m) => readAt(m, cursor, 2, 'be')));
    if (pairs.size >= 2 && pairs.size <= cap && pairs.size <= Math.ceil(singles.size * 0.6)) return { width: 2 };
  }

  return { width: 1 };
}

/** How a column of bytes across the capture behaves. */
type ColumnClass = 'length' | 'const' | 'step' | 'set' | 'var';

/**
 * A two-byte counter and a counter followed by a constant are indistinguishable until the high
 * byte moves, so the header is built from the narrowest reading the data supports. Reporting the
 * extra byte as `reserved` is honest about what the capture proved.
 */
function classifyColumn(values: number[], messageCount: number): ColumnClass {
  if (values.every((value) => value === values[0])) return 'const';

  const step = byteStep(values);
  if (step > 0) return 'step';

  const distinct = new Set(values).size;
  const cap = Math.max(4, Math.ceil(messageCount * 0.6));
  if (distinct >= 2 && distinct <= cap) return 'set';

  return 'var';
}

/** The constant step of a byte column, wrapping at 256, or 0 when there is none. */
function byteStep(values: number[]): number {
  if (values.length < 3) return 0;
  const step = (values[1]! - values[0]! + 256) % 256;
  if (step === 0 || step > 128) return 0;
  for (let i = 1; i < values.length; i++) {
    if ((values[i]! - values[i - 1]! + 256) % 256 !== step) return 0;
  }
  return step;
}

/** The constant positive step of an integer column, or 0 when there is none. */
function constantStep(values: number[]): number {
  if (values.length < 3) return 0;
  const step = values[1]! - values[0]!;
  if (step <= 0) return 0;
  for (let i = 2; i < values.length; i++) if (values[i]! - values[i - 1]! !== step) return 0;
  return step;
}

function isEpoch(value: number): boolean {
  return (value >= 1_000_000_000 && value < 2_200_000_000) || (value >= 1_000_000_000_000 && value < 4_000_000_000_000);
}

/**
 * A multi-byte field whose value climbs by a constant amount per message.
 *
 * A clock is checked first and at full width, because its low bytes jitter across every message
 * and a narrower reading sees noise. A counter is then reported at the narrowest width that
 * explains the bytes, since a wider read whose extra bytes are constant is not evidence.
 */
function detectWideField(
  messages: Buffer[],
  at: number,
  limit: number,
  excluded: (offset: number) => boolean,
): { width: 2 | 4; endian: Endian; step: number; role: 'counter' | 'timestamp' } | null {
  if (messages.length < 4) return null;

  const spansExcluded = (width: number): boolean => {
    if (at + width > limit) return true;
    for (let i = at; i < at + width; i++) if (excluded(i)) return true;
    return false;
  };

  if (!spansExcluded(4)) {
    for (const endian of ['le', 'be'] as const) {
      const values = messages.map((message) => readAt(message, at, 4, endian));
      if (values.some((value) => value < 0)) continue;
      if (new Set(values).size !== values.length) continue;
      const step = constantStep(values);
      if (step > 0 && isEpoch(values[0]!)) return { width: 4, endian, step, role: 'timestamp' };

      // A real clock jitters: the amount it advances by varies, but it always advances, it never
      // jumps far, and every value sits in the epoch window. Requiring a constant step found only
      // the clocks that no sender actually emits.
      const climbing = values.every((value, index) => index === 0 || (value > values[index - 1]! && value - values[index - 1]! <= 65_536));
      if (climbing && values.every((value) => isEpoch(value))) {
        return { width: 4, endian, step: Math.round((values[values.length - 1]! - values[0]!) / (values.length - 1)), role: 'timestamp' };
      }
    }
  }

  if (spansExcluded(2)) return null;
  // Both byte orders can step constantly — a big-endian counter 00 01, 00 02 reads little-endian
  // as 0x0100, 0x0200, a step of 256. The reading whose value advances by the smaller amount is
  // the field the sender wrote.
  let best: { endian: Endian; step: number } | null = null;
  for (const endian of ['le', 'be'] as const) {
    const values = messages.map((message) => readAt(message, at, 2, endian));
    if (new Set(values).size !== values.length) continue;
    const step = constantStep(values);
    if (step === 0) continue;
    if (!best || step < best.step) best = { endian, step };
  }

  return best ? { width: 2, endian: best.endian, step: best.step, role: 'counter' } : null;
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

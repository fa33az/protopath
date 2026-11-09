import { Buffer } from 'node:buffer';
import { fieldSpan, type Field, type FieldRole } from './fields.js';

/**
 * Payload semantics.
 *
 * Framing and field boundaries say where the bytes are. This module says what they look like
 * they mean: whether a field is a flag set or a counter, whether a payload is text with a
 * command word, and whether a binary payload is an array of fixed records.
 *
 * Everything here is derived from the captured values only. A field is reported as a timestamp
 * because its values fall in a range where seconds-since-1970 are plausible and nothing else
 * is; that is a hypothesis with a number attached, not a fact about the protocol. The evidence
 * string always names the observation, so a reader can disagree with it.
 */

export type ValueDomain =
  | 'constant'
  | 'boolean'
  | 'enum'
  | 'flags'
  | 'counter'
  | 'timestamp'
  | 'length'
  | 'text'
  | 'range'
  | 'opaque';

export interface FieldDomain {
  field: string;
  role: FieldRole;
  domain: ValueDomain;
  confidence: number;
  /** Up to six distinct observed values, formatted for a human. */
  values: string[];
  note: string;
}

export interface TextArgument {
  position: number;
  kind: 'integer' | 'decimal' | 'address' | 'identifier' | 'quoted' | 'mixed';
  examples: string[];
}

export interface TextVocabulary {
  separator: string;
  verbs: Array<{ value: string; count: number }>;
  arguments: TextArgument[];
  /** Tokens that held the same value at the same position in every message that had one. */
  constants: Array<{ position: number; value: string }>;
}

export interface EmbeddedString {
  offset: number;
  values: string[];
  messages: number;
}

export interface RecordLayout {
  size: number;
  records: number;
  columns: number;
  constantColumns: number;
  note: string;
}

export interface PayloadSemantics {
  encoding: 'text' | 'binary';
  vocabulary?: TextVocabulary;
  strings: EmbeddedString[];
  record?: RecordLayout;
  notes: string[];
}

export interface Semantics {
  domains: FieldDomain[];
  payload: PayloadSemantics;
  notes: string[];
}

const PRINTABLE = (byte: number): boolean =>
  (byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d;

function readInt(message: Buffer, at: number, width: number, endian: 'le' | 'be'): number {
  if (width === 1) return message[at]!;
  if (width === 2) return endian === 'le' ? message.readUInt16LE(at) : message.readUInt16BE(at);
  return endian === 'le' ? message.readUInt32LE(at) : message.readUInt32BE(at);
}

function hex(value: number, width: number): string {
  return `0x${value.toString(16).padStart(width * 2, '0')}`;
}

function popcount(value: number): number {
  let count = 0;
  let rest = value;
  while (rest > 0) {
    if (rest & 1) count++;
    rest >>>= 1;
  }
  return count;
}

export function inferSemantics(messages: Buffer[], fields: Field[]): Semantics {
  const notes: string[] = [];
  const domains: FieldDomain[] = [];

  if (messages.length < 3) {
    return {
      domains,
      payload: { encoding: 'binary', strings: [], notes: ['fewer than three messages; no value domains to compare'] },
      notes,
    };
  }

  for (const field of fields) {
    if (field.role === 'payload') continue;
    if (field.length <= 0) {
      if (field.role === 'text') {
        domains.push({
          field: field.name,
          role: field.role,
          domain: 'text',
          confidence: 0.8,
          values: [],
          note: 'the whole message body is text; the interesting structure is inside it',
        });
      }
      continue;
    }

    const values: number[] = [];
    let printable = true;
    for (const message of messages) {
      const span = fieldSpan(message, field);
      if (!span) continue;
      values.push(readInt(message, span[0], field.length, field.endian ?? 'be'));
      for (let i = span[0]; i < span[1]; i++) if (!PRINTABLE(message[i]!)) printable = false;
    }
    if (values.length < 3) continue;

    domains.push(classify(field, values, messages, printable));
  }

  const payload = inferPayload(messages, fields);
  notes.push(...payload.notes);

  const aliases = domains.filter((domain) => domain.domain === 'length' && domain.role !== 'length');
  if (aliases.length > 0) {
    notes.push(
      `${aliases.map((alias) => alias.field).join(', ')} track message length without being the framing length; they are candidate body-length fields`,
    );
  }

  return { domains, payload, notes };
}

function classify(field: Field, values: number[], messages: Buffer[], printable: boolean): FieldDomain {
  const width = field.length;
  const distinct = [...new Set(values)];
  const sorted = [...distinct].sort((a, b) => a - b);
  const sample = sorted.slice(0, 6).map((value) => (width === 1 ? `0x${value.toString(16).padStart(2, '0')}` : hex(value, width)));

  const base = {
    field: field.name,
    role: field.role,
    values: sample,
  };

  if (distinct.length === 1) {
    return { ...base, domain: 'constant', confidence: 0.95, note: `always ${hex(distinct[0]!, width)} in this capture` };
  }

  // A field that equals message length minus a constant is a body-length field even when the
  // framing uses a different one. This is checked before the statistical shapes because it is
  // an exact relation, not a resemblance.
  for (let bias = 0; bias <= 12; bias++) {
    const hits = values.filter((value, index) => messages[index] && value === messages[index]!.length - bias).length;
    if (hits === values.length) {
      return {
        ...base,
        domain: 'length',
        confidence: 0.9,
        note: `equals message length ${bias === 0 ? '' : `minus ${bias} `}in every message, so it counts bytes rather than carrying data`,
      };
    }
  }

  if (field.role === 'counter') {
    return { ...base, domain: 'counter', confidence: 0.95, note: 'increases by one per message; it orders the conversation' };
  }

  if (field.role === 'checksum') {
    return {
      ...base,
      domain: 'opaque',
      confidence: 0.95,
      note: 'a check value is a function of the other bytes, so its own values carry no meaning beyond passing or failing',
    };
  }

  if (distinct.every((value) => value === 0 || value === 1)) {
    return {
      ...base,
      domain: 'boolean',
      confidence: 0.9,
      note: `only 0 and 1 appear, both values are present: a flag rather than a number`,
    };
  }

  // Four printable bytes read as an integer land in the unix-seconds window often enough that
  // this check has to come before the timestamp one, not after it.
  if (printable) {
    const words = [
      ...new Set(
        messages
          .map((message) => {
            const span = fieldSpan(message, field);
            return span ? message.subarray(span[0], span[1]).toString('latin1') : '';
          })
          .filter((word) => word.length > 0),
      ),
    ].slice(0, 6);
    return {
      ...base,
      domain: 'text',
      confidence: 0.8,
      values: words,
      note: 'every byte of this field is printable ASCII in every message: a word or identifier, not a number',
    };
  }

  if (width === 4) {
    const seconds = values.every((value) => value >= 946_684_800 && value <= 2_208_988_800);
    if (seconds) {
      const span = `${new Date(Math.min(...values) * 1000).toISOString().slice(0, 10)} to ${new Date(Math.max(...values) * 1000).toISOString().slice(0, 10)}`;
      return { ...base, domain: 'timestamp', confidence: 0.7, note: `every value lands between ${span} read as unix seconds` };
    }
    const millis = values.every((value) => value >= 946_684_800_000 && value <= 2_208_988_800_000);
    if (millis) {
      const span = `${new Date(Math.min(...values)).toISOString().slice(0, 10)} to ${new Date(Math.max(...values)).toISOString().slice(0, 10)}`;
      return { ...base, domain: 'timestamp', confidence: 0.7, note: `every value lands between ${span} read as unix milliseconds` };
    }
  }

  // Flags: few bits ever set, and the values are not a dense run, which is what separates a
  // bitmask from a small enum. An opcode is never a flag set: the values are alternatives, not
  // things that combine.
  const bits = distinct.map(popcount);
  const maxBits = Math.max(...bits);
  const dense = sorted.every((value, index) => index === 0 || value === sorted[index - 1]! + 1);
  if (field.role !== 'opcode' && maxBits <= 3 && distinct.length >= 2 && !dense && width >= 1) {
    return {
      ...base,
      domain: 'flags',
      confidence: 0.6,
      note: `at most ${maxBits} bit${maxBits === 1 ? '' : 's'} set in any observed value, and the values are not consecutive: looks like independent flags`,
    };
  }

  if (distinct.length <= 8 && distinct.length * 2 <= values.length) {
    return {
      ...base,
      domain: 'enum',
      confidence: 0.75,
      note: `${distinct.length} distinct values over ${values.length} messages: a small closed set, the shape of a code`,
    };
  }

  return {
    ...base,
    domain: 'range',
    confidence: 0.4,
    note: `${distinct.length} distinct values spanning ${Math.min(...values)} to ${Math.max(...values)}; no shape beyond range`,
  };
}

function inferPayload(messages: Buffer[], fields: Field[]): PayloadSemantics {
  const notes: string[] = [];
  const bodies: Array<{ bytes: Buffer; payload: Buffer }> = [];

  for (const message of messages) {
    const payloadField = fields.find((field) => field.role === 'payload');
    const span = payloadField ? fieldSpan(message, payloadField) : [0, message.length] as [number, number];
    if (!span || span[1] <= span[0]) continue;
    bodies.push({ bytes: message, payload: message.subarray(span[0], span[1]) });
  }

  if (bodies.length === 0) {
    return { encoding: 'binary', strings: [], notes: ['no payload bytes were recovered'] };
  }

  let printable = 0;
  let total = 0;
  for (const body of bodies) {
    for (const byte of body.payload) {
      total++;
      if (PRINTABLE(byte)) printable++;
    }
  }

  if (total > 0 && printable / total >= 0.9) {
    const vocabulary = readVocabulary(bodies.map((body) => body.payload));
    notes.push(
      `the payload is ${Math.round((printable / total) * 100)}% printable ASCII; the structure is a word sequence, not a byte layout`,
    );
    if (vocabulary.verbs.length > 0) {
      notes.push(
        `${vocabulary.verbs.length} distinct leading token(s); they are the closest thing this protocol has to message types`,
      );
    }
    return { encoding: 'text', vocabulary, strings: [], notes };
  }

  const strings = findEmbeddedStrings(bodies.map((body) => body.payload));
  if (strings.length > 0) {
    notes.push('printable runs at stable offsets inside a binary payload are usually names, identifiers or constants');
  }

  const record = guessRecord(bodies.map((body) => body.payload));
  if (record) notes.push(record.note);

  return { encoding: 'binary', strings, record: record ?? undefined, notes: [...notes, ...(record ? [] : [])] };
}

function readVocabulary(payloads: Buffer[]): TextVocabulary {
  const separator = ' ';
  const lines = payloads
    .map((payload) => payload.toString('latin1').replace(/[\r\n]+$/, ''))
    .filter((line) => line.trim().length > 0);

  const tokenised = lines.map((line) => line.split(/[ \t]+/).filter((token) => token.length > 0));
  const verbCounts = new Map<string, number>();
  for (const tokens of tokenised) {
    const verb = tokens[0];
    if (verb) verbCounts.set(verb, (verbCounts.get(verb) ?? 0) + 1);
  }

  const verbs = [...verbCounts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
    .slice(0, 12);

  const maxTokens = Math.max(0, ...tokenised.map((tokens) => tokens.length));
  const argumentsOut: TextArgument[] = [];
  const constants: Array<{ position: number; value: string }> = [];

  for (let position = 1; position < maxTokens; position++) {
    const column = tokenised.map((tokens) => tokens[position]).filter((token): token is string => token !== undefined);
    if (column.length < 3) continue;

    if (new Set(column).size === 1) {
      constants.push({ position, value: column[0]! });
      continue;
    }

    argumentsOut.push({ position, kind: classifyToken(column), examples: [...new Set(column)].slice(0, 3) });
  }

  return { separator, verbs, arguments: argumentsOut, constants };
}

function classifyToken(column: string[]): TextArgument['kind'] {
  if (column.every((token) => /^-?\d+$/.test(token))) return 'integer';
  if (column.every((token) => /^-?\d*\.\d+$/.test(token))) return 'decimal';
  if (column.every((token) => /^\d{1,3}(\.\d{1,3}){3}$/.test(token))) return 'address';
  if (column.every((token) => /^[A-Za-z_][A-Za-z0-9_.:-]*$/.test(token))) return 'identifier';
  if (column.every((token) => /^".*"$/.test(token))) return 'quoted';
  return 'mixed';
}

function findEmbeddedStrings(payloads: Buffer[]): EmbeddedString[] {
  const byOffset = new Map<number, Set<string>>();
  const hits = new Map<number, number>();

  for (const payload of payloads) {
    const seenHere = new Set<number>();
    let runStart = -1;
    for (let i = 0; i <= payload.length; i++) {
      const byte = i < payload.length ? payload[i]! : 0;
      const printable = i < payload.length && PRINTABLE(byte) && byte !== 0x09 && byte !== 0x0a && byte !== 0x0d;
      if (printable && runStart < 0) runStart = i;
      if (!printable && runStart >= 0) {
        const run = payload.subarray(runStart, i).toString('latin1');
        if (run.length >= 3 && run.length <= 32) {
          const bucket = byOffset.get(runStart);
          if (bucket) bucket.add(run);
          else byOffset.set(runStart, new Set([run]));
          if (!seenHere.has(runStart)) {
            hits.set(runStart, (hits.get(runStart) ?? 0) + 1);
            seenHere.add(runStart);
          }
        }
        runStart = -1;
      }
    }
  }

  const threshold = Math.max(2, Math.ceil(payloads.length * 0.5));
  return [...byOffset.entries()]
    .filter(([offset]) => (hits.get(offset) ?? 0) >= threshold)
    .map(([offset, values]) => ({
      offset,
      values: [...values].slice(0, 4),
      messages: hits.get(offset) ?? 0,
    }))
    .sort((a, b) => b.messages - a.messages || a.offset - b.offset)
    .slice(0, 6);
}

/**
 * A fixed record array shows up as payload lengths that are multiples of a small size and byte
 * columns that never change. The test is deliberately weak — it only reports when a clear
 * fraction of columns is constant — because "the payload is 12 bytes, therefore three 4-byte
 * records" is a claim that is wrong more often than it is right.
 */
function guessRecord(payloads: Buffer[]): RecordLayout | null {
  const usable = payloads.filter((payload) => payload.length >= 4);
  if (usable.length < 4) return null;

  let best: RecordLayout | null = null;
  for (let size = 2; size <= 16; size++) {
    if (!usable.every((payload) => payload.length % size === 0)) continue;
    const recordsPerMessage = usable.map((payload) => payload.length / size);
    if (Math.max(...recordsPerMessage) < 2) continue;

    let constantColumns = 0;
    for (let column = 0; column < size; column++) {
      const values = new Set<number>();
      for (const payload of usable) {
        for (let record = 0; record < payload.length / size; record++) values.add(payload[record * size + column]!);
      }
      if (values.size === 1) constantColumns++;
    }

    const ratio = constantColumns / size;
    if (ratio < 0.25) continue;
    const candidate: RecordLayout = {
      size,
      records: Math.max(...recordsPerMessage),
      columns: size,
      constantColumns,
      note: '',
    };
    candidate.note =
      `payloads are all multiples of ${size} bytes, and ${constantColumns} of ${size} byte column(s) never change; ` +
      `consistent with ${candidate.records} ${size}-byte record(s) per message, though a padded structure looks the same`;
    if (!best || ratio > best.constantColumns / best.columns) best = candidate;
  }

  return best;
}

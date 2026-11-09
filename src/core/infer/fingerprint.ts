import { Buffer } from 'node:buffer';
import type { Field } from './fields.js';
import type { FramingHypothesis } from './framing.js';

/**
 * Protocol family identification.
 *
 * This runs last, after framing and fields, and it is deliberately hard to trigger: a match
 * needs several independent structural facts to agree, on every message or close to it. A
 * wrong family label is worse than no label, because it invites the reader to stop looking.
 *
 * Port numbers count as one signal, never as the reason. A server on 502 that frames like
 * Modbus is Modbus; a server on 502 that frames like nothing in particular is a server on 502.
 */

export interface FingerprintDirection {
  messages: Buffer[];
  fields: Field[];
  framing: FramingHypothesis | undefined;
}

export interface FingerprintInput {
  transport: 'tcp' | 'udp';
  clientPort: number;
  serverPort: number;
  directions: FingerprintDirection[];
}

export interface Fingerprint {
  family: string;
  /** Structural name, e.g. "Modbus/TCP application header". */
  detail: string;
  confidence: number;
  signals: string[];
  /** The single assumption that, if false, makes this label wrong. */
  caveat: string;
  reference: string;
}

interface Candidate {
  family: string;
  detail: string;
  signals: string[];
  caveat: string;
  reference: string;
}

const HTTP_VERBS = ['GET', 'POST', 'PUT', 'HEAD', 'DELETE', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT'];
const SIP_VERBS = ['INVITE', 'REGISTER', 'ACK', 'BYE', 'CANCEL', 'OPTIONS', 'SUBSCRIBE', 'NOTIFY', 'PRACK', 'INFO', 'MESSAGE'];
const FTP_VERBS = ['USER', 'PASS', 'RETR', 'STOR', 'PASV', 'TYPE', 'QUIT', 'LIST', 'CWD', 'PWD', 'SIZE', 'PORT'];
const SMTP_VERBS = ['EHLO', 'HELO', 'MAIL', 'RCPT', 'DATA', 'QUIT', 'AUTH', 'STARTTLS'];
const MEMCACHED_VERBS = ['set', 'get', 'gets', 'add', 'replace', 'append', 'prepend', 'delete', 'incr', 'decr', 'touch', 'stats', 'version', 'quit', 'flush_all'];

function text(message: Buffer): string {
  return message.toString('latin1');
}

function ratio<T>(items: T[], predicate: (item: T) => boolean): number {
  if (items.length === 0) return 0;
  return items.filter(predicate).length / items.length;
}

function serversOf(input: FingerprintInput): Buffer[] {
  return dedupeBuffers(input.directions[1]?.messages ?? input.directions[0]?.messages ?? []);
}

function clientsOf(input: FingerprintInput): Buffer[] {
  return dedupeBuffers(input.directions[0]?.messages ?? []);
}

function dedupeBuffers(messages: Buffer[]): Buffer[] {
  const seen = new Set<string>();
  const out: Buffer[] = [];
  for (const message of messages) {
    const key = message.toString('hex');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(message);
  }
  return out;
}

export function fingerprintProtocol(input: FingerprintInput): Fingerprint | undefined {
  const all = dedupeBuffers([...(input.directions[0]?.messages ?? []), ...(input.directions[1]?.messages ?? [])]);
  if (all.length < 3) return undefined;

  const candidates = [
    modbus(input),
    mqtt(all),
    dnp3(all),
    snmp(all),
    tls(all, input.transport),
    http(all),
    sip(all),
    ftp(all),
    smtp(all),
    memcached(all),
    redis(all),
  ].filter((candidate): candidate is Candidate => candidate !== null);

  if (candidates.length === 0) return undefined;

  const ranked = candidates
    .map((candidate) => ({ candidate, score: candidate.signals.length }))
    .sort((a, b) => b.score - a.score);

  const winner = ranked[0]!;
  if (winner.score < 2) return undefined;

  return {
    ...winner.candidate,
    signals: [...new Set(winner.candidate.signals)],
    confidence: winner.score >= 4 ? 0.95 : winner.score === 3 ? 0.85 : 0.7,
  };
}

/**
 * Modbus/TCP is checkable field by field: the protocol identifier is always zero, the length
 * field counts everything after itself, and the function code sits right after the unit id.
 */
function modbus(input: FingerprintInput): Candidate | null {
  const signals: string[] = [];

  for (const direction of input.directions) {
    const spec = direction.framing?.lengthPrefix;
    if (!spec) continue;

    if (spec.lenOffset === 4 && spec.size === 2 && spec.endian === 'be' && spec.bias === 6) {
      signals.push('a 16-bit big-endian length at offset 4 with bias +6 is the MBAP length field');
    }

    const constant = direction.fields.find((field) => field.role === 'reserved' && field.offset === 2 && field.length === 2);
    if (constant && constant.stats.constant === '0000') {
      signals.push('bytes 2..4 are 0x0000 in every message: the MBAP protocol identifier');
    }

    const unit = direction.fields.find((field) => field.role === 'reserved' && field.offset === 6 && field.length === 1);
    if (unit) signals.push('byte 6 is constant across messages: the MBAP unit identifier');

    const opcode = direction.fields.find((field) => field.role === 'opcode' && field.offset === 7 && field.length === 1);
    if (opcode) {
      const values = direction.fields.find((field) => field.name === opcode.name)?.stats;
      const plausible = values?.min !== undefined && values.min >= 1 && (values.max ?? 0) <= 0x7f;
      if (plausible) signals.push(`byte 7 holds ${values!.distinct} distinct function codes in the Modbus range`);
    }

    if (direction.fields.some((field) => field.role === 'checksum')) {
      return null; // Modbus/TCP has no application checksum; a checksum field contradicts the label
    }
  }

  if (input.serverPort === 502) signals.push('server port 502 is the registered Modbus/TCP port');

  return signals.length >= 2
    ? {
        family: 'Modbus/TCP',
        detail: 'Modbus application protocol header (MBAP) over TCP',
        signals,
        caveat: 'a Modbus/TCP gateway that adds a checksum or a length bias would not be labelled',
        reference: 'https://www.modbus.org/docs/Modbus_Messaging_Implementation_Guide_V1_0b.pdf',
      }
    : null;
}

/** MQTT's remaining-length field is a base-128 varint that must account for the rest exactly. */
function mqtt(messages: Buffer[]): Candidate | null {
  const scored = messages.filter((message) => message.length >= 3);
  if (scored.length < 4) return null;

  const consistent = scored.filter((message) => {
    const type = message[0]! >> 4;
    if (type < 1 || type > 15) return false;

    let multiplier = 1;
    let length = 0;
    let index = 1;
    let bytes = 0;
    while (index < message.length && bytes < 4) {
      const byte = message[index++]!;
      length += (byte & 0x7f) * multiplier;
      multiplier *= 128;
      bytes++;
      if ((byte & 0x80) === 0) break;
    }
    return 1 + bytes + length === message.length;
  });

  if (ratio(scored, (message) => consistent.includes(message)) < 0.8) return null;

  return {
    family: 'MQTT',
    detail: 'MQTT control packet with a base-128 remaining-length varint',
    signals: [
      `${consistent.length}/${scored.length} messages have a control type in the first nibble`,
      'the varint after the type accounts for exactly the rest of the message',
    ],
    caveat: 'any protocol whose second field is a varint matching the remainder would pass the same test',
    reference: 'https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html',
  };
}

function dnp3(messages: Buffer[]): Candidate | null {
  if (messages.length < 3) return null;
  const starts = messages.filter((message) => message.length >= 4 && message[0] === 0x05 && message[1] === 0x64);
  if (ratio(messages, (message) => starts.includes(message)) < 0.9) return null;

  return {
    family: 'DNP3',
    detail: 'DNP3 data link frame',
    signals: [
      `${starts.length}/${messages.length} messages begin with the 0x0564 start bytes`,
      'the link header follows at a fixed offset, so the framing is stable across the capture',
    ],
    caveat: 'a proprietary protocol that copied 0x0564 as a magic number is indistinguishable here',
    reference: 'https://www.dnp.org/Portals/0/AboutUs/DNP3%20Primer%20Rev%20A.pdf',
  };
}

/** SNMP is BER: 0x30, then a short-form length covering the rest. */
function snmp(messages: Buffer[]): Candidate | null {
  if (messages.length < 3) return null;
  const scored = messages.filter((message) => message.length >= 4);
  if (scored.length < 3) return null;

  const consistent = scored.filter((message) => message[0] === 0x30 && message[1] === message.length - 2);
  if (ratio(scored, (message) => consistent.includes(message)) < 0.9) return null;

  return {
    family: 'SNMP',
    detail: 'SNMP message in BER with a short-form length',
    signals: [
      `${consistent.length}/${scored.length} messages start with the 0x30 SEQUENCE tag`,
      'the BER length byte equals the remaining message length in every one of them',
    ],
    caveat: 'any BER-encoded protocol with a short-form length at the top level looks the same',
    reference: 'https://datatracker.ietf.org/doc/html/rfc3417',
  };
}

function tls(messages: Buffer[], transport: 'tcp' | 'udp'): Candidate | null {
  if (transport !== 'tcp') return null;
  const scored = messages.filter((message) => message.length >= 5);
  if (scored.length < 3) return null;

  const consistent = scored.filter((message) => {
    const type = message[0]!;
    if (type < 0x14 || type > 0x17) return false;
    if (message[1] !== 0x03) return false;
    if (message[2]! > 0x04) return false;
    const length = (message[3]! << 8) | message[4]!;
    return length === message.length - 5;
  });

  if (ratio(scored, (message) => consistent.includes(message)) < 0.8) return null;

  return {
    family: 'TLS',
    detail: 'TLS record layer',
    signals: [
      `${consistent.length}/${scored.length} messages start with a TLS content type and version 0x03xx`,
      'the two-byte record length equals the remaining message length in every one of them',
    ],
    caveat: 'the application data inside these records is encrypted; infer nothing from it without keys',
    reference: 'https://datatracker.ietf.org/doc/html/rfc8446',
  };
}

function http(messages: Buffer[]): Candidate | null {
  const lines = messages.map(text);
  const requests = lines.filter((line) => {
    const match = /^([A-Z]+) (\S+) HTTP\/1\.[01]\r?$/.exec(line.split('\n')[0] ?? '');
    return match !== null && HTTP_VERBS.includes(match[1]!);
  });
  const responses = lines.filter((line) => /^HTTP\/1\.[01] \d{3}/.test(line));
  if (requests.length + responses.length < 3) return null;

  return {
    family: 'HTTP/1.x',
    detail: 'HTTP/1.x request and response lines',
    signals: [
      `${requests.length} message(s) begin with a known method and an HTTP/1.x version`,
      `${responses.length} message(s) begin with an HTTP/1.x status line`,
    ],
    caveat: 'the body may be compressed, chunked or not text at all; only the start line is read',
    reference: 'https://www.rfc-editor.org/rfc/rfc9112',
  };
}

function sip(messages: Buffer[]): Candidate | null {
  const lines = messages.map(text);
  const requests = lines.filter((line) => {
    const first = line.split('\n')[0] ?? '';
    const match = /^([A-Z]+) \S+ SIP\/2\.0/.exec(first);
    return match !== null && SIP_VERBS.includes(match[1]!);
  });
  const responses = lines.filter((line) => /^SIP\/2\.0 \d{3}/.test(line));
  if (requests.length + responses.length < 3) return null;

  return {
    family: 'SIP',
    detail: 'SIP request and status lines',
    signals: [
      `${requests.length} message(s) start with a SIP method and SIP/2.0`,
      `${responses.length} message(s) start with a SIP/2.0 status line`,
    ],
    caveat: 'SDP bodies and routing headers are not parsed, so nothing here describes the media session',
    reference: 'https://www.rfc-editor.org/rfc/rfc3261',
  };
}

function ftp(messages: Buffer[]): Candidate | null {
  const lines = messages.map((message) => text(message).split('\n')[0] ?? '');
  const commands = lines.filter((line) => FTP_VERBS.some((verb) => line.startsWith(`${verb} `) || line === verb));
  const replies = lines.filter((line) => /^\d{3} /.test(line));
  if (commands.length < 2 || replies.length < 2) return null;

  return {
    family: 'FTP',
    detail: 'FTP command channel',
    signals: [
      `${commands.length} message(s) start with an FTP command verb`,
      `${replies.length} message(s) start with a three-digit reply code`,
    ],
    caveat: 'the data channel is a separate connection and is not part of this analysis',
    reference: 'https://www.rfc-editor.org/rfc/rfc959',
  };
}

function smtp(messages: Buffer[]): Candidate | null {
  const lines = messages.map((message) => text(message).split('\n')[0] ?? '');
  const commands = lines.filter((line) => SMTP_VERBS.some((verb) => line.startsWith(`${verb} `) || line === verb));
  const replies = lines.filter((line) => /^(2|3|4|5)\d{2} /.test(line));
  if (commands.length < 2 || replies.length < 2) return null;

  return {
    family: 'SMTP',
    detail: 'SMTP command channel',
    signals: [
      `${commands.length} message(s) start with an SMTP verb`,
      `${replies.length} message(s) start with a three-digit reply code`,
    ],
    caveat: 'STARTTLS moves the rest of the session into an encrypted channel and it is not followed',
    reference: 'https://www.rfc-editor.org/rfc/rfc5321',
  };
}

function memcached(messages: Buffer[]): Candidate | null {
  const lines = messages.map((message) => text(message).split('\n')[0] ?? '');
  const commands = lines.filter((line) => MEMCACHED_VERBS.includes(line.split(' ')[0] ?? ''));
  const replies = lines.filter((line) => /^(VALUE |END$|STORED$|NOT_STORED$|NOT_FOUND$|DELETED$|STAT |\d+$)/.test(line));
  if (commands.length < 2 || replies.length < 2) return null;

  return {
    family: 'memcached',
    detail: 'memcached text protocol',
    signals: [
      `${commands.length} message(s) start with a memcached command verb`,
      `${replies.length} message(s) match a memcached reply line`,
      'the reply set and the command set are disjoint, which a single-direction text protocol does not show',
    ],
    caveat: 'memcached also has a binary protocol that looks nothing like this',
    reference: 'https://github.com/memcached/memcached/blob/master/doc/protocol.txt',
  };
}

function redis(messages: Buffer[]): Candidate | null {
  const prefixes = new Set(['+', '-', ':', '$', '*']);
  const scored = messages.filter((message) => message.length >= 2);
  if (scored.length < 4) return null;

  const consistent = scored.filter((message) => prefixes.has(String.fromCharCode(message[0]!)));
  if (ratio(scored, (message) => consistent.includes(message)) < 0.95) return null;

  const types = new Set(consistent.map((message) => String.fromCharCode(message[0]!)));
  if (types.size < 1) return null;

  return {
    family: 'RESP',
    detail: 'Redis serialization protocol',
    signals: [
      `${consistent.length}/${scored.length} messages begin with a RESP type byte (+ - : $ *)`,
      `the observed type bytes are ${[...types].join(' ')}`,
    ],
    caveat: 'RESP2 and RESP3 share these type bytes; the dialect needs the HELLO exchange to pin down',
    reference: 'https://redis.io/docs/latest/develop/reference/protocol-spec/',
  };
}

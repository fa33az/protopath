import { Buffer } from 'node:buffer';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tcpFrame, udpFrame, writePcap, type PcapRecord } from '../scripts/pcap-writer.js';

/**
 * The benchmark corpus.
 *
 * Every protocol here was written from its published wire format, not from protopath's
 * inference code, and none of them was present while the inference layers were developed.
 * The point is to ask the tool about traffic it has never seen and score the answers against
 * a ground truth that is written down before the tool runs.
 *
 * The generator writes both the captures and `manifest.json`: the expected message lengths per
 * direction, the framing shape from the specification, and the trailer algorithm if the
 * protocol has one. The benchmark compares against that file, never against its own output.
 *
 * Captures are deterministic: same input, same bytes, so a diff in `bench/corpus/` means the
 * generator changed.
 */

interface Endpoint {
  ip: string;
  port: number;
}

const CLIENT: Endpoint = { ip: '10.1.0.10', port: 49152 };
const SERVER: Endpoint = { ip: '10.1.0.20', port: 0 };

const BASE_TS = 1_760_000_000;
const STEP = 0.0012;

interface Exchange {
  /** 'forward' is client to server. */
  side: 'forward' | 'reverse';
  payload: Buffer;
}

interface Framing {
  kind: 'length-prefix' | 'delimiter' | 'start-marker' | 'none';
  lenOffset?: number;
  size?: number;
  endian?: 'be' | 'le';
  bias?: number;
  marker?: string;
  terminator?: string;
}

interface ChecksumExpectation {
  algorithm: string;
  offsetFromEnd: number;
  width: number;
  rangeStart?: number;
}

interface BenchCase {
  file: string;
  protocol: string;
  basis: string;
  transport: 'tcp' | 'udp';
  client: Endpoint;
  server: Endpoint;
  exchanges: Exchange[];
  framing: Framing;
  checksum: ChecksumExpectation | null;
  note: string;
}

interface ManifestEntry {
  file: string;
  protocol: string;
  basis: string;
  transport: 'tcp' | 'udp';
  framing: Framing;
  checksum: ChecksumExpectation | null;
  note: string;
  directions: Record<'forward' | 'reverse', { messages: number; lengths: number[] }>;
}

function clock(): () => number {
  let now = BASE_TS;
  return () => (now += STEP);
}

/** A TCP session in order, one segment per message, sequence numbers tracked per direction. */
function tcpSession(client: Endpoint, server: Endpoint, exchanges: Exchange[]): PcapRecord[] {
  const advance = clock();
  let seqForward = 1000;
  let seqReverse = 90000;
  const records: PcapRecord[] = [];
  for (const exchange of exchanges) {
    const forward = exchange.side === 'forward';
    const from = forward ? client : server;
    const to = forward ? server : client;
    records.push({
      ts: advance(),
      data: tcpFrame(from.ip, from.port, to.ip, to.port, forward ? seqForward : seqReverse, forward ? seqReverse : seqForward, exchange.payload),
    });
    if (forward) seqForward += exchange.payload.length;
    else seqReverse += exchange.payload.length;
  }
  return records;
}

function udpSession(client: Endpoint, server: Endpoint, exchanges: Exchange[]): PcapRecord[] {
  const advance = clock();
  return exchanges.map((exchange) => {
    const forward = exchange.side === 'forward';
    const from = forward ? client : server;
    const to = forward ? server : client;
    return { ts: advance(), data: udpFrame(from.ip, from.port, to.ip, to.port, exchange.payload) };
  });
}

const ascii = (value: string): Buffer => Buffer.from(value, 'ascii');

// ---------------------------------------------------------------------------
// DNS over TCP - RFC 1035 section 4.2.2, RFC 7766
// ---------------------------------------------------------------------------

function dnsName(host: string): Buffer {
  const labels = host.split('.').map((label) => Buffer.concat([Buffer.from([label.length]), ascii(label)]));
  return Buffer.concat([...labels, Buffer.from([0])]);
}

function dnsQuery(id: number, host: string): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2); // standard query, recursion desired
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, dnsName(host), Buffer.from([0x00, 0x01, 0x00, 0x01])]);
}

function dnsAnswer(id: number, host: string, address: string, ttl: number): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x8180, 2); // standard response, recursion available
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(1, 6);
  const answer = Buffer.alloc(16);
  answer.writeUInt16BE(0xc00c, 0); // name pointer to the question
  answer.writeUInt16BE(0x0001, 2);
  answer.writeUInt16BE(0x0001, 4);
  answer.writeUInt32BE(ttl, 6);
  answer.writeUInt16BE(4, 10);
  address.split('.').forEach((part, i) => answer.writeUInt8(Number(part), 12 + i));
  return Buffer.concat([header, dnsName(host), Buffer.from([0x00, 0x01, 0x00, 0x01]), answer]);
}

/** RFC 1035: a two-byte big-endian length precedes every message on a TCP stream. */
function withLengthPrefix(message: Buffer): Buffer {
  const prefix = Buffer.alloc(2);
  prefix.writeUInt16BE(message.length, 0);
  return Buffer.concat([prefix, message]);
}

function dnsTcp(): BenchCase {
  const queries: Array<[string, string, number]> = [
    ['telemetry.example.net', '203.0.113.7', 300],
    ['api.example.net', '203.0.113.19', 60],
    ['mqtt-broker.internal', '10.9.0.4', 120],
    ['firmware.updates.example.org', '198.51.100.42', 3600],
    ['ntp.pool.example.net', '203.0.113.80', 300],
    ['auth.example.net', '203.0.113.21', 900],
    ['logs.example.net', '198.51.100.9', 30],
    ['gateway.internal', '10.9.0.1', 86400],
    ['metrics.example.net', '203.0.113.55', 15],
    ['backup.example.net', '198.51.100.77', 600],
  ];
  const exchanges: Exchange[] = [];
  queries.forEach(([host, address, ttl], index) => {
    const id = 0x1200 + index * 7;
    exchanges.push({ side: 'forward', payload: withLengthPrefix(dnsQuery(id, host)) });
    exchanges.push({ side: 'reverse', payload: withLengthPrefix(dnsAnswer(id, host, address, ttl)) });
  });
  return {
    file: 'dns-tcp.pcap',
    protocol: 'DNS over TCP',
    basis: 'RFC 1035 section 4.2.2, RFC 7766',
    transport: 'tcp',
    client: { ip: CLIENT.ip, port: 50231 },
    server: { ip: SERVER.ip, port: 53 },
    exchanges,
    framing: { kind: 'length-prefix', lenOffset: 0, size: 2, endian: 'be', bias: 2 },
    checksum: null,
    note: 'a two-byte length prefixes each DNS message on a stream connection',
  };
}

// ---------------------------------------------------------------------------
// PostgreSQL v3 frontend/backend protocol
// ---------------------------------------------------------------------------

function pgMessage(type: string, body: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeInt32BE(body.length + 4, 0);
  return Buffer.concat([ascii(type), length, body]);
}

const cstring = (value: string): Buffer => Buffer.concat([ascii(value), Buffer.from([0])]);

function pgDataRow(value: string): Buffer {
  const body = Buffer.alloc(6 + Buffer.byteLength(value));
  body.writeInt16BE(1, 0);
  body.writeInt32BE(Buffer.byteLength(value), 2);
  body.write(value, 6, 'utf8');
  return pgMessage('D', body);
}

function pgRowDescription(column: string, typeOid: number): Buffer {
  const head = Buffer.alloc(2);
  head.writeInt16BE(1, 0);
  const field = Buffer.alloc(18);
  field.writeInt32BE(0, 0); // table oid
  field.writeInt16BE(1, 4); // column number
  field.writeInt32BE(typeOid, 6);
  field.writeInt16BE(typeOid === 25 ? -1 : 4, 10); // type size
  field.writeInt32BE(-1, 12); // type modifier
  field.writeInt16BE(0, 16); // text format
  return pgMessage('T', Buffer.concat([head, cstring(column), field]));
}

function postgres(): BenchCase {
  const statements: Array<[string, string, string, number]> = [
    ['SELECT name FROM devices WHERE id = 1', 'pump-7', 'SELECT 1', 25],
    ['SELECT firmware FROM devices WHERE id = 2', '1.4.7', 'SELECT 1', 25],
    ['SELECT pressure FROM readings ORDER BY ts DESC LIMIT 1', '3.412', 'SELECT 1', 1700],
    ['SELECT count(*) FROM events WHERE kind = $1', '41208', 'SELECT 1', 20],
    ['SELECT address FROM devices WHERE zone = $1', '10.9.0.31', 'SELECT 1', 25],
    ['SELECT max(ts) FROM readings', '1760000000', 'SELECT 1', 1114],
    ['SELECT name, zone FROM devices WHERE active', 'valve-3', 'SELECT 1', 25],
    ['SELECT settings FROM config WHERE key = $1', '{"poll": 250}', 'SELECT 1', 114],
    ['SELECT version()', 'PostgreSQL 16.4', 'SELECT 1', 25],
  ];
  const exchanges: Exchange[] = [];
  for (const [sql, value, tag, oid] of statements) {
    exchanges.push({ side: 'forward', payload: pgMessage('Q', cstring(sql)) });
    exchanges.push({ side: 'reverse', payload: pgRowDescription('column', oid) });
    exchanges.push({ side: 'reverse', payload: pgDataRow(value) });
    exchanges.push({ side: 'reverse', payload: pgMessage('C', cstring(tag)) });
    exchanges.push({ side: 'reverse', payload: pgMessage('Z', Buffer.from([0x49])) });
  }
  return {
    file: 'postgres-v3.pcap',
    protocol: 'PostgreSQL v3',
    basis: 'PostgreSQL frontend/backend message format',
    transport: 'tcp',
    client: { ip: CLIENT.ip, port: 50412 },
    server: { ip: SERVER.ip, port: 5432 },
    exchanges,
    // One type byte, then a four-byte length that counts itself but not the type byte.
    framing: { kind: 'length-prefix', lenOffset: 1, size: 4, endian: 'be', bias: 1 },
    checksum: null,
    note: 'length counts itself and the body, not the leading type byte',
  };
}

// ---------------------------------------------------------------------------
// RADIUS - RFC 2865
// ---------------------------------------------------------------------------

function radiusAttribute(type: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([type, value.length + 2]), value]);
}

/** Deterministic stand-in for the 16-byte authenticator. Not a checksum of anything. */
function radiusAuthenticator(seed: number): Buffer {
  const out = Buffer.alloc(16);
  let state = (seed * 2654435761) >>> 0;
  for (let i = 0; i < 16; i++) {
    state = (state * 1664525 + 1013904223) >>> 0;
    out[i] = state >>> 24;
  }
  return out;
}

function radiusPacket(code: number, id: number, attributes: Buffer[]): Buffer {
  const body = Buffer.concat(attributes);
  const header = Buffer.alloc(20);
  header.writeUInt8(code, 0);
  header.writeUInt8(id, 1);
  header.writeUInt16BE(20 + body.length, 2);
  radiusAuthenticator(id + 17).copy(header, 4);
  return Buffer.concat([header, body]);
}

function radius(): BenchCase {
  const users = ['svc-telemetry', 'ops-adele', 'ops-bruno', 'svc-backup', 'monitor-1', 'ops-chen', 'svc-vpn-7', 'ops-dara'];
  const exchanges: Exchange[] = [];
  users.forEach((user, index) => {
    const id = 0x30 + index;
    exchanges.push({
      side: 'forward',
      payload: radiusPacket(1, id, [
        radiusAttribute(1, ascii(user)),
        radiusAttribute(4, Buffer.from([10, 1, 0, 10 + index])),
        radiusAttribute(31, ascii(`ap-${index + 1}.example.net`)),
        radiusAttribute(2, radiusAuthenticator(id * 3 + 1)),
      ]),
    });
    exchanges.push({
      side: 'reverse',
      payload: radiusPacket(2, id, [
        radiusAttribute(6, Buffer.from([1, 0, 0, 0])),
        radiusAttribute(27, Buffer.from([0, 0, 0, 3600])),
        // Class is opaque to the client and varies per authentication in real deployments.
        radiusAttribute(25, Buffer.alloc(8 + index * 3, 0x41 + index)),
      ]),
    });
  });
  return {
    file: 'radius-auth.pcap',
    protocol: 'RADIUS',
    basis: 'RFC 2865',
    transport: 'udp',
    client: { ip: CLIENT.ip, port: 40123 },
    server: { ip: SERVER.ip, port: 1812 },
    exchanges,
    framing: { kind: 'length-prefix', lenOffset: 2, size: 2, endian: 'be', bias: 0 },
    checksum: null,
    note: 'the authenticator is MD5, not a checksum over the message; nothing may be reported',
  };
}

// ---------------------------------------------------------------------------
// Kafka protocol, Metadata request v9
// ---------------------------------------------------------------------------

function kafkaRequest(apiKey: number, apiVersion: number, correlationId: number, clientId: string, body: Buffer): Buffer {
  const head = Buffer.alloc(10);
  head.writeInt16BE(apiKey, 0);
  head.writeInt16BE(apiVersion, 2);
  head.writeInt32BE(correlationId, 4);
  head.writeInt16BE(clientId.length, 8);
  const payload = Buffer.concat([head, ascii(clientId), body]);
  const size = Buffer.alloc(4);
  size.writeInt32BE(payload.length, 0);
  return Buffer.concat([size, payload]);
}

function kafkaMetadataBody(topics: string[]): Buffer {
  const count = Buffer.alloc(4);
  count.writeInt32BE(topics.length, 0);
  const entries = topics.map((topic) => {
    const name = ascii(topic);
    const head = Buffer.alloc(2);
    head.writeInt16BE(name.length, 0);
    return Buffer.concat([head, name]);
  });
  return Buffer.concat([count, ...entries]);
}

function kafkaResponse(correlationId: number, topics: Array<[string, number]>, throttle: number): Buffer {
  const throttleBytes = Buffer.alloc(4);
  throttleBytes.writeInt32BE(throttle, 0);
  const count = Buffer.alloc(4);
  count.writeInt32BE(topics.length, 0);
  const entries = topics.map(([topic, partitions]) => {
    const name = ascii(topic);
    const head = Buffer.alloc(4);
    head.writeInt16BE(0, 0); // error code
    head.writeInt16BE(name.length, 2);
    const partitionCount = Buffer.alloc(4);
    partitionCount.writeInt32BE(partitions, 0);
    return Buffer.concat([head, name, partitionCount]);
  });
  const correlation = Buffer.alloc(4);
  correlation.writeInt32BE(correlationId, 0);
  const payload = Buffer.concat([correlation, throttleBytes, count, ...entries]);
  const size = Buffer.alloc(4);
  size.writeInt32BE(payload.length, 0);
  return Buffer.concat([size, payload]);
}

function kafka(): BenchCase {
  const rounds: Array<[string[], Array<[string, number]>, number]> = [
    [['events'], [['events', 3]], 0],
    [['events', 'readings'], [['events', 3], ['readings', 2]], 0],
    [['events', 'readings', 'audit'], [['events', 3], ['readings', 2], ['audit', 1]], 12],
    [['audit'], [['audit', 1]], 0],
    [['readings'], [['readings', 2]], 5],
    [['events', 'readings'], [['events', 3], ['readings', 2]], 0],
    [['audit', 'readings'], [['audit', 1], ['readings', 2]], 3],
    [['events'], [['events', 3]], 0],
  ];
  const exchanges: Exchange[] = [];
  rounds.forEach(([topics, layout, throttle], index) => {
    const correlationId = 41 + index * 3;
    exchanges.push({ side: 'forward', payload: kafkaRequest(3, 9, correlationId, 'protopath-bench', kafkaMetadataBody(topics)) });
    exchanges.push({ side: 'reverse', payload: kafkaResponse(correlationId, layout, throttle) });
  });
  return {
    file: 'kafka-metadata.pcap',
    protocol: 'Kafka (Metadata v9)',
    basis: 'Kafka protocol guide, request header v1',
    transport: 'tcp',
    client: { ip: CLIENT.ip, port: 50555 },
    server: { ip: SERVER.ip, port: 9092 },
    exchanges,
    framing: { kind: 'length-prefix', lenOffset: 0, size: 4, endian: 'be', bias: 4 },
    checksum: null,
    note: 'the four-byte size does not count itself',
  };
}

// ---------------------------------------------------------------------------
// STOMP 1.2 - frames end with a NUL byte
// ---------------------------------------------------------------------------

const NUL = Buffer.from([0x00]);

function stompFrame(command: string, headers: Array<[string, string]>, body = ''): Buffer {
  const lines = [command, ...headers.map(([key, value]) => `${key}:${value}`), '', body];
  return Buffer.concat([ascii(lines.join('\n')), NUL]);
}

function stomp(): BenchCase {
  const exchanges: Exchange[] = [
    {
      side: 'forward',
      payload: stompFrame('CONNECT', [['accept-version', '1.2'], ['host', 'broker.example.net'], ['heart-beat', '10000,10000']]),
    },
    { side: 'reverse', payload: stompFrame('CONNECTED', [['version', '1.2'], ['session', 'session-104'], ['heart-beat', '10000,10000']]) },
    { side: 'forward', payload: stompFrame('SUBSCRIBE', [['id', 'sub-0'], ['destination', '/topic/readings']]) },
  ];
  for (let i = 0; i < 8; i++) {
    exchanges.push({
      side: 'forward',
      payload: stompFrame('SEND', [['destination', '/topic/readings'], ['content-length', String(24 + i)]], `{"sensor":${i},"value":${(21 + i).toFixed(1)}}`),
    });
    exchanges.push({
      side: 'reverse',
      payload: stompFrame('MESSAGE', [['subscription', 'sub-0'], ['message-id', `msg-${100 + i}`], ['destination', '/topic/readings'], ['content-length', String(20 + i)]], `{"sensor":${i},"ok":true}`),
    });
  }
  return {
    file: 'stomp-1.2.pcap',
    protocol: 'STOMP 1.2',
    basis: 'STOMP 1.2 specification, frame termination',
    transport: 'tcp',
    client: { ip: CLIENT.ip, port: 50666 },
    server: { ip: SERVER.ip, port: 61613 },
    exchanges,
    framing: { kind: 'delimiter', terminator: '00' },
    checksum: null,
    note: 'every frame ends with a NUL byte',
  };
}

// ---------------------------------------------------------------------------
// HL7 v2 over MLLP - 0x0b starts a frame, 0x1c 0x0d ends it
// ---------------------------------------------------------------------------

const MLLP_START = Buffer.from([0x0b]);
const MLLP_END = Buffer.from([0x1c, 0x0d]);

function mllpFrame(segments: string[]): Buffer {
  return Buffer.concat([MLLP_START, ascii(segments.join('\r') + '\r'), MLLP_END]);
}

function hl7(): BenchCase {
  const exchanges: Exchange[] = [];
  const names = ['DOE^JOHN', 'ROE^JANE', 'POE^EDGAR', 'LOE^MARIA', 'TOE^SAMUEL'];
  names.forEach((name, index) => {
    const control = 2000 + index;
    exchanges.push({
      side: 'forward',
      payload: mllpFrame([
        'MSH|^~\\&|PROTOPATH|LAB|RIS|HOSP|20260101000000||ORM^O01|MSG' + control + '|P|2.5',
        `PID|1||MRN${control}||${name}||19800101|M`,
        `OBR|1|ORD${control}||CBC^Complete Blood Count`,
      ]),
    });
    exchanges.push({
      side: 'reverse',
      payload: mllpFrame([
        'MSH|^~\\&|RIS|HOSP|PROTOPATH|LAB|20260101000001||ACK^O01|ACK' + control + '|P|2.5',
        `MSA|AA|MSG${control}`,
      ]),
    });
  });
  return {
    file: 'hl7-mllp.pcap',
    protocol: 'HL7 v2 over MLLP',
    basis: 'HL7 MLLP framing, 0x0b start and 0x1c 0x0d end',
    transport: 'tcp',
    client: { ip: CLIENT.ip, port: 50777 },
    server: { ip: SERVER.ip, port: 2575 },
    exchanges,
    framing: { kind: 'start-marker', marker: '0b' },
    checksum: null,
    note: 'a text stream with a binary frame marker; no trailing checksum exists',
  };
}

// ---------------------------------------------------------------------------
// CoAP - RFC 7252. No length field, no delimiter: the header is self-describing.
// ---------------------------------------------------------------------------

function coapOption(delta: number, value: string): Buffer {
  const bytes = ascii(value);
  return Buffer.concat([Buffer.from([(delta << 4) | bytes.length]), bytes]);
}

function coapRequest(id: number, path: string, token: Buffer, type: number, code: number): Buffer {
  const header = Buffer.from([0x40 | (type << 4) | token.length, code]);
  const messageId = Buffer.alloc(2);
  messageId.writeUInt16BE(id, 0);
  return Buffer.concat([header, messageId, token, coapOption(11, path)]);
}

function coapResponse(id: number, token: Buffer, payload: string): Buffer {
  const header = Buffer.from([0x60 | token.length, 0x45]);
  const messageId = Buffer.alloc(2);
  messageId.writeUInt16BE(id, 0);
  return Buffer.concat([header, messageId, token, coapOption(12, 'text/plain'), Buffer.from([0xff]), ascii(payload)]);
}

function coap(): BenchCase {
  const paths = ['temp', 'pressure', 'firmware', 'channel', 'gain', 'mode', 'uptime', 'serial'];
  const codes = [0x01, 0x01, 0x03, 0x01, 0x02, 0x01, 0x04, 0x01];
  const exchanges: Exchange[] = [];
  paths.forEach((path, index) => {
    const id = 0x4000 + index * 4;
    // Token length and message type vary, as they do on a real CoAP network: that removes the
    // coincidental constant first two bytes and leaves the header self-describing, not framed.
    const token = Buffer.alloc(2 + index, 0xa0 + index);
    exchanges.push({ side: 'forward', payload: coapRequest(id, path, token, index % 2, codes[index]!) });
    exchanges.push({ side: 'reverse', payload: coapResponse(id, token, `value-${index}`) });
  });
  return {
    file: 'coap-udp.pcap',
    protocol: 'CoAP',
    basis: 'RFC 7252',
    transport: 'udp',
    client: { ip: CLIENT.ip, port: 50888 },
    server: { ip: SERVER.ip, port: 5683 },
    exchanges,
    framing: { kind: 'none' },
    checksum: null,
    note: 'datagram protocol with a self-describing header: the right answer is no claim',
  };
}

// ---------------------------------------------------------------------------
// Syslog - RFC 5424. One datagram, one line, no framing at all.
// ---------------------------------------------------------------------------

function syslog(): BenchCase {
  const lines = [
    '<35>1 2026-01-01T00:00:01.112Z gateway app 4102 ID47 - link up on port 3',
    '<46>1 2026-01-01T00:00:02.004Z gateway kernel 0 - - link down on port 4',
    '<17>1 2026-01-01T00:00:03.871Z sensor-7 thermod 220 - - reading 21.75 at channel 2',
    '<28>1 2026-01-01T00:00:05.551Z gateway app 4103 ID48 - heartbeat 200ms',
    '<39>1 2026-01-01T00:00:07.008Z sensor-2 thermod 221 - - reading 19.10 at channel 1',
    '<24>1 2026-01-01T00:00:09.400Z gateway app 4104 ID49 - config reload requested',
    '<11>1 2026-01-01T00:00:11.135Z gateway kernel 0 - - interface eth1 reset',
    '<22>1 2026-01-01T00:00:13.772Z sensor-9 thermod 222 - - reading 24.02 at channel 3',
  ];
  return {
    file: 'syslog-udp.pcap',
    protocol: 'Syslog',
    basis: 'RFC 5424',
    transport: 'udp',
    client: { ip: CLIENT.ip, port: 50999 },
    server: { ip: SERVER.ip, port: 514 },
    exchanges: lines.map((line) => ({ side: 'forward' as const, payload: ascii(line) })),
    framing: { kind: 'none' },
    checksum: null,
    note: 'one line per datagram: there is no field model to build and none may be invented',
  };
}

// ---------------------------------------------------------------------------
// UBX - u-blox binary protocol. Length is little endian; the trailing CK_A/CK_B
// are two independent byte sums, not a CRC.
// ---------------------------------------------------------------------------

function ubxFrame(classId: number, messageId: number, payload: Buffer): Buffer {
  const head = Buffer.from([0xb5, 0x62, classId, messageId]);
  const length = Buffer.alloc(2);
  length.writeUInt16LE(payload.length, 0);
  const body = Buffer.concat([head, length, payload]);
  let a = 0;
  let b = 0;
  for (let i = 2; i < body.length; i++) {
    a = (a + body[i]!) & 0xff;
    b = (b + a) & 0xff;
  }
  return Buffer.concat([body, Buffer.from([a, b])]);
}

function ubx(): BenchCase {
  const exchanges: Exchange[] = [];
  const firmware = ['ROM CORE 3.01 (107888)', 'ROM CORE 3.01 (107900)', 'ROM CORE 3.01 (108000)'];
  firmware.forEach((version, index) => {
    exchanges.push({ side: 'forward', payload: ubxFrame(0x0a, 0x04, Buffer.alloc(0)) });
    const payload = Buffer.alloc(40 + index * 8);
    ascii(version).copy(payload, 0);
    exchanges.push({ side: 'reverse', payload: ubxFrame(0x0a, 0x04, payload) });
    const status = Buffer.alloc(16 + index * 4);
    status.writeUInt32LE(1760000000 + index, 0);
    status.writeUInt16LE(2 + index, 4);
    exchanges.push({ side: 'forward', payload: ubxFrame(0x01, 0x02, status) });
    const ack = Buffer.from([0x01, 0x02]);
    exchanges.push({ side: 'reverse', payload: ubxFrame(0x05, 0x01, ack) });
  });
  return {
    file: 'ubx-serial.pcap',
    protocol: 'UBX (u-blox)',
    basis: 'u-blox UBX protocol specification',
    transport: 'tcp',
    client: { ip: CLIENT.ip, port: 51000 },
    server: { ip: SERVER.ip, port: 4001 },
    exchanges,
    // The sync bytes b5 62 are a real marker; the two-byte length at offset 4 is also real.
    framing: { kind: 'start-marker', marker: 'b562' },
    // CK_A is a plain byte sum over class..payload, which the 8-bit catalogue can name.
    checksum: { algorithm: 'sum8', offsetFromEnd: 1, width: 1, rangeStart: 2 },
    note: 'length is little endian and counts only the payload; CK_A is a running sum, CK_B is not catalogued',
  };
}

// ---------------------------------------------------------------------------
// A 32-bit CRC probe. The 32-bit branch of the catalogue had no fixture before.
// Layout: length(4 BE, counts the whole message) type(1) payload(n) crc32(4 BE).
// ---------------------------------------------------------------------------

function crc32Ieee(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function crc32Frame(index: number): Buffer {
  const payload = ascii(`sample=${index};value=${(20 + index * 0.5).toFixed(2)};unit=C`);
  const type = index % 3 === 0 ? 0x31 : index % 3 === 1 ? 0x32 : 0x33;
  const total = 4 + 1 + payload.length + 4;
  const head = Buffer.alloc(5);
  head.writeUInt32BE(total, 0);
  head.writeUInt8(type, 4);
  const body = Buffer.concat([head, payload]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32Ieee(body), 0);
  return Buffer.concat([body, crc]);
}

function crc32Session(): BenchCase {
  const exchanges: Exchange[] = [];
  for (let i = 0; i < 12; i++) exchanges.push({ side: 'forward', payload: crc32Frame(i) });
  return {
    file: 'crc32-frame.pcap',
    protocol: 'CRC-32 probe (synthetic)',
    basis: 'CRC-32/ISO-HDLC, poly 0x04c11db7, init 0xffffffff, xorout 0xffffffff',
    transport: 'tcp',
    client: { ip: CLIENT.ip, port: 51111 },
    server: { ip: SERVER.ip, port: 7000 },
    exchanges,
    framing: { kind: 'length-prefix', lenOffset: 0, size: 4, endian: 'be', bias: 0 },
    checksum: { algorithm: 'crc32/ieee', offsetFromEnd: 0, width: 4, rangeStart: 0 },
    note: 'synthetic probe for the 32-bit branch of the catalogue, not a real protocol',
  };
}

// ---------------------------------------------------------------------------

function manifestEntry(testCase: BenchCase): ManifestEntry {
  const lengths = (side: Exchange['side']): number[] =>
    testCase.exchanges.filter((exchange) => exchange.side === side).map((exchange) => exchange.payload.length);
  return {
    file: testCase.file,
    protocol: testCase.protocol,
    basis: testCase.basis,
    transport: testCase.transport,
    framing: testCase.framing,
    checksum: testCase.checksum,
    note: testCase.note,
    directions: {
      forward: { messages: lengths('forward').length, lengths: lengths('forward') },
      reverse: { messages: lengths('reverse').length, lengths: lengths('reverse') },
    },
  };
}

function main(): void {
  const out = join(process.cwd(), 'bench', 'corpus');
  mkdirSync(out, { recursive: true });

  const cases = [dnsTcp(), postgres(), radius(), kafka(), stomp(), hl7(), coap(), syslog(), ubx(), crc32Session()];
  for (const testCase of cases) {
    const records = testCase.transport === 'tcp' ? tcpSession(testCase.client, testCase.server, testCase.exchanges) : udpSession(testCase.client, testCase.server, testCase.exchanges);
    writePcap(join(out, testCase.file), records);
  }

  writeFileSync(join(out, 'manifest.json'), JSON.stringify(cases.map(manifestEntry), null, 2) + '\n');
  console.log(`wrote ${cases.length} benchmark captures and manifest to ${out}`);
}

main();

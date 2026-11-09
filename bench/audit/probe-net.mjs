// Adversarial probes against src/core/net/ and src/core/pcap/.
// Every case builds bytes by hand and asks the real pipeline what it saw.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Buffer } from 'node:buffer';
import { readCapture, parseCapture } from '../../dist/core/pcap/reader.js';
import { framesFromCapture } from '../../dist/core/net/decode.js';
import { buildFlows } from '../../dist/core/net/flows.js';

const out = join(process.cwd(), 'out', 'audit');
mkdirSync(out, { recursive: true });

function checksum(data) {
  let sum = 0;
  for (let i = 0; i + 1 < data.length; i += 2) sum += (data[i] << 8) | data[i + 1];
  if (data.length % 2) sum += data[data.length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

function ipv4(src, dst, proto, payload, { fragField = 0x4000 } = {}) {
  const eth = Buffer.alloc(14);
  Buffer.from('020000000001', 'hex').copy(eth, 0);
  Buffer.from('020000000002', 'hex').copy(eth, 6);
  eth.writeUInt16BE(0x0800, 12);
  const ip = Buffer.alloc(20);
  ip.writeUInt8(0x45, 0);
  ip.writeUInt16BE(20 + payload.length, 2);
  ip.writeUInt16BE(fragField, 6);
  ip.writeUInt8(64, 8);
  ip.writeUInt8(proto, 9);
  ip.writeUInt32BE(ip2int(src), 12);
  ip.writeUInt32BE(ip2int(dst), 16);
  ip.writeUInt16BE(checksum(ip), 10);
  return Buffer.concat([eth, ip, payload]);
}

function ip2int(ip) {
  return ip.split('.').reduce((v, p) => v * 256 + Number(p), 0) >>> 0;
}

function tcp(srcPort, dstPort, seq, ack, payload, { dataOffsetWords = 5 } = {}) {
  const headerLen = dataOffsetWords * 4;
  const seg = Buffer.alloc(headerLen + payload.length);
  seg.writeUInt16BE(srcPort, 0);
  seg.writeUInt16BE(dstPort, 2);
  seg.writeUInt32BE(seq >>> 0, 4);
  seg.writeUInt32BE(ack >>> 0, 8);
  seg.writeUInt8(dataOffsetWords << 4, 12);
  seg.writeUInt8(0x18, 13);
  seg.writeUInt16BE(8000, 14);
  // Timestamps option in the padding, as a real Linux stack sends.
  if (dataOffsetWords > 5) {
    seg.writeUInt8(8, 20);
    seg.writeUInt8(10, 21);
    seg.writeUInt32BE(0x12345678, 22);
  }
  payload.copy(seg, headerLen);
  return seg;
}

function pcapLE(records) {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(262144, 16);
  header.writeUInt32LE(1, 20);
  const chunks = [header];
  for (const r of records) {
    const h = Buffer.alloc(16);
    h.writeUInt32LE(Math.floor(r.ts), 0);
    h.writeUInt32LE(Math.round((r.ts % 1) * 1e6), 4);
    h.writeUInt32LE(r.captured ?? r.data.length, 8);
    h.writeUInt32LE(r.original ?? r.data.length, 12);
    chunks.push(h, r.data.subarray(0, r.captured ?? r.data.length));
  }
  return Buffer.concat(chunks);
}

function pcapBE(records) {
  const header = Buffer.alloc(24);
  header.writeUInt32BE(0xa1b2c3d4, 0);
  header.writeUInt16BE(2, 4);
  header.writeUInt16BE(4, 6);
  header.writeUInt32BE(262144, 16);
  header.writeUInt32BE(1, 20);
  const chunks = [header];
  for (const r of records) {
    const h = Buffer.alloc(16);
    h.writeUInt32BE(Math.floor(r.ts), 0);
    h.writeUInt32BE(Math.round((r.ts % 1) * 1e6), 4);
    h.writeUInt32BE(r.data.length, 8);
    h.writeUInt32BE(r.data.length, 12);
    chunks.push(h, r.data);
  }
  return Buffer.concat(chunks);
}

function blockBE(type, body) {
  const total = 12 + body.length;
  const head = Buffer.alloc(8);
  head.writeUInt32BE(type, 0);
  head.writeUInt32BE(total, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt32BE(total, 0);
  return Buffer.concat([head, body, tail]);
}

function pcapngBE(records) {
  const blocks = [];
  const shb = Buffer.alloc(16);
  shb.writeUInt32BE(0x1a2b3c4d, 0);
  shb.writeUInt16BE(1, 4);
  shb.writeUInt16BE(0, 6);
  shb.writeBigUInt64BE(0xffffffffffffffffn, 8);
  blocks.push(blockBE(0x0a0d0d0a, shb));
  const idb = Buffer.alloc(8);
  idb.writeUInt16BE(1, 0);
  idb.writeUInt32BE(262144, 4);
  blocks.push(blockBE(1, idb));
  for (const r of records) {
    const padded = Buffer.alloc((r.data.length + 3) & ~3);
    r.data.copy(padded, 0);
    const body = Buffer.alloc(20 + padded.length);
    body.writeUInt32BE(0, 0);
    const ticks = BigInt(Math.round(r.ts * 1e6));
    body.writeUInt32BE(Number(ticks >> 32n), 4);
    body.writeUInt32BE(Number(ticks & 0xffffffffn), 8);
    body.writeUInt32BE(r.data.length, 12);
    body.writeUInt32BE(r.data.length, 16);
    padded.copy(body, 20);
    blocks.push(blockBE(6, body));
  }
  return Buffer.concat(blocks);
}

const line = (s) => console.log(s);
const summarise = (buf, label) => {
  line(`\n=== ${label} ===`);
  let raw;
  try {
    raw = parseCapture(buf);
  } catch (e) {
    line(`  THREW: ${e.message}`);
    return;
  }
  line(`  format ${raw.format}, records ${raw.records.length}`);
  const { frames, skipped } = framesFromCapture(raw.records);
  line(`  frames ${frames.length}, skipped ${skipped}`);
  const flows = buildFlows(frames);
  line(`  flows ${flows.length}`);
  for (const f of flows) {
    line(`    ${f.key}  fwd ${f.forward.data.length}B gaps ${JSON.stringify(f.forward.gaps)} retrans ${f.forward.retransmits} ooo ${f.forward.outOfOrder}`);
    line(`    ${' '.repeat(f.key.length)}  rev ${f.reverse.data.length}B gaps ${JSON.stringify(f.reverse.gaps)}`);
  }
  return { raw, frames, flows };
};

// ---------------------------------------------------------------------------
// 1. Big-endian pcapng
// ---------------------------------------------------------------------------
const hello = [Buffer.from('hello world'), Buffer.from('second message')];
const beRecords = hello.map((payload, i) => ({
  ts: 1760000000 + i,
  data: ipv4('10.0.0.1', '10.0.0.2', 6, tcp(1111, 2222, 1000 + i * payload.length, 5000, payload)),
}));
summarise(pcapngBE(beRecords), 'big-endian pcapng, 2 TCP segments');

// ---------------------------------------------------------------------------
// 2. Snap-length truncated capture
// ---------------------------------------------------------------------------
// Two segments of 20 bytes each; the first is captured only to 10 bytes.
// seq still advances by 20, so the reassembler must notice the missing half.
const segA = ipv4('10.0.0.1', '10.0.0.2', 6, tcp(1111, 2222, 1000, 5000, Buffer.from('AAAAAAAAAAAAAAAAAAAA')));
const segB = ipv4('10.0.0.1', '10.0.0.2', 6, tcp(1111, 2222, 1020, 5000, Buffer.from('BBBBBBBBBBBBBBBBBBBB')));
const truncated = pcapLE([
  { ts: 1760000000, data: segA, captured: 14 + 20 + 20 + 10, original: segA.length },
  { ts: 1760000000.1, data: segB },
]);
summarise(truncated, 'snaplen truncated first segment (10 of 20 payload bytes captured)');

// ---------------------------------------------------------------------------
// 3. IPv4 first fragment with MF set
// ---------------------------------------------------------------------------
const big = ipv4('10.0.0.1', '10.0.0.2', 6, tcp(1111, 2222, 1000, 5000, Buffer.from('X'.repeat(40))), { fragField: 0x2000 });
summarise(pcapLE([{ ts: 1760000000, data: big }]), 'IPv4 first fragment (MF=1, offset 0)');

// ---------------------------------------------------------------------------
// 4. TCP options present (data offset 8 words)
// ---------------------------------------------------------------------------
const withOptions = pcapLE([
  { ts: 1760000000, data: ipv4('10.0.0.1', '10.0.0.2', 6, tcp(1111, 2222, 1000, 5000, Buffer.from('optioned payload'), { dataOffsetWords: 8 })) },
]);
const opt = summarise(withOptions, 'TCP header with 12 bytes of options');
if (opt?.flows[0]) line(`  forward bytes looked like: ${JSON.stringify(opt.flows[0].forward.data.toString('latin1'))}`);

// ---------------------------------------------------------------------------
// 5. pcap record with captured > original (malformed)
// ---------------------------------------------------------------------------
const badLen = pcapLE([{ ts: 1760000000, data: segB, captured: segB.length + 500, original: segB.length }]);
summarise(badLen, 'pcap record claiming 500 more captured bytes than the file holds');

// ---------------------------------------------------------------------------
// 6. Sequence delta at exactly 2^31
// ---------------------------------------------------------------------------
const { reassembleTcp } = await import('../../dist/core/net/flows.js');
const mk = (seq, payload) => ({ index: 1, ts: 0, transport: 'tcp', src: { ip: 'a', port: 1 }, dst: { ip: 'b', port: 2 }, payload: Buffer.from(payload), seq });

line(`\n=== sequence delta at exactly 2^31 ===`);
let halfErr = null;
const t0 = Date.now();
try {
  reassembleTcp([mk(0x00000000, 'early'), mk(0x80000000, 'late')]);
} catch (e) {
  halfErr = e.message.split('\n')[0];
}
line(`  ${halfErr ? 'THREW' : 'ok'} after ${Date.now() - t0}ms: ${halfErr ?? ''}`);

// A realistic case: a capture with a stray frame from a reused 4-tuple, 40 MB ahead.
line(`\n=== sequence jump of 40 MB (a stray frame from another connection) ===`);
let jumpErr = null;
const t1 = Date.now();
let jumpResult = null;
try {
  jumpResult = reassembleTcp([mk(1000, 'first'), mk(1000 + 40 * 1024 * 1024, 'second')]);
} catch (e) {
  jumpErr = e.message.split('\n')[0];
}
line(`  ${jumpErr ? 'THREW' : 'ok'} after ${Date.now() - t1}ms, allocated ${jumpResult ? jumpResult.data.length : '-'} bytes, gaps ${JSON.stringify(jumpResult?.gaps ?? [])}`);

// ---------------------------------------------------------------------------
// 7. Retransmission that starts earlier and is longer
// ---------------------------------------------------------------------------
const wider = reassembleTcp([mk(105, 'fghij'), mk(100, 'ABCDEFGHIJ')]);
line(`\n=== longer retransmission arriving second ===`);
line(`  data ${JSON.stringify(wider.data.toString('latin1'))} retrans ${wider.retransmits} ooo ${wider.outOfOrder}`);

// ---------------------------------------------------------------------------
// 8. UDP with zero-length payload, then a real one
// ---------------------------------------------------------------------------
const udpFrame = (payload) => {
  const udp = Buffer.alloc(8 + payload.length);
  udp.writeUInt16BE(5000, 0);
  udp.writeUInt16BE(6000, 2);
  udp.writeUInt16BE(8 + payload.length, 4);
  payload.copy(udp, 8);
  return ipv4('10.0.0.1', '10.0.0.2', 17, udp);
};
summarise(pcapLE([
  { ts: 1760000000, data: udpFrame(Buffer.alloc(0)) },
  { ts: 1760000000.1, data: udpFrame(Buffer.from('real')) },
]), 'UDP with one empty datagram followed by a real one');

// ---------------------------------------------------------------------------
// 9. IPv6 with a fragment extension header (next header 44)
// ---------------------------------------------------------------------------
function ipv6Frame(srcHex, dstHex, nextHeader, payload, ext) {
  const eth = Buffer.alloc(14);
  eth.writeUInt16BE(0x86dd, 12);
  const ip = Buffer.alloc(40);
  ip.writeUInt8(0x60, 0);
  ip.writeUInt16BE(ext.length + payload.length, 4);
  ip.writeUInt8(nextHeader, 6);
  ip.writeUInt8(64, 7);
  Buffer.from(srcHex, 'hex').copy(ip, 8);
  Buffer.from(dstHex, 'hex').copy(ip, 24);
  return Buffer.concat([eth, ip, ...(ext ? [ext] : []), payload]);
}
const src6 = '20010db8000000000000000000000001';
const dst6 = '20010db8000000000000000000000002';
const fragHeader = Buffer.from([0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
summarise(pcapLE([
  { ts: 1760000000, data: ipv6Frame(src6, dst6, 44, tcp(1111, 2222, 1000, 5000, Buffer.from('ipv6 fragmented')), fragHeader) },
]), 'IPv6 with a fragment extension header');

// A plain IPv6 TCP frame, as the control.
const hopByHop = Buffer.from([0x06, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]);
summarise(pcapLE([
  { ts: 1760000000, data: ipv6Frame(src6, dst6, 0, tcp(1111, 2222, 1000, 5000, Buffer.from('ipv6 hop-by-hop')), hopByHop) },
]), 'IPv6 with a hop-by-hop extension header (control)');

// ---------------------------------------------------------------------------
// 10. Two different conversations on the same 4-tuple, far apart in time
// ---------------------------------------------------------------------------
const conv1 = { ts: 1760000000, data: ipv4('10.0.0.1', '10.0.0.2', 6, tcp(1111, 2222, 1000, 5000, Buffer.from('first-conversation'))) };
const conv2 = { ts: 1760003600, data: ipv4('10.0.0.1', '10.0.0.2', 6, tcp(1111, 2222, 9000, 5000, Buffer.from('second-conversation'))) };
const reuse = summarise(pcapLE([conv1, conv2]), 'same 4-tuple, two conversations an hour apart');
if (reuse?.flows[0]) line(`  merged payload: ${JSON.stringify(reuse.flows[0].forward.data.toString('latin1'))}`);

// ---------------------------------------------------------------------------
// 11. A TCP segment with FIN and payload, then a new connection on the same tuple
// ---------------------------------------------------------------------------
const finPayload = tcp(1111, 2222, 1000, 5000, Buffer.from('closing'));
finPayload[13] = 0x19; // PSH + ACK + FIN
const afterFin = tcp(1111, 2222, 1100, 5000, Buffer.from('next-connection'));
const fin = summarise(pcapLE([
  { ts: 1760000000, data: ipv4('10.0.0.1', '10.0.0.2', 6, finPayload) },
  { ts: 1760000001, data: ipv4('10.0.0.1', '10.0.0.2', 6, afterFin) },
]), 'FIN with payload, then a new connection');
if (fin?.flows[0]) line(`  merged payload: ${JSON.stringify(fin.flows[0].forward.data.toString('latin1'))} gaps ${JSON.stringify(fin.flows[0].forward.gaps)}`);

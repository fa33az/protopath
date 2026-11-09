import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';

interface RawRecord {
  ts: number;
  linkType: number;
  data: Buffer;
}

export interface RawCapture {
  format: 'pcap' | 'pcapng';
  records: RawRecord[];
}

const PCAP_USEC = 0xa1b2c3d4;
const PCAP_NSEC = 0xa1b23c4d;
const PCAPNG_SHB = 0x0a0d0d0a;
const PCAPNG_IDB = 0x00000001;
const PCAPNG_EPB = 0x00000006;
const PCAPNG_SPB = 0x00000003;
const PCAPNG_BOM_LE = 0x1a2b3c4d;

class Cursor {
  private at = 0;
  constructor(private readonly buf: Buffer) {}

  get remaining(): number {
    return this.buf.length - this.at;
  }

  get offset(): number {
    return this.at;
  }

  seek(to: number): void {
    this.at = to;
  }

  u8(): number {
    this.need(1);
    return this.buf[this.at++]!;
  }

  u16(endian: 'le' | 'be'): number {
    this.need(2);
    const v = endian === 'le' ? this.buf.readUInt16LE(this.at) : this.buf.readUInt16BE(this.at);
    this.at += 2;
    return v;
  }

  u32(endian: 'le' | 'be'): number {
    this.need(4);
    const v = endian === 'le' ? this.buf.readUInt32LE(this.at) : this.buf.readUInt32BE(this.at);
    this.at += 4;
    return v;
  }

  bytes(n: number): Buffer {
    this.need(n);
    const out = this.buf.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }

  skip(n: number): void {
    this.need(n);
    this.at += n;
  }

  private need(n: number): void {
    if (n < 0 || this.at + n > this.buf.length) {
      throw new RangeError(`capture truncated at offset ${this.at}, needed ${n} more bytes`);
    }
  }
}

/**
 * Reads classic pcap (microsecond and nanosecond variants) and pcapng.
 *
 * The parser is local rather than a dependency: both formats are small, and owning the
 * decoding keeps endianness, padding and truncation behaviour explicit.
 */
export function readCapture(path: string): RawCapture {
  return parseCapture(readFileSync(path));
}

export function parseCapture(buf: Buffer): RawCapture {
  if (buf.length < 4) throw new Error('capture is shorter than a file header');

  const asLe = buf.readUInt32LE(0);
  const asBe = buf.readUInt32BE(0);

  if (asLe === PCAPNG_SHB || asBe === PCAPNG_SHB) return parsePcapng(buf);

  if (asLe === PCAP_USEC || asLe === PCAP_NSEC) return parsePcap(buf, 'le', asLe === PCAP_NSEC);
  if (asBe === PCAP_USEC || asBe === PCAP_NSEC) return parsePcap(buf, 'be', asBe === PCAP_NSEC);

  throw new Error('not a pcap or pcapng capture: unrecognised magic');
}

function parsePcap(buf: Buffer, endian: 'le' | 'be', nanosecond: boolean): RawCapture {
  const c = new Cursor(buf);
  c.skip(4);
  c.u16(endian); // major
  c.u16(endian); // minor
  c.u32(endian); // thiszone
  c.u32(endian); // sigfigs
  c.u32(endian); // snaplen
  const linkType = c.u32(endian) & 0x0fffffff;

  const records: RawRecord[] = [];
  const ticksPerSecond = nanosecond ? 1e9 : 1e6;

  while (c.remaining >= 16) {
    const seconds = c.u32(endian);
    const fraction = c.u32(endian);
    const captured = c.u32(endian);
    c.u32(endian); // original length, not needed once captured length bounds the slice
    if (captured > c.remaining) break;
    records.push({
      ts: seconds + fraction / ticksPerSecond,
      linkType,
      data: Buffer.from(c.bytes(captured)),
    });
  }

  return { format: 'pcap', records };
}

interface PcapngInterface {
  linkType: number;
  ticksPerSecond: number;
}

function parsePcapng(buf: Buffer): RawCapture {
  const c = new Cursor(buf);
  const records: RawRecord[] = [];
  const interfaces: PcapngInterface[] = [];
  let endian: 'le' | 'be' = 'le';

  while (c.remaining >= 12) {
    const start = c.offset;
    const rawType = c.u32('le');

    if (rawType === PCAPNG_SHB) {
      // The byte-order magic sits at offset 8, after the type and the block length, so the
      // section's endianness is only known after reading it.
      const byteOrder = buf.readUInt32LE(start + 8);
      endian = byteOrder === PCAPNG_BOM_LE ? 'le' : 'be';
      const total = endian === 'le' ? buf.readUInt32LE(start + 4) : buf.readUInt32BE(start + 4);
      if (total < 12 || start + total > buf.length) break;
      interfaces.length = 0;
      c.seek(start + total);
      continue;
    }

    const total = buf.readUInt32LE(start + 4);
    const totalBE = buf.readUInt32BE(start + 4);
    const blockLength = endian === 'le' ? total : totalBE;
    if (blockLength < 12 || start + blockLength > buf.length) break;

    c.seek(start + 8);
    const body = c.bytes(blockLength - 12);
    c.seek(start + blockLength);
    const inner = new Cursor(body);

    if (rawType === PCAPNG_IDB) {
      const linkType = inner.u16(endian);
      inner.u16(endian); // reserved
      inner.u32(endian); // snaplen
      let ticksPerSecond = 1e6;
      while (inner.remaining >= 4) {
        const code = inner.u16(endian);
        const length = inner.u16(endian);
        const value = inner.bytes(length);
        if (code === 9 && length >= 1) {
          const exponent = value[0]!;
          const base2 = (exponent & 0x80) !== 0;
          const power = exponent & 0x7f;
          ticksPerSecond = base2 ? Math.pow(2, power) : Math.pow(10, power);
        }
        inner.skip(pad4(length));
      }
      interfaces.push({ linkType, ticksPerSecond });
    } else if (rawType === PCAPNG_EPB) {
      const interfaceId = inner.u32(endian);
      const high = inner.u32(endian);
      const low = inner.u32(endian);
      const captured = inner.u32(endian);
      inner.u32(endian); // original length
      const iface = interfaces[interfaceId] ?? interfaces[0];
      if (!iface || captured > inner.remaining) continue;
      const data = Buffer.from(inner.bytes(captured));
      const ticks = high * 4294967296 + low;
      records.push({ ts: ticks / iface.ticksPerSecond, linkType: iface.linkType, data });
    } else if (rawType === PCAPNG_SPB) {
      const original = inner.u32(endian);
      const iface = interfaces[0];
      if (!iface) continue;
      const length = Math.min(original, inner.remaining);
      records.push({ ts: 0, linkType: iface.linkType, data: Buffer.from(inner.bytes(length)) });
    }
  }

  return { format: 'pcapng', records };
}

function pad4(n: number): number {
  return (4 - (n % 4)) % 4;
}

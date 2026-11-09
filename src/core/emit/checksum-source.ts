/** Source text for the inverse of an inferred checksum, used by generated clients. */

import { algorithmByName, type ChecksumSpec } from '../infer/checksum.js';

export interface ChecksumSource {
  helpers: string[];
  expression: string;
  pythonHelpers: string[];
  pythonExpression: string;
}

const TS_CRC = `function crcCompute(data: Buffer, width: number, poly: number, init: number, refin: boolean, refout: boolean, xorout: number): number {
  const mask = width === 32 ? 0xffffffff : width === 16 ? 0xffff : 0xff;
  const high = width === 32 ? 0x80000000 : width === 16 ? 0x8000 : 0x80;
  const reflect = (value: number, bits: number): number => {
    let out = 0;
    for (let bit = 0; bit < bits; bit++) out = (out << 1) | ((value >> bit) & 1);
    return out >>> 0;
  };
  let crc = init & mask;
  for (const raw of data) {
    const byte = refin ? reflect(raw, 8) : raw;
    crc = width === 32 ? (crc ^ (byte * 0x1000000)) >>> 0 : width === 16 ? crc ^ (byte << 8) : crc ^ byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = width === 32 ? ((crc & high) ? (((crc << 1) >>> 0) ^ poly) >>> 0 : (crc << 1) >>> 0)
        : ((crc & high) ? (((crc << 1) ^ poly) & mask) : ((crc << 1) & mask));
    }
  }
  if (refout) crc = reflect(crc, width);
  return ((crc ^ xorout) & mask) >>> 0;
}`;

const TS_INET = `function inetChecksum(data: Buffer): number {
  let sum = 0;
  for (let i = 0; i < data.length; i += 2) {
    sum += (data[i]! << 8) | (i + 1 < data.length ? data[i + 1]! : 0);
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return ~sum & 0xffff;
}`;

const TS_FLETCHER16 = `function fletcher16(data: Buffer): number {
  let sum1 = 0;
  let sum2 = 0;
  for (const byte of data) {
    sum1 = (sum1 + byte) % 255;
    sum2 = (sum2 + sum1) % 255;
  }
  return ((sum2 << 8) | sum1) & 0xffff;
}`;

const TS_FLETCHER32 = `function fletcher32(data: Buffer): number {
  let sum1 = 0xffff;
  let sum2 = 0xffff;
  for (let i = 0; i < data.length; i += 2) {
    const word = (data[i]! << 8) | (i + 1 < data.length ? data[i + 1]! : 0);
    sum1 = (sum1 + word) % 65535;
    sum2 = (sum2 + sum1) % 65535;
  }
  return ((sum2 << 16) | sum1) >>> 0;
}`;

const TS_ADLER32 = `function adler32(data: Buffer): number {
  let a = 1;
  let b = 0;
  for (const byte of data) {
    a = (a + byte) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}`;

const PY_CRC = `def _crc_compute(data: bytes, width: int, poly: int, init: int, refin: bool, refout: bool, xorout: int) -> int:
    mask = {32: 0xFFFFFFFF, 16: 0xFFFF, 8: 0xFF}[width]
    high = {32: 0x80000000, 16: 0x8000, 8: 0x80}[width]

    def reflect(value: int, bits: int) -> int:
        out = 0
        for bit in range(bits):
            out = (out << 1) | ((value >> bit) & 1)
        return out

    crc = init & mask
    for raw in data:
        byte = reflect(raw, 8) if refin else raw
        if width == 32:
            crc ^= byte << 24
        elif width == 16:
            crc ^= byte << 8
        else:
            crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & mask if crc & high else (crc << 1) & mask
    if refout:
        crc = reflect(crc, width)
    return (crc ^ xorout) & mask`;

const PY_INET = `def _inet_checksum(data: bytes) -> int:
    total = 0
    for i in range(0, len(data) - 1, 2):
        total += (data[i] << 8) | data[i + 1]
    if len(data) % 2:
        total += data[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF`;

const PY_FLETCHER16 = `def _fletcher16(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    for byte in data:
        sum1 = (sum1 + byte) % 255
        sum2 = (sum2 + sum1) % 255
    return (sum2 << 8) | sum1`;

const PY_FLETCHER32 = `def _fletcher32(data: bytes) -> int:
    sum1 = 0xFFFF
    sum2 = 0xFFFF
    for i in range(0, len(data) - 1, 2):
        sum1 = (sum1 + ((data[i] << 8) | data[i + 1])) % 65535
        sum2 = (sum2 + sum1) % 65535
    if len(data) % 2:
        sum1 = (sum1 + (data[-1] << 8)) % 65535
        sum2 = (sum2 + sum1) % 65535
    return (sum2 << 16) | sum1`;

const PY_ADLER32 = `def _adler32(data: bytes) -> int:
    a = 1
    b = 0
    for byte in data:
        a = (a + byte) % 65521
        b = (b + a) % 65521
    return (b << 16) | a`;

const PY_XOR = `def _xor(data: bytes) -> int:
    value = 0
    for byte in data:
        value ^= byte
    return value`;

/**
 * Resolves a checksum field into source code that recomputes it.
 *
 * `spec` wins when present, because a recovered parameter set cannot be found by name. The
 * expression always embeds the literal parameters, so the generated client is self-contained:
 * it does not import this package and it does not need the catalogue.
 */
export function checksumSource(algorithm: string, spec?: ChecksumSpec): ChecksumSource | null {
  const resolved = spec ?? algorithmByName(algorithm)?.spec;
  if (!resolved) return null;

  switch (resolved.kind) {
    case 'crc': {
      const p = resolved.params;
      return {
        helpers: [TS_CRC],
        expression: `crcCompute(data, ${p.width}, 0x${p.poly.toString(16)}, 0x${p.init.toString(16)}, ${p.refin}, ${p.refout}, 0x${p.xorout.toString(16)})`,
        pythonHelpers: [PY_CRC],
        pythonExpression: `_crc_compute(data, ${p.width}, 0x${p.poly.toString(16)}, 0x${p.init.toString(16)}, ${p.refin ? 'True' : 'False'}, ${p.refout ? 'True' : 'False'}, 0x${p.xorout.toString(16)})`,
      };
    }
    case 'sum8':
      return {
        helpers: [],
        expression: 'data.reduce((sum, byte) => (sum + byte) & 0xff, 0)',
        pythonHelpers: [],
        pythonExpression: 'sum(data) & 0xFF',
      };
    case 'sum16':
      return {
        helpers: [],
        expression: 'data.reduce((sum, byte) => (sum + byte) & 0xffff, 0)',
        pythonHelpers: [],
        pythonExpression: 'sum(data) & 0xFFFF',
      };
    case 'xor8':
      return {
        helpers: [],
        expression: 'data.reduce((value, byte) => value ^ byte, 0)',
        pythonHelpers: [PY_XOR],
        pythonExpression: '(_xor(data) & 0xFF)',
      };
    case 'inet16':
      return {
        helpers: [TS_INET],
        expression: 'inetChecksum(data)',
        pythonHelpers: [PY_INET],
        pythonExpression: '_inet_checksum(data)',
      };
    case 'fletcher16':
      return {
        helpers: [TS_FLETCHER16],
        expression: 'fletcher16(data)',
        pythonHelpers: [PY_FLETCHER16],
        pythonExpression: '_fletcher16(data)',
      };
    case 'fletcher32':
      return {
        helpers: [TS_FLETCHER32],
        expression: 'fletcher32(data)',
        pythonHelpers: [PY_FLETCHER32],
        pythonExpression: '_fletcher32(data)',
      };
    case 'adler32':
      return {
        helpers: [TS_ADLER32],
        expression: 'adler32(data)',
        pythonHelpers: [PY_ADLER32],
        pythonExpression: '_adler32(data)',
      };
  }
}

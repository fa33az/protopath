/** Source text for the inverse of an inferred checksum, used by generated clients. */

export interface ChecksumSource {
  helpers: string[];
  expression: string;
  pythonHelpers: string[];
  pythonExpression: string;
}

const CRC16_REFLECTED = `function crc16Reflected(data: Buffer, poly: number, init: number): number {
  let crc = init;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? (crc >>> 1) ^ poly : crc >>> 1;
  }
  return crc & 0xffff;
}`;

const CRC16_FORWARD = `function crc16Forward(data: Buffer, poly: number, init: number): number {
  let crc = init;
  for (const byte of data) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit++) crc = crc & 0x8000 ? ((crc << 1) ^ poly) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}`;

const CRC8 = `function crc8(data: Buffer, poly: number, init: number): number {
  let crc = init;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = crc & 0x80 ? ((crc << 1) ^ poly) & 0xff : (crc << 1) & 0xff;
  }
  return crc;
}`;

const CRC32 = `function crc32Ieee(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}`;

const PY_CRC16_REFLECTED = `def _crc16_reflected(data: bytes, poly: int, init: int) -> int:
    crc = init
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
    return crc & 0xFFFF`;

const PY_CRC16_FORWARD = `def _crc16_forward(data: bytes, poly: int, init: int) -> int:
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc`;

const PY_CRC8 = `def _crc8(data: bytes, poly: int, init: int) -> int:
    crc = init
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc`;

const PY_CRC32 = `def _crc32_ieee(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF`;

const PY_SUM = `def _sum_bytes(data: bytes) -> int:
    return sum(data)`;

const PY_XOR = `def _xor_bytes(data: bytes) -> int:
    value = 0
    for byte in data:
        value ^= byte
    return value`;

export function checksumSource(algorithm: string): ChecksumSource | null {
  switch (algorithm) {
    case 'sum8':
      return {
        helpers: [],
        expression: 'data.reduce((sum, byte) => (sum + byte) & 0xff, 0)',
        pythonHelpers: [PY_SUM],
        pythonExpression: '_sum_bytes(data) & 0xFF',
      };
    case 'sum16':
      return {
        helpers: [],
        expression: 'data.reduce((sum, byte) => (sum + byte) & 0xffff, 0)',
        pythonHelpers: [PY_SUM],
        pythonExpression: '_sum_bytes(data) & 0xFFFF',
      };
    case 'xor8':
      return {
        helpers: [],
        expression: 'data.reduce((value, byte) => value ^ byte, 0)',
        pythonHelpers: [PY_XOR],
        pythonExpression: '_xor_bytes(data) & 0xFF',
      };
    case 'crc8':
      return {
        helpers: [CRC8],
        expression: 'crc8(data, 0x07, 0x00)',
        pythonHelpers: [PY_CRC8],
        pythonExpression: '_crc8(data, 0x07, 0x00)',
      };
    case 'crc8/itu':
      return {
        helpers: [CRC8],
        expression: 'crc8(data, 0x07, 0x55)',
        pythonHelpers: [PY_CRC8],
        pythonExpression: '_crc8(data, 0x07, 0x55)',
      };
    case 'crc16/ccitt-false':
      return {
        helpers: [CRC16_FORWARD],
        expression: 'crc16Forward(data, 0x1021, 0xffff)',
        pythonHelpers: [PY_CRC16_FORWARD],
        pythonExpression: '_crc16_forward(data, 0x1021, 0xFFFF)',
      };
    case 'crc16/xmodem':
      return {
        helpers: [CRC16_FORWARD],
        expression: 'crc16Forward(data, 0x1021, 0x0000)',
        pythonHelpers: [PY_CRC16_FORWARD],
        pythonExpression: '_crc16_forward(data, 0x1021, 0x0000)',
      };
    case 'crc16/modbus':
    case 'crc16/usb':
      return {
        helpers: [CRC16_REFLECTED],
        expression: 'crc16Reflected(data, 0xa001, 0xffff)',
        pythonHelpers: [PY_CRC16_REFLECTED],
        pythonExpression: '_crc16_reflected(data, 0xA001, 0xFFFF)',
      };
    case 'crc16/arc':
      return {
        helpers: [CRC16_REFLECTED],
        expression: 'crc16Reflected(data, 0xa001, 0x0000)',
        pythonHelpers: [PY_CRC16_REFLECTED],
        pythonExpression: '_crc16_reflected(data, 0xA001, 0x0000)',
      };
    case 'crc32/ieee':
      return {
        helpers: [CRC32],
        expression: 'crc32Ieee(data)',
        pythonHelpers: [PY_CRC32],
        pythonExpression: '_crc32_ieee(data)',
      };
    default:
      return null;
  }
}

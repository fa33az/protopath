import { Buffer } from 'node:buffer';
import type { Endpoint, Frame, Transport } from '../types.js';

export const LINKTYPE_NULL = 0;
export const LINKTYPE_ETHERNET = 1;
export const LINKTYPE_RAW = 101;
export const LINKTYPE_LINUX_SLL = 113;
export const LINKTYPE_IPV4 = 228;
export const LINKTYPE_IPV6 = 229;

const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;
const ETHERTYPE_VLAN = 0x8100;
const ETHERTYPE_QINQ = 0x88a8;

const PROTO_TCP = 6;
const PROTO_UDP = 17;

export interface DecodedFrame {
  transport: Transport;
  src: Endpoint;
  dst: Endpoint;
  payload: Buffer;
  seq?: number;
  ack?: number;
  flags?: number;
}

/** Decodes one link-layer record down to its transport payload, or returns null. */
export function decodeLinkFrame(linkType: number, data: Buffer): DecodedFrame | null {
  switch (linkType) {
    case LINKTYPE_ETHERNET:
      return decodeEthernet(data);
    case LINKTYPE_RAW:
      return decodeIp(data);
    case LINKTYPE_LINUX_SLL:
      return data.length >= 16 ? decodeIp(data.subarray(16)) : null;
    case LINKTYPE_IPV4:
      return decodeIp(data, 'ipv4');
    case LINKTYPE_IPV6:
      return decodeIp(data, 'ipv6');
    case LINKTYPE_NULL:
      return data.length >= 4 ? decodeIp(data.subarray(4)) : null;
    default:
      return null;
  }
}

function decodeEthernet(data: Buffer): DecodedFrame | null {
  if (data.length < 14) return null;
  let etherType = data.readUInt16BE(12);
  let at = 14;

  while (etherType === ETHERTYPE_VLAN || etherType === ETHERTYPE_QINQ) {
    if (data.length < at + 4) return null;
    etherType = data.readUInt16BE(at + 2);
    at += 4;
  }

  if (etherType === ETHERTYPE_IPV4) return decodeIp(data.subarray(at), 'ipv4');
  if (etherType === ETHERTYPE_IPV6) return decodeIp(data.subarray(at), 'ipv6');
  return null;
}

function decodeIp(data: Buffer, family?: 'ipv4' | 'ipv6'): DecodedFrame | null {
  if (data.length < 1) return null;
  const version = data[0]! >> 4;
  if (family === 'ipv4' && version !== 4) return null;
  if (family === 'ipv6' && version !== 6) return null;
  if (version === 4) return decodeIpv4(data);
  if (version === 6) return decodeIpv6(data);
  return null;
}

function decodeIpv4(data: Buffer): DecodedFrame | null {
  if (data.length < 20) return null;
  const headerLength = (data[0]! & 0x0f) * 4;
  if (headerLength < 20 || data.length < headerLength) return null;

  const totalLength = data.readUInt16BE(2);
  const fragment = data.readUInt16BE(6);
  if ((fragment & 0x1fff) !== 0) return null; // non-first fragment: no L4 header
  if (data[9] === PROTO_TCP || data[9] === PROTO_UDP) {
    const proto = data[9] as number;
    const end = totalLength > 0 && totalLength <= data.length ? totalLength : data.length;
    const src: Endpoint = { ip: `${data[12]}.${data[13]}.${data[14]}.${data[15]}`, port: 0 };
    const dst: Endpoint = { ip: `${data[16]}.${data[17]}.${data[18]}.${data[19]}`, port: 0 };
    return decodeTransport(data.subarray(headerLength, end), proto, src, dst);
  }
  return null;
}

function decodeIpv6(data: Buffer): DecodedFrame | null {
  if (data.length < 40) return null;
  const payloadLength = data.readUInt16BE(4);
  let nextHeader = data[6]!;
  let at = 40;
  const end = Math.min(data.length, 40 + payloadLength);

  while (nextHeader === 0 || nextHeader === 43 || nextHeader === 60) {
    if (at + 2 > end) return null;
    const extensionLength = (data[at + 1]! + 1) * 8;
    nextHeader = data[at]!;
    at += extensionLength;
  }

  if (nextHeader !== PROTO_TCP && nextHeader !== PROTO_UDP) return null;
  if (at + 4 > end) return null;

  const src: Endpoint = { ip: formatIpv6(data, 8), port: 0 };
  const dst: Endpoint = { ip: formatIpv6(data, 24), port: 0 };
  return decodeTransport(data.subarray(at, end), nextHeader, src, dst);
}

function decodeTransport(data: Buffer, proto: number, src: Endpoint, dst: Endpoint): DecodedFrame | null {
  if (data.length < 4) return null;

  if (proto === PROTO_UDP) {
    if (data.length < 8) return null;
    const length = data.readUInt16BE(4);
    const end = length >= 8 && length <= data.length ? length : data.length;
    return {
      transport: 'udp',
      src: { ...src, port: data.readUInt16BE(0) },
      dst: { ...dst, port: data.readUInt16BE(2) },
      payload: Buffer.from(data.subarray(8, end)),
    };
  }

  if (data.length < 20) return null;
  const dataOffset = (data[12]! >> 4) * 4;
  if (dataOffset < 20 || data.length < dataOffset) return null;

  return {
    transport: 'tcp',
    src: { ...src, port: data.readUInt16BE(0) },
    dst: { ...dst, port: data.readUInt16BE(2) },
    seq: data.readUInt32BE(4),
    ack: data.readUInt32BE(8),
    flags: data[13]!,
    payload: Buffer.from(data.subarray(dataOffset)),
  };
}

function formatIpv6(data: Buffer, at: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 8; i++) parts.push(data.readUInt16BE(at + i * 2).toString(16));
  return parts.join(':');
}

export function framesFromCapture(
  records: Array<{ ts: number; linkType: number; data: Buffer }>,
): { frames: Frame[]; skipped: number } {
  const frames: Frame[] = [];
  let skipped = 0;

  records.forEach((record, i) => {
    const decoded = decodeLinkFrame(record.linkType, record.data);
    if (!decoded || decoded.payload.length === 0) {
      skipped++;
      return;
    }
    frames.push({
      index: i + 1,
      ts: record.ts,
      transport: decoded.transport,
      src: decoded.src,
      dst: decoded.dst,
      payload: decoded.payload,
      ...(decoded.seq === undefined ? {} : { seq: decoded.seq }),
      ...(decoded.ack === undefined ? {} : { ack: decoded.ack }),
      ...(decoded.flags === undefined ? {} : { flags: decoded.flags }),
    });
  });

  return { frames, skipped };
}

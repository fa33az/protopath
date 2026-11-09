import type { Buffer } from 'node:buffer';

export type Endian = 'le' | 'be';
export type Transport = 'tcp' | 'udp';

export interface Endpoint {
  ip: string;
  port: number;
}

/** One decoded transport-layer datagram, payload attached. */
export interface Frame {
  /** 1-based position in the capture. */
  index: number;
  /** Seconds since the Unix epoch, sub-millisecond precision preserved when the capture has it. */
  ts: number;
  transport: Transport;
  src: Endpoint;
  dst: Endpoint;
  payload: Buffer;
  seq?: number;
  ack?: number;
  flags?: number;
}

export interface Capture {
  path: string;
  format: 'pcap' | 'pcapng';
  linkType: number;
  frames: Frame[];
  /** Frames whose link type, address family or transport we declined to decode. */
  skipped: number;
}

export interface Segment {
  offset: number;
  length: number;
  ts: number;
  frameIndex: number;
}

export interface StreamState {
  data: Buffer;
  /** Byte ranges that never arrived, filled with zeros so offsets stay honest. */
  gaps: Array<[number, number]>;
  retransmits: number;
  outOfOrder: number;
  segments: Segment[];
}

export interface Flow {
  /** Stable identifier: "a -> b proto", built from the endpoints only. */
  key: string;
  transport: Transport;
  /** Endpoint of the first frame observed, which is usually the client. */
  a: Endpoint;
  b: Endpoint;
  firstTs: number;
  lastTs: number;
  frames: Frame[];
  /** Bytes travelling from {@link Flow.a} to {@link Flow.b}. */
  forward: StreamState;
  /** Bytes travelling from {@link Flow.b} to {@link Flow.a}. */
  reverse: StreamState;
}

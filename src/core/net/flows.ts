import { Buffer } from 'node:buffer';
import type { Endpoint, Flow, Frame, Segment, StreamState } from '../types.js';

interface Piece {
  offset: number;
  data: Buffer;
  ts: number;
  frameIndex: number;
}

/** Groups frames into bidirectional flows, preserving first-seen endpoint orientation. */
export function buildFlows(frames: Frame[]): Flow[] {
  const flows = new Map<string, Flow>();

  for (const frame of frames) {
    const key = flowKey(frame.src, frame.dst, frame.transport);
    let flow = flows.get(key);
    if (!flow) {
      flow = {
        key,
        transport: frame.transport,
        a: frame.src,
        b: frame.dst,
        firstTs: frame.ts,
        lastTs: frame.ts,
        frames: [],
        forward: emptyStream(),
        reverse: emptyStream(),
      };
      flows.set(key, flow);
    }
    flow.frames.push(frame);
    if (frame.ts > flow.lastTs) flow.lastTs = frame.ts;
  }

  for (const flow of flows.values()) {
    const toB = flow.frames.filter((f) => sameEndpoint(f.src, flow.a));
    const toA = flow.frames.filter((f) => sameEndpoint(f.src, flow.b));
    flow.forward = flow.transport === 'tcp' ? reassembleTcp(toB) : concatenate(toB);
    flow.reverse = flow.transport === 'tcp' ? reassembleTcp(toA) : concatenate(toA);
  }

  return [...flows.values()].sort((x, y) => x.firstTs - y.firstTs);
}

export function flowKey(src: Endpoint, dst: Endpoint, transport: string): string {
  // Sorted so both directions of a conversation land on the same key; the flow itself keeps
  // the first-seen endpoint order for display.
  const labels = [endpointLabel(src), endpointLabel(dst)].sort();
  return `${labels[0]} <> ${labels[1]} ${transport}`;
}

export function endpointLabel(endpoint: Endpoint): string {
  const host = endpoint.ip.includes(':') ? `[${endpoint.ip}]` : endpoint.ip;
  return `${host}:${endpoint.port}`;
}

export function sameEndpoint(a: Endpoint, b: Endpoint): boolean {
  return a.ip === b.ip && a.port === b.port;
}

function emptyStream(): StreamState {
  return { data: Buffer.alloc(0), gaps: [], retransmits: 0, outOfOrder: 0, segments: [] };
}

function concatenate(frames: Frame[]): StreamState {
  const segments: Segment[] = [];
  let total = 0;
  for (const frame of frames) {
    segments.push({ offset: total, length: frame.payload.length, ts: frame.ts, frameIndex: frame.index });
    total += frame.payload.length;
  }
  return {
    data: Buffer.concat(frames.map((f) => f.payload)),
    gaps: [],
    retransmits: 0,
    outOfOrder: 0,
    segments,
  };
}

/**
 * Reassembles one direction of a TCP conversation by sequence number.
 *
 * Offsets are taken relative to the lowest sequence number in the direction, not to the
 * first packet seen: a capture that starts mid-burst, or a segment that arrives early,
 * would otherwise make every earlier byte look like a retransmission.
 *
 * Retransmissions are counted and dropped, out-of-order segments are placed by offset, and
 * holes are reported instead of silently closed, because a fabricated byte would corrupt
 * every inference downstream.
 */
export function reassembleTcp(frames: Frame[]): StreamState {
  const withSeq = frames.filter((f) => typeof f.seq === 'number');
  if (withSeq.length === 0) return emptyStream();

  const reference = withSeq[0]!.seq!;
  const deltas = withSeq.map((frame) => signedDelta(frame.seq!, reference));
  const lowest = Math.min(...deltas);

  let highest = -1;
  let outOfOrder = 0;
  let retransmits = 0;
  const pieces: Piece[] = [];

  withSeq.forEach((frame, index) => {
    const offset = deltas[index]! - lowest;
    if (offset < highest) outOfOrder++;
    highest = Math.max(highest, offset + frame.payload.length);
    pieces.push({ offset, data: frame.payload, ts: frame.ts, frameIndex: frame.index });
  });

  pieces.sort((a, b) => a.offset - b.offset);

  const merged: Piece[] = [];
  let cursor = 0;
  for (const piece of pieces) {
    if (piece.offset + piece.data.length <= cursor) {
      retransmits++;
      continue;
    }
    if (piece.offset < cursor) {
      const drop = cursor - piece.offset;
      merged.push({ ...piece, offset: cursor, data: piece.data.subarray(drop) });
      cursor += piece.data.length - drop;
      retransmits++;
      continue;
    }
    merged.push(piece);
    cursor = piece.offset + piece.data.length;
  }

  const total = merged.length === 0 ? 0 : merged[merged.length - 1]!.offset + merged[merged.length - 1]!.data.length;
  const data = Buffer.alloc(total);
  const gaps: Array<[number, number]> = [];
  const segments: Segment[] = [];

  let filled = 0;
  for (const piece of merged) {
    if (piece.offset > filled) gaps.push([filled, piece.offset]);
    piece.data.copy(data, piece.offset);
    segments.push({ offset: piece.offset, length: piece.data.length, ts: piece.ts, frameIndex: piece.frameIndex });
    filled = piece.offset + piece.data.length;
  }
  if (filled < total) gaps.push([filled, total]);

  return { data, gaps, retransmits, outOfOrder, segments };
}

/** Sequence-space delta, corrected for 32-bit wraparound. */
function signedDelta(value: number, reference: number): number {
  let delta = (value - reference) >>> 0;
  if (delta > 0x7fffffff) delta -= 0x100000000;
  return delta;
}

/** Timestamp of the segment covering a stream offset. */
export function timestampAt(stream: StreamState, offset: number): number {
  let best = stream.segments.length > 0 ? stream.segments[0]!.ts : 0;
  for (const segment of stream.segments) {
    if (segment.offset > offset) break;
    best = segment.ts;
  }
  return best;
}

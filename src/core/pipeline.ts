import { Buffer } from 'node:buffer';
import { readCapture } from './pcap/reader.js';
import { framesFromCapture } from './net/decode.js';
import { buildFlows, sameEndpoint, timestampAt } from './net/flows.js';
import { detectChecksum, type ChecksumMatch } from './infer/checksum.js';
import { inferFraming, isConfident, type FramingHypothesis } from './infer/framing.js';
import { inferFields, type Field } from './infer/fields.js';
import { buildStateGraph, labelMessage, type MessageRecord, type StateGraph } from './infer/state.js';
import type { Capture, Flow, StreamState } from './types.js';

export const VERSION = '0.1.0';

export interface DirectionAnalysis {
  direction: 'forward' | 'reverse';
  label: string;
  bytes: number;
  messageCount: number;
  framing: FramingHypothesis[];
  best: FramingHypothesis | undefined;
  fields: Field[];
  checksums: ChecksumMatch[];
  messages: MessageRecord[];
  notes: string[];
  limitations: string[];
}

export interface FlowAnalysis {
  flow: Flow;
  forward: DirectionAnalysis;
  reverse: DirectionAnalysis;
  graph: StateGraph;
  /** Direction the protocol description was taken from: the one with more structure. */
  primary: 'forward' | 'reverse';
  /** Capture this flow was read from, used in generated file headers. */
  capturePath: string;
  notes: string[];
}

export interface CaptureAnalysis {
  capture: {
    path: string;
    format: Capture['format'];
    frames: number;
    flows: number;
    skipped: number;
  };
  flows: FlowAnalysis[];
  warnings: string[];
  generatedAt: string;
  version: string;
}

export interface AnalyzeOptions {
  /** Restrict analysis to one flow, keyed exactly as printed by `protopath flows`. */
  flow?: string;
  /** Upper bound on how many flows are analysed, largest first. */
  maxFlows?: number;
}

export function loadCapture(path: string): Capture {
  const raw = readCapture(path);
  const { frames, skipped } = framesFromCapture(raw.records);
  return {
    path,
    format: raw.format,
    linkType: raw.records[0]?.linkType ?? 1,
    frames,
    skipped,
  };
}

export function analyzeFile(path: string, options: AnalyzeOptions = {}): CaptureAnalysis {
  return analyzeCapture(loadCapture(path), options);
}

export function analyzeCapture(capture: Capture, options: AnalyzeOptions = {}): CaptureAnalysis {
  const warnings: string[] = [];
  const allFlows = buildFlows(capture.frames);

  if (allFlows.length === 0) warnings.push('no TCP or UDP payload was decoded from this capture');
  if (capture.skipped > 0) {
    warnings.push(`${capture.skipped} frames were skipped: no IP, no transport payload, or a non-first fragment`);
  }

  const candidates = options.flow ? allFlows.filter((f) => f.key === options.flow) : allFlows;
  if (options.flow && candidates.length === 0) {
    throw new Error(`no flow matches "${options.flow}"; run \`protopath flows ${capture.path}\` for the exact keys`);
  }

  const analyzed = candidates
    .map((flow) => analyzeFlow(flow, capture.path))
    .sort((a, b) => scoreFlow(b) - scoreFlow(a))
    .slice(0, options.maxFlows ?? 4);

  const partial = analyzed.filter((a) => {
    const direction = a.primary === 'forward' ? a.forward : a.reverse;
    return !direction.best || direction.best.score < 0.6;
  });
  if (partial.length > 0) {
    warnings.push(
      'at least one direction produced no confident framing; the report lists every hypothesis it could not rule out',
    );
  }

  return {
    capture: {
      path: capture.path,
      format: capture.format,
      frames: capture.frames.length,
      flows: allFlows.length,
      skipped: capture.skipped,
    },
    flows: analyzed,
    warnings,
    generatedAt: new Date().toISOString(),
    version: VERSION,
  };
}

export function analyzeFlow(flow: Flow, capturePath = ''): FlowAnalysis {
  const forward = analyzeDirection(flow, 'forward');
  const reverse = analyzeDirection(flow, 'reverse');

  const primary = forward.best && (!reverse.best || forward.best.score >= reverse.best.score) ? 'forward' : 'reverse';
  const primaryFields = primary === 'forward' ? forward.fields : reverse.fields;
  const messages = [...forward.messages, ...reverse.messages];
  const graph = buildStateGraph(messages, primaryFields);

  const notes: string[] = [];
  if (forward.best && reverse.best) {
    if (forward.best.kind !== reverse.best.kind) {
      notes.push(
        `the two directions frame differently (${forward.best.kind} vs ${reverse.best.kind}); treat them as separate protocols`,
      );
    } else if (forward.best.kind === 'length-prefix' && reverse.best.kind === 'length-prefix') {
      const a = forward.best.lengthPrefix;
      const b = reverse.best.lengthPrefix;
      if (a && b && (a.lenOffset !== b.lenOffset || a.size !== b.size || a.endian !== b.endian || a.bias !== b.bias)) {
        notes.push('both directions are length-prefixed but with different length encodings');
      }
    }
  }

  return { flow, forward, reverse, graph, primary, capturePath, notes };
}

function analyzeDirection(flow: Flow, direction: 'forward' | 'reverse'): DirectionAnalysis {
  const stream: StreamState = direction === 'forward' ? flow.forward : flow.reverse;
  const label = direction === 'forward' ? `${formatEndpoint(flow.a)} -> ${formatEndpoint(flow.b)}` : `${formatEndpoint(flow.b)} -> ${formatEndpoint(flow.a)}`;
  const notes: string[] = [];
  const limitations: string[] = [];

  if (stream.data.length === 0) {
    return {
      direction,
      label,
      bytes: 0,
      messageCount: 0,
      framing: [],
      best: undefined,
      fields: [],
      checksums: [],
      messages: [],
      notes: ['this direction carries no bytes'],
      limitations: [],
    };
  }

  if (stream.gaps.length > 0) {
    limitations.push(
      `${stream.gaps.length} capture gap(s) totalling ${stream.gaps.reduce((n, [from, to]) => n + to - from, 0)} bytes; zeros were inserted so offsets stay aligned`,
    );
  }
  if (stream.retransmits > 0) limitations.push(`${stream.retransmits} duplicate or overlapping segment(s) were dropped during reassembly`);

  const framing = inferFraming(stream.data);
  const best = framing[0];
  const confident = isConfident(best);

  let checksums: ChecksumMatch[] = [];
  let fields: Field[] = [];

  if (best && confident) {
    checksums = detectChecksum(best.messages);
    const inference = inferFields({
      messages: best.messages,
      framing: best.kind,
      ...(best.lengthPrefix ? { lengthPrefix: best.lengthPrefix } : {}),
      ...(checksums[0] ? { checksum: checksums[0] } : {}),
    });
    fields = inference.fields;
    notes.push(...inference.notes);

    const alternative = framing[1];
    if (alternative && best.score - alternative.score < 0.05) {
      limitations.push(
        `the second hypothesis (${alternative.kind}) scores within ${(best.score - alternative.score).toFixed(2)} of the winner; confirm the framing before trusting field offsets`,
      );
    }
  } else {
    limitations.push('no framing hypothesis reached the confidence threshold, so no field model was produced');
  }

  const messages: MessageRecord[] = [];
  if (best && confident) {
    best.messages.forEach((bytes, i) => {
      const offset = best.offsets[i]!;
      messages.push({
        direction,
        offset,
        ts: timestampAt(stream, offset),
        bytes,
        label: labelMessage(bytes, direction, fields),
      });
    });
  }

  return {
    direction,
    label,
    bytes: stream.data.length,
    messageCount: messages.length,
    framing,
    best,
    fields,
    checksums,
    messages,
    notes,
    limitations,
  };
}

function scoreFlow(analysis: FlowAnalysis): number {
  const forward = analysis.forward.best?.score ?? 0;
  const reverse = analysis.reverse.best?.score ?? 0;
  const bytes = analysis.forward.bytes + analysis.reverse.bytes;
  const opcodeBonus = analysis.forward.fields.some((f) => f.role === 'opcode') ? 0.05 : 0;
  const checksumBonus = analysis.forward.checksums.length > 0 ? 0.05 : 0;
  return (forward + reverse) / 2 + Math.min(bytes, 1_000_000) / 5_000_000 + opcodeBonus + checksumBonus;
}

export function formatEndpoint(endpoint: { ip: string; port: number }): string {
  return `${endpoint.ip.includes(':') ? `[${endpoint.ip}]` : endpoint.ip}:${endpoint.port}`;
}

export function isServerPort(flow: Flow, endpoint: { ip: string; port: number }): boolean {
  return sameEndpoint(endpoint, flow.b);
}

export function summarizeMessages(messages: MessageRecord[], limit = 5): Array<{ label: string; hex: string; length: number }> {
  return messages.slice(0, limit).map((message) => ({
    label: message.label,
    hex: message.bytes.toString('hex'),
    length: message.bytes.length,
  }));
}

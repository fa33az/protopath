import { Buffer } from 'node:buffer';
import { fieldValue, type Field } from './fields.js';

export interface MessageRecord {
  direction: 'forward' | 'reverse';
  /** Byte offset inside the direction's stream. */
  offset: number;
  ts: number;
  bytes: Buffer;
  label: string;
}

export interface StateNode {
  id: string;
  label: string;
  count: number;
}

export interface Transition {
  from: string;
  to: string;
  count: number;
}

export interface StateGraph {
  nodes: StateNode[];
  transitions: Transition[];
  /** First observed label in each direction, which is where a replay must start. */
  start: string[];
  notes: string[];
}

/**
 * Builds a message-transition graph from the chronological message sequence.
 *
 * This is a first-order graph, not a protocol grammar: it says which message types were
 * followed by which, which is enough to spot handshakes and to seed a replay.
 */
export function buildStateGraph(messages: MessageRecord[], fields: Field[]): StateGraph {
  const ordered = [...messages].sort((a, b) => a.ts - b.ts);
  const counts = new Map<string, number>();
  const edges = new Map<string, Transition>();
  const start: string[] = [];
  const notes: string[] = [];

  if (ordered.length === 0) {
    return { nodes: [], transitions: [], start: [], notes: ['no messages were recovered'] };
  }

  for (const message of ordered) counts.set(message.label, (counts.get(message.label) ?? 0) + 1);

  for (let i = 1; i < ordered.length; i++) {
    const from = ordered[i - 1]!.label;
    const to = ordered[i]!.label;
    const key = `${from}\u0000${to}`;
    const existing = edges.get(key);
    if (existing) existing.count++;
    else edges.set(key, { from, to, count: 1 });
  }

  for (const direction of ['forward', 'reverse'] as const) {
    const first = ordered.find((m) => m.direction === direction);
    if (first) start.push(first.label);
  }

  const opcodeField = fields.find((f) => f.role === 'opcode');
  if (opcodeField) {
    notes.push(`labels come from the ${opcodeField.name} field; messages with the same label produced the same field value`);
  } else {
    notes.push('no message-type field was found, so labels fall back to direction plus length bucket');
  }
  if (ordered.length < 8) notes.push('fewer than eight messages: transition counts are anecdotal');

  const nodes = [...counts.entries()]
    .map(([label, count]) => ({ id: slug(label), label, count }))
    .sort((a, b) => b.count - a.count);

  return { nodes, transitions: [...edges.values()].sort((a, b) => b.count - a.count), start, notes };
}

/** Stable label for a message: its type field when available, otherwise direction and size. */
export function labelMessage(message: Buffer, direction: 'forward' | 'reverse', fields: Field[]): string {
  const opcode = fields.find((f) => f.role === 'opcode');
  if (opcode) {
    const value = fieldValue(message, opcode);
    if (typeof value === 'number') return `type=0x${value.toString(16).padStart(opcode.length * 2, '0')}`;
  }
  const text = fields.find((f) => f.role === 'text');
  if (text) {
    const value = fieldValue(message, text);
    if (typeof value === 'string') {
      const word = value.trim().split(/\s+/)[0];
      if (word) return `verb=${word.slice(0, 12)}`;
    }
  }
  const arrow = direction === 'forward' ? 'fwd' : 'rev';
  return `${arrow}:${bucket(message.length)}B`;
}

function bucket(length: number): number {
  if (length <= 16) return 16;
  if (length <= 32) return 32;
  if (length <= 64) return 64;
  if (length <= 128) return 128;
  return 256;
}

export function slug(label: string): string {
  return label.replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_|_$/g, '').toLowerCase();
}

export function toMermaid(graph: StateGraph, title = 'message flow'): string {
  const lines: string[] = ['```mermaid', 'flowchart LR'];
  for (const node of graph.nodes) {
    lines.push(`  ${node.id}["${node.label} · ${node.count}"]`);
  }
  for (const transition of graph.transitions) {
    const from = slug(transition.from);
    const to = slug(transition.to);
    lines.push(`  ${from} -->|${transition.count}| ${to}`);
  }
  lines.push('```');
  return `### ${title}\n\n${lines.join('\n')}\n`;
}

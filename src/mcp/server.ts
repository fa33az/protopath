#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { analyzeFile, VERSION, type CaptureAnalysis, type FlowAnalysis } from '../core/pipeline.js';
import { renderJson, renderJsonl, renderReport } from '../core/report.js';
import { emitClient } from '../core/emit/client.js';
import { emitDissector } from '../core/emit/dissector.js';
import { emitFuzzer } from '../core/emit/fuzz.js';
import { diffCaptures } from '../core/diff.js';
import { buildFlows } from '../core/net/flows.js';
import { loadCapture } from '../core/pipeline.js';

const server = new McpServer({
  name: 'protopath',
  version: VERSION,
});

function text(value: string) {
  return { content: [{ type: 'text' as const, text: value }] };
}

function pickFlow(analysis: CaptureAnalysis, flowKey: string | undefined): FlowAnalysis {
  const flow = flowKey ? analysis.flows.find((candidate) => candidate.flow.key === flowKey) : analysis.flows[0];
  if (!flow) {
    const available = analysis.flows.map((candidate) => candidate.flow.key).join('\n') || '(none)';
    throw new Error(`flow not found. Analysed flows:\n${available}`);
  }
  return flow;
}

server.registerTool(
  'list_flows',
  {
    title: 'List conversations in a capture',
    description:
      'Lists every TCP and UDP conversation with byte counts, capture gaps and retransmissions. Use the returned key with the other tools.',
    inputSchema: {
      capture: z.string().describe('Absolute path to a pcap or pcapng file'),
    },
  },
  async ({ capture }) => {
    const loaded = loadCapture(capture);
    const flows = buildFlows(loaded.frames);
    const lines = [`${loaded.path} — ${loaded.format}, ${loaded.frames.length} frames with payload, ${loaded.skipped} skipped`, ''];

    if (flows.length === 0) return text(`${lines.join('\n')}no TCP or UDP payload found`);

    for (const flow of flows) {
      const gaps = flow.forward.gaps.length + flow.reverse.gaps.length;
      const retransmits = flow.forward.retransmits + flow.reverse.retransmits;
      lines.push(
        `- ${flow.key}\n  packets=${flow.frames.length} forward=${flow.forward.data.length}B reverse=${flow.reverse.data.length}B gaps=${gaps} retransmits=${retransmits}`,
      );
    }
    return text(lines.join('\n'));
  },
);

server.registerTool(
  'analyze_capture',
  {
    title: 'Infer protocol structure',
    description:
      'Infers framing, field layout, counters and checksums for the strongest flows in a capture. Every finding is returned with the evidence behind it and the case it cannot rule out.',
    inputSchema: {
      capture: z.string().describe('Absolute path to a pcap or pcapng file'),
      flow: z.string().optional().describe('Exact flow key from list_flows'),
      maxFlows: z.number().int().min(1).max(32).optional().describe('How many flows to analyse, default 4'),
      format: z.enum(['markdown', 'json']).optional(),
    },
  },
  async ({ capture, flow, maxFlows, format }) => {
    const analysis = analyzeFile(capture, {
      ...(flow ? { flow } : {}),
      ...(maxFlows ? { maxFlows } : {}),
    });
    return text(format === 'json' ? renderJson(analysis) : renderReport(analysis));
  },
);

server.registerTool(
  'infer_fields',
  {
    title: 'Field layout for one direction',
    description:
      'Returns the field table for one direction of one flow: offsets, widths, roles, confidence, and why each boundary was placed where it is.',
    inputSchema: {
      capture: z.string().describe('Absolute path to a pcap or pcapng file'),
      flow: z.string().optional().describe('Exact flow key from list_flows'),
      direction: z.enum(['forward', 'reverse', 'primary']).optional(),
    },
  },
  async ({ capture, flow, direction }) => {
    const analysis = analyzeFile(capture, flow ? { flow } : {});
    const selected = pickFlow(analysis, flow);
    const wanted =
      direction === 'forward'
        ? selected.forward
        : direction === 'reverse'
          ? selected.reverse
          : selected.primary === 'forward'
            ? selected.forward
            : selected.reverse;

    const lines = [`${wanted.label} — ${wanted.bytes} bytes, ${wanted.messageCount} messages`];
    if (!wanted.best) return text([...lines, '', 'no confident framing for this direction'].join('\n'));

    lines.push(`framing: ${wanted.best.kind} (score ${wanted.best.score.toFixed(2)})`, '');
    for (const field of wanted.fields) {
      const width = field.length < 0 ? 'var' : `${field.length}B`;
      const anchor = field.anchor === 'tail' ? `end-${field.offset + field.length}` : `@${field.offset}`;
      lines.push(`${field.name.padEnd(24)} ${field.role.padEnd(10)} ${anchor.padEnd(8)} ${width.padEnd(5)} confidence=${field.confidence.toFixed(2)}`);
      for (const item of field.evidence) lines.push(`  ${item}`);
    }
    for (const item of [...wanted.notes, ...wanted.limitations]) lines.push(`note: ${item}`);
    return text(lines.join('\n'));
  },
);

server.registerTool(
  'detect_checksums',
  {
    title: 'Find a checksum field',
    description:
      'Searches standard checksums (crc8, crc16 variants, crc32, sums, xor) against every message. Returns only candidates that match every message, with the covered byte range.',
    inputSchema: {
      capture: z.string().describe('Absolute path to a pcap or pcapng file'),
      flow: z.string().optional().describe('Exact flow key from list_flows'),
    },
  },
  async ({ capture, flow }) => {
    const analysis = analyzeFile(capture, flow ? { flow } : {});
    const selected = pickFlow(analysis, flow);
    const direction = selected.primary === 'forward' ? selected.forward : selected.reverse;

    if (direction.checksums.length === 0) {
      return text(`no checksum matched all ${direction.messageCount} messages in ${direction.label}`);
    }

    const lines = [`${direction.label} — ${direction.checksums[0]!.matches}/${direction.checksums[0]!.total} messages agree on the top candidate`, ''];
    for (const checksum of direction.checksums.slice(0, 6)) {
      lines.push(
        `${checksum.algorithm.padEnd(18)} width=${checksum.width} end=${checksum.endian} position=len-${checksum.offsetFromEnd + checksum.width} agreement=${checksum.matches}/${checksum.total}`,
      );
      lines.push(`  ${checksum.evidence}`);
    }
    return text(lines.join('\n'));
  },
);

server.registerTool(
  'emit_artifacts',
  {
    title: 'Write dissector, clients and report',
    description:
      'Writes a Wireshark Lua dissector, TypeScript and Python clients, a mutation harness, a markdown report and a JSONL message dump for the primary flow.',
    inputSchema: {
      capture: z.string().describe('Absolute path to a pcap or pcapng file'),
      out: z.string().describe('Directory to write into'),
      flow: z.string().optional().describe('Exact flow key from list_flows'),
      targets: z
        .array(z.enum(['lua', 'ts', 'python', 'fuzz', 'report']))
        .optional()
        .describe('Subset of artifacts to write; default all'),
    },
  },
  async ({ capture, out, flow, targets }) => {
    const analysis = analyzeFile(capture, flow ? { flow } : {});
    const primary = pickFlow(analysis, flow);
    const wanted = new Set(targets ?? ['lua', 'ts', 'python', 'fuzz', 'report']);
    const port = primary.primary === 'forward' ? primary.flow.b.port : primary.flow.a.port;

    mkdirSync(out, { recursive: true });
    const written: string[] = [];
    const write = (name: string, content: string): void => {
      const target = join(out, name);
      writeFileSync(target, content, 'utf8');
      written.push(target);
    };

    if (wanted.has('lua')) write('dissector.lua', emitDissector(primary, { port }));
    if (wanted.has('ts')) write('client.ts', emitClient(primary, 'ts'));
    if (wanted.has('python')) write('client.py', emitClient(primary, 'python'));
    if (wanted.has('fuzz')) write('fuzz.py', emitFuzzer(primary));
    if (wanted.has('report')) {
      write('report.md', renderReport(analysis));
      write('analysis.json', renderJson(analysis));
      write('messages.jsonl', renderJsonl(primary));
    }

    return text([`flow: ${primary.flow.key}`, `port: ${port}`, '', ...written].join('\n'));
  },
);

server.registerTool(
  'diff_captures',
  {
    title: 'Compare two inferred layouts',
    description:
      'Pairs flows between two captures and reports framing changes, moved fields, and fields that stopped varying. This is the check for a protocol revision breaking an existing client.',
    inputSchema: {
      before: z.string().describe('Capture from the older protocol version'),
      after: z.string().describe('Capture from the newer protocol version'),
    },
  },
  async ({ before, after }) => {
    const report = diffCaptures(analyzeFile(before), analyzeFile(after));
    const lines: string[] = [];
    for (const flow of report.flows) {
      lines.push(`flow ${flow.key}`);
      lines.push(`  framing: ${flow.framingBefore} -> ${flow.framingAfter}`);
      lines.push(`  verdict: ${flow.verdict}`);
      for (const field of flow.fields) {
        if (field.status === 'same') continue;
        lines.push(`  ${field.status} ${field.name}${field.detail.length > 0 ? `: ${field.detail.join('; ')}` : ''}`);
      }
      lines.push('');
    }
    for (const note of report.notes) lines.push(`note: ${note}`);
    return text(lines.join('\n'));
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);

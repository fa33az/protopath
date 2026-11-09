#!/usr/bin/env node
import { mkdirSync, writeFileSync, existsSync, readFileSync, copyFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { analyzeFile, loadCapture, VERSION, type CaptureAnalysis, type FlowAnalysis } from '../core/pipeline.js';
import { buildFlows } from '../core/net/flows.js';
import { renderJson, renderJsonl, renderReport } from '../core/report.js';
import { emitDissector } from '../core/emit/dissector.js';
import { emitClient } from '../core/emit/client.js';
import { emitFuzzer } from '../core/emit/fuzz.js';
import { diffCaptures } from '../core/diff.js';
import { flagBool, flagNumber, flagString, parseArgs } from './args.js';

const HELP = `protopath ${VERSION} — infer protocol structure from a capture

usage
  protopath flows  <capture>                  list conversations in a capture
  protopath analyze <capture>                 infer framing, fields and checksums
  protopath emit   <capture> [--out <dir>]    write dissector, clients, fuzzer and report
  protopath diff   <captureA> <captureB>      compare two inferred layouts
  protopath setup  [--yes]                    register the MCP server with an agent

flags
  --flow <key>        restrict analysis to one flow (exact key from "protopath flows")
  --max-flows <n>     how many flows to analyse, default 4
  --out <dir>         output directory for emit, default out/<port>
  --port <n>          port the generated Lua dissector binds to
  --json              machine-readable output on stdout
  --targets <list>    emit subset of lua,ts,python,fuzz,report
  --yes               setup: write the project .mcp.json instead of printing only
  --help, --version

exit codes
  0  analysis complete with a confident framing hypothesis
  1  error (bad capture, unknown flow, unwritable output)
  3  analysis ran but no hypothesis cleared the confidence threshold

captures: classic pcap (us, ns) and pcapng, with Ethernet, raw IP, Linux SLL,
IPv4 and IPv6. TLS is not decrypted; feed decrypted payloads instead.`;

function main(argv: string[]): number {
  const args = parseArgs(argv);

  if (args.flags.has('help') || args.command === 'help') {
    console.log(HELP);
    return 0;
  }
  if (args.command === '') {
    console.log(HELP);
    return 1;
  }
  if (args.flags.has('version')) {
    console.log(VERSION);
    return 0;
  }

  switch (args.command) {
    case 'flows':
      return commandFlows(args.positional[0], args.flags);
    case 'analyze':
      return commandAnalyze(args.positional[0], args.flags);
    case 'emit':
      return commandEmit(args.positional[0], args.flags);
    case 'diff':
      return commandDiff(args.positional[0], args.positional[1], args.flags);
    case 'setup':
      return commandSetup(args.flags);
    default:
      console.error(`unknown command "${args.command}"\n\n${HELP}`);
      return 1;
  }
}

function requireCapture(path: string | undefined): string {
  if (!path) throw new Error('a capture path is required');
  return path;
}

function commandFlows(path: string | undefined, flags: Map<string, string | true>): number {
  const capture = loadCapture(requireCapture(path));
  const flows = buildFlows(capture.frames);

  if (flagBool(flags, 'json')) {
    console.log(
      JSON.stringify(
        {
          capture: { path: capture.path, format: capture.format, frames: capture.frames.length, skipped: capture.skipped },
          flows: flows.map((flow) => ({
            key: flow.key,
            transport: flow.transport,
            packets: flow.frames.length,
            forwardBytes: flow.forward.data.length,
            reverseBytes: flow.reverse.data.length,
            gaps: flow.forward.gaps.length + flow.reverse.gaps.length,
            retransmits: flow.forward.retransmits + flow.reverse.retransmits,
          })),
        },
        null,
        2,
      ),
    );
    return 0;
  }

  console.log(`${capture.path} — ${capture.format}, ${capture.frames.length} frames with payload, ${capture.skipped} skipped`);
  if (flows.length === 0) {
    console.log('no TCP or UDP payload found');
    return 1;
  }
  console.log('');
  const rows = flows.map((flow) => [
    flow.key,
    String(flow.frames.length),
    String(flow.forward.data.length),
    String(flow.reverse.data.length),
    String(flow.forward.gaps.length + flow.reverse.gaps.length),
  ]);
  printTable(['flow', 'packets', '→ bytes', '← bytes', 'gaps'], rows);
  return 0;
}

function commandAnalyze(path: string | undefined, flags: Map<string, string | true>): number {
  const analysis = analyzeFile(requireCapture(path), analysisOptions(flags));

  if (flagBool(flags, 'json')) {
    console.log(renderJson(analysis));
  } else {
    console.log(renderReport(analysis));
  }

  const out = flagString(flags, 'out');
  if (out) {
    mkdirSync(out, { recursive: true });
    const reportPath = join(out, 'report.md');
    const jsonPath = join(out, 'analysis.json');
    writeFileSync(reportPath, renderReport(analysis), 'utf8');
    writeFileSync(jsonPath, renderJson(analysis), 'utf8');
    console.error(`wrote ${reportPath}`);
    console.error(`wrote ${jsonPath}`);
  }

  return confident(analysis) ? 0 : 3;
}

function commandEmit(path: string | undefined, flags: Map<string, string | true>): number {
  const analysis = analyzeFile(requireCapture(path), analysisOptions(flags));
  const primary = analysis.flows[0];

  if (!primary) {
    console.error('no flow to describe');
    return 1;
  }

  const out = flagString(flags, 'out') ?? join('out', String(serverPort(primary)));
  mkdirSync(out, { recursive: true });
  const targets = (flagString(flags, 'targets') ?? 'lua,ts,python,fuzz,report').split(',').map((t) => t.trim());
  const port = flagNumber(flags, 'port') ?? serverPort(primary);
  const written: string[] = [];

  const write = (name: string, content: string): void => {
    const target = join(out, name);
    writeFileSync(target, content, 'utf8');
    written.push(target);
  };

  if (targets.includes('lua')) write('dissector.lua', emitDissector(primary, { port }));
  if (targets.includes('ts')) write('client.ts', emitClient(primary, 'ts'));
  if (targets.includes('python')) write('client.py', emitClient(primary, 'python'));
  if (targets.includes('fuzz')) write('fuzz.py', emitFuzzer(primary));
  if (targets.includes('report')) {
    write('report.md', renderReport(analysis));
    write('analysis.json', renderJson(analysis));
    write('messages.jsonl', renderJsonl(primary));
  }

  for (const file of written) console.log(file);
  console.error(`\nprimary flow: ${primary.flow.key}`);
  console.error(`framing: ${describePrimary(primary)}`);
  return confident(analysis) ? 0 : 3;
}

function commandDiff(a: string | undefined, b: string | undefined, flags: Map<string, string | true>): number {
  const before = analyzeFile(requireCapture(a));
  const after = analyzeFile(requireCapture(b));
  const report = diffCaptures(before, after);

  if (flagBool(flags, 'json')) {
    console.log(JSON.stringify(report, null, 2));
    return 0;
  }

  for (const flow of report.flows) {
    console.log(`flow ${flow.key}`);
    console.log(`  framing: ${flow.framingBefore} -> ${flow.framingAfter}`);
    console.log(`  verdict: ${flow.verdict}`);
    for (const field of flow.fields) {
      if (field.status === 'same') continue;
      console.log(`  ${field.status.padEnd(8)} ${field.name}${field.detail.length > 0 ? ` — ${field.detail.join('; ')}` : ''}`);
    }
    console.log('');
  }
  for (const note of report.notes) console.log(`note: ${note}`);
  return 0;
}

function commandSetup(flags: Map<string, string | true>): number {
  const entry = resolve(join(dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', 'mcp', 'server.js'));
  const snippet = {
    mcpServers: {
      protopath: {
        command: 'node',
        args: [entry],
      },
    },
  };

  console.log('MCP registration for protopath:\n');
  console.log(JSON.stringify(snippet, null, 2));
  console.log('\nClaude Code:  claude mcp add --scope project protopath node ' + entry);
  console.log('Cursor:       add the snippet above to .cursor/mcp.json');
  console.log('Codex:        add the snippet above to ~/.codex/config.toml as [mcp_servers.protopath]');
  console.log('Other:        use the same command and args in your client config');

  if (!flagBool(flags, 'yes')) {
    console.log('\nnothing was written. re-run with --yes to create .mcp.json in this directory.');
    return 0;
  }

  const target = resolve('.mcp.json');
  if (existsSync(target)) {
    const backup = `${target}.bak`;
    copyFileSync(target, backup);
    const existing = JSON.parse(readFileSync(target, 'utf8')) as { mcpServers?: Record<string, unknown> };
    existing.mcpServers = { ...(existing.mcpServers ?? {}), ...snippet.mcpServers };
    writeFileSync(target, JSON.stringify(existing, null, 2) + '\n', 'utf8');
    console.log(`\nupdated ${target} (backup at ${backup})`);
  } else {
    writeFileSync(target, JSON.stringify(snippet, null, 2) + '\n', 'utf8');
    console.log(`\nwrote ${target}`);
  }
  return 0;
}

function analysisOptions(flags: Map<string, string | true>) {
  const flow = flagString(flags, 'flow');
  const maxFlows = flagNumber(flags, 'max-flows');
  return { ...(flow ? { flow } : {}), ...(maxFlows ? { maxFlows } : {}) };
}

function confident(analysis: CaptureAnalysis): boolean {
  const best = analysis.flows[0];
  if (!best) return false;
  const direction = best.primary === 'forward' ? best.forward : best.reverse;
  return (direction.best?.score ?? 0) >= 0.6;
}

function serverPort(analysis: FlowAnalysis): number {
  return analysis.primary === 'forward' ? analysis.flow.b.port : analysis.flow.a.port;
}

function describePrimary(analysis: FlowAnalysis): string {
  const direction = analysis.primary === 'forward' ? analysis.forward : analysis.reverse;
  const best = direction.best;
  if (!best) return 'none';
  if (best.lengthPrefix) {
    const spec = best.lengthPrefix;
    return `length-prefix, ${spec.size}-byte ${spec.endian} field at offset ${spec.lenOffset}, bias ${spec.bias}, score ${best.score.toFixed(2)}`;
  }
  if (best.startMarker) return `start-marker 0x${best.startMarker.marker.toString('hex')}, score ${best.score.toFixed(2)}`;
  if (best.delimiter) return `delimiter 0x${best.delimiter.terminator.toString('hex')}, score ${best.score.toFixed(2)}`;
  if (best.fixed) return `fixed ${best.fixed.size} bytes, score ${best.score.toFixed(2)}`;
  return 'unframed';
}

function printTable(headers: string[], rows: string[][]): void {
  const widths = headers.map((header, i) => Math.max(header.length, ...rows.map((row) => (row[i] ?? '').length)));
  const line = (cells: string[]): string => cells.map((cell, i) => cell.padEnd(widths[i]!)).join('  ');
  console.log(line(headers));
  console.log(widths.map((width) => '-'.repeat(width)).join('  '));
  for (const row of rows) console.log(line(row));
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`protopath: ${message}`);
  process.exitCode = 1;
}

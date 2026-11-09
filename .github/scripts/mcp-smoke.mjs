#!/usr/bin/env node
// Drives the MCP server over stdio the way a client would: handshake, tool listing, one real
// tool call. Run from the repository root after `npm run build`.
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';

const TIMEOUT_MS = 30_000;
const child = spawn(process.execPath, ['dist/mcp/server.js'], { stdio: ['pipe', 'pipe', 'inherit'] });

const pending = new Map();
let buffer = '';
let nextId = 1;

child.stdout.on('data', (chunk) => {
  buffer += chunk.toString('utf8');
  const lines = buffer.split('\n');
  buffer = lines.pop() ?? '';
  for (const line of lines) {
    if (!line.trim()) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      continue;
    }
    const waiter = pending.get(message.id);
    if (!waiter) continue;
    pending.delete(message.id);
    waiter(message);
  }
});

function request(method, params) {
  const id = nextId++;
  return new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error(`${method} timed out`)), TIMEOUT_MS);
    pending.set(id, (message) => {
      clearTimeout(timer);
      if (message.error) reject(new Error(`${method} failed: ${JSON.stringify(message.error)}`));
      else resolvePromise(message.result);
    });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}

function notify(method, params) {
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
}

function fail(message) {
  console.error(`mcp smoke test failed: ${message}`);
  child.kill();
  process.exit(1);
}

try {
  const init = await request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'protopath-ci', version: '1' },
  });
  notify('notifications/initialized');

  if (init.serverInfo?.name !== 'protopath') fail(`unexpected server name ${init.serverInfo?.name}`);

  const tools = await request('tools/list', {});
  const names = (tools.tools ?? []).map((tool) => tool.name).sort();
  const expected = [
    'analyze_capture',
    'detect_checksums',
    'diff_captures',
    'emit_artifacts',
    'explain_semantics',
    'infer_fields',
    'list_flows',
    'recover_checksum_parameters',
    'trace_conversation',
  ];
  if (JSON.stringify(names) !== JSON.stringify(expected)) fail(`tool list was ${names.join(', ')}`);

  const call = await request('tools/call', {
    name: 'list_flows',
    arguments: { capture: resolve('captures/binary-session.pcap') },
  });
  const text = call.content?.[0]?.text ?? '';
  if (!text.includes('7401')) fail(`list_flows output did not mention the server port:\n${text}`);
  if (!text.includes('10.0.0.10')) fail(`list_flows output did not mention the client:\n${text}`);

  const analysis = await request('tools/call', {
    name: 'detect_checksums',
    arguments: { capture: resolve('captures/binary-session.pcap') },
  });
  const analysisText = analysis.content?.[0]?.text ?? '';
  if (!analysisText.includes('crc16/modbus')) fail(`checksum detection regressed:\n${analysisText}`);

  const recovery = await request('tools/call', {
    name: 'recover_checksum_parameters',
    arguments: { capture: resolve('captures/custom-crc.pcap') },
  });
  const recoveryText = recovery.content?.[0]?.text ?? '';
  if (!recoveryText.includes('0x8f57')) fail(`CRC parameter recovery regressed:\n${recoveryText}`);

  const semantics = await request('tools/call', {
    name: 'explain_semantics',
    arguments: { capture: resolve('captures/text-session.pcap') },
  });
  const semanticsText = semantics.content?.[0]?.text ?? '';
  if (!semanticsText.includes('PING')) fail(`payload semantics regressed:\n${semanticsText}`);

  const trace = await request('tools/call', {
    name: 'trace_conversation',
    arguments: { capture: resolve('captures/modbus-session.pcap') },
  });
  const traceText = trace.content?.[0]?.text ?? '';
  if (!traceText.includes('type=0x84')) fail(`conversation pairing regressed:\n${traceText}`);

  console.log('mcp smoke test passed: handshake, 9 tools, and five tool calls answered');
  child.kill();
  process.exit(0);
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}

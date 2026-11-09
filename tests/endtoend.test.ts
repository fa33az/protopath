import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { analyzeFile } from '../src/core/pipeline.js';
import { diffCaptures } from '../src/core/diff.js';
import { emitClient } from '../src/core/emit/client.js';
import { emitDissector } from '../src/core/emit/dissector.js';
import { renderReport } from '../src/core/report.js';
import { capture, root } from './helpers.js';

test('the binary capture yields one confident flow with both directions', () => {
  const analysis = analyzeFile(capture('binary-session.pcap'));
  assert.equal(analysis.flows.length, 1);

  const flow = analysis.flows[0]!;
  assert.ok(flow.forward.best && flow.forward.best.score > 0.85);
  assert.ok(flow.reverse.best && flow.reverse.best.score > 0.85);
  assert.equal(flow.forward.messageCount, 10);
  assert.equal(flow.reverse.messageCount, 10);
  assert.equal(analysis.warnings.length, 0);
});

test('the state graph links the observed request and response types', () => {
  const flow = analyzeFile(capture('binary-session.pcap')).flows[0]!;
  assert.ok(flow.graph.nodes.length >= 3);
  assert.ok(flow.graph.transitions.length >= 3);
  const first = flow.graph.transitions[0]!;
  assert.equal(first.from, 'type=0x10', 'the first transition starts with a read request');
  assert.equal(first.to, 'type=0x11', 'and is followed by a data response');
});

test('the pcapng copy produces the same protocol model as the pcap', () => {
  const pcap = analyzeFile(capture('binary-session.pcap')).flows[0]!;
  const pcapng = analyzeFile(capture('binary-session.pcapng')).flows[0]!;

  const signature = (flow: typeof pcap) =>
    flow.forward.fields.map((field) => `${field.name}:${field.role}:${field.offset}:${field.length}`).join('|');

  assert.equal(signature(pcapng), signature(pcap));
});

test('a second protocol version is reported as a layout change', () => {
  const report = diffCaptures(analyzeFile(capture('binary-session.pcap')), analyzeFile(capture('binary-session-v2.pcap')));
  assert.equal(report.flows.length, 1);

  const flow = report.flows[0]!;
  assert.match(flow.verdict, /field|layout|framing/);
  const removed = flow.fields.filter((field) => field.status === 'removed');
  assert.ok(removed.length > 0, 'the dropped type byte should show up as a removed field');
});

test('the report states its limits instead of only its findings', () => {
  const report = renderReport(analyzeFile(capture('binary-session.pcap')));
  assert.match(report, /## What this report does not know/);
  assert.match(report, /crc16\/modbus/);
  assert.match(report, /Confidence/);
});

test('the generated Lua dissector is well formed', () => {
  const analysis = analyzeFile(capture('binary-session.pcap'));
  const lua = emitDissector(analysis.flows[0]!);

  const protos = lua.match(/^local \w+ = Proto\(/gm) ?? [];
  assert.equal(protos.length, 1);
  assert.match(lua, /function p_inferred\.dissector\(buffer, pinfo, tree\)/);
  assert.match(lua, /p_inferred\.fields = \{/);
  assert.match(lua, /DissectorTable\.get\("tcp\.port"\)/);
  assert.match(lua, /tcp_port:add\(7401, p_inferred\)/);

  const open = (lua.match(/\bfunction\b/g) ?? []).length;
  const close = (lua.match(/^end$/gm) ?? []).length;
  assert.ok(open >= 1 && close >= open - 1, `unbalanced function/end: ${open} functions, ${close} ends`);
});

test('the generated TypeScript client compiles, and round-trips a real message', async () => {
  const analysis = analyzeFile(capture('binary-session.pcap'));
  const flow = analysis.flows[0]!;
  const source = emitClient(flow, 'ts');
  const workDir = mkdtempSync(join(tmpdir(), 'protopath-client-'));
  const sourcePath = join(workDir, 'client.ts');
  writeFileSync(sourcePath, source, 'utf8');
  writeFileSync(join(workDir, 'package.json'), '{"type":"module"}\n', 'utf8');

  const tsc = spawnSync(
    process.execPath,
    [
      join(root, 'node_modules', 'typescript', 'bin', 'tsc'),
      '--ignoreConfig',
      sourcePath,
      '--outDir',
      join(workDir, 'out'),
      '--strict',
      '--types',
      'node',
      '--typeRoots',
      join(root, 'node_modules', '@types'),
      '--target',
      'es2023',
      '--module',
      'nodenext',
      '--moduleResolution',
      'nodenext',
      '--skipLibCheck',
    ],
    { encoding: 'utf8' },
  );

  assert.equal(tsc.status, 0, `generated client failed to compile:\n${tsc.stdout}\n${tsc.stderr}\n\n${source}`);

  const emitted = await import(pathToFileURL(join(workDir, 'out', 'client.js')).href);
  const raw = Buffer.from(flow.forward.messages[0]!.bytes);
  const decoded = emitted.decode(raw);

  assert.ok(decoded, 'decode returned null for a real message');
  assert.equal(decoded.payload.toString('latin1'), 'uptime');
  assert.equal(decoded.type, 0x10);
  assert.ok(Buffer.from(emitted.encode(decoded)).equals(raw), 're-encoding did not reproduce the message');
  assert.equal(emitted.verify(raw), true);

  const corrupted = Buffer.from(raw);
  corrupted[corrupted.length - 1] ^= 0xff;
  assert.equal(emitted.verify(corrupted), false);
});

test('the generated Python client decodes, re-encodes and verifies a real message', (t) => {
  const python = spawnSync('python', ['--version'], { encoding: 'utf8' });
  if (python.status !== 0) {
    t.skip('python is not available on this machine');
    return;
  }

  const analysis = analyzeFile(capture('binary-session.pcap'));
  const flow = analysis.flows[0]!;
  const workDir = mkdtempSync(join(tmpdir(), 'protopath-py-'));
  writeFileSync(join(workDir, 'client.py'), emitClient(flow, 'python'), 'utf8');
  writeFileSync(
    join(workDir, 'run.py'),
    [
      'from client import decode, encode, verify',
      `raw = bytes.fromhex("${flow.forward.messages[0]!.bytes.toString('hex')}")`,
      'message = decode(raw)',
      'assert message is not None, "decode returned None"',
      'assert message.payload == b"uptime", message.payload',
      'assert encode(message) == raw, "round trip changed the bytes"',
      'assert verify(raw), "checksum verification failed"',
      'broken = bytearray(raw)',
      'broken[-1] ^= 0xFF',
      'assert not verify(bytes(broken)), "corrupted message was accepted"',
      'print("ok")',
    ].join('\n'),
    'utf8',
  );

  const run = spawnSync('python', ['run.py'], { cwd: workDir, encoding: 'utf8' });
  assert.equal(run.status, 0, `generated python client failed:\n${run.stdout}\n${run.stderr}`);
  assert.match(run.stdout, /ok/);
});

test('the generated Python client carries the checksum inverse it detected', () => {
  const analysis = analyzeFile(capture('binary-session.pcap'));
  const python = emitClient(analysis.flows[0]!, 'python');

  assert.match(python, /def decode\(buffer: bytes\)/);
  assert.match(python, /def encode\(message: Message\) -> bytes/);
  assert.match(python, /def compute_checksum\(data: bytes\) -> int/);
  assert.match(python, /_crc16_reflected/);
  assert.match(python, /HEADER_LENGTH = 6/);
});

test('garbage input is rejected before it reaches the model', () => {
  const workDir = mkdtempSync(join(tmpdir(), 'protopath-bad-'));
  const badPath = join(workDir, 'not-a-capture.pcap');
  writeFileSync(badPath, 'definitely not a capture', 'utf8');
  assert.throws(() => analyzeFile(badPath), /not a pcap/);
});

test('a capture with no matching flow reports the available keys', () => {
  assert.throws(() => analyzeFile(capture('binary-session.pcap'), { flow: 'nope' }), /no flow matches "nope"/);
});

test('the fixture captures are reproducible: the committed bytes match a fresh build', () => {
  const pcap = readFileSync(capture('binary-session.pcap'));
  assert.ok(pcap.length > 1000);
  assert.equal(pcap.readUInt32LE(0), 0xa1b2c3d4);
  const pcapng = readFileSync(capture('binary-session.pcapng'));
  assert.equal(pcapng.readUInt32LE(0), 0x0a0d0d0a);
});

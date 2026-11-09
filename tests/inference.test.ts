import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { analyzeFile } from '../src/core/pipeline.js';
import { ALGORITHMS, crcCompute } from '../src/core/infer/checksum.js';
import { recoverCrc } from '../src/core/infer/crc-recovery.js';
import { inferSemantics } from '../src/core/infer/semantics.js';
import { inferGrammar } from '../src/core/infer/grammar.js';
import { emitClient } from '../src/core/emit/client.js';
import { renderReport } from '../src/core/report.js';
import type { MessageRecord } from '../src/core/infer/state.js';
import { capture, root } from './helpers.js';

/**
 * The layers above framing: what the check field is, what the values mean, who answered whom,
 * and which published protocol the whole thing matches.
 */

test('the checksum catalogue reproduces the published check values', () => {
  // "123456789" is the check string every CRC catalogue is quoted against.
  const check = Buffer.from('123456789');
  const expected: Record<string, number> = {
    crc8: 0xf4,
    'crc8/rohc': 0xd0,
    'crc8/maxim': 0xa1,
    'crc8/sae-j1850': 0x4b,
    'crc16/ccitt-false': 0x29b1,
    'crc16/xmodem': 0x31c3,
    'crc16/kermit': 0x2189,
    'crc16/x25': 0x906e,
    'crc16/modbus': 0x4b37,
    'crc16/arc': 0xbb3d,
    'crc16/dnp': 0xea82,
    'crc32/ieee': 0xcbf43926,
    'crc32/c': 0xe3069283,
  };

  for (const [name, value] of Object.entries(expected)) {
    const algorithm = ALGORITHMS.find((entry) => entry.name === name);
    assert.ok(algorithm, `${name} is missing from the catalogue`);
    assert.equal(algorithm.compute(check), value, `${name} produced 0x${algorithm.compute(check).toString(16)}`);
  }
});

/** Builds messages with a chosen CRC parameter set, checksum last, little endian. */
function framesWithCrc(options: { poly: number; init: number; refin: boolean; xorout: number; lengths: number[] }): Buffer[] {
  return options.lengths.map((length, index) => {
    const body = Buffer.alloc(length);
    for (let i = 0; i < length; i++) body[i] = (index * 37 + i * 11 + 5) & 0xff;
    body[0] = 0x40 + index; // make every message distinguishable
    const crc = crcCompute(body, {
      width: 16,
      poly: options.poly,
      init: options.init,
      refin: options.refin,
      refout: options.refin,
      xorout: options.xorout,
    });
    const tail = Buffer.alloc(2);
    tail.writeUInt16LE(crc, 0);
    return Buffer.concat([body, tail]);
  });
}

test('a CRC with a private polynomial and a private initial value is solved from the data', () => {
  // Neither the polynomial nor the init appears in any catalogue.
  const messages = framesWithCrc({
    poly: 0x8f57,
    init: 0x1234,
    refin: true,
    xorout: 0,
    lengths: [8, 9, 8, 11, 12, 9, 14, 10, 8],
  });

  const [recovered] = recoverCrc(messages);
  assert.ok(recovered, 'nothing was recovered');

  assert.equal(recovered.params.poly, 0x8f57);
  assert.equal(recovered.params.init, 0x1234);
  assert.equal(recovered.params.refin, true);
  assert.equal(recovered.params.refout, true);
  assert.equal(recovered.params.xorout, 0);
  assert.equal(recovered.offsetFromEnd, 0);
  assert.equal(recovered.rangeStart, 0);
  assert.equal(recovered.endian, 'le');
  assert.equal(recovered.matches, messages.length);
  assert.equal(recovered.initAmbiguous, false, 'differing message lengths should pin the initial value down');
});

test('the initial value is derived even when the final xor is not zero', () => {
  const messages = framesWithCrc({
    poly: 0x3d65,
    init: 0x0000,
    refin: true,
    xorout: 0x7e5a,
    lengths: [10, 12, 13, 10, 15, 12],
  });

  const [recovered] = recoverCrc(messages);
  assert.ok(recovered, 'nothing was recovered');
  assert.equal(recovered.params.xorout, 0x7e5a);
  assert.equal(recovered.params.poly, 0x3d65);
});

test('a capture that cannot separate init from xorout says so instead of guessing', () => {
  // Every message has the same covered length, so init and xorout cancel each other exactly.
  const messages = framesWithCrc({
    poly: 0x1021,
    init: 0xffff,
    refin: false,
    xorout: 0,
    lengths: [12, 12, 12, 12, 12, 12],
  });

  const [recovered] = recoverCrc(messages);
  assert.ok(recovered, 'the CRC should still be reproducible');
  assert.equal(recovered.initAmbiguous, true);
  assert.ok(
    recovered.limitations.some((limitation) => limitation.includes('cannot separate init from xorout')),
    `limitations were ${recovered.limitations.join(' | ')}`,
  );
});

test('the custom-CRC fixture is recovered exactly from the capture', () => {
  const flow = analyzeFile(capture('custom-crc.pcap')).flows[0]!;
  const recovered = flow.forward.crcRecovery[0];
  assert.ok(recovered, 'no parameter set was recovered from the fixture');

  assert.equal(recovered.params.poly, 0x8f57);
  assert.equal(recovered.params.init, 0x1234);
  assert.equal(recovered.params.refin, true);
  assert.equal(recovered.params.refout, true);
  assert.equal(recovered.params.xorout, 0);
  assert.equal(recovered.reflectedPoly, 0xeaf1);
  assert.equal(recovered.matches, flow.forward.messageCount);

  // The field model has to carry the recovered parameters, not just name them.
  const checksum = flow.forward.fields.find((field) => field.role === 'checksum');
  assert.ok(checksum, 'the recovered checksum was not placed in the field model');
  assert.equal(checksum.spec?.kind, 'crc');
  assert.equal(checksum.algorithm, 'crc16/8f57');
});

test('the generated client embeds the recovered parameters and verifies the fixture', () => {
  const flow = analyzeFile(capture('custom-crc.pcap')).flows[0]!;
  const typescript = emitClient(flow, 'ts');

  assert.match(typescript, /crcCompute\(data, 16, 0x8f57, 0x1234, true, true, 0x0\)/);
  assert.match(typescript, /export function verify\(buffer: Buffer\): boolean/);

  const workDir = mkdtempSync(join(tmpdir(), 'protopath-recovered-'));
  writeFileSync(join(workDir, 'client.ts'), typescript, 'utf8');
  writeFileSync(join(workDir, 'package.json'), '{"type":"module"}\n', 'utf8');
  writeFileSync(
    join(workDir, 'run.mjs'),
    [
      `import { decode, encode, verify } from './out/client.js';`,
      `const raw = Buffer.from('${flow.forward.messages[0]!.bytes.toString('hex')}', 'hex');`,
      'const message = decode(raw);',
      'if (!message) throw new Error("decode returned null");',
      'if (!verify(raw)) throw new Error("checksum verification failed");',
      'if (!encode(message).equals(raw)) throw new Error("round trip changed the bytes");',
      'const broken = Buffer.from(raw);',
      'broken[broken.length - 1] ^= 0xff;',
      'if (verify(broken)) throw new Error("a corrupted message was accepted");',
      'console.log("ok");',
    ].join('\n'),
    'utf8',
  );

  const compile = spawnSync(
    process.execPath,
    [
      join(root, 'node_modules', 'typescript', 'bin', 'tsc'),
      '--ignoreConfig',
      join(workDir, 'client.ts'),
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
    { cwd: workDir, encoding: 'utf8' },
  );
  assert.equal(compile.status, 0, `compiling the generated client failed:\n${compile.stdout}\n${compile.stderr}`);

  const run = spawnSync(process.execPath, ['run.mjs'], { cwd: workDir, encoding: 'utf8' });
  assert.equal(run.status, 0, `the recovered checksum client failed:\n${run.stdout}\n${run.stderr}`);
  assert.match(run.stdout, /ok/);
});

test('field value domains separate a code from a check value from a word', () => {
  const flow = analyzeFile(capture('binary-session.pcap')).flows[0]!;
  const domains = new Map(flow.forward.semantics.domains.map((domain) => [domain.field, domain]));

  assert.equal(domains.get('magic')?.domain, 'constant');
  assert.equal(domains.get('length')?.domain, 'length');
  assert.equal(domains.get('sequence')?.domain, 'counter');
  assert.equal(domains.get('type')?.domain, 'enum');
  assert.equal(domains.get('checksum_crc16_modbus')?.domain, 'opaque');
});

test('a four-byte ASCII field is read as a word, not as a timestamp', () => {
  const flow = analyzeFile(capture('binary-session-v2.pcap')).flows[0]!;
  const header = flow.forward.fields.filter((field) => field.anchor === 'head' && field.role !== 'payload');

  // The v2 fixture puts the key name straight after the sequence number, so it is payload now
  // and the header ends at the sequence field.
  assert.equal(header[header.length - 1]!.role, 'counter');
  assert.ok(
    !flow.forward.semantics.domains.some((domain) => domain.domain === 'timestamp'),
    'a printable field was misread as a timestamp',
  );
});

test('the text fixture yields a vocabulary with a typed argument', () => {
  const flow = analyzeFile(capture('text-session.pcap')).flows[0]!;
  const vocabulary = flow.forward.semantics.payload.vocabulary;
  assert.ok(vocabulary, 'no vocabulary was produced');
  assert.equal(flow.forward.semantics.payload.encoding, 'text');

  const verbs = vocabulary.verbs.map((verb) => verb.value);
  assert.ok(verbs.includes('PING'));
  assert.ok(verbs.includes('GET'));
  assert.ok(verbs.includes('SET'));

  const argument = vocabulary.arguments.find((entry) => entry.position === 1);
  assert.ok(argument, 'no argument column was described');
  assert.equal(argument.kind, 'identifier');
  assert.ok(argument.examples.includes('temp'));
});

test('the binary fixture exposes the printable runs inside the payload', () => {
  const flow = analyzeFile(capture('binary-session.pcap')).flows[0]!;
  const payload = flow.forward.semantics.payload;
  assert.equal(payload.encoding, 'binary');
  assert.ok(payload.strings.length > 0, 'no printable run was found');
  const values = payload.strings.flatMap((entry) => entry.values);
  assert.ok(values.includes('uptime'), `strings were ${values.join(', ')}`);
});

test('requests are paired with their responses and the exception response is visible', () => {
  const flow = analyzeFile(capture('modbus-session.pcap')).flows[0]!;
  const grammar = flow.grammar;

  assert.equal(grammar.exchanges.length, 15);
  assert.equal(grammar.unpairedRequests, 0);
  assert.equal(grammar.unpairedResponses, 0);
  assert.ok(grammar.latency, 'no latency was computed');
  assert.ok(grammar.latency!.medianMs > 0);

  const responses = grammar.exchanges.map((exchange) => exchange.response?.label);
  assert.ok(responses.includes('type=0x84'), 'the Modbus exception response was not paired');
});

test('pairing prefers the request when a burst shares one timestamp', () => {
  const base = 1_700_000_000;
  const messages: MessageRecord[] = [
    { direction: 'forward', offset: 0, ts: base, bytes: Buffer.from([1]), label: 'req-a' },
    { direction: 'forward', offset: 4, ts: base + 0.001, bytes: Buffer.from([1]), label: 'req-b' },
    { direction: 'reverse', offset: 0, ts: base + 0.001, bytes: Buffer.from([2]), label: 'res-a' },
    { direction: 'reverse', offset: 4, ts: base + 0.002, bytes: Buffer.from([2]), label: 'res-b' },
  ];

  const grammar = inferGrammar(messages);
  assert.deepEqual(
    grammar.exchanges.map((exchange) => `${exchange.request.label}->${exchange.response?.label}`),
    ['req-a->res-a', 'req-b->res-b'],
  );
  assert.equal(grammar.pipelined, true);
});

test('Modbus/TCP traffic is labelled from structure, not from the port number', () => {
  const flow = analyzeFile(capture('modbus-session.pcap')).flows[0]!;
  assert.ok(flow.fingerprint, 'no family was identified');
  assert.equal(flow.fingerprint!.family, 'Modbus/TCP');
  assert.ok(flow.fingerprint!.signals.length >= 3);
  assert.ok(flow.fingerprint!.signals.every((signal) => signal.length > 10));
});

test('a custom protocol is not forced into a known family', () => {
  const flow = analyzeFile(capture('custom-crc.pcap')).flows[0]!;
  assert.equal(flow.fingerprint, undefined, `wrongly labelled as ${flow.fingerprint?.family}`);
});

test('the report carries the new layers', () => {
  const report = renderReport(analyzeFile(capture('custom-crc.pcap')));
  assert.match(report, /Recovered checksum parameters/);
  assert.match(report, /polynomial: `0x8f57`/);
  assert.match(report, /Request\/response pairing/);
  assert.match(report, /Field semantics/);
});

test('the recovered parameters drive the generated Python client too', (t) => {
  const python = findPython();
  if (!python) {
    t.skip('no python interpreter on this machine');
    return;
  }

  const flow = analyzeFile(capture('custom-crc.pcap')).flows[0]!;
  const workDir = mkdtempSync(join(tmpdir(), 'protopath-recovered-py-'));
  writeFileSync(join(workDir, 'client.py'), emitClient(flow, 'python'), 'utf8');
  writeFileSync(
    join(workDir, 'run.py'),
    [
      'import warnings',
      'warnings.simplefilter("error")', // a Windows path inside the docstring would surface here
      'from client import decode, encode, verify',
      `raw = bytes.fromhex("${flow.forward.messages[0]!.bytes.toString('hex')}")`,
      'message = decode(raw)',
      'assert message is not None, "decode returned None"',
      'assert verify(raw), "recovered checksum rejected a good message"',
      'assert encode(message) == raw, "round trip changed the bytes"',
      'broken = bytearray(raw)',
      'broken[-1] ^= 0xFF',
      'assert not verify(bytes(broken)), "corrupted message was accepted"',
      'print("ok")',
    ].join('\n'),
    'utf8',
  );

  const run = spawnSync(python, ['run.py'], { cwd: workDir, encoding: 'utf8' });
  assert.equal(run.status, 0, `the recovered Python client failed:\n${run.stdout}\n${run.stderr}`);
  assert.match(run.stdout, /ok/);
});

/** First working interpreter, so the suite runs on Linux (python3) and Windows (python). */
function findPython(): string | null {
  for (const candidate of ['python3', 'python']) {
    const probe = spawnSync(candidate, ['--version'], { encoding: 'utf8' });
    if (probe.status === 0) return candidate;
  }
  return null;
}

test('semantics degenerates cleanly on too little data', () => {
  const semantics = inferSemantics([Buffer.from([1, 2])], []);
  assert.equal(semantics.domains.length, 0);
  assert.equal(semantics.payload.encoding, 'binary');
  assert.ok(semantics.payload.notes.length > 0);
});

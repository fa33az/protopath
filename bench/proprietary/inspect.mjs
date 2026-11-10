// What does one failing capture actually look like, byte for byte?
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeFile } from '../../dist/index.js';

const seeds = process.argv.slice(2).map(Number);
const manifest = JSON.parse(readFileSync(join('bench', 'proprietary', 'corpus', 'manifest.json'), 'utf8'));

for (const seed of seeds) {
  const entry = manifest.find((e) => e.seed === seed);
  const analysis = analyzeFile(join('bench', 'proprietary', 'corpus', `${entry.name}.pcap`), { maxFlows: 1, deep: false });
  const dir = analysis.flows[0]?.forward;
  const best = dir?.best;
  console.log(`\n=== ${entry.name} transport ${entry.transport} ===`);
  console.log(`truth framing : ${JSON.stringify(entry.framing)}`);
  console.log(`truth header  : ${entry.headerLength}  counter ${JSON.stringify(entry.counter)}  checksum ${JSON.stringify(entry.checksum)}`);
  console.log(`truth lengths : ${entry.messages.lengths.join(',')}`);
  console.log(`report framing: ${best?.kind} score ${best?.score?.toFixed(2)} ${JSON.stringify(best?.lengthPrefix ?? best?.startMarker ?? best?.delimiter ?? best?.fixed)}`);
  console.log(`report offsets: ${best?.offsets.slice(0, 8).join(',')}`);
  const first = best?.messages?.[0];
  if (first) console.log(`first message : ${first.toString('hex')}  (${first.length}B)`);
  console.log('report fields :');
  for (const field of dir?.fields ?? []) {
    console.log(`  ${field.name.padEnd(20)} ${field.role.padEnd(9)} ${field.anchor} off ${field.offset} len ${field.length === -1 ? 'var' : field.length} conf ${field.confidence}`);
  }
  for (const hypothesis of (analysis.flows[0]?.forward?.hypotheses ?? []).slice(0, 4)) {
    console.log(`  hypo ${hypothesis.kind.padEnd(13)} ${hypothesis.score.toFixed(2)} ${JSON.stringify(hypothesis.lengthPrefix ?? hypothesis.startMarker ?? hypothesis.delimiter ?? hypothesis.fixed ?? null)} msgs ${hypothesis.messages.length}`);
  }
}

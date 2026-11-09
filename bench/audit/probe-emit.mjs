// Does the generated TypeScript client survive input that is not the capture it came from?
import { readFileSync } from 'node:fs';
import { copyFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

mkdirSync('out/audit/tsclient', { recursive: true });
copyFileSync('out/emit/binary/client.ts', 'out/audit/tsclient/client.ts');
const client = await import('./tsclient/client.ts');

const rows = JSON.parse(readFileSync('out/emit/binary/messages.jsonl', 'utf8').trim().split('\n').map((l) => l).join(',') ? '[' + readFileSync('out/emit/binary/messages.jsonl', 'utf8').trim().split('\n').join(',') + ']' : '[]');
const forward = rows.filter((r) => r.direction === 'forward').map((r) => Buffer.from(r.hex, 'hex'));
const good = forward[0];

const probe = (label, buffer) => {
  let outcome;
  try {
    const decoded = client.decode(buffer);
    if (decoded === null) outcome = 'null';
    else {
      let verified;
      try {
        verified = client.verify(buffer);
      } catch (e) {
        verified = `verify threw: ${e.code ?? e.message}`;
      }
      outcome = `decoded, verify=${verified}`;
    }
  } catch (e) {
    outcome = `THREW ${e.code ?? e.message}`;
  }
  console.log(`  ${label.padEnd(46)} ${outcome}`);
};

console.log(`\n=== generated client.ts, ${good.length}-byte message ===`);
probe('the real message', good);
probe('same message with one trailing byte', Buffer.concat([good, Buffer.from([0x00])]));
probe('two messages concatenated (a stream read)', Buffer.concat([good, forward[1]]));
probe('a length byte that says 1', Buffer.from([0xa5, 0x5a, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff]));
probe('a length byte that says 0', Buffer.from([0xa5, 0x5a, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff]));
probe('six bytes, no room for a trailer', Buffer.from([0xa5, 0x5a, 0x06, 0x00, 0x00, 0x01]));
probe('random 64 bytes', Buffer.from(Array.from({ length: 64 }, (_, i) => (i * 37 + 11) & 0xff)));

console.log('\n  note: verify() takes buffer.length as the message end, not the decoded length.');

import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { recoverCrc } from '../src/core/infer/crc-recovery.js';
import { crcCompute } from '../src/core/infer/checksum.js';

/**
 * Which recovered parameter set is reported first.
 *
 * Several parameter sets can reproduce every message in a capture, because init absorbs the
 * difference. Before this test existed the list was ordered by the smallest polynomial, so a
 * degenerate 8-bit set sorted ahead of the protocol's real 16-bit one on 10 of 60 private
 * polynomials, and the generated client embedded it. Nothing in the capture distinguishes the two,
 * so the ranking has to rest on how many independent derivations agreed - that is what is locked
 * down here.
 */

function bodiesFor(poly: number, init: number, count = 8): Buffer[] {
  const truth = { width: 16 as const, poly, init, refin: true, refout: true, xorout: 0 };
  const messages: Buffer[] = [];
  for (let i = 0; i < count; i++) {
    const body = Buffer.alloc(10 + (i % 5));
    for (let b = 0; b < body.length; b++) body[b] = (i * 31 + b * 17) & 0xff;
    const field = Buffer.alloc(2);
    field.writeUInt16LE(crcCompute(body, truth), 0);
    messages.push(Buffer.concat([body, field]));
  }
  return messages;
}

test('the real parameter set is ranked ahead of a degenerate one that also fits', () => {
  const misses: string[] = [];

  for (let trial = 0; trial < 20; trial++) {
    // The same series the audit probe draws: private polynomials with a non-standard init.
    const poly = (0x8100 + trial * 397) | 1;
    const init = (0x2000 + trial * 61) & 0xffff;
    const verified = recoverCrc(bodiesFor(poly, init)).filter((candidate) => candidate.matches === candidate.total);
    const [first] = verified;

    if (first?.params.poly !== poly) {
      misses.push(
        `truth 0x${poly.toString(16)} ranked behind 0x${first?.params.poly.toString(16) ?? 'nothing'}`,
      );
    }
  }

  assert.deepEqual(misses, [], `${misses.length} of 20 private polynomials reported the wrong set first`);
});

test('a capture whose real set is 16-bit is not answered with an 8-bit set', () => {
  const messages = bodiesFor(0xb42d, 0x2000, 8);
  const [first] = recoverCrc(messages).filter((candidate) => candidate.matches === candidate.total);

  assert.ok(first, 'recovery returned nothing that verifies');
  assert.equal(first.params.width, 16);
  assert.equal(first.params.poly, 0xb42d);
});

test('the check field a generated client would embed is the one that survives unseen bodies', () => {
  const poly = 0xb42d;
  const truth = { width: 16 as const, poly, init: 0x2000, refin: true, refout: true, xorout: 0 };
  const set = bodiesFor(poly, 0x2000, 8);
  const [first] = recoverCrc(set).filter((candidate) => candidate.matches === candidate.total);
  assert.ok(first);

  const unseen = Buffer.from(Array.from({ length: 23 }, (_, i) => (i * 47 + 11) & 0xff));
  const expected = crcCompute(unseen, truth);
  const reported = crcCompute(unseen, first.params);

  assert.equal(reported, expected, 'the reported set disagrees with the protocol on a body the capture never contained');
});

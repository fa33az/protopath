import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { reassembleTcp } from '../src/core/net/flows.js';
import type { Frame } from '../src/core/types.js';

function frame(seq: number, payload: string, index: number): Frame {
  return {
    index,
    ts: 1000 + index,
    transport: 'tcp',
    src: { ip: '10.0.0.1', port: 1000 },
    dst: { ip: '10.0.0.2', port: 2000 },
    payload: Buffer.from(payload, 'latin1'),
    seq,
  };
}

test('out-of-order segments are reassembled by sequence number', () => {
  const stream = reassembleTcp([frame(105, 'fghij', 1), frame(100, 'abcde', 2)]);
  assert.equal(stream.data.toString('latin1'), 'abcdefghij');
  assert.deepEqual(stream.gaps, []);
  assert.equal(stream.outOfOrder, 1);
  assert.equal(stream.retransmits, 0);
});

test('a retransmitted segment is dropped and counted', () => {
  const stream = reassembleTcp([frame(100, 'abcde', 1), frame(100, 'abcde', 2), frame(105, 'fghij', 3)]);
  assert.equal(stream.data.toString('latin1'), 'abcdefghij');
  assert.equal(stream.retransmits, 1);
});

test('a partial overlap keeps only the new bytes', () => {
  const stream = reassembleTcp([frame(100, 'abcde', 1), frame(103, 'defgh', 2)]);
  assert.equal(stream.data.toString('latin1'), 'abcdefgh');
  assert.equal(stream.retransmits, 1);
});

test('a hole becomes a reported gap, filled with zeros', () => {
  const stream = reassembleTcp([frame(100, 'abcde', 1), frame(110, 'klmno', 2)]);
  assert.equal(stream.data.length, 15);
  assert.deepEqual(stream.gaps, [[5, 10]]);
  assert.equal(stream.data.subarray(0, 5).toString('latin1'), 'abcde');
  assert.equal(stream.data.subarray(10).toString('latin1'), 'klmno');
});

test('the sequence number wraps without corrupting offsets', () => {
  const near = 0xfffffffe;
  const stream = reassembleTcp([frame(near, 'ab', 1), frame(0, 'cd', 2), frame(2, 'ef', 3)]);
  assert.equal(stream.data.toString('latin1'), 'abcdef');
  assert.deepEqual(stream.gaps, []);
});

test('a capture that starts mid-stream does not lose the first bytes', () => {
  const stream = reassembleTcp([frame(9005, 'later', 1), frame(9000, 'early', 2)]);
  assert.equal(stream.data.toString('latin1'), 'earlylater');
  assert.deepEqual(stream.gaps, []);
  assert.equal(stream.retransmits, 0);
});

test('a mid-stream capture with a real hole reports the hole', () => {
  const stream = reassembleTcp([frame(9000, 'later', 1), frame(8000, 'early', 2)]);
  assert.equal(stream.data.subarray(0, 5).toString('latin1'), 'early');
  assert.equal(stream.data.subarray(1000).toString('latin1'), 'later');
  assert.deepEqual(stream.gaps, [[5, 1000]]);
});

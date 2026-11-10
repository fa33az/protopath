import { Buffer } from 'node:buffer';
import type { Endian } from '../types.js';
import {
  crcCompute,
  reflectedPoly,
  type ChecksumMatch,
  type ChecksumSpec,
  type CrcParameters,
} from './checksum.js';

/**
 * CRC parameter recovery.
 *
 * The catalogue in `checksum.ts` finds checksums somebody already named. A protocol that
 * copied a published CRC but changed the initial value, or rolled its own polynomial, matches
 * nothing there. This module recovers the parameter set from the data.
 *
 * The method is exact, not statistical. CRC is affine in its input, so two messages of equal
 * covered length have identical init and xorout contributions; xoring their check values
 * cancels both unknowns and leaves one equation in the polynomial alone. With the polynomial
 * known, the register after a byte range is linear in the initial value, so two messages of
 * *different* length give a small linear system over GF(2) and init falls out of it. Every
 * parameter set is then verified against every message, and only one that reproduces all of
 * them is reported. There is no threshold to tune: either the bytes come out equal or the
 * candidate is discarded.
 *
 * Cost is why this is a fallback rather than the first move: the polynomial search is
 * 2^(width-1) candidates per layout and reflection, which is sub-second for width 16 and
 * infeasible for width 32. The catalogue runs first, and this runs only when it found nothing.
 */

export interface CrcLayout {
  /** Bytes after the checksum field, counted from the message end. */
  offsetFromEnd: number;
  /** First message byte covered by the checksum. */
  rangeStart: number;
}

export interface CrcRecovery extends ChecksumMatch {
  /** The recovered parameter set, in canonical (Williams) form. */
  params: CrcParameters;
  /** The polynomial as it appears in reflected implementations, e.g. 0xa001 for CRC-16/MODBUS. */
  reflectedPoly: number;
  /** Ready-to-embed descriptor for the generated client. */
  spec: ChecksumSpec;
  /** True when the data does not pin the initial value down to a single answer. */
  initAmbiguous: boolean;
  limitations: string[];
}

export interface CrcRecoveryOptions {
  /** Polynomial candidates evaluated before the search gives up. */
  budget?: number;
  widths?: Array<8 | 16>;
  /** Field positions and covered ranges to try, in order. */
  layouts?: CrcLayout[];
}

/**
 * Field positions tried by default, cheapest first. A check value at the very end covering the
 * whole message is by far the most common; then a checksum that skips a fixed header, then a
 * checksum with a trailing byte after it.
 */
const DEFAULT_LAYOUTS: CrcLayout[] = [
  { offsetFromEnd: 0, rangeStart: 0 },
  { offsetFromEnd: 0, rangeStart: 2 },
  { offsetFromEnd: 0, rangeStart: 4 },
  { offsetFromEnd: 1, rangeStart: 0 },
];

/** Conventional initial values, preferred when the data cannot tell them apart. */
const STANDARD_INITS: Record<8 | 16, number[]> = {
  8: [0xff, 0x00, 0x55],
  16: [0xffff, 0x0000, 0x1d0f],
};

function reflectWidth(value: number, width: 8 | 16): number {
  let out = 0;
  for (let bit = 0; bit < width; bit++) out = (out << 1) | ((value >> bit) & 1);
  return out & (width === 16 ? 0xffff : 0xff);
}

function readField(message: Buffer, layout: CrcLayout, width: number, endian: Endian): number {
  const position = message.length - layout.offsetFromEnd - width;
  if (position < 0) return -1;
  if (width === 1) return message[position]!;
  return endian === 'le' ? message.readUInt16LE(position) : message.readUInt16BE(position);
}

function covered(message: Buffer, layout: CrcLayout, width: number): Buffer {
  return message.subarray(layout.rangeStart, message.length - layout.offsetFromEnd - width);
}

/**
 * Recovers a CRC parameter set from a set of messages.
 *
 * Returns every parameter set that reproduces the check field of every message. More than one
 * is possible when the capture has no messages with differing covered lengths — in that case
 * init and xorout are algebraically interchangeable, and the result says so rather than
 * pretending the split was discovered.
 */
export function recoverCrc(messages: Buffer[], options: CrcRecoveryOptions = {}): CrcRecovery[] {
  const usable = messages.filter((message) => message.length >= 6);
  if (usable.length < 5) return [];

  const widths = options.widths ?? [16, 8];
  const layouts = options.layouts ?? DEFAULT_LAYOUTS;
  let budget = options.budget ?? 400_000;
  const found: CrcRecovery[] = [];

  // How many independent derivations produced each parameter set. A polynomial that is really the
  // protocol's is reached from several layouts, byte orders and differentiating pairs; one that
  // only fits because init absorbed the difference is reached from fewer. This is the only
  // evidence available that separates two sets which both reproduce every captured message, and
  // it beats ordering by coefficient size, which is what this did before.
  const support = new Map<string, number>();
  const keyOf = (candidate: CrcRecovery): string =>
    [
      candidate.params.width,
      candidate.params.poly,
      Number(candidate.params.refin),
      Number(candidate.params.refout),
      candidate.endian,
    ].join(':');

  for (const width of widths) {
    const mask = width === 16 ? 0xffff : 0xff;
    const fieldBytes = width / 8;

    for (const layout of layouts) {
      if (budget <= 0) break;

      const eligible = usable.filter((message) => message.length - layout.offsetFromEnd - fieldBytes > layout.rangeStart);
      if (eligible.length < 5) continue;

      // The check value has to vary, otherwise this is not a check value.
      if (new Set(eligible.map((message) => readField(message, layout, fieldBytes, 'le'))).size < 2) continue;

      // Equal covered length is what cancels init and xorout, so the prefilter needs a pair.
      // Without one there is nothing cheap to test, and the search would verify every
      // polynomial exhaustively; the catalogue already covered the named cases.
      const byLength = new Map<number, Buffer[]>();
      for (const message of eligible) {
        const key = message.length - layout.offsetFromEnd - fieldBytes;
        const bucket = byLength.get(key);
        if (bucket) bucket.push(message);
        else byLength.set(key, [message]);
      }
      const pair = [...byLength.values()].sort((a, b) => b.length - a.length).find((bucket) => bucket.length >= 2);
      if (!pair) continue;
      const [a, b] = pair as [Buffer, Buffer];

      const rangeA = covered(a, layout, fieldBytes);
      const rangeB = covered(b, layout, fieldBytes);
      if (rangeA.length === 0) continue;

      const difference = Buffer.alloc(rangeA.length);
      for (let i = 0; i < rangeA.length; i++) difference[i] = rangeA[i]! ^ rangeB[i]!;
      if (difference.every((byte) => byte === 0)) continue;

      const targets = new Set<number>();
      for (const endian of ['le', 'be'] as const) {
        const observed = readField(a, layout, fieldBytes, endian) ^ readField(b, layout, fieldBytes, endian);
        if (observed === 0) continue;
        targets.add(observed);
        // With refout the observed xor is the reflected register, and reflection is linear.
        targets.add(reflectWidth(observed, width));
      }
      if (targets.size === 0) continue;

      for (const refin of [false, true]) {
        for (let poly = 1; poly <= mask; poly += 2) {
          if (--budget < 0) break;
          const raw = crcCompute(difference, { width, poly, init: 0, refin, refout: false, xorout: 0 });
          if (!targets.has(raw)) continue;

          for (const endian of ['le', 'be'] as const) {
            for (const refout of [false, true]) {
              const verified = verifyCandidate(eligible, layout, width, endian, { width, poly, init: 0, refin, refout, xorout: 0 });
              if (!verified) continue;
              const key = keyOf(verified);
              support.set(key, (support.get(key) ?? 0) + 1);
              found.push(verified);
            }
          }
        }
      }
    }
  }

  // Ordering is evidence first. Every set below reproduces every captured message, so the bytes
  // in this capture cannot separate them; what can is how many independent derivations arrived at
  // the same answer. Ordering by the smallest polynomial put a degenerate 8-bit set in front of the
  // protocol's real 16-bit one on 10 of 60 private polynomials, and the generated client embedded
  // it. Width is the next tiebreak: a 16-bit check field is the common case, and the field bytes
  // have already been read as one.
  return dedupe(found).sort(
    (x, y) =>
      (support.get(keyOf(y)) ?? 0) - (support.get(keyOf(x)) ?? 0) ||
      y.params.width - x.params.width ||
      x.params.poly - y.params.poly,
  );
}

/**
 * Fixes init and xorout for a candidate polynomial and verifies every message.
 *
 * A published parameter set beats a recovered one even when both fit, so the conventional
 * initial values are tried first. Otherwise the initial value is derived from a linear system
 * over GF(2) built from two messages of different covered length.
 */
function verifyCandidate(
  messages: Buffer[],
  layout: CrcLayout,
  width: 8 | 16,
  endian: Endian,
  base: CrcParameters,
): CrcRecovery | null {
  const mask = width === 16 ? 0xffff : 0xff;
  const fieldBytes = width / 8;
  const samples = messages.map((message) => ({
    covered: covered(message, layout, fieldBytes),
    observed: readField(message, layout, fieldBytes, endian),
  }));
  if (samples.some((sample) => sample.observed < 0)) return null;

  const singleLength = new Set(samples.map((sample) => sample.covered.length)).size === 1;

  /** Register after the covered bytes, before refout and xorout. */
  const raw = (sample: { covered: Buffer }, init: number): number =>
    crcCompute(sample.covered, { ...base, init, refout: false, xorout: 0 });

  const xoroutFor = (sample: { covered: Buffer; observed: number }, init: number): number => {
    const final = raw(sample, init);
    return ((base.refout ? reflectWidth(final, width) : final) ^ sample.observed) & mask;
  };

  const fits = (init: number, xorout: number): boolean =>
    samples.every(({ covered: bytes, observed }) => {
      const final = crcCompute(bytes, { ...base, init, refout: false, xorout: 0 });
      return ((base.refout ? reflectWidth(final, width) : final) ^ xorout) === observed;
    });

  const build = (init: number, xorout: number, ambiguous: boolean): CrcRecovery => {
    const params: CrcParameters = { ...base, init, xorout };
    const polyHex = params.poly.toString(16).padStart(width / 4, '0');
    const reflected = reflectedPoly(params);
    const limitations: string[] = [];

    if (ambiguous) {
      limitations.push(
        'the capture cannot separate init from xorout because every covered message has the same length; the reported split is a convention, not a discovery',
      );
    }

    const hex = (value: number): string => `0x${value.toString(16).padStart(width / 4, '0')}`;
    return {
      algorithm: `crc${width}/${polyHex}`,
      width: width === 16 ? 2 : 1,
      endian,
      offsetFromEnd: layout.offsetFromEnd,
      rangeStart: layout.rangeStart,
      matches: samples.length,
      total: samples.length,
      confidence: 1,
      evidence:
        `crc-${width} with poly ${hex(params.poly)} (reflected ${hex(reflected)}), init ${hex(init)}, ` +
        `refin ${base.refin}, refout ${base.refout}, xorout ${hex(xorout)} reproduces the ${fieldBytes}-byte ${endian} ` +
        `field at len-${layout.offsetFromEnd + fieldBytes} in all ${samples.length} messages; it covers bytes ` +
        `[${layout.rangeStart}, len-${layout.offsetFromEnd + fieldBytes})`,
      params,
      reflectedPoly: reflected,
      spec: { kind: 'crc', params },
      initAmbiguous: ambiguous,
      limitations,
    };
  };

  for (const init of STANDARD_INITS[width]) {
    const xorout = xoroutFor(samples[0]!, init);
    if (fits(init, xorout)) return build(init, xorout, singleLength);
  }

  if (singleLength) {
    const xorout = xoroutFor(samples[0]!, 0);
    return fits(0, xorout) ? build(0, xorout, true) : null;
  }

  const solved = solveInit(samples, raw, width, base.refout, base.poly, base.refin);
  if (!solved) return null;
  const xorout = xoroutFor(samples[0]!, solved.init);
  if (!fits(solved.init, xorout)) return null;
  return build(solved.init, xorout, solved.ambiguous);
}

/**
 * Solves `T(short, init) ^ T(long, init) = known` over GF(2), where `T(L, x)` is the register
 * state after L covered bytes starting from x. Rank deficiency means several initial values
 * fit; the returned solution is still valid, and the caller records the ambiguity.
 */
function solveInit(
  samples: Array<{ covered: Buffer; observed: number }>,
  raw: (sample: { covered: Buffer }, init: number) => number,
  width: 8 | 16,
  refout: boolean,
  poly: number,
  refin: boolean,
): { init: number; ambiguous: boolean } | null {
  const byLength = new Map<number, { covered: Buffer; observed: number }>();
  for (const sample of samples) if (!byLength.has(sample.covered.length)) byLength.set(sample.covered.length, sample);

  const lengths = [...byLength.keys()].sort((a, b) => a - b);
  if (lengths.length < 2) return null;

  const short = byLength.get(lengths[0]!)!;
  const long = byLength.get(lengths[lengths.length - 1]!)!;
  const rawOf = (sample: { observed: number }): number => (refout ? reflectWidth(sample.observed, width) : sample.observed);
  const known = rawOf(short) ^ rawOf(long) ^ raw(short, 0) ^ raw(long, 0);

  const shortZeros = Buffer.alloc(short.covered.length);
  const longZeros = Buffer.alloc(long.covered.length);
  const mask = width === 16 ? 0xffff : 0xff;

  /** Response of the difference operator to one initial value. */
  const response = (init: number): number =>
    (crcCompute(shortZeros, { width, poly, init, refin, refout: false, xorout: 0 }) ^
      crcCompute(longZeros, { width, poly, init, refin, refout: false, xorout: 0 })) &
    mask;

  const byPivot = new Array<number>(width).fill(0);
  const maskByPivot = new Array<number>(width).fill(0);
  for (let bit = 0; bit < width; bit++) {
    let vector = response(1 << bit);
    let combined = 1 << bit;
    while (vector !== 0) {
      const pivot = 31 - Math.clz32(vector);
      if (byPivot[pivot] === 0) {
        byPivot[pivot] = vector;
        maskByPivot[pivot] = combined;
        break;
      }
      vector ^= byPivot[pivot]!;
      combined ^= maskByPivot[pivot]!;
    }
  }

  const rank = byPivot.filter((vector) => vector !== 0).length;
  let remainder = known;
  let solution = 0;
  while (remainder !== 0) {
    const pivot = 31 - Math.clz32(remainder);
    if (byPivot[pivot] === 0) return null;
    remainder ^= byPivot[pivot]!;
    solution ^= maskByPivot[pivot]!;
  }

  return { init: solution, ambiguous: rank < width };
}

/**
 * Several covered ranges can reproduce every message when the initial value is allowed to
 * absorb the difference: a checksum that skips two header bytes and one that covers them are
 * the same function with different seeds. Only one answer is worth printing, so the widest
 * and earliest range wins, and the alternatives are reported as a limitation rather than as
 * separate findings.
 */
function dedupe(candidates: CrcRecovery[]): CrcRecovery[] {
  const groups = new Map<string, CrcRecovery[]>();
  for (const candidate of candidates) {
    const key = [
      candidate.params.width,
      candidate.params.poly,
      candidate.params.refin,
      candidate.params.refout,
      candidate.endian,
    ].join(':');
    const bucket = groups.get(key);
    if (bucket) bucket.push(candidate);
    else groups.set(key, [candidate]);
  }

  const out: CrcRecovery[] = [];
  for (const group of groups.values()) {
    group.sort((a, b) => a.rangeStart - b.rangeStart || a.offsetFromEnd - b.offsetFromEnd || Number(a.initAmbiguous) - Number(b.initAmbiguous));
    const chosen = group[0]!;
    if (group.length > 1) {
      chosen.limitations = [
        ...chosen.limitations,
        `${group.length - 1} other field position(s) also reproduce every message once the initial value absorbs the difference; the reported one covers the longest range starting at the earliest byte`,
      ];
    }
    out.push(chosen);
  }
  return out;
}

/** Human-readable parameter set, for reports and generated file headers. */
export function describeCrc(params: CrcParameters): string {
  const hex = (value: number): string => `0x${value.toString(16).padStart(params.width / 4, '0')}`;
  return (
    `crc-${params.width} poly=${hex(params.poly)} init=${hex(params.init)} ` +
    `refin=${params.refin} refout=${params.refout} xorout=${hex(params.xorout)}`
  );
}

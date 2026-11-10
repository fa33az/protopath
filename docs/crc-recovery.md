# Recovering a CRC from the bytes

The checksum catalogue in `src/core/infer/checksum.ts` finds checksums somebody already named.
Real hardware often uses a published polynomial with a private initial value, or a polynomial that
appears in nothing you can look up. This note describes the fallback that solves for the parameters
instead, and is honest about the two cases where it cannot.

Code: [`src/core/infer/crc-recovery.ts`](../src/core/infer/crc-recovery.ts).
Fixture: [`captures/custom-crc.pcap`](captures.md). Test: `tests/inference.test.ts`.

---

## The idea, in one line

CRC is affine in its input, so the differences between messages cancel every unknown except the
polynomial.

## Step 1 — cancel init and xorout

Write the canonical CRC of a message `m` of `n` bits as

```
crc(m) = reflect_if_refout( T_n(init) ^ G(data) ) ^ xorout
```

where `T_n` advances the register `n` zero bits from `init` (linear in `init`) and `G` is the
register after processing the data starting from zero (linear in the data, for a fixed polynomial).

For two messages of the **same covered length** `n`, `T_n(init)` is identical, so

```
crc(a) ^ crc(b) = reflect( G(a) ^ G(b) ) = reflect( G(a ^ b) )
```

because reflection is linear and `G` is linear. Both `init` and `xorout` are gone. What remains is
one equation in the polynomial alone:

```
G(a ^ b, poly) == crc(a) ^ crc(b)        (or its reflection, for refout)
```

So the search is: every odd polynomial of the given width, times `refin` `{false, true}`, times
the field layout (top `4` positions and `4` covered ranges). A candidate survives only when the
equation holds **and** a full reconstruction succeeds.

That prefilter matters. It rejects `2^15 - 1` wrong polynomials per layout and reflection at the
cost of one CRC evaluation each, which is what makes a brute-force polynomial search affordable at
all — around 300 ms for width 16.

## Step 2 — solve the initial value

With the polynomial known, `T_n(init)` is linear in `init`, so two messages of **different** length
give a linear system over GF(2):

```
T_short(init) ^ T_long(init) = crc(short) ^ crc(long) ^ G(short) ^ G(long)
```

`T_k(x)` is computed by running the CRC over `k` zero bytes starting from `x`, so the 16 columns of
the matrix cost 32 zero-byte CRC passes. Gaussian elimination then yields `init`, and `xorout`
follows from any single message. The whole solve runs only for polynomials that already passed
step 1, so its cost is invisible.

## Step 3 — verify everything, or report nothing

The candidate parameter set recomputes the check field of **every** message. There is no agreement
threshold: a CRC that reproduces 9 of 10 messages is not a CRC with low confidence, it is the wrong
CRC. Anything short of 100% is discarded.

## Three ambiguities, stated rather than hidden

**Every message the same covered length.** Then `T_n(init)` is the same for all of them, the system
in step 2 is the zero matrix, and *any* initial value fits once `xorout` compensates. The capture
cannot tell init from xorout — the information is not there. The report marks the result
`initAmbiguous`, prefers a conventional initial value (`0xffff`, `0x0000`, `0x1d0f`), and says the
split is a convention.

**Several field positions fit.** A checksum that covers bytes `[0, len-2)` and one that covers
`[2, len-2)` are the same function with different seeds, so both reproduce the data once the
initial value absorbs the difference. Only one answer is worth printing: the widest range starting
at the earliest byte. The report lists the alternatives as a limitation.

**Several parameter sets fit.** A polynomial of low degree can be made to reproduce a whole capture
once the initial value is allowed to absorb what it cannot express, so a capture with any checksum
at all can yield more than one fully verified answer — a degenerate 8-bit set beside the protocol's
real 16-bit one. The bytes in the capture do not separate them; the only evidence is agreement
between derivations. The candidate the most independent derivations reached — across layouts, byte
orders and differentiating message pairs — is the one reported, and the rest are listed with it.
Ordering by the smallest polynomial, which is what this did before, put the degenerate set in front
on 10 of 60 private polynomials, and the generated client embedded it.

## What it does not attempt

| Case | Why not |
|---|---|
| Width 32 with a private polynomial | `2^31` candidates per layout — infeasible by search; the catalogue carries four 32-bit algorithms |
| All messages a different length | step 1 has nothing to cancel with; the catalogue still runs |
| Fewer than five messages | a six-parameter fit against four samples proves nothing |
| Non-standard output reflection | `refout` is searched, but `refout != refin` combined with a private polynomial is not; the catalogue covers the published combinations |

## Proof fixture

`captures/custom-crc.pcap` uses CRC-16, polynomial `0x8f57`, initial value `0x1234`, refin and
refout true, xorout `0`.

```
$ protopath analyze captures/custom-crc.pcap
```

```
**Recovered checksum parameters**

- polynomial: `0x8f57` (normal form), `0xeaf1` reflected
- init: `0x1234`, xorout: `0x0000`, refin true, refout true
- covers bytes `[0, len-2)`, field read le at `len-2`
- verified against all 10 messages, no exceptions
```

Every value matches the generator, including the reflected polynomial the fixture never stores.
`tests/inference.test.ts` also compiles the generated client, decodes a captured message,
re-encodes it byte-for-byte and confirms a single-bit corruption is rejected — so the recovered
parameters are load-bearing, not decorative.

The same file also carries three unit fixtures with known answers: a private polynomial with a
private init, a private polynomial with a non-zero xorout, and a capture where every message has
the same length so the ambiguity flag has to fire.

## Using it directly

```js
import { recoverCrc, describeCrc, crcCompute } from 'protopath';

const recovered = recoverCrc(messages);
if (recovered[0]) {
  console.log(describeCrc(recovered[0].params));
  const ok = messages.every((m) => {
    const field = m.length - recovered[0].offsetFromEnd - recovered[0].width;
    return crcCompute(m.subarray(recovered[0].rangeStart, field), recovered[0].params) ===
      (recovered[0].endian === 'le' ? m.readUInt16LE(field) : m.readUInt16BE(field));
  });
  console.log(ok); // true
}
```

`options.budget` caps the polynomial evaluations, and `options.layouts` lets you point the search
at a field position you already suspect.

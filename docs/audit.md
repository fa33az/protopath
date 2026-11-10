# Implementation audit

This is an audit of the code, not of the documentation. Every claim below was produced by running
the shipped build against an input the test suite does not contain, and every probe is committed
next to this file so the result can be reproduced.

```console
$ npm run build && npm run build:test
$ node bench/audit/probe-net.mjs       # decoder and TCP reassembly
$ node bench/audit/probe-emit.mjs      # the generated TypeScript client
$ python bench/audit/test-emit.py      # the generated Python clients, against the capture
$ node bench/audit/probe-crc.mjs       # recovery on data that has no checksum
$ node bench/audit/probe-crc2.mjs      # recovery against 40 private polynomials
$ node bench/audit/probe-crc3.mjs      # does the reported set survive an unseen message
$ node bench/audit/probe-crc4.mjs      # is the true set returned, and where in the list
$ node bench/audit/probe-e2e.mjs       # an ambiguous capture carried through to the emitted client
$ node bench/audit/probe-fields.mjs    # field inference on inputs outside the fixtures
$ node bench/audit/probe-time.mjs      # whether the timestamp domain is reachable at all
```

Eleven defects. Three of them produce confidently wrong output from a valid-looking capture.
Nothing below was found by reading the README.

## Status

This document is the record of one audit run and is not edited as the code moves; each section
describes the build as it was at `e5462f4`. What has changed since:

| Finding | Status |
|---|---|
| 3.2 the `timestamp` value domain is unreachable | **fixed.** A four-byte field in the epoch window that advances by a constant amount is now a `timestamp` field, and the semantics pass labels the domain at 0.85. The proprietary benchmark scores it. |
| 3.3 a field that steps by a constant other than one ends the header | **fixed.** Every column of the common prefix is classified before it is named, so a stride other than one is a `sequence` field and the header continues. |
| 3.1 CRC recovery tiebreak | **fixed.** Candidates are ranked by how many independent derivations reached them, not by the smallest polynomial; `probe-crc4.mjs` now reports the true set first on 60 of 60 private polynomials, and `probe-e2e.mjs` reports 0 of 8 unseen bodies wrong instead of 8 of 8. The duplicate-candidate half of this finding is still open. |
| 1.1 a big-endian pcapng parses as an empty capture | **fixed.** Block types are read in the section's byte order, so a big-endian section no longer skips every block after its header. `probe-net.mjs` now reports 2 records instead of 0, and `tests/pcapng-endian.test.ts` pins both orders to the same frames. |
| 2.1–2.4 emitted clients, 1.2–1.5 decoder and reassembly | open. The ranked fix plan at the end of this document is unchanged. |

The probe scripts still run and still fail the way they describe, except `probe-time.mjs`, which
now reports a `timestamp` field for a jittered clock — the point of keeping the probes is that the
answer to "is this fixed?" is a command, not a sentence.

---

## 1. `src/core/net/` and `src/core/pcap/`

### 1.1 A big-endian pcapng parses as an empty capture

`parsePcapng` reads the first four bytes of every block with `c.u32('le')` before it knows the
section's byte order (`reader.ts:143`). When the section is big-endian the block-type word for an
IDB is `00 00 00 01`, which reads little-endian as `0x01000000`; the type test fails, the block is
skipped, and so is every enhanced packet block after it.

The result is `{ format: 'pcapng', records: [] }` — no exception, no warning about the format. The
pipeline then reports `no TCP or UDP payload was decoded from this capture`, which is the message it
prints for a file that genuinely contains no IP traffic. A reader is told their capture is empty when
it is not.

```
=== big-endian pcapng, 2 TCP segments ===
  format pcapng, records 0
  frames 0, skipped 0
  flows 0
```

The section byte-order magic at offset 8 is read correctly; only the block types are not. Fix: read
`rawType` with the endianness of the current section, keeping the SHB as the one block whose type is
byte-order independent.

### 1.2 A truncated record silently discards the rest of the file

`parsePcap` stops at the first record whose captured length exceeds what the file still holds
(`reader.ts:119`: `if (captured > c.remaining) break;`). Everything after it is dropped, and the
function returns a shorter, valid-looking record list. A capture whose last write was interrupted by
a crashed capture daemon therefore analyses as whatever arrived before the break, with no indication
that the file was cut.

```
=== pcap record claiming 500 more captured bytes than the file holds ===
  format pcap, records 0
```

A truncated file is not the same as a small file, and the two currently look identical. Fix: keep the
records read so far, and record a truncation flag on `RawCapture` that the pipeline turns into a
warning.

### 1.3 A sequence jump allocates the whole gap in memory

`reassembleTcp` places segments by offset and then allocates one buffer covering the span
(`flows.ts:133-134`). The span is whatever the sequence numbers say it is. One stray frame from a
reused four-tuple — or a capture with a single corrupted sequence number — is enough to ask for a
gigabyte of zeros.

```
=== sequence jump of 40 MB (a stray frame from another connection) ===
  ok after 1ms, allocated 41943046 bytes, gaps [[5,41943040]]

=== sequence delta at exactly 2^31 ===
  (first run: RangeError: Cannot create a string longer than 0x1fffffe8)
```

Forty megabytes of zeros is not a stream anyone wants to run framing inference over, and the two
gigabyte case throws out of `buildFlows` rather than reporting anything. Fix: cap the accepted gap
(a hole wider than, say, 1 MB is evidence of a sequence-number discontinuity, not of a lost segment),
and report the discontinuity instead of materialising it.

### 1.4 The IPv4 more-fragments flag is ignored

`decodeIpv4` rejects non-first fragments by checking the fragment offset (`decode.ts:82`) but never
looks at the more-fragments bit. A first fragment is therefore decoded as a complete TCP segment.

```
=== IPv4 first fragment (MF=1, offset 0) ===
  frames 1, skipped 0
  fwd 40B gaps []
```

The bytes that follow in the datagram are never seen and nothing in the report says a packet was
fragmented. The `skipped` counter, which is surfaced as a warning, does not count this frame. Fix:
raise a `fragmented` limitation, or refuse the segment and count it as skipped.

The IPv6 equivalent behaves differently: a fragment extension header (next header 44) is not one of
the three extension headers the loop walks, so the whole frame is dropped and counted as skipped —
at least that is visible.

### 1.5 Four-tuple reuse is documented, and worse than the documentation implies

```
=== same 4-tuple, two conversations an hour apart ===
  fwd 8019B gaps [[18,8000]]
```

Two nineteen-byte messages become one 8019-byte stream with an eight-kilobyte hole. The gap is
reported, which is honest, but the framing inference downstream sees a stream that is mostly zeros
and still returns a hypothesis. The README mentions the merge; it does not mention that the merged
stream is what the next four layers run on.

---

## 2. `src/core/emit/`

The good news first, because it is the part that matters most: **the generated clients reproduce the
capture they came from, byte for byte.**

```
=== binary ===      decoded 10/10, round trip 10/10, verify() true 10/10
=== crc ===         decoded 10/10, round trip 10/10, verify() true 10/10
=== modbus ===      decoded 15/15, round trip 15/15
```

The `custom-crc` client embeds `crcCompute(data, 16, 0x8f57, 0x1234, true, true, 0x0)` and verifies
every message. That path works.

### 2.1 `decode()` throws on a length field it does not like

```
=== generated client.ts, 14-byte message ===
  the real message                               decoded, verify=true
  a length byte that says 1                      THREW ERR_OUT_OF_RANGE
  a length byte that says 0                      THREW ERR_OUT_OF_RANGE
```

The TypeScript client checks `buffer.length < total` and then reads `readUInt16LE(total - 2)`. When
`total` is smaller than the trailer, the read is out of range and Node throws. The Python client has
the same hole with a different failure: `buffer[-1:1]` is `b''`, `int.from_bytes(b'')` is `0`, and it
returns a message whose checksum is zero.

This is the client the tool hands to someone who is about to point it at a target. The first
malformed response crashes it. Fix: bound `total` to `[HEADER_LENGTH + TRAILER_LENGTH, buffer.length]`
before any read, in both languages.

### 2.2 `verify()` measures against the wrong length

```
  same message with one trailing byte            decoded, verify=false
  two messages concatenated (a stream read)      decoded, verify=false
```

Both emitters end `verify()` with `compute_checksum(buffer[0 : len(buffer) - 2])`. `buffer.length` is
the caller's buffer, not the message's length. A stream reader almost always holds more than one
message, and then `verify()` returns false for a message that is perfectly valid. The one context the
function exists for is the one where it fails.

### 2.3 The mutation harness mutates past the field width

`fuzz.ts` emits, for any integer field:

```python
return Message(**{**message.__dict__, target: rng.randrange(0, 1 << 16)})
```

`1 << 16` regardless of whether the field is one byte. For `type` (one byte in the Modbus capture)
every iteration that picks this target produces a value above 255, `to_bytes(1, "big")` raises
`OverflowError`, and the harness catches it and adds one to `error`. Half the mutation budget is
spent generating exceptions, and the summary line calls them protocol errors.

The same file also calls `sock.recv(65535)` once and treats a partial read as an undecodable reply,
which conflates TCP segmentation with a protocol failure.

### 2.4 The Lua dissector has no floor on the message length

`dissector.ts` emits `local total = <length field>` and then reads
`buffer(cursor + total - 2, 2)` and `buffer(cursor + 3, 2)` with no check that `total` can hold the
header and the trailer. In Wireshark, `buffer(offset, len)` past the end of the tvb raises, and the
dissector stops with an error instead of showing a bad message. A `total < HEADER_LENGTH +
TRAILER_LENGTH` guard before the first read fixes it.

---

## 3. `src/core/infer/`

### 3.1 CRC recovery returns a parameter set that is not the protocol's

This is the finding that matters, because it is the feature the product is named after.

Recovery is sound in the direction the documentation describes: it never invents a parameter set for
data that has none. Over 360 random message sets with no checksum, it reported nothing, 360 times.

```
=== recovery on random data with no checksum ===
       5       8      60         0
       5      10      60         0
       6      12      60         0
       6      20      60         0
       8      16      60         0
      10      24      60         0
```

The gap is in the other direction. **More than one parameter set can reproduce every message in a
capture, and the tool picks the degenerate one first.** Over 60 private 16-bit polynomials:

```
  the true set appears first   : 50
  the true set appears later   : 10
  the true set is not returned : 0
  more than one fully verified : 10
```

The sort in `crc-recovery.ts:173` breaks ties with `x.params.poly - y.params.poly`, ascending. A
degenerate polynomial like `0x3b` sorts before the real `0x8b75` for the trivial reason that it is a
smaller number. The consequence:

```
real parameter set  : poly 0x8b75 init 0x1094 xorout 0x0
reported set        : poly 0x3b   init 0x74   xorout 0x0   verified 8/8

agreement on messages that were not captured:
  body length  real value  reported value  agree
           10  0x4599     0x0034     NO
           11  0x37f0     0x00d0     NO
           ...
           64  0x3918     0x0082     NO

9 of 9 unseen bodies disagree with the real protocol.
```

And because the sort compares width before polynomial, an eight-bit degeneracy outranks a real 16-bit
one. Carried end to end through `analyzeFile` and `emitClient`:

```
captured message lengths: 16, 17, 18, 19, 20, 16, 17, 18
recovery candidates: 5
  poly 0x005f init 0x0020 ... 8/8
  poly 0x005f init 0x0020 ... 8/8
  poly 0x00d7 init 0x0020 ... 8/8
  poly 0x00d7 init 0x0020 ... 8/8
  poly 0xb42d init 0x2000 ... 8/8   <- the real one

field table embeds: checksum_crc8_5f poly 0x5f init 0x20

8 of 8 unseen bodies get the wrong checksum from the generated client.
```

Two separate defects are visible here. The tiebreak prefers the wrong candidate, and the same
candidate appears twice in the list, so `dedupe` is not merging sets that differ only in layout.

To be fair to the implementation: the Markdown report does say so, in a line of its own —

> _4 other parameter set(s) also reproduce this direction; the generated client embeds the first._

— and it carries the sentence *"A recovered CRC is exact for the messages captured and says nothing
about messages the capture never contained."* That is honest. What is not honest is that the caveat
lives in `report.md`, while `client.ts`, `client.py` and `dissector.lua` carry the degenerate
constants with no comment, and the README says only *"verified against the whole capture"* without
saying that several parameter sets can pass that test.

Ranked fix:

1. Order candidates by something that is not "smallest number". A real CRC polynomial has an odd
   number of terms in the vast majority of published tables; more importantly, prefer the candidate
   with the *longest* verified covered range and the *most* distinct message lengths, not the
   smallest coefficients.
2. When more than one set verifies, the emitted client must carry a comment naming the alternatives,
   and `emit` should refuse to pick one silently.
3. Add a test that uses a tie. Every existing recovery test uses a parameter set that recovers
   uniquely, which is why this survived.

### 3.2 The `timestamp` value domain is unreachable

The README lists `timestamp` as a field role the tool assigns, and `semantics.ts` has a rule for it.
Across all nineteen shipped captures — fixtures, benchmark corpus and recorded — no field is ever
given that domain:

```
value domains across every shipped capture:
  constant 34   counter 17   opaque 11   enum 11
  range 10      length 7     text 5      flags 3
```

That is not a sampling accident, it is structural. A four-byte field is only ever formed by
`findWideCounters`, which requires values that step by exactly one, or by the checksum placement. A
real clock never steps by exactly one:

```
=== a 4-byte unix timestamp at offset 0, jittered as a real clock is ===
  steps 1,1,1,1                       fields: sequence:counter@0:4 ...   domains: counter
  steps varying 1..6 ms               fields: magic:magic@0:3 payload    domains: constant
  steps 250, 90, 1000, 30             fields: magic:magic@0:2 type:opcode@2:1
  a 4-byte millisecond timestamp      fields: magic:magic@0:2 type:opcode@2:1
```

The last two are the bad cases: the varying low bytes of a clock are labelled `type:opcode`, at
confidence 0.8, and the report will then offer a value alphabet for a field that is a clock.

### 3.3 A field that steps by a constant other than one ends the header

```
=== a counter that steps by the record size, as an offset field does ===
  fields: magic:magic@0:1 payload:payload@1:var
```

An offset field advancing by 24 per record is ordinary in file and block formats. The group loop
classifies bytes one at a time and `break`s at the first byte that is neither constant, `+1` counter
nor small-alphabet opcode (`fields.ts:255`). Everything from there on becomes payload. Two small-set
bytes and a `+3` counter in the probe above were swallowed the same way.

The design document states the `+1` requirement; what it does not state is that the penalty for
missing it is the whole rest of the header, not one field.

### 3.4 A documented limitation that does not exist

`docs/crc-recovery.md` and the README limits table both say a private polynomial with
`refout != refin` is not searched. It is:

```
=== refin != refout with a private polynomial ===
  recovered 1 set(s); 1 verified on every message
```

The 32-bit exclusion is real: a private 32-bit polynomial returns nothing, as documented. Drift in
the safe direction, but it is still drift, and the documentation gate does not check prose like this.

---

## 4. `tests/`

The suite is stronger than most projects at this stage, and it is worth saying what it actually does
rather than only what it misses.

- `inference.test.ts:23` checks 13 catalogue algorithms against the published `"123456789"` check
  values, so the catalogue is verified against an external table instead of against itself.
- `inference.test.ts:148` compiles the generated TypeScript client with `tsc --strict` in a temporary
  directory, runs it, decodes a captured message, verifies the checksum, round-trips it, and confirms
  a corrupted message is rejected. That is an end-to-end test of an artifact, not of a function.
- `reassembly.test.ts` covers out-of-order arrival, retransmission, partial overlap, a reported hole,
  sequence wraparound, a mid-stream capture, and a mid-stream capture with a real hole.
- `robustness.test.ts` counts false positives across 50 deterministic random buffers and asserts a
  ceiling, which is the right shape for a heuristic.
- `scripts/benchmark.mjs` scores 12 unseen protocols against a manifest written before the tool runs.

Where it is thin, precisely:

1. **Every recovery test asserts the happy path.** Each builds messages from a parameter set that
   recovers uniquely (`0x8f57`, `0x3d65`, `0x1021`) and asserts that set comes back. None builds a
   capture where several sets verify. One test using `poly 0xb42d` over eight messages of five
   distinct lengths would have caught 3.1.
2. **No test feeds the generated client a malformed or multi-message buffer**, which is why 2.1 and
   2.2 are both live. The existing test hands `verify()` exactly one message, the one case where
   `buffer.length` happens to be right.
3. **Reassembly is tested as a function, not through a capture.** The three decoder defects — 1.1,
   1.2, 1.3 — all live between the file and `reassembleTcp`, a seam the tests do not cross with a
   malformed file.
4. **No test asserts that a value domain is reachable at all.** A single assertion that `timestamp`
   appears somewhere in the corpus would have failed, and that failure is the point.

---

## 5. What is solid

Worth stating plainly, because an audit that only lists defects is not a measurement.

- Checksum detection is correct on the whole catalogue. It found nothing on 360 random message sets,
  which is the failure mode that matters.
- CRC recovery is complete: across 60 private polynomials the true parameter set was never missing
  from the candidate list. It is the *ordering* that is wrong, not the search.
- Generated clients round-trip the capture byte for byte, in TypeScript and in Python, including the
  recovered-CRC path.
- TCP reassembly handles out-of-order, overlap, retransmission, wrap and mid-stream capture correctly,
  and reports holes rather than filling them silently.
- The framing layer's false-positive rate on noise is measured and low (3 in 200 buffers clear the
  confidence bar), and the fix that got it there — requiring a second structural column — is a real
  insight rather than a threshold tweak.
- The documentation gate (`scripts/check-docs.mjs`) is a genuinely good idea and found eight real
  drifts when it was first run.

## 6. Fix order

| Priority | Defect | Why first |
|---|---|---|
| 1 | 3.1 recovery tiebreak and duplicate candidates | produces a wrong client from a valid capture, silently |
| 2 | 2.1 / 2.2 generated client bounds and verify length | the emitted artifact crashes or lies on ordinary input |
| 3 | 1.1 big-endian pcapng | a valid file reports as empty |
| 4 | 1.2 truncated pcap | a partial file reports as a complete analysis |
| 5 | 1.3 unbounded gap allocation | a corrupt capture allocates gigabytes |
| 6 | 3.2 / 3.3 field model coverage | the header stops at the first field it cannot name |
| 7 | 2.3 / 2.4 harness and dissector guards | the tooling around the tool |
| 8 | 1.4 / 1.5 fragmentation and tuple reuse | reported, but not characterised |
| 9 | 3.4 documentation drift | harmless, but the gate should catch it |

Each of the first five is a small change with a test that this audit already demonstrates how to
write.

# How the inference works

This document explains what each step actually computes, so a surprising result can be traced
back to the step that produced it. It also lists the failure modes with their symptoms, because
those are more useful than a list of features.

The pipeline is:

```
bytes -> flow -> reassembly -> framing -> field model -> checksum
      -> recovered CRC -> value semantics -> conversation grammar -> family label
```

Each stage is allowed to say "no". Nothing invents structure to avoid an empty result.

## 1. Framing

Input: the reassembled byte stream of one direction.

The enumerator produces candidate segmentations. A candidate is kept only if it splits the
stream into at least three messages and consumes it exactly — the final message must end on the
last byte. That single rule discards most wrong frame lengths, because an incorrect length that
happens to fit the first message will not land on the end of the buffer.

**Length-prefixed.** For every combination of:

- length-field offset `0..8`
- width `1`, `2`, `4`
- endianness `le`, `be` (width 1 has no order)
- bias `-6..12`, where `total = value + bias`

the stream is walked and segmented. The bias collapses the usual variants (`length` includes
itself, includes the header, excludes the trailer) into one parameter.

Score:
`0.92 - 0.025·min(|bias|, 8) - 0.015·offset (+0.02 for 16-bit, +0.02 for 6+ messages)
− 0.20 if the field never varied − 0.22 if it was zero in more than half the messages`

The two penalties exist because of a real capture. MBAP headers are full of `0x00` bytes, so a
1-byte "length" at offset 0 with bias +4 happily tiles a Modbus stream into four-byte messages.
A length field that never varies is fixed-size framing with an extra claim attached; a length
field that is zero in most messages is a constant byte plus a bias. Neither is evidence of
length-prefixed framing, and both are demoted rather than silently accepted.

When two parameterisations produce the same boundaries — a 2-byte length at offset 4 and a
4-byte length at offset 2 are indistinguishable when the bytes between them are a constant zero
— the tie breaks on a width prior: 16-bit, then 8-bit, then 32-bit. The data cannot settle it;
the prior decides, and the report says so by listing the alternatives.

**Start-marker.** Markers are the first 2, 3 and 4 bytes of the stream. The stream is split at
every occurrence and the marker must begin every message. All-zero and all-`0xff` markers are
rejected: they are padding runs, not boundaries. Nested markers (`aa55` and `aa5503`) produce
identical segmentations; only the shortest is kept, and longer ones lose 0.02 per extra byte.

Score: `0.86 - 0.2 if any message < 6 bytes, - 0.02·(width - 2)`.

**Delimiter.** `0a`, `0d0a`, `0d`, `00`, `0000`, `ff`, `03`. Split after every terminator; a
short trailing residue rejects the hypothesis. Score `0.80`, `+0.06` when at least 90% of
messages are printable text.

**Fixed.** Every divisor of the stream length between 4 and 1024. Weakest family; score starts
at `0.55`. Only the two best fixed hypotheses are reported, because divisors of any length
produce a crowd of them.

**Unframed.** Always present at `0.20` so the ranking has a floor and the report can say "no
boundary was found" rather than failing.

The winner is reported only when its score is at least `0.60`. When the top two are within
`0.05`, the report states that the framing is unconfirmed and names the runner-up.

**Symptom of a wrong winner:** the message count is implausible for the exchange you recorded
(e.g. 40 messages for a 3-request session), or the field table has many one-byte `unknown`
fields. Check the runner-up.

## 2. Fields

Input: the messages from the winning segmentation, plus the length-field parameters.

Single-offset statistics across all messages:

| Observation | Primitive |
|---|---|
| all messages equal | `const` |
| strictly `+1 mod 256` between consecutive messages | `counter` |
| otherwise | `var` |

Printable runs are deliberately **not** a primitive. A variable ASCII run inside a binary-framed
message is data: a constant word is already captured as `const` and relabelled as text by the
semantics pass, while a variable one is the start of the payload. Treating it as a header field
invents a boundary that is not there — the mistake this rule exists to prevent is a "text" field
swallowing the first four characters of every command word.

Before grouping, wide counters are searched: widths 2 and 4 at offsets inside the first 24 bytes,
both endiannesses, requiring distinct values and exact `+1` steps modulo the width. This runs
first because a two-byte little-endian counter otherwise looks like a constant byte followed by a
stepping byte. Offsets are tried low to high and widths narrow to wide, so the reported field is
the smallest reading the data supports: a counter whose upper bytes never moved is reported as
2 bytes, not 4.

Grouping, left to right:

1. Leading constant run of up to 4 bytes → `magic`.
2. The length field span → `length`.
3. A wide counter span → `sequence` (2 or 4 bytes).
4. Single-byte stepping → `sequence` (1 byte, confidence 0.88).
5. Constant run → `reserved`.
6. A `var` offset becomes `type` when its value repeats enough to be a type rather than data:
   the distinct count must stay under `max(6, 75% of messages)`, and the byte must not be
   printable in every message — the first letter of a command word varies like a type and is not
   one. A 2-byte reading wins over a 1-byte one only when pairing the bytes actually shrinks the
   alphabet, which is what a 16-bit type does and what "type plus the first data byte" does not.
   At most one type field per direction is accepted; a second low-cardinality byte is data that
   happens to repeat.
7. After the type, only a counter is accepted. A constant or printable run there is payload that
   happens to repeat, and the header ends.
8. Anything else ends the header; the remainder is `payload`.

A detected checksum is appended as a tail-anchored field at `len - offsetFromEnd - width`, so it
stays correct when payload lengths vary.

Head fields are inferred from the common prefix only, because bytes past the shortest message are
different fields in different messages. When message length varies, the report says so and marks
the payload as variable.

**Symptom of a wrong boundary:** a `type` field whose values include implausible noise, or a
`payload` that starts one byte early. Compare the field table against four hex messages by hand;
the report prints them for exactly this reason.

## 3. Checksums

Input: the messages, unmodified.

Twenty-six algorithms across three widths:

```
8-bit   sum8  xor8  crc8  crc8/itu  crc8/rohc  crc8/maxim  crc8/darc
        crc8/sae-j1850  crc8/autosar  crc8/cdma2000
16-bit  sum16  inet16  fletcher16  crc16/ccitt-false  crc16/xmodem  crc16/aug-ccitt
        crc16/genibus  crc16/t10-dif  crc16/profibus  crc16/kermit  crc16/x25
        crc16/modbus  crc16/arc  crc16/dnp
32-bit  fletcher32  adler32  crc32/ieee  crc32/c  crc32/mpeg2  crc32/bzip2
```

Every algorithm is expressed through one canonical CRC function, with the polynomial in normal
form and `refin`/`refout`/`xorout` explicit. That is what makes a recovered parameter set directly
comparable to a published one instead of merely similar to it.

For each algorithm, the search enumerates field width, field position (`0..4` bytes from the
end), covered range start (`0..8`), and endianness. Because the catalogue is now large, the first
pass runs on a spread sample of at most 32 messages; every survivor is then re-verified on the
whole direction, and the reported agreement is over all messages. A candidate is reported only
when it matches at least 95% of messages — in practice a real checksum matches 100%.

**Symptom:** a checksum that is real but computed over a range starting past byte 8 is not found.
It appears as no candidate rather than a wrong one.

## 4. Recovered CRC parameters

When the catalogue finds nothing, the parameters are solved instead of guessed. The full
derivation and its two ambiguities are in **[crc-recovery.md](crc-recovery.md)**; the short
version:

1. Two messages of equal covered length cancel init and xorout under xor, leaving one equation in
   the polynomial. Enumerate odd polynomials, both reflections, four field layouts.
2. For each survivor, solve init from a GF(2) system built from two messages of *different*
   length, then derive xorout from any one message.
3. Recompute the check field of every message. Anything short of 100% is discarded.

This runs on the strongest flow only, because it costs a few hundred milliseconds per direction
and a capture with twenty conversations does not need twenty solves.

Reported when it succeeds: polynomial in both normal and reflected form, init, xorout, refin,
refout, the covered range, and any ambiguity the capture could not settle.

**Symptom of a useless result:** `init` marked ambiguous while every message has the same length.
That is not a defect — the capture genuinely lacks the information.

## 5. Value semantics

Input: the messages and the field model.

Each numeric field is classified from its decoded values, in this order:

| Test | Domain | Confidence |
|---|---|---|
| one distinct value | `constant` | 0.95 |
| equals `len - c` for a constant `c`, every message | `length` | 0.90 |
| role is `counter` | `counter` | 0.95 |
| role is `checksum` | `opaque` | 0.95 |
| only 0 and 1, both present | `boolean` | 0.90 |
| every byte printable ASCII | `text` | 0.80 |
| 4 bytes inside the unix seconds or milliseconds window | `timestamp` | 0.70 |
| ≤ 3 bits ever set, values not consecutive | `flags` | 0.60 |
| ≤ 8 distinct values, each seen at least twice | `enum` | 0.75 |
| anything else | `range` | 0.40 |

The printable check comes **before** the timestamp check on purpose: `"chan"` read as a 32-bit
big-endian integer is 1667331182, which is 22 July 2022. Four ASCII bytes land in the unix window
often enough that the ordering decides correctness, not taste.

Payloads are then read whole. If at least 90% of payload bytes are printable, the payload is text
and is tokenised: the first token becomes a verb, later positions are typed as integer, decimal,
IPv4 address, identifier or quoted string, and positions that never vary are reported as
constants. Otherwise printable runs of 3–32 bytes are located by offset and kept when they appear
at the same offset in at least half the messages, and a fixed-record layout is reported only when
payload lengths are multiples of a small size **and** at least a quarter of the byte columns never
change.

## 6. Conversation grammar

Input: the messages from both directions.

Messages are merged by timestamp, with the request sorted before the response when a burst shares
one timestamp — without that tie-break, a segment carrying two messages pairs backwards and every
latency figure after it is wrong.

Pairing is FIFO: the oldest unanswered forward message takes the next reverse message. That is
right for strict request/response protocols and for pipelining, and wrong for anything that
answers out of order, which the notes say out loud.

From the pairing:

- **latency** — min, median and max round trip
- **call shapes** — which request label drew which response label, and how often
- **handshake** — the leading run of exchanges whose pair never recurs later, capped at six and
  reported only when at least three exchanges follow it
- **pipelining** — whether more than one request was ever outstanding

The handshake list is the practical output: it is where a replay has to start.

## 7. Protocol family

Input: everything above.

A family is named only when at least two independent structural signals agree, and the match is
written as "consistent with", never "is". Port numbers count as one signal and are never the
reason: a server on 502 that frames like Modbus is Modbus, a server on 502 that frames like
nothing in particular is a server on 502.

Modbus/TCP, for instance, needs the MBAP length bias at offset 4, the constant protocol identifier
at bytes 2–4, the unit identifier, and function codes in range — and is rejected outright if a
checksum field was found, because Modbus/TCP has none.

Four or more signals score 0.95, three score 0.85, two score 0.70.

**Symptom of a wrong label:** one signal is present for an unrelated reason. Two signals is a low
bar by design; read them before trusting the name.

## 8. Message transitions

Messages from both directions are merged by timestamp. Each is labelled from the `type` field
when one exists, otherwise from direction and a length bucket. Consecutive labels become edges.

This is a first-order Markov graph, not a grammar. It finds handshakes and reveals which response
follows which request. It cannot tell you that a field must be `0x02` before `0x10` is legal.

## Failure modes, by symptom

| Symptom | Likely cause | What to do |
|---|---|---|
| `unframed`, score 0.20 | fewer than 3 messages, or framing that fits none of the families | capture a longer session |
| Two hypotheses within 0.05 | the protocol genuinely fits both descriptions | read the field table for both; the wrong one usually produces garbage field names |
| `reserved` where you expect a type field | the field never varied in this capture | capture both sides of the exchange |
| Counter detected at a fixed offset, confidence 0.88 | a data byte that happened to step | check whether the values wrap at 0xff in order |
| Payload one byte too long | a field at the end of the header varies too much to classify | inspect the four hex messages the report prints |
| No checksum candidate | covered range past byte 8 | the recovery pass tries a smaller layout set; extend it with `options.layouts` |
| CRC recovery finds nothing | fewer than five messages, a constant check field, or no two messages of equal covered length | capture more traffic |
| A four-byte field labelled `timestamp` | an ASCII word that happens to read as a plausible date | it should not happen; the printable check runs first, so report it |
| Latency of 0.00 ms | both messages arrived in one segment | expected; the capture has no finer timing |

## What this method cannot do

- Prove a field boundary. It reports the most likely one, with a confidence and a competing
  hypothesis.
- Name a message type. `type=0x10` is a value, not "read request". The family label narrows the
  vocabulary; the mapping is yours.
- Recover encryption. Ciphertext is high-entropy noise to these statistics.
- Work on a single message. Everything here is a comparison across messages.

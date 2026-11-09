# How the inference works

This document explains what each step actually computes, so a surprising result can be traced
back to the step that produced it. It also lists the failure modes with their symptoms, because
those are more useful than a list of features.

The pipeline is:

```
bytes  ->  flow  ->  reassembly  ->  framing hypotheses  ->  field model  ->  checksum  ->  state graph
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

Score: `0.92 - 0.025·min(|bias|, 8) - 0.015·offset (+0.02 for 16-bit, +0.02 for 6+ messages)`.

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
| every byte printable ASCII | `printable` |
| otherwise | `var` |

Before grouping, wide counters are searched: widths 4 and 2 at offsets inside the first 24 bytes,
both endiannesses, requiring distinct values and exact `+1` steps modulo the width. This runs
first because a two-byte little-endian counter otherwise looks like a constant byte followed by a
stepping byte.

Grouping, left to right:

1. Leading constant run of up to 4 bytes → `magic`.
2. The length field span → `length`.
3. A wide counter span → `sequence` (2 or 4 bytes).
4. Single-byte stepping → `sequence` (1 byte, confidence 0.88).
5. Constant run → `reserved`.
6. Printable run of 2+ bytes → `text`.
7. `var` offset or pair with few distinct values → `type`, when distinct count is at most
   `max(6, 30% of messages)`.
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

Twelve algorithms:

```
sum8  xor8  crc8  crc8/itu
crc16/ccitt-false  crc16/xmodem  crc16/modbus  crc16/arc  sum16
crc32/ieee
```

For each algorithm, the search enumerates field width, field position (`0..4` bytes from the
end), covered range start (`0..8`), and endianness. A candidate is reported only when it matches
at least 95% of messages — in practice a real checksum matches 100%, and anything less means the
algorithm is wrong.

The enumerator is small on purpose: roughly 810 configurations per algorithm, each linear in
message count. It runs in milliseconds on the fixtures and seconds on a few thousand messages.

**Symptom:** a checksum that is real but computed over a range starting past byte 8, or with a
non-standard seed, is not found. Those appear as no candidate rather than a wrong one.

## 4. Message transitions

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
| Payload one byte too long | a field at the end of the header varies too much to classify | lower the opcode threshold or inspect the four hex messages |
| No checksum candidate | non-standard seed, or range beyond byte 8 | verify manually with the algorithm list |

## What this method cannot do

- Prove a field boundary. It reports the most likely one, with a confidence and a competing
  hypothesis.
- Infer semantics. `type=0x10` is a value, not "read request". That mapping is yours.
- Recover encryption. Ciphertext is high-entropy noise to these statistics.
- Work on a single message. Everything here is a comparison across messages.

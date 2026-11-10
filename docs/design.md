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
last byte.

Exact consumption alone is weak evidence, and this was measured rather than assumed: on random
buffers, "explains every byte" cleared a naive confidence bar in 16 of 40 cases. A random walk whose
step is a byte value lands exactly on the buffer end about once per hundred hypotheses, and the
search tries a thousand hypotheses per stream. So a length-prefix candidate must also show a second
regularity that the length field cannot produce by itself: at least two byte columns in the message
headers that are constant, drawn from a small set, or a counter stepping by a fixed amount. Random
data supplies those about once in a million parses; a real header supplies them because a magic, a
type, a length high byte and a counter all sit there. Without that corroboration the candidate loses
0.36, which puts it below the confidence bar while still listing it as a runner-up.

**Length-prefixed.** For every combination of:

- length-field offset `0..8`
- width `1`, `2`, `4`
- endianness `le`, `be` (width 1 has no order)
- bias `-6..12`, where `total = value + bias`

the stream is walked and segmented. The bias collapses the usual variants (`length` includes
itself, includes the header, excludes the trailer) into one parameter.

Score:
`0.92 - 0.025·min(|bias|, 8) - 0.015·offset (+0.02 for 16-bit, +0.02 for 4+ messages)
− 0.20 if the field never varied − 0.22 if it was zero in more than half the messages
− 0.30 if the stream and the field are printable text − 0.35·(share of messages under four bytes)
+ 0.06 if the header shows a structural column, − 0.36 if it does not`

The penalties exist because of real captures. MBAP headers are full of `0x00` bytes, so a 1-byte
"length" at offset 0 with bias +4 happily tiles a Modbus stream into four-byte messages: a length
field that never varies is fixed-size framing with an extra claim attached, and a length field that
is zero in most messages is a constant byte plus a bias. Syslog over UDP is printable text in which
any ASCII byte can act as a length, and a one-byte length that is itself a printable character is
demoted. MQTT's DISCONNECT is two bytes, so a parse made of tiny fragments is penalised by share
rather than rejected — one legitimate short message must not hide the framing, a stream of them is
a tiling.

When two parameterisations produce the same boundaries — a 2-byte length at offset 4 and a
4-byte length at offset 2 are indistinguishable when the bytes between them are a constant zero
— the tie breaks toward the narrowest field: 16-bit, then 8-bit, then 32-bit. The data cannot
settle it; the prior decides, and the report says so by listing the alternatives. The benchmark
measures the consequence: five of twenty framing checks report a field narrower than the
specification, with byte-identical boundaries.

**Start-marker.** Markers are the first 2, 3 and 4 bytes of the stream. The stream is split at
every occurrence and the marker must begin every message. All-zero and all-`0xff` markers are
rejected: they are padding runs, not boundaries. Nested markers (`aa55` and `aa5503`) produce
identical segmentations; only the shortest is kept, and longer ones lose 0.02 per extra byte.

A wider marker is also checked against its own first two bytes. If those occur far more often than
the wider marker starts messages, the wider marker is a marker plus data: on a capture whose header
was `a5 5a` plus a length byte, the three-byte `a5 5a 1f` appeared only for one message length and
swallowed forty-eight messages at a time, scoring higher than the real two-byte marker. The fix is
proportional: the hypothesis loses `0.35 × share of first-two-byte occurrences that are not message
starts`.

Score: `0.86 - 0.2 if any message < 6 bytes, - 0.02·(width - 2)`.

A length-prefix parse is checked against every competing marker: each occurrence of the marker is a
boundary under the marker parse, and any occurrence the length parse treats as payload costs
`0.3 × share missed`. Two parses that both explain every byte cannot be separated by coverage; the
repeated marker is the evidence that one of them dropped a boundary.

**Delimiter.** `0a`, `0d0a`, `0d`, `00`, `0000`, `ff`, `03`. Split after every terminator; a
short trailing residue rejects the hypothesis. Score `0.80`, `+0.06` when at least 90% of
messages are printable text.

**Fixed.** Every divisor of the stream length between 4 and 1024. Weakest family; score starts
at `0.50`, and `+0.08` for a plausible size puts it at `0.58`, below the confidence bar. Any
stream length has divisors, so a fixed-size claim is reported as a hypothesis and never used to
build a field model on its own. Only the two best fixed hypotheses are reported.

**Unframed.** Always present at `0.20` so the ranking has a floor and the report can say "no
boundary was found" rather than failing.

The winner is reported only when its score is at least `0.60`. When the top two are within
`0.05`, the report states that the framing is unconfirmed and names the runner-up.

**Symptom of a wrong winner:** the message count is implausible for the exchange you recorded
(e.g. 40 messages for a 3-request session), or the field table has many one-byte `unknown`
fields. Check the runner-up.

## 2. Fields

Input: the messages from the winning segmentation, plus the length-field parameters.

Only the common prefix of every message can carry a head field: past it, the shortest message has
no byte to read. Every column of that prefix is classified first and named second, because a walk
that stops at the first byte it cannot name throws the rest of the header into the payload — that
single behaviour cost this model more accuracy than every other rule combined.

| Observation | Primitive |
|---|---|
| inside the length-field span | `length` |
| all messages equal | `const` |
| a constant non-zero step mod 256 (1, 1, 1 or 24, 24, 24) | `step` |
| distinct count under `max(4, 60% of messages)` | `set` |
| otherwise | `var` |

Named left to right, each rule requiring evidence the one before it did not:

1. The length-field span → `length`.
2. A field wider than one byte, at this offset → `sequence`, or `timestamp` when four bytes land in
   the epoch window. The requirement is a constant positive step, not a step of one: a byte offset
   advancing by 24 per record is an ordinary field. Both byte orders are tried and the reading whose
   value advances by the smaller amount wins, because a big-endian counter `00 01`, `00 02` read
   little-endian also steps — by 256.
3. Four columns that are printable in every message → the body starts here.
4. A leading constant run → `magic`, at most 4 bytes, and only as far as the run stops being
   printable: `09 01` followed by `status ok` is a two-byte header on a text body.
5. A constant run → `reserved`, at most 8 bytes. Longer is padding or a repeated word.
6. A stepping byte → `sequence`, one byte.
7. A small alphabet → `type`, at most two per direction. A byte that is printable in every message
   is never a type: the first letter of a command word varies like one and is not one. A 2-byte
   reading is preferred only when pairing the bytes shrinks the alphabet.
8. After a type, only a length, a stepping value, a wide field, or a constant run of at most two
   bytes that leads straight into one of those — or that leaves a body large enough to be a body —
   is still header. Modbus answers begin with a constant register high byte that runs into data.
9. A `var` run of at most 8 bytes → `unknown`, and the walk continues, so a request id that matches
   nothing no longer hides the length field behind it. A longer run is the body.

A detected checksum is appended as a tail-anchored field at `len - offsetFromEnd - width`, so it
stays correct when payload lengths vary. When at least 90% of the bytes after the header are
printable, the body field is `text` rather than `payload`: a terminator-delimited protocol has a
byte-level header too, and reporting a single text field from offset 0 loses it.

Head fields come from the common prefix, so when message length varies the report says so and marks
the body as variable.

**Symptom of a wrong boundary:** a `type` field whose values include implausible noise, or a
`payload` that starts one byte early. Compare the field table against four hex messages by hand;
the report prints them for exactly this reason.

## 3. Checksums

Input: the messages, unmodified.

Thirty algorithms across three widths:

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

Three rules keep a coincidence out of the report:

- **Six messages minimum.** Five equal-length messages whose bodies xor to zero produce a perfect
  `xor8` match on the byte outside the range. That is arithmetic, not a protocol.
- **The check field must vary.** A constant trailer byte is not a checksum; it is a delimiter or a
  terminator that a weak algorithm over a fixed range happened to reproduce.
- **Abandon early.** A candidate that misses more than 5% of the sample is dropped while hashing,
  not after. On a flow of kilobyte messages this is the difference between twelve seconds and
  one: a wrong candidate usually dies on its first message.

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
| role is `timestamp` | `timestamp` | 0.85 |
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

## Cost

Measured with `npm run profile` on two synthetic captures of 20 000 frames: one stream of 20 000
messages, and two hundred flows of one hundred messages each.

| Stage | single stream | many flows |
|---|---|---|
| load and decode | 0.15 s | 0.09 s |
| group into flows | 0.13 s | 0.09 s |
| one flow | 2.3 s | 0.03 s |
| whole capture (four flows) | 2.3 s | 0.37 s |

Three stages were quadratic or duplicated and are not any more:

- `timestampAt` scanned every segment for every message — 400 million comparisons on a
  twenty-thousand-message stream. It is a binary search over the segment table.
- `analyzeCapture` analysed every flow and then kept four. Candidates are now ranked by carried
  bytes and a shortlist is analysed, so a two-hundred-conversation capture does not pay for two
  hundred analyses.
- The winning flow was analysed a second time to run CRC recovery, even when recovery found
  nothing. The second pass now runs only when the search actually recovers a parameter set.

What remains is per-message work: hashing the checksum sample, copying message slices, labelling.
No algorithm is super-linear any more, and a native rewrite would mean a second implementation of
every rule above. The measured ceiling is about 0.7 MB/s of payload; a 100 MB capture takes roughly
two and a half minutes. For a file a person opens in a terminal that is ample, so the answer to
"should this be Rust" is not yet.

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

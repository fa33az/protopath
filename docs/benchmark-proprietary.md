# Proprietary protocol benchmark

Twelve hand-written captures are a test set, not a benchmark. They were written by the same hands
that wrote the inference, they name their own answer, and after the first pass any rule that fits
them is a rule fitted to them. The question that actually matters is the one the tool exists for:

> Given a protocol nobody has seen, how much of it does the tool get right?

Nothing in this document was measured on a protocol a person wrote. Every capture below is drawn
from a parameter space — framing family, header primitives and their order, checksum family and
placement, payload style — serialised from a seed, and scored against a manifest written before the
inference runs.

```console
$ npm run build
$ npm run bench:proprietary:corpus     # writes 120 captures and their manifest
$ npm run bench:proprietary            # scores them
```

Everything is deterministic. Seed 37 always produces the same bytes.

---

## What the corpus is

`bench/proprietary/make-proprietary.ts` draws one protocol per seed from:

| Dimension | Values |
|---|---|
| transport | TCP, UDP |
| framing | length-prefix (62%), start marker (16%), delimiter (16%), unframed (6%) |
| length field | offset anywhere in the header, width 1/2/4, either endianness, bias −6…+6 |
| header | magic, version, type, counter (1/2/4 bytes, step 1 or 2–12), timestamp, flags, reserved, in a random order |
| checksum | CRC with a private 16-bit polynomial, six named CRCs, sum8, xor8, sum16, fletcher16, fletcher32 — or none (30%) |
| checksum placement | 0 or 1 bytes from the end, covered range starting at byte 0–4 |
| payload | ascii key/value, ascii words, structured binary, random noise |

Two properties make the answers trustworthy:

1. **The generator checks itself.** Every CRC it uses is verified against the published check value
   for `"123456789"` before a single capture is written. A wrong CRC would corrupt every ground
   truth in the corpus, silently.
2. **The framing bytes are really there.** An early version of this generator declared a start
   marker without ever writing it into the stream, and declared a terminator the messages did not
   end with. The tool was then scored against a truth the bytes did not contain — and it lost. The
   generator now writes the marker at the head and the terminator at the tail of every message, and
   retries until those bytes occur exactly once per message. A protocol whose own framing bytes sit
   inside its header cannot be split by anyone, and scoring against it measures nothing.

The corpus lives in `bench/proprietary/corpus/` and is not committed; the generator is.

---

## How it is scored

Six questions per capture, each scored separately, because a tool that finds the boundaries and
then mislabels every field has not succeeded:

| Question | What has to be right |
|---|---|
| boundaries | message count and every byte offset |
| family | which of the five framing families |
| lengthField | offset, width, endianness and bias of the length field |
| header | how many leading bytes are structure rather than body |
| counter | the stepping field, at the right offset, named as a counter |
| checksum | a real check field found, or silence where there is none |

Every miss is then sorted into one of two bins. This distinction is the point of the benchmark:

- **ambiguous** — the bytes cannot separate the reported answer from the truth. A four-byte
  big-endian length `00 00 00 33` is also a two-byte length at offset +2. A message that starts
  with a constant marker and also ends with a terminator reads as either family. Reporting one of
  them is not an error; what matters is whether the tool says the other is still standing.
- **wrong** — the truth's own rule does not reproduce the reported answer. This is the number
  worth driving down.

The scorer decides which bin a miss belongs to by replaying the truth's rule against the stream the
tool reported and comparing boundaries. It does not consult the tool's opinion.

---

## The score

120 protocols, 629 scored checks, over a run where the inference was not developed against these
captures:

| Question | Scored | Hit | Ambiguous | Wrong | Strict | Wrong |
|---|---:|---:|---:|---:|---:|---:|
| boundaries | 109 | 99 | 0 | 10 | 90.8% | 9.2% |
| family | 120 | 86 | 16 | 18 | 71.7% | 15.0% |
| lengthField | 73 | 30 | 38 | 5 | 41.1% | 6.8% |
| header | 109 | 71 | 0 | 38 | 65.1% | 34.9% |
| counter | 109 | 60 | 19 | 30 | 55.0% | 27.5% |
| checksum | 109 | 82 | 1 | 26 | 75.2% | 23.9% |
| **all** | **629** | **428** | **74** | **127** | — | — |

Read the `wrong` column, not the `strict` one. Boundaries are right on 90.8% of captures; nearly all
of the rest are captures where a delimiter parse and a marker parse disagree about the same byte
offsets. The length field is `wrong` on 5 of 73; the other 38 misses are a 16-bit length whose high
byte never moves in the capture, which is byte-for-byte identical to an 8-bit length one byte
later.

The skips are the unframed captures (nothing to find) and the checksum/header/counter questions on
captures with no confident framing claim.

---

## What this benchmark found

Every defect below was found by this corpus and fixed. The rate shown is the question's score on
the current corpus, so it measures the fix together with everything else that landed.

| Defect | Fixed by | Now |
|---|---|---|
| the header walk stopped at the first byte it could not name, and everything after it became payload | every column of the common prefix is classified first and named second; a short unnamed run is reported as `unknown` instead of ending the header | header 65.1% |
| the length field was searched only in the first 8 bytes of a message, so a header with a magic, version, type and counter put it out of reach | search window extended to 16 bytes | lengthField 41.1% strict, 6.8% wrong |
| a wide counter was only recognised when it stepped by exactly 1, so an offset field advancing by 24 per record was rejected | any constant step is a counter, at one byte or wider | counter 55.0% |
| `timestamp` was a documented value domain that no capture could produce | a four-byte field in the epoch range that advances by a constant amount is a timestamp | scored, never wrong |
| a delimited text protocol produced a single `text` field and no header model at all | the byte model runs on text protocols too, and the body is labelled `text` where the header ends | header scored |
| `0x0a` and `0x0d0a` parses both consumed the stream, and the shorter one split at every `0x0a` inside a checksum | a terminator whose occurrences are a subset of a longer one wins | family 71.7% |
| a coarse parse that treats real terminators as payload could outrank the delimiter parse that explains them | competing parses lose score in proportion to the terminators they split through | family |
| a counter's byte order was whichever the loop tried first, so a big-endian counter read as little-endian scored a step of 256 | both orders are tried and the smaller step wins | counter |

Three of these were not inference bugs at all. The first version of this benchmark scored the tool
against a corpus whose markers and terminators were never written, and against one-byte fields
recorded with a byte order the bytes cannot show. A benchmark that lies about its own answers
measures the lie.

The corpus changed twice while these fixes landed, so no column here is a controlled before and
after on identical input. The one series worth quoting: the header question was at 29.7% when the
corpus first told the truth, and it is at 65.1% now.

## Known limits this benchmark makes visible

These are not on the fix list because the bytes do not decide them. They are reported as
`ambiguous`, and the tool says so in the report:

1. **A length field whose high bytes never move.** 38 of 43 length-field misses. The reading is
   pinned by a width prior — 16-bit first, then 8-bit, then 32-bit — because 16-bit lengths are the
   common case in published protocols (Modbus, DNS, RADIUS); a capture with one message long enough
   to set the high byte resolves it.
2. **A marker that is also the message prefix plus a terminator.** 16 family misses. Both splits
   produce identical boundaries, so the family name is a coin toss and the report says a competing
   parse splits at exactly the same offsets.
3. **A two-byte counter whose high byte is constant across the capture.** 19 counter misses: the
   tool reports the two-byte reading, which covers the same bytes at the same offset, and the
   scorer calls that ambiguous rather than wrong.
4. **Where the header ends after the message type.** 38 header misses, the largest remaining
   bucket. In Modbus the body starts right after the function code; in a private protocol a flags
   byte and a reserved byte may sit after the type and before the body. The rule used is: a short
   constant run after the type is header only when a length or stepping field follows it, or when
   it leaves a body large enough to be a body. That is a judgement, and it is the one place where
   this model still guesses.

## Regression floor

CI runs the corpus and fails below 428 passing checks (`PROPRIETARY_FLOOR`). The floor is a
regression guard, not a target: raise it when a rule improves, never lower it to make a run green.
The captures are generated in CI, so the seed set cannot drift between runs.

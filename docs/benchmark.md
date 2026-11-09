# Benchmark

The fixtures in `captures/` were written while the inference layers were being developed, which
makes them a regression suite, not a test of generalisation. `bench/` is the other thing: protocols
written from their specifications, after the inference code was finished, and captures recorded from
libraries that never appeared in the test suite.

The ground truth is written before the tool runs. `bench/corpus/manifest.json` is produced by the
generator from the specification; `bench/recorded/manifest.json` describes the recorded captures.
Neither file is derived from protopath's output, and `npm run bench` fails when a claim and the
manifest disagree.

```console
$ npm run bench:corpus     # regenerate the written-from-spec captures
$ npm run bench            # score the tool against the manifest
```

## Corpus

| Capture | Protocol | Basis | Expected framing |
|---|---|---|---|
| `dns-tcp.pcap` | DNS over TCP | RFC 1035 §4.2.2, RFC 7766 | 2-byte big-endian length prefix |
| `postgres-v3.pcap` | PostgreSQL v3 | frontend/backend message format | 4-byte length after a type byte, bias +1 |
| `radius-auth.pcap` | RADIUS | RFC 2865 | 2-byte length at offset 2, bias 0 |
| `kafka-metadata.pcap` | Kafka Metadata v9 | Kafka protocol guide | 4-byte size, does not count itself |
| `stomp-1.2.pcap` | STOMP 1.2 | STOMP 1.2 frame termination | NUL terminator |
| `hl7-mllp.pcap` | HL7 v2 over MLLP | MLLP framing | `0x0b` start marker, `0x1c 0x0d` end |
| `coap-udp.pcap` | CoAP | RFC 7252 | none: the header is self-describing |
| `syslog-udp.pcap` | Syslog | RFC 5424 | none: one line per datagram |
| `ubx-serial.pcap` | UBX (u-blox) | u-blox protocol spec | `b5 62` sync; small-endian payload length; `CK_A` is a byte sum |
| `crc32-frame.pcap` | synthetic probe | CRC-32/ISO-HDLC | 4-byte length, 32-bit CRC at the tail |
| `real-mqtt.pcap` | MQTT 3.1.1 | amqtt broker, paho-mqtt client | 1-byte remaining length at offset 1 |
| `real-http.pcap` | HTTP/1.1 | `http.server`, `http.client` | line framing (see limits) |

The two recorded captures were produced by `bench/record/record_all.py`, which runs the real
libraries through a byte-level proxy and writes what they put on the wire. Re-running it records a
different session, so the bytes differ while the protocol does not.

## Scoring

Three inferences are scored independently, each as true positives, false positives and false
negatives:

- **framing** — the message boundaries. A confident claim with the wrong boundaries is a false
  positive; no confident claim where the specification has one is a false negative. When the
  boundaries are right but the reported field differs from the specification (a 4-byte length read
  as its low two bytes), it is counted as a true positive with a different field and reported
  separately: on this evidence the two readings are byte-identical.
- **checksum** — a real trailer must be found, and none may be invented.
- **family** — the protocol family label. The corpus protocols outside the rule set must stay
  unlabelled; MQTT and HTTP must be named.

## Result

Twelve captures, twenty-two direction-and-family checks:

```
framing   true positives 20  false positives 0  false negatives 0
          exact field shape 12, boundaries right with a different field 5
checksum  true positives 3   false positives 0  false negatives 0
family    true positives 2   false positives 0  false negatives 0
```

The five approximations are the length-field width ambiguity: PostgreSQL, Kafka and the CRC-32 probe
declare a field wider than the one reported, and every message in those captures is short enough
that the high bytes never move. The capture is honest about it; `docs/design.md` explains why the
narrower reading wins.

## What the benchmark changed

The corpus was written to be failed. Each of these defects was found by a protocol the tool had
never seen, and fixed at the rule that was wrong rather than at the capture:

| Symptom | Cause | Fix |
|---|---|---|
| PostgreSQL and Kafka field shapes were truncated | a width preference that always chose the 2-byte view of a 4-byte field | reverted to narrowest-field, with the ambiguity documented instead of resolved by guesswork |
| HL7 reverse stream parsed as length-prefixed | a 1-byte ASCII length tiled the frame body | length parses whose field bytes are printable text in a printable stream lose 0.3 |
| HL7 ACK stream produced a false `xor8` | five equal-length messages whose bodies xor to zero | a checksum field must vary, and fewer than six messages is not evidence |
| MQTT length parse was missed entirely | one legitimate two-byte message (DISCONNECT) rejected the whole hypothesis | tiny messages are penalised by share instead of rejecting the parse |
| Random 600-byte buffers cleared the confidence bar up to 40% of the time | "explains every byte" is nearly vacuous; a random walk lands exactly on the buffer end about once per hundred hypotheses | a length parse now needs two independent structural columns (constant magic, small type set, or a counter) or it loses 0.36 |
| A three-byte marker swallowed 48 messages and beat the real two-byte marker | wider markers were never checked against their own first two bytes | a marker whose first two bytes occur far more often than its message starts is a marker plus data |
| `readInt` crashed on 24-bit fields | width dispatch assumed 1, 2 or 4 bytes | any width reads as a loop |

Those seven are the reason the corpus exists. Six of the seven would have shipped silently: they
produced confident, plausible, wrong output.

## False positives on noise

The sweep in `tests/robustness.test.ts` runs fifty deterministic random buffers through framing: at
most one in ten may clear the confidence bar, and the current rate is 3 in 200. The residue is a
random stream that happens to contain two structural columns; it is reported, not hidden.

## Performance

`npm run profile` builds two synthetic captures and times each stage. On this machine (Node 24,
Windows):

| Capture | Frames | load + flows | one flow | whole capture |
|---|---|---|---|---|
| single stream, 20 000 messages | 20 000 | 0.2 s | 2.3 s | 2.3 s |
| two hundred flows, 100 messages each | 20 000 | 0.2 s | 0.03 s | 0.37 s |

Three changes came out of profiling:

- **`timestampAt` was quadratic.** One pass over every segment for every message: 400 million
  comparisons on a twenty-thousand-message stream. It is a binary search now.
- **Every flow was analysed, then four were kept.** A capture with two hundred conversations paid
  for two hundred analyses. The candidates are ranked by carried bytes and a shortlist is analysed.
- **The winning flow was analysed twice, always.** The second pass existed to run CRC recovery. It
  now runs only when recovery actually finds a parameter set, which skips the whole second pass on
  the common path.

Rust is not justified yet. The remaining cost is about 115 µs per message, spread across hashing
the checksum sample, copying message slices, and labelling messages; none of it is algorithmic
debt, and a rewrite would mean a second implementation of every rule in `docs/design.md` and a
native build step in the package. The measured ceiling — roughly 0.7 MB/s of payload, and a
100 MB capture in about two and a half minutes — is far above the size of capture a person opens
in a terminal. If a future workload needs more, the next steps are: stop copying message slices in
`walkLengthPrefix`, compute the checksum sample once per `(rangeStart, end)` pair instead of per
field width, and only then consider a native kernel for the polynomial search.

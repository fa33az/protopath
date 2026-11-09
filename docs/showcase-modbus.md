# Showcase: a real Modbus/TCP session

The other fixtures in this repository are synthetic, which makes them exact but circular: the
generator and the inference were written by the same hand. This capture is different. It was
recorded from a real industrial protocol implementation, and the expected layout comes from the
Modbus specification rather than from protopath.

## How it was recorded

```
pymodbus client  ──►  TCP proxy :15021  ──►  pymodbus server :15020
                            │
                            └─► every byte, both directions, written to pcap
```

`scripts/record-modbus.py` starts a pymodbus server holding coils and holding registers, a TCP
proxy in front of it, and a pymodbus client that performs fifteen mixed operations: read holding
registers, read coils, read discrete inputs, read input registers, write single register, write
single coil, write multiple registers, write multiple coils. One operation asks for an address
the server does not hold, so the session also contains a Modbus exception response.

The proxy records what the two libraries actually exchanged. No request or response byte is
written by this repository; only the surrounding pcap container and the frame headers are.

Recorded with `pymodbus 3.16.2` on Python 3.12.

```
$ python scripts/record-modbus.py captures/modbus-session.pcap
wrote captures/modbus-session.pcap — 30 frames
```

## What protopath recovered

```console
$ protopath analyze captures/modbus-session.pcap
```

| Field | Role | Offset | Width | Endian | Confidence | Evidence |
|---|---|---|---|---|---|---|
| `sequence` | counter | 0 | 2 | be | 0.95 | value increases by exactly 1 per message |
| `reserved` | reserved | 2 | 2 | — | 0.90 | `0x0000` in all 15 messages |
| `length` | length | 4 | 2 | be | 0.97 | decoding it reproduces every message length when 6 is added |
| `reserved_2` | reserved | 6 | 1 | — | 0.90 | `0x01` in all 15 messages |
| `type` | opcode | 7 | 1 | — | 0.80 | 8 distinct values across 15 messages |
| `payload` | payload | 8 | var | — | 0.60 | absorbs the rest, 12 to 19 bytes |

Framing: length-prefixed, 2-byte big-endian field at message offset 4, `total = value + 6`.
Both directions arrived at the same layout independently.

## Compared with the specification

| Modbus/TCP (spec) | protopath | Verdict |
|---|---|---|
| Transaction identifier, 2 bytes, big endian, incremented per request | `sequence`, 2 bytes, big endian, +1 per message | match |
| Protocol identifier, always `0x0000` | `reserved`, 2 bytes, constant `0x0000` | match |
| Length, 2 bytes, big endian, counts unit id and PDU | `length`, 2 bytes, big endian, bias +6 | match |
| Unit identifier | `reserved_2`, 1 byte, constant `0x01` | match |
| Function code | `type`, 1 byte, 8 values | match |
| No application-layer checksum | no checksum field reported | match |

The distinction between `reserved` and "protocol identifier" is real: a field that never varies
is a constant, and calling it a protocol identifier would be a claim the bytes do not support.
The report says `reserved` and the reader supplies the name.

## What the later layers said about the same bytes

The field table is only the start. On this capture the layers above it each produced something
checkable:

**Family.** Modbus/TCP, confidence 0.95, from four structural signals: the MBAP length bias at
offset 4, `0x0000` at bytes 2–4, a constant unit identifier at byte 6, and function codes in
range. Port 502 is not one of them — it happens to be the registered port here, and the label
would be the same on any port.

**Grammar.** Fifteen requests, fifteen responses, no unpaired message, median round trip 1.18 ms.
The pairing is what surfaces the one operation the PLC rejected:

```
10  type=0x04  type=0x84  1.18 ms
```

`0x84` is function code `0x04` with the Modbus error bit set. protopath has no idea what a
Modbus exception is; it paired an exchange and the byte appeared.

**Semantics.** The transaction identifier is a counter, the protocol identifier and unit
identifier are constants, the length field is a length (it equals message length minus six, which
the semantics pass checks directly rather than inferring from the framing), and the function code
is a `range` — eight distinct values across fifteen messages, no shape beyond that. The tool does
not claim to know what the codes mean.

```console
$ protopath trace captures/modbus-session.pcap
```

## What this capture exposed

Recording real traffic found three defects that the synthetic fixtures could not: the packet
headers were too regular to trigger them.

1. **Over-segmentation on zero-heavy streams.** A 1-byte "length" at offset 0 with bias +4 tiled
   the stream into 38 messages, because MBAP is full of `0x00` bytes. Fixed by requiring the
   length field to vary, and by penalising hypotheses whose length field is zero in most
   messages — those sizes come from the bias, not from the field.
2. **Ambiguous field width.** As a byte stream, a 2-byte length at offset 4 and a 4-byte length
   at offset 2 are identical, because the protocol identifier between them is a constant zero.
   The tie now breaks on the width prior (16-bit first), which selects the Modbus answer.
3. **Function codes suppressed by a strict threshold.** Eight distinct function codes over
   fifteen messages was above the old opcode threshold of 30% of messages. The rule now combines
   cardinality with a collapse test: a 16-bit type is preferred only when pairing the bytes
   actually shrinks the alphabet.

All three fixes are covered by `tests/real-world.test.ts`, which asserts the Modbus layout
against the values above.

## Limits this capture demonstrates

- `reserved` is not a name. The unit identifier and the protocol identifier are both constants
  here; the tool refuses to guess which is which.
- Confidence is not certainty. The function code scored 0.80 because eight values over fifteen
  messages is plausible either as a type field or as repetitive data. The alternative was not
  wrong by a wide margin.
- A session with one operation type would report that function code as `reserved`, correctly and
  uselessly. Variation is what makes a field visible.

## Reproduce

```console
$ pip install pymodbus
$ python scripts/record-modbus.py captures/modbus-session.pcap
$ protopath analyze captures/modbus-session.pcap
$ protopath emit captures/modbus-session.pcap --out out/modbus
```

The emitted client decodes the recovered header; `out/modbus/messages.jsonl` lists all thirty
messages with their function codes.

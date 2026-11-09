# protopath

Infer wire-protocol structure from a packet capture, then hand the result to an agent.

You have traffic and no specification. `protopath` reads the capture, works out how messages
are framed, which bytes are fields, which field is a counter, whether there is a checksum,
and which message type follows which. Every finding comes with the evidence that produced it
and the alternative it could not rule out. Then it writes a Wireshark dissector, clients, a
mutation harness, and a report — or exposes the same analysis to an agent over MCP.

```console
$ protopath analyze captures/binary-session.pcap
```

```
| Field                 | Role     | Offset | Width | Encoding | Confidence | Why                                                              |
|-----------------------|----------|--------|-------|----------|------------|------------------------------------------------------------------|
| `magic`               | magic    | 0      | 2     | bytes    | 0.95       | bytes 0..2 are 0xa55a in all 10 messages                         |
| `length`              | length   | 2      | 1     | bytes    | 0.97       | a 1-byte be integer here reproduces every message length         |
| `sequence`            | counter  | 3      | 2     | le       | 0.95       | value increases by exactly 1 per message                         |
| `type`                | opcode   | 5      | 1     | bytes    | 0.80       | 2 distinct values across 10 messages                             |
| `payload`             | payload  | 6      | var   | bytes    | 0.60       | message lengths range from 8 to 19 bytes                         |
| `checksum_crc16_modbus` | checksum | end-2  | 2     | le       | 1.00       | crc16/modbus over bytes [0, len-2) matches in 10/10 messages     |
```

That is the whole output reduced to its table. The full report also carries the framing
hypotheses it rejected, the second-best answer with its score, reassembly damage, and a
message-transition graph.

## Install

Requires Node.js 20.19 or newer. There is nothing to compile and no native dependency.

```console
$ npm install --global protopath
$ protopath --help
```

Or run it without installing:

```console
$ npx protopath analyze capture.pcap
```

Register the agent side once, in the project you want it available in:

```console
$ protopath setup --yes
```

That writes `.mcp.json` with a `protopath` server entry and prints the equivalent command for
Claude Code, Cursor and Codex. Without `--yes` it prints and writes nothing.

## What it reads

| Capture | Support |
|---------|---------|
| pcap, microsecond and nanosecond | yes |
| pcapng (SHB/IDB/EPB/SPB) | yes, including per-interface `if_tsresol` |
| Ethernet, VLAN, QinQ | yes |
| Raw IP, Linux SLL, null/loopback | yes |
| IPv4, IPv6, extension-header skipping | yes |
| TCP with reassembly | sequence-number based, retransmits dropped, out-of-order placed |
| UDP | datagrams concatenated per direction |
| Fragmented IP, TLS, QUIC | no — see limits |

## What it infers

**Framing.** Five hypothesis families are enumerated and ranked: length-prefixed, start-marker,
terminator-delimited, fixed-size, and unframed. A hypothesis only survives if it explains the
stream byte-for-byte, so a wrong frame length almost never lands on the end of the buffer.
Each surviving hypothesis reports its score, its parameters and its own limitation.

**Fields.** Per-offset statistics over all messages: constant runs become `magic` or `reserved`,
two- and four-byte monotonic runs become `sequence`, the field that reproduces message length
becomes `length`, a low-cardinality field becomes `type`, printable runs become `text`, and the
rest is `payload`. Tail-anchored fields (checksums) are located from the end of each message so
they survive variable length.

**Checksums.** Twelve algorithms across widths 1, 2 and 4 are enumerated against every plausible
field position and covered range. A candidate is reported only when it matches every message.

**Message transitions.** Messages from both directions are ordered by timestamp and labelled from
the inferred type field, producing a first-order transition graph ready for a replay.

## Generated artifacts

`protopath emit capture.pcap` writes, for the strongest flow:

| File | Contents |
|------|----------|
| `dissector.lua` | Wireshark dissector that consumes every message in a segment |
| `client.ts` | Decoder, encoder, checksum inverse, verifier |
| `client.py` | Same, for Python |
| `fuzz.py` | Mutation harness that reuses `client.py` for encoding |
| `report.md` | The full report |
| `analysis.json` | Everything above, structured, buffers as hex |
| `messages.jsonl` | Every recovered message with offset, timestamp and hex |

The generated TypeScript is compiled in the test suite, and the generated Python carries the
inverse of the checksum that was actually detected — not a placeholder.

## CLI

```
protopath flows   <capture>                 list conversations
protopath analyze <capture>                 infer framing, fields, checksums
protopath emit    <capture> [--out <dir>]   write dissector, clients, fuzzer, report
protopath diff    <captureA> <captureB>     compare two inferred layouts
protopath setup   [--yes]                   register the MCP server
```

Flags: `--flow <key>`, `--max-flows <n>`, `--out <dir>`, `--port <n>`, `--json`,
`--targets lua,ts,python,fuzz,report`.

Exit codes: `0` confident analysis, `1` error, `3` analysis ran but no hypothesis cleared the
confidence threshold. `3` is deliberate — it lets a pipeline fail loudly without pretending the
report is useless.

## MCP tools

| Tool | Purpose |
|------|---------|
| `list_flows` | conversations with byte counts, gaps and retransmissions |
| `analyze_capture` | the full report, markdown or JSON |
| `infer_fields` | field table for one direction, with the reason for each boundary |
| `detect_checksums` | checksum candidates and the range each covers |
| `emit_artifacts` | write dissector, clients, harness and report to a directory |
| `diff_captures` | framing changes, moved fields, fields that stopped varying |

## Showcase

`captures/` holds three synthetic protocols with documented ground truth, plus a second revision
of the first one. They are generated by `scripts/make-captures.ts`, so every result in
`tests/` is checked against a known answer rather than a vibe.

```
binary-session.pcap     length-prefixed, crc16/modbus trailer, 10 messages per direction
binary-session-v2.pcap  same protocol with the type byte removed
binary-session.pcapng   the same capture in pcapng, read through a different parser
text-session.pcap       terminator-delimited ASCII, 8 messages per direction
sensor-udp.pcap         24 datagrams, start-marker framing, no transport session
```

Detecting a protocol revision is one command:

```console
$ protopath diff captures/binary-session.pcap captures/binary-session-v2.pcap
flow 10.0.0.10:41000 <> 10.0.0.20:7401 tcp -> 10.0.0.10:42000 <> 10.0.0.20:7401 tcp
  framing: length-prefix 1B be @2 bias 0 -> length-prefix 1B be @2 bias 0
  verdict: fields moved; a client built for the first capture will misparse the second
  changed  text — renamed from type to text; width 1 -> 4; role opcode -> text
  removed  payload — no field starts at head offset 6 in the second capture
  added    payload — new field at head offset 9
```

## Limits

These are the cases that produce a wrong or empty answer. They are not edge cases to be fixed
later; they are the boundary of the method.

- **A field that never varies is invisible.** Ten messages that all carry `type=0x10` are
  reported as `reserved`, correctly but unhelpfully. Capture both sides of the exchange.
- **TLS and QUIC are opaque.** Decrypt first or record at the application boundary.
- **Framing is ranked, not proven.** A length-prefixed protocol also looks like a start-marker
  protocol when the marker is 2 bytes. When two hypotheses are within 0.05 the report says so.
- **A single-byte marker is never accepted as a boundary.** Too little evidence, too many false
  splits.
- **Checksums are found, not explained.** A detected `crc16/modbus` is a match, not a claim
  about why the vendor chose it. Some protocols obfuscate with an unknown seed; those appear
  as no candidate at all.
- **TCP reassembly assumes one connection per 4-tuple.** A capture that reuses a 4-tuple across
  connections will merge them.

## Repository

```
src/core/pcap/       pcap and pcapng readers
src/core/net/        link/IP/transport decoding, TCP reassembly
src/core/infer/      framing, fields, checksums, state graph
src/core/emit/       Lua dissector, TypeScript/Python clients, mutation harness
src/core/            pipeline, report, diff
src/cli/             command line
src/mcp/             MCP server, stdio
tests/               unit and end-to-end tests against the fixture captures
scripts/             fixture capture generator
docs/                design, capture formats
```

Development:

```console
$ npm install
$ npm run captures   # regenerate captures/ from the generator
$ npm test           # build and run 39 tests
```

## License

MIT. Use it on traffic you are authorised to inspect.

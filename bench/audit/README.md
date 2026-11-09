# Audit probes

One script per question, each building its input by hand and calling the shipped build. They are
here so that every finding in [docs/audit.md](../../docs/audit.md) can be re-run instead of taken
on trust.

```console
$ npm run build && npm run build:test
```

| Script | Question it answers |
|---|---|
| `probe-net.mjs` | does the decoder and the TCP reassembler handle what a real capture throws at them |
| `probe-emit.mjs` | does the generated TypeScript client survive input that is not its own capture |
| `test-emit.py` | do the generated Python clients round-trip the capture they came from |
| `probe-crc.mjs` | does recovery invent parameters for data that has no checksum, and how much does it cost |
| `probe-crc2.mjs` | over 40 private polynomials, is the true set returned, and is an equivalent one returned instead |
| `probe-crc3.mjs` | does the reported parameter set still describe the protocol on a message that was not captured |
| `probe-crc4.mjs` | when several sets verify, is the true one in the list and where |
| `probe-e2e.mjs` | an ambiguous capture carried all the way to the emitted client and the checksums it computes |
| `probe-fields.mjs` | field, semantics and grammar behaviour on headers the fixtures do not contain |
| `probe-time.mjs` | is the `timestamp` value domain reachable for a clock that jitters |

These are not part of `npm test`: several of them assert the current, wrong behaviour, and a test
that fails is not a test. They become tests one bug at a time, as each is fixed.

Nothing in this directory writes to `captures/` or `bench/corpus/`; generated files land in
`out/audit/`, which is ignored.

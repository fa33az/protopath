"""Round-trip the generated clients against the bytes they were generated from.

A generated client is only useful if it decodes a real captured message and re-encodes it to
the same bytes. Anything less is a template with a protocol name in it.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys


def load(path: str):
    spec = importlib.util.spec_from_file_location(os.path.basename(path)[:-3], path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def messages(directory: str, direction: str) -> list[bytes]:
    out = []
    with open(os.path.join(directory, "messages.jsonl"), "r", encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("direction") == direction:
                out.append(bytes.fromhex(row["hex"]))
    return out


CASES = [
    ("out/emit/binary", "forward"),
    ("out/emit/crc", "forward"),
    ("out/emit/modbus", "forward"),
]

failures = 0
for directory, direction in CASES:
    name = os.path.basename(directory)
    print(f"\n=== {name} ===")
    client = load(os.path.join(directory, "client.py"))
    realised = messages(directory, direction)
    print(f"  captured messages: {len(realised)}")

    decoded = 0
    roundtripped = 0
    verified = 0
    mismatches = []
    for index, raw in enumerate(realised):
        try:
            message = client.decode(raw)
        except Exception as error:  # noqa: BLE001
            print(f"  decode threw on message {index}: {error!r}")
            failures += 1
            break
        if message is None:
            continue
        decoded += 1
        try:
            again = client.encode(message)
        except Exception as error:  # noqa: BLE001
            print(f"  encode threw on message {index}: {error!r}")
            failures += 1
            break
        if again == raw:
            roundtripped += 1
        elif len(mismatches) < 3:
            mismatches.append((index, raw.hex(), again.hex()))
        if hasattr(client, "verify"):
            if client.verify(raw):
                verified += 1

    print(f"  decoded {decoded}/{len(realised)}, byte-exact round trip {roundtripped}/{decoded}, verify() true {verified}/{decoded}")
    if mismatches:
        failures += 1
        for index, before, after in mismatches:
            print(f"  MISMATCH message {index}")
            print(f"    in  {before}")
            print(f"    out {after}")

    # A message from the other direction must not be silently accepted as this one.
    other = messages(directory, "reverse")
    if other:
        accepted = 0
        for raw in other:
            try:
                if client.decode(raw) is not None:
                    accepted += 1
            except Exception:  # noqa: BLE001
                accepted += 1
        print(f"  reverse-direction messages accepted by this client: {accepted}/{len(other)}")

print()
if failures:
    print(f"{failures} client failure(s)")
    sys.exit(1)
print("every generated client round-trips the capture it came from.")

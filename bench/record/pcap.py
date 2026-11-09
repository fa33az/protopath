"""A minimal pcap writer for the recorder.

The recorder logs what a real client and a real server exchanged, then writes those bytes into
an Ethernet/IPv4 pcap. It is deliberately separate from the TypeScript writer: the whole point
of a recorded capture is that the tool sees bytes it had no hand in producing.
"""

from __future__ import annotations

import struct
import time

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip_int(ip: str) -> int:
    value = 0
    for part in ip.split("."):
        value = value * 256 + int(part)
    return value


def _pseudo_header(src: str, dst: str, protocol: int, length: int) -> bytes:
    return struct.pack("!4s4sBBH", bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))), 0, protocol, length)


def _ipv4(src: str, dst: str, protocol: int, payload: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        0x4000,
        0,
        64,
        protocol,
        0,
        bytes(map(int, src.split("."))),
        bytes(map(int, dst.split("."))),
    )
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    ethernet = SERVER_MAC + CLIENT_MAC + b"\x08\x00"
    return ethernet + header + payload


def tcp_frame(src: str, src_port: int, dst: str, dst_port: int, seq: int, ack: int, payload: bytes) -> bytes:
    segment = struct.pack("!HHIIBBHHH", src_port, dst_port, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, 0x18, 8000, 0, 0) + payload
    checksum = _checksum(_pseudo_header(src, dst, 6, len(segment)) + segment)
    segment = segment[:16] + struct.pack("!H", checksum) + segment[18:]
    return _ipv4(src, dst, 6, segment)


def udp_frame(src: str, src_port: int, dst: str, dst_port: int, payload: bytes) -> bytes:
    datagram = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    checksum = _checksum(_pseudo_header(src, dst, 17, len(datagram)) + datagram)
    if checksum == 0:
        checksum = 0xFFFF
    datagram = datagram[:6] + struct.pack("!H", checksum) + datagram[8:]
    return _ipv4(src, dst, 17, datagram)


class Recorder:
    """Collects frames with timestamps and writes them as a pcap file."""

    def __init__(self) -> None:
        self.records: list[tuple[float, bytes]] = []

    def tcp(self, src: str, src_port: int, dst: str, dst_port: int, seq: int, ack: int, payload: bytes) -> None:
        self.records.append((time.time(), tcp_frame(src, src_port, dst, dst_port, seq, ack, payload)))

    def udp(self, src: str, src_port: int, dst: str, dst_port: int, payload: bytes) -> None:
        self.records.append((time.time(), udp_frame(src, src_port, dst, dst_port, payload)))

    def write(self, path: str) -> int:
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
        chunks = [header]
        base = self.records[0][0] if self.records else 0.0
        for timestamp, frame in self.records:
            # Rewrite timestamps relative to the first frame so the capture reads like a short
            # session regardless of when it was recorded.
            offset = timestamp - base
            seconds = int(offset)
            micros = int(round((offset - seconds) * 1_000_000))
            chunks.append(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
            chunks.append(frame)
        with open(path, "wb") as handle:
            handle.write(b"".join(chunks))
        return len(self.records)

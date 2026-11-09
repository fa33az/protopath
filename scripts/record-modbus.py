#!/usr/bin/env python3
"""Record a real Modbus/TCP session into a pcap.

Three processes' worth of work in one script:

  pymodbus server  — a simulated PLC holding coils and registers
  pymodbus client  — performs a mixed read/write sequence
  TCP proxy        — sits between them, logs every byte in both directions

The capture therefore contains exactly what a real Modbus client and server
exchanged, including the MBAP header the client library generated. Nothing in
the bytes is hand-written by this repository; only the surrounding pcap
container is.

Usage:
    pip install pymodbus
    python scripts/record-modbus.py captures/modbus-session.pcap
"""

from __future__ import annotations

import socket
import struct
import sys
import threading
import time
from pathlib import Path

from pymodbus.client import ModbusTcpClient
from pymodbus.datastore import ModbusDeviceContext, ModbusSequentialDataBlock, ModbusServerContext
from pymodbus.server import StartTcpServer

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 15020
PROXY_PORT = 15021

CLIENT_IP = "10.1.0.10"
SERVER_IP = "10.1.0.20"
CLIENT_MAC = bytes.fromhex("0200000000a1")
SERVER_MAC = bytes.fromhex("0200000000b2")

frames: list[tuple[float, bytes]] = []
frames_lock = threading.Lock()


# --- pcap plumbing ---------------------------------------------------------


def checksum(data: bytes) -> int:
    total = 0
    for i in range(0, len(data) - 1, 2):
        total += (data[i] << 8) | data[i + 1]
    if len(data) % 2:
        total += data[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_bytes(address: str) -> bytes:
    return bytes(int(part) for part in address.split("."))


def frame(client_to_server: bool, seq: int, ack: int, payload: bytes) -> bytes:
    if client_to_server:
        src_ip, dst_ip = CLIENT_IP, SERVER_IP
        src_port, dst_port = PROXY_PORT, SERVER_PORT
        src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
    else:
        src_ip, dst_ip = SERVER_IP, CLIENT_IP
        src_port, dst_port = SERVER_PORT, PROXY_PORT
        src_mac, dst_mac = SERVER_MAC, CLIENT_MAC

    tcp = bytearray(struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 5 << 4, 0x18, 8000, 0, 0))
    tcp += payload
    pseudo = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp[16:18] = struct.pack("!H", checksum(pseudo + bytes(tcp)))

    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0, ip_bytes(src_ip), ip_bytes(dst_ip)))
    ip[10:12] = struct.pack("!H", checksum(bytes(ip)))

    ethernet = dst_mac + src_mac + b"\x08\x00"
    return ethernet + bytes(ip) + bytes(tcp)


def write_pcap(path: Path, records: list[tuple[float, bytes]]) -> None:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    chunks = [header]
    for timestamp, data in records:
        seconds = int(timestamp)
        micros = int((timestamp - seconds) * 1_000_000)
        chunks.append(struct.pack("<IIII", seconds, micros, len(data), len(data)))
        chunks.append(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(chunks))


# --- recording -------------------------------------------------------------


class Recorder:
    def __init__(self) -> None:
        self.client_seq = 1000
        self.server_seq = 5000
        self.lock = threading.Lock()

    def record(self, client_to_server: bool, payload: bytes) -> None:
        if not payload:
            return
        with self.lock:
            if client_to_server:
                data = frame(True, self.client_seq, self.server_seq, payload)
                self.client_seq += len(payload)
            else:
                data = frame(False, self.server_seq, self.client_seq, payload)
                self.server_seq += len(payload)
            with frames_lock:
                frames.append((time.time(), data))


def pump(source: socket.socket, target: socket.socket, recorder: Recorder, client_to_server: bool) -> None:
    try:
        while True:
            chunk = source.recv(65535)
            if not chunk:
                break
            recorder.record(client_to_server, chunk)
            target.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            target.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def run_server() -> None:
    context = ModbusServerContext(
        devices=ModbusDeviceContext(
            co=ModbusSequentialDataBlock(1, [False] * 64),
            hr=ModbusSequentialDataBlock(1, list(range(100))),
        ),
        single=True,
    )
    StartTcpServer(context=context, address=(SERVER_HOST, SERVER_PORT))


def run_proxy(ready: threading.Event, stop: threading.Event) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((SERVER_HOST, PROXY_PORT))
    listener.listen(8)
    listener.settimeout(0.2)
    ready.set()

    while not stop.is_set():
        try:
            client, _ = listener.accept()
        except socket.timeout:
            continue
        upstream = socket.create_connection((SERVER_HOST, SERVER_PORT))
        recorder = Recorder()
        threading.Thread(target=pump, args=(client, upstream, recorder, True), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client, recorder, False), daemon=True).start()

    listener.close()


def run_client() -> None:
    client = ModbusTcpClient(SERVER_HOST, port=PROXY_PORT)
    assert client.connect(), "could not reach the proxy"

    operations = [
        lambda: client.read_holding_registers(0, count=4, device_id=1),
        lambda: client.read_coils(0, count=8, device_id=1),
        lambda: client.write_register(10, 4321, device_id=1),
        lambda: client.read_holding_registers(10, count=1, device_id=1),
        lambda: client.write_coil(3, True, device_id=1),
        lambda: client.write_registers(20, [111, 222, 333], device_id=1),
        lambda: client.read_holding_registers(20, count=3, device_id=1),
        lambda: client.write_coils(8, [True, True, False, True], device_id=1),
        lambda: client.read_coils(8, count=4, device_id=1),
        lambda: client.read_holding_registers(8, count=6, device_id=1),
        lambda: client.read_input_registers(0, count=2, device_id=1),
        lambda: client.read_discrete_inputs(0, count=6, device_id=1),
        lambda: client.write_coil(5, False, device_id=1),
        lambda: client.read_coils(2, count=6, device_id=1),
        lambda: client.read_holding_registers(0, count=2, device_id=1),
    ]

    for operation in operations:
        response = operation()
        if response.isError():
            print(f"server rejected an operation: {response}", file=sys.stderr)
        time.sleep(0.04)

    client.close()


def main() -> int:
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "captures/modbus-session.pcap")

    threading.Thread(target=run_server, daemon=True).start()
    time.sleep(0.8)

    ready = threading.Event()
    stop = threading.Event()
    proxy = threading.Thread(target=run_proxy, args=(ready, stop), daemon=True)
    proxy.start()
    ready.wait(timeout=5)

    run_client()
    time.sleep(0.2)
    stop.set()
    proxy.join(timeout=2)

    with frames_lock:
        records = sorted(frames, key=lambda record: record[0])

    write_pcap(target, records)
    print(f"wrote {target} — {len(records)} frames")
    return 0


if __name__ == "__main__":
    sys.exit(main())

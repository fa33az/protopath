"""Record real traffic from real implementations into pcap files.

Three protocols, three independent implementations, none of which was used while protopath's
inference layers were written:

    mqtt     amqtt (broker) + paho-mqtt (client)
    dns-tcp  dnslib (server and message builder)
    http     Python's standard-library http.server + http.client

Each session runs through a byte-level proxy that logs what the two libraries put on the wire.
Nothing here knows anything about protopath: the recorder writes the bytes, and the benchmark
asks the tool what it thinks they are.

    pip install paho-mqtt dnslib amqtt
    python bench/record/record_all.py

The committed captures in bench/recorded/ were produced by this script; re-running it produces a
capture of a fresh session, so the bytes differ while the protocol does not.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))
from pcap import Recorder  # noqa: E402

CLIENT_IP = "10.2.0.10"
SERVER_IP = "10.2.0.20"


class TcpProxy:
    """Accepts a client connection, forwards it to a server, and logs every chunk."""

    def __init__(self, listen_port: int, target_port: int, recorder: Recorder, host: str = "127.0.0.1") -> None:
        self.listen_port = listen_port
        self.target_port = target_port
        self.recorder = recorder
        self.host = host
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, listen_port))
        self.socket.listen(4)
        self.socket.settimeout(0.2)
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.connections: list[socket.socket] = []

    def start(self) -> None:
        self.thread.start()

    def _accept(self) -> None:
        while not self.stopped.is_set():
            try:
                client, address = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            upstream = socket.create_connection((self.host, self.target_port), timeout=5)
            self.connections.extend([client, upstream])
            client.settimeout(0.2)
            upstream.settimeout(0.2)
            sequence = {"client": 1000, "server": 5000}
            lock = threading.Lock()
            client_port = address[1]

            def pump(source: socket.socket, target: socket.socket, name: str) -> None:
                while not self.stopped.is_set():
                    try:
                        chunk = source.recv(65535)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not chunk:
                        break
                    with lock:
                        if name == "client":
                            self.recorder.tcp(CLIENT_IP, client_port, SERVER_IP, self.target_port, sequence["client"], sequence["server"], chunk)
                            sequence["client"] += len(chunk)
                        else:
                            self.recorder.tcp(SERVER_IP, self.target_port, CLIENT_IP, client_port, sequence["server"], sequence["client"], chunk)
                            sequence["server"] += len(chunk)
                    try:
                        target.sendall(chunk)
                    except OSError:
                        break
                # A connection closing is normal; it must not stop the proxy for other connections.
                for endpoint in (source, target):
                    try:
                        endpoint.close()
                    except OSError:
                        pass

            threading.Thread(target=pump, args=(client, upstream, "client"), daemon=True).start()
            threading.Thread(target=pump, args=(upstream, client, "server"), daemon=True).start()

    def stop(self) -> None:
        self.stopped.set()
        time.sleep(0.4)
        for connection in self.connections:
            try:
                connection.close()
            except OSError:
                pass
        try:
            self.socket.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# MQTT - amqtt broker, paho client
# ---------------------------------------------------------------------------


def record_mqtt(recorder: Recorder) -> None:
    import asyncio

    import paho.mqtt.client as mqtt
    from amqtt.broker import Broker

    broker_config = {
        "listeners": {"default": {"type": "tcp", "bind": "127.0.0.1:18831"}},
        "plugins": {"amqtt.plugins.authentication.AnonymousAuthPlugin": {"allow_anonymous": True}},
    }

    loop = asyncio.new_event_loop()
    ready = threading.Event()
    failure: dict[str, BaseException] = {}

    async def serve() -> None:
        try:
            broker = Broker(broker_config)
            await broker.start()
            ready.set()
            await asyncio.sleep(8)
            await broker.shutdown()
        except BaseException as error:  # noqa: BLE001 - surfaced to the caller below
            failure["error"] = error
            ready.set()

    thread = threading.Thread(target=lambda: loop.run_until_complete(serve()), daemon=True)
    thread.start()
    if not ready.wait(8):
        raise RuntimeError("broker did not start")
    if "error" in failure:
        raise failure["error"]

    proxy = TcpProxy(18830, 18831, recorder)
    proxy.start()
    time.sleep(0.4)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="bench-recorder")
    client.connect("127.0.0.1", 18830, keepalive=30)
    client.loop_start()
    client.subscribe("bench/readings", qos=1)
    time.sleep(0.3)
    for index in range(6):
        client.publish("bench/readings", json.dumps({"sensor": index, "value": 21.5 + index}), qos=1)
        time.sleep(0.25)
    time.sleep(0.5)
    client.disconnect()
    client.loop_stop()
    proxy.stop()
    thread.join(timeout=9)


# ---------------------------------------------------------------------------
# DNS over TCP - dnslib
# ---------------------------------------------------------------------------


def record_dns(recorder: Recorder) -> None:
    from dnslib import A, QTYPE, RR, DNSRecord
    from dnslib.server import BaseResolver, DNSServer

    class Resolver(BaseResolver):
        def resolve(self, request, handler):  # noqa: ANN001
            reply = request.reply()
            reply.add_answer(RR(rname=request.q.qname, rtype=QTYPE.A, rclass=1, ttl=120, rdata=A("203.0.113.42")))
            return reply

    server = DNSServer(Resolver(), port=15354, address="127.0.0.1", tcp=True, logger=None)
    server.start_thread()
    proxy = TcpProxy(15353, 15354, recorder)
    proxy.start()
    time.sleep(0.4)

    hosts = ["telemetry.example.net", "api.example.net", "firmware.example.org", "auth.example.net", "metrics.example.net"]

    def recv_exact(sock: socket.socket, size: int) -> bytes:
        chunks = b""
        while len(chunks) < size:
            piece = sock.recv(size - len(chunks))
            if not piece:
                raise RuntimeError("connection closed mid-message")
            chunks += piece
        return chunks

    connection = socket.create_connection(("127.0.0.1", 15353), timeout=5)
    for host in hosts:
        query = DNSRecord.question(host, "A").pack()
        connection.sendall(struct.pack("!H", len(query)) + query)
        length = struct.unpack("!H", recv_exact(connection, 2))[0]
        answer = recv_exact(connection, length)
        DNSRecord.parse(answer)
        time.sleep(0.2)
        # dnslib handles one request per TCP connection, and so do many real clients.
        connection.close()
        connection = socket.create_connection(("127.0.0.1", 15353), timeout=5)
    connection.close()
    proxy.stop()
    server.stop()


# ---------------------------------------------------------------------------
# HTTP/1.1 - standard library on both sides
# ---------------------------------------------------------------------------


def record_http(recorder: Recorder) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    payloads = {
        "/status": b'{"state":"ready","uptime":4127}',
        "/reading": b'{"channel":2,"value":21.75,"unit":"C"}',
        "/config": b'{"poll_ms":250,"gain":0.5,"mode":"auto"}',
        "/devices": b'{"devices":["pump-1","valve-3","sensor-9"]}',
    }

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            body = payloads.get(self.path, b"{}")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:  # noqa: ANN002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 18081), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    proxy = TcpProxy(18080, 18081, recorder)
    proxy.start()
    time.sleep(0.4)

    connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=5)
    for path in payloads:
        connection.request("GET", path, headers={"User-Agent": "protopath-bench/1.0", "Accept": "*/*"})
        response = connection.getresponse()
        response.read()
        time.sleep(0.15)
    connection.close()
    proxy.stop()
    server.shutdown()


SCENARIOS = {"mqtt": record_mqtt, "dns-tcp": record_dns, "http": record_http}


def main() -> None:
    parser = argparse.ArgumentParser(description="record real protocol traffic into a pcap")
    parser.add_argument("--only", choices=sorted(SCENARIOS), action="append", help="record only the named scenario")
    parser.add_argument("--out", default=os.path.join("bench", "recorded"), help="output directory")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    names = args.only or sorted(SCENARIOS)
    for name in names:
        recorder = Recorder()
        SCENARIOS[name](recorder)
        path = os.path.join(args.out, f"real-{name}.pcap")
        frames = recorder.write(path)
        print(f"{name}: {frames} frames -> {path}")


if __name__ == "__main__":
    main()

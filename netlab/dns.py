"""A deliberately small authoritative lab DNS responder (UDP, A and AAAA)."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import signal
import socket
import struct
import sys


def _question(data: bytes) -> tuple[str, int, int]:
    if len(data) < 12 or len(data) > 4096:
        raise ValueError("invalid DNS packet length")
    _, flags, count, _, _, _ = struct.unpack("!6H", data[:12])
    if flags & 0x8000 or count != 1:
        raise ValueError("expected one DNS query")
    labels, offset = [], 12
    while True:
        if offset >= len(data):
            raise ValueError("truncated DNS name")
        size = data[offset]
        offset += 1
        if size == 0:
            break
        if size > 63 or offset + size > len(data):
            raise ValueError("invalid or compressed question name")
        labels.append(data[offset:offset + size].decode("ascii").lower())
        offset += size
        if offset - 12 > 255:
            raise ValueError("DNS name too long")
    if offset + 4 > len(data):
        raise ValueError("missing DNS question type")
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    if qclass != 1:
        raise ValueError("only Internet class is supported")
    return ".".join(labels), qtype, offset + 4


def respond(data: bytes, mode: str = "healthy") -> bytes:
    """Answer backend.lab; unknown names/NXDOMAIN fault receive real NXDOMAIN."""
    name, qtype, end = _question(data)
    ident, request_flags = struct.unpack("!HH", data[:4])
    rcode = 3 if mode == "nxdomain" or name != "backend.lab" else 0
    answer = b""
    if rcode == 0 and qtype == 1:
        address = "10.77.3.99" if mode == "wrong-answer" else "10.77.3.2"
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton(address)
    flags = 0x8400 | (request_flags & 0x0100) | rcode
    return struct.pack("!6H", ident, flags, 1, bool(answer), 0, 0) + data[12:end] + answer


def query(address: str = "10.77.1.1", name: str = "backend.lab", timeout: float = 0.5) -> dict:
    ident = secrets.randbits(16)
    labels = name.rstrip(".").split(".")
    encoded = b"".join(bytes([len(p)]) + p.encode("ascii") for p in labels) + b"\x00"
    packet = struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", 1, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((address, 53))
            sock.send(packet)
            result = sock.recv(4096)
        if len(result) < 12:
            raise ValueError("truncated DNS response")
        reply_id, flags, questions, answers, _, _ = struct.unpack("!6H", result[:12])
        if reply_id != ident or not flags & 0x8000 or questions != 1:
            raise ValueError("DNS response does not match query")
        rcode = flags & 15
        answer = None
        # This responder emits exactly one fixed-length A answer or no answer.
        if answers == 1 and len(result) >= len(packet) + 16:
            answer = socket.inet_ntoa(result[-4:])
        return {"ok": rcode == 0 and answer == "10.77.3.2", "rcode": rcode,
                "address": answer, "name": name}
    except (OSError, ValueError) as exc:
        return {"ok": False, "rcode": None, "address": None, "name": name,
                "error": str(exc)}


def serve(bind: str, state: Path) -> None:
    running = True

    def stop(*_args):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind, 53))
        sock.settimeout(0.25)
        while running:
            try:
                packet, source = sock.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                mode = json.loads(state.read_text()).get("mode", "healthy")
                if mode == "timeout":
                    continue
                answer = respond(packet, mode)
                sock.sendto(answer, source)
            except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
                # Malformed packets do not take down the resolver.
                continue


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="10.77.1.1")
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--query", action="store_true")
    args = parser.parse_args()
    if args.query:
        print(json.dumps(query(args.bind), sort_keys=True))
    else:
        serve(args.bind, args.state)
    return 0


if __name__ == "__main__":
    sys.exit(main())

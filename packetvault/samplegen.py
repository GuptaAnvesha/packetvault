"""Deterministic synthetic lab traffic generator.

Produces a realistic PCAP of a small host-only lab network (192.168.56.0/24)
together with ground-truth labels, so the full pipeline and the port-scan
detector can be demonstrated and tested without a live VM lab:

* benign clients browsing a web server (full TCP handshakes, data, FIN)
* DNS lookups and ICMP pings
* a "crawler" that opens many connections - but only to ports 80/443
* an Nmap-style SYN scan (-sS) of ports 1-1024 from the attacker VM
* a slower Nmap-style connect scan (-sT -T2) of 60 ports

Real captures from the Kali/Ubuntu VirtualBox lab are drop-in replacements.
"""

from __future__ import annotations

import json
import random
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .pcapio import PcapWriter

NET = "192.168.56."
SERVER = NET + "10"
DNS_SERVER = NET + "2"
CLIENTS = [NET + "20", NET + "21", NET + "22"]
CRAWLER = NET + "23"
SYN_SCANNER = NET + "101"
SLOW_SCANNER = NET + "102"
OPEN_PORTS = {22, 80, 443}


def _ip_bytes(ip: str) -> bytes:
    return bytes(int(p) for p in ip.split("."))


def _mac_for(ip: str) -> bytes:
    return bytes([0x08, 0x00, 0x27, 0x00, 0x38, int(ip.split(".")[-1])])  # VirtualBox OUI


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, 64, proto, 0,
        _ip_bytes(src), _ip_bytes(dst),
    )
    csum = _checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:] + payload


def _l4_checksum(src: str, dst: str, proto: int, segment: bytes) -> int:
    pseudo = _ip_bytes(src) + _ip_bytes(dst) + struct.pack("!BBH", 0, proto, len(segment))
    return _checksum(pseudo + segment)


TCP_FLAGS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10}


def _tcp(src, dst, sport, dport, flags: str, seq: int, ack: int, payload: bytes = b"") -> bytes:
    bits = sum(TCP_FLAGS[c] for c in flags)
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, bits, 64240, 0, 0)
    seg += payload
    csum = _l4_checksum(src, dst, 6, seg)
    return seg[:16] + struct.pack("!H", csum) + seg[18:]


def _udp(src, dst, sport, dport, payload: bytes) -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = _l4_checksum(src, dst, 17, seg) or 0xFFFF
    return seg[:6] + struct.pack("!H", csum) + seg[8:]


def _icmp_echo(ident: int, seq: int, reply: bool) -> bytes:
    body = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, ident, seq) + b"packetvault-lab-ping"
    return body[:2] + struct.pack("!H", _checksum(body)) + body[4:]


@dataclass
class _Builder:
    rng: random.Random
    t: float
    frames: list[tuple[float, bytes]] = field(default_factory=list)
    ident: int = 1

    def emit(self, at: float, src: str, dst: str, proto: int, l4: bytes) -> None:
        eth = _mac_for(dst) + _mac_for(src) + b"\x08\x00"
        self.frames.append((at, eth + _ipv4(src, dst, proto, l4, self.ident)))
        self.ident += 1

    def tcp(self, at, src, dst, sport, dport, flags, seq=0, ack=0, payload=b""):
        self.emit(at, src, dst, 6, _tcp(src, dst, sport, dport, flags, seq, ack, payload))

    def udp(self, at, src, dst, sport, dport, payload):
        self.emit(at, src, dst, 17, _udp(src, dst, sport, dport, payload))


def _http_session(b: _Builder, start: float, client: str, dport: int) -> None:
    rng = b.rng
    sport = rng.randint(40000, 60999)
    cseq, sseq = rng.getrandbits(32), rng.getrandbits(32)
    rtt = rng.uniform(0.0003, 0.002)
    t = start
    b.tcp(t, client, SERVER, sport, dport, "S", cseq)
    t += rtt
    b.tcp(t, SERVER, client, dport, sport, "SA", sseq, cseq + 1)
    t += rtt
    b.tcp(t, client, SERVER, sport, dport, "A", cseq + 1, sseq + 1)
    request = b"GET /index.html HTTP/1.1\r\nHost: lab-server\r\n\r\n"
    t += 0.001
    b.tcp(t, client, SERVER, sport, dport, "PA", cseq + 1, sseq + 1, request)
    cseq += 1 + len(request)
    sseq += 1
    for _ in range(rng.randint(1, 4)):
        chunk = bytes(rng.getrandbits(8) for _ in range(rng.randint(200, 1400)))
        t += rtt
        b.tcp(t, SERVER, client, dport, sport, "PA", sseq, cseq, chunk)
        sseq += len(chunk)
        t += rtt
        b.tcp(t, client, SERVER, sport, dport, "A", cseq, sseq)
    t += 0.01
    b.tcp(t, client, SERVER, sport, dport, "FA", cseq, sseq)
    t += rtt
    b.tcp(t, SERVER, client, dport, sport, "FA", sseq, cseq + 1)
    t += rtt
    b.tcp(t, client, SERVER, sport, dport, "A", cseq + 1, sseq + 1)


def _dns_lookup(b: _Builder, start: float, client: str) -> None:
    sport = b.rng.randint(30000, 60999)
    txid = b.rng.getrandbits(16)
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + b"\x0alab-server\x05local\x00\x00\x01\x00\x01"
    b.udp(start, client, DNS_SERVER, sport, 53, query)
    answer = query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x01" + query[8:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04" + _ip_bytes(SERVER)
    b.udp(start + 0.0008, DNS_SERVER, client, 53, sport, answer)


def _ping(b: _Builder, start: float, client: str, seq: int) -> None:
    b.emit(start, client, SERVER, 1, _icmp_echo(0x1234, seq, reply=False))
    b.emit(start + 0.0004, SERVER, client, 1, _icmp_echo(0x1234, seq, reply=True))


def _syn_scan(b: _Builder, start: float, scanner: str, ports: list[int], duration: float) -> None:
    """Nmap -sS: SYN, then RST on SYN/ACK (open) or receive RST/ACK (closed)."""
    sport = b.rng.randint(40000, 60999)  # Nmap reuses one source port per scan
    step = duration / len(ports)
    for i, port in enumerate(ports):
        t = start + i * step + b.rng.uniform(0, step / 4)
        seq = b.rng.getrandbits(32)
        b.tcp(t, scanner, SERVER, sport, port, "S", seq)
        if port in OPEN_PORTS:
            sseq = b.rng.getrandbits(32)
            b.tcp(t + 0.0004, SERVER, scanner, port, sport, "SA", sseq, seq + 1)
            b.tcp(t + 0.0008, scanner, SERVER, sport, port, "R", seq + 1)
        else:
            b.tcp(t + 0.0004, SERVER, scanner, port, sport, "RA", 0, seq + 1)


def _connect_scan(b: _Builder, start: float, scanner: str, ports: list[int], duration: float) -> None:
    """Nmap -sT: full connect() on open ports, a new source port each probe."""
    step = duration / len(ports)
    for i, port in enumerate(ports):
        t = start + i * step
        sport = b.rng.randint(40000, 60999)
        seq = b.rng.getrandbits(32)
        b.tcp(t, scanner, SERVER, sport, port, "S", seq)
        if port in OPEN_PORTS:
            sseq = b.rng.getrandbits(32)
            b.tcp(t + 0.0005, SERVER, scanner, port, sport, "SA", sseq, seq + 1)
            b.tcp(t + 0.0010, scanner, SERVER, sport, port, "A", seq + 1, sseq + 1)
            b.tcp(t + 0.0015, scanner, SERVER, sport, port, "RA", seq + 1, sseq + 1)
        else:
            b.tcp(t + 0.0005, SERVER, scanner, port, sport, "RA", 0, seq + 1)


def generate_lab_capture(out_pcap: str | Path, labels_path: str | Path | None = None,
                         seed: int = 7, start_time: float = 1_759_800_000.0) -> dict:
    """Write the synthetic lab capture and return its ground-truth labels."""
    rng = random.Random(seed)
    b = _Builder(rng=rng, t=start_time)

    # ~2 minutes of benign background traffic
    for client in CLIENTS:
        t = start_time + rng.uniform(0, 2)
        for seq in range(1, 4):
            _ping(b, t + seq, client, seq)
        while t < start_time + 120:
            _dns_lookup(b, t, client)
            _http_session(b, t + 0.002, client, rng.choice([80, 443]))
            t += rng.uniform(3, 9)

    # crawler: many connections, few distinct destination ports -> must NOT alert
    t = start_time + 10
    for _ in range(40):
        _http_session(b, t, CRAWLER, rng.choice([80, 443]))
        t += rng.uniform(0.2, 0.6)

    # attacker 1: fast SYN scan of the well-known ports (nmap -sS -p1-1024)
    ports = list(range(1, 1025))
    rng.shuffle(ports)  # nmap randomises port order
    _syn_scan(b, start_time + 40, SYN_SCANNER, ports, duration=6.0)

    # attacker 2: slow connect scan of 60 common ports over 30 s (nmap -sT -T2)
    slow_ports = rng.sample(range(1, 10000), 57) + [22, 80, 443]
    rng.shuffle(slow_ports)
    _connect_scan(b, start_time + 70, SLOW_SCANNER, slow_ports, duration=30.0)

    b.frames.sort(key=lambda item: item[0])
    Path(out_pcap).parent.mkdir(parents=True, exist_ok=True)
    with PcapWriter(out_pcap) as writer:
        for ts, frame in b.frames:
            writer.write(ts, frame)

    labels = {
        "description": "Ground truth for the PacketVault synthetic lab capture",
        "seed": seed,
        "packets": len(b.frames),
        "scanners": [SYN_SCANNER, SLOW_SCANNER],
        "benign": sorted(CLIENTS + [CRAWLER, SERVER, DNS_SERVER]),
    }
    if labels_path:
        Path(labels_path).write_text(json.dumps(labels, indent=2), encoding="utf-8")
    return labels

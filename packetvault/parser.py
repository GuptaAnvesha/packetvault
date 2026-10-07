"""M1 - Packet Parser.

Reads a PCAP/PCAPNG capture into normalised ``PacketRecord`` objects and
writes them out as an XML interchange document and an indexed SQLite store.

Two acquisition backends are available:

* ``pyshark`` - uses tshark's dissectors (requires Wireshark/tshark).
* ``builtin`` - a pure-Python decoder (``pcapio``), always available.

``auto`` picks pyshark when tshark is installed, otherwise builtin.
"""

from __future__ import annotations

import shutil
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from .models import RECORD_FIELDS, PacketRecord, format_timestamp, tcp_flags_to_str
from .pcapio import decode_frame, iter_frames

BACKENDS = ("auto", "builtin", "pyshark")


def resolve_backend(backend: str = "auto") -> str:
    if backend not in BACKENDS:
        raise ValueError(f"unknown backend {backend!r}; choose from {BACKENDS}")
    if backend != "auto":
        return backend
    try:
        import pyshark  # noqa: F401
    except ImportError:
        return "builtin"
    return "pyshark" if shutil.which("tshark") else "builtin"


def parse_pcap(path: str | Path, backend: str = "auto") -> list[PacketRecord]:
    backend = resolve_backend(backend)
    if backend == "pyshark":
        return list(_parse_with_pyshark(path))
    return [decode_frame(i, frame) for i, frame in enumerate(iter_frames(path), start=1)]


def _parse_with_pyshark(path: str | Path) -> Iterator[PacketRecord]:
    import pyshark

    capture = pyshark.FileCapture(str(path), keep_packets=False)
    try:
        for i, pkt in enumerate(capture, start=1):
            yield _record_from_pyshark(i, pkt)
    finally:
        capture.close()


def _record_from_pyshark(index: int, pkt) -> PacketRecord:
    def layer(name):
        return getattr(pkt, name, None) if name in pkt else None

    eth, ip, ip6, tcp, udp = (layer(n) for n in ("eth", "ip", "ipv6", "tcp", "udp"))
    src_ip = dst_ip = None
    protocol = "OTHER"
    if ip is not None:
        src_ip, dst_ip, protocol = ip.src, ip.dst, "IPv4"
    elif ip6 is not None:
        src_ip, dst_ip, protocol = ip6.src, ip6.dst, "IPv6"
    elif "arp" in pkt:
        src_ip, dst_ip, protocol = pkt.arp.src_proto_ipv4, pkt.arp.dst_proto_ipv4, "ARP"

    src_port = dst_port = flags = None
    payload_len = 0
    if tcp is not None:
        protocol = "TCP"
        src_port, dst_port = int(tcp.srcport), int(tcp.dstport)
        flags = tcp_flags_to_str(int(tcp.flags, 16))
        payload_len = int(getattr(tcp, "len", 0))
    elif udp is not None:
        protocol = "UDP"
        src_port, dst_port = int(udp.srcport), int(udp.dstport)
        payload_len = int(udp.length) - 8
    elif "icmp" in pkt:
        protocol = "ICMP"
    elif "icmpv6" in pkt:
        protocol = "ICMPv6"

    return PacketRecord(
        index=index,
        timestamp=format_timestamp(float(pkt.sniff_timestamp)),
        src_mac=eth.src if eth is not None else None,
        dst_mac=eth.dst if eth is not None else None,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        frame_len=int(pkt.length),
        payload_len=max(payload_len, 0),
    )


# --------------------------------------------------------------------------- XML


def write_xml(records: Iterable[PacketRecord], out_path: str | Path, metadata: dict | None = None) -> None:
    root = ET.Element("packetvault", version="1")
    if metadata:
        meta_el = ET.SubElement(root, "acquisition")
        for key, value in sorted(metadata.items()):
            ET.SubElement(meta_el, key).text = str(value)
    packets_el = ET.SubElement(root, "packets")
    for rec in records:
        pkt_el = ET.SubElement(packets_el, "packet", index=str(rec.index))
        for name in RECORD_FIELDS[1:]:
            value = getattr(rec, name)
            if value is not None:
                ET.SubElement(pkt_el, name).text = str(value)
    ET.indent(root)
    ET.ElementTree(root).write(out_path, encoding="utf-8", xml_declaration=True)


def read_xml(path: str | Path) -> list[PacketRecord]:
    int_fields = {"src_port", "dst_port", "frame_len", "payload_len"}
    records = []
    for pkt_el in ET.parse(path).getroot().iter("packet"):
        data: dict = {name: None for name in RECORD_FIELDS}
        data["index"] = int(pkt_el.get("index"))
        for child in pkt_el:
            data[child.tag] = int(child.text) if child.tag in int_fields else child.text
        records.append(PacketRecord(**data))
    return records


# --------------------------------------------------------------------------- SQLite

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS packets (
    idx          INTEGER PRIMARY KEY,
    timestamp    TEXT    NOT NULL,
    src_mac      TEXT,
    dst_mac      TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    protocol     TEXT    NOT NULL,
    src_port     INTEGER,
    dst_port     INTEGER,
    tcp_flags    TEXT,
    frame_len    INTEGER NOT NULL,
    payload_len  INTEGER NOT NULL,
    chain_hash   TEXT
);
CREATE INDEX IF NOT EXISTS ix_packets_ts      ON packets (timestamp);
CREATE INDEX IF NOT EXISTS ix_packets_ip_pair ON packets (src_ip, dst_ip);
"""

_COLUMNS = ("idx",) + RECORD_FIELDS[1:]


def build_database(records: Iterable[PacketRecord], chain_hashes: Sequence[str] | None = None,
                   metadata: dict | None = None) -> bytes:
    """Build the evidence database entirely in memory and return its bytes.

    Building in memory means the plaintext store never touches disk during
    sealing - only the AES-GCM ciphertext does.
    """
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(SCHEMA)
        rows = []
        for i, rec in enumerate(records):
            row = tuple(getattr(rec, name) for name in RECORD_FIELDS)
            rows.append(row + ((chain_hashes[i] if chain_hashes else None),))
        placeholders = ",".join("?" * (len(_COLUMNS) + 1))
        conn.executemany(f"INSERT INTO packets ({','.join(_COLUMNS)},chain_hash) VALUES ({placeholders})", rows)
        if metadata:
            conn.executemany("INSERT INTO meta (key, value) VALUES (?, ?)",
                             sorted((k, str(v)) for k, v in metadata.items()))
        conn.commit()
        return conn.serialize()
    finally:
        conn.close()


def open_database(data: bytes) -> sqlite3.Connection:
    """Open database bytes (e.g. freshly decrypted) as an in-memory connection."""
    conn = sqlite3.connect(":memory:")
    conn.deserialize(data)
    return conn


def load_database(data: bytes) -> tuple[list[PacketRecord], list[str | None], dict]:
    """Return (records, stored chain hashes, metadata) in frame order."""
    conn = open_database(data)
    try:
        rows = conn.execute(f"SELECT {','.join(_COLUMNS)},chain_hash FROM packets ORDER BY idx").fetchall()
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    finally:
        conn.close()
    records = [PacketRecord(*row[:-1]) for row in rows]
    return records, [row[-1] for row in rows], meta


def write_sqlite(records: Iterable[PacketRecord], db_path: str | Path, **kwargs) -> None:
    """Write a plaintext (unsealed) database file - used by the ``parse`` command."""
    Path(db_path).write_bytes(build_database(records, **kwargs))

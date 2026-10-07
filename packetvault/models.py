"""Core data model: the normalised per-packet record and its canonical form.

Every cryptographic operation in PacketVault (hash chain, signature) works on
*canonical bytes*, never on Python objects, so the exact serialisation rules
live here in one place.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields
from typing import Any

# Field order is part of the evidence format. Changing it breaks every
# previously sealed case, so treat it as frozen.
RECORD_FIELDS = (
    "index",
    "timestamp",
    "src_mac",
    "dst_mac",
    "src_ip",
    "dst_ip",
    "protocol",
    "src_port",
    "dst_port",
    "tcp_flags",
    "frame_len",
    "payload_len",
)


@dataclass(frozen=True)
class PacketRecord:
    """One normalised packet. ``index`` is the 1-based frame number."""

    index: int
    timestamp: str  # fixed-precision decimal string, e.g. "1700000000.123456"
    src_mac: str | None
    dst_mac: str | None
    src_ip: str | None
    dst_ip: str | None
    protocol: str  # TCP / UDP / ICMP / ICMPv6 / ARP / IPv4 / IPv6 / OTHER
    src_port: int | None
    dst_port: int | None
    tcp_flags: str | None  # e.g. "SYN" or "SYN,ACK"; None for non-TCP
    frame_len: int
    payload_len: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PacketRecord":
        return cls(**{f.name: data[f.name] for f in fields(cls)})

    def canonical_bytes(self) -> bytes:
        """Deterministic serialisation used as hash-chain input."""
        return canonical_json([getattr(self, name) for name in RECORD_FIELDS])

    @property
    def ts_float(self) -> float:
        return float(self.timestamp)

    def has_flag(self, flag: str) -> bool:
        return bool(self.tcp_flags) and flag in self.tcp_flags.split(",")


def canonical_json(obj: Any) -> bytes:
    """Stable JSON encoding: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def format_timestamp(seconds: float) -> str:
    return f"{seconds:.6f}"


TCP_FLAG_NAMES = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)


def tcp_flags_to_str(bits: int) -> str:
    names = [name for mask, name in TCP_FLAG_NAMES if bits & mask]
    return ",".join(names)

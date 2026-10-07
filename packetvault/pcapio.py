"""Minimal, dependency-free PCAP / PCAPNG reading and classic PCAP writing.

This is the fallback acquisition backend used when tshark/pyshark is not
installed (and the backend the test-suite uses, so tests run anywhere).
It decodes Ethernet, Linux SLL and raw-IP link layers, IPv4/IPv6, ARP,
TCP, UDP, ICMP and ICMPv6 - enough for the fields in ``PacketRecord``.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

from .models import PacketRecord, format_timestamp, tcp_flags_to_str

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_SHB = 0x0A0D0D0A


class PcapFormatError(ValueError):
    pass


@dataclass(frozen=True)
class RawFrame:
    timestamp: float
    linktype: int
    data: bytes
    orig_len: int


# --------------------------------------------------------------------------- reading


def iter_frames(path: str | Path) -> Iterator[RawFrame]:
    """Yield raw frames from a classic PCAP or PCAPNG file."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        fh.seek(0)
        if len(head) < 4:
            raise PcapFormatError("file too short to be a capture")
        if struct.unpack("<I", head)[0] == PCAPNG_SHB:
            yield from _iter_pcapng(fh)
        else:
            yield from _iter_pcap(fh)


def _iter_pcap(fh: BinaryIO) -> Iterator[RawFrame]:
    header = fh.read(24)
    if len(header) < 24:
        raise PcapFormatError("truncated PCAP global header")
    for endian in ("<", ">"):
        magic = struct.unpack(endian + "I", header[:4])[0]
        if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            break
    else:
        raise PcapFormatError("not a PCAP/PCAPNG file (bad magic)")
    divisor = 1e9 if magic == PCAP_MAGIC_NS else 1e6
    linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF

    rec_hdr = struct.Struct(endian + "IIII")
    while True:
        raw = fh.read(16)
        if not raw:
            return
        if len(raw) < 16:
            raise PcapFormatError("truncated PCAP record header")
        ts_sec, ts_frac, incl_len, orig_len = rec_hdr.unpack(raw)
        data = fh.read(incl_len)
        if len(data) < incl_len:
            raise PcapFormatError("truncated PCAP record body")
        yield RawFrame(ts_sec + ts_frac / divisor, linktype, data, orig_len)


def _iter_pcapng(fh: BinaryIO) -> Iterator[RawFrame]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, ticks per second)
    while True:
        head = fh.read(8)
        if not head:
            return
        if len(head) < 8:
            raise PcapFormatError("truncated PCAPNG block header")
        block_type = struct.unpack("<I", head[:4])[0]
        if block_type == PCAPNG_SHB:
            # The byte-order magic decides endianness for the whole section.
            bom = fh.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            block_len = struct.unpack(endian + "I", head[4:8])[0]
            fh.read(block_len - 12)
            interfaces = []
            continue

        block_type, block_len = struct.unpack(endian + "II", head)
        if block_len < 12:
            raise PcapFormatError("invalid PCAPNG block length")
        body = fh.read(block_len - 8)
        if len(body) < block_len - 8:
            raise PcapFormatError("truncated PCAPNG block")
        body = body[:-4]  # trailing duplicate length

        if block_type == 0x00000001:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            interfaces.append((linktype, _pcapng_tsresol(body[8:], endian)))
        elif block_type == 0x00000006:  # Enhanced Packet Block
            if_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            linktype, ticks = interfaces[if_id]
            ts = ((ts_hi << 32) | ts_lo) / ticks
            yield RawFrame(ts, linktype, body[20 : 20 + cap_len], orig_len)
        elif block_type == 0x00000003:  # Simple Packet Block (no timestamp)
            orig_len = struct.unpack(endian + "I", body[:4])[0]
            linktype, _ = interfaces[0]
            yield RawFrame(0.0, linktype, body[4 : 4 + orig_len], orig_len)
        # every other block type (NRB, ISB, custom...) is skipped


def _pcapng_tsresol(options: bytes, endian: str) -> float:
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[pos : pos + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:  # if_tsresol
            value = options[pos + 4]
            return float(2 ** (value & 0x7F)) if value & 0x80 else float(10**value)
        pos += 4 + ((length + 3) & ~3)
    return 1e6


# --------------------------------------------------------------------------- decoding


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def decode_frame(index: int, frame: RawFrame) -> PacketRecord:
    """Decode one raw frame into a normalised ``PacketRecord``.

    Malformed or unsupported frames still produce a record (protocol
    ``OTHER``) - evidence must never be silently dropped.
    """
    f: dict = dict(
        index=index,
        timestamp=format_timestamp(frame.timestamp),
        src_mac=None,
        dst_mac=None,
        src_ip=None,
        dst_ip=None,
        protocol="OTHER",
        src_port=None,
        dst_port=None,
        tcp_flags=None,
        frame_len=frame.orig_len,
        payload_len=0,
    )
    data = frame.data
    try:
        ethertype, l3 = _strip_link_layer(frame.linktype, data, f)
        if ethertype == 0x0800:
            _decode_ipv4(l3, f)
        elif ethertype == 0x86DD:
            _decode_ipv6(l3, f)
        elif ethertype == 0x0806:
            _decode_arp(l3, f)
    except (struct.error, IndexError, ValueError):
        pass  # keep whatever was decoded before the frame became unparseable
    return PacketRecord(**f)


def _strip_link_layer(linktype: int, data: bytes, f: dict) -> tuple[int | None, bytes]:
    if linktype == LINKTYPE_ETHERNET:
        f["dst_mac"], f["src_mac"] = _mac(data[0:6]), _mac(data[6:12])
        ethertype = struct.unpack("!H", data[12:14])[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8):  # 802.1Q / QinQ VLAN tags
            ethertype = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            offset += 4
        return ethertype, data[offset:]
    if linktype == LINKTYPE_LINUX_SLL:
        addr_len = struct.unpack("!H", data[4:6])[0]
        if addr_len == 6:
            f["src_mac"] = _mac(data[6:12])
        return struct.unpack("!H", data[14:16])[0], data[16:]
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        version = data[0] >> 4
        return (0x0800 if version == 4 else 0x86DD if version == 6 else None), data
    return None, data


def _decode_ipv4(pkt: bytes, f: dict) -> None:
    ihl = (pkt[0] & 0x0F) * 4
    total_len = struct.unpack("!H", pkt[2:4])[0]
    proto = pkt[9]
    f["protocol"] = "IPv4"
    f["src_ip"] = str(ipaddress.IPv4Address(pkt[12:16]))
    f["dst_ip"] = str(ipaddress.IPv4Address(pkt[16:20]))
    _decode_l4(proto, pkt[ihl : max(total_len, ihl)], f)


def _decode_ipv6(pkt: bytes, f: dict) -> None:
    payload_len = struct.unpack("!H", pkt[4:6])[0]
    f["protocol"] = "IPv6"
    f["src_ip"] = str(ipaddress.IPv6Address(pkt[8:24]))
    f["dst_ip"] = str(ipaddress.IPv6Address(pkt[24:40]))
    _decode_l4(pkt[6], pkt[40 : 40 + payload_len], f)


def _decode_arp(pkt: bytes, f: dict) -> None:
    f["protocol"] = "ARP"
    if len(pkt) >= 28 and pkt[4] == 6 and pkt[5] == 4:
        f["src_ip"] = str(ipaddress.IPv4Address(pkt[14:18]))
        f["dst_ip"] = str(ipaddress.IPv4Address(pkt[24:28]))


def _decode_l4(proto: int, seg: bytes, f: dict) -> None:
    if proto == 6:
        f["protocol"] = "TCP"
        f["src_port"], f["dst_port"] = struct.unpack("!HH", seg[0:4])
        data_offset = (seg[12] >> 4) * 4
        f["tcp_flags"] = tcp_flags_to_str(seg[13])
        f["payload_len"] = max(len(seg) - data_offset, 0)
    elif proto == 17:
        f["protocol"] = "UDP"
        f["src_port"], f["dst_port"] = struct.unpack("!HH", seg[0:4])
        f["payload_len"] = max(len(seg) - 8, 0)
    elif proto == 1:
        f["protocol"] = "ICMP"
        f["payload_len"] = max(len(seg) - 8, 0)
    elif proto == 58:
        f["protocol"] = "ICMPv6"
        f["payload_len"] = max(len(seg) - 8, 0)
    else:
        f["payload_len"] = len(seg)


# --------------------------------------------------------------------------- writing


class PcapWriter:
    """Writes classic little-endian microsecond PCAP files (Ethernet)."""

    def __init__(self, path: str | Path, linktype: int = LINKTYPE_ETHERNET, snaplen: int = 65535):
        self._fh = open(path, "wb")
        self._fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, snaplen, linktype))

    def write(self, timestamp: float, frame: bytes) -> None:
        sec = int(timestamp)
        usec = int(round((timestamp - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self._fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self._fh.write(frame)

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

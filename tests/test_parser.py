import struct

from packetvault.parser import build_database, load_database, read_xml, write_xml
from packetvault.pcapio import RawFrame, decode_frame, iter_frames


def test_parses_every_frame(lab, records):
    assert len(records) == lab["labels"]["packets"]
    assert [r.index for r in records] == list(range(1, len(records) + 1))


def test_decodes_tcp_handshake_fields(records):
    syn = next(r for r in records if r.protocol == "TCP" and r.tcp_flags == "SYN")
    assert syn.src_ip.startswith("192.168.56.")
    assert syn.src_mac.startswith("08:00:27")
    assert syn.dst_port is not None and syn.payload_len == 0
    assert any(r.tcp_flags == "SYN,ACK" for r in records)


def test_protocol_mix(records):
    assert {"TCP", "UDP", "ICMP"} <= {r.protocol for r in records}


def test_xml_round_trip(records, tmp_path):
    path = tmp_path / "out.xml"
    write_xml(records[:200], path, metadata={"source_file": "lab.pcap"})
    assert read_xml(path) == records[:200]


def test_sqlite_round_trip(records):
    hashes = [f"{i:064x}" for i in range(len(records))]
    loaded, stored, meta = load_database(build_database(records, hashes, metadata={"k": "v"}))
    assert loaded == records and stored == hashes and meta == {"k": "v"}


def test_malformed_frame_is_kept_not_dropped():
    rec = decode_frame(7, RawFrame(1.5, 1, b"\x00" * 13, 13))  # truncated Ethernet header
    assert rec.index == 7 and rec.protocol == "OTHER" and rec.frame_len == 13


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    body += b"\x00" * (-len(body) % 4)
    length = len(body) + 12
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def test_reads_pcapng(tmp_path, records, lab):
    # Re-wrap the first frames of the classic capture as a PCAPNG file.
    frames = list(iter_frames(lab["pcap"]))[:20]
    data = _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    data += _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    for f in frames:
        ticks = int(round(f.timestamp * 1e6))
        epb = struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(f.data), f.orig_len) + f.data
        data += _pcapng_block(6, epb)
    path = tmp_path / "x.pcapng"
    path.write_bytes(data)
    decoded = [decode_frame(i, f) for i, f in enumerate(iter_frames(path), start=1)]
    assert decoded == records[:20]

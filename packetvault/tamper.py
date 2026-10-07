"""Attack simulator for demonstrations and tests.

Models an adversary - typically an insider who knows the case passphrase -
altering a sealed bundle in place. Every mode must be caught by ``verify``.

modify     change one field of record k, leave the stored hashes alone
delete     remove record k
insert     inject a forged packet after record k (reusing a stored hash)
recompute  change record k *and* recompute every later hash (strongest insider)
bitflip    flip one bit of the ciphertext (no passphrase needed)
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from . import chain, vault_crypto
from .bundle import CONTAINER_NAME
from .models import PacketRecord
from .parser import build_database, load_database

MODES = ("modify", "delete", "insert", "recompute", "bitflip")


def tamper_case(case_dir: str | Path, mode: str, index: int, passphrase: str | None = None,
                field: str = "dst_port", value: str = "4444") -> str:
    """Apply one attack to the bundle and return a description of what was done."""
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}; choose from {MODES}")
    path = Path(case_dir) / CONTAINER_NAME
    blob = path.read_bytes()

    if mode == "bitflip":
        offset = min(vault_crypto.HEADER_LEN + index, len(blob) - vault_crypto.TAG_LEN - 1)
        mutated = bytearray(blob)
        mutated[offset] ^= 0x01
        path.write_bytes(bytes(mutated))
        return f"flipped 1 bit of ciphertext at byte offset {offset}"

    if passphrase is None:
        raise ValueError(f"mode {mode!r} needs the case passphrase (insider attack)")
    records, hashes, meta = load_database(vault_crypto.decrypt(blob, passphrase))
    pos = index - 1
    if not 0 <= pos < len(records):
        raise ValueError(f"index {index} is out of range 1..{len(records)}")
    original = records[pos]

    if mode in ("modify", "recompute"):
        records[pos] = _with_field(original, field, value)
        what = f"changed {field} of frame #{index}: {getattr(original, field)!r} -> {getattr(records[pos], field)!r}"
        if mode == "recompute":
            acquisition = json.loads(meta["acquisition"])
            hashes = chain.seal(records, acquisition).hashes
            what += " and recomputed all subsequent chain hashes"
    elif mode == "delete":
        del records[pos], hashes[pos]
        records = _renumber(records)
        what = f"deleted frame #{index} ({original.src_ip} -> {original.dst_ip} {original.protocol}) and renumbered later frames"
    else:  # insert
        forged = dataclasses.replace(original, src_ip="10.66.66.66", tcp_flags="SYN", payload_len=0)
        records.insert(pos + 1, forged)
        hashes.insert(pos + 1, hashes[pos])
        records = _renumber(records)
        what = f"inserted a forged packet from 10.66.66.66 after frame #{index} and renumbered later frames"

    db_bytes = build_database(records, hashes, metadata=meta)
    header = vault_crypto.ContainerHeader.unpack(blob)
    path.write_bytes(vault_crypto.encrypt(db_bytes, passphrase, iterations=header.iterations, salt=header.salt))
    return what + " (container re-encrypted with the correct passphrase)"


def _renumber(records: list[PacketRecord]) -> list[PacketRecord]:
    """A careful forger keeps frame numbers contiguous so the gap is not obvious."""
    return [r if r.index == i else dataclasses.replace(r, index=i) for i, r in enumerate(records, start=1)]


def _with_field(rec: PacketRecord, field: str, value: str) -> PacketRecord:
    current = getattr(rec, field)
    if isinstance(current, int) or field in ("src_port", "dst_port", "frame_len", "payload_len", "index"):
        return dataclasses.replace(rec, **{field: int(value)})
    return dataclasses.replace(rec, **{field: value})

"""M2 - Integrity Sealing Engine (SHA-256 rolling hash chain).

    H0 = SHA256("PacketVault/v1/H0" || canonical(acquisition_metadata))
    Hn = SHA256(Hn-1 || canonical(record_n))

Each stored hash commits to every record before it, so altering, inserting
or deleting record k invalidates H_k ... H_N. The verifier walks the chain
and reports the first position where the recomputed hash diverges from the
stored one.

An insider who edits a record *and* recomputes every later hash produces an
internally-consistent chain - but its root no longer matches the root in the
RSA-signed report. Signed checkpoint hashes (every ``CHECKPOINT_INTERVAL``
records) then narrow the tampering down to a window of records.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Sequence

from .models import PacketRecord, canonical_json

H0_DOMAIN = b"PacketVault/v1/H0"
CHECKPOINT_INTERVAL = 256


def genesis_hash(acquisition_metadata: dict) -> bytes:
    return hashlib.sha256(H0_DOMAIN + canonical_json(acquisition_metadata)).digest()


def link(prev: bytes, record: PacketRecord) -> bytes:
    return hashlib.sha256(prev + record.canonical_bytes()).digest()


@dataclass
class SealedChain:
    h0: str
    hashes: list[str]  # hex digest per record, same order as the records
    checkpoints: dict[int, str]  # 1-based position -> hex digest

    @property
    def root(self) -> str:
        return self.hashes[-1] if self.hashes else self.h0


def seal(records: Sequence[PacketRecord], acquisition_metadata: dict,
         checkpoint_interval: int = CHECKPOINT_INTERVAL) -> SealedChain:
    h = genesis_hash(acquisition_metadata)
    h0 = h.hex()
    hashes: list[str] = []
    checkpoints: dict[int, str] = {}
    for pos, rec in enumerate(records, start=1):
        h = link(h, rec)
        hashes.append(h.hex())
        if pos % checkpoint_interval == 0 or pos == len(records):
            checkpoints[pos] = hashes[-1]
    return SealedChain(h0=h0, hashes=hashes, checkpoints=checkpoints)


@dataclass
class ChainVerdict:
    ok: bool
    records_checked: int
    first_divergence: int | None = None  # 1-based position of the first bad record
    divergent_record_index: int | None = None  # that record's frame number
    window: tuple[int, int] | None = None  # (from, to) positions, when only checkpoints localise
    recomputed_root: str | None = None
    problems: list[str] = field(default_factory=list)


def verify(records: Sequence[PacketRecord], stored_hashes: Sequence[str | None], acquisition_metadata: dict,
           expected_root: str | None = None, expected_count: int | None = None,
           checkpoints: dict[int, str] | None = None) -> ChainVerdict:
    """Recompute the chain over ``records`` and compare against stored and signed values."""
    verdict = ChainVerdict(ok=True, records_checked=len(records))
    h = genesis_hash(acquisition_metadata)
    recomputed: list[str] = []

    for pos, (rec, stored) in enumerate(zip(records, stored_hashes), start=1):
        h = link(h, rec)
        recomputed.append(h.hex())
        if verdict.first_divergence is None and stored != recomputed[-1]:
            verdict.first_divergence = pos
            verdict.divergent_record_index = rec.index
            verdict.problems.append(
                f"hash chain diverges at position {pos} (frame #{rec.index}): "
                f"stored {_short(stored)} != recomputed {_short(recomputed[-1])}"
            )
        if verdict.first_divergence is None and rec.index != pos:
            verdict.first_divergence = pos
            verdict.divergent_record_index = rec.index
            verdict.problems.append(f"frame numbering breaks at position {pos}: expected #{pos}, found #{rec.index}")

    verdict.recomputed_root = recomputed[-1] if recomputed else genesis_hash(acquisition_metadata).hex()

    if expected_count is not None and expected_count != len(records):
        verdict.problems.append(f"record count is {len(records)} but the signed report says {expected_count}")

    if expected_root is not None and verdict.recomputed_root != expected_root:
        verdict.problems.append(
            f"recomputed root {_short(verdict.recomputed_root)} != signed root {_short(expected_root)}"
        )
        if verdict.first_divergence is None and checkpoints:
            verdict.window = _localise_with_checkpoints(recomputed, checkpoints)
            if verdict.window:
                lo, hi = verdict.window
                verdict.problems.append(
                    f"stored hashes were recomputed (chain is self-consistent); "
                    f"signed checkpoints localise tampering to positions {lo}-{hi}"
                )

    verdict.ok = not verdict.problems
    return verdict


def _localise_with_checkpoints(recomputed: list[str], checkpoints: dict[int, str]) -> tuple[int, int] | None:
    prev = 0
    for pos in sorted(checkpoints):
        actual = recomputed[pos - 1] if pos <= len(recomputed) else None
        if actual != checkpoints[pos]:
            return prev + 1, pos
        prev = pos
    return (prev + 1, len(recomputed)) if len(recomputed) > prev else None


def _short(digest: str | None) -> str:
    return "<missing>" if digest is None else digest[:16] + "..."

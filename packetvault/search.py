"""Searchable encryption: a blind index over the sealed packet records.

The evidence container (``evidence.db.enc``) is one AES-256-GCM blob, so
answering a query means decrypting all of it. The search index
(``search.idx``) lets an *untrusted store* answer equality queries without
ever seeing a key, a field value or a query value.

Two roles, kept apart in the code
---------------------------------
``IndexStore`` (the server, holds no keys)
    Holds a table of opaque tokens -> record positions and a table of
    individually encrypted records. Its only operation is "which positions
    carry these tokens?", then "hand over those ciphertexts".

``SearchClient`` (the investigator, holds the passphrase)
    Derives the keys, turns each query value into a *trapdoor* token, sends
    only tokens to the store, and decrypts and authenticates the hits.

Construction (blind index, as in CipherSweet / MongoDB queryable encryption)
----------------------------------------------------------------------------
    master  = PBKDF2-HMAC-SHA256(passphrase, index_salt, iterations)
    k_tok   = HMAC-SHA256(master, "PacketVault/v1/idx-token")
    k_rec   = HMAC-SHA256(master, "PacketVault/v1/idx-record")
    token   = HMAC-SHA256(k_tok, field || 0x00 || value)[:16]          (128 bits)
    record  = AES-256-GCM(k_rec, nonce, pad64(record || chain hash),
                          AAD = "PVIDX/1" || H0 || position)

* Domain separation: ``src_ip=X`` and ``dst_ip=X`` give different tokens.
* The AAD binds every ciphertext to this case (H0 from the signed report) and
  to its position, so a store cannot swap in records from another case or
  reorder them.
* Records are padded to a multiple of 64 bytes so ciphertext length does not
  reveal, e.g., IPv4 vs IPv6 or whether ports are present.
* The index file's SHA-256 is in the signed report, so deleting or editing
  token rows (hiding packets from search) is caught by ``verify``.
* A separate PBKDF2 salt keeps these keys independent of the container key.

Leakage (what the store *does* learn) - the standard blind-index trade-off
--------------------------------------------------------------------------
* Equality pattern: which records share a value in the same field, so value
  frequencies per field (the most common destination port is probably 443).
  Low-cardinality fields (protocol, TCP flags) leak the most.
* Access pattern: which positions match a query; search pattern: whether two
  queries were the same.
* Record count and positions (frame order) - already public via the report.
It never learns a field value, a query value or a record's contents, and
without the key it cannot compute a token to test a guess.
Only equality queries are supported; ranges (timestamps) would need
order-revealing encryption, which leaks far more.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from Crypto.Cipher import AES

from .models import RECORD_FIELDS, PacketRecord, canonical_json
from .vault_crypto import DEFAULT_ITERATIONS, DecryptionError, derive_key

INDEX_NAME = "search.idx"
FORMAT = "PVIDX/1"
TOKEN_BYTES = 16
NONCE_BYTES = 12
PAD_TO = 64
INDEXED_FIELDS = ("src_ip", "dst_ip", "protocol", "src_port", "dst_port", "tcp_flags")

# query criterion -> record fields it matches (OR across fields)
CRITERIA = {
    "src_ip": ("src_ip",), "dst_ip": ("dst_ip",), "host": ("src_ip", "dst_ip"),
    "src_port": ("src_port",), "dst_port": ("dst_port",), "port": ("src_port", "dst_port"),
    "protocol": ("protocol",), "flags": ("tcp_flags",),
}

_SCHEMA = """
CREATE TABLE meta    (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE tokens  (token BLOB NOT NULL, position INTEGER NOT NULL, PRIMARY KEY (token, position)) WITHOUT ROWID;
CREATE TABLE records (position INTEGER PRIMARY KEY, nonce BLOB NOT NULL, ct BLOB NOT NULL);
"""


class IndexIntegrityError(Exception):
    """The search index does not match the signed report (replaced, edited or missing)."""


# --------------------------------------------------------------------------- keys and tokens

@dataclass(frozen=True)
class SearchKeys:
    token: bytes
    record: bytes

    @classmethod
    def derive(cls, passphrase: str, salt: bytes, iterations: int) -> "SearchKeys":
        master = derive_key(passphrase, salt, iterations)
        return cls(hmac.new(master, b"PacketVault/v1/idx-token", hashlib.sha256).digest(),
                   hmac.new(master, b"PacketVault/v1/idx-record", hashlib.sha256).digest())

    def key_check(self) -> str:
        """Lets the client reject a wrong passphrase even when a query has no hits."""
        return hmac.new(self.token, b"PacketVault/v1/key-check", hashlib.sha256).hexdigest()[:32]


def normalise(field_name: str, value) -> str:
    if field_name in ("src_port", "dst_port"):
        return str(int(value))
    if field_name == "protocol":
        return str(value).strip().upper()
    if field_name == "tcp_flags":
        return ",".join(p.strip() for p in str(value).upper().split(",") if p.strip())
    return str(value).strip()


def make_token(k_token: bytes, field_name: str, value) -> bytes:
    msg = field_name.encode() + b"\x00" + normalise(field_name, value).encode()
    return hmac.new(k_token, msg, hashlib.sha256).digest()[:TOKEN_BYTES]


def record_tokens(k_token: bytes, rec: PacketRecord) -> list[bytes]:
    return [make_token(k_token, f, getattr(rec, f)) for f in INDEXED_FIELDS
            if getattr(rec, f) not in (None, "")]


def _aad(h0: str, position: int) -> bytes:
    return FORMAT.encode() + bytes.fromhex(h0) + struct.pack(">Q", position)


def _record_plaintext(rec: PacketRecord, chain_hash: str | None) -> bytes:
    data = canonical_json({"r": [getattr(rec, n) for n in RECORD_FIELDS], "h": chain_hash})
    return data.ljust(-(-len(data) // PAD_TO) * PAD_TO, b" ")  # JSON ignores trailing spaces


# --------------------------------------------------------------------------- build (at seal time)

def build_index(records: Sequence[PacketRecord], chain_hashes: Sequence[str], h0: str, passphrase: str,
                path: str | Path, iterations: int = DEFAULT_ITERATIONS) -> dict:
    """Write ``search.idx`` and return its description for the signed report."""
    salt = os.urandom(16)
    keys = SearchKeys.derive(passphrase, salt, iterations)
    token_rows, record_rows = [], []
    for pos, (rec, h) in enumerate(zip(records, chain_hashes), start=1):
        token_rows += [(t, pos) for t in record_tokens(keys.token, rec)]
        nonce = os.urandom(NONCE_BYTES)
        cipher = AES.new(keys.record, AES.MODE_GCM, nonce=nonce)
        cipher.update(_aad(h0, pos))
        ct, tag = cipher.encrypt_and_digest(_record_plaintext(rec, h))
        record_rows.append((pos, nonce, ct + tag))
    token_rows.sort()  # storage order follows the token, not the capture

    meta = {"format": FORMAT, "salt": salt.hex(), "iterations": str(iterations), "h0": h0,
            "fields": json.dumps(INDEXED_FIELDS), "token_bytes": str(TOKEN_BYTES), "key_check": keys.key_check()}
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(_SCHEMA)
        conn.executemany("INSERT INTO meta VALUES (?, ?)", sorted(meta.items()))
        conn.executemany("INSERT INTO tokens VALUES (?, ?)", token_rows)
        conn.executemany("INSERT INTO records VALUES (?, ?, ?)", record_rows)
        conn.commit()
        data = conn.serialize()
    finally:
        conn.close()
    path = Path(path)
    path.write_bytes(data)
    return {
        "file": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "scheme": "blind index: HMAC-SHA256 tokens (128-bit) per field + AES-256-GCM per record",
        "fields": list(INDEXED_FIELDS),
        "kdf": "PBKDF2-HMAC-SHA256",
        "kdf_iterations": iterations,
        "records": len(record_rows),
        "tokens": len(token_rows),
    }


# --------------------------------------------------------------------------- server side (no keys)

class IndexStore:
    """The untrusted side: matches opaque tokens and returns ciphertexts. Never sees a key."""

    def __init__(self, data: bytes):
        self.conn = sqlite3.connect(":memory:")
        self.conn.deserialize(data)
        self.meta = dict(self.conn.execute("SELECT key, value FROM meta"))
        if self.meta.get("format") != FORMAT:
            raise ValueError("not a PacketVault search index")
        self.seen: list[str] = []  # every token the store was asked about, for the demo

    @classmethod
    def open(cls, path: str | Path) -> "IndexStore":
        return cls(Path(path).read_bytes())

    def lookup(self, token_groups: list[list[bytes]], frame_from: int | None = None,
               frame_to: int | None = None, limit: int = 100) -> tuple[int, list[tuple[int, bytes, bytes]]]:
        """Positions carrying at least one token of *every* group (AND of ORs), plus their ciphertexts."""
        clauses, params = [], []
        for group in token_groups:
            clauses.append(f"position IN (SELECT position FROM tokens WHERE token IN ({','.join('?' * len(group))}))")
            params += group
            self.seen += [t.hex() for t in group]
        if frame_from is not None:
            clauses.append("position >= ?")
            params.append(int(frame_from))
        if frame_to is not None:
            clauses.append("position <= ?")
            params.append(int(frame_to))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        total = self.conn.execute(f"SELECT COUNT(*) FROM records {where}", params).fetchone()[0]
        rows = self.conn.execute(f"SELECT position, nonce, ct FROM records {where} ORDER BY position LIMIT ?",
                                 params + [int(limit)]).fetchall()
        return total, rows

    def all_records(self) -> list[tuple[int, bytes, bytes]]:
        return self.conn.execute("SELECT position, nonce, ct FROM records ORDER BY position").fetchall()

    def all_tokens(self) -> set[tuple[bytes, int]]:
        return set(self.conn.execute("SELECT token, position FROM tokens"))

    def close(self) -> None:
        self.conn.close()


# --------------------------------------------------------------------------- client side (has the keys)

@dataclass
class SearchResult:
    total: int
    rows: list[dict]
    trapdoors: list[dict] = field(default_factory=list)
    kdf_ms: float = 0.0
    lookup_ms: float = 0.0
    decrypt_ms: float = 0.0


class SearchClient:
    def __init__(self, store: IndexStore, passphrase: str, expected_h0: str):
        start = time.perf_counter()
        meta = store.meta
        self.keys = SearchKeys.derive(passphrase, bytes.fromhex(meta["salt"]), int(meta["iterations"]))
        self.kdf_ms = (time.perf_counter() - start) * 1000
        if not hmac.compare_digest(self.keys.key_check(), meta["key_check"]):
            raise DecryptionError("wrong passphrase for the search index")
        self.store, self.h0 = store, expected_h0

    def trapdoors(self, criteria: dict) -> tuple[list[list[bytes]], list[dict]]:
        groups, shown = [], []
        for name, value in criteria.items():
            if value in (None, ""):
                continue
            if name not in CRITERIA:
                raise ValueError(f"unknown search field {name!r}; choose from {sorted(CRITERIA)}")
            group = []
            for f in CRITERIA[name]:
                t = make_token(self.keys.token, f, value)
                group.append(t)
                shown.append({"criterion": name, "field": f, "token": t.hex()})
            groups.append(group)
        return groups, shown

    def decrypt(self, position: int, nonce: bytes, blob: bytes) -> dict:
        cipher = AES.new(self.keys.record, AES.MODE_GCM, nonce=nonce)
        cipher.update(_aad(self.h0, position))
        try:
            data = json.loads(cipher.decrypt_and_verify(blob[:-16], blob[-16:]))
        except ValueError:
            raise DecryptionError(f"index record at position {position} failed its GCM check "
                                  "(tampered, or from a different case)") from None
        row = dict(zip(RECORD_FIELDS, data["r"]))
        row["idx"] = row.pop("index")
        row["chain_hash"] = data["h"]
        return row

    def search(self, criteria: dict, frame_from: int | None = None, frame_to: int | None = None,
               limit: int = 100) -> SearchResult:
        groups, shown = self.trapdoors(criteria)
        start = time.perf_counter()
        total, hits = self.store.lookup(groups, frame_from, frame_to, limit)
        lookup_ms = (time.perf_counter() - start) * 1000
        start = time.perf_counter()
        rows = [self.decrypt(pos, nonce, ct) for pos, nonce, ct in hits]
        return SearchResult(total, rows, shown, round(self.kdf_ms, 1), round(lookup_ms, 2),
                            round((time.perf_counter() - start) * 1000, 2))


# --------------------------------------------------------------------------- case-level helpers

def check_index_digest(case_dir: str | Path, report: dict) -> bytes:
    """Index bytes, after checking them against the (signed) report's digest."""
    info = report.get("search_index")
    if not info:
        raise FileNotFoundError("this case was sealed without a search index")
    path = Path(case_dir) / info["file"]
    if not path.is_file():
        raise IndexIntegrityError(f"{info['file']} is missing")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != info["sha256"]:
        raise IndexIntegrityError(f"{info['file']} does not match the SHA-256 in the signed report "
                                  "(token rows or ciphertexts were added, removed or changed)")
    return data


def search_case(case_dir: str | Path, passphrase: str, criteria: dict, *, frame_from: int | None = None,
                frame_to: int | None = None, limit: int = 100, public_key_path: str | Path | None = None) -> SearchResult:
    """Blind-index search of a sealed case. With ``public_key_path`` the report signature is checked first."""
    from .bundle import REPORT_NAME, SIGNATURE_NAME
    from . import signing

    case_dir = Path(case_dir)
    report_bytes = (case_dir / REPORT_NAME).read_bytes()
    if public_key_path is not None and not signing.verify(report_bytes, (case_dir / SIGNATURE_NAME).read_bytes(),
                                                          signing.load_public_key(public_key_path)):
        raise IndexIntegrityError("report.json signature is invalid; the index digest cannot be trusted")
    report = json.loads(report_bytes)
    store = IndexStore(check_index_digest(case_dir, report))
    try:
        return SearchClient(store, passphrase, report["integrity"]["h0"]).search(
            criteria, frame_from, frame_to, limit)
    finally:
        store.close()


def consistency(store: IndexStore, client: SearchClient, records: Sequence[PacketRecord],
                chain_hashes: Sequence[str | None]) -> int | None:
    """First position where the index disagrees with the decrypted container, else None."""
    first: int | None = None
    entries = store.all_records()
    for pos, nonce, ct in entries:
        rec = records[pos - 1] if pos <= len(records) else None
        row = client.decrypt(pos, nonce, ct)
        if rec is None or row["chain_hash"] != chain_hashes[pos - 1] or \
                [row["idx" if n == "index" else n] for n in RECORD_FIELDS] != [getattr(rec, n) for n in RECORD_FIELDS]:
            first = pos
            break
    if len(entries) != len(records):
        n = min(len(entries), len(records)) + 1
        first = n if first is None else min(first, n)
    expected = {(t, pos) for pos, rec in enumerate(records, start=1) for t in record_tokens(client.keys.token, rec)}
    diff = expected ^ store.all_tokens()
    if diff:
        n = min(pos for _, pos in diff)
        first = n if first is None else min(first, n)
    return first


def drop_from_index(path: str | Path, position: int) -> int:
    """DEMO ATTACK: a keyless store deletes one record's token rows to hide it from search."""
    store = IndexStore.open(path)
    try:
        n = store.conn.execute("DELETE FROM tokens WHERE position = ?", (position,)).rowcount
        store.conn.commit()
        Path(path).write_bytes(store.conn.serialize())
    finally:
        store.close()
    return n

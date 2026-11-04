"""Keyed integrity layer: Nested MAC (NMAC) over SHA-256, and why the nesting matters.

    NMAC_{k1,k2}(m) = H(k2 || H(k1 || m))

The inner hash compresses the message under k1; the outer hash re-keys the
result under an independent k2 (Bellare, Canetti, Krawczyk 1996). HMAC is the
practical instance of the same construction with k1, k2 derived from one key
via ipad/opad.

The naive *prefix MAC* ``H(k || m)`` is broken for Merkle-Damgard hashes such
as SHA-256: the tag *is* the hash's internal state, so anyone holding
(m, tag) can compute a valid tag for ``m || padding || extension`` without the
key (length-extension attack). ``forge_prefix_mac`` below does exactly that
with a pure-Python SHA-256, and ``length_extension_demo`` shows the same
forgery failing against NMAC, because the attacker never sees the inner state.

Use in PacketVault (separation of duties)
    The SHA-256 chain is unkeyed: an insider who knows the *case passphrase*
    can edit a record and recompute every later hash, and only the signed
    root and checkpoints (a 256-record window) reveal it. With a *custodian
    key* - held by the evidence custodian, not by analysts who query the
    case - every chain link also gets a tag

        T_n = NMAC_{k1,k2}( "PacketVault/v1/T" || n || H_n )

    stored inside the encrypted store. The verifier recomputes H_n from the
    records and checks T_n, so the first record whose content changed is
    pinpointed exactly, even after a full chain recompute, because the
    insider cannot forge tags without the custodian key.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from pathlib import Path

DIGEST_SIZE = 32
_INNER_LABEL = b"PacketVault/nmac/k1-inner"
_OUTER_LABEL = b"PacketVault/nmac/k2-outer"
_TAG_DOMAIN = b"PacketVault/v1/T"


def derive_keys(master: bytes) -> tuple[bytes, bytes]:
    """Two independent 256-bit keys (k1 inner, k2 outer) from one master key."""
    k1 = hmac.new(master, _INNER_LABEL, hashlib.sha256).digest()
    k2 = hmac.new(master, _OUTER_LABEL, hashlib.sha256).digest()
    return k1, k2


def nmac(k1: bytes, k2: bytes, message: bytes) -> bytes:
    inner = hashlib.sha256(k1 + message).digest()
    return hashlib.sha256(k2 + inner).digest()


def nmac_trace(k1: bytes, k2: bytes, message: bytes) -> dict:
    """Intermediate values, for the dashboard's step-by-step view."""
    inner = hashlib.sha256(k1 + message).digest()
    outer = hashlib.sha256(k2 + inner).digest()
    return {"inner": inner.hex(), "outer": outer.hex()}


def verify(k1: bytes, k2: bytes, message: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(nmac(k1, k2, message), tag)


def chain_tag(k1: bytes, k2: bytes, position: int, chain_hash_hex: str) -> str:
    """T_n for one chain link (position is 1-based)."""
    return nmac(k1, k2, _TAG_DOMAIN + struct.pack(">Q", position) + bytes.fromhex(chain_hash_hex)).hex()


def chain_tags(custodian_key: bytes, chain_hashes: list[str]) -> list[str]:
    k1, k2 = derive_keys(custodian_key)
    return [chain_tag(k1, k2, pos, h) for pos, h in enumerate(chain_hashes, start=1)]


def key_fingerprint(custodian_key: bytes) -> str:
    fp = hashlib.sha256(b"PacketVault/custodian-fp" + custodian_key).hexdigest()[:32]
    return ":".join(fp[i:i + 2] for i in range(0, 32, 2))


def generate_custodian_key(path: str | Path) -> bytes:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    path.write_text(key.hex() + "\n")
    return key


def load_custodian_key(path: str | Path) -> bytes:
    key = bytes.fromhex(Path(path).read_text().strip())
    if len(key) != 32:
        raise ValueError("custodian key must be 32 bytes (64 hex characters)")
    return key


def prefix_mac(key: bytes, message: bytes) -> bytes:
    """INSECURE ``H(k || m)``, kept only to demonstrate the attack."""
    return hashlib.sha256(key + message).digest()


# --------------------------------------------------------------------------- SHA-256 length extension

_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _compress(state: list[int], block: bytes) -> list[int]:
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        t1 = (h + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) + ((e & f) ^ (~e & g)) + _K[i] + w[i]) & 0xFFFFFFFF
        t2 = ((_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & 0xFFFFFFFF
        a, b, c, d, e, f, g, h = (t1 + t2) & 0xFFFFFFFF, a, b, c, (d + t1) & 0xFFFFFFFF, e, f, g
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def sha256_padding(length: int) -> bytes:
    """Merkle-Damgard padding SHA-256 appends to a message of ``length`` bytes."""
    return b"\x80" + b"\x00" * ((55 - length) % 64) + struct.pack(">Q", length * 8)


def forge_prefix_mac(known_tag: bytes, original_len: int, extension: bytes) -> tuple[bytes, bytes]:
    """Length-extension forgery against ``H(k || m)`` with no knowledge of ``k``.

    ``original_len`` is len(k) + len(m) (the attacker only needs the key length).
    Returns (glue, forged_tag): ``H(k || m || glue || extension) == forged_tag``.
    """
    glue = sha256_padding(original_len)
    state = list(struct.unpack(">8I", known_tag))  # the tag *is* the internal state
    processed = original_len + len(glue)
    tail = extension + sha256_padding(processed + len(extension))
    for i in range(0, len(tail), 64):
        state = _compress(state, tail[i:i + 64])
    return glue, struct.pack(">8I", *state)


def length_extension_demo(master: bytes, message: bytes = b"case=CASE-001&role=analyst",
                          extension: bytes = b"&role=custodian") -> dict:
    """Run the same forgery against the prefix MAC and against NMAC."""
    key = hashlib.sha256(master).digest()  # 32-byte key; attacker knows only its length
    k1, k2 = derive_keys(master)

    prefix_tag = prefix_mac(key, message)
    glue, forged = forge_prefix_mac(prefix_tag, len(key) + len(message), extension)
    forged_msg = message + glue + extension
    prefix_accepts = hmac.compare_digest(prefix_mac(key, forged_msg), forged)

    nmac_tag = nmac(k1, k2, message)
    glue_n, forged_n = forge_prefix_mac(nmac_tag, len(k2) + DIGEST_SIZE, extension)
    nmac_accepts = verify(k1, k2, message + glue_n + extension, forged_n)

    return {
        "message": message.decode(),
        "extension": extension.decode(),
        "forged_message_hex": forged_msg.hex(),
        "forged_message_printable": forged_msg.decode("latin-1").encode("unicode_escape").decode(),
        "prefix_mac": {"tag": prefix_tag.hex(), "forged_tag": forged.hex(), "forgery_accepted": prefix_accepts},
        "nmac": {"tag": nmac_tag.hex(), "forged_tag": forged_n.hex(), "forgery_accepted": nmac_accepts},
    }


def benchmark(sizes=(64, 256, 1024, 4096), min_time: float = 0.05) -> list[dict]:
    """Microseconds per tag for prefix MAC, NMAC and stdlib HMAC-SHA256."""
    master = b"\x11" * 32
    k1, k2 = derive_keys(master)
    out = []
    for size in sizes:
        msg = b"\xab" * size
        row = {"bytes": size}
        for name, fn in (("prefix", lambda: prefix_mac(k1, msg)),
                         ("nmac", lambda: nmac(k1, k2, msg)),
                         ("hmac", lambda: hmac.new(master, msg, hashlib.sha256).digest())):
            n, start = 0, time.perf_counter()
            while (elapsed := time.perf_counter() - start) < min_time:
                for _ in range(200):
                    fn()
                n += 200
            row[name] = round(elapsed / n * 1e6, 3)
        out.append(row)
    return out

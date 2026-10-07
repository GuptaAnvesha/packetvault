"""M3 - Confidentiality Layer (AES-256-GCM + PBKDF2-HMAC-SHA256).

Encrypted container layout (all integers big-endian)::

    offset  size  field
    0       4     magic  b"PVLT"
    4       1     format version (1)
    5       1     cipher id (1 = AES-256-GCM)
    6       4     PBKDF2 iteration count
    10      16    salt (random, per case)
    26      12    GCM nonce (random, per encryption)
    38      n     ciphertext
    38+n    16    GCM authentication tag

The 38-byte header is authenticated as GCM associated data, so tampering
with the salt, nonce or iteration count is detected exactly like tampering
with the ciphertext itself.

AES-CBC and AES-CTR are implemented alongside GCM for the M7 comparative
benchmark only; neither provides integrity on its own.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

MAGIC = b"PVLT"
FORMAT_VERSION = 1
CIPHER_AES256_GCM = 1
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
DEFAULT_ITERATIONS = 600_000  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256

_HEADER = struct.Struct("!4sBBI16s12s")
HEADER_LEN = _HEADER.size  # 38


class DecryptionError(Exception):
    """Wrong passphrase, or the container / its header was modified."""


@dataclass(frozen=True)
class ContainerHeader:
    version: int
    cipher: int
    iterations: int
    salt: bytes
    nonce: bytes

    def pack(self) -> bytes:
        return _HEADER.pack(MAGIC, self.version, self.cipher, self.iterations, self.salt, self.nonce)

    @classmethod
    def unpack(cls, blob: bytes) -> "ContainerHeader":
        if len(blob) < HEADER_LEN + TAG_LEN:
            raise DecryptionError("container is truncated")
        magic, version, cipher, iterations, salt, nonce = _HEADER.unpack(blob[:HEADER_LEN])
        if magic != MAGIC:
            raise DecryptionError("not a PacketVault container (bad magic)")
        if version != FORMAT_VERSION or cipher != CIPHER_AES256_GCM:
            raise DecryptionError(f"unsupported container version {version} / cipher {cipher}")
        return cls(version, cipher, iterations, salt, nonce)


def derive_key(passphrase: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    return PBKDF2(passphrase.encode("utf-8"), salt, dkLen=KEY_LEN, count=iterations, hmac_hash_module=SHA256)


def encrypt(plaintext: bytes, passphrase: str, iterations: int = DEFAULT_ITERATIONS,
            salt: bytes | None = None) -> bytes:
    header = ContainerHeader(
        version=FORMAT_VERSION,
        cipher=CIPHER_AES256_GCM,
        iterations=iterations,
        salt=salt or get_random_bytes(SALT_LEN),
        nonce=get_random_bytes(NONCE_LEN),
    )
    key = derive_key(passphrase, header.salt, iterations)
    header_bytes = header.pack()
    cipher = AES.new(key, AES.MODE_GCM, nonce=header.nonce, mac_len=TAG_LEN)
    cipher.update(header_bytes)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return header_bytes + ciphertext + tag


def decrypt(blob: bytes, passphrase: str) -> bytes:
    header = ContainerHeader.unpack(blob)
    key = derive_key(passphrase, header.salt, header.iterations)
    cipher = AES.new(key, AES.MODE_GCM, nonce=header.nonce, mac_len=TAG_LEN)
    cipher.update(blob[:HEADER_LEN])
    try:
        return cipher.decrypt_and_verify(blob[HEADER_LEN:-TAG_LEN], blob[-TAG_LEN:])
    except ValueError as exc:
        raise DecryptionError("GCM authentication tag mismatch: wrong passphrase or tampered ciphertext") from exc


# --------------------------------------------------------------------------- comparison modes (M7)


def encrypt_cbc(key: bytes, plaintext: bytes) -> bytes:
    iv = get_random_bytes(16)
    return iv + AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pad(plaintext, AES.block_size))


def decrypt_cbc(key: bytes, blob: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_CBC, iv=blob[:16]).decrypt(blob[16:]), AES.block_size)


def encrypt_ctr(key: bytes, plaintext: bytes) -> bytes:
    nonce = get_random_bytes(8)
    return nonce + AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(plaintext)


def decrypt_ctr(key: bytes, blob: bytes) -> bytes:
    return AES.new(key, AES.MODE_CTR, nonce=blob[:8]).decrypt(blob[8:])


def encrypt_gcm_raw(key: bytes, plaintext: bytes) -> bytes:
    nonce = get_random_bytes(NONCE_LEN)
    ciphertext, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag

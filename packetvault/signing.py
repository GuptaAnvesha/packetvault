"""RSA-2048 investigator keys and PKCS#1 v1.5 detached signatures (M5 / M6)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

RSA_BITS = 2048
SIGNATURE_ALGORITHM = "RSA-2048 / PKCS#1 v1.5 / SHA-256"


def generate_keypair(out_dir: str | Path, name: str = "investigator",
                     key_passphrase: str | None = None) -> tuple[Path, Path]:
    """Create ``<name>_private.pem`` and ``<name>_public.pem`` in ``out_dir``.

    With ``key_passphrase`` the private key is stored as encrypted PKCS#8
    (scrypt + AES-128-CBC).
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key = RSA.generate(RSA_BITS)
    priv_path = out_dir / f"{name}_private.pem"
    pub_path = out_dir / f"{name}_public.pem"
    if key_passphrase:
        priv_pem = key.export_key(format="PEM", pkcs=8, passphrase=key_passphrase,
                                  protection="scryptAndAES128-CBC")
    else:
        priv_pem = key.export_key(format="PEM", pkcs=8)
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(key.public_key().export_key(format="PEM"))
    return priv_path, pub_path


def load_private_key(path: str | Path, key_passphrase: str | None = None) -> RSA.RsaKey:
    key = RSA.import_key(Path(path).read_bytes(), passphrase=key_passphrase)
    if not key.has_private():
        raise ValueError(f"{path} is a public key; signing needs the private key")
    return key


def load_public_key(path: str | Path) -> RSA.RsaKey:
    return RSA.import_key(Path(path).read_bytes()).public_key()


def fingerprint(key: RSA.RsaKey) -> str:
    """SHA-256 over the DER-encoded public key, as colon-separated hex (first 16 bytes)."""
    digest = hashlib.sha256(key.public_key().export_key(format="DER")).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, 32, 2))


def sign(data: bytes, private_key: RSA.RsaKey) -> bytes:
    return pkcs1_15.new(private_key).sign(SHA256.new(data))


def verify(data: bytes, signature: bytes, public_key: RSA.RsaKey) -> bool:
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(data), signature)
        return True
    except (ValueError, TypeError):
        return False

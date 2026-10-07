import pytest
from Crypto.Random import get_random_bytes

from packetvault import signing
from packetvault import vault_crypto as vc

ITER = 1_000


def test_gcm_round_trip():
    blob = vc.encrypt(b"evidence" * 100, "pw", iterations=ITER)
    assert blob[:4] == vc.MAGIC
    assert vc.decrypt(blob, "pw") == b"evidence" * 100


def test_ciphertext_hides_plaintext():
    assert b"192.168.56.101" not in vc.encrypt(b"192.168.56.101 " * 50, "pw", iterations=ITER)


def test_wrong_passphrase_rejected():
    with pytest.raises(vc.DecryptionError):
        vc.decrypt(vc.encrypt(b"x", "pw", iterations=ITER), "nope")


@pytest.mark.parametrize("offset", [5, 12, 30, vc.HEADER_LEN + 1, -1])
def test_any_byte_flip_rejected(offset):
    """Header (authenticated as AAD), ciphertext and tag are all protected."""
    blob = bytearray(vc.encrypt(b"secret evidence", "pw", iterations=ITER))
    blob[offset] ^= 0x80
    with pytest.raises(vc.DecryptionError):
        vc.decrypt(bytes(blob), "pw")


def test_fresh_salt_and_nonce_per_encryption():
    a = vc.encrypt(b"same", "pw", iterations=ITER)
    b = vc.encrypt(b"same", "pw", iterations=ITER)
    assert a[10:38] != b[10:38] and a != b


def test_pbkdf2_is_deterministic_and_salted():
    salt = b"s" * 16
    key = vc.derive_key("pw", salt, ITER)
    assert len(key) == 32
    assert key == vc.derive_key("pw", salt, ITER)
    assert key != vc.derive_key("pw", b"t" * 16, ITER)


@pytest.mark.parametrize("enc,dec", [(vc.encrypt_cbc, vc.decrypt_cbc), (vc.encrypt_ctr, vc.decrypt_ctr)])
def test_comparison_modes_round_trip(enc, dec):
    key, data = get_random_bytes(32), get_random_bytes(1000)
    assert dec(key, enc(key, data)) == data


def test_rsa_sign_verify(lab):
    priv = signing.load_private_key(lab["priv"])
    pub = signing.load_public_key(lab["pub"])
    sig = signing.sign(b"report", priv)
    assert len(sig) == 256  # 2048-bit modulus
    assert signing.verify(b"report", sig, pub)
    assert not signing.verify(b"report!", sig, pub)


def test_protected_private_key(tmp_path):
    priv, _ = signing.generate_keypair(tmp_path, "p", key_passphrase="kp")
    assert b"ENCRYPTED" in priv.read_bytes()
    signing.load_private_key(priv, "kp")
    with pytest.raises(ValueError):
        signing.load_private_key(priv, "wrong")

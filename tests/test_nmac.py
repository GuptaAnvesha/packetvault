import hashlib
import shutil

import pytest

from packetvault import nmac
from packetvault.bundle import seal_case
from packetvault.tamper import tamper_case
from packetvault.verify import verify_case

from .conftest import FAST_KDF, PASSPHRASE

CUSTODIAN = b"\x5a" * 32


def test_nmac_matches_definition():
    k1, k2 = nmac.derive_keys(CUSTODIAN)
    assert k1 != k2
    msg = b"record"
    assert nmac.nmac(k1, k2, msg) == hashlib.sha256(k2 + hashlib.sha256(k1 + msg).digest()).digest()
    assert nmac.verify(k1, k2, msg, nmac.nmac(k1, k2, msg))
    assert not nmac.verify(k1, k2, msg + b"x", nmac.nmac(k1, k2, msg))


def test_pure_python_sha256_compression_matches_hashlib():
    data = b"packetvault" * 13
    padded = data + nmac.sha256_padding(len(data))
    state = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    for i in range(0, len(padded), 64):
        state = nmac._compress(state, padded[i:i + 64])
    assert b"".join(x.to_bytes(4, "big") for x in state) == hashlib.sha256(data).digest()


def test_length_extension_forges_prefix_mac_but_not_nmac():
    demo = nmac.length_extension_demo(b"\x01" * 32)
    assert demo["prefix_mac"]["forgery_accepted"] is True
    assert demo["nmac"]["forgery_accepted"] is False


@pytest.fixture(scope="module")
def keyed_case(lab, tmp_path_factory):
    case = tmp_path_factory.mktemp("keyed") / "case"
    result = seal_case(lab["pcap"], case, passphrase=PASSPHRASE, private_key_path=lab["priv"],
                       investigator="Custodian Test", case_id="NMAC-1", backend="builtin",
                       kdf_iterations=FAST_KDF, custodian_key=CUSTODIAN)
    assert set(result.timings) == {"parse", "hash_chain", "encrypt", "search_index", "detect", "report_and_sign"}
    return case


@pytest.fixture
def keyed_copy(keyed_case, tmp_path):
    dest = tmp_path / "case"
    shutil.copytree(keyed_case, dest)
    return dest


def statuses(result):
    return {c.name: c.status for c in result.checks}


def test_keyed_case_verifies(keyed_case, lab):
    result = verify_case(keyed_case, lab["pub"], PASSPHRASE, custodian_key=CUSTODIAN)
    assert result.summary == "PASS" and statuses(result)["NMAC tags"] == "PASS"
    assert all(c.ms >= 0 for c in result.checks)


def test_without_custodian_key_the_check_is_skipped(keyed_case, lab):
    result = verify_case(keyed_case, lab["pub"], PASSPHRASE)
    assert result.ok and result.summary == "PASS (custodian check skipped)"


def test_wrong_custodian_key_fails(keyed_case, lab):
    result = verify_case(keyed_case, lab["pub"], PASSPHRASE, custodian_key=b"\x00" * 32)
    assert statuses(result)["NMAC tags"] == "FAIL"


def test_recompute_attack_is_localised_exactly(keyed_copy, lab):
    tamper_case(keyed_copy, "recompute", 1500, PASSPHRASE)
    result = verify_case(keyed_copy, lab["pub"], PASSPHRASE, custodian_key=CUSTODIAN)
    assert result.chain_verdict.first_divergence is None and result.chain_verdict.window == (1281, 1536)
    assert result.nmac_divergence == (1500, 1500)


@pytest.mark.parametrize("mode", ["modify", "delete", "insert"])
def test_other_insider_attacks_hit_the_same_record(keyed_copy, lab, mode):
    tamper_case(keyed_copy, mode, 900, PASSPHRASE)
    result = verify_case(keyed_copy, lab["pub"], PASSPHRASE, custodian_key=CUSTODIAN)
    expected = 901 if mode == "insert" else 900
    assert result.nmac_divergence[0] == expected
    assert result.chain_verdict.first_divergence == expected


def test_unkeyed_cases_have_no_nmac_check(sealed_case, lab):
    result = verify_case(sealed_case, lab["pub"], PASSPHRASE, custodian_key=CUSTODIAN)
    assert "NMAC tags" not in statuses(result) and result.summary == "PASS"

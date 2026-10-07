import shutil

import pytest

from packetvault.bundle import seal_case
from packetvault.parser import parse_pcap
from packetvault.samplegen import generate_lab_capture
from packetvault.signing import generate_keypair

PASSPHRASE = "correct horse battery staple"
FAST_KDF = 1_000  # keep tests quick; production default is 600k


@pytest.fixture(scope="session")
def lab(tmp_path_factory):
    root = tmp_path_factory.mktemp("lab")
    pcap = root / "lab.pcap"
    labels = generate_lab_capture(pcap, root / "lab.labels.json")
    priv, pub = generate_keypair(root / "keys")
    return {"root": root, "pcap": pcap, "labels": labels, "priv": priv, "pub": pub}


@pytest.fixture(scope="session")
def records(lab):
    return parse_pcap(lab["pcap"], backend="builtin")


@pytest.fixture(scope="session")
def sealed_case(lab):
    case = lab["root"] / "case"
    seal_case(lab["pcap"], case, passphrase=PASSPHRASE, private_key_path=lab["priv"],
              investigator="Test Investigator", case_id="TEST-1", backend="builtin", kdf_iterations=FAST_KDF)
    return case


@pytest.fixture
def case_copy(sealed_case, tmp_path):
    """A fresh, writable copy of the sealed bundle for destructive tests."""
    dest = tmp_path / "case"
    shutil.copytree(sealed_case, dest)
    return dest

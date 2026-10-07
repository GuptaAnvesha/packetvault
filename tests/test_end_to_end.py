import json

import pytest

from packetvault.bundle import open_case
from packetvault.cli import main
from packetvault.signing import generate_keypair
from packetvault.tamper import tamper_case
from packetvault.verify import FAIL, PASS, SKIP, verify_case

from .conftest import PASSPHRASE


def statuses(result):
    return {c.name: c.status for c in result.checks}


def test_bundle_contents(sealed_case):
    for name in ("evidence.db.enc", "report.json", "report.sig", "report.txt"):
        assert (sealed_case / name).exists()
    report = json.loads((sealed_case / "report.json").read_text())
    assert report["integrity"]["record_count"] == report["acquisition"]["record_count"]
    assert len(report["detection"]["alerts"]) == 2


def test_no_plaintext_ip_in_container(sealed_case):
    assert b"192.168.56" not in (sealed_case / "evidence.db.enc").read_bytes()


def test_untampered_case_passes(sealed_case, lab):
    result = verify_case(sealed_case, lab["pub"], PASSPHRASE)
    assert result.ok and result.complete and result.summary == "PASS"


def test_public_only_verification(sealed_case, lab):
    result = verify_case(sealed_case, lab["pub"])
    assert result.ok and not result.complete
    assert statuses(result)["AES-GCM tag"] == SKIP


@pytest.mark.parametrize("mode,expected_position", [("modify", 1200), ("delete", 1200), ("insert", 1201)])
def test_insider_tampering_localised(case_copy, lab, mode, expected_position):
    tamper_case(case_copy, mode, 1200, PASSPHRASE)
    result = verify_case(case_copy, lab["pub"], PASSPHRASE)
    s = statuses(result)
    assert not result.ok
    assert s["RSA signature"] == PASS and s["AES-GCM tag"] == PASS
    assert s["Container digest"] == FAIL and s["Hash chain"] == FAIL
    assert result.chain_verdict.first_divergence == expected_position


def test_recomputed_chain_localised_by_checkpoints(case_copy, lab):
    tamper_case(case_copy, "recompute", 1200, PASSPHRASE)
    verdict = verify_case(case_copy, lab["pub"], PASSPHRASE).chain_verdict
    assert not verdict.ok and verdict.window == (1025, 1280)


def test_bitflip_caught_by_gcm(case_copy, lab):
    tamper_case(case_copy, "bitflip", 500)
    s = statuses(verify_case(case_copy, lab["pub"], PASSPHRASE))
    assert s["AES-GCM tag"] == FAIL and s["Hash chain"] == SKIP


def test_edited_report_fails_signature(case_copy, lab):
    path = case_copy / "report.json"
    path.write_text(path.read_text().replace("Test Investigator", "Mallory"))
    assert statuses(verify_case(case_copy, lab["pub"], PASSPHRASE))["RSA signature"] == FAIL


def test_wrong_public_key_fails(sealed_case, tmp_path):
    _, other_pub = generate_keypair(tmp_path, "other")
    assert not verify_case(sealed_case, other_pub, PASSPHRASE).ok


def test_open_case_returns_all_records(sealed_case, lab):
    records, hashes, _ = open_case(sealed_case, PASSPHRASE)
    assert len(records) == len(hashes) == lab["labels"]["packets"]


def test_cli_verify_exit_codes(sealed_case, case_copy, lab, capsys):
    args = ["--pubkey", str(lab["pub"]), "--passphrase", PASSPHRASE]
    assert main(["verify", str(sealed_case), *args]) == 0
    tamper_case(case_copy, "modify", 10, PASSPHRASE)
    assert main(["verify", str(case_copy), *args]) == 2
    assert "frame #10" in capsys.readouterr().out

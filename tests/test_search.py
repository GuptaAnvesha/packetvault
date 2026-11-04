"""Searchable encryption (blind index): correctness, confidentiality, integrity and leakage boundaries."""

import json
import shutil

import pytest

from packetvault import search
from packetvault.bundle import load_report, open_case, seal_case
from packetvault.cli import main
from packetvault.tamper import tamper_case
from packetvault.vault_crypto import DecryptionError
from packetvault.verify import FAIL, PASS, SKIP, verify_case

from .conftest import FAST_KDF, PASSPHRASE


def statuses(result):
    return {c.name: c.status for c in result.checks}


def plaintext_search(records, src_ip=None, dst_ip=None, host=None, port=None, dst_port=None, protocol=None,
                     flags=None, frame_from=None, frame_to=None):
    """Reference answer computed over decrypted records."""
    out = []
    for r in records:
        if src_ip and r.src_ip != src_ip or dst_ip and r.dst_ip != dst_ip:
            continue
        if host and host not in (r.src_ip, r.dst_ip):
            continue
        if port is not None and port not in (r.src_port, r.dst_port):
            continue
        if dst_port is not None and r.dst_port != dst_port:
            continue
        if protocol and r.protocol != protocol.upper() or flags and r.tcp_flags != flags.upper().replace(" ", ""):
            continue
        if frame_from is not None and r.index < frame_from or frame_to is not None and r.index > frame_to:
            continue
        out.append(r.index)
    return out


QUERIES = [
    {"src_ip": "192.168.56.101", "flags": "SYN"},
    {"src_ip": "192.168.56.102"},
    {"host": "192.168.56.10"},
    {"port": 443},
    {"port": 80, "protocol": "tcp"},
    {"dst_port": 22},
    {"protocol": "UDP"},
    {"flags": "syn, ack"},
    {"host": "192.168.56.23", "frame_from": 1000, "frame_to": 2500},
    {"src_ip": "10.99.99.99"},  # no match
    {},  # everything
]


@pytest.mark.parametrize("query", QUERIES, ids=lambda q: json.dumps(q) or "all")
def test_blind_index_matches_plaintext_search(sealed_case, query):
    records, _, _ = open_case(sealed_case, PASSPHRASE)
    criteria = dict(query)
    ff, ft = criteria.pop("frame_from", None), criteria.pop("frame_to", None)
    result = search.search_case(sealed_case, PASSPHRASE, criteria, frame_from=ff, frame_to=ft, limit=100_000)
    expected = plaintext_search(records, **query)
    assert [r["idx"] for r in result.rows] == expected
    assert result.total == len(expected)


def test_hits_carry_full_records_and_chain_hashes(sealed_case):
    records, hashes, _ = open_case(sealed_case, PASSPHRASE)
    r = search.search_case(sealed_case, PASSPHRASE, {"src_ip": "192.168.56.102"}, limit=5)
    for row in r.rows:
        rec = records[row["idx"] - 1]
        assert row["dst_port"] == rec.dst_port and row["timestamp"] == rec.timestamp
        assert row["chain_hash"] == hashes[row["idx"] - 1]
    assert r.decrypt_ms >= 0 and len(r.rows) == 5


def test_index_file_holds_no_plaintext(sealed_case):
    data = (sealed_case / search.INDEX_NAME).read_bytes()
    # needles of 5+ bytes: shorter ones turn up by chance in 1.7 MB of ciphertext
    for needle in (b"192.168.56", b'"SYN"', b'"TCP"', b'"SYN,ACK"', b'"udp"', b'"UDP"'):
        assert needle not in data


def test_store_sees_only_tokens(sealed_case):
    report = load_report(sealed_case)
    store = search.IndexStore.open(sealed_case / search.INDEX_NAME)
    client = search.SearchClient(store, PASSPHRASE, report["integrity"]["h0"])
    client.search({"host": "192.168.56.101", "port": 80})
    assert len(store.seen) == 4  # host -> src/dst token, port -> src/dst token
    assert all(len(t) == 2 * search.TOKEN_BYTES and "192" not in t for t in store.seen)
    # domain separation: the same IP gives different tokens in the src and dst fields
    assert search.make_token(client.keys.token, "src_ip", "1.2.3.4") != search.make_token(client.keys.token, "dst_ip", "1.2.3.4")
    store.close()


def test_ciphertexts_are_length_padded(sealed_case):
    store = search.IndexStore.open(sealed_case / search.INDEX_NAME)
    lengths = {len(ct) - 16 for _, _, ct in store.all_records()}
    store.close()
    assert all(n % search.PAD_TO == 0 for n in lengths)


def test_wrong_passphrase_rejected_even_without_hits(sealed_case):
    with pytest.raises(DecryptionError):
        search.search_case(sealed_case, "not the passphrase", {"src_ip": "10.0.0.1"})


def test_report_signs_the_index(sealed_case, lab):
    info = load_report(sealed_case)["search_index"]
    assert info["records"] == 3548 and info["fields"] == list(search.INDEXED_FIELDS)
    s = statuses(verify_case(sealed_case, lab["pub"], PASSPHRASE))
    assert s["Search index"] == PASS and s["Index consistency"] == PASS


def test_public_verification_checks_index_digest(sealed_case, lab):
    s = statuses(verify_case(sealed_case, lab["pub"]))
    assert s["Search index"] == PASS and s["Index consistency"] == SKIP


def test_keyless_store_hiding_a_packet_is_caught(case_copy, lab):
    before = search.search_case(case_copy, PASSPHRASE, {"src_ip": "192.168.56.101"}, limit=1).total
    what = tamper_case(case_copy, "unindex", 1500)  # no passphrase: the store has no keys
    assert "deleted" in what
    s = statuses(verify_case(case_copy, lab["pub"], PASSPHRASE))
    assert s["Search index"] == FAIL and s["Index consistency"] == SKIP
    assert s["Container digest"] == PASS and s["Hash chain"] == PASS  # evidence itself untouched
    with pytest.raises(search.IndexIntegrityError):
        search.search_case(case_copy, PASSPHRASE, {"src_ip": "192.168.56.101"})
    # without the digest check the hiding would have worked: that is what the signature buys
    store = search.IndexStore.open(case_copy / search.INDEX_NAME)
    client = search.SearchClient(store, PASSPHRASE, load_report(case_copy)["integrity"]["h0"])
    assert client.search({"src_ip": "192.168.56.101"}).total <= before
    store.close()


def test_container_tampering_shows_as_index_disagreement(case_copy, lab):
    tamper_case(case_copy, "modify", 1200, PASSPHRASE)
    result = verify_case(case_copy, lab["pub"], PASSPHRASE)
    s = statuses(result)
    assert s["Search index"] == PASS and s["Index consistency"] == FAIL
    assert "position 1200" in next(c.detail for c in result.checks if c.name == "Index consistency")


def test_index_from_another_case_is_rejected(sealed_case, lab, tmp_path):
    other = tmp_path / "other"
    seal_case(lab["pcap"], other, passphrase=PASSPHRASE, private_key_path=lab["priv"], investigator="X",
              case_id="OTHER", backend="builtin", kdf_iterations=FAST_KDF)
    victim = tmp_path / "victim"
    shutil.copytree(sealed_case, victim)
    shutil.copy(other / search.INDEX_NAME, victim / search.INDEX_NAME)
    assert statuses(verify_case(victim, lab["pub"], PASSPHRASE))["Search index"] == FAIL
    # even bypassing the digest, the AAD binds each record to its own case's H0
    store = search.IndexStore.open(victim / search.INDEX_NAME)
    client = search.SearchClient(store, PASSPHRASE, load_report(victim)["integrity"]["h0"])
    with pytest.raises(DecryptionError):
        client.search({"src_ip": "192.168.56.101"})
    store.close()


def test_sealing_without_index(lab, tmp_path):
    case = tmp_path / "plain"
    seal_case(lab["pcap"], case, passphrase=PASSPHRASE, private_key_path=lab["priv"], investigator="X",
              backend="builtin", kdf_iterations=FAST_KDF, searchable=False)
    assert not (case / search.INDEX_NAME).exists() and "search_index" not in load_report(case)
    result = verify_case(case, lab["pub"], PASSPHRASE)
    assert result.ok and "Search index" not in statuses(result)
    with pytest.raises(FileNotFoundError):
        search.search_case(case, PASSPHRASE, {})


def test_cli_query_uses_blind_index(sealed_case, lab, capsys):
    rc = main(["query", str(sealed_case), "--src", "192.168.56.102", "--pubkey", str(lab["pub"]),
               "--show-tokens", "--passphrase", PASSPHRASE])
    out = capsys.readouterr().out
    assert rc == 0 and "blind index" in out and "tokens sent to the store" in out
    assert "matching packets shown" in out
    rc = main(["query", str(sealed_case), "--src", "192.168.56.102", "--full-decrypt", "--passphrase", PASSPHRASE])
    assert rc == 0 and "full in-memory decryption" in capsys.readouterr().out

import json
import threading
import urllib.error
import urllib.request

import pytest

from packetvault.webui.server import make_server

PASS = "dashboard-test-passphrase"


@pytest.fixture(scope="module")
def ui(tmp_path_factory):
    server, ws = make_server("127.0.0.1", 0, tmp_path_factory.mktemp("workspace"))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def call(path, body=None, headers=None, raw=None, ctype="application/json"):
        data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
        h = {"Content-Type": ctype} if data is not None else {}
        h.update(headers or {})
        req = urllib.request.Request(base + path, data=data, headers=h, method="POST" if data is not None else "GET")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    call("/api/captures/sample", {"seed": 7})
    status, sealed = call("/api/cases/seal", {"file": "lab-sample-seed7.pcap", "case_id": "UI-1",
                                              "passphrase": PASS, "kdf_iterations": 100_000})
    assert status == 200, sealed
    yield call
    server.shutdown()


def test_preview_reports_detection_accuracy(ui):
    status, p = ui("/api/captures/preview", {"file": "lab-sample-seed7.pcap"})
    assert status == 200
    assert p["statistics"]["packets"] == 3548 and len(p["alerts"]) == 2
    assert p["evaluation"]["f1"] == 1.0


def test_seal_verify_with_nmac(ui):
    status, v = ui("/api/cases/UI-1/verify", {"passphrase": PASS})
    assert status == 200 and v["summary"] == "PASS"
    assert {"NMAC tags", "Search index", "Index consistency"} <= {c["name"] for c in v["checks"]}


def test_tamper_works_on_a_copy_and_is_localised(ui):
    status, t = ui("/api/cases/UI-1/tamper", {"mode": "recompute", "index": 1500, "passphrase": PASS})
    assert status == 200 and t["case_id"].startswith("UI-1~recompute-1500")
    _, v = ui(f"/api/cases/{t['case_id']}/verify", {"passphrase": PASS})
    assert v["localisation"] == {"kind": "exact", "by": "NMAC tags", "position": 1500, "frame": 1500}
    assert v["chain_localisation"]["kind"] == "window"
    _, original = ui("/api/cases/UI-1/verify", {"passphrase": PASS})
    assert original["summary"] == "PASS"


def test_encrypted_search_and_wrong_passphrase(ui):
    status, q = ui("/api/cases/UI-1/query", {"passphrase": PASS, "src_ip": "192.168.56.101", "flags": "SYN"})
    assert status == 200 and q["total"] == 1024
    status, err = ui("/api/cases/UI-1/query", {"passphrase": "not-the-passphrase"})
    assert status == 400 and "passphrase" in err["error"]


def test_scan_target_restriction(ui):
    status, err = ui("/api/nmap", {"target": "8.8.8.8", "ports": "80"})
    assert status == 400 and "public" in err["error"]
    status, err = ui("/api/nmap", {"target": "127.0.0.1", "ports": "80;whoami"})
    assert status == 400


def test_request_guards(ui):
    assert ui("/api/overview", headers={"Host": "evil.example:80"})[0] == 403
    assert ui("/api/cases/seal", {"x": 1}, headers={"Origin": "http://evil.example"})[0] == 403
    assert ui("/api/cases/seal", raw=b"x=1", ctype="application/x-www-form-urlencoded")[0] == 415
    assert ui("/api/captures/upload?name=x.pcap", raw=b"not a pcap", ctype="application/octet-stream")[0] == 400
    assert ui("/files/cases/UI-1/..%2F..%2Fkeys%2Finvestigator_private.pem")[0] == 404
    assert ui("/api/cases/..%2Fkeys/verify", {"passphrase": PASS})[0] in (400, 404)


def test_overview_metrics(ui):
    status, o = ui("/api/overview")
    assert status == 200
    assert o["totals"]["cases"] >= 1 and o["totals"]["packets_sealed"] >= 3548
    assert set(o["seals"][-1]["timings"]) == {"parse", "hash_chain", "encrypt", "search_index", "detect", "report_and_sign"}


def test_upload_never_overwrites_or_inherits_labels(ui):
    pcap = (b"\xd4\xc3\xb2\xa1" + b"\x02\x00\x04\x00" + b"\x00" * 8 + b"\xff\xff\x00\x00" + b"\x01\x00\x00\x00")
    # the sample capture already exists and has ground-truth labels
    status, up = ui("/api/captures/upload?name=lab-sample-seed7.pcap", raw=pcap, ctype="application/octet-stream")
    assert status == 200 and up["file"] == "lab-sample-seed7-2.pcap" and up["renamed_from"] == "lab-sample-seed7.pcap"
    status, p = ui("/api/captures/preview", {"file": "lab-sample-seed7.pcap"})
    assert p["statistics"]["packets"] == 3548  # original untouched
    files = {f["file"]: f for f in ui("/api/captures")[1]["files"]}
    assert files["lab-sample-seed7-2.pcap"]["labels"] is False
    status, again = ui("/api/captures/upload?name=lab-sample-seed7.pcap", raw=pcap, ctype="application/octet-stream")
    assert again["file"] == "lab-sample-seed7-3.pcap"


def test_security_matrix_reflects_bind_address(tmp_path):
    from packetvault.webui.api import Workspace

    def loopback_measure(host):
        return next(m for m in Workspace(tmp_path / host.replace(":", "_"), bind_host=host).security()["measures"]
                    if m["name"].startswith("Loopback-only"))

    assert loopback_measure("127.0.0.1")["active"] is True
    exposed = loopback_measure("0.0.0.0")
    assert exposed["active"] is False and "no authentication" in exposed["detail"]


def test_search_blind_index_vs_full_decryption(ui):
    q = {"passphrase": PASS, "host": "192.168.56.102", "port": 22}
    status, idx = ui("/api/cases/UI-1/query", q)
    assert status == 200 and idx["mode"] == "index"
    assert len(idx["trapdoors"]) == 4 and all("192" not in t["token"] for t in idx["trapdoors"])
    status, full = ui("/api/cases/UI-1/query", {**q, "mode": "full"})
    assert status == 200 and full["mode"] == "full"
    assert [r["idx"] for r in idx["rows"]] == [r["idx"] for r in full["rows"]] and idx["total"] == full["total"]
    assert idx["decrypted_records"] == len(idx["rows"]) < full["decrypted_records"]

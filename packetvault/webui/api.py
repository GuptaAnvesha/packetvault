"""Dashboard back end: every action the UI offers, on top of the PacketVault modules.

Workspace layout::

    workspace/
        captures/   *.pcap / *.pcapng (+ <name>.labels.json ground truth)
        cases/      sealed bundles (one directory per case)
        keys/       investigator RSA keypair + custodian NMAC key
        bench/      benchmark results
        history.jsonl   seal / verify / scan events, for the metrics view

Passphrases are only ever held for the duration of one request; nothing
derived from them is stored by the dashboard.
"""

from __future__ import annotations

import hmac
import json
import re
import shutil
import sqlite3
import tempfile
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from Crypto.PublicKey import RSA

from .. import __version__, nmac, search, signing, vault_crypto
from ..bundle import CONTAINER_NAME, REPORT_NAME, SIGNATURE_NAME, load_report, seal_case
from ..detect import DetectionConfig, detect_port_scans, evaluate, host_statistics
from ..parser import load_database, load_nmac_tags, open_database, parse_pcap, resolve_backend
from ..report import traffic_statistics
from ..samplegen import generate_lab_capture
from ..tamper import KEYLESS_MODES, MODES, tamper_case
from ..verify import verify_case
from . import tools

_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,120}$")
_CASE_RE = re.compile(r"^[A-Za-z0-9_.\-~]{1,120}$")
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")
QUERY_COLUMNS = ("idx", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "tcp_flags",
                 "frame_len", "payload_len", "chain_hash")


LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class Workspace:
    def __init__(self, root: Path, bind_host: str = "127.0.0.1"):
        self.root = root
        self.bind_host = bind_host
        self.captures = root / "captures"
        self.cases = root / "cases"
        self.keys = root / "keys"
        self.bench_dir = root / "bench"
        for d in (self.captures, self.cases, self.keys):
            d.mkdir(parents=True, exist_ok=True)
        self.history_file = root / "history.jsonl"
        self._history_lock = threading.Lock()
        self.live = tools.LiveCapture(self.captures)
        self._nmap_lock = threading.Lock()

    # ------------------------------------------------------------------ helpers

    @property
    def private_key(self) -> Path:
        return self.keys / "investigator_private.pem"

    @property
    def public_key(self) -> Path:
        return self.keys / "investigator_public.pem"

    @property
    def custodian_path(self) -> Path:
        return self.keys / "custodian.key"

    def custodian_key(self) -> bytes | None:
        return nmac.load_custodian_key(self.custodian_path) if self.custodian_path.exists() else None

    def capture_path(self, name: str) -> Path:
        if not _NAME_RE.match(name or "") or not name.lower().endswith(CAPTURE_SUFFIXES):
            raise ValueError("invalid capture name")
        p = self.captures / name
        if not p.is_file():
            raise FileNotFoundError(name)
        return p

    def case_path(self, case_id: str) -> Path:
        if not _CASE_RE.match(case_id or "") or case_id in (".", ".."):
            raise ValueError("invalid case id")
        p = self.cases / case_id
        if not (p / REPORT_NAME).is_file():
            raise FileNotFoundError(case_id)
        return p

    def log(self, kind: str, **data) -> None:
        entry = {"ts": time.time(), "kind": kind, **data}
        with self._history_lock, open(self.history_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def history(self, limit: int = 200) -> list[dict]:
        if not self.history_file.exists():
            return []
        lines = self.history_file.read_text(encoding="utf-8").splitlines()[-limit:]
        return [json.loads(line) for line in lines if line.strip()]

    # ------------------------------------------------------------------ keys

    def keys_info(self) -> dict:
        info = {"investigator": None, "custodian": None, "private_key_encrypted": False}
        if self.public_key.exists():
            info["investigator"] = signing.fingerprint(signing.load_public_key(self.public_key))
            info["private_key_encrypted"] = "ENCRYPTED" in self.private_key.read_text()
        key = self.custodian_key()
        if key:
            info["custodian"] = nmac.key_fingerprint(key)
        return info

    def generate_keys(self, custodian: bool, overwrite: bool = False) -> dict:
        if self.private_key.exists() and not overwrite:
            raise ValueError("an investigator keypair already exists (existing cases are signed with it)")
        if not self.private_key.exists() or overwrite:
            signing.generate_keypair(self.keys)
        if custodian and (not self.custodian_path.exists() or overwrite):
            nmac.generate_custodian_key(self.custodian_path)
        self.log("keygen", custodian=custodian)
        return self.keys_info()

    def ensure_custodian(self) -> dict:
        if not self.custodian_path.exists():
            nmac.generate_custodian_key(self.custodian_path)
            self.log("keygen", custodian=True)
        return self.keys_info()

    # ------------------------------------------------------------------ captures

    def list_captures(self) -> list[dict]:
        out = []
        for p in sorted(self.captures.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if p.suffix.lower() not in CAPTURE_SUFFIXES:
                continue
            labels = self._labels_for(p)
            out.append({"file": p.name, "bytes": p.stat().st_size, "modified": p.stat().st_mtime,
                        "labels": labels is not None, "scanners": labels.get("scanners", []) if labels else []})
        return out

    def _labels_for(self, capture: Path) -> dict | None:
        lp = capture.with_suffix(".labels.json")
        return json.loads(lp.read_text(encoding="utf-8")) if lp.exists() else None

    def sample(self, seed: int = 7) -> dict:
        name = f"lab-sample-seed{int(seed)}.pcap"
        path = self.captures / name
        labels = generate_lab_capture(path, path.with_suffix(".labels.json"), seed=int(seed))
        self.log("capture", source="sample", file=name, packets=labels["packets"])
        return {"file": name, "packets": labels["packets"], "scanners": labels["scanners"]}

    def upload(self, name: str, data: bytes) -> dict:
        name = re.sub(r"[^A-Za-z0-9_.\-]", "_", Path(name).name)[:100] or "upload.pcap"
        if not name.lower().endswith(CAPTURE_SUFFIXES):
            name += ".pcap"
        magic = data[:4]
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
                         b"\x0a\x0d\x0d\x0a"):
            raise ValueError("not a PCAP or PCAPNG file (bad magic number)")
        # Never overwrite an existing capture (it may be evidence), and never let a new upload
        # pick up an old capture's ground-truth labels: take the next free name instead.
        requested, stem, suffix = name, Path(name).stem, Path(name).suffix
        for n in range(1, 10_000):
            name = requested if n == 1 else f"{stem}-{n}{suffix}"
            path = self.captures / name
            if path.with_suffix(".labels.json").exists():
                continue
            try:
                with open(path, "xb") as fh:  # exclusive create: safe against concurrent uploads
                    fh.write(data)
                break
            except FileExistsError:
                continue
        else:
            raise ValueError(f"too many captures named {requested}")
        self.log("capture", source="upload", file=name, bytes=len(data))
        return {"file": name, "bytes": len(data), "renamed_from": requested if name != requested else None}

    def set_labels(self, name: str, scanners: list[str]) -> dict:
        path = self.capture_path(name)
        labels = {"description": "ground truth set in the dashboard", "scanners": sorted(set(scanners))}
        path.with_suffix(".labels.json").write_text(json.dumps(labels, indent=2), encoding="utf-8")
        return labels

    def preview(self, name: str, backend: str = "builtin", limit: int = 200, threshold: int = 15,
                window: float = 10.0) -> dict:
        path = self.capture_path(name)
        backend = resolve_backend(backend)
        start = time.perf_counter()
        records = parse_pcap(path, backend=backend)
        parse_ms = (time.perf_counter() - start) * 1000
        config = DetectionConfig(window_seconds=window, port_threshold=int(threshold))
        alerts = detect_port_scans(records, config)
        hosts = host_statistics(records, config)
        labels = self._labels_for(path)
        evaluation = None
        if labels and labels.get("scanners"):
            evaluation = evaluate(alerts, labels["scanners"], {r.src_ip for r in records if r.src_ip})
        return {
            "file": name, "backend": backend, "parse_ms": round(parse_ms, 1),
            "packets_per_s": round(len(records) / (parse_ms / 1000)) if parse_ms else None,
            "statistics": traffic_statistics(records, top_n=8),
            "timeline": _timeline(records),
            "alerts": [a.to_dict() for a in alerts],
            "hosts": [{"ip": h.src_ip, "probes": h.probes, "ports": h.distinct_ports_total,
                       "max_ports_in_window": h.max_ports_in_window, "syn_ratio": round(h.syn_ratio, 2)}
                      for h in sorted(hosts.values(), key=lambda h: -h.max_ports_in_window)][:12],
            "labels": labels, "evaluation": evaluation,
            "records": [r.to_dict() for r in records[:max(1, min(int(limit), 1000))]],
        }

    def crosscheck(self, name: str) -> dict:
        """Validate the pure-Python decoder against tshark (via pyshark), field by field."""
        path = self.capture_path(name)
        avail = tools.available()
        if not (avail["pyshark"] and avail["tshark"]):
            raise ValueError("needs Wireshark's tshark on PATH and `pip install pyshark`")
        builtin = parse_pcap(path, backend="builtin")
        shark = parse_pcap(path, backend="pyshark")
        fields = [f for f in builtin[0].to_dict() if f != "timestamp"] if builtin else []
        mismatches: dict[str, int] = {f: 0 for f in fields}
        examples = []
        for a, b in zip(builtin, shark):
            da, db = a.to_dict(), b.to_dict()
            for f in fields:
                if da[f] != db[f]:
                    mismatches[f] += 1
                    if len(examples) < 10:
                        examples.append({"frame": a.index, "field": f, "builtin": da[f], "tshark": db[f]})
        return {"packets_builtin": len(builtin), "packets_tshark": len(shark),
                "fields_compared": len(fields), "mismatches": mismatches,
                "agreement": round(1 - sum(mismatches.values()) / max(1, len(fields) * min(len(builtin), len(shark))), 5),
                "examples": examples}

    def delete_capture(self, name: str) -> dict:
        path = self.capture_path(name)
        path.unlink()
        path.with_suffix(".labels.json").unlink(missing_ok=True)
        return {"deleted": name}

    # ------------------------------------------------------------------ nmap (+ capture)

    def nmap(self, body: dict) -> dict:
        if not self._nmap_lock.acquire(blocking=False):
            raise ValueError("a scan is already running")
        try:
            target, ports = str(body.get("target", "")), str(body.get("ports", "1-1024"))
            capture_iface = body.get("capture_interface") or None
            capture_file = None
            if capture_iface:
                ip = tools.resolve_target(target, bool(body.get("allow_public")))
                capture_file = f"nmap-{ip.replace('.', '_')}-{time.strftime('%Y%m%d-%H%M%S')}.pcap"
                self.live.start(capture_iface, f"host {ip}", seconds=900, name=capture_file)
                time.sleep(1.5)  # let dumpcap open the interface before the first probe
            try:
                result = tools.nmap_scan(target, ports, scan_type=str(body.get("scan_type", "connect")),
                                         service_detection=bool(body.get("service_detection")),
                                         timing=int(body.get("timing", 4)), use_nmap=bool(body.get("use_nmap", True)),
                                         allow_public=bool(body.get("allow_public")))
            finally:
                if capture_iface:
                    time.sleep(1.5)
                    status = self.live.stop()
                    if status and status.get("error"):
                        capture_file = None
            if capture_file and (self.captures / capture_file).exists():
                self.set_labels(capture_file, [result["scanner_ip"]])
                result["capture"] = capture_file
            self.log("scan", engine=result["engine"], target=result["ip"], open=len(result["open"]),
                     elapsed_s=result["elapsed_s"], capture=result.get("capture"))
            return result
        finally:
            self._nmap_lock.release()

    # ------------------------------------------------------------------ cases

    def list_cases(self) -> list[dict]:
        out = []
        for d in sorted(self.cases.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if not (d / REPORT_NAME).is_file():
                continue
            r = load_report(d)
            out.append({
                "case_id": d.name, "investigator": r["case"]["investigator"], "sealed_at": r["case"]["sealed_at"],
                "source_file": r["acquisition"]["source_file"], "records": r["integrity"]["record_count"],
                "alerts": len(r["detection"]["alerts"]), "keyed": "keyed_integrity" in r,
                "root_hash": r["integrity"]["root_hash"], "container_bytes": r["evidence_container"]["size"],
                "derived_from": _derived_from(d.name),
            })
        return out

    def seal(self, body: dict) -> dict:
        capture = self.capture_path(str(body.get("file", "")))
        passphrase = _passphrase(body)
        if not self.private_key.exists():
            self.generate_keys(custodian=bool(body.get("custodian", True)))
        custodian = None
        if body.get("custodian", True):
            self.ensure_custodian()
            custodian = self.custodian_key()
        case_id = str(body.get("case_id") or f"CASE-{datetime.now():%Y%m%d-%H%M%S}")
        if not _CASE_RE.match(case_id) or "~" in case_id:
            raise ValueError("case id may contain letters, digits, '.', '_' and '-'")
        case_dir = self.cases / case_id
        if case_dir.exists():
            raise ValueError(f"case {case_id} already exists")
        iterations = max(100_000, min(int(body.get("kdf_iterations", vault_crypto.DEFAULT_ITERATIONS)), 5_000_000))
        detection = DetectionConfig(window_seconds=float(body.get("window", 10.0)),
                                    port_threshold=int(body.get("threshold", 15)))
        start = time.perf_counter()
        result = seal_case(capture, case_dir, passphrase=passphrase, private_key_path=self.private_key,
                           investigator=str(body.get("investigator") or "Investigator")[:80], case_id=case_id,
                           backend=str(body.get("backend", "builtin")), kdf_iterations=iterations,
                           detection=detection, custodian_key=custodian)
        total_ms = (time.perf_counter() - start) * 1000
        self.log("seal", case_id=case_id, records=result.record_count, alerts=result.alerts,
                 keyed=custodian is not None, total_ms=round(total_ms, 1), timings=result.timings,
                 kdf_iterations=iterations)
        return {"case_id": case_id, "records": result.record_count, "root_hash": result.root_hash,
                "alerts": result.alerts, "timings": result.timings, "total_ms": round(total_ms, 1),
                "keyed": custodian is not None}

    def case_detail(self, case_id: str) -> dict:
        d = self.case_path(case_id)
        report = load_report(d)
        sig_ok = signing.verify((d / REPORT_NAME).read_bytes(), (d / SIGNATURE_NAME).read_bytes(),
                                signing.load_public_key(self.public_key)) if self.public_key.exists() else None
        files = [{"file": p.name, "bytes": p.stat().st_size} for p in sorted(d.iterdir()) if p.is_file()]
        return {"case_id": case_id, "report": report, "signature_valid": sig_ok, "files": files,
                "derived_from": _derived_from(case_id)}

    def verify(self, case_id: str, body: dict) -> dict:
        d = self.case_path(case_id)
        passphrase = body.get("passphrase") or None
        custodian = self.custodian_key() if body.get("use_custodian", True) else None
        start = time.perf_counter()
        result = verify_case(d, self.public_key, passphrase, custodian_key=custodian)
        total_ms = (time.perf_counter() - start) * 1000
        out = _verification_dict(result, load_report(d))
        out["total_ms"] = round(total_ms, 1)
        self.log("verify", case_id=case_id, verdict=out["summary"], total_ms=out["total_ms"],
                 layers=[{"name": c["name"], "status": c["status"], "ms": c["ms"]} for c in out["checks"]])
        return out

    def tamper(self, case_id: str, body: dict) -> dict:
        """Attack a *copy* of the case so the original evidence stays intact."""
        src = self.case_path(case_id)
        mode = str(body.get("mode", "modify"))
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        index = int(body.get("index", 1))
        base = case_id.split("~")[0]
        copy_id = f"{base}~{mode}-{index}"
        n = 2
        while (self.cases / copy_id).exists():
            copy_id = f"{base}~{mode}-{index}-{n}"
            n += 1
        dest = self.cases / copy_id
        shutil.copytree(src, dest)
        try:
            what = tamper_case(dest, mode, index, None if mode in KEYLESS_MODES else _passphrase(body),
                               str(body.get("field", "dst_port")), str(body.get("value", "4444")))
        except Exception:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        self.log("tamper", case_id=copy_id, source=case_id, mode=mode, index=index)
        return {"case_id": copy_id, "attack": what}

    def delete_case(self, case_id: str) -> dict:
        shutil.rmtree(self.case_path(case_id))
        return {"deleted": case_id}

    def query(self, case_id: str, body: dict) -> dict:
        """Search a sealed case: blind index by default, or full in-memory decryption for comparison."""
        d = self.case_path(case_id)
        mode = str(body.get("mode") or "index")
        report = load_report(d)
        if mode == "index" and "search_index" in report:
            return self._query_index(d, body)
        if mode not in ("index", "full"):
            raise ValueError("mode must be index or full")
        start = time.perf_counter()
        db = vault_crypto.decrypt((d / CONTAINER_NAME).read_bytes(), _passphrase(body))
        decrypt_ms = (time.perf_counter() - start) * 1000
        conn = open_database(db)
        try:
            clauses, params = [], []
            for column in ("src_ip", "dst_ip"):
                if body.get(column):
                    clauses.append(f"{column} = ?")
                    params.append(str(body[column]))
            if body.get("protocol"):
                clauses.append("protocol = ?")
                params.append(str(body["protocol"]).upper())
            if body.get("host"):
                clauses.append("(src_ip = ? OR dst_ip = ?)")
                params += [str(body["host"])] * 2
            if body.get("port") not in (None, ""):
                clauses.append("(src_port = ? OR dst_port = ?)")
                params += [int(body["port"])] * 2
            if body.get("flags"):
                clauses.append("tcp_flags = ?")
                params.append(str(body["flags"]).upper())
            if body.get("frame_from") not in (None, ""):
                clauses.append("idx >= ?")
                params.append(int(body["frame_from"]))
            if body.get("frame_to") not in (None, ""):
                clauses.append("idx <= ?")
                params.append(int(body["frame_to"]))
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            limit = max(1, min(int(body.get("limit", 100)), 2000))
            start = time.perf_counter()
            total = conn.execute(f"SELECT COUNT(*) FROM packets {where}", params).fetchone()[0]
            conn.row_factory = sqlite3.Row
            rows = conn.execute(f"SELECT {','.join(QUERY_COLUMNS)} FROM packets {where} ORDER BY idx LIMIT ?",
                                params + [limit]).fetchall()
            query_ms = (time.perf_counter() - start) * 1000
        finally:
            conn.close()
        return {"mode": "full", "total": total, "rows": [dict(r) for r in rows], "decrypt_ms": round(decrypt_ms, 1),
                "query_ms": round(query_ms, 2), "decrypted_records": report["integrity"]["record_count"]}

    def _query_index(self, d: Path, body: dict) -> dict:
        """Blind-index search: the store only ever sees opaque tokens; only the hits are decrypted."""
        passphrase = _passphrase(body)
        criteria = {k: body.get(k) for k in ("host", "src_ip", "dst_ip", "port", "protocol", "flags")}
        if criteria["port"] not in (None, ""):
            criteria["port"] = int(criteria["port"])
        frame_from = int(body["frame_from"]) if body.get("frame_from") not in (None, "") else None
        frame_to = int(body["frame_to"]) if body.get("frame_to") not in (None, "") else None
        limit = max(1, min(int(body.get("limit", 100)), 2000))
        r = search.search_case(d, passphrase, criteria, frame_from=frame_from, frame_to=frame_to, limit=limit,
                               public_key_path=self.public_key if self.public_key.exists() else None)
        return {"mode": "index", "total": r.total, "rows": r.rows, "trapdoors": r.trapdoors,
                "kdf_ms": r.kdf_ms, "query_ms": r.lookup_ms, "decrypt_ms": r.decrypt_ms,
                "decrypted_records": len(r.rows)}

    # ------------------------------------------------------------------ security

    def tamper_matrix(self, case_id: str, body: dict) -> dict:
        """Run every attack on a throw-away copy and record which layer caught it."""
        src = self.case_path(case_id)
        passphrase = _passphrase(body)
        report = load_report(src)
        n = report["integrity"]["record_count"]
        index = max(1, min(int(body.get("index") or n // 2 or 1), n))
        custodian = self.custodian_key()
        attacks = [(m, f"tamper --mode {m}") for m in MODES] + [
            ("report_edit", "edit report.json (change investigator)"),
            ("wrong_passphrase", "open with a wrong passphrase"),
            ("swap_signature", "replace report.sig with a signature from another key"),
        ]
        rows = []
        with tempfile.TemporaryDirectory(prefix="pv-matrix-") as tmp:
            for kind, label in attacks:
                dest = Path(tmp) / kind
                shutil.copytree(src, dest)
                pw = passphrase
                if kind in MODES:
                    if kind == "unindex" and not (dest / search.INDEX_NAME).exists():
                        continue  # case sealed without a search index
                    what = tamper_case(dest, kind, index if kind != "bitflip" else 4096,
                                       None if kind in KEYLESS_MODES else passphrase)
                elif kind == "report_edit":
                    r = json.loads((dest / REPORT_NAME).read_text(encoding="utf-8"))
                    r["case"]["investigator"] = "Mallory"
                    (dest / REPORT_NAME).write_text(json.dumps(r, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    what = "changed the investigator name inside report.json"
                elif kind == "wrong_passphrase":
                    pw = passphrase + "x"
                    what = "attempted decryption with a wrong passphrase"
                else:
                    other = RSA.generate(2048)
                    (dest / SIGNATURE_NAME).write_bytes(signing.sign((dest / REPORT_NAME).read_bytes(), other))
                    what = "re-signed report.json with an attacker's RSA key"
                result = verify_case(dest, self.public_key, pw, custodian_key=custodian)
                v = _verification_dict(result, report)
                rows.append({"attack": kind, "label": label, "what": what, "detected": not result.ok,
                             "checks": {c["name"]: c["status"] for c in v["checks"]},
                             "localised": v["localisation"], "chain_only": v["chain_localisation"]})
        self.log("matrix", case_id=case_id, attacks=len(rows), detected=sum(r["detected"] for r in rows))
        layers = ["RSA signature", "Container digest", "AES-GCM tag", "Hash chain"] + (
            ["NMAC tags"] if "keyed_integrity" in report else []) + (
            ["Search index", "Index consistency"] if "search_index" in report else [])
        return {"case_id": case_id, "index": index, "layers": layers, "rows": rows}

    def security(self) -> dict:
        cases = self.list_cases()
        reports = [load_report(self.cases / c["case_id"]) for c in cases if "~" not in c["case_id"]]
        iters = [r["evidence_container"]["kdf_iterations"] for r in reports]
        keys = self.keys_info()
        gitignore = Path(__file__).resolve().parents[2] / ".gitignore"
        ignored = gitignore.exists() and all(x in gitignore.read_text() for x in ("*.pem", "workspace/"))
        keyed = sum(1 for r in reports if "keyed_integrity" in r)
        indexed = sum(1 for r in reports if "search_index" in r)

        def m(group, name, active, detail, technique=""):
            return {"group": group, "name": name, "active": bool(active), "detail": detail, "technique": technique}

        measures = [
            m("Integrity", "SHA-256 rolling hash chain", True,
              "Hn = SHA256(Hn-1 ‖ record_n): any modified, inserted or deleted packet is located by index", "Lab 5"),
            m("Integrity", "Signed checkpoints", True, "chain hash every 256 records inside the signed report", "Lab 5"),
            m("Integrity", "Custodian NMAC tags", keys["custodian"] is not None,
              f"NMAC over every chain link with a separate custodian key; {keyed}/{len(reports)} cases keyed"
              if keys["custodian"] else "no custodian key yet: chain rebuilds are only localised to a 256-record window",
              "Nested MAC"),
            m("Confidentiality", "AES-256-GCM evidence container", True,
              "authenticated encryption; the 38-byte header is GCM associated data", "Lab 2"),
            m("Confidentiality", "PBKDF2-HMAC-SHA256 key derivation", not iters or min(iters) >= 600_000,
              f"random per-case salt; iterations: {min(iters):,} to {max(iters):,}" if iters
              else "600,000 iterations by default (OWASP 2023 guidance)", "Lab 2"),
            m("Confidentiality", "Plaintext never written to disk", True,
              "SQLite store is built, decrypted and queried only in memory (sqlite3 serialize/deserialize)"),
            m("Confidentiality", "Searchable encryption (blind index)", not reports or indexed == len(reports),
              f"{indexed}/{len(reports)} cases indexed: HMAC-SHA256 trapdoor tokens + AES-256-GCM per record; "
              "the store sees only tokens. Leaks equality / frequency per field and which records match",
              "SSE"),
            m("Authenticity", "RSA-2048 PKCS#1 v1.5 signature", keys["investigator"] is not None,
              f"investigator key {keys['investigator'] or 'not generated yet'}", "Labs 3, 6"),
            m("Authenticity", "Private key protected", keys["private_key_encrypted"],
              "PEM is passphrase-encrypted" if keys["private_key_encrypted"]
              else "PEM is not encrypted: run `packetvault keygen --protect` for production use"),
            m("Authenticity", "Public-only verification", True, "signature and container digest need only the public key"),
            m("Operational", "Keys and cases excluded from git", ignored, ".gitignore covers *.pem, keys/, cases/, workspace/"),
            m("Operational", "Tamper simulations on copies", True, "the dashboard never alters original evidence"),
            m("Operational", "Scan target restriction", True, "Nmap targets limited to loopback / private lab addresses"),
            m("Dashboard", "Loopback-only, Host allow-list", self.bind_host in LOOPBACK_HOSTS,
              f"bound to {self.bind_host}: blocks remote access and DNS rebinding" if self.bind_host in LOOPBACK_HOSTS
              else f"bound to {self.bind_host}: reachable from the network with no authentication "
                   "(the Host check is not access control); restart with --host 127.0.0.1"),
            m("Dashboard", "CSRF / clickjacking / XSS headers", True,
              "Origin check on POST, CSP, X-Frame-Options DENY, nosniff, no-store"),
            m("Dashboard", "Passphrases not stored", True, "used for one request only, never logged or cached"),
        ]
        return {"measures": measures, "keys": keys}

    # ------------------------------------------------------------------ metrics

    def overview(self) -> dict:
        cases = self.list_cases()
        originals = [c for c in cases if "~" not in c["case_id"]]
        hist = self.history()
        seals = [h for h in hist if h["kind"] == "seal"]
        verifies = [h for h in hist if h["kind"] == "verify"]
        return {
            "version": __version__,
            "tools": tools.available(),
            "keys": self.keys_info(),
            "totals": {
                "captures": len(self.list_captures()),
                "cases": len(originals),
                "tampered_copies": len(cases) - len(originals),
                "packets_sealed": sum(c["records"] for c in originals),
                "alerts": sum(c["alerts"] for c in originals),
                "keyed_cases": sum(1 for c in originals if c["keyed"]),
                "verifications": len(verifies),
                "verify_fail": sum(1 for v in verifies if v["verdict"] == "FAIL"),
                "scans": sum(1 for h in hist if h["kind"] == "scan"),
            },
            "seals": seals[-30:],
            "verifies": verifies[-30:],
            "events": list(reversed(hist[-40:])),
            "benchmarks": self.benchmarks(),
        }

    def benchmarks(self) -> dict | None:
        for p in (self.bench_dir / "benchmarks.json",
                  Path(__file__).resolve().parents[2] / "docs" / "benchmarks" / "benchmarks.json"):
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                data["source"] = "workspace" if p.parent == self.bench_dir else "docs/benchmarks"
                return data
        return None

    def run_bench(self, body: dict) -> dict:
        from ..bench import run_benchmarks

        name = body.get("file")
        if name:
            records = parse_pcap(self.capture_path(name), backend="builtin")
        else:
            records = parse_pcap(Path(__file__).resolve().parents[2] / "samples" / "lab_capture.pcap", backend="builtin")
        volumes = [int(v) for v in str(body.get("volumes", "1000,5000,10000")).split(",") if v.strip()][:6]
        volumes = [max(100, min(v, 100_000)) for v in volumes]
        start = time.perf_counter()
        run_benchmarks(records, self.bench_dir, volumes, plot=True)
        self.log("bench", volumes=volumes, total_s=round(time.perf_counter() - start, 1))
        return self.benchmarks()

    # ------------------------------------------------------------------ nested MAC

    def nmac_trace(self, message: str) -> dict:
        key = self.custodian_key()
        demo = key is None
        key = key or b"\x00" * 32
        k1, k2 = nmac.derive_keys(key)
        msg = message.encode()[:1024]
        trace = nmac.nmac_trace(k1, k2, msg)
        return {"message": message, "key": "demo all-zero key" if demo else f"custodian {nmac.key_fingerprint(key)}",
                **trace, "hmac": hmac.new(key, msg, "sha256").hexdigest(),
                "prefix": nmac.prefix_mac(k1, msg).hex()}

    def nmac_chain_example(self, case_id: str, body: dict) -> dict:
        """First few chain links of a keyed case with their NMAC tags, recomputed live."""
        d = self.case_path(case_id)
        key = self.custodian_key()
        if key is None:
            raise ValueError("no custodian key in this workspace")
        db = vault_crypto.decrypt((d / CONTAINER_NAME).read_bytes(), _passphrase(body))
        records, hashes, _ = load_database(db)
        tags = load_nmac_tags(db)
        k1, k2 = nmac.derive_keys(key)
        out = []
        for pos in range(1, min(6, len(records)) + 1):
            expected = nmac.chain_tag(k1, k2, pos, hashes[pos - 1])
            out.append({"position": pos, "frame": records[pos - 1].index, "chain_hash": hashes[pos - 1],
                        "stored_tag": tags[pos - 1] if pos <= len(tags) else None, "expected_tag": expected})
        return {"links": out}


# --------------------------------------------------------------------------- helpers

def _passphrase(body: dict) -> str:
    pw = body.get("passphrase")
    if not isinstance(pw, str) or len(pw) < 8:
        raise ValueError("case passphrase must be at least 8 characters")
    return pw


def _derived_from(case_id: str) -> str | None:
    return case_id.split("~")[0] if "~" in case_id else None


def _timeline(records, buckets: int = 60) -> list[dict]:
    if not records:
        return []
    t0, t1 = records[0].ts_float, records[-1].ts_float
    span = max(t1 - t0, 1e-6)
    width = span / buckets
    out = [{"t": t0 + i * width, "packets": 0, "syn": 0} for i in range(buckets)]
    for r in records:
        i = min(int((r.ts_float - t0) / width), buckets - 1)
        out[i]["packets"] += 1
        if r.has_flag("SYN") and not r.has_flag("ACK"):
            out[i]["syn"] += 1
    return out


def _verification_dict(result, report: dict) -> dict:
    v = result.chain_verdict
    loc = None
    if result.nmac_divergence:
        loc = {"kind": "exact", "by": "NMAC tags", "position": result.nmac_divergence[0],
               "frame": result.nmac_divergence[1]}
    elif v and v.first_divergence is not None:
        loc = {"kind": "exact", "by": "Hash chain", "position": v.first_divergence, "frame": v.divergent_record_index}
    elif v and v.window:
        loc = {"kind": "window", "by": "Signed checkpoints", "from": v.window[0], "to": v.window[1]}
    chain_loc = None
    if v and v.first_divergence is not None:
        chain_loc = {"kind": "exact", "position": v.first_divergence, "frame": v.divergent_record_index}
    elif v and v.window:
        chain_loc = {"kind": "window", "from": v.window[0], "to": v.window[1]}
    return {
        "summary": result.summary, "ok": result.ok,
        "checks": [asdict(c) for c in result.checks],
        "localisation": loc,
        "chain_localisation": chain_loc,
        "records": report["integrity"]["record_count"],
        "checkpoint_interval": report["integrity"]["checkpoint_interval"],
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

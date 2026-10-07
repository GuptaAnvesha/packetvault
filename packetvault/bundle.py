"""Sealing pipeline: PCAP -> parsed, hash-chained, encrypted, signed evidence bundle.

Bundle layout::

    <case_dir>/
        evidence.db.enc   AES-256-GCM container holding the SQLite evidence store
        report.json       signed case report (canonical JSON)
        report.sig        detached RSA-2048 PKCS#1 v1.5 signature over report.json
        report.txt        human-readable rendering of report.json
        report.pdf        (only when ReportLab is installed)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, chain, signing, vault_crypto
from .detect import DetectionConfig, detect_port_scans
from .parser import build_database, load_database, parse_pcap, resolve_backend
from .report import REPORT_FORMAT, render_pdf, render_text, serialise, traffic_statistics

CONTAINER_NAME = "evidence.db.enc"
REPORT_NAME = "report.json"
SIGNATURE_NAME = "report.sig"


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class SealResult:
    case_dir: Path
    record_count: int
    root_hash: str
    alerts: int
    report: dict


def seal_case(pcap_path: str | Path, case_dir: str | Path, *, passphrase: str, private_key_path: str | Path,
              investigator: str, case_id: str | None = None, key_passphrase: str | None = None,
              backend: str = "auto", kdf_iterations: int = vault_crypto.DEFAULT_ITERATIONS,
              detection: DetectionConfig = DetectionConfig(),
              checkpoint_interval: int = chain.CHECKPOINT_INTERVAL) -> SealResult:
    pcap_path, case_dir = Path(pcap_path), Path(case_dir)
    private_key = signing.load_private_key(private_key_path, key_passphrase)
    sealed_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    case_id = case_id or f"PV-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
    backend = resolve_backend(backend)

    # M1 - acquisition
    records = parse_pcap(pcap_path, backend=backend)
    acquisition = {
        "case_id": case_id,
        "investigator": investigator,
        "acquired_at": sealed_at,
        "source_file": pcap_path.name,
        "source_size": pcap_path.stat().st_size,
        "source_sha256": sha256_file(pcap_path),
        "parser_backend": backend,
        "record_count": len(records),
    }

    # M2 - integrity sealing
    sealed = chain.seal(records, acquisition, checkpoint_interval)

    # M3 - confidentiality (plaintext DB only ever exists in memory)
    db_bytes = build_database(records, sealed.hashes, metadata={"acquisition": json.dumps(acquisition, sort_keys=True)})
    container = vault_crypto.encrypt(db_bytes, passphrase, iterations=kdf_iterations)
    case_dir.mkdir(parents=True, exist_ok=True)
    container_path = case_dir / CONTAINER_NAME
    container_path.write_bytes(container)

    # M4 - detection
    alerts = detect_port_scans(records, detection)

    # M5 - report + signature
    report = {
        "format": REPORT_FORMAT,
        "case": {"case_id": case_id, "investigator": investigator, "sealed_at": sealed_at,
                 "tool_version": __version__},
        "acquisition": acquisition,
        "integrity": {
            "algorithm": "SHA-256 rolling hash chain",
            "h0": sealed.h0,
            "root_hash": sealed.root,
            "record_count": len(records),
            "checkpoint_interval": checkpoint_interval,
            "checkpoints": {str(k): v for k, v in sealed.checkpoints.items()},
        },
        "evidence_container": {
            "file": CONTAINER_NAME,
            "size": len(container),
            "sha256": hashlib.sha256(container).hexdigest(),
            "cipher": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "kdf_iterations": kdf_iterations,
        },
        "statistics": traffic_statistics(records),
        "detection": {"config": asdict(detection), "alerts": [a.to_dict() for a in alerts]},
        "signer": {"algorithm": signing.SIGNATURE_ALGORITHM,
                   "public_key_fingerprint": signing.fingerprint(private_key)},
    }
    report_bytes = serialise(report)
    (case_dir / REPORT_NAME).write_bytes(report_bytes)
    (case_dir / SIGNATURE_NAME).write_bytes(signing.sign(report_bytes, private_key))
    (case_dir / "report.txt").write_text(render_text(report), encoding="utf-8")
    render_pdf(report, case_dir / "report.pdf")

    return SealResult(case_dir, len(records), sealed.root, len(alerts), report)


def open_case(case_dir: str | Path, passphrase: str):
    """Decrypt a bundle's evidence store: returns (records, stored_hashes, db_metadata)."""
    blob = (Path(case_dir) / CONTAINER_NAME).read_bytes()
    return load_database(vault_crypto.decrypt(blob, passphrase))


def load_report(case_dir: str | Path) -> dict:
    return json.loads((Path(case_dir) / REPORT_NAME).read_text(encoding="utf-8"))

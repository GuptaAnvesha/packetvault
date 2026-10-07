"""M6 - Verification Utility.

Checks run in order of trust:

1. **Signature** - report.sig verifies over report.json with the
   investigator's public key (authenticity + non-repudiation). Everything
   below is compared against values *inside the signed report*.
2. **Container digest** - SHA-256 of evidence.db.enc equals the signed value
   (detects any byte change to the ciphertext; needs no passphrase).
3. **GCM tag** - the container decrypts and authenticates (needs passphrase).
4. **Hash chain** - every stored record hash is recomputed from the signed
   acquisition metadata; the first divergent record is reported, and the
   recomputed root / count / checkpoints are compared with the signed ones.

Checks 1-2 need only the public key, so any third party can run them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import chain, signing, vault_crypto
from .bundle import CONTAINER_NAME, REPORT_NAME, SIGNATURE_NAME
from .parser import load_database

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


@dataclass
class Check:
    name: str
    status: str
    detail: str


@dataclass
class VerificationResult:
    case_dir: Path
    checks: list[Check] = field(default_factory=list)
    chain_verdict: chain.ChainVerdict | None = None

    @property
    def ok(self) -> bool:
        return all(c.status != FAIL for c in self.checks)

    @property
    def complete(self) -> bool:
        return all(c.status != SKIP for c in self.checks)

    @property
    def summary(self) -> str:
        if not self.ok:
            return "FAIL"
        return "PASS" if self.complete else "PASS (public checks only)"

    def add(self, name: str, status: str, detail: str) -> None:
        self.checks.append(Check(name, status, detail))


def verify_case(case_dir: str | Path, public_key_path: str | Path, passphrase: str | None = None) -> VerificationResult:
    case_dir = Path(case_dir)
    result = VerificationResult(case_dir)

    report_bytes = (case_dir / REPORT_NAME).read_bytes()
    signature = (case_dir / SIGNATURE_NAME).read_bytes()
    public_key = signing.load_public_key(public_key_path)

    # 1. signature
    if signing.verify(report_bytes, signature, public_key):
        result.add("RSA signature", PASS, f"report.json signed by key {signing.fingerprint(public_key)}")
    else:
        result.add("RSA signature", FAIL, "signature does not match report.json for this public key")
        # Nothing in an unauthenticated report can be trusted as a reference.
        for name in ("Container digest", "AES-GCM tag", "Hash chain"):
            result.add(name, SKIP, "skipped: report is not authentic")
        return result

    report = json.loads(report_bytes)
    container_info, integrity = report["evidence_container"], report["integrity"]

    # 2. container digest
    container_path = case_dir / CONTAINER_NAME
    blob = container_path.read_bytes() if container_path.exists() else b""
    actual = hashlib.sha256(blob).hexdigest()
    if actual == container_info["sha256"]:
        result.add("Container digest", PASS, f"SHA-256 {actual[:16]}... matches signed report")
    else:
        result.add("Container digest", FAIL,
                   f"SHA-256 {actual[:16]}... != signed {container_info['sha256'][:16]}... (container replaced or modified)")

    if passphrase is None:
        result.add("AES-GCM tag", SKIP, "no passphrase supplied")
        result.add("Hash chain", SKIP, "no passphrase supplied")
        return result

    # 3. GCM authentication
    try:
        db_bytes = vault_crypto.decrypt(blob, passphrase)
        result.add("AES-GCM tag", PASS, "container decrypted and authenticated")
    except vault_crypto.DecryptionError as exc:
        result.add("AES-GCM tag", FAIL, str(exc))
        result.add("Hash chain", SKIP, "skipped: container could not be decrypted")
        return result

    # 4. hash chain, anchored on the signed acquisition metadata
    records, stored_hashes, _ = load_database(db_bytes)
    verdict = chain.verify(
        records, stored_hashes, report["acquisition"],
        expected_root=integrity["root_hash"],
        expected_count=integrity["record_count"],
        checkpoints={int(k): v for k, v in integrity["checkpoints"].items()},
    )
    result.chain_verdict = verdict
    if verdict.ok:
        result.add("Hash chain", PASS, f"{verdict.records_checked} records, root {verdict.recomputed_root[:16]}... matches")
    else:
        result.add("Hash chain", FAIL, "; ".join(verdict.problems))
    return result

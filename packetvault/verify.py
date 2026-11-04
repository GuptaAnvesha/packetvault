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
5. **NMAC tags** (only for cases sealed with a custodian key) - each stored
   tag must equal NMAC(custodian key, n || recomputed H_n). An insider who
   recomputed the chain cannot forge these, so the first changed record is
   found exactly instead of within a checkpoint window.
6. **Search index** (cases with a blind index) - SHA-256 of search.idx equals
   the signed value, so a storage provider cannot hide packets from search by
   deleting token rows (public check, no passphrase).
7. **Index consistency** - every index record decrypts, authenticates and
   equals the container's record and chain hash, and every token matches,
   so the index is a faithful view of the sealed evidence.

Checks 1, 2 and 6 need only the public key, so any third party can run them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import chain, nmac, search, signing, vault_crypto
from .bundle import CONTAINER_NAME, REPORT_NAME, SIGNATURE_NAME
from .parser import load_database, load_nmac_tags

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


@dataclass
class Check:
    name: str
    status: str
    detail: str
    ms: float = 0.0


@dataclass
class VerificationResult:
    case_dir: Path
    checks: list[Check] = field(default_factory=list)
    chain_verdict: chain.ChainVerdict | None = None
    nmac_divergence: tuple[int, int] | None = None  # (position, frame number) of the first bad tag
    _clock: float = field(default_factory=time.perf_counter, repr=False)

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
        if self.complete:
            return "PASS"
        skipped = {c.name for c in self.checks if c.status == SKIP}
        return "PASS (custodian check skipped)" if skipped == {"NMAC tags"} else "PASS (public checks only)"

    def add(self, name: str, status: str, detail: str) -> None:
        now = time.perf_counter()
        ms = round((now - self._clock) * 1000, 2) if status != SKIP else 0.0
        self._clock = now
        self.checks.append(Check(name, status, detail, ms))


def verify_case(case_dir: str | Path, public_key_path: str | Path, passphrase: str | None = None,
                custodian_key: bytes | None = None) -> VerificationResult:
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
    index_info = report.get("search_index")

    # 2. container digest
    container_path = case_dir / CONTAINER_NAME
    blob = container_path.read_bytes() if container_path.exists() else b""
    actual = hashlib.sha256(blob).hexdigest()
    if actual == container_info["sha256"]:
        result.add("Container digest", PASS, f"SHA-256 {actual[:16]}... matches signed report")
    else:
        result.add("Container digest", FAIL,
                   f"SHA-256 {actual[:16]}... != signed {container_info['sha256'][:16]}... (container replaced or modified)")

    # 6. search index digest (public)
    index_bytes = None
    if index_info:
        try:
            index_bytes = search.check_index_digest(case_dir, report)
            result.add("Search index", PASS, f"SHA-256 {index_info['sha256'][:16]}... matches signed report "
                                             f"({index_info['tokens']} tokens)")
        except search.IndexIntegrityError as exc:
            result.add("Search index", FAIL, str(exc))

    keyed = report.get("keyed_integrity")
    if passphrase is None:
        result.add("AES-GCM tag", SKIP, "no passphrase supplied")
        result.add("Hash chain", SKIP, "no passphrase supplied")
        if keyed:
            result.add("NMAC tags", SKIP, "no passphrase supplied")
        if index_info:
            result.add("Index consistency", SKIP, "no passphrase supplied")
        return result

    # 3. GCM authentication
    try:
        db_bytes = vault_crypto.decrypt(blob, passphrase)
        result.add("AES-GCM tag", PASS, "container decrypted and authenticated")
    except vault_crypto.DecryptionError as exc:
        result.add("AES-GCM tag", FAIL, str(exc))
        result.add("Hash chain", SKIP, "skipped: container could not be decrypted")
        if keyed:
            result.add("NMAC tags", SKIP, "skipped: container could not be decrypted")
        if index_info:
            result.add("Index consistency", SKIP, "skipped: container could not be decrypted")
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

    if keyed:
        _verify_nmac(result, keyed, records, verdict.recomputed_hashes, load_nmac_tags(db_bytes), custodian_key)
    if index_info:
        _verify_index(result, index_bytes, passphrase, integrity["h0"], records, stored_hashes)
    return result


def _verify_index(result: VerificationResult, index_bytes: bytes | None, passphrase: str, h0: str,
                  records, stored_hashes) -> None:
    if index_bytes is None:
        result.add("Index consistency", SKIP, "skipped: index failed its digest check")
        return
    store = search.IndexStore(index_bytes)
    try:
        client = search.SearchClient(store, passphrase, h0)
        first = search.consistency(store, client, records, stored_hashes)
    except vault_crypto.DecryptionError as exc:
        result.add("Index consistency", FAIL, str(exc))
        return
    finally:
        store.close()
    if first is None:
        result.add("Index consistency", PASS, f"all {len(records)} index records and tokens match the container")
    else:
        result.add("Index consistency", FAIL, f"index and container disagree from position {first} "
                                              "(the container digest and hash chain show which side changed)")


def _verify_nmac(result: VerificationResult, keyed: dict, records, recomputed: list[str],
                 stored: list[str | None], custodian_key: bytes | None) -> None:
    if custodian_key is None:
        result.add("NMAC tags", SKIP, "case has custodian NMAC tags; supply the custodian key to check them")
        return
    if nmac.key_fingerprint(custodian_key) != keyed["custodian_key_fingerprint"]:
        result.add("NMAC tags", FAIL, "custodian key fingerprint does not match the signed report (wrong key)")
        return
    k1, k2 = nmac.derive_keys(custodian_key)
    problems = []
    for pos, (rec, h) in enumerate(zip(records, recomputed), start=1):
        tag = stored[pos - 1] if pos <= len(stored) else None
        if tag is None or not hmac.compare_digest(tag, nmac.chain_tag(k1, k2, pos, h)):
            result.nmac_divergence = (pos, rec.index)
            reason = "tag missing" if tag is None else "record or chain link was altered"
            problems.append(f"first invalid NMAC tag at position {pos} (frame #{rec.index}): {reason}")
            break
    if len(stored) != keyed["tag_count"] or len(records) != keyed["tag_count"]:
        problems.append(f"{len(stored)} tags / {len(records)} records stored, signed report says {keyed['tag_count']}")
    if stored and stored[-1] != keyed["root_tag"]:
        problems.append("final tag differs from the signed root tag")
    if problems:
        result.add("NMAC tags", FAIL, "; ".join(problems))
    else:
        result.add("NMAC tags", PASS, f"{len(stored)} keyed tags valid "
                                      f"(custodian key {keyed['custodian_key_fingerprint'][:23]}...)")

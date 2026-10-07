"""M7 - Benchmarking Suite.

Measures, over increasing packet volumes drawn from a real capture:

* AES-256 encryption throughput in CBC, CTR and GCM modes
* per-record hashing time with MD5, SHA-1 and SHA-256 (the hash-chain workload)
* RSA-2048 vs ECC secp256r1 (ECDSA) key generation, signing and verification

and writes three plots plus a JSON file of the raw numbers.
"""

from __future__ import annotations

import itertools
import json
import statistics
import time
from pathlib import Path
from typing import Callable, Sequence

from Crypto.Hash import MD5, SHA1, SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS, pkcs1_15

from . import vault_crypto
from .models import PacketRecord

DEFAULT_VOLUMES = (1_000, 5_000, 10_000, 25_000, 50_000)


def _median_time(fn: Callable[[], object], repeat: int) -> float:
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def _record_payloads(records: Sequence[PacketRecord], n: int) -> list[bytes]:
    return [r.canonical_bytes() for r in itertools.islice(itertools.cycle(records), n)]


def bench_aes_modes(payloads_by_volume: dict[int, list[bytes]], repeat: int = 5) -> dict:
    key = get_random_bytes(32)
    modes = {"CBC": vault_crypto.encrypt_cbc, "CTR": vault_crypto.encrypt_ctr, "GCM": vault_crypto.encrypt_gcm_raw}
    out: dict = {m: [] for m in modes}
    for volume, payloads in payloads_by_volume.items():
        data = b"".join(payloads)
        for mode, fn in modes.items():
            secs = _median_time(lambda: fn(key, data), repeat)
            out[mode].append({"packets": volume, "bytes": len(data), "seconds": secs,
                              "mb_per_s": len(data) / secs / 1e6})
    return out


def bench_hashes(payloads_by_volume: dict[int, list[bytes]], repeat: int = 3) -> dict:
    algos = {"MD5": MD5, "SHA-1": SHA1, "SHA-256": SHA256}
    out: dict = {a: [] for a in algos}
    for volume, payloads in payloads_by_volume.items():
        for name, mod in algos.items():
            def chain_run(mod=mod):
                h = b"\x00" * 32
                for p in payloads:
                    h = mod.new(h + p).digest()
            secs = _median_time(chain_run, repeat)
            out[name].append({"packets": volume, "seconds": secs, "us_per_record": secs / volume * 1e6})
    return out


def bench_rsa_vs_ecc(payloads_by_volume: dict[int, list[bytes]], keygen_repeat: int = 5,
                     op_repeat: int = 30) -> dict:
    rsa_key = RSA.generate(2048)
    ecc_key = ECC.generate(curve="secp256r1")
    report_like = get_random_bytes(16 * 1024)
    digest = SHA256.new(report_like)
    rsa_sig = pkcs1_15.new(rsa_key).sign(digest)
    ecc_sig = DSS.new(ecc_key, "fips-186-3").sign(digest)

    ops = {
        "RSA-2048": {
            "keygen": _median_time(lambda: RSA.generate(2048), keygen_repeat),
            "sign": _median_time(lambda: pkcs1_15.new(rsa_key).sign(digest), op_repeat),
            "verify": _median_time(lambda: pkcs1_15.new(rsa_key.public_key()).verify(digest, rsa_sig), op_repeat),
            "public_key_bytes": len(rsa_key.public_key().export_key(format="DER")),
            "signature_bytes": len(rsa_sig),
        },
        "ECC P-256": {
            "keygen": _median_time(lambda: ECC.generate(curve="secp256r1"), keygen_repeat * 4),
            "sign": _median_time(lambda: DSS.new(ecc_key, "fips-186-3").sign(digest), op_repeat),
            "verify": _median_time(lambda: DSS.new(ecc_key.public_key(), "fips-186-3").verify(digest, ecc_sig), op_repeat),
            "public_key_bytes": len(ecc_key.public_key().export_key(format="DER")),
            "signature_bytes": len(ecc_sig),
        },
    }
    # Signing an evidence set of N packets = hash N records + one private-key operation.
    by_volume: dict = {"RSA-2048": [], "ECC P-256": []}
    for volume, payloads in payloads_by_volume.items():
        data = b"".join(payloads)
        by_volume["RSA-2048"].append({"packets": volume, "seconds": _median_time(
            lambda: pkcs1_15.new(rsa_key).sign(SHA256.new(data)), 5)})
        by_volume["ECC P-256"].append({"packets": volume, "seconds": _median_time(
            lambda: DSS.new(ecc_key, "fips-186-3").sign(SHA256.new(data)), 5)})
    return {"operations": ops, "sign_by_volume": by_volume}


def run_benchmarks(records: Sequence[PacketRecord], out_dir: str | Path,
                   volumes: Sequence[int] = DEFAULT_VOLUMES, plot: bool = True,
                   progress: Callable[[str], None] = lambda _msg: None) -> dict:
    if not records:
        raise ValueError("benchmarks need at least one parsed record")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    payloads = {v: _record_payloads(records, v) for v in volumes}

    progress("AES modes (CBC / CTR / GCM)")
    aes = bench_aes_modes(payloads)
    progress("hash functions (MD5 / SHA-1 / SHA-256)")
    hashes = bench_hashes(payloads)
    progress("RSA-2048 vs ECC secp256r1")
    asym = bench_rsa_vs_ecc(payloads)

    results = {"volumes": list(volumes), "aes_modes": aes, "hashes": hashes, "rsa_vs_ecc": asym}
    (out_dir / "benchmarks.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    if plot:
        progress("plotting")
        _plot(results, out_dir)
    return results


def _plot(results: dict, out_dir: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    def line_chart(series: dict, key: str, ylabel: str, title: str, filename: str) -> None:
        fig, ax = plt.subplots(figsize=(7, 4.2))
        for name, points in series.items():
            ax.plot([p["packets"] for p in points], [p[key] for p in points], marker="o", label=name)
        ax.set_xlabel("packets")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(alpha=0.3)
        ax.legend()
        fig.tight_layout()
        fig.savefig(out_dir / filename, dpi=150)
        plt.close(fig)

    line_chart(results["aes_modes"], "mb_per_s", "throughput (MB/s)",
               "AES-256 encryption throughput by mode", "bench_aes_modes.png")
    line_chart(results["hashes"], "seconds", "time to hash-chain all records (s)",
               "Hash-chain cost: MD5 vs SHA-1 vs SHA-256", "bench_hashes.png")

    ops = results["rsa_vs_ecc"]["operations"]
    fig, (left, right) = plt.subplots(1, 2, figsize=(11, 4.2))
    names = list(ops)
    labels = ["keygen", "sign", "verify"]
    width = 0.38
    for i, name in enumerate(names):
        xs = [x + (i - 0.5) * width for x in range(len(labels))]
        left.bar(xs, [ops[name][op] * 1000 for op in labels], width, label=name)
    left.set_xticks(range(len(labels)), labels)
    left.set_yscale("log")
    left.set_ylabel("median time (ms, log scale)")
    left.set_title("RSA-2048 vs ECC P-256 key operations")
    left.legend()
    left.grid(alpha=0.3, axis="y")
    for name, points in results["rsa_vs_ecc"]["sign_by_volume"].items():
        right.plot([p["packets"] for p in points], [p["seconds"] * 1000 for p in points], marker="o", label=name)
    right.set_xlabel("packets in evidence set")
    right.set_ylabel("hash + sign time (ms)")
    right.set_title("Signing cost vs evidence volume")
    right.legend()
    right.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "bench_rsa_vs_ecc.png", dpi=150)
    plt.close(fig)

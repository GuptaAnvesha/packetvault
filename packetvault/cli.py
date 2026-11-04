"""Command-line interface: ``packetvault <command> ...`` (or ``python -m packetvault``)."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sqlite3
import sys
from pathlib import Path

from . import __version__

PASSPHRASE_ENV = "PACKETVAULT_PASSPHRASE"


# --------------------------------------------------------------------------- output helpers

def _supports_colour() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


_COLOURS = {"PASS": "32", "FAIL": "31", "SKIP": "33", "HIGH": "31", "MEDIUM": "33", "dim": "2", "bold": "1"}


def _c(text: str, style: str) -> str:
    code = _COLOURS.get(style)
    return f"\033[{code}m{text}\033[0m" if code and _supports_colour() else text


def _passphrase(args, confirm: bool = False, required: bool = True) -> str | None:
    if getattr(args, "passphrase", None):
        return args.passphrase
    if os.environ.get(PASSPHRASE_ENV):
        return os.environ[PASSPHRASE_ENV]
    if not required:
        return None
    value = getpass.getpass("Case passphrase: ")
    if confirm and value != getpass.getpass("Confirm passphrase: "):
        sys.exit("error: passphrases do not match")
    return value


# --------------------------------------------------------------------------- commands

def cmd_sample(args) -> int:
    from .samplegen import generate_lab_capture

    labels_path = args.labels or str(Path(args.output).with_suffix(".labels.json"))
    labels = generate_lab_capture(args.output, labels_path, seed=args.seed)
    print(f"wrote {args.output} ({labels['packets']} packets) and ground truth {labels_path}")
    print(f"  scanners: {', '.join(labels['scanners'])}")
    return 0


def cmd_keygen(args) -> int:
    from .signing import fingerprint, generate_keypair, load_public_key

    key_pass = getpass.getpass("Private-key passphrase (empty for none): ") if args.protect else None
    priv, pub = generate_keypair(args.out_dir, args.name, key_pass or None)
    print(f"private key : {priv}  (keep secret)")
    print(f"public key  : {pub}  (distribute to verifiers)")
    print(f"fingerprint : {fingerprint(load_public_key(pub))}")
    if args.custodian:
        from .nmac import generate_custodian_key, key_fingerprint

        path = Path(args.out_dir) / "custodian.key"
        key = generate_custodian_key(path)
        print(f"custodian   : {path}  (NMAC key; give it only to the evidence custodian)")
        print(f"custodian fp: {key_fingerprint(key)}")
    return 0


def cmd_parse(args) -> int:
    from .parser import parse_pcap, resolve_backend, write_sqlite, write_xml

    backend = resolve_backend(args.backend)
    records = parse_pcap(args.pcap, backend=backend)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = Path(args.pcap).stem
    write_xml(records, out / f"{stem}.xml", metadata={"source_file": Path(args.pcap).name, "parser_backend": backend})
    write_sqlite(records, out / f"{stem}.db")
    print(f"parsed {len(records)} packets with the {backend} backend")
    print(f"  XML    : {out / (stem + '.xml')}")
    print(f"  SQLite : {out / (stem + '.db')}  (unsealed working copy)")
    return 0


def cmd_seal(args) -> int:
    from .bundle import seal_case
    from .detect import DetectionConfig

    passphrase = _passphrase(args, confirm=True)
    key_pass = getpass.getpass("Private-key passphrase: ") if args.key_protected else None
    result = seal_case(
        args.pcap, args.out, passphrase=passphrase, private_key_path=args.key, key_passphrase=key_pass,
        investigator=args.investigator, case_id=args.case_id, backend=args.backend,
        kdf_iterations=args.kdf_iterations,
        detection=DetectionConfig(args.window, args.threshold, args.min_syn_ratio),
        custodian_key=_custodian_key(args), searchable=not args.no_search_index,
    )
    print(_c(f"sealed case {result.report['case']['case_id']} -> {result.case_dir}", "bold"))
    print(f"  records      : {result.record_count}")
    print(f"  root hash    : {result.root_hash}")
    print(f"  scan alerts  : {result.alerts}")
    print(f"  signed by    : {result.report['signer']['public_key_fingerprint']}")
    if "keyed_integrity" in result.report:
        print(f"  NMAC tags    : {result.report['keyed_integrity']['tag_count']} "
              f"(custodian {result.report['keyed_integrity']['custodian_key_fingerprint'][:23]}...)")
    if "search_index" in result.report:
        print(f"  search index : {result.report['search_index']['tokens']} blind tokens over "
              f"{', '.join(result.report['search_index']['fields'])}")
    for name in ("evidence.db.enc", "search.idx", "report.json", "report.sig", "report.txt", "report.pdf"):
        if (result.case_dir / name).exists():
            print(_c(f"    {result.case_dir / name}", "dim"))
    return 0


def cmd_verify(args) -> int:
    from .verify import verify_case

    passphrase = None if args.public_only else _passphrase(args, required=False)
    if passphrase is None and not args.public_only and sys.stdin.isatty():
        passphrase = getpass.getpass("Case passphrase (empty to run public checks only): ") or None
    result = verify_case(args.case_dir, args.pubkey, passphrase, custodian_key=_custodian_key(args))

    print(_c(f"Verifying {result.case_dir}", "bold"))
    for check in result.checks:
        print(f"  [{_c(check.status, check.status)}] {check.name:<17} {check.detail}")
    v = result.chain_verdict
    if result.nmac_divergence:
        pos, frame = result.nmac_divergence
        print(_c(f"\n  >> NMAC tags localise tampering to record position {pos} (frame #{frame})", "FAIL"))
    elif v and v.first_divergence is not None:
        print(_c(f"\n  >> tampering localised to record position {v.first_divergence} "
                 f"(frame #{v.divergent_record_index})", "FAIL"))
    elif v and v.window:
        print(_c(f"\n  >> tampering localised to record positions {v.window[0]}-{v.window[1]}", "FAIL"))
    print(f"\nVERDICT: {_c(result.summary, 'PASS' if result.ok else 'FAIL')}")
    return 0 if result.ok else 2


def cmd_tamper(args) -> int:
    from .tamper import KEYLESS_MODES, tamper_case

    passphrase = None if args.mode in KEYLESS_MODES else _passphrase(args)
    print(_c("ATTACK: " + tamper_case(args.case_dir, args.mode, args.index, passphrase, args.field, args.value), "FAIL"))
    return 0


def cmd_detect(args) -> int:
    from .detect import DetectionConfig, detect_port_scans, evaluate

    records = _records_from_source(args)
    config = DetectionConfig(args.window, args.threshold, args.min_syn_ratio)
    alerts = detect_port_scans(records, config)
    print(f"analysed {len(records)} packets  (>{config.port_threshold} ports in {config.window_seconds}s window)")
    if not alerts:
        print("  no scanning activity detected")
    for a in alerts:
        print(f"  [{_c(a.severity, a.severity)}] {a.src_ip:<16} {a.max_ports_in_window:>4} ports/window  "
              f"{a.distinct_ports_total:>5} ports total  SYN:SYN-ACK {a.syn_sent}:{a.synack_received} "
              f"(ratio {a.syn_ratio})  targets {', '.join(a.targets)}")
    if args.labels:
        labels = json.loads(Path(args.labels).read_text(encoding="utf-8"))
        hosts = {ip for r in records for ip in (r.src_ip,) if ip}
        metrics = evaluate(alerts, labels["scanners"], hosts)
        print("\nevaluation against ground truth:")
        for key in ("true_positives", "false_positives", "false_negatives", "true_negatives",
                    "precision", "recall", "f1", "accuracy"):
            print(f"  {key:<16} {metrics[key]}")
    return 0


def _print_packet_rows(rows) -> None:
    print(f"{'#':>6}  {'time':<17} {'source':<22} {'destination':<22} {'proto':<6} {'flags':<8} {'len':>5}")
    for r in rows:
        src = f"{r['src_ip']}:{r['src_port']}" if r["src_port"] is not None else str(r["src_ip"])
        dst = f"{r['dst_ip']}:{r['dst_port']}" if r["dst_port"] is not None else str(r["dst_ip"])
        print(f"{r['idx']:>6}  {r['timestamp']:<17} {src:<22} {dst:<22} {r['protocol']:<6} "
              f"{(r['tcp_flags'] or ''):<8} {r['frame_len']:>5}")


def cmd_query(args) -> int:
    from .bundle import CONTAINER_NAME, load_report
    from .parser import open_database
    from .vault_crypto import decrypt

    if not args.full_decrypt and "search_index" in load_report(args.case_dir):
        from .search import search_case

        criteria = {"src_ip": args.src, "dst_ip": args.dst, "protocol": args.proto, "host": args.host,
                    "port": args.port, "flags": args.flags}
        r = search_case(args.case_dir, _passphrase(args), criteria, limit=args.limit, public_key_path=args.pubkey)
        _print_packet_rows(r.rows)
        print(_c(f"{min(r.total, args.limit)} of {r.total} matching packets shown (blind index: "
                 f"KDF {r.kdf_ms:.0f} ms, token lookup {r.lookup_ms:.2f} ms, {len(r.rows)} records decrypted "
                 f"in {r.decrypt_ms:.2f} ms)", "dim"))
        if not args.pubkey:
            print(_c("note: pass --pubkey to check the report signature that anchors the index digest", "dim"))
        if args.show_tokens:
            print("tokens sent to the store (all it ever sees):")
            for t in r.trapdoors:
                print(f"  {t['criterion']:<9} -> {t['field']:<9} {t['token']}")
        return 0

    blob = (Path(args.case_dir) / CONTAINER_NAME).read_bytes()
    conn = open_database(decrypt(blob, _passphrase(args)))
    clauses, params = [], []
    for column, value in (("src_ip", args.src), ("dst_ip", args.dst), ("protocol", args.proto)):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value.upper() if column == "protocol" else value)
    if args.host:
        clauses.append("(src_ip = ? OR dst_ip = ?)")
        params += [args.host, args.host]
    if args.port is not None:
        clauses.append("(src_port = ? OR dst_port = ?)")
        params += [args.port, args.port]
    if args.flags:
        clauses.append("tcp_flags = ?")
        params.append(args.flags.upper())
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    conn.row_factory = sqlite3.Row
    total = conn.execute(f"SELECT COUNT(*) FROM packets {where}", params).fetchone()[0]
    rows = conn.execute(f"SELECT * FROM packets {where} ORDER BY idx LIMIT ?", params + [args.limit]).fetchall()
    _print_packet_rows(rows)
    print(_c(f"{min(total, args.limit)} of {total} matching packets shown (full in-memory decryption)", "dim"))
    conn.close()
    return 0


def cmd_export(args) -> int:
    from .bundle import load_report, open_case
    from .parser import write_xml

    records, _, _ = open_case(args.case_dir, _passphrase(args))
    write_xml(records, args.output, metadata=load_report(args.case_dir)["acquisition"])
    print(f"exported {len(records)} packets to {args.output}")
    return 0


def cmd_bench(args) -> int:
    from .bench import run_benchmarks

    records = _records_from_source(args)
    volumes = [int(v) for v in args.volumes.split(",")]
    results = run_benchmarks(records, args.out_dir, volumes, progress=lambda m: print(f"  benchmarking {m} ..."))
    largest = volumes[-1]
    print(f"\nresults for {largest} packets:")
    for mode, pts in results["aes_modes"].items():
        print(f"  AES-{mode:<4} {pts[-1]['mb_per_s']:8.1f} MB/s")
    for algo, pts in results["hashes"].items():
        print(f"  {algo:<8} {pts[-1]['us_per_record']:8.2f} us/record chained  {pts[-1]['bulk_mb_per_s']:8.0f} MB/s bulk")
    for name, ops in results["rsa_vs_ecc"]["operations"].items():
        print(f"  {name:<9} keygen {ops['keygen']*1000:8.1f} ms  sign {ops['sign']*1000:6.2f} ms  "
              f"verify {ops['verify']*1000:6.2f} ms")
    print(f"\nplots and raw data written to {args.out_dir}")
    return 0


def cmd_ui(args) -> int:
    from .webui.server import run

    return run(args.host, args.port, Path(args.workspace), open_browser=not args.no_browser)


def _custodian_key(args) -> bytes | None:
    if not getattr(args, "custodian_key", None):
        return None
    from .nmac import load_custodian_key

    return load_custodian_key(args.custodian_key)


def _records_from_source(args):
    from .bundle import open_case
    from .parser import parse_pcap

    source = Path(args.source)
    if source.is_dir():
        records, _, _ = open_case(source, _passphrase(args))
        return records
    return parse_pcap(source, backend=getattr(args, "backend", "auto"))


# --------------------------------------------------------------------------- argument parsing

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="packetvault",
        description="Tamper-evident network forensics store: hash-chained, AES-256-GCM encrypted, RSA-signed PCAP evidence.",
    )
    p.add_argument("--version", action="version", version=f"PacketVault {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    def add_passphrase(sp):
        sp.add_argument("--passphrase", help=f"case passphrase (prefer the {PASSPHRASE_ENV} env var or the prompt)")

    def add_detection(sp):
        sp.add_argument("--window", type=float, default=10.0, help="sliding window in seconds (default 10)")
        sp.add_argument("--threshold", type=int, default=15, help="distinct-port threshold (default 15)")
        sp.add_argument("--min-syn-ratio", type=float, default=3.0, help="SYN:SYN-ACK ratio for HIGH severity")

    sp = sub.add_parser("sample", help="generate a synthetic lab capture with ground-truth labels")
    sp.add_argument("output", help="output .pcap path")
    sp.add_argument("--labels", help="ground-truth JSON path (default <output>.labels.json)")
    sp.add_argument("--seed", type=int, default=7)
    sp.set_defaults(func=cmd_sample)

    sp = sub.add_parser("keygen", help="create an investigator RSA-2048 keypair")
    sp.add_argument("--out-dir", default="keys")
    sp.add_argument("--name", default="investigator")
    sp.add_argument("--protect", action="store_true", help="encrypt the private key with a passphrase")
    sp.add_argument("--custodian", action="store_true", help="also create a custodian NMAC key (custodian.key)")
    sp.set_defaults(func=cmd_keygen)

    sp = sub.add_parser("parse", help="M1: parse a capture into XML + SQLite (unsealed)")
    sp.add_argument("pcap")
    sp.add_argument("--out-dir", default="parsed")
    sp.add_argument("--backend", choices=("auto", "builtin", "pyshark"), default="auto")
    sp.set_defaults(func=cmd_parse)

    sp = sub.add_parser("seal", help="M1-M5: build a sealed, encrypted, signed evidence bundle")
    sp.add_argument("pcap")
    sp.add_argument("--out", required=True, help="case bundle directory")
    sp.add_argument("--key", required=True, help="investigator private key (PEM)")
    sp.add_argument("--key-protected", action="store_true", help="prompt for the private-key passphrase")
    sp.add_argument("--investigator", required=True)
    sp.add_argument("--case-id")
    sp.add_argument("--backend", choices=("auto", "builtin", "pyshark"), default="auto")
    sp.add_argument("--kdf-iterations", type=int, default=600_000)
    sp.add_argument("--custodian-key", help="custodian NMAC key file: adds a keyed tag to every chain link")
    sp.add_argument("--no-search-index", action="store_true", help="skip the blind index (search.idx)")
    add_passphrase(sp)
    add_detection(sp)
    sp.set_defaults(func=cmd_seal)

    sp = sub.add_parser("verify", help="M6: verify a bundle against the investigator's public key")
    sp.add_argument("case_dir")
    sp.add_argument("--pubkey", required=True)
    sp.add_argument("--public-only", action="store_true", help="run only the checks that need no passphrase")
    sp.add_argument("--custodian-key", help="custodian NMAC key file, to check the keyed chain tags")
    add_passphrase(sp)
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("tamper", help="simulate an attack on a bundle (for demonstration)")
    sp.add_argument("case_dir")
    sp.add_argument("--mode", choices=("modify", "delete", "insert", "recompute", "bitflip", "unindex"), default="modify")
    sp.add_argument("--index", type=int, required=True, help="target frame number (byte offset for bitflip)")
    sp.add_argument("--field", default="dst_port", help="field to change for modify/recompute")
    sp.add_argument("--value", default="4444")
    add_passphrase(sp)
    sp.set_defaults(func=cmd_tamper)

    sp = sub.add_parser("detect", help="M4: run port-scan detection on a capture or bundle")
    sp.add_argument("source", help=".pcap file or case bundle directory")
    sp.add_argument("--labels", help="ground-truth JSON to compute precision / recall")
    sp.add_argument("--backend", choices=("auto", "builtin", "pyshark"), default="auto")
    add_passphrase(sp)
    add_detection(sp)
    sp.set_defaults(func=cmd_detect)

    sp = sub.add_parser("query", help="search an encrypted bundle via its blind index (searchable encryption)")
    sp.add_argument("case_dir")
    sp.add_argument("--src")
    sp.add_argument("--dst")
    sp.add_argument("--host", help="match either source or destination IP")
    sp.add_argument("--port", type=int)
    sp.add_argument("--proto")
    sp.add_argument("--flags", help='exact TCP flag set, e.g. "SYN" or "SYN,ACK"')
    sp.add_argument("--limit", type=int, default=25)
    sp.add_argument("--pubkey", help="investigator public key: check the signature anchoring the index digest")
    sp.add_argument("--show-tokens", action="store_true", help="print the trapdoor tokens the store receives")
    sp.add_argument("--full-decrypt", action="store_true", help="ignore the index; decrypt the whole container")
    add_passphrase(sp)
    sp.set_defaults(func=cmd_query)

    sp = sub.add_parser("export", help="export a bundle's packets to XML")
    sp.add_argument("case_dir")
    sp.add_argument("--output", required=True)
    add_passphrase(sp)
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("bench", help="M7: benchmark AES modes, hashes and RSA vs ECC")
    sp.add_argument("source", help=".pcap file or case bundle directory")
    sp.add_argument("--out-dir", default="results")
    sp.add_argument("--volumes", default="1000,5000,10000,25000,50000")
    add_passphrase(sp)
    sp.set_defaults(func=cmd_bench)

    sp = sub.add_parser("ui", help="web dashboard: capture, Nmap, seal/verify, metrics, security, NMAC")
    sp.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1; keep it local)")
    sp.add_argument("--port", type=int, default=8765)
    sp.add_argument("--workspace", default="workspace", help="captures, cases and keys live here")
    sp.add_argument("--no-browser", action="store_true")
    sp.set_defaults(func=cmd_ui)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc.filename}: file not found", file=sys.stderr)
    except Exception as exc:  # surface domain errors as one clean line
        if os.environ.get("PACKETVAULT_DEBUG"):
            raise
        print(f"error: {exc}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

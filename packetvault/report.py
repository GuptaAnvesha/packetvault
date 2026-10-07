"""M5 - Case report generation.

``report.json`` is the signed artefact: it carries the acquisition metadata,
the hash-chain root and checkpoints, the SHA-256 of the encrypted container,
traffic statistics and detection results. ``report.txt`` (and ``report.pdf``
when ReportLab is installed) are human-readable renderings of the same data.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Sequence

from .models import PacketRecord

REPORT_FORMAT = "packetvault-report/1"


def traffic_statistics(records: Sequence[PacketRecord], top_n: int = 5) -> dict:
    if not records:
        return {"packets": 0}
    protocols = Counter(r.protocol for r in records)
    talkers = Counter(r.src_ip for r in records if r.src_ip)
    pairs = Counter(f"{r.src_ip} -> {r.dst_ip}" for r in records if r.src_ip and r.dst_ip)
    dst_ports = Counter(r.dst_port for r in records if r.dst_port is not None)
    first, last = records[0].ts_float, records[-1].ts_float
    return {
        "packets": len(records),
        "bytes": sum(r.frame_len for r in records),
        "first_timestamp": records[0].timestamp,
        "last_timestamp": records[-1].timestamp,
        "duration_seconds": round(last - first, 6),
        "unique_hosts": len({ip for r in records for ip in (r.src_ip, r.dst_ip) if ip}),
        "protocols": dict(sorted(protocols.items())),
        "top_talkers": [{"ip": ip, "packets": n} for ip, n in talkers.most_common(top_n)],
        "top_conversations": [{"pair": p, "packets": n} for p, n in pairs.most_common(top_n)],
        "top_destination_ports": [{"port": p, "packets": n} for p, n in dst_ports.most_common(top_n)],
    }


def serialise(report: dict) -> bytes:
    """Deterministic bytes that get signed (and written as report.json)."""
    return (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def render_text(report: dict) -> str:
    case, acq, integ = report["case"], report["acquisition"], report["integrity"]
    cont, stats, det = report["evidence_container"], report["statistics"], report["detection"]
    lines = [
        "=" * 72,
        "PACKETVAULT FORENSIC CASE REPORT".center(72),
        "=" * 72,
        f"Case ID         : {case['case_id']}",
        f"Investigator    : {case['investigator']}",
        f"Sealed at (UTC) : {case['sealed_at']}",
        f"Tool            : PacketVault {case['tool_version']}",
        "",
        "-- Acquisition " + "-" * 57,
        f"Source capture  : {acq['source_file']} ({acq['source_size']} bytes)",
        f"Capture SHA-256 : {acq['source_sha256']}",
        f"Parser backend  : {acq['parser_backend']}",
        f"Records         : {acq['record_count']}",
        "",
        "-- Integrity (SHA-256 hash chain) " + "-" * 38,
        f"H0 (genesis)    : {integ['h0']}",
        f"Root hash (H_N) : {integ['root_hash']}",
        f"Checkpoints     : {len(integ['checkpoints'])} (every {integ['checkpoint_interval']} records)",
        "",
        "-- Confidentiality " + "-" * 53,
        f"Container       : {cont['file']} ({cont['size']} bytes)",
        f"Cipher / KDF    : {cont['cipher']} / {cont['kdf']} x{cont['kdf_iterations']}",
        f"Container SHA256: {cont['sha256']}",
        "",
        "-- Traffic statistics " + "-" * 50,
        f"Packets / bytes : {stats.get('packets', 0)} / {stats.get('bytes', 0)}",
        f"Time span       : {stats.get('first_timestamp')} -> {stats.get('last_timestamp')}"
        f" ({stats.get('duration_seconds', 0)} s)",
        f"Unique hosts    : {stats.get('unique_hosts', 0)}",
        "Protocols       : " + ", ".join(f"{k}={v}" for k, v in stats.get("protocols", {}).items()),
        "Top talkers     : " + ", ".join(f"{t['ip']} ({t['packets']})" for t in stats.get("top_talkers", [])),
        "",
        "-- Port-scan detection " + "-" * 49,
        f"Rule            : >{det['config']['port_threshold']} distinct dst ports in "
        f"{det['config']['window_seconds']} s window; SYN:SYN-ACK >= {det['config']['min_syn_ratio']} => HIGH",
    ]
    if det["alerts"]:
        for a in det["alerts"]:
            lines.append(
                f"  [{a['severity']:<6}] {a['src_ip']:<16} {a['max_ports_in_window']:>4} ports/window, "
                f"{a['distinct_ports_total']:>4} total, SYN:SYN-ACK {a['syn_sent']}:{a['synack_received']}"
                f" -> {', '.join(a['targets'])}"
            )
    else:
        lines.append("  no scanning activity detected")
    lines += [
        "",
        "-- Signature " + "-" * 59,
        f"Algorithm       : {report['signer']['algorithm']}",
        f"Key fingerprint : {report['signer']['public_key_fingerprint']}",
        "Detached signature over report.json is in report.sig.",
        "Verify with: packetvault verify <bundle> --pubkey <investigator_public.pem>",
        "=" * 72,
    ]
    return "\n".join(lines) + "\n"


def render_pdf(report: dict, out_path: str | Path) -> bool:
    """Render the report as PDF with ReportLab. Returns False if ReportLab is missing."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        return False
    pdf = canvas.Canvas(str(out_path), pagesize=A4)
    width, height = A4
    y = height - 40
    pdf.setFont("Courier", 7.5)
    for line in render_text(report).splitlines():
        if y < 40:
            pdf.showPage()
            pdf.setFont("Courier", 7.5)
            y = height - 40
        pdf.drawString(30, y, line)
        y -= 10
    pdf.save()
    return True

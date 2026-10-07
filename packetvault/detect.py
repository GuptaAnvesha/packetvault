"""M4 - Detection Module (port-scan heuristic).

Primary rule
    A source host is flagged when, inside any sliding window of
    ``window_seconds``, it sends connection-initiating probes to more than
    ``port_threshold`` distinct destination ports.

    "Probes" are TCP segments with SYN set and ACK clear, plus UDP datagrams
    from an ephemeral source port. Responses (SYN/ACK, server-side UDP
    replies) are excluded, so a busy server answering many clients on many
    ephemeral ports is not mistaken for a scanner.

Corroborating signal
    SYN-to-SYN/ACK ratio: SYNs sent by the host divided by SYN/ACKs it
    received. A legitimate client completes most handshakes (ratio ~ 1); a
    scanner hitting mostly-closed ports gets RSTs instead (ratio >> 1).
    Alerts with both signals are rated HIGH, otherwise MEDIUM.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass
from typing import Iterable, Sequence

from .models import PacketRecord

EPHEMERAL_PORT_MIN = 1024


@dataclass(frozen=True)
class DetectionConfig:
    window_seconds: float = 10.0
    port_threshold: int = 15
    min_syn_ratio: float = 3.0


@dataclass
class HostStats:
    src_ip: str
    probes: int
    distinct_ports_total: int
    max_ports_in_window: int
    window_start: float | None
    syn_sent: int
    synack_received: int
    targets: list[str]

    @property
    def syn_ratio(self) -> float:
        return self.syn_sent / max(self.synack_received, 1)


@dataclass
class ScanAlert:
    src_ip: str
    severity: str  # HIGH / MEDIUM
    max_ports_in_window: int
    distinct_ports_total: int
    syn_sent: int
    synack_received: int
    syn_ratio: float
    window_start: str | None
    targets: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _is_probe(rec: PacketRecord) -> bool:
    if rec.dst_port is None:
        return False
    if rec.protocol == "TCP":
        return rec.has_flag("SYN") and not rec.has_flag("ACK")
    if rec.protocol == "UDP":
        return (rec.src_port or 0) >= EPHEMERAL_PORT_MIN
    return False


def _max_distinct_in_window(probes: Sequence[tuple[float, int]], window: float) -> tuple[int, float | None]:
    """Two-pointer sweep: max distinct ports seen in any window of length ``window``."""
    counts: Counter[int] = Counter()
    q: deque[tuple[float, int]] = deque()
    best, best_start = 0, None
    for ts, port in probes:
        q.append((ts, port))
        counts[port] += 1
        while q and ts - q[0][0] > window:
            _, old = q.popleft()
            counts[old] -= 1
            if not counts[old]:
                del counts[old]
        if len(counts) > best:
            best, best_start = len(counts), q[0][0]
    return best, best_start


def host_statistics(records: Iterable[PacketRecord], config: DetectionConfig = DetectionConfig()) -> dict[str, HostStats]:
    probes: dict[str, list[tuple[float, int]]] = defaultdict(list)
    targets: dict[str, set[str]] = defaultdict(set)
    syn_sent: Counter[str] = Counter()
    synack_recv: Counter[str] = Counter()

    for rec in records:
        if not rec.src_ip:
            continue
        if rec.protocol == "TCP" and rec.has_flag("SYN"):
            if rec.has_flag("ACK"):
                if rec.dst_ip:
                    synack_recv[rec.dst_ip] += 1
            else:
                syn_sent[rec.src_ip] += 1
        if _is_probe(rec):
            probes[rec.src_ip].append((rec.ts_float, rec.dst_port))
            if rec.dst_ip:
                targets[rec.src_ip].add(rec.dst_ip)

    stats = {}
    for src, items in probes.items():
        items.sort()
        best, start = _max_distinct_in_window(items, config.window_seconds)
        stats[src] = HostStats(
            src_ip=src,
            probes=len(items),
            distinct_ports_total=len({p for _, p in items}),
            max_ports_in_window=best,
            window_start=start,
            syn_sent=syn_sent[src],
            synack_received=synack_recv[src],
            targets=sorted(targets[src]),
        )
    return stats


def detect_port_scans(records: Sequence[PacketRecord], config: DetectionConfig = DetectionConfig()) -> list[ScanAlert]:
    alerts = []
    for src, st in sorted(host_statistics(records, config).items()):
        if st.max_ports_in_window <= config.port_threshold:
            continue
        severity = "HIGH" if st.syn_ratio >= config.min_syn_ratio else "MEDIUM"
        alerts.append(ScanAlert(
            src_ip=src,
            severity=severity,
            max_ports_in_window=st.max_ports_in_window,
            distinct_ports_total=st.distinct_ports_total,
            syn_sent=st.syn_sent,
            synack_received=st.synack_received,
            syn_ratio=round(st.syn_ratio, 2),
            window_start=f"{st.window_start:.6f}" if st.window_start is not None else None,
            targets=st.targets,
        ))
    alerts.sort(key=lambda a: (a.severity != "HIGH", -a.max_ports_in_window))
    return alerts


def evaluate(alerts: Sequence[ScanAlert], scanners: Iterable[str], all_hosts: Iterable[str]) -> dict:
    """Host-level confusion matrix against ground-truth labels."""
    flagged = {a.src_ip for a in alerts}
    scanners = set(scanners)
    hosts = set(all_hosts) | scanners | flagged
    tp = len(flagged & scanners)
    fp = len(flagged - scanners)
    fn = len(scanners - flagged)
    tn = len(hosts - flagged - scanners)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positives": tp, "false_positives": fp, "false_negatives": fn, "true_negatives": tn,
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "accuracy": round((tp + tn) / len(hosts), 4) if hosts else 1.0,
        "missed": sorted(scanners - flagged), "false_alarms": sorted(flagged - scanners),
    }

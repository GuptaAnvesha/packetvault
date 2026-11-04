"""External tool integration: Nmap (scanning) and Wireshark (dumpcap / tshark / GUI).

Nmap runs as a TCP connect scan by default (no admin rights needed); a SYN
scan (-sS) needs Administrator / root and Npcap. When nmap is not installed,
a built-in threaded TCP connect scanner is used, so the scan still generates
real traffic that can be captured.

Scan targets are limited to loopback and private (RFC 1918) addresses unless
explicitly allowed: scan only machines you own or are authorised to test,
e.g. the isolated VirtualBox host-only lab from the synopsis.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]{1,253}$")
_IFACE_RE = re.compile(r"^[\w\\{}\-.: ]{1,200}$")
_BPF_RE = re.compile(r"^[\w\s.:/()!&|<>=\-]{0,200}$")
_SEARCH_DIRS = {
    "nmap": [r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"],
    "wireshark": [r"C:\Program Files\Wireshark", r"C:\Program Files (x86)\Wireshark"],
}
MAX_PORTS = 5000
SCAN_TYPES = {"connect": "-sT", "syn": "-sS"}


class ToolError(ValueError):
    pass


def find(tool: str) -> str | None:
    found = shutil.which(tool)
    if found:
        return found
    group = "nmap" if tool == "nmap" else "wireshark"
    for d in _SEARCH_DIRS[group]:
        p = os.path.join(d, tool + ".exe")
        if os.path.exists(p):
            return p
    return None


def available() -> dict:
    tools = {name: find(name) for name in ("nmap", "tshark", "dumpcap", "wireshark")}
    try:
        import pyshark  # noqa: F401
        tools["pyshark"] = True
    except ImportError:
        tools["pyshark"] = False
    return tools


# --------------------------------------------------------------------------- nmap

def parse_ports(spec: str) -> int:
    spec = spec.replace(" ", "")
    if not _PORTS_RE.match(spec):
        raise ToolError("ports must look like 22,80,1-1024")
    total = 0
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        lo_i, hi_i = int(lo), int(hi or lo)
        if not 1 <= lo_i <= hi_i <= 65535:
            raise ToolError(f"invalid port range {part}")
        total += hi_i - lo_i + 1
    if total > MAX_PORTS:
        raise ToolError(f"at most {MAX_PORTS} ports per scan")
    return total


def expand_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.replace(" ", "").split(","):
        lo, _, hi = part.partition("-")
        ports.update(range(int(lo), int(hi or lo) + 1))
    return sorted(ports)


def resolve_target(target: str, allow_public: bool = False) -> str:
    target = target.strip()
    if not _HOST_RE.match(target) or target.startswith("-"):
        raise ToolError("invalid target")
    try:
        ip = socket.getaddrinfo(target, None, socket.AF_INET)[0][4][0]
    except socket.gaierror:
        raise ToolError(f"cannot resolve {target}") from None
    addr = ipaddress.ip_address(ip)
    if not allow_public and not (addr.is_loopback or addr.is_private):
        raise ToolError(f"{ip} is a public address; only loopback/private lab targets are allowed")
    return ip


def local_ip_towards(ip: str) -> str:
    """The source address this machine uses to reach ``ip`` (the scanner's address in a capture)."""
    if ipaddress.ip_address(ip).is_loopback:
        return "127.0.0.1"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((ip, 9))
        return s.getsockname()[0]


def nmap_scan(target: str, ports: str, scan_type: str = "connect", service_detection: bool = False,
              timing: int = 4, use_nmap: bool = True, allow_public: bool = False) -> dict:
    ip = resolve_target(target, allow_public)
    count = parse_ports(ports)
    ports = ports.replace(" ", "")
    timing = max(0, min(int(timing), 5))
    exe = find("nmap") if use_nmap else None
    start = time.perf_counter()
    if exe:
        if scan_type not in SCAN_TYPES:
            raise ToolError("scan type must be connect or syn")
        cmd = [exe, SCAN_TYPES[scan_type], "-Pn", "-n", f"-T{timing}", "--reason", "-p", ports]
        if service_detection:
            cmd += ["-sV", "--version-light"]
        cmd += ["-oX", "-", ip]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if proc.returncode != 0 or not proc.stdout.strip():
            raise ToolError(f"nmap failed: {(proc.stderr or proc.stdout).strip()[:400]}")
        result = _parse_nmap_xml(proc.stdout)
        result.update(engine="nmap", command=" ".join(cmd))
    else:
        result = _builtin_scan(ip, expand_ports(ports), timing)
    result.update(target=target, ip=ip, scanner_ip=local_ip_towards(ip), ports_scanned=count,
                  elapsed_s=round(time.perf_counter() - start, 2))
    return result


def _parse_nmap_xml(xml: str) -> dict:
    root = ET.fromstring(xml)
    ports, states = [], {}
    for port in root.iter("port"):
        state = port.find("state")
        st = state.get("state") if state is not None else "unknown"
        states[st] = states.get(st, 0) + 1
        if st != "open":
            continue
        svc = port.find("service")
        ports.append({
            "port": int(port.get("portid")), "proto": port.get("protocol"),
            "service": svc.get("name", "") if svc is not None else "",
            "product": " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else "",
            "reason": state.get("reason", ""),
        })
    for extra in root.iter("extraports"):
        states[extra.get("state")] = states.get(extra.get("state"), 0) + int(extra.get("count", 0))
    return {"open": ports, "states": states, "nmap_version": root.get("version", "")}


def _builtin_scan(ip: str, ports: list[int], timing: int) -> dict:
    timeout = {0: 2.0, 1: 1.5, 2: 1.0, 3: 0.6, 4: 0.4, 5: 0.25}[timing]
    workers = {0: 1, 1: 2, 2: 8, 3: 64, 4: 128, 5: 256}[timing]

    def probe(port: int):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                pass
        except OSError:
            return None
        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = ""
        return {"port": port, "proto": "tcp", "service": service, "product": "", "reason": "syn-ack"}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        found = [r for r in pool.map(probe, ports) if r]
    return {"engine": "builtin", "command": f"built-in TCP connect scan of {len(ports)} ports on {ip} (T{timing})",
            "open": found, "states": {"open": len(found), "closed|filtered": len(ports) - len(found)},
            "nmap_version": ""}


# --------------------------------------------------------------------------- wireshark

def interfaces() -> list[dict]:
    exe = find("dumpcap") or find("tshark")
    if not exe:
        return []
    try:
        out = subprocess.run([exe, "-D"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    result = []
    for line in out.splitlines():
        m = re.match(r"^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line.strip())
        if m:
            result.append({"index": m.group(1), "name": m.group(2), "description": m.group(3) or m.group(2)})
    return result


class LiveCapture:
    """One dumpcap/tshark capture at a time, written as classic PCAP."""

    def __init__(self, captures_dir: Path):
        self.dir = captures_dir
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self.current: dict | None = None

    def start(self, interface: str, bpf: str = "", seconds: int = 60, name: str | None = None) -> dict:
        exe = find("dumpcap") or find("tshark")
        if not exe:
            raise ToolError("Wireshark's dumpcap/tshark not found; install Wireshark with Npcap")
        if not interface or not _IFACE_RE.match(interface):
            raise ToolError("choose a capture interface")
        if not _BPF_RE.match(bpf or ""):
            raise ToolError("capture filter contains unsupported characters")
        seconds = max(2, min(int(seconds), 3600))
        with self._lock:
            if self._proc and self._proc.poll() is None:
                raise ToolError("a capture is already running")
            name = name or f"live-{time.strftime('%Y%m%d-%H%M%S')}.pcap"
            path = self.dir / name
            cmd = [exe, "-i", interface, "-a", f"duration:{seconds}", "-F", "pcap", "-w", str(path)]
            if bpf:
                cmd[3:3] = ["-f", bpf]
            if Path(exe).stem.lower() == "dumpcap":
                cmd.insert(1, "-q")
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            self.current = {"file": name, "command": " ".join(cmd), "started": time.time(), "seconds": seconds,
                            "running": True, "error": None}
            return dict(self.current)

    def stop(self) -> dict | None:
        with self._lock:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            return self._status_locked()

    def status(self) -> dict | None:
        with self._lock:
            return self._status_locked()

    def _status_locked(self) -> dict | None:
        cur = self.current
        if cur and cur["running"] and self._proc and self._proc.poll() is not None:
            cur["running"] = False
            err = (self._proc.stderr.read() or "").strip() if self._proc.stderr else ""
            if self._proc.returncode not in (0, None) and not (self.dir / cur["file"]).exists():
                cur["error"] = err[-400:] or f"exit code {self._proc.returncode}"
        if cur and (self.dir / cur["file"]).exists():
            cur["bytes"] = (self.dir / cur["file"]).stat().st_size
        return dict(cur) if cur else None


def open_in_wireshark(path: Path) -> str:
    exe = find("wireshark")
    if not exe:
        raise ToolError("Wireshark is not installed")
    subprocess.Popen([exe, "-r", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return f"{exe} -r {path}"

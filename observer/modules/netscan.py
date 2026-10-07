"""Network/port scanning. Wraps nmap (if installed) for host discovery and
service/version detection. Always scoped to a single authorized target.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Callable

from ..models import Finding, Severity

MODULE_NAME = "netscan"
LogFn = Callable[[str], None]


def _noop(_: str) -> None:
    pass


RISKY_PORTS = {
    21: "FTP (often anonymous/cleartext)",
    23: "Telnet (cleartext)",
    445: "SMB (frequent lateral-movement target)",
    3389: "RDP (common brute-force target)",
    6379: "Redis (often unauthenticated)",
    9200: "Elasticsearch (often unauthenticated)",
    27017: "MongoDB (often unauthenticated)",
}


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def port_scan(target: str, ports: str = "1-1024", log: LogFn = _noop, timeout: int = 180) -> list[Finding]:
    if not _nmap_available():
        return [Finding(
            target=target, module=MODULE_NAME, severity=Severity.INFO,
            title="nmap not installed",
            detail="Install nmap to enable port/service scanning (e.g. apt install nmap).",
        )]

    log(f"Running nmap -Pn -T4 -sV -p {ports} {target} ...")
    try:
        proc = subprocess.run(
            ["nmap", "-Pn", "-T4", "-sV", "-p", ports, "-oX", "-", target],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return [Finding(target=target, module=MODULE_NAME, severity=Severity.INFO,
                         title="Scan timed out", detail=f"nmap did not finish within {timeout}s")]

    if proc.returncode != 0:
        return [Finding(target=target, module=MODULE_NAME, severity=Severity.INFO,
                         title="nmap failed", detail=proc.stderr[:2000])]

    findings: list[Finding] = []
    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        return [Finding(target=target, module=MODULE_NAME, severity=Severity.INFO,
                         title="Could not parse nmap output", detail=proc.stdout[:2000])]

    open_count = 0
    for host in root.findall("host"):
        for port_el in host.findall("ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            open_count += 1
            portid = int(port_el.get("portid"))
            proto = port_el.get("protocol")
            service_el = port_el.find("service")
            service = service_el.get("name") if service_el is not None else "unknown"
            product = (service_el.get("product", "") if service_el is not None else "")
            version = (service_el.get("version", "") if service_el is not None else "")
            banner = f"{service} {product} {version}".strip()

            sev = Severity.MEDIUM if portid in RISKY_PORTS else Severity.INFO
            note = f" — {RISKY_PORTS[portid]}" if portid in RISKY_PORTS else ""
            findings.append(Finding(
                target=target, module=MODULE_NAME, severity=sev,
                title=f"Open port {portid}/{proto} ({banner}){note}",
                detail=f"Port {portid}/{proto} is open, service: {banner or 'unknown'}",
            ))

    log(f"Scan complete: {open_count} open ports.")
    if open_count == 0:
        findings.append(Finding(target=target, module=MODULE_NAME, severity=Severity.INFO,
                                 title="No open ports found in range " + ports, detail=""))
    return findings


def run(target: str, log: LogFn = _noop) -> list[Finding]:
    return port_scan(target, log=log)

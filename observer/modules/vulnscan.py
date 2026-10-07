"""Vulnerability scanning: wraps nmap's NSE 'vuln' script category.

This is noisier/heavier than a plain port scan and must only ever be run
against a target that is explicitly in scope and whose owner/program
permits active vulnerability scanning.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Callable

from ..models import Finding, Severity

MODULE_NAME = "vulnscan"
LogFn = Callable[[str], None]


def _noop(_: str) -> None:
    pass


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


VULN_BLOCK_RE = re.compile(r"\|\s*([\w\-/.]+):\s*\n(.*?)(?=\n\S|\Z)", re.S)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def run(target: str, log: LogFn = _noop, timeout: int = 600) -> list[Finding]:
    if not _nmap_available():
        return [Finding(
            target=target, module=MODULE_NAME, severity=Severity.INFO,
            title="nmap not installed",
            detail="Install nmap (with NSE scripts) to enable vulnerability scanning.",
        )]

    log(f"Running nmap -Pn -sV --script vuln {target} (this can take a while) ...")
    try:
        proc = subprocess.run(
            ["nmap", "-Pn", "-sV", "--script", "vuln", target],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return [Finding(target=target, module=MODULE_NAME, severity=Severity.INFO,
                         title="Vuln scan timed out", detail=f"Did not finish within {timeout}s")]

    output = proc.stdout
    findings: list[Finding] = []

    if "VULNERABLE" in output:
        for match in re.finditer(r"^\|\s+(.+VULNERABLE.*)$", output, re.M):
            line = match.group(1).strip()
            cves = CVE_RE.findall(output[max(0, match.start() - 400):match.end() + 400])
            title = "Potential vulnerability flagged by nmap NSE"
            if cves:
                title += f" ({', '.join(sorted(set(cves)))})"
            findings.append(Finding(
                target=target, module=MODULE_NAME, severity=Severity.HIGH,
                title=title,
                detail=line,
            ))
    else:
        findings.append(Finding(
            target=target, module=MODULE_NAME, severity=Severity.INFO,
            title="No NSE 'vuln' script findings",
            detail="nmap's vuln script category did not flag anything on open ports.",
        ))

    log(f"Vuln scan complete: {len(findings)} findings.")
    return findings

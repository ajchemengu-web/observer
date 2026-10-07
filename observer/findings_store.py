"""Durable findings log — a JSON-lines file under OBSERVER_HOME so the
dashboard and history survive restarts, independent of the per-run
markdown/JSON reports in ./reports/.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, Severity
from .scope import OBSERVER_HOME

FINDINGS_FILE = OBSERVER_HOME / "findings.jsonl"


def append(findings: list[Finding], path: Path = FINDINGS_FILE) -> None:
    if not findings:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        for f in findings:
            fh.write(json.dumps(f.to_dict()) + "\n")


def load_all(path: Path = FINDINGS_FILE) -> list[Finding]:
    if not path.exists():
        return []
    findings = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            findings.append(Finding(
                target=d["target"], module=d["module"],
                severity=Severity(d["severity"]), title=d["title"],
                detail=d.get("detail", ""), timestamp=d.get("timestamp", ""),
            ))
        except (json.JSONDecodeError, KeyError, ValueError):
            continue
    return findings


def clear(path: Path = FINDINGS_FILE) -> None:
    if path.exists():
        path.unlink()

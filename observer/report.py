from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def _slug(target: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in target).strip("_")


def save_report(target: str, findings: list[Finding]) -> tuple[Path, Path]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"{_slug(target)}_{ts}"

    json_path = REPORTS_DIR / f"{base}.json"
    json_path.write_text(json.dumps([f.to_dict() for f in findings], indent=2))

    md_path = REPORTS_DIR / f"{base}.md"
    lines = [f"# Observer report — {target}", "", f"Generated: {ts}", ""]
    by_sev = sorted(findings, key=lambda f: -f.severity.rank)
    for f in by_sev:
        lines += [
            f"## [{f.severity.value.upper()}] {f.title}",
            f"- module: `{f.module}`",
            f"- target: `{f.target}`",
            f"- time: {f.timestamp}",
            "",
            f.detail or "_no further detail_",
            "",
        ]
    md_path.write_text("\n".join(lines))
    return json_path, md_path


def list_reports() -> list[Path]:
    if not REPORTS_DIR.exists():
        return []
    return sorted(REPORTS_DIR.glob("*.md"), reverse=True)

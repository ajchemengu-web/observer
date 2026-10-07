"""Scope management.

Nothing in this tool's active modules (recon, web checks, network/vuln
scanning) is allowed to run against a target unless it matches an entry
the user has explicitly punched into scope. This is the core safety rail
that keeps the tool pointed only at authorized targets (your own assets,
or assets covered by a bug bounty program's published scope).
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

OBSERVER_HOME = Path(os.environ.get("OBSERVER_HOME", Path.home() / ".observer"))
SCOPE_FILE = OBSERVER_HOME / "scope.json"


@dataclass
class ScopeEntry:
    value: str          # domain, IP, or CIDR, as entered
    note: str = ""       # e.g. "HackerOne program XYZ", "my homelab"
    kind: str = field(default="")  # "domain" | "ip" | "cidr"

    def __post_init__(self):
        if not self.kind:
            self.kind = _classify(self.value)


def _classify(value: str) -> str:
    try:
        ipaddress.ip_network(value, strict=False)
        return "cidr" if "/" in value else "ip"
    except ValueError:
        return "domain"


def _normalize_target(raw: str) -> str:
    """Pull a bare host/IP out of a URL or host:port string."""
    raw = raw.strip()
    if "://" in raw:
        host = urlparse(raw).hostname or raw
    else:
        host = raw.split("/")[0].split(":")[0]
    return host.lower().lstrip(".")


class ScopeManager:
    def __init__(self, path: Path = SCOPE_FILE):
        self.path = path
        self.entries: list[ScopeEntry] = []
        self._load()

    def _load(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text())
                self.entries = [ScopeEntry(**e) for e in raw]
            except (json.JSONDecodeError, TypeError):
                self.entries = []

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([e.__dict__ for e in self.entries], indent=2))

    def add(self, value: str, note: str = "") -> ScopeEntry:
        value = value.strip().lower()
        entry = ScopeEntry(value=value, note=note)
        if not any(e.value == entry.value for e in self.entries):
            self.entries.append(entry)
            self._save()
        return entry

    def remove(self, value: str) -> bool:
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.value != value.strip().lower()]
        changed = len(self.entries) != before
        if changed:
            self._save()
        return changed

    def list(self) -> list[ScopeEntry]:
        return list(self.entries)

    def import_file(self, path: str, note: str = "") -> tuple[int, list[str]]:
        """Import one target per line from a plain-text scope file (as many
        bug bounty programs publish). Blank lines and lines starting with
        '#' are ignored. Returns (count_added, lines_skipped)."""
        p = Path(path).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"Scope file not found: {p}")

        added = 0
        skipped: list[str] = []
        for raw_line in p.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            value = _normalize_target(line) if "://" in line else line.lower()
            if _classify(value) == "domain" and any(c in value for c in " \t"):
                skipped.append(raw_line)
                continue
            before = len(self.entries)
            self.add(value, note or f"imported from {p.name}")
            if len(self.entries) > before:
                added += 1
        return added, skipped

    def is_in_scope(self, raw_target: str) -> bool:
        host = _normalize_target(raw_target)
        for entry in self.entries:
            if entry.kind == "domain":
                if host == entry.value or host.endswith("." + entry.value):
                    return True
            elif entry.kind == "ip":
                if host == entry.value:
                    return True
            elif entry.kind == "cidr":
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(entry.value, strict=False):
                        return True
                except ValueError:
                    continue
        return False


class OutOfScopeError(Exception):
    pass


def require_in_scope(scope: ScopeManager, target: str) -> None:
    if not scope.is_in_scope(target):
        raise OutOfScopeError(
            f"'{target}' is not in scope. Add it first (Scope screen) before "
            f"running active checks against it."
        )

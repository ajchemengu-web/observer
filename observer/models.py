from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "cyan",
            Severity.LOW: "green",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "orange",
            Severity.CRITICAL: "red",
        }[self]


@dataclass
class Finding:
    target: str
    module: str
    severity: Severity
    title: str
    detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "module": self.module,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }

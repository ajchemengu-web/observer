"""Cross-module correlation and risk-scoring engine.

The other modules (recon, webcheck, netscan, vulnscan, monitor) each
produce independent Findings. This engine's job is the actual research
contribution: fusing those independent signals into a single, auditable
per-asset risk score, where co-occurring findings across modules can
compound risk beyond what summing severities alone would show (e.g. a
reachable, typically-unauthenticated database plus a large undocumented
subdomain surface is worse than either fact alone).

Design goals (see docs/methodology.md for the full write-up):
  1. Deterministic and pure: score_target() is a function of a list of
     Findings, nothing else — reproducible, unit-testable.
  2. Auditable: every point on the final score traces back to either a
     documented severity weight or a named, rationale-carrying rule in
     correlation_rules.py. No opaque ML black box.
  3. Volume-dampened: ten INFO findings from one chatty module should
     not outweigh one CRITICAL finding from another. See
     `_module_contribution` for the dampening formula.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from .correlation_rules import CorrelationRule, RULES
from .models import Finding, Severity

# --- severity weights -------------------------------------------------
# A documented, original mapping (not a reproduction of CVSS) expressing
# the intuition that risk grows super-linearly with severity band.
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.INFO: 0.5,
    Severity.LOW: 2.0,
    Severity.MEDIUM: 5.0,
    Severity.HIGH: 9.0,
    Severity.CRITICAL: 15.0,
}

# Per-module decay: the single worst finding in a module counts at full
# weight; each additional finding (in descending severity order) counts
# at a geometrically shrinking fraction. This is what makes a lone
# finding of any severity score at exactly its own weight (no artificial
# amplification of small/clean results) while still dampening a flood of
# redundant same-module findings. See docs/methodology.md for why a
# single concave curve pinned at one anchor point cannot have both
# properties, which is why decay-weighting (not sqrt-scaling) is used.
MODULE_DECAY = 0.5

# Saturating-curve constant for mapping raw scores onto a 0-100 scale.
# Calibrated (see tests/test_correlate.py) so that a synthetic
# "clearly compromised" asset lands at or above the CRITICAL threshold,
# while a clean/INFO-only asset stays well within LOW.
SATURATION_K = 14.0

RISK_TIERS: list[tuple[float, str]] = [
    (80.0, "CRITICAL"),
    (55.0, "HIGH"),
    (25.0, "MEDIUM"),
    (0.0, "LOW"),
]

SUBDOMAIN_COUNT_RE = re.compile(r"(\d+)\s+subdomains discovered")


def _module_contribution(findings: list[Finding]) -> float:
    """Decay-weighted contribution of one module's findings to the raw score.

    The findings are sorted by severity weight, descending; the worst one
    counts fully, and each subsequent one counts at MODULE_DECAY**i of
    its own weight. A module with exactly one finding therefore always
    contributes precisely that finding's own weight — a single INFO
    finding stays worth 0.5, a single CRITICAL stays worth 15 — so a
    quiet/clean target is never inflated just because several modules
    each reported one harmless INFO finding. A module reporting many
    findings of the same severity sees strongly sublinear growth, since
    each additional one is worth half as much (then a quarter, etc.) as
    the last — this is what keeps one chatty module's finding *count*
    from dominating a score that is meant to reflect *risk*.
    """
    if not findings:
        return 0.0
    weights = sorted((SEVERITY_WEIGHTS[f.severity] for f in findings), reverse=True)
    return sum(w * (MODULE_DECAY ** i) for i, w in enumerate(weights))


def _normalize(raw_score: float) -> float:
    """Map an unbounded raw score onto 0-100 via a saturating curve."""
    return 100.0 * (1.0 - math.exp(-raw_score / SATURATION_K))


def _tier_for(score_0_100: float) -> str:
    for threshold, tier in RISK_TIERS:
        if score_0_100 >= threshold:
            return tier
    return "LOW"


@dataclass
class TargetFindings:
    """Convenience view over one target's findings, used by rule predicates."""

    target: str
    findings: list[Finding]

    def module(self, name: str) -> list[Finding]:
        return [f for f in self.findings if f.module == name]

    def has_title_containing(self, module: str, *needles: str) -> bool:
        needles_lower = [n.lower() for n in needles]
        for f in self.module(module):
            title_lower = f.title.lower()
            if any(n in title_lower for n in needles_lower):
                return True
        return False

    def has_cve(self, module: str | None = None) -> bool:
        pool = self.module(module) if module else self.findings
        return any("CVE-" in f.title for f in pool)

    def min_severity_at_least(self, module: str, sev: Severity) -> bool:
        return any(f.severity.rank >= sev.rank for f in self.module(module))

    def subdomain_count(self) -> int | None:
        for f in self.module("recon"):
            m = SUBDOMAIN_COUNT_RE.search(f.title)
            if m:
                return int(m.group(1))
        return None

    def has_open_port(self, *port_or_terms: str) -> bool:
        return self.has_title_containing("netscan", *port_or_terms)


@dataclass
class TriggeredRule:
    rule_id: str
    name: str
    weight: float
    rationale: str


@dataclass
class RiskReport:
    target: str
    raw_score: float
    score: float  # 0-100
    tier: str
    module_breakdown: dict[str, float] = field(default_factory=dict)
    triggered_rules: list[TriggeredRule] = field(default_factory=list)
    finding_count: int = 0

    def summary_line(self) -> str:
        rules = ", ".join(r.name for r in self.triggered_rules) or "none"
        return f"{self.target}: {self.score:.1f}/100 [{self.tier}] (correlations: {rules})"


def score_target(target: str, findings: list[Finding], all_findings: list[Finding] | None = None) -> RiskReport:
    """Compute a RiskReport for one target.

    `all_findings` (defaults to `findings`) is passed to rule predicates
    that need global context — e.g. correlating a passive Network
    Monitor alert (which has no domain target) against a specific
    asset's independent findings.
    """
    all_findings = all_findings if all_findings is not None else findings
    tf = TargetFindings(target=target, findings=findings)

    modules = sorted({f.module for f in findings})
    module_breakdown = {m: round(_module_contribution(tf.module(m)), 2) for m in modules}
    base = sum(module_breakdown.values())

    triggered: list[TriggeredRule] = []
    for rule in RULES:
        try:
            if rule.predicate(tf, all_findings):
                triggered.append(TriggeredRule(
                    rule_id=rule.id, name=rule.name, weight=rule.weight, rationale=rule.rationale,
                ))
        except Exception:
            # A malformed/overly-specific predicate must never crash scoring.
            continue

    correlation_bonus = sum(r.weight for r in triggered)
    raw = base + correlation_bonus
    score = _normalize(raw)

    return RiskReport(
        target=target,
        raw_score=round(raw, 2),
        score=round(score, 2),
        tier=_tier_for(score),
        module_breakdown=module_breakdown,
        triggered_rules=triggered,
        finding_count=len(findings),
    )


def score_all(findings: list[Finding]) -> list[RiskReport]:
    """Group findings by target and score each, ranked highest-risk first."""
    by_target: dict[str, list[Finding]] = {}
    for f in findings:
        by_target.setdefault(f.target, []).append(f)

    reports = [score_target(t, fs, all_findings=findings) for t, fs in by_target.items()]
    reports.sort(key=lambda r: r.score, reverse=True)
    return reports

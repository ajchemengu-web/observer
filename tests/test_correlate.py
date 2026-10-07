"""Unit tests for the correlation/risk-scoring engine.

These are written as a synthetic ground-truth benchmark: each test states
up front what a human analyst would conclude about a hand-constructed
scenario, then asserts the engine reaches the same conclusion. This is
the evaluation methodology referenced in docs/methodology.md — a thesis
reviewer should be able to read this file as the spec for "does the
scoring behave the way we claim it does."
"""

import math

from observer.correlate import (
    MODULE_DECAY,
    SEVERITY_WEIGHTS,
    TargetFindings,
    _module_contribution,
    _normalize,
    _tier_for,
    score_all,
    score_target,
)
from observer.correlation_rules import RULES
from observer.models import Finding, Severity


def mk(target, module, severity, title, detail=""):
    return Finding(target=target, module=module, severity=severity, title=title, detail=detail)


# --- core formula properties -------------------------------------------

def test_single_critical_finding_is_not_dampened():
    """A lone CRITICAL finding should contribute exactly its own weight —
    dampening only applies to *redundant* findings within a module."""
    findings = [mk("a.com", "vulnscan", Severity.CRITICAL, "CVE-2024-0001 remote code execution")]
    contribution = _module_contribution(findings)
    assert math.isclose(contribution, SEVERITY_WEIGHTS[Severity.CRITICAL], rel_tol=1e-9)


def test_lone_finding_of_any_severity_is_never_amplified():
    """A module with exactly one finding must contribute exactly that
    finding's own weight, whatever the severity — this is what keeps a
    clean/quiet target from being inflated by trivial INFO output."""
    for sev in Severity:
        findings = [mk("a.com", "recon", sev, "single finding")]
        assert math.isclose(_module_contribution(findings), SEVERITY_WEIGHTS[sev], rel_tol=1e-9)


def test_repeated_findings_in_one_module_are_dampened():
    """Ten LOW findings from one chatty module must contribute less than
    their naive linear sum — volume from a single source is weaker
    evidence than the same weight spread across independent modules."""
    findings = [mk("a.com", "netscan", Severity.LOW, f"Open port {p}") for p in range(10)]
    naive_sum = 10 * SEVERITY_WEIGHTS[Severity.LOW]
    contribution = _module_contribution(findings)
    assert contribution < naive_sum
    expected = sum(SEVERITY_WEIGHTS[Severity.LOW] * (MODULE_DECAY ** i) for i in range(10))
    assert math.isclose(contribution, expected, rel_tol=1e-9)


def test_clean_asset_with_only_info_findings_stays_low_regardless_of_module_count():
    """Scattering the same trivial INFO finding across many modules must
    not, by itself, escalate tier — this directly regression-tests the
    small-value-amplification failure mode of a naive sqrt(raw*anchor)
    dampening curve (any such curve lies above the identity line below
    its anchor point, which inflates exactly this scenario)."""
    findings = [mk("clean.com", m, Severity.INFO, "informational") for m in
                ["recon", "webcheck", "netscan", "vulnscan"]]
    report = score_target("clean.com", findings)
    assert report.tier == "LOW"


def test_normalize_is_monotonic_and_bounded():
    xs = [0, 5, 15, 30, 60, 120]
    ys = [_normalize(x) for x in xs]
    assert all(0.0 <= y < 100.0 for y in ys)
    assert ys == sorted(ys)  # monotonic non-decreasing


def test_tier_boundaries():
    assert _tier_for(0) == "LOW"
    assert _tier_for(24.9) == "LOW"
    assert _tier_for(25.0) == "MEDIUM"
    assert _tier_for(54.9) == "MEDIUM"
    assert _tier_for(55.0) == "HIGH"
    assert _tier_for(79.9) == "HIGH"
    assert _tier_for(80.0) == "CRITICAL"
    assert _tier_for(100.0) == "CRITICAL"


def test_scoring_is_deterministic():
    findings = [
        mk("a.com", "recon", Severity.INFO, "DNS records"),
        mk("a.com", "webcheck", Severity.MEDIUM, "Missing security header: Strict-Transport-Security"),
    ]
    r1 = score_target("a.com", findings)
    r2 = score_target("a.com", findings)
    assert r1 == r2


# --- clean asset ground truth -------------------------------------------

def test_clean_asset_scores_low_with_no_correlations():
    findings = [
        mk("clean.com", "recon", Severity.INFO, "DNS records"),
        mk("clean.com", "webcheck", Severity.INFO, "HTTP 200 response received"),
        mk("clean.com", "netscan", Severity.INFO, "Open port 443/tcp (https)"),
    ]
    report = score_target("clean.com", findings)
    assert report.tier == "LOW"
    assert report.triggered_rules == []


# --- each correlation rule: positive + negative control ------------------

def test_rule_exposed_datastore_plus_surface():
    positive = [
        mk("db.com", "netscan", Severity.MEDIUM, "Open port 6379/tcp (redis) — Redis (often unauthenticated)"),
        mk("db.com", "recon", Severity.INFO, "12 subdomains discovered via certificate transparency"),
    ]
    report = score_target("db.com", positive)
    assert "exposed-unauth-datastore-plus-surface" in {r.rule_id for r in report.triggered_rules}

    # negative control: same datastore exposure, but small/no subdomain surface
    negative = [
        mk("db2.com", "netscan", Severity.MEDIUM, "Open port 6379/tcp (redis) — Redis (often unauthenticated)"),
        mk("db2.com", "recon", Severity.INFO, "2 subdomains discovered via certificate transparency"),
    ]
    report2 = score_target("db2.com", negative)
    assert "exposed-unauth-datastore-plus-surface" not in {r.rule_id for r in report2.triggered_rules}


def test_rule_weak_transport_stack():
    positive = [
        mk("t.com", "webcheck", Severity.MEDIUM, "Missing security header: Strict-Transport-Security"),
        mk("t.com", "webcheck", Severity.HIGH, "Outdated TLS protocol negotiated: TLSv1.1"),
    ]
    assert "weak-transport-stack" in {r.rule_id for r in score_target("t.com", positive).triggered_rules}

    # negative control: only one of the two transport weaknesses present
    negative = [mk("t2.com", "webcheck", Severity.MEDIUM, "Missing security header: Strict-Transport-Security")]
    assert "weak-transport-stack" not in {r.rule_id for r in score_target("t2.com", negative).triggered_rules}


def test_rule_legacy_service_known_cve():
    positive = [
        mk("v.com", "vulnscan", Severity.HIGH, "Potential vulnerability flagged by nmap NSE (CVE-2021-41773)"),
        mk("v.com", "netscan", Severity.MEDIUM, "Open port 80/tcp (http) — FTP (often anonymous/cleartext)"),
    ]
    assert "legacy-service-known-cve" in {r.rule_id for r in score_target("v.com", positive).triggered_rules}

    negative = [mk("v2.com", "vulnscan", Severity.HIGH, "Potential vulnerability flagged by nmap NSE (CVE-2021-41773)")]
    assert "legacy-service-known-cve" not in {r.rule_id for r in score_target("v2.com", negative).triggered_rules}


def test_rule_spoofable_mail_surface():
    positive = [
        mk("m.com", "recon", Severity.LOW, "No SPF record found"),
        mk("m.com", "netscan", Severity.INFO, "Open port 25/tcp (smtp)"),
    ]
    assert "spoofable-mail-surface" in {r.rule_id for r in score_target("m.com", positive).triggered_rules}

    negative = [mk("m2.com", "recon", Severity.LOW, "No SPF record found")]
    assert "spoofable-mail-surface" not in {r.rule_id for r in score_target("m2.com", negative).triggered_rules}


def test_rule_unmonitored_shadow_surface():
    positive = [mk("s.com", "recon", Severity.INFO, "40 subdomains discovered via certificate transparency")]
    assert "unmonitored-shadow-surface" in {r.rule_id for r in score_target("s.com", positive).triggered_rules}

    # negative control: same subdomain count, but other modules DID run
    negative = [
        mk("s2.com", "recon", Severity.INFO, "40 subdomains discovered via certificate transparency"),
        mk("s2.com", "webcheck", Severity.INFO, "HTTP 200 response received"),
    ]
    assert "unmonitored-shadow-surface" not in {r.rule_id for r in score_target("s2.com", negative).triggered_rules}


def test_rule_active_recon_plus_known_weakness():
    target_findings = [mk("p.com", "vulnscan", Severity.HIGH, "Potential vulnerability (CVE-2024-9999)")]
    global_with_scan = target_findings + [
        mk("eth0", "monitor", Severity.HIGH, "Possible port scan from 10.0.0.5"),
    ]
    report = score_target("p.com", target_findings, all_findings=global_with_scan)
    assert "active-recon-plus-known-weakness" in {r.rule_id for r in report.triggered_rules}

    # negative control: no global scan alert present
    report2 = score_target("p.com", target_findings, all_findings=target_findings)
    assert "active-recon-plus-known-weakness" not in {r.rule_id for r in report2.triggered_rules}


# --- composite "clearly compromised" synthetic asset ---------------------

def test_compromised_asset_reaches_critical_tier():
    """A synthetic asset combining several independently-plausible
    findings that security practitioners would agree compound into a
    severe overall posture. This is the benchmark scenario referenced
    in docs/methodology.md as the SATURATION_K calibration target."""
    findings = [
        mk("bad.com", "netscan", Severity.MEDIUM, "Open port 6379/tcp (redis) — Redis (often unauthenticated)"),
        mk("bad.com", "recon", Severity.INFO, "20 subdomains discovered via certificate transparency"),
        mk("bad.com", "webcheck", Severity.MEDIUM, "Missing security header: Strict-Transport-Security"),
        mk("bad.com", "webcheck", Severity.HIGH, "Outdated TLS protocol negotiated: TLSv1.0"),
        mk("bad.com", "vulnscan", Severity.HIGH, "Potential vulnerability flagged by nmap NSE (CVE-2023-1234)"),
    ]
    global_findings = findings + [mk("eth0", "monitor", Severity.HIGH, "Possible port scan from 203.0.113.9")]

    report = score_target("bad.com", findings, all_findings=global_findings)

    triggered_ids = {r.rule_id for r in report.triggered_rules}
    assert "exposed-unauth-datastore-plus-surface" in triggered_ids
    assert "weak-transport-stack" in triggered_ids
    assert "legacy-service-known-cve" in triggered_ids
    assert "active-recon-plus-known-weakness" in triggered_ids
    assert report.tier == "CRITICAL"
    assert report.score >= 80.0


# --- score_all grouping/ranking -------------------------------------------

def test_score_all_groups_and_ranks_by_target():
    findings = [
        mk("quiet.com", "recon", Severity.INFO, "DNS records"),
        mk("loud.com", "vulnscan", Severity.CRITICAL, "CVE-2024-5555 remote code execution"),
        mk("loud.com", "netscan", Severity.HIGH, "Open port 445/tcp (smb)"),
    ]
    reports = score_all(findings)
    assert [r.target for r in reports] == ["loud.com", "quiet.com"]
    assert reports[0].score > reports[1].score


def test_rule_catalog_has_unique_ids_and_rationale():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids)), "rule ids must be unique"
    for r in RULES:
        assert r.weight > 0
        assert len(r.rationale) > 20, f"rule {r.id} needs a real rationale, not a stub"

"""The correlation rule catalog.

Each rule expresses a compound-risk hypothesis: a specific combination of
findings, possibly from different modules, that together indicate higher
risk than the sum of their individual severities would suggest. Rules are
intentionally declarative (id, predicate, weight, rationale) so the whole
catalog can be read, reviewed, and cited as a unit — this file doubles as
the appendix of a methodology write-up.

Adding a rule: a predicate takes (TargetFindings, all_findings) and
returns bool. Keep predicates narrow and explainable; prefer several
specific rules over one broad one, since each triggered rule's rationale
is shown to the analyst (and would be shown to a thesis evaluator).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, TYPE_CHECKING

from .models import Finding, Severity

if TYPE_CHECKING:
    from .correlate import TargetFindings

Predicate = Callable[["TargetFindings", list[Finding]], bool]


@dataclass(frozen=True)
class CorrelationRule:
    id: str
    name: str
    weight: float
    rationale: str
    predicate: Predicate


def _exposed_unauth_datastore_plus_surface(tf: "TargetFindings", _all: list[Finding]) -> bool:
    has_exposed_store = tf.has_open_port("redis", "mongodb", "elasticsearch", "often unauthenticated")
    n = tf.subdomain_count()
    return has_exposed_store and n is not None and n >= 10


def _weak_transport_stack(tf: "TargetFindings", _all: list[Finding]) -> bool:
    missing_hsts = tf.has_title_containing("webcheck", "missing security header: strict-transport-security")
    weak_tls = tf.has_title_containing("webcheck", "outdated tls protocol", "certificate expires")
    return missing_hsts and weak_tls


def _legacy_service_known_cve(tf: "TargetFindings", _all: list[Finding]) -> bool:
    return tf.has_cve("vulnscan") and tf.min_severity_at_least("netscan", Severity.MEDIUM)


def _spoofable_mail_surface(tf: "TargetFindings", _all: list[Finding]) -> bool:
    no_spf = tf.has_title_containing("recon", "no spf record found")
    mail_port_open = tf.has_open_port("25/tcp")
    return no_spf and mail_port_open


def _unmonitored_shadow_surface(tf: "TargetFindings", _all: list[Finding]) -> bool:
    n = tf.subdomain_count()
    has_other_active_checks = bool(tf.module("webcheck") or tf.module("netscan") or tf.module("vulnscan"))
    return n is not None and n >= 15 and not has_other_active_checks


def _active_recon_plus_known_weakness(tf: "TargetFindings", all_findings: list[Finding]) -> bool:
    global_scan_alert = any(
        f.module == "monitor" and "possible port scan" in f.title.lower()
        for f in all_findings
    )
    target_has_high_plus = any(f.severity.rank >= Severity.HIGH.rank for f in tf.findings)
    return global_scan_alert and target_has_high_plus


RULES: list[CorrelationRule] = [
    CorrelationRule(
        id="exposed-unauth-datastore-plus-surface",
        name="Exposed data store + large attack surface",
        weight=10.0,
        rationale=(
            "An internet-reachable, typically-unauthenticated data store "
            "(Redis/MongoDB/Elasticsearch) combined with a large discovered "
            "subdomain surface compounds exposure: a single misconfigured "
            "host becomes a high-value pivot point across a wide, likely "
            "unevenly-maintained perimeter."
        ),
        predicate=_exposed_unauth_datastore_plus_surface,
    ),
    CorrelationRule(
        id="weak-transport-stack",
        name="Systemic weak transport security",
        weight=6.0,
        rationale=(
            "Missing HSTS together with either an outdated TLS protocol or "
            "a certificate at/near expiry indicates neglect of the transport "
            "security stack as a whole, not an isolated oversight — raising "
            "confidence that other transport hardening is also absent."
        ),
        predicate=_weak_transport_stack,
    ),
    CorrelationRule(
        id="legacy-service-known-cve",
        name="Versioned service with a matching known vulnerability",
        weight=9.0,
        rationale=(
            "A banner-identified open service together with an NSE "
            "vulnerability-script hit on the same host indicates a specific, "
            "plausibly exploitable known weakness rather than a generic, "
            "unconfirmed exposure."
        ),
        predicate=_legacy_service_known_cve,
    ),
    CorrelationRule(
        id="spoofable-mail-surface",
        name="Missing SPF with a reachable mail port",
        weight=5.0,
        rationale=(
            "No SPF record combined with a reachable mail-submission port "
            "raises the likelihood that this domain can be impersonated in "
            "phishing sent to its own users or partners."
        ),
        predicate=_spoofable_mail_surface,
    ),
    CorrelationRule(
        id="unmonitored-shadow-surface",
        name="Large subdomain surface with no active checks performed",
        weight=7.0,
        rationale=(
            "A large number of discovered subdomains with zero corresponding "
            "web or network checks indicates likely unmonitored shadow "
            "infrastructure — a common initial-access vector precisely "
            "because it falls outside routine scanning."
        ),
        predicate=_unmonitored_shadow_surface,
    ),
    CorrelationRule(
        id="active-recon-plus-known-weakness",
        name="Active external probing coincides with a known weakness",
        weight=8.0,
        rationale=(
            "The passive Network Monitor independently observed port-scan-"
            "like traffic while this asset already carries a HIGH or "
            "CRITICAL finding — suggesting the exposure may already be "
            "under active reconnaissance, raising urgency beyond the "
            "finding's severity alone."
        ),
        predicate=_active_recon_plus_known_weakness,
    ),
]

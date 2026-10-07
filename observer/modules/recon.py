"""Passive/OSINT recon: certificate-transparency subdomain enumeration,
DNS records, and whois — all information already public about a domain.
"""

from __future__ import annotations

import json
from typing import Callable

import requests

from ..models import Finding, Severity

MODULE_NAME = "recon"
LogFn = Callable[[str], None]


def _noop(_: str) -> None:
    pass


def enumerate_subdomains(domain: str, log: LogFn = _noop, timeout: int = 20) -> list[str]:
    log(f"Querying crt.sh for certificates issued to *.{domain} ...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "the-observer/0.1"})
        resp.raise_for_status()
        rows = json.loads(resp.text)
    except Exception as exc:  # crt.sh is flaky; degrade gracefully
        log(f"crt.sh lookup failed: {exc}")
        return []

    names = set()
    for row in rows:
        for name in str(row.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and domain in name:
                names.add(name)
    log(f"Found {len(names)} unique subdomains.")
    return sorted(names)


def dns_lookup(domain: str, log: LogFn = _noop) -> dict[str, list[str]]:
    import dns.resolver

    records: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = sorted(str(r).strip() for r in answers)
        except Exception:
            records[rtype] = []
    log("DNS lookup complete.")
    return records


def whois_lookup(domain: str, log: LogFn = _noop) -> str:
    try:
        import whois  # python-whois

        w = whois.whois(domain)
        return str(w)
    except Exception as exc:
        log(f"whois lookup unavailable: {exc}")
        return ""


def run(target: str, log: LogFn = _noop) -> list[Finding]:
    findings: list[Finding] = []

    subs = enumerate_subdomains(target, log)
    if subs:
        preview = ", ".join(subs[:25]) + (" ..." if len(subs) > 25 else "")
        findings.append(Finding(
            target=target, module=MODULE_NAME, severity=Severity.INFO,
            title=f"{len(subs)} subdomains discovered via certificate transparency",
            detail=preview,
        ))

    records = dns_lookup(target, log)
    non_empty = {k: v for k, v in records.items() if v}
    findings.append(Finding(
        target=target, module=MODULE_NAME, severity=Severity.INFO,
        title="DNS records",
        detail="\n".join(f"{k}: {', '.join(v)}" for k, v in non_empty.items()) or "no records resolved",
    ))

    spf_txt = [t for t in records.get("TXT", []) if "spf" in t.lower()]
    if not spf_txt:
        findings.append(Finding(
            target=target, module=MODULE_NAME, severity=Severity.LOW,
            title="No SPF record found",
            detail="No TXT record containing an SPF policy was found; this can make email spoofing easier.",
        ))

    whois_text = whois_lookup(target, log)
    if whois_text:
        findings.append(Finding(
            target=target, module=MODULE_NAME, severity=Severity.INFO,
            title="Whois record retrieved",
            detail=whois_text[:2000],
        ))

    return findings

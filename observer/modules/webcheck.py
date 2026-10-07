"""Non-intrusive web application checks: security headers, TLS posture,
cookie flags, and banner disclosure. All GET requests, nothing destructive.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Callable

import requests

from ..models import Finding, Severity

MODULE_NAME = "webcheck"
LogFn = Callable[[str], None]


def _noop(_: str) -> None:
    pass


SECURITY_HEADERS = {
    "Strict-Transport-Security": Severity.MEDIUM,
    "Content-Security-Policy": Severity.MEDIUM,
    "X-Content-Type-Options": Severity.LOW,
    "X-Frame-Options": Severity.LOW,
    "Referrer-Policy": Severity.LOW,
    "Permissions-Policy": Severity.LOW,
}


def check_headers(url: str, log: LogFn = _noop, timeout: int = 15) -> list[Finding]:
    findings: list[Finding] = []
    if "://" not in url:
        url = "https://" + url
    try:
        log(f"GET {url}")
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "the-observer/0.1"})
    except requests.RequestException as exc:
        return [Finding(target=url, module=MODULE_NAME, severity=Severity.INFO,
                         title="Request failed", detail=str(exc))]

    headers = {k: v for k, v in resp.headers.items()}
    findings.append(Finding(
        target=url, module=MODULE_NAME, severity=Severity.INFO,
        title=f"HTTP {resp.status_code} response received",
        detail="\n".join(f"{k}: {v}" for k, v in headers.items()),
    ))

    for name, sev in SECURITY_HEADERS.items():
        if name not in headers:
            findings.append(Finding(
                target=url, module=MODULE_NAME, severity=sev,
                title=f"Missing security header: {name}",
                detail="Response did not include this header.",
            ))

    server = headers.get("Server") or headers.get("X-Powered-By")
    if server:
        findings.append(Finding(
            target=url, module=MODULE_NAME, severity=Severity.LOW,
            title="Server/tech banner disclosed",
            detail=f"Server identifies itself as: {server}",
        ))

    for cookie in resp.cookies:
        flags = []
        if not cookie.secure:
            flags.append("missing Secure")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            flags.append("missing HttpOnly")
        if flags:
            findings.append(Finding(
                target=url, module=MODULE_NAME, severity=Severity.MEDIUM,
                title=f"Cookie '{cookie.name}' missing flags",
                detail=", ".join(flags),
            ))

    log(f"Header check complete: {len(findings)} findings.")
    return findings


def check_tls(host: str, port: int = 443, log: LogFn = _noop) -> list[Finding]:
    findings: list[Finding] = []
    host = host.split("://")[-1].split("/")[0].split(":")[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
        not_after = cert.get("notAfter")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days
            sev = Severity.INFO if days_left > 30 else (Severity.MEDIUM if days_left > 0 else Severity.HIGH)
            findings.append(Finding(
                target=host, module=MODULE_NAME, severity=sev,
                title=f"TLS certificate expires in {days_left} days",
                detail=f"Expiry: {not_after}, protocol: {proto}",
            ))
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append(Finding(
                target=host, module=MODULE_NAME, severity=Severity.HIGH,
                title=f"Outdated TLS protocol negotiated: {proto}",
                detail="Server should disable legacy TLS/SSL versions.",
            ))
        log("TLS check complete.")
    except Exception as exc:
        findings.append(Finding(
            target=host, module=MODULE_NAME, severity=Severity.INFO,
            title="TLS check failed", detail=str(exc),
        ))
    return findings


def run(target: str, log: LogFn = _noop) -> list[Finding]:
    findings = check_headers(target, log)
    findings += check_tls(target, log=log)
    return findings

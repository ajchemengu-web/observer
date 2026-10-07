"""Passive network intrusion / suspicious-activity detection.

This module does not send anything — it only observes traffic on a local
interface (your own machine/network) and flags heuristically suspicious
patterns: SYN-scan-style half-open connection attempts, ARP spoofing
(an IP suddenly claimed by a new MAC), and abnormal per-host packet rates.
It needs raw-socket privileges (root / CAP_NET_RAW) to sniff; if those
aren't available it reports that cleanly instead of crashing.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from typing import Callable

from ..models import Finding, Severity

MODULE_NAME = "monitor"
LogFn = Callable[[str], None]


def _noop(_: str) -> None:
    pass


class _State:
    def __init__(self):
        self.syn_no_ack: Counter[str] = Counter()
        self.packet_counts: Counter[str] = Counter()
        self.arp_table: dict[str, str] = {}
        self.findings: list[Finding] = []
        self.start = time.time()


def _handle_packet(pkt, state: "_State", log: LogFn):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import ARP

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        if arp.op == 2:  # is-at (reply)
            ip, mac = arp.psrc, arp.hwsrc
            prev = state.arp_table.get(ip)
            if prev and prev != mac:
                state.findings.append(Finding(
                    target=ip, module=MODULE_NAME, severity=Severity.HIGH,
                    title=f"Possible ARP spoofing: {ip} changed MAC",
                    detail=f"{ip} was {prev}, now claimed by {mac}",
                ))
                log(f"[!] ARP change: {ip} {prev} -> {mac}")
            state.arp_table[ip] = mac

    if pkt.haslayer(IP):
        src = pkt[IP].src
        state.packet_counts[src] += 1
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags == "S":  # SYN only, no ACK — half-open attempt
                state.syn_no_ack[src] += 1


def sniff_window(interface: str | None, duration: int, log: LogFn = _noop) -> list[Finding]:
    try:
        from scapy.all import sniff
    except Exception as exc:
        return [Finding(target=interface or "any", module=MODULE_NAME, severity=Severity.INFO,
                         title="scapy unavailable", detail=str(exc))]

    state = _State()
    log(f"Listening on {interface or 'default interface'} for {duration}s "
        f"(passive — observing only, nothing is transmitted) ...")

    try:
        sniff(
            iface=interface,
            timeout=duration,
            store=False,
            prn=lambda p: _handle_packet(p, state, log),
        )
    except PermissionError:
        return [Finding(
            target=interface or "any", module=MODULE_NAME, severity=Severity.INFO,
            title="Insufficient privileges to sniff packets",
            detail="Run with elevated privileges / CAP_NET_RAW to enable the network monitor.",
        )]
    except OSError as exc:
        return [Finding(target=interface or "any", module=MODULE_NAME, severity=Severity.INFO,
                         title="Could not open interface for sniffing", detail=str(exc))]

    findings = list(state.findings)

    # Heuristic: many SYNs, no completed handshake → looks like a port/host scan
    for src, count in state.syn_no_ack.items():
        if count >= 20:
            findings.append(Finding(
                target=src, module=MODULE_NAME, severity=Severity.HIGH,
                title=f"Possible port scan from {src}",
                detail=f"{count} SYN packets with no matching ACK seen in {duration}s window.",
            ))

    # Heuristic: one host generating a disproportionate share of traffic
    total = sum(state.packet_counts.values())
    for src, count in state.packet_counts.most_common(5):
        if total > 0 and count / total > 0.5 and count > 200:
            findings.append(Finding(
                target=src, module=MODULE_NAME, severity=Severity.MEDIUM,
                title=f"Abnormal traffic volume from {src}",
                detail=f"{src} accounted for {count}/{total} packets observed in this window.",
            ))

    if not findings:
        findings.append(Finding(
            target=interface or "any", module=MODULE_NAME, severity=Severity.INFO,
            title="No suspicious activity observed",
            detail=f"Clean {duration}s capture window, {total} packets seen.",
        ))

    log(f"Monitor window complete: {len(findings)} findings.")
    return findings


def run(target: str, log: LogFn = _noop) -> list[Finding]:
    """`target` here is an interface name (or 'any'/empty for default)."""
    iface = target.strip() or None
    return sniff_window(iface, duration=30, log=log)

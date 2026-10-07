# The Observer

A local, scope-gated security auditing console for authorized security
research and bug bounty work. Runs as a terminal UI (TUI) — fast,
keyboard-driven, no server, no accounts, everything stays on your machine.

> **Authorized use only.** Every active module (Recon, Web App Checks,
> Network Scan, Vulnerability Scan) refuses to run against a target that
> hasn't been explicitly added on the **Scope** screen. Only test assets
> you own or that a program's published scope covers you to test.

## Features

- **Scope manager** — the allowlist every active module is gated on (domains, IPs, CIDRs).
- **Recon / OSINT** — certificate-transparency subdomain enumeration, DNS records, whois. All passive/public-data lookups.
- **Web App Checks** — missing security headers, cookie flags, banner disclosure, TLS protocol/expiry.
- **Network Scan** — nmap-backed port/service discovery (requires `nmap` on PATH).
- **Vulnerability Scan** — nmap's NSE `vuln` script category, parsed into findings (requires `nmap`).
- **Network Monitor** — *passive* packet observation on a local interface: flags SYN-scan-style probing, ARP spoofing, and abnormal traffic volume. Needs root/`CAP_NET_RAW` to sniff; otherwise reports that cleanly instead of crashing. Not scope-gated since it only watches your own interface.
- **Reports** — every run is saved to `reports/<target>_<timestamp>.{md,json}`.

## Install

```bash
cd the-observer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

`nmap` is optional but required for Network Scan / Vulnerability Scan:

```bash
sudo apt install nmap   # Debian/Ubuntu
brew install nmap       # macOS
```

## Run

```bash
./launch.sh       # opens The Observer in its own terminal window, if one is available
# or
python3 -m observer   # run in the current terminal
```

## Data locations

- Scope list: `~/.observer/scope.json` (override with `OBSERVER_HOME`)
- Reports: `./reports/`

## Design notes

- Nothing talks to any third-party service except: the target itself (for
  Web Checks / Network Scan / Vuln Scan, once it's in scope) and
  `crt.sh` (for public certificate-transparency subdomain lookups).
- The Network Monitor never transmits — it only listens.

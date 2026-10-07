from __future__ import annotations

import threading
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label, Log, Static,
)

from ..models import Finding, Severity
from ..report import save_report, list_reports
from ..scope import ScopeManager, OutOfScopeError, require_in_scope
from ..modules import recon, webcheck, netscan, vulnscan, monitor

CSS_PATH = Path(__file__).with_name("observer.tcss")

MODULES = {
    "recon": (recon, "Recon / OSINT", False),
    "webcheck": (webcheck, "Web App Checks", False),
    "netscan": (netscan, "Network Scan", False),
    "vulnscan": (vulnscan, "Vulnerability Scan", False),
    "monitor": (monitor, "Network Monitor (passive)", True),  # True = interface, not scope-gated target
}

NAV_ITEMS = [
    ("dashboard", "📊 Dashboard"),
    ("scope", "🎯 Scope"),
    ("recon", "🔍 Recon / OSINT"),
    ("webcheck", "🌐 Web App Checks"),
    ("netscan", "📡 Network Scan"),
    ("vulnscan", "🛡  Vulnerability Scan"),
    ("monitor", "👁  Network Monitor"),
    ("reports", "📁 Reports"),
]


class ObserverApp(App):
    CSS_PATH = str(CSS_PATH)
    TITLE = "THE OBSERVER"
    SUB_TITLE = "local security auditing console"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+c", "quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self.scope = ScopeManager()
        self.all_findings: list[Finding] = []
        self.current_view = "dashboard"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="app-grid"):
            with VerticalScroll(id="sidebar"):
                yield Label("THE OBSERVER", classes="nav-title")
                for key, label in NAV_ITEMS:
                    yield Button(label, id=f"nav-{key}", classes="nav")
            with VerticalScroll(id="content"):
                yield Static(id="content-body")
        yield Footer()

    def on_mount(self) -> None:
        self.show_view("dashboard")

    # ---------- navigation ----------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid.startswith("nav-"):
            self.show_view(bid.removeprefix("nav-"))
        elif bid.startswith("run-"):
            self.run_module(bid.removeprefix("run-"))
        elif bid == "scope-add":
            self.add_scope_entry()
        elif bid.startswith("scope-remove-"):
            value = bid.removeprefix("scope-remove-")
            self.scope.remove(value)
            self.show_view("scope")

    def show_view(self, view: str) -> None:
        self.current_view = view
        for key, _ in NAV_ITEMS:
            btn = self.query_one(f"#nav-{key}", Button)
            btn.set_class(key == view, "-active")

        content = self.query_one("#content", VerticalScroll)
        content.remove_children()

        if view == "dashboard":
            content.mount(self._build_dashboard())
        elif view == "scope":
            content.mount(self._build_scope())
        elif view in MODULES:
            content.mount(self._build_module_view(view))
        elif view == "reports":
            content.mount(self._build_reports())

    # ---------- dashboard ----------

    def _build_dashboard(self) -> Container:
        counts = {s: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity] += 1

        box = Vertical()
        box.compose_add_child(Static("Dashboard", classes="panel-title"))
        box.compose_add_child(Static(
            f"Scope: {len(self.scope.list())} target(s) authorized · "
            f"{len(self.all_findings)} finding(s) this session",
            classes="hint",
        ))

        stats = Horizontal(id="stats-row")
        for sev in Severity:
            stats.compose_add_child(Static(
                f"{sev.value.upper()}\n{counts[sev]}", classes=f"stat-box stat-{sev.value}"
            ))
        box.compose_add_child(stats)

        box.compose_add_child(Static(
            "Pick a module from the sidebar. Active modules (Recon, Web Checks, "
            "Network Scan, Vulnerability Scan) only run against targets you've "
            "added to Scope. The Network Monitor passively watches your own "
            "interface for suspicious traffic and needs no scope entry.",
            classes="hint",
        ))
        return box

    # ---------- scope ----------

    def _build_scope(self) -> Container:
        box = Vertical()
        box.compose_add_child(Static("Scope — authorized targets", classes="panel-title"))
        box.compose_add_child(Static(
            "Only domains/IPs/CIDRs added here can be targeted by active modules.",
            classes="hint",
        ))
        box.compose_add_child(Input(placeholder="domain, IP, or CIDR e.g. example.com", id="scope-value"))
        box.compose_add_child(Input(placeholder="note (optional) e.g. HackerOne program", id="scope-note"))
        box.compose_add_child(Button("Add to scope", id="scope-add", variant="primary"))

        table = DataTable(id="scope-table")
        table.add_columns("Target", "Type", "Note", "")
        for entry in self.scope.list():
            table.add_row(entry.value, entry.kind, entry.note, f"[remove]")
        box.compose_add_child(table)
        return box

    def add_scope_entry(self) -> None:
        value_input = self.query_one("#scope-value", Input)
        note_input = self.query_one("#scope-note", Input)
        if value_input.value.strip():
            self.scope.add(value_input.value, note_input.value)
            value_input.value = ""
            note_input.value = ""
        self.show_view("scope")

    # ---------- modules ----------

    def _build_module_view(self, key: str) -> Container:
        mod, label, is_interface = MODULES[key]
        box = Vertical()
        box.compose_add_child(Static(label, classes="panel-title"))

        if is_interface:
            box.compose_add_child(Static(
                "Passive mode: listens on a local interface for 30s and flags "
                "suspicious patterns (port-scan-like SYNs, ARP spoofing, abnormal "
                "traffic volume). Leave blank for the default interface. Needs "
                "root/CAP_NET_RAW to sniff.",
                classes="hint",
            ))
            box.compose_add_child(Input(placeholder="interface (optional, e.g. eth0)", id=f"{key}-target"))
        else:
            box.compose_add_child(Static(
                "Target must already be added in Scope.", classes="hint",
            ))
            box.compose_add_child(Input(placeholder="target, e.g. example.com", id=f"{key}-target"))

        box.compose_add_child(Button(f"Run {label}", id=f"run-{key}", variant="primary"))
        box.compose_add_child(Log(id=f"{key}-log", auto_scroll=True))

        table = DataTable(id=f"{key}-results")
        table.add_columns("Severity", "Title", "Detail")
        box.compose_add_child(table)
        return box

    def run_module(self, key: str) -> None:
        mod, label, is_interface = MODULES[key]
        target_input = self.query_one(f"#{key}-target", Input)
        target = target_input.value.strip()
        log_widget = self.query_one(f"#{key}-log", Log)
        table = self.query_one(f"#{key}-results", DataTable)
        table.clear()

        if not is_interface:
            try:
                require_in_scope(self.scope, target or "")
            except OutOfScopeError as exc:
                log_widget.write_line(f"[BLOCKED] {exc}")
                return

        log_widget.write_line(f"Starting {label} against '{target or 'default'}' ...")
        run_button = self.query_one(f"#run-{key}", Button)
        run_button.disabled = True

        def worker():
            def ui_log(msg: str) -> None:
                self.call_from_thread(log_widget.write_line, msg)

            try:
                findings = mod.run(target, log=ui_log)
            except Exception as exc:  # keep the app alive on module errors
                findings = [Finding(target=target or "?", module=key, severity=Severity.INFO,
                                     title="Module raised an exception", detail=str(exc))]

            def finish():
                for f in findings:
                    table.add_row(f.severity.value.upper(), f.title, (f.detail or "")[:200])
                self.all_findings.extend(findings)
                log_widget.write_line(f"Done: {len(findings)} finding(s).")
                if findings:
                    json_path, md_path = save_report(target or key, findings)
                    log_widget.write_line(f"Saved report: {md_path.name}")
                run_button.disabled = False

            self.call_from_thread(finish)

        threading.Thread(target=worker, daemon=True).start()

    # ---------- reports ----------

    def _build_reports(self) -> Container:
        box = Vertical()
        box.compose_add_child(Static("Saved reports", classes="panel-title"))
        reports = list_reports()
        if not reports:
            box.compose_add_child(Static("No reports yet — run a module first.", classes="hint"))
        else:
            table = DataTable()
            table.add_columns("File", "Path")
            for p in reports:
                table.add_row(p.name, str(p))
            box.compose_add_child(table)
        return box


def main() -> None:
    ObserverApp().run()


if __name__ == "__main__":
    main()

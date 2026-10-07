from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label, LoadingIndicator,
    Log, Markdown, Rule, Static,
)

from ..models import Finding, Severity
from ..report import save_report, list_reports
from ..scope import ScopeManager, OutOfScopeError, require_in_scope
from ..findings_store import append as store_append, load_all as store_load_all, clear as store_clear
from ..modules import recon, webcheck, netscan, vulnscan, monitor
from .widgets import SatelliteOrbit

CSS_PATH = Path(__file__).with_name("observer.tcss")

MODULES = {
    "recon": (recon, "Recon / OSINT", False),
    "webcheck": (webcheck, "Web App Checks", False),
    "netscan": (netscan, "Network Scan", False),
    "vulnscan": (vulnscan, "Vulnerability Scan", False),
    "monitor": (monitor, "Network Monitor (passive)", True),  # True = interface, not scope-gated target
}

ICONS = {
    "dashboard": "▣",
    "scope": "◎",
    "recon": "◇",
    "webcheck": "◈",
    "netscan": "▤",
    "vulnscan": "▲",
    "monitor": "◉",
    "reports": "▦",
}

NAV_LABELS = {
    "dashboard": "Dashboard",
    "scope": "Scope",
    "recon": "Recon / OSINT",
    "webcheck": "Web App Checks",
    "netscan": "Network Scan",
    "vulnscan": "Vuln Scan",
    "monitor": "Net Monitor",
    "reports": "Reports",
}

NAV_ORDER = ["dashboard", "scope", "recon", "webcheck", "netscan", "vulnscan", "monitor", "reports"]
NAV_ITEMS = [(k, f"{i + 1} {ICONS[k]} {NAV_LABELS[k]}") for i, k in enumerate(NAV_ORDER)]
NAV_KEYS = [key for key, _ in NAV_ITEMS]


class ObserverApp(App):
    CSS_PATH = str(CSS_PATH)
    TITLE = "THE OBSERVER"
    SUB_TITLE = "local security auditing console"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+c", "quit", "Quit"),
        ("1", "goto('dashboard')", "Dashboard"),
        ("2", "goto('scope')", "Scope"),
        ("3", "goto('recon')", "Recon"),
        ("4", "goto('webcheck')", "Web"),
        ("5", "goto('netscan')", "NetScan"),
        ("6", "goto('vulnscan')", "VulnScan"),
        ("7", "goto('monitor')", "Monitor"),
        ("8", "goto('reports')", "Reports"),
    ]

    def __init__(self):
        super().__init__()
        self.scope = ScopeManager()
        self.all_findings: list[Finding] = store_load_all()
        self.current_view = "dashboard"
        self._report_paths: list[Path] = []

    def action_goto(self, view: str) -> None:
        if view in NAV_KEYS or view in ("dashboard", "scope", "reports"):
            self.show_view(view)

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
            idx_str = bid.removeprefix("scope-remove-")
            entries = self.scope.list()
            if idx_str.isdigit() and int(idx_str) < len(entries):
                self.scope.remove(entries[int(idx_str)].value)
            self.show_view("scope")
        elif bid == "scope-import":
            self.import_scope_file()
        elif bid == "clear-history":
            self.all_findings = []
            store_clear()
            self.show_view("dashboard")

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

        top = Horizontal(id="dashboard-top")
        left = Vertical(id="dashboard-left")
        left.compose_add_child(Static(f"{ICONS['dashboard']} Dashboard", classes="panel-title"))
        left.compose_add_child(Static(
            f"Scope: {len(self.scope.list())} target(s) authorized · "
            f"{len(self.all_findings)} finding(s) this session",
            classes="hint",
        ))

        stats = Horizontal(id="stats-row")
        for sev in Severity:
            stats.compose_add_child(Static(
                f"{sev.value.upper()}\n{counts[sev]}", classes=f"stat-box stat-{sev.value}"
            ))
        left.compose_add_child(stats)

        left.compose_add_child(Static(
            "Pick a module from the sidebar (or press 1-8). Active modules "
            "(Recon, Web Checks, Network Scan, Vulnerability Scan) only run "
            "against targets you've added to Scope. The Network Monitor "
            "passively watches your own interface for suspicious traffic "
            "and needs no scope entry.",
            classes="hint",
        ))
        top.compose_add_child(left)

        orbit_panel = Vertical(id="orbit-panel")
        orbit_panel.compose_add_child(Static("UPLINK", classes="orbit-title"))
        orbit_panel.compose_add_child(SatelliteOrbit())
        top.compose_add_child(orbit_panel)

        box.compose_add_child(top)

        if self.all_findings:
            box.compose_add_child(Rule())
            recent = Vertical()
            recent.compose_add_child(Static("Recent findings (all time, persisted)", classes="panel-title"))
            table = DataTable(zebra_stripes=True)
            table.add_columns("Severity", "Module", "Target", "Title")
            for f in sorted(self.all_findings, key=lambda f: f.timestamp, reverse=True)[:30]:
                table.add_row(f.severity.value.upper(), f.module, f.target, f.title)
            recent.compose_add_child(table)
            recent.compose_add_child(Button("Clear history", id="clear-history"))
            box.compose_add_child(recent)
        return box

    # ---------- scope ----------

    def _build_scope(self) -> Container:
        box = Vertical()
        box.compose_add_child(Static(f"{ICONS['scope']} Scope — authorized targets", classes="panel-title"))

        form = Vertical(classes="card")
        form.compose_add_child(Static(
            "Only domains/IPs/CIDRs added here can be targeted by active modules.",
            classes="hint",
        ))
        form.compose_add_child(Input(placeholder="domain, IP, or CIDR e.g. example.com", id="scope-value"))
        form.compose_add_child(Input(placeholder="note (optional) e.g. HackerOne program", id="scope-note"))
        form.compose_add_child(Button("+ Add to scope", id="scope-add", variant="primary"))
        box.compose_add_child(form)

        import_form = Vertical(classes="card")
        import_form.compose_add_child(Static(
            "Or import a program's published scope file "
            "(one target per line, '#' comments allowed):",
            classes="hint",
        ))
        import_form.compose_add_child(Input(placeholder="/path/to/scope.txt", id="scope-import-path"))
        import_form.compose_add_child(Button("⤓ Import from file", id="scope-import"))
        import_form.compose_add_child(Static(id="scope-import-status", classes="hint"))
        box.compose_add_child(import_form)

        box.compose_add_child(Rule())

        entries = self.scope.list()
        list_panel = Vertical(classes="card")
        if not entries:
            list_panel.compose_add_child(Static(
                "No targets yet — add one above or import a scope file.", classes="hint",
            ))
        else:
            header = Horizontal(classes="scope-row scope-header")
            header.compose_add_child(Static("TARGET", classes="scope-col-target"))
            header.compose_add_child(Static("TYPE", classes="scope-col-type"))
            header.compose_add_child(Static("NOTE", classes="scope-col-note"))
            header.compose_add_child(Static("", classes="scope-col-action"))
            list_panel.compose_add_child(header)
            for idx, entry in enumerate(entries):
                row = Horizontal(classes="scope-row")
                row.compose_add_child(Static(entry.value, classes="scope-col-target"))
                row.compose_add_child(Static(entry.kind, classes="scope-col-type"))
                row.compose_add_child(Static(entry.note or "—", classes="scope-col-note"))
                row.compose_add_child(Button("✕", id=f"scope-remove-{idx}", classes="scope-remove-btn"))
                list_panel.compose_add_child(row)
        box.compose_add_child(list_panel)
        return box

    def add_scope_entry(self) -> None:
        value_input = self.query_one("#scope-value", Input)
        note_input = self.query_one("#scope-note", Input)
        if value_input.value.strip():
            self.scope.add(value_input.value, note_input.value)
            value_input.value = ""
            note_input.value = ""
        self.show_view("scope")

    def import_scope_file(self) -> None:
        path_input = self.query_one("#scope-import-path", Input)
        path = path_input.value.strip()
        if not path:
            return
        try:
            added, skipped = self.scope.import_file(path)
            msg = f"Imported {added} target(s)."
            if skipped:
                msg += f" Skipped {len(skipped)} unrecognized line(s)."
        except FileNotFoundError as exc:
            msg = str(exc)
        self.show_view("scope")
        self.query_one("#scope-import-status", Static).update(msg)

    # ---------- modules ----------

    def _build_module_view(self, key: str) -> Container:
        mod, label, is_interface = MODULES[key]
        box = Vertical()
        box.compose_add_child(Static(f"{ICONS[key]} {label}", classes="panel-title"))

        form = Vertical(classes="card")
        if is_interface:
            form.compose_add_child(Static(
                "Passive mode: listens on a local interface for 30s and flags "
                "suspicious patterns (port-scan-like SYNs, ARP spoofing, abnormal "
                "traffic volume). Leave blank for the default interface. Needs "
                "root/CAP_NET_RAW to sniff.",
                classes="hint",
            ))
            form.compose_add_child(Input(placeholder="interface (optional, e.g. eth0)", id=f"{key}-target"))
        else:
            form.compose_add_child(Static(
                "Target must already be added in Scope.", classes="hint",
            ))
            form.compose_add_child(Input(placeholder="target, e.g. example.com", id=f"{key}-target"))
        form.compose_add_child(Button(f"▶ Run {label}", id=f"run-{key}", variant="primary"))
        box.compose_add_child(form)

        loading = LoadingIndicator(id=f"{key}-loading")
        loading.display = False
        box.compose_add_child(loading)

        box.compose_add_child(Log(id=f"{key}-log", auto_scroll=True))

        table = DataTable(id=f"{key}-results", zebra_stripes=True)
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
        loading = self.query_one(f"#{key}-loading", LoadingIndicator)
        loading.display = True

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
                store_append(findings)
                log_widget.write_line(f"Done: {len(findings)} finding(s).")
                if findings:
                    json_path, md_path = save_report(target or key, findings)
                    log_widget.write_line(f"Saved report: {md_path.name}")
                run_button.disabled = False
                loading.display = False

            self.call_from_thread(finish)

        threading.Thread(target=worker, daemon=True).start()

    # ---------- reports ----------

    def _build_reports(self) -> Container:
        box = Vertical()
        box.compose_add_child(Static(f"{ICONS['reports']} Saved reports", classes="panel-title"))
        reports = list_reports()
        self._report_paths = reports
        if not reports:
            box.compose_add_child(Static("No reports yet — run a module first.", classes="hint"))
        else:
            box.compose_add_child(Static("Click a report to preview it below.", classes="hint"))
            table = DataTable(id="reports-table", cursor_type="row", zebra_stripes=True)
            table.add_columns("File", "Modified")
            for idx, p in enumerate(reports):
                try:
                    mtime = datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                except OSError:
                    mtime = "?"
                table.add_row(p.name, mtime, key=str(idx))
            box.compose_add_child(table)
            box.compose_add_child(Rule())
            box.compose_add_child(VerticalScroll(Markdown(id="report-preview"), classes="card", id="report-preview-panel"))
        return box

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "reports-table" or event.row_key.value is None:
            return
        idx = int(event.row_key.value)
        if idx >= len(self._report_paths):
            return
        path = self._report_paths[idx]
        try:
            content = path.read_text()
        except OSError as exc:
            content = f"Could not read `{path}`: {exc}"
        self.query_one("#report-preview", Markdown).update(content)


def main() -> None:
    ObserverApp().run()


if __name__ == "__main__":
    main()

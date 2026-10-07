#!/usr/bin/env python3
"""Run The Observer's active modules against the evaluation corpus's
live lab targets (see corpus/README.md to bring them up first) and save
raw findings + a correlated risk report per target.

Usage:
    python3 corpus/run_corpus.py                  # all targets in targets.yaml
    python3 corpus/run_corpus.py --target dvwa     # just one

This script still goes through scope enforcement (a dedicated
ScopeManager pointed at corpus/.corpus_scope.json, not your real
~/.observer scope) — the evaluation harness follows the same safety
rail as the interactive app, it just declares its scope from
targets.yaml instead of a human typing into the Scope screen.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from observer.correlate import score_target  # noqa: E402
from observer.modules import netscan, vulnscan, webcheck  # noqa: E402
from observer.scope import OutOfScopeError, ScopeManager, require_in_scope  # noqa: E402

CORPUS_DIR = Path(__file__).resolve().parent
RESULTS_DIR = CORPUS_DIR / "results"
SCOPE_FILE = CORPUS_DIR / ".corpus_scope.json"

MODULE_RUNNERS = {
    "webcheck": lambda target_conf, log: webcheck.run(target_conf["url"], log=log),
    "netscan": lambda target_conf, log: netscan.run(target_conf["host"], log=log),
    "vulnscan": lambda target_conf, log: vulnscan.run(target_conf["host"], log=log),
}


def load_targets(targets_file: Path) -> list[dict]:
    data = yaml.safe_load(targets_file.read_text())
    return data["targets"]


def run_target(target_conf: dict, scope: ScopeManager) -> dict:
    name = target_conf["name"]
    print(f"\n=== {name} ({target_conf['description']}) ===")

    for host in {target_conf["host"], target_conf["url"]}:
        scope.add(host, note=f"evaluation corpus target: {name}")

    try:
        require_in_scope(scope, target_conf["host"])
    except OutOfScopeError as exc:
        print(f"  [BLOCKED] {exc}")
        return {"target": name, "error": str(exc), "findings": []}

    all_findings = []
    for module_name in target_conf["run_modules"]:
        runner = MODULE_RUNNERS.get(module_name)
        if runner is None:
            print(f"  [skip] unknown module '{module_name}'")
            continue
        print(f"  running {module_name} ...")
        try:
            findings = runner(target_conf, lambda msg: print(f"    {msg}"))
        except Exception as exc:
            print(f"  [error] {module_name} raised: {exc}")
            findings = []
        for f in findings:
            print(f"    [{f.severity.value.upper()}] {f.title}")
        all_findings.extend(findings)

    report = score_target(name, all_findings, all_findings=all_findings)
    print(f"  --> risk score: {report.score}/100 [{report.tier}]")
    if report.triggered_rules:
        for r in report.triggered_rules:
            print(f"      correlation triggered: {r.name}")

    return {
        "target": name,
        "run_at": datetime.now(timezone.utc).isoformat(),
        "findings": [f.to_dict() for f in all_findings],
        "risk_report": {
            "score": report.score,
            "tier": report.tier,
            "raw_score": report.raw_score,
            "module_breakdown": report.module_breakdown,
            "triggered_rules": [r.rule_id for r in report.triggered_rules],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", help="run only this target by name")
    parser.add_argument("--targets-file", type=Path, default=CORPUS_DIR / "targets.yaml")
    args = parser.parse_args()

    targets = load_targets(args.targets_file)
    if args.target:
        targets = [t for t in targets if t["name"] == args.target]
        if not targets:
            print(f"No such target: {args.target}")
            sys.exit(1)

    scope = ScopeManager(path=SCOPE_FILE)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    for target_conf in targets:
        result = run_target(target_conf, scope)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = RESULTS_DIR / f"{target_conf['name']}_{ts}.json"
        out_path.write_text(json.dumps(result, indent=2))
        print(f"  saved: {out_path}")


if __name__ == "__main__":
    main()

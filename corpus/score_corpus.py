#!/usr/bin/env python3
"""Compute precision/recall of the evaluation corpus from hand-verified
ground truth (see ground_truth/_SCHEMA.md for the annotation workflow).

Loudly refuses to present unverified entries as results — this script is
meant to produce numbers that go in a thesis table, so it treats
un-annotated ground truth as a visible gap, not a silent zero.

Usage:
    python3 corpus/score_corpus.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

CORPUS_DIR = Path(__file__).resolve().parent
RESULTS_DIR = CORPUS_DIR / "results"


def latest_result_for(target_name: str) -> Path | None:
    candidates = sorted(RESULTS_DIR.glob(f"{target_name}_*.json"))
    return candidates[-1] if candidates else None


def score_target(target_conf: dict) -> dict:
    name = target_conf["name"]
    gt_path = CORPUS_DIR / target_conf["ground_truth"]
    if not gt_path.exists():
        return {"target": name, "error": f"no ground truth file at {gt_path}"}

    gt = yaml.safe_load(gt_path.read_text())
    detections = gt.get("expected_detections", [])
    false_positives = gt.get("false_positives", [])

    confirmed = [d for d in detections if d.get("status") == "confirmed"]
    false_negatives = [d for d in detections if d.get("status") == "false-negative-confirmed"]
    unverified = [d for d in detections if d.get("status") == "unverified"]
    not_applicable = [d for d in detections if d.get("status") == "not-applicable"]

    confirmed_fp = [fp for fp in false_positives if fp.get("status") == "confirmed"]

    result_path = latest_result_for(name)
    total_findings = None
    if result_path:
        import json
        data = json.loads(result_path.read_text())
        total_findings = len(data.get("findings", []))

    tp, fn = len(confirmed), len(false_negatives)
    recall = tp / (tp + fn) if (tp + fn) > 0 else None

    precision = None
    if total_findings:
        fp = len(confirmed_fp)
        # Approximate: only reflects findings specifically reviewed and
        # flagged, not an exhaustive per-finding audit. See _SCHEMA.md.
        precision = (total_findings - fp) / total_findings

    return {
        "target": name,
        "result_file": str(result_path) if result_path else None,
        "total_findings": total_findings,
        "confirmed": tp,
        "false_negatives": fn,
        "unverified": len(unverified),
        "not_applicable": len(not_applicable),
        "confirmed_false_positives": len(confirmed_fp),
        "recall": recall,
        "precision_approx": precision,
    }


def main() -> None:
    targets_file = CORPUS_DIR / "targets.yaml"
    targets = yaml.safe_load(targets_file.read_text())["targets"]

    rows = [score_target(t) for t in targets]

    print(f"{'target':<14} {'findings':>8} {'TP':>4} {'FN':>4} {'unverif.':>9} {'recall':>8} {'precision~':>11}")
    print("-" * 65)
    for r in rows:
        if "error" in r:
            print(f"{r['target']:<14} ERROR: {r['error']}")
            continue
        recall_s = f"{r['recall']:.2f}" if r["recall"] is not None else "n/a"
        prec_s = f"{r['precision_approx']:.2f}" if r["precision_approx"] is not None else "n/a"
        findings_s = str(r["total_findings"]) if r["total_findings"] is not None else "no run yet"
        print(f"{r['target']:<14} {findings_s:>8} {r['confirmed']:>4} {r['false_negatives']:>4} "
              f"{r['unverified']:>9} {recall_s:>8} {prec_s:>11}")

    total_unverified = sum(r.get("unverified", 0) for r in rows if "error" not in r)
    if total_unverified:
        print()
        print(f"WARNING: {total_unverified} ground-truth entries are still 'unverified'.")
        print("These are EXCLUDED from the recall/precision numbers above.")
        print("Do not report these numbers as final results until annotation is complete —")
        print("see corpus/ground_truth/_SCHEMA.md for the annotation workflow.")


if __name__ == "__main__":
    main()

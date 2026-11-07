#!/usr/bin/env python3
"""KMN-CyberSeek engagement coverage scorer.

Compares an autonomous engagement's report against a lab's ground-truth
vulnerability set and prints a coverage score — so every future change can be
judged by a number instead of a feeling.

Usage:
    python benchmarks/score.py <report.md> [--lab benchmarks/labs/kmn_training_win.json] [--json]
    python benchmarks/score.py --report-text "<raw text>" --lab <lab.json>

Legacy scoring (heuristic coverage only, NOT vulnerability verification):
    touched   = any of the item's signals appears ANYWHERE in the report text.
    confirmed = a signal appears in a CONFIRMED section of the report
                (Confirmed Compromises / Credentials Captured / Vulnerability Findings).

Dependency-free (stdlib only): works anywhere, no pip installs.

Structured scoring:
    python benchmarks/score.py findings.json --structured --lab lab.json --json
    Input: {"findings": [finding, ...]}; each finding follows
    core.finding_verification and may supply a single "ground_truth_id".
    IDs are matched exactly, never inferred from prose or source labels. Missing
    IDs on verified findings make precision unavailable, rather than hiding false
    positives. Recall counts only verified IDs in the ground-truth item set.
"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.finding_verification import assess_finding

# Report section headings whose content counts as "confirmed" (case-insensitive
# substring match on the heading line).
_CONFIRMED_HEADINGS = (
    "confirmed compromises",
    "credentials captured",
    "vulnerability findings",
)


def load_lab(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def split_confirmed_text(report: str) -> str:
    """Return the concatenated text of the report's 'confirmed' sections.

    A markdown report is split on '##'/'###' headings; sections whose heading
    contains one of _CONFIRMED_HEADINGS are collected until the next heading of
    the same-or-higher level.
    """
    lines = report.splitlines()
    out: List[str] = []
    capturing = False
    capture_level = 0
    for line in lines:
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            level = len(m.group(1))
            heading = m.group(2).lower()
            if any(h in heading for h in _CONFIRMED_HEADINGS):
                capturing = True
                capture_level = level
                out.append(line)
                continue
            # A heading at the same or higher level ends the captured section.
            if capturing and level <= capture_level:
                capturing = False
        if capturing:
            out.append(line)
    return "\n".join(out)


def score(report: str, lab: Dict) -> Dict:
    """Preserve legacy heading/signal counts; these are not verified findings."""
    full = report.lower()
    confirmed_text = split_confirmed_text(report).lower()

    items = lab.get("items", [])
    results = []
    for it in items:
        signals = [s.lower() for s in it.get("any", [])]
        touched = any(sig in full for sig in signals if sig)
        confirmed = any(sig in confirmed_text for sig in signals if sig)
        results.append({
            "id": it["id"],
            "category": it.get("category", "uncategorised"),
            "title": it.get("title", it["id"]),
            "touched": touched,
            "confirmed": confirmed,
        })

    total = len(results)
    touched_n = sum(1 for r in results if r["touched"])
    confirmed_n = sum(1 for r in results if r["confirmed"])

    # Per-category breakdown
    cats: Dict[str, Dict[str, int]] = {}
    for r in results:
        c = cats.setdefault(r["category"], {"total": 0, "touched": 0, "confirmed": 0})
        c["total"] += 1
        c["touched"] += 1 if r["touched"] else 0
        c["confirmed"] += 1 if r["confirmed"] else 0

    return {
        "mode": "legacy_markdown_heuristic",
        "verification": False,
        "notice": "Heuristic text coverage only; confirmed counts are not verification.",
        "lab": lab.get("lab", "?"),
        "total": total,
        "touched": touched_n,
        "confirmed": confirmed_n,
        "touched_pct": round(100.0 * touched_n / total, 1) if total else 0.0,
        "confirmed_pct": round(100.0 * confirmed_n / total, 1) if total else 0.0,
        "categories": cats,
        "items": results,
    }


def score_structured(report: Dict, lab: Dict) -> Dict:
    """Score raw evidence-backed findings, deduplicating exact ground-truth IDs.

    Precision and recall are fractions (0..1), or None when undefined. Unknown
    verified IDs are false positives; unverified claims are not predictions.
    Input assessments/status are ignored and recomputed from raw evidence.
    This evaluates declared evidence, not the authenticity of artifact contents.
    """
    if (not isinstance(report, dict) or not isinstance(report.get("findings"), list)
            or any(not isinstance(f, dict) for f in report["findings"])):
        raise ValueError("Structured report requires a findings list of objects.")
    items = lab.get("items", [])
    ids = [item.get("id") for item in items]
    if (any(not isinstance(key, str) or not key.strip() for key in ids)
            or len(set(ids)) != len(ids)):
        raise ValueError("Ground-truth items require unique nonempty string IDs.")
    touched, predicted = set(), set()
    assessments = []
    unlabelled = 0
    for finding in report["findings"]:
        assessment = assess_finding(finding)
        key = finding.get("ground_truth_id")
        labelled = isinstance(key, str) and bool(key.strip())
        if labelled:
            touched.add(key)
        if assessment["verified"]:
            if labelled:
                predicted.add(key)
            else:
                unlabelled += 1
        assessments.append({"ground_truth_id": key if labelled else None,
                            "assessment": assessment})
    truth = set(ids)
    true_positives, false_positives = predicted & truth, predicted - truth
    false_negatives = truth - predicted
    results, categories = [], {}
    for item in items:
        key = item["id"]
        row = {"id": key, "title": item.get("title", key),
               "category": item.get("category", "uncategorised"),
               "touched": key in touched, "confirmed": key in true_positives,
               "verified": key in true_positives}
        results.append(row)
        category = categories.setdefault(row["category"], {"total": 0, "touched": 0, "confirmed": 0})
        category["total"] += 1
        category["touched"] += int(row["touched"])
        category["confirmed"] += int(row["verified"])
    total, touched_n, verified_n = len(truth), len(touched & truth), len(true_positives)
    return {
        "mode": "structured_evidence", "verification": True,
        "notice": "Evidence-reference assessment only; artifact authenticity is not checked.",
        "lab": lab.get("lab", "?"), "total": total,
        "touched": touched_n, "confirmed": verified_n, "verified": verified_n,
        "touched_pct": round(100.0 * touched_n / total, 1) if total else 0.0,
        "confirmed_pct": round(100.0 * verified_n / total, 1) if total else 0.0,
        "categories": categories, "items": results, "assessments": assessments,
        "true_positives": sorted(true_positives), "false_positives": sorted(false_positives),
        "false_negatives": sorted(false_negatives), "unlabelled_verified": unlabelled,
        "precision": len(true_positives) / len(predicted) if predicted and not unlabelled else None,
        "recall": len(true_positives) / total if total else None,
    }


def print_report(res: Dict) -> None:
    print(f"\n=== Coverage vs {res['lab']} ===")
    print(res["notice"])
    print(f"Touched:   {res['touched']}/{res['total']}  ({res['touched_pct']}%)")
    label = "Verified" if res["verification"] else "Confirmed (heuristic)"
    print(f"{label}: {res['confirmed']}/{res['total']}  ({res['confirmed_pct']}%)")
    if res["verification"]:
        print(f"Precision: {res['precision']}  Recall: {res['recall']}")
    print("\nBy category (confirmed / touched / total):")
    for cat, c in sorted(res["categories"].items()):
        print(f"  {cat:20s} {c['confirmed']:>2}/{c['touched']:>2}/{c['total']:<2}")
    missed = [r for r in res["items"] if not r["touched"]]
    if missed:
        print(f"\nMissed (not even touched) — {len(missed)}:")
        for r in missed:
            print(f"  [ ] {r['id']:26s} {r['title']}")
    touched_not_confirmed = [r for r in res["items"] if r["touched"] and not r["confirmed"]]
    if touched_not_confirmed:
        print(f"\nTouched but not confirmed — {len(touched_not_confirmed)}:")
        for r in touched_not_confirmed:
            print(f"  [~] {r['id']:26s} {r['title']}")
    print("")


def _default_lab() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "labs", "kmn_training_win.json")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score engagement coverage vs a lab ground-truth.")
    ap.add_argument("report", nargs="?", help="Path to the engagement report (.md/.txt)")
    ap.add_argument("--report-text", help="Raw report text instead of a file")
    ap.add_argument("--lab", default=_default_lab(), help="Path to lab ground-truth JSON")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of a table")
    ap.add_argument("--structured", action="store_true", help="Read evidence-backed findings JSON")
    args = ap.parse_args(argv)

    if args.structured and (args.report_text is not None or not args.report):
        ap.error("--structured requires a JSON report path, not --report-text")
    if args.report_text is not None:
        report = args.report_text
    elif args.report:
        with open(args.report, "r", encoding="utf-8") as fh:
            report = fh.read()
    else:
        ap.error("provide a report path or --report-text")

    try:
        res = (score_structured(json.loads(report), load_lab(args.lab)) if args.structured
               else score(report, load_lab(args.lab)))
    except ValueError as exc:
        ap.error(str(exc))
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print_report(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())

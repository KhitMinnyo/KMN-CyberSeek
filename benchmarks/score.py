#!/usr/bin/env python3
"""KMN-CyberSeek engagement coverage scorer.

Compares an autonomous engagement's report against a lab's ground-truth
vulnerability set and prints a coverage score — so every future change can be
judged by a number instead of a feeling.

Usage:
    python benchmarks/score.py <report.md> [--lab benchmarks/labs/kmn_training_win.json] [--json]
    python benchmarks/score.py --report-text "<raw text>" --lab <lab.json>

Scoring (per ground-truth item):
    touched   = any of the item's signals appears ANYWHERE in the report text.
    confirmed = a signal appears in a CONFIRMED section of the report
                (Confirmed Compromises / Credentials Captured / Vulnerability Findings).

Dependency-free (stdlib only): works anywhere, no pip installs.
"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Tuple

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
        "lab": lab.get("lab", "?"),
        "total": total,
        "touched": touched_n,
        "confirmed": confirmed_n,
        "touched_pct": round(100.0 * touched_n / total, 1) if total else 0.0,
        "confirmed_pct": round(100.0 * confirmed_n / total, 1) if total else 0.0,
        "categories": cats,
        "items": results,
    }


def print_report(res: Dict) -> None:
    print(f"\n=== Coverage vs {res['lab']} ===")
    print(f"Touched:   {res['touched']}/{res['total']}  ({res['touched_pct']}%)")
    print(f"Confirmed: {res['confirmed']}/{res['total']}  ({res['confirmed_pct']}%)")
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
    args = ap.parse_args(argv)

    if args.report_text is not None:
        report = args.report_text
    elif args.report:
        with open(args.report, "r", encoding="utf-8") as fh:
            report = fh.read()
    else:
        ap.error("provide a report path or --report-text")

    res = score(report, load_lab(args.lab))
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print_report(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Print a non-claiming capability comparison from explicit manifests.

This is a code-level inventory, not a performance leaderboard. Systems without
an attached reproducible manifest remain ``unassessed`` rather than receiving a
zero or an inferred score.
"""

import argparse
import json
from pathlib import Path


def load(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def compare(matrix: dict) -> dict:
    capabilities = [item["id"] for item in matrix.get("capabilities", [])]
    rows = []
    for name, system in matrix.get("systems", {}).items():
        values = system.get("capabilities", {})
        implemented = sum(values.get(cap) == "implemented" for cap in capabilities)
        assessed = sum(values.get(cap) not in (None, "unassessed") for cap in capabilities)
        rows.append({
            "system": name,
            "assessment": system.get("assessment", "unassessed"),
            "implemented": implemented,
            "assessed": assessed,
            "total": len(capabilities),
            "comparison_allowed": system.get("assessment") == "code_and_regression_tests",
        })
    return {"format": matrix.get("format"), "capabilities": capabilities, "systems": rows}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Print the code-level capability matrix")
    parser.add_argument("--matrix", default=str(Path(__file__).with_name("capability_matrix.json")))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = compare(load(args.matrix))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("Code-level capability inventory (not a performance leaderboard)\n")
        for row in result["systems"]:
            print(
                f"{row['system']}: {row['implemented']}/{row['total']} implemented; "
                f"assessment={row['assessment']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

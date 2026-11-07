"""Pure assessment completeness policy, independent of objectives and lifecycle."""

import copy


def check_identity(row):
    """Stable coverage identity used by snapshots and attributed waivers."""
    return {key: row[key] for key in ("endpoint_id", "role", "category")}


def evaluate_completeness(snapshot=None, waivers=(), *, evidence_refs=()):
    """Return the versioned verdict contract without I/O or mutating input.

    Only evidence-backed verified coverage or an explicit, attributed waiver
    satisfies a check. evidence_refs contains already-resolved session-owned,
    committed references, not claimed references from the snapshot. Omitting it
    cannot establish verification. Completion says nothing about vulnerabilities.
    """
    result = {"version": 1, "verdict": "unknown", "missing_checks": [],
              "blockers": [], "waived_checks": []}
    if not isinstance(snapshot, dict) or not snapshot.get("endpoints"):
        return result
    rows = snapshot.get("coverage", [])
    try:
        expected = {(e["id"], role, category) for e in snapshot["endpoints"]
                    for role in snapshot["roles"] for category in snapshot["categories"]}
        actual = [(r["endpoint_id"], r["role"], r["category"]) for r in rows]
        valid_matrix = bool(expected) and len(actual) == len(expected) and set(actual) == expected
    except (KeyError, TypeError):
        valid_matrix = False
    if not valid_matrix:
        result["blockers"].append({"reason": "coverage_inventory_missing"})
        return result
    attributed = {}
    committed = frozenset(evidence_refs or ())
    for waiver in waivers:
        if (isinstance(waiver, dict)
                and all(isinstance(waiver.get(k), str) and waiver[k].strip()
                        for k in ("endpoint_id", "role", "category", "reviewer", "reason", "timestamp"))):
            attributed[tuple(check_identity(waiver).values())] = waiver
    result["verdict"] = "complete"
    for row in rows:
        identity = check_identity(row)
        waiver = attributed.get(tuple(identity.values()))
        if waiver:
            result["waived_checks"].append(copy.deepcopy(waiver))
        elif not (row.get("status") == "verified" and type(row.get("attempts")) is int
                  and row["attempts"] > 0 and isinstance(row.get("evidence_ref"), str)
                  and row["evidence_ref"] in committed):
            missing = {**identity, "status": row.get("status", "pending")}
            if row.get("status") == "verified":
                missing["reason"] = "evidence_not_committed"
            result["missing_checks"].append(missing)
            if row.get("status") in {"blocked", "skipped", "inconclusive", "attempted", "verified"}:
                result["blockers"].append(copy.deepcopy(missing))
            result["verdict"] = "incomplete"
    return result

"""Assessment completeness is not objective success or a clean bill of health."""

import copy

import pytest

from core.run_policy import evaluate_completeness


def snapshot(status="pending"):
    return {"version": 1, "endpoints": [{"id": "endpoint"}], "roles": {"anonymous": None},
            "categories": ["headers"], "coverage": [
                {"endpoint_id": "endpoint", "role": "anonymous", "category": "headers",
                 "status": status, "attempts": 1, "evidence_ref": "evidence:check"}]}


@pytest.mark.parametrize("inventory", [None, {}, {"endpoints": []}])
def test_empty_inventory_is_unknown(inventory):
    result = evaluate_completeness(inventory)
    assert result == {"version": 1, "verdict": "unknown", "missing_checks": [],
                      "blockers": [], "waived_checks": []}


@pytest.mark.parametrize("status", ["pending", "attempted", "blocked", "skipped", "inconclusive"])
def test_unfinished_checks_cannot_complete(status):
    result = evaluate_completeness(snapshot(status))
    assert result["verdict"] == "incomplete"
    assert result["missing_checks"][0]["status"] == status


def test_verified_requires_evidence_and_attempt():
    data = snapshot("verified")
    assert evaluate_completeness(data, evidence_refs={"evidence:check"})["verdict"] == "complete"
    data["coverage"][0]["evidence_ref"] = None
    assert evaluate_completeness(data)["verdict"] == "incomplete"
    data["coverage"][0].update(evidence_ref="evidence:check", attempts=0)
    assert evaluate_completeness(data, evidence_refs={"evidence:check"})["verdict"] == "incomplete"


def test_prefix_is_not_proof_and_validated_references_are_exact():
    data = snapshot("verified")
    assert evaluate_completeness(data)["verdict"] == "incomplete"
    result = evaluate_completeness(data, evidence_refs={"evidence:other-session-check"})
    assert result["verdict"] == "incomplete"
    assert result["blockers"][0]["reason"] == "evidence_not_committed"
    assert evaluate_completeness(data, evidence_refs={"evidence:check"})["verdict"] == "complete"


def test_waiver_must_be_explicit_attributed_and_exact():
    data = snapshot("blocked")
    waiver = {"endpoint_id": "endpoint", "role": "anonymous", "category": "headers",
              "reviewer": "operator", "reason": "Approved exclusion", "timestamp": "2026-11-07T00:00:00"}
    before = copy.deepcopy((data, waiver))
    result = evaluate_completeness(data, [waiver])
    assert result["verdict"] == "complete" and result["waived_checks"] == [waiver]
    result["waived_checks"][0]["reason"] = "mutation"
    assert (data, waiver) == before
    for key in waiver:
        invalid = {k: v for k, v in waiver.items() if k != key}
        assert evaluate_completeness(data, [invalid])["verdict"] == "incomplete"


def test_truncated_matrix_is_not_complete():
    data = snapshot("verified")
    data["categories"].append("authorization")
    assert evaluate_completeness(data)["verdict"] == "unknown"


def test_objective_and_lifecycle_do_not_affect_assessment():
    data = snapshot("blocked")
    data.update(objective_complete=True, status="completed", objective_progress=1.0)
    assert evaluate_completeness(data)["verdict"] == "incomplete"

"""Public exports retain completeness and review provenance without audit prose."""

import copy
import json

import pytest

from core.report_export import build_report_snapshot, export_sarif


def finding():
    return {
        "target": "https://example.test/api", "risk_level": "high",
        "artifacts": [{"id": "a1", "uri": "artifact://a1"}],
        "evidence": [{"id": "e1", "target": "https://example.test/api", "method": "review",
                      "result": "positive", "artifact_refs": ["a1"]}],
        "verification_events": [{"kind": "verification", "target": "https://example.test/api",
                                 "method": "review", "result": "positive", "evidence_refs": ["e1"],
                                 "provenance": {"type": "review_only", "source": "operator_review"}}],
    }


@pytest.mark.parametrize("verdict,success", [("complete", True), ("incomplete", False), ("unknown", False)])
def test_safe_completeness_survives_sarif_without_waiver_prose(verdict, success):
    report = {"session": {"status": "completed", "objective_complete": True}, "completeness": {
        "verdict": verdict,
        "missing_checks": [{"endpoint_id": "endpoint", "role": "reader", "category": "observation", "status": "blocked"}],
        "waived_checks": [{"endpoint_id": "endpoint", "role": "reader", "category": "observation",
                           "reviewer": "private-reviewer", "reason": "private-waiver-prose", "timestamp": "private-timestamp"}],
    }}
    before = copy.deepcopy(report)
    snapshot = build_report_snapshot(report)
    sarif = export_sarif(snapshot)
    assert snapshot["completeness"]["verdict"] == verdict
    assert snapshot["summary"]["assessment_complete"] is success
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is success
    assert sarif["runs"][0]["properties"]["completeness"] == snapshot["completeness"]
    for private in ("private-reviewer", "private-waiver-prose", "private-timestamp"):
        assert private not in json.dumps(sarif)
    assert report == before


def test_objective_achievement_without_coverage_is_not_complete():
    snapshot = build_report_snapshot({"session": {"objective_complete": True, "status": "completed"}})
    assert snapshot["completeness"]["verdict"] == "unknown"
    assert snapshot["summary"]["assessment_partial"] is True
    assert export_sarif(snapshot)["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_operator_review_provenance_is_not_erased_or_claimed_independent():
    snapshot = build_report_snapshot({"vulnerabilities": [finding()]})
    item = snapshot["findings"][0]
    assert item["verification"] == "verified"
    assert item["provenance"] == {"type": "review_only", "source": "operator_review",
                                  "runtime_bound": False, "independent_reproduction": False}
    assert export_sarif(snapshot)["runs"][0]["results"][0]["properties"]["provenance"] == item["provenance"]


def test_runtime_binding_requires_matching_attempt_and_artifact_links():
    data = finding()
    data["evidence"][0].update(command_id="c1", attempt_id="t1")
    data["verification_events"][0]["provenance"] = {"type": "runtime", "source": "command_result"}
    report = {"vulnerabilities": [data], "commands_executed": [
        {"command_id": "c1", "attempt_id": "different", "artifacts": [{"id": "a1"}]},
    ]}
    assert build_report_snapshot(report)["findings"][0]["provenance"]["runtime_bound"] is False
    report["commands_executed"][0]["attempt_id"] = "t1"
    assert build_report_snapshot(report)["findings"][0]["provenance"]["runtime_bound"] is True
    report["commands_executed"][0]["artifacts"] = [{"id": "foreign"}]
    assert build_report_snapshot(report)["findings"][0]["provenance"]["runtime_bound"] is False


def test_invalid_last_event_cannot_inherit_prior_runtime_provenance():
    data = finding()
    data["verification_events"].append({"kind": "verification", "result": "positive",
                                         "provenance": {"type": "runtime", "source": "command_result"}})
    exported = build_report_snapshot({"vulnerabilities": [data]})["findings"][0]
    assert exported["verification"] == "unverified"
    assert exported["provenance"]["type"] == "unspecified"
    assert exported["provenance"]["runtime_bound"] is False

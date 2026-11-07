"""Evidence-backed lifecycle tests, independent of source/display heuristics."""

from copy import deepcopy

import pytest

from core.finding_verification import assess_finding
from core.vuln_validate import validate


def finding_with_events(*checks):
    """Build explicit evidence and artifacts for each ordered check."""
    finding = {"target": "https://lab.example:443/path", "artifacts": [],
               "evidence": [], "verification_events": []}
    for index, (kind, result) in enumerate(checks):
        artifact_id, evidence_id = f"a{index}", f"e{index}"
        finding["artifacts"].append({"id": artifact_id, "uri": f"file:///checks/{index}.txt"})
        finding["evidence"].append({"id": evidence_id, "target": finding["target"],
                                    "method": "bounded protocol check", "result": result,
                                    "artifact_refs": [artifact_id]})
        finding["verification_events"].append({"kind": kind, "target": finding["target"],
                                               "method": "bounded protocol check", "result": result,
                                               "evidence_refs": [evidence_id]})
    return finding


@pytest.mark.parametrize("source", ["nmap-vuln-script", "exploit", "manual", "post_ex", "nvd"])
def test_labels_confidence_exit_and_precomputed_assessment_do_not_verify(source):
    finding = {"source_tool": source, "status": "confirmed", "confidence": 1.0,
               "exit_code": 0, "success": True, "lifecycle": "verified", "verified": True,
               "verification": {"verified": True}}
    assessment = assess_finding(finding)
    assert not assessment["verified"]
    assert assessment["status"] == "potential"


def test_pure_positive_assessment_has_traceable_references():
    finding = finding_with_events(("verification", "positive"))
    original = deepcopy(finding)
    assessment = assess_finding(finding)
    assert finding == original
    assert assessment["verified"] and assessment["lifecycle"] == "verified"
    assert assessment["status"] == "confirmed"
    assert assessment["evidence_refs"] == ["e0"]
    assert assessment["artifact_refs"] == ["a0"]
    assert assessment["history"][0]["evidence_refs"] == ["e0"]


@pytest.mark.parametrize("kind,result,state", [
    ("observation", "observed", "observed"),
    ("suspicion", "suspected", "suspected"),
    ("verification", "negative", "inconclusive"),
    ("verification", "inconclusive", "inconclusive"),
    ("verification", "success", "inconclusive"),
    ("verification", True, "inconclusive"),
    ("remediation", "applied", "inconclusive"),
    ("retest", "negative", "inconclusive"),
])
def test_states_require_explicit_results_and_valid_order(kind, result, state):
    assessment = assess_finding(finding_with_events((kind, result)))
    assert assessment["lifecycle"] == state
    assert not assessment["verified"]


@pytest.mark.parametrize("change", [
    "missing_target", "wrong_event_target", "wrong_evidence_target", "missing_method",
    "wrong_method", "wrong_result", "missing_evidence", "dangling_evidence",
    "missing_artifact", "dangling_artifact", "missing_uri", "duplicate_evidence",
    "duplicate_artifact", "malformed_refs", "malformed_event",
])
def test_incomplete_or_mismatched_chain_cannot_verify(change):
    finding = finding_with_events(("verification", "positive"))
    event, evidence = finding["verification_events"][0], finding["evidence"][0]
    if change == "missing_target":
        finding.pop("target")
    elif change == "wrong_event_target":
        event["target"] = "https://other.example:443/path"
    elif change == "wrong_evidence_target":
        evidence["target"] = "https://lab.example:8443/path"
    elif change == "missing_method":
        event.pop("method")
    elif change == "wrong_method":
        evidence["method"] = "different check"
    elif change == "wrong_result":
        evidence["result"] = "negative"
    elif change == "missing_evidence":
        finding["evidence"] = []
    elif change == "dangling_evidence":
        event["evidence_refs"] = ["unknown"]
    elif change == "missing_artifact":
        finding["artifacts"] = []
    elif change == "dangling_artifact":
        evidence["artifact_refs"] = ["unknown"]
    elif change == "missing_uri":
        finding["artifacts"][0].pop("uri")
    elif change == "duplicate_evidence":
        finding["evidence"].append(deepcopy(evidence))
    elif change == "duplicate_artifact":
        finding["artifacts"].append(deepcopy(finding["artifacts"][0]))
    elif change == "malformed_refs":
        event["evidence_refs"] = [{}]
    elif change == "malformed_event":
        finding["verification_events"] = [None]
    assessment = assess_finding(finding)
    assert assessment["lifecycle"] == "inconclusive"
    assert not assessment["verified"]


def test_full_lifecycle_and_negative_retest():
    finding = finding_with_events(("observation", "observed"), ("suspicion", "suspected"),
                                  ("verification", "positive"), ("remediation", "applied"),
                                  ("retest", "negative"))
    assessment = assess_finding(finding)
    assert [event["lifecycle"] for event in assessment["history"]] == [
        "observed", "suspected", "verified", "remediated", "retested"]
    assert assessment["remediation_verified"]
    assert not assessment["verified"]
    assert assessment["status"] == "potential"


def test_applied_remediation_is_not_a_verified_fix():
    assessment = assess_finding(finding_with_events(("verification", "positive"),
                                                    ("remediation", "applied")))
    assert assessment["lifecycle"] == "remediated"
    assert not assessment["verified"] and not assessment["remediation_verified"]


def test_positive_retest_verifies_persistent_vulnerability_not_fix():
    assessment = assess_finding(finding_with_events(("verification", "positive"),
                                                    ("remediation", "applied"),
                                                    ("retest", "positive")))
    assert assessment["lifecycle"] == "retested"
    assert assessment["verified"] and not assessment["remediation_verified"]


def test_retest_cannot_replay_pre_remediation_positive_evidence():
    finding = finding_with_events(("verification", "positive"), ("remediation", "applied"),
                                  ("retest", "positive"))
    finding["verification_events"][-1]["evidence_refs"] = ["e0"]
    assessment = assess_finding(finding)
    assert assessment["lifecycle"] == "inconclusive" and not assessment["verified"]


def test_retest_cannot_repackage_an_old_artifact_under_new_evidence_id():
    finding = finding_with_events(("verification", "positive"), ("remediation", "applied"),
                                  ("retest", "positive"))
    finding["evidence"][-1]["artifact_refs"] = ["a0"]
    assessment = assess_finding(finding)
    assert assessment["lifecycle"] == "inconclusive" and not assessment["verified"]


def test_inconclusive_retest_does_not_claim_a_fix_or_persistent_vulnerability():
    finding = finding_with_events(("verification", "positive"), ("remediation", "applied"),
                                  ("retest", "inconclusive"))
    assessment = assess_finding(finding)
    assert assessment["lifecycle"] == "inconclusive"
    assert not assessment["verified"] and not assessment["remediation_verified"]


def test_artifacts_and_successful_exit_without_explicit_positive_result_do_not_verify():
    finding = finding_with_events(("verification", "positive"))
    for record in (finding["evidence"][0], finding["verification_events"][0]):
        record.pop("result")
        record["exit_code"] = 0
        record["success"] = True
    assert not assess_finding(finding)["verified"]


@pytest.mark.parametrize("field", ["artifacts", "evidence", "verification_events"])
def test_malformed_containers_fail_closed(field):
    finding = finding_with_events(("verification", "positive"))
    finding[field] = "not a list"
    assert not assess_finding(finding)["verified"]


def test_later_inconclusive_check_clears_current_verification_not_history():
    assessment = assess_finding(finding_with_events(("verification", "positive"),
                                                    ("verification", "inconclusive")))
    assert assessment["history"][0]["lifecycle"] == "verified"
    assert assessment["lifecycle"] == "inconclusive" and not assessment["verified"]


def test_validate_preserves_legacy_projection_but_does_not_verify_source():
    finding = {"source_tool": "nmap-vuln-script", "service": "http"}
    result = validate(finding)
    assert result["status"] == "confirmed"
    assert not result["verification"]["verified"]
    assert "verification" not in finding


def test_validate_attaches_assessment_even_when_suppressed():
    result = validate({"service": "ftp", "cve_ids": ["CVE-2014-0160"]})
    assert result["suppressed"]
    assert not result["verification"]["verified"]


def test_legacy_projection_does_not_control_evidence_projection():
    finding = finding_with_events(("verification", "positive"))
    finding["source_tool"] = "nvd"
    result = validate(finding)
    assert result["status"] == "potential"
    assert result["verification"]["status"] == "confirmed"

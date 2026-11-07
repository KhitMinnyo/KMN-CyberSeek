"""Structured evidence scoring and explicit legacy non-verification labeling."""

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from benchmarks.score import main, print_report, score, score_structured
from tests.test_verified_findings import finding_with_events


LAB = {"lab": "structured-lab", "items": [
    {"id": "one", "category": "web", "any": ["one"]},
    {"id": "two", "category": "web", "any": ["two"]},
]}


def verified(key):
    finding = finding_with_events(("verification", "positive"))
    finding["ground_truth_id"] = key
    return finding


def test_exact_ids_precision_recall_and_deduplication():
    report = {"findings": [verified("one"), verified("one"), verified("unknown"),
                            {"ground_truth_id": "two", "status": "confirmed",
                             "source_tool": "exploit", "confidence": 1, "exit_code": 0}]}
    before = deepcopy(report)
    result = score_structured(report, LAB)
    assert report == before
    assert result["verified"] == result["confirmed"] == 1
    assert result["touched"] == 2
    assert result["true_positives"] == ["one"]
    assert result["false_positives"] == ["unknown"]
    assert result["false_negatives"] == ["two"]
    assert result["precision"] == result["recall"] == 0.5
    assert result["categories"]["web"] == {"total": 2, "touched": 2, "confirmed": 1}


def test_unlabelled_verified_findings_make_precision_unavailable():
    result = score_structured({"findings": [verified(None), verified("one")]}, LAB)
    assert result["unlabelled_verified"] == 1
    assert result["precision"] is None
    assert result["recall"] == 0.5


def test_no_ids_are_inferred_from_text_or_a_precomputed_assessment():
    finding = {"name": "one", "description": "two", "status": "confirmed",
               "verification": {"verified": True}, "ground_truth_id": "ONE"}
    result = score_structured({"findings": [finding]}, LAB)
    assert result["touched"] == result["verified"] == 0
    assert result["precision"] is None and result["recall"] == 0


def test_empty_report_and_empty_ground_truth():
    result = score_structured({"findings": []}, LAB)
    assert result["precision"] is None and result["recall"] == 0
    result = score_structured({"findings": [verified("one")]}, {"items": []})
    assert result["precision"] == 0 and result["recall"] is None
    assert result["false_positives"] == ["one"]


def test_remediation_and_retest_outcomes_affect_current_score():
    finding = finding_with_events(("verification", "positive"), ("remediation", "applied"),
                                  ("retest", "negative"))
    finding["ground_truth_id"] = "one"
    result = score_structured({"findings": [finding]}, LAB)
    assert result["touched"] == 1 and result["verified"] == 0
    assert result["assessments"][0]["assessment"]["remediation_verified"]


def test_broken_artifact_chain_does_not_score_as_verified():
    finding = verified("one")
    finding["artifacts"] = []
    result = score_structured({"findings": [finding]}, LAB)
    assert result["touched"] == 1 and result["verified"] == 0


@pytest.mark.parametrize("report", [[], {}, {"findings": {}}, {"findings": [None]}])
def test_malformed_reports_are_rejected(report):
    with pytest.raises(ValueError, match="findings list"):
        score_structured(report, LAB)


@pytest.mark.parametrize("items", [[{"id": "a"}, {"id": "a"}], [{}], [{"id": []}]])
def test_bad_ground_truth_ids_are_rejected(items):
    with pytest.raises(ValueError, match="unique nonempty"):
        score_structured({"findings": []}, {"items": items})


def test_legacy_keeps_counts_but_labels_them_non_verification(capsys):
    result = score("## Vulnerability Findings\none\n", LAB)
    assert result["confirmed"] == 1
    assert result["mode"] == "legacy_markdown_heuristic"
    assert result["verification"] is False
    print_report(result)
    output = capsys.readouterr().out
    assert "not verification" in output and "Confirmed (heuristic)" in output


def test_cli_structured_and_legacy_json(tmp_path, capsys):
    lab_path, report_path = tmp_path / "lab.json", tmp_path / "findings.json"
    lab_path.write_text(json.dumps(LAB), encoding="utf-8")
    report_path.write_text(json.dumps({"findings": [verified("one")]}), encoding="utf-8")
    assert main([str(report_path), "--structured", "--lab", str(lab_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "structured_evidence" and result["verified"] == 1
    assert main(["--report-text", "## Vulnerability Findings\none", "--lab", str(lab_path),
                 "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["confirmed"] == 1 and not result["verification"]


def test_direct_script_cli_imports_core(tmp_path):
    lab_path, report_path = tmp_path / "lab.json", tmp_path / "findings.json"
    lab_path.write_text(json.dumps(LAB), encoding="utf-8")
    report_path.write_text(json.dumps({"findings": [verified("one")]}), encoding="utf-8")
    script = Path(__file__).resolve().parents[1] / "benchmarks" / "score.py"
    result = subprocess.run([sys.executable, str(script), str(report_path), "--structured",
                             "--lab", str(lab_path), "--json"], cwd=tmp_path,
                            capture_output=True, text=True, check=True)
    assert json.loads(result.stdout)["verified"] == 1


def test_cli_rejects_invalid_json_and_ambiguous_modes(tmp_path, capsys):
    report_path = tmp_path / "invalid.json"
    report_path.write_text("not json", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main([str(report_path), "--structured"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main(["--structured", "--report-text", "one"])
    assert exc.value.code == 2
    assert "requires a JSON report path" in capsys.readouterr().err

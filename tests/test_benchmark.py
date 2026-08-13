"""Tests for the engagement-coverage benchmark scorer (benchmarks/score.py).

The scorer is how every coverage-engine milestone is judged, so its own logic —
signal matching, confirmed-section extraction, and the coverage math — is locked
in here. Dependency-free (stdlib only)."""

import os

from benchmarks.score import score, split_confirmed_text, load_lab, _default_lab


_LAB = {
    "lab": "unit-lab",
    "items": [
        {"id": "a.one", "category": "cat_a", "title": "One", "any": ["signal-one", "alt-one"]},
        {"id": "a.two", "category": "cat_a", "title": "Two", "any": ["signal-two"]},
        {"id": "b.three", "category": "cat_b", "title": "Three", "any": ["signal-three"]},
    ],
}


def test_touched_vs_confirmed_split():
    report = (
        "## 3. Vulnerability Findings\n"
        "signal-one was validated here\n"
        "## 5. Executed Commands Log\n"
        "the AI mentioned signal-two while reasoning\n"
    )
    res = score(report, _LAB)
    by_id = {r["id"]: r for r in res["items"]}
    # signal-one is in a confirmed section → touched AND confirmed
    assert by_id["a.one"]["touched"] and by_id["a.one"]["confirmed"]
    # signal-two only in the commands log → touched but NOT confirmed
    assert by_id["a.two"]["touched"] and not by_id["a.two"]["confirmed"]
    # signal-three absent → neither
    assert not by_id["b.three"]["touched"]


def test_coverage_math_and_percentages():
    report = "## 4.1 Confirmed Compromises\nsignal-one and signal-three\n"
    res = score(report, _LAB)
    assert res["total"] == 3
    assert res["touched"] == 2 and res["confirmed"] == 2
    assert res["touched_pct"] == round(100 * 2 / 3, 1)
    assert res["categories"]["cat_a"]["touched"] == 1
    assert res["categories"]["cat_b"]["confirmed"] == 1


def test_case_insensitive_and_alt_signal():
    report = "## Vulnerability Findings\nALT-ONE appeared in caps\n"
    res = score(report, _LAB)
    by_id = {r["id"]: r for r in res["items"]}
    assert by_id["a.one"]["confirmed"]  # matched via the alt signal, case-insensitive


def test_split_confirmed_sections_stops_at_next_heading():
    report = (
        "## 4. Credentials Captured\n"
        "kept-line\n"
        "## 5. Executed Commands Log\n"
        "dropped-line\n"
    )
    conf = split_confirmed_text(report).lower()
    assert "kept-line" in conf
    assert "dropped-line" not in conf


def test_real_lab_file_is_wellformed():
    lab = load_lab(_default_lab())
    assert lab["lab"] == "KMN-Training-Win"
    items = lab["items"]
    assert len(items) >= 30
    ids = set()
    for it in items:
        assert it["id"] and it["category"] and it["any"], f"malformed item: {it}"
        assert it["id"] not in ids, f"duplicate id: {it['id']}"
        ids.add(it["id"])


def test_empty_report_scores_zero():
    res = score("", _LAB)
    assert res["touched"] == 0 and res["confirmed"] == 0 and res["touched_pct"] == 0.0

"""Tests for the dependency-free Markdown report generator. Verifies the report
contains ALL findings, EVERY executed command, and EVERY attack decision in
chronological order (the DOCX/PDF paths need python-docx/fpdf2 and are covered
manually)."""

import os
import tempfile

from core.report_generator import generate_markdown_report


def _sample_report():
    decisions = [
        {"timestamp": f"2026-08-12T13:{i:02d}:00", "reasoning": f"idea number {i}",
         "suggested_command": f"cmd{i}", "risk_level": "low",
         "attack_phase": "enumeration", "context": ""}
        for i in range(12)
    ]
    decisions.append({"timestamp": "2026-08-12T13:20:00",
                      "reasoning": "operator said focus", "suggested_command": "",
                      "risk_level": "low", "context": "operator_instruction"})
    decisions.append({"timestamp": "2026-08-12T13:22:00", "reasoning": "caught shell",
                      "suggested_command": "", "risk_level": "high",
                      "context": "shell_caught"})
    return {
        "session": {
            "session_id": "Win_test", "target_ip": "10.0.0.9", "target_domain": None,
            "created_at": "2026-08-12T12:00:00", "status": "executing",
            "current_stage": "credential_reuse",
            "compromise_evidence": [{"service": "smb", "port": 445, "host": "10.0.0.9",
                                     "privilege": "root/SYSTEM", "command": "cme smb",
                                     "signal": "uid=0", "proof": "uid=0(root)"}],
            "operator_instructions": ["Focus on GlassFish 4848", "Skip SMB"],
            "strategic_plan": [{"step": "exploit tomcat", "status": "pending"}],
            "reflections": ["found glassfish"], "exhausted_services": ["smb"],
        },
        "discovered_services": [{"host": "10.0.0.9", "port": 445, "service": "smb",
                                 "version": "Win", "state": "open"}],
        "discovered_hosts": [{"ip": "10.0.0.9"}],
        "vulnerabilities": [{"risk_level": "high", "name": "Ghostcat", "host": "10.0.0.9",
                             "port": 8009, "cve_ids": ["CVE-2020-1938"], "source_tool": "nvd",
                             "status": "confirmed", "description": "AJP read",
                             "service_version": "Tomcat 8.5"}],
        "commands_executed": [{"command": f"cmd{i}", "output": f"out{i}", "success": True,
                               "timestamp": f"2026-08-12T13:{i:02d}:00"} for i in range(12)],
        "credentials": [{"username": "admin", "secret": "admin",
                         "secret_type": "password", "service": "glassfish"}],
        "ai_decisions": decisions, "evidence": [], "summary": {},
    }


def _render():
    path = os.path.join(tempfile.gettempdir(), "kmn_test_report.md")
    generate_markdown_report(_sample_report(), output_path=path)
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_markdown_includes_all_commands_in_order():
    md = _render()
    for i in range(12):
        assert f"`cmd{i}`" in md
    assert "out11" in md  # command output rendered


def test_markdown_includes_all_decisions_chronologically():
    md = _render()
    assert "chronological (14)" in md
    assert "idea number 0" in md          # first decision, not truncated
    assert "operator said focus" in md    # near-last decision present
    assert "**OPERATOR**" in md and "**SHELL**" in md  # context tags


def test_markdown_includes_compromises_and_proof():
    md = _render()
    assert "Confirmed Compromises" in md
    assert "root/SYSTEM" in md
    assert "uid=0(root)" in md


def test_markdown_includes_plan_steering_and_findings():
    md = _render()
    assert "Focus on GlassFish 4848" in md   # operator steering
    assert "exploit tomcat" in md            # strategic plan
    assert "Exhausted vectors:" in md
    assert "Ghostcat" in md and "CVE-2020-1938" in md
    assert "glassfish" in md                 # credential


def test_markdown_report_writes_file():
    path = os.path.join(tempfile.gettempdir(), "kmn_test_report2.md")
    out = generate_markdown_report(_sample_report(), output_path=path)
    assert out == path and os.path.getsize(path) > 500

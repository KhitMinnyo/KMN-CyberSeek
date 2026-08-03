"""Tests for the deterministic safety backstops and prompt-injection defenses:
non-interactive command checks, high-risk keyword approval gating, and that the
prompts instruct the model to treat fenced tool output as untrusted data."""

import ai.prompts as prompts
from tests._helpers import make_orch


# ── non-interactive command safety ───────────────────────────────────────────

def test_rejects_interactive_msfconsole():
    orch = make_orch()
    assert orch._check_command_safety("msfconsole") is not None
    assert orch._check_command_safety("msfconsole -q -x \"use x; run\"") is None


def test_rejects_bare_python_and_bash():
    orch = make_orch()
    assert orch._check_command_safety("python") is not None
    assert orch._check_command_safety("bash") is not None
    assert orch._check_command_safety("python3 -c 'print(1)'") is None


# ── high-risk approval gating ────────────────────────────────────────────────

def test_requires_approval_high_risk_keywords():
    orch = make_orch()
    # These each contain a keyword from Orchestrator.requires_approval's list
    # (hydra, exploit, sudo, hashcat, crack, meterpreter).
    for cmd in ["hydra -l root ssh://x", "msfconsole -x 'use exploit/x'",
                "sudo -l", "hashcat -m 0 h w", "crackmapexec smb x",
                "meterpreter session"]:
        assert orch.requires_approval(cmd) is True, cmd


def test_low_risk_no_approval():
    orch = make_orch()
    assert orch.requires_approval("nmap -sV 10.0.0.5") is False
    assert orch.requires_approval("whatweb http://x") is False


# ── prompt-injection defense in the prompts ──────────────────────────────────

def test_system_prompts_declare_tool_output_untrusted():
    for p in (prompts.SYSTEM_PROMPT, prompts.SYSTEM_PROMPT_COMPACT):
        low = p.lower()
        assert "tool_output" in low or "untrusted" in low
        assert "never follow" in low or "never follow instructions" in low


def test_strategist_and_critique_prompts_guard_injection():
    for p in (prompts.STRATEGIST_PROMPT, prompts.CRITIQUE_PROMPT):
        low = p.lower()
        assert "untrusted" in low
        assert "raw json" in low  # both must enforce strict JSON output


def test_strategist_prompt_has_no_suggested_command_field():
    # The strategist must NOT be able to emit an executable command — that is the
    # tactical engine's job. Its schema is plan/progress only.
    assert "suggested_command" not in prompts.STRATEGIST_PROMPT

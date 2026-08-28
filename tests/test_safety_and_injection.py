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
    # Each command contains a genuine high-risk keyword; all must require approval.
    for cmd in [
        "hydra -l root ssh://x",          # hydra (word boundary)
        "msfconsole -x 'use exploit/x'",  # msfconsole (exact) + exploit (word)
        "sudo -l",                         # sudo (word boundary)
        "hashcat -m 0 h w",               # hashcat (word boundary)
        "crackmapexec smb x",             # crackmapexec (exact substr)
        "meterpreter session",             # meterpreter (exact substr)
    ]:
        assert orch.requires_approval(cmd) is True, f"Expected True for: {cmd!r}"


def test_upload_and_webshell_commands_are_high_risk():
    orch = make_orch()
    for cmd in [
        "curl -s -T /tmp/shell.php ftp://10.0.0.5/",
        "echo payload > /tmp/shell.php; curl http://10.0.0.5/shell.php?c=id",
        "mysql -e \"SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/var/www/html/shell.php'\"",
    ]:
        assert orch.requires_approval(cmd) is True


def test_low_risk_no_approval():
    orch = make_orch()
    assert orch.requires_approval("nmap -sV 10.0.0.5") is False
    assert orch.requires_approval("whatweb http://x") is False


def test_no_false_positives_on_recon_tools():
    """Fix #4: word-boundary matching must not block recon tools whose names
    contain high-risk substrings (e.g. 'su' in 'subfinder')."""
    orch = make_orch()
    false_positive_candidates = [
        "subfinder -d example.com",           # 'su' inside 'subfinder'
        "gobuster dir -u http://x -x php",    # no match
        "curl -sk https://x/password-reset",  # 'password' not in list
        "nmap --script ssh-auth-methods 10.x",# 'su' → no match (word boundary)
        "nuclei -u https://x/assume-role",    # 'su' inside 'assume'
    ]
    for cmd in false_positive_candidates:
        assert orch.requires_approval(cmd) is False, f"False positive for: {cmd!r}"


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

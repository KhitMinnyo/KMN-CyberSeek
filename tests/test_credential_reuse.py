"""Tests for the deterministic credential-reuse trigger. When a credential is
found it must be sprayed across OTHER services automatically (not left to the LLM
to remember), skipping the origin service, deduped, and shell-safe.

Also covers Fix #1: john _CRED_PATTERNS must have 2 groups so match.group(2) works."""

import re
from core.orchestrator import _CRED_PATTERNS
from tests._helpers import make_orch, make_session, svc


def _sess():
    return make_session(services=[
        svc(22, "ssh"),
        svc(80, "http"),
        svc(445, "smb"),
        svc(3306, "mysql"),
    ])


def test_password_reuse_dispatched_to_other_services():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    cred = {"username": "admin", "secret": "S3cr3t!", "secret_type": "password",
            "service": "http", "host": "10.0.0.5", "reused": False}
    orch._dispatch_credential_reuse(s.session_id, cred)

    joined = " | ".join(orch.queued)
    assert cred["reused"] is True
    assert "ssh" in joined and "admin@10.0.0.5" in joined
    assert "crackmapexec smb 10.0.0.5" in joined
    assert "mysql -h 10.0.0.5" in joined


def test_origin_service_skipped():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    cred = {"username": "admin", "secret": "pw", "secret_type": "password",
            "service": "http", "host": "10.0.0.5", "reused": False}
    orch._dispatch_credential_reuse(s.session_id, cred)
    # no http basic-auth curl back against the origin http service
    assert not any(q.startswith("curl") and "http://10.0.0.5/" in q for q in orch.queued)


def test_dedup_second_dispatch_noop():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    cred = {"username": "admin", "secret": "pw", "secret_type": "password",
            "service": "http", "host": "10.0.0.5", "reused": False}
    orch._dispatch_credential_reuse(s.session_id, cred)
    n = len(orch.queued)
    orch._dispatch_credential_reuse(s.session_id, cred)
    assert len(orch.queued) == n


def test_hash_uses_pass_the_hash_only():
    orch = make_orch()
    s = make_session(services=[svc(445, "smb"), svc(5985, "winrm"), svc(22, "ssh")])
    orch.sessions[s.session_id] = s
    cred = {"username": "svc", "secret": "aad3b435b51404eeaad3b435b51404ee",
            "secret_type": "hash", "service": "ldap", "host": "10.0.0.5", "reused": False}
    orch._dispatch_credential_reuse(s.session_id, cred)
    assert orch.queued, "expected pass-the-hash commands"
    assert all("-H " in q for q in orch.queued)
    # SSH cannot use an NTLM hash — must not appear
    assert not any(q.startswith("sshpass") for q in orch.queued)


def test_cred_patterns_all_have_two_groups():
    """Fix #1: every pattern in _CRED_PATTERNS must have exactly 2 capture groups
    (username, secret) so match.group(2) never raises IndexError."""
    for pattern in _CRED_PATTERNS:
        assert pattern.groups == 2, (
            f"Pattern {pattern.pattern!r} has {pattern.groups} group(s); expected 2"
        )


def test_john_pattern_extracts_hash_and_password():
    """Fix #1: verify the john --show pattern actually captures (hash, cracked_pw)."""
    john_output = "5f4dcc3b5aa765d61d8327deb882cf99 (password123)"
    john_pattern = _CRED_PATTERNS[-2]   # john is second-to-last
    m = john_pattern.search(john_output)
    assert m is not None, "john pattern should match"
    assert m.group(1) == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert m.group(2) == "password123"


def test_secret_is_shell_quoted():
    orch = make_orch()
    s = make_session(services=[svc(22, "ssh")])
    orch.sessions[s.session_id] = s
    cred = {"username": "admin", "secret": "pa ss'w$rd", "secret_type": "password",
            "service": "http", "host": "10.0.0.5", "reused": False}
    orch._dispatch_credential_reuse(s.session_id, cred)
    # the raw unquoted secret must not appear verbatim (it was shlex.quoted)
    assert orch.queued
    assert "pa ss'w$rd" not in orch.queued[0]

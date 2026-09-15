"""Regression tests for the "pro-level pentester" gap analysis (2026-09-15,
fourth pass): fixes aimed at the 5 bars the user set for calling KMN-CyberSeek
a professional-style autonomous pentester --

  1. discovery -> exploitation -> post-ex -> closure repeatable
  2. evidence/claim precision ("host compromised" != "N services exploited")
  3. state-aware reasoning exposed in the report
  4. uncertainty marked unverified/potential instead of fabricated confidence
  5. full audit trail: raw command -> evidence -> finding -> access path -> impact

Covers:
  - compromise-evidence dedup fingerprint was host-blind -> a second host
    compromised via the identical service/port/privilege combo was silently
    dropped, undercounting hosts compromised
  - compromise evidence now carries command_id (FK to the commands log) and a
    best-effort pivoted_from access-path lead
  - add_vulnerability() defaulted EVERY finding's status to "confirmed"
    before _vuln_validate.validate() ever ran, defeating its own
    confirmed-vs-potential logic for NVD/Vulners keyword/version matches
  - vulnerability findings now carry source_command when the caller has one
  - get_session_report() summary now exposes hosts_compromised (distinct) and
    pending_approval_count, separate from the raw evidence-entry count
  - credentials now carry a validated flag, set only when the credential was
    actually used in an executed command with no auth-failure signal
  - the markdown report surfaces a closure checklist, distinct-host counts,
    access-path/pivot info, and credential provenance columns
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from tests._helpers import make_orch, make_session, svc


def _run(coro):
    return asyncio.run(coro)


# ── Fix: host-blind dedup fingerprint undercounted hosts compromised ───────

def test_capture_exploitation_evidence_dedup_includes_host():
    """Two DIFFERENT hosts compromised via the identical service/port/
    privilege combo must both get their own evidence entry. Before this fix
    the dedup fingerprint omitted host, so the second host's evidence was
    silently dropped as a 'duplicate' -- undercounting how many hosts were
    actually owned (the mirror-image bug of the earlier over-counting one)."""
    orch = make_orch()
    s = make_session(services=[svc(445, "smb", host="10.0.0.5"), svc(445, "smb", host="10.0.0.6")])
    orch.sessions[s.session_id] = s
    orch.add_evidence = lambda *a, **k: None

    output = "pwn3d! NT AUTHORITY\\SYSTEM"

    orch._capture_exploitation_evidence(
        s, "crackmapexec smb 10.0.0.5 -u a -p b -x whoami", output,
        [svc(445, "smb", host="10.0.0.5")], ["pwn3d"],
    )
    orch._capture_exploitation_evidence(
        s, "crackmapexec smb 10.0.0.6 -u a -p b -x whoami", output,
        [svc(445, "smb", host="10.0.0.6")], ["pwn3d"],
    )

    assert len(s.compromise_evidence) == 2
    assert {e["host"] for e in s.compromise_evidence} == {"10.0.0.5", "10.0.0.6"}


def test_capture_exploitation_evidence_still_dedupes_same_host():
    """Regression guard: the SAME host/service/port/privilege confirmed twice
    must still collapse to one entry -- only host was missing from the
    fingerprint, not the dedup behaviour itself."""
    orch = make_orch()
    s = make_session(services=[svc(445, "smb", host="10.0.0.5")])
    orch.sessions[s.session_id] = s
    orch.add_evidence = lambda *a, **k: None

    output = "pwn3d! NT AUTHORITY\\SYSTEM"
    services = [svc(445, "smb", host="10.0.0.5")]

    orch._capture_exploitation_evidence(s, "cme smb 10.0.0.5 -u a -p b -x whoami", output, services, ["pwn3d"])
    orch._capture_exploitation_evidence(s, "cme smb 10.0.0.5 -u a -p b -x whoami", output, services, ["pwn3d"])

    assert len(s.compromise_evidence) == 1


# ── Fix: evidence now carries a command_id FK back to the commands log ─────

def test_capture_exploitation_evidence_records_command_id():
    orch = make_orch()
    s = make_session(services=[svc(445, "smb")])
    orch.sessions[s.session_id] = s
    orch.add_evidence = lambda *a, **k: None

    orch._capture_exploitation_evidence(
        s, "cme smb 10.0.0.5 -u a -p b -x whoami", "pwn3d! NT AUTHORITY\\SYSTEM",
        [svc(445, "smb")], ["pwn3d"], command_id="abc123-def456",
    )
    assert s.compromise_evidence[0]["command_id"] == "abc123-def456"


# ── Fix: best-effort pivoted_from access-path lead ──────────────────────────

def test_capture_exploitation_evidence_detects_pivot_from_other_host():
    """A compromise reached using a credential originally captured on a
    DIFFERENT host is an access-path lead worth recording -- e.g. a hash
    dumped on Host A used to pass-the-hash into Host B."""
    orch = make_orch()
    s = make_session(services=[svc(445, "smb", host="10.0.0.6")])
    s.credentials = [{
        "username": "admin", "secret": "aad3b435b51404eeaad3b435b51404ee",
        "secret_type": "hash", "host": "10.0.0.5", "service": "smb",
    }]
    orch.sessions[s.session_id] = s
    orch.add_evidence = lambda *a, **k: None

    command = "crackmapexec smb 10.0.0.6 -u admin -H aad3b435b51404eeaad3b435b51404ee -x whoami"
    orch._capture_exploitation_evidence(
        s, command, "pwn3d! NT AUTHORITY\\SYSTEM", [svc(445, "smb", host="10.0.0.6")], ["pwn3d"],
    )

    assert s.compromise_evidence[0]["pivoted_from"] == {"host": "10.0.0.5", "service": "smb"}


def test_capture_exploitation_evidence_no_pivot_when_credential_same_host():
    """No false pivot claim when the credential used originated on the SAME
    host being compromised -- that's direct access, not a pivot."""
    orch = make_orch()
    s = make_session(services=[svc(445, "smb", host="10.0.0.5")])
    s.credentials = [{
        "username": "admin", "secret": "aad3b435b51404eeaad3b435b51404ee",
        "secret_type": "hash", "host": "10.0.0.5", "service": "smb",
    }]
    orch.sessions[s.session_id] = s
    orch.add_evidence = lambda *a, **k: None

    command = "crackmapexec smb 10.0.0.5 -u admin -H aad3b435b51404eeaad3b435b51404ee -x whoami"
    orch._capture_exploitation_evidence(
        s, command, "pwn3d! NT AUTHORITY\\SYSTEM", [svc(445, "smb", host="10.0.0.5")], ["pwn3d"],
    )

    assert s.compromise_evidence[0]["pivoted_from"] is None


# ── Fix: add_vulnerability() pre-empted its own confirmed/potential logic ──

def _vuln_orch():
    orch = make_orch()
    orch._save_vulnerability_db = lambda *a, **k: None
    orch._upsert_asset = lambda *a, **k: "node"
    orch._link_assets = lambda *a, **k: None
    return orch


def test_add_vulnerability_nvd_source_defaults_to_potential():
    """An NVD/Vulners finding is a keyword/version-database match, not proof
    of exploitation. Before this fix, add_vulnerability() defaulted status to
    'confirmed' BEFORE _vuln_validate.validate() ran, and validate()'s own
    downgrade check ('if status != confirmed: downgrade') then saw the
    already-'confirmed' value and never fired -- silently overstating every
    database-lookup finding's certainty."""
    orch = _vuln_orch()
    s = make_session()
    orch.sessions[s.session_id] = s

    record = orch.add_vulnerability(s.session_id, {
        "host": "10.0.0.5", "port": 443, "service": "https",
        "service_version": "OpenSSL 3.0.2",
        "name": "CVE-2024-12345 keyword match", "source_tool": "nvd",
        "cve_ids": ["CVE-2024-12345"],
    })
    assert record["status"] == "potential"


def test_add_vulnerability_nmap_vuln_script_defaults_to_confirmed():
    """An nmap NSE vuln-script hit is an actual on-host probe -- unchanged
    behaviour: it should still default to 'confirmed'."""
    orch = _vuln_orch()
    s = make_session()
    orch.sessions[s.session_id] = s

    record = orch.add_vulnerability(s.session_id, {
        "host": "10.0.0.5", "port": 80, "service": "http",
        "name": "Apache directory traversal", "source_tool": "nmap-vuln-script",
    })
    assert record["status"] == "confirmed"


def test_add_vulnerability_stores_source_command():
    """A finding sourced from a specific nmap NSE invocation should keep the
    exact command that produced it, so a reader can trace finding -> scan
    without a fuzzy host/port/source_tool guess."""
    orch = _vuln_orch()
    s = make_session()
    orch.sessions[s.session_id] = s

    record = orch.add_vulnerability(s.session_id, {
        "host": "10.0.0.5", "port": 80, "service": "http",
        "name": "Some finding", "source_tool": "nmap-vuln-script",
        "source_command": "nmap -Pn -sV -T4 -p 80 --script vuln 10.0.0.5",
    })
    assert record["source_command"] == "nmap -Pn -sV -T4 -p 80 --script vuln 10.0.0.5"


# ── Fix: report summary now distinguishes hosts compromised from evidence
#         entries, and exposes pending-approval count for the closure check ─

def test_get_session_report_summary_hosts_compromised_and_pending_approval():
    orch = make_orch()
    s = make_session()
    s.compromise_evidence = [
        {"host": "10.0.0.5", "service": "smb", "port": 445, "privilege": "SYSTEM"},
        {"host": "10.0.0.5", "service": "http", "port": 80, "privilege": "SYSTEM"},
        {"host": "10.0.0.6", "service": "smb", "port": 445, "privilege": "SYSTEM"},
    ]
    orch.sessions[s.session_id] = s
    orch.pending_commands = {
        "c1": {"session_id": s.session_id, "status": "pending"},
        "c2": {"session_id": s.session_id, "status": "completed"},
        "c3": {"session_id": "other-session", "status": "pending"},
    }
    orch.get_session_events = lambda sid: []
    orch.get_session_jobs = lambda sid: []

    report = orch.get_session_report(s.session_id)
    # 3 evidence entries, but only 2 DISTINCT hosts.
    assert report["summary"]["hosts_compromised"] == 2
    assert report["summary"]["pending_approval_count"] == 1


# ── Fix: credential "validated" flag ────────────────────────────────────────

def _reuse_execute_setup(orch, s, cred, output, success):
    orch._last_activity = {}
    orch._execution_gate = MagicMock(return_value=None)
    orch._mark_services_in_progress = MagicMock()
    orch._pick_credential = MagicMock(return_value=cred)
    orch._inject_credentials = lambda cmd, session, cred=None: cmd
    orch._downsize_wordlists = lambda cmd: cmd
    orch._execute_prepared_command = AsyncMock(return_value={
        "command_id": "c1", "command": "ssh -l admin 10.0.0.5", "output": output,
        "error": "", "return_code": 0 if success else 1, "success": success,
    })
    orch._track_task = MagicMock()


def test_credential_marked_validated_after_successful_reuse():
    """A credential that gets injected into a command and produces NO
    auth-failure signal must be marked validated=True -- the same
    deterministic success criterion the rotation logic itself already
    trusts. Before this fix, credentials had no way to distinguish 'scraped
    from tool output, never re-tested' from 'confirmed working'."""
    orch = make_orch()
    s = make_session(services=[svc(22, "ssh")])
    cred = {"username": "admin", "secret": "pw1", "secret_type": "password",
            "host": "10.0.0.5", "validated": False}
    s.credentials = [cred]
    orch.sessions[s.session_id] = s
    _reuse_execute_setup(orch, s, cred, "uid=0(root)", success=True)

    marked = []
    orch._mark_credential_validated = lambda sid, c: marked.append((sid, c.get("username")))

    result = _run(orch.execute_command(s.session_id, "ssh -l admin 10.0.0.5"))

    assert result["success"] is True
    assert marked == [(s.session_id, "admin")]


def test_credential_not_marked_validated_after_auth_failure():
    """No false 'validated' claim when the injected credential was actually
    rejected -- an auth-failure signal must NOT mark it confirmed working."""
    orch = make_orch()
    s = make_session(services=[svc(22, "ssh")])
    cred = {"username": "admin", "secret": "wrongpw", "secret_type": "password",
            "host": "10.0.0.5", "validated": False}
    s.credentials = [cred]
    orch.sessions[s.session_id] = s
    _reuse_execute_setup(orch, s, cred, "Permission denied (publickey,password)", success=False)

    marked = []
    orch._mark_credential_validated = lambda sid, c: marked.append((sid, c.get("username")))

    _run(orch.execute_command(s.session_id, "ssh -l admin 10.0.0.5"))

    assert marked == []


# ── Fix: markdown report — closure checklist, distinct-host count,
#         access-path/pivot, credential provenance ─────────────────────────

def test_markdown_report_closure_checklist_and_distinct_host_count():
    from core.report_generator import generate_markdown_report
    session_report = {
        "session": {
            "session_id": "s1", "target_ip": "10.0.0.5", "target_domain": "",
            "created_at": "2026-09-15T02:25:17", "status": "completed",
            "current_stage": "credential_reuse",
            "compromise_evidence": [
                {"service": "http", "port": 80, "host": "10.0.0.5", "privilege": "root/SYSTEM",
                 "command": "whoami", "signal": "windows-rce", "proof": "nt authority\\system",
                 "command_id": "abcdef1234567890", "pivoted_from": None},
                {"service": "smb", "port": 445, "host": "10.0.0.5", "privilege": "SYSTEM",
                 "command": "cme smb 10.0.0.5", "signal": "pwn3d",
                 "proof": "Pwn3d!", "command_id": "1122334455667788",
                 "pivoted_from": {"host": "10.0.0.6", "service": "smb"}},
            ],
            "strategic_plan": [], "operator_instructions": [], "reflections": [],
            "exhausted_services": ["smb:smbclient_enum"],
            "objective_complete": True,
            "objective_progress": 1.0,
        },
        "discovered_services": [], "discovered_hosts": [],
        "vulnerabilities": [],
        "commands_executed": [
            {"command": "whoami", "success": True, "timestamp": "2026-09-15T02:26:00",
             "output": "nt authority\\system", "command_id": "abcdef1234567890"},
        ],
        "credentials": [
            {"username": "admin", "secret": "hunter2", "secret_type": "password",
             "service": "smb", "host": "10.0.0.6", "validated": True,
             "source_command": "hydra -l admin -P rockyou.txt smb://10.0.0.6",
             "discovered_at": "2026-09-15T02:20:00"},
        ],
        "ai_decisions": [],
        "summary": {"pending_approval_count": 0},
    }
    out_path = generate_markdown_report(session_report)
    md = open(out_path, encoding="utf-8").read()

    # Host-count vs evidence-entry-count distinction (2 entries, 1 distinct host).
    assert "distinct host(s) compromised" in md
    assert "2 piece(s) of exploitation evidence" in md

    # Closure checklist present, and readiness reflects the completed state.
    assert "Engagement Closure Checklist" in md
    assert "READY TO CLOSE" in md

    # Access path / pivot and command-id cross-reference.
    assert "via 10.0.0.6" in md
    assert "1122334" in md  # short command-id fragment
    assert "abcdef12" in md  # command-id shown on the matching commands-log entry

    # Credential provenance columns.
    assert "Validated" in md
    assert "10.0.0.6" in md

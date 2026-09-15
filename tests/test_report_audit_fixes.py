"""Regression tests for bugs found auditing a real AI-generated final report
against its own embedded command log (session WinServer_a7a14e58, 2026-09-15):

  - credential extraction  -> loose regexes mistook English prose and
                               `findstr`-style "<path>: <line>" output for
                               real username/password pairs
  - credential injection   -> a bogus credential rewrote an unrelated file
                               path ("mysql" as a directory name) instead of
                               only a real `mysql` CLI invocation
  - compromise detection   -> the AI's own halt-banner echo, which merely
                               *quotes* "nt authority\\system" in its own
                               command text, was misread as fresh proof
  - vulnerability parsing  -> a raw `vulners` NSE table row leaked into the
                               finding's "name" field verbatim
  - vulnerability risk     -> a KEV-confirmed finding stayed "unknown" risk
                               because its source never printed a State: line
  - operator steering      -> "Skip last steps & end now" was only advisory
                               text for the next AI turn, not a real stop
"""

import asyncio
from unittest.mock import AsyncMock

from core.orchestrator import _is_windows_rce_proof
from core.scanner import Scanner
from tests._helpers import make_orch, make_session


def _run(coro):
    return asyncio.run(coro)


def _cred_orch():
    orch = make_orch()
    orch._save_credential_db = lambda *a, **k: None
    orch._dispatch_credential_reuse = lambda *a, **k: None
    return orch


# ── Bug A: credential extraction ────────────────────────────────────────────

def test_extract_credentials_rejects_english_prose_username_and_password():
    """tomcat-users.xml's own comment - '...the username and password are
    arbitrary...' - must not be read as user='and' secret='are'."""
    orch = _cred_orch()
    s = make_session(); orch.sessions[s.session_id] = s
    output = (
        "<!--\n"
        "  NOTE:  By default, no user is included in the \"manager-gui\" role required\n"
        "  to operate the \"/manager/html\" web application.  If you wish to use this app,\n"
        "  you must define such a user - the username and password are arbitrary. It is\n"
        "  strongly recommended that you do NOT use one of the users in the commented out\n"
        "-->\n"
    )
    orch._extract_and_store_credentials(s.session_id, "type C:\\xampp\\tomcat\\conf\\tomcat-users.xml", output)
    assert s.credentials == []


def test_extract_credentials_rejects_findstr_path_prefixed_output():
    """`findstr /s` prefixes every matched line with '<filepath>:'. A line
    like 'C:\\xampp\\passwords.txt:   ...(users and passwords).' must not be
    read as username='C:\\xampp\\passwords.txt:' secret='means no password!'."""
    orch = _cred_orch()
    s = make_session(); orch.sessions[s.session_id] = s
    output = (
        "C:\\xampp\\passwords.txt:### XAMPP Default Passwords ###\n"
        "C:\\xampp\\passwords.txt:   Password:\n"
        "C:\\xampp\\passwords.txt:   (means no password!)\n"
        "C:\\xampp\\passwords.txt:   Please do not forget to refresh the WEBDAV "
        "authentification (users and passwords).\n"
        "C:\\xampp\\readme_en.txt:(3) MySQL starts with standard values for the "
        "user id and the password. The preset user id is \"root\", the password "
        "is \"\" (= no password).\n"
    )
    orch._extract_and_store_credentials(s.session_id, "findstr /s /i /c:\"password\" C:\\xampp\\*.txt", output)
    assert s.credentials == []


def test_extract_credentials_still_captures_real_hydra_hit():
    """Sanity check: tightening the regexes must not break real tool output."""
    orch = _cred_orch()
    s = make_session(); orch.sessions[s.session_id] = s
    output = "[22][ssh] host: 10.0.0.5   login: admin   password: hunter2"
    orch._extract_and_store_credentials(s.session_id, "hydra -L users.txt -P pass.txt ssh://10.0.0.5", output)
    assert len(s.credentials) == 1
    assert s.credentials[0]["username"] == "admin"
    assert s.credentials[0]["secret"] == "hunter2"


def test_extract_credentials_still_captures_structured_nmap_style():
    """The tightened nmap-style pattern must still match a real, delimited
    'username: X password: Y' finding, just not bare prose."""
    orch = _cred_orch()
    s = make_session(); orch.sessions[s.session_id] = s
    output = "Found credentials -> username: admin password: sup3rsecret"
    orch._extract_and_store_credentials(s.session_id, "curl http://10.0.0.5/login", output)
    assert len(s.credentials) == 1
    assert s.credentials[0]["username"] == "admin"
    assert s.credentials[0]["secret"] == "sup3rsecret"


# ── Bug B: credential injection corrupting file paths ──────────────────────

def test_inject_credentials_does_not_corrupt_mysql_path_component():
    """A bogus 'and'/'are' credential must not turn a plain file-read command
    into a mangled path: `type C:\\xampp\\mysql\\bin\\my.ini` must survive
    untouched (it has no `mysql` CLI invocation to rewrite)."""
    orch = make_orch()
    s = make_session()
    s.credentials = [{"username": "and", "secret": "are", "secret_type": "password"}]
    command = "type C:\\xampp\\mysql\\bin\\my.ini"
    result = orch._inject_credentials(command, s)
    assert result == command


def test_inject_credentials_still_rewrites_real_mysql_invocation():
    """A genuine `mysql` CLI call (command starts with/contains the word as
    an actual invocation, not a path segment) must still get credentials."""
    orch = make_orch()
    s = make_session()
    s.credentials = [{"username": "root", "secret": "toor", "secret_type": "password"}]
    command = "mysql -h 10.0.0.5 -P 3306 -e 'show databases;'"
    result = orch._inject_credentials(command, s)
    assert "-u root" in result and "-ptoor" in result


# ── Bug D: self-referential halt-echo mistaken for compromise proof ────────

def test_is_windows_rce_proof_rejects_self_referential_halt_echo():
    """The AI's own closing echo/halt banner quotes 'nt authority\\system' in
    its OWN command text - that must not count as evidence retrieved from
    the target."""
    banner = (
        "echo '[KMN-CYBERSEEK] RUN TERMINATED | TARGET: 192.168.100.194 | "
        "OBJECTIVE ACHIEVED: SYSTEM (nt authority\\system) | NO FURTHER TARGET TRAFFIC'"
    )
    output = (
        "[KMN-CYBERSEEK] RUN TERMINATED | TARGET: 192.168.100.194 | "
        "OBJECTIVE ACHIEVED: SYSTEM (nt authority\\system) | NO FURTHER TARGET TRAFFIC"
    )
    assert _is_windows_rce_proof(banner, output) is False


def test_is_windows_rce_proof_still_accepts_real_whoami_evidence():
    """Regression: the self-referential guard must not blind real detection -
    a whoami/webshell command whose OUTPUT (not its own text) proves SYSTEM
    still counts."""
    assert _is_windows_rce_proof("whoami", "nt authority\\system") is True
    assert _is_windows_rce_proof(
        "curl -s 'http://10.0.0.5/cmd.php?cmd=whoami'", "nt authority\\system"
    ) is True


# ── Bug E: raw vulners.com table row leaking into the finding name ─────────

def test_parse_vulnerability_output_sanitizes_raw_vulners_row():
    nse_output = (
        "PORT   STATE SERVICE\n"
        "21/tcp open  ftp\n"
        "| some-ssl-script: \n"
        "|   VULNERABLE:\n"
        "|     1254\t7.5\thttps://vulners.com/vulnerlab/1254\t*EXPLOIT*\n"
        "|     State: VULNERABLE\n"
        "|     References: CVE-2014-0160 CVE-2014-0224\n"
    )
    scanner = Scanner.__new__(Scanner)
    findings = scanner._parse_vulnerability_output(nse_output)
    assert len(findings) == 1
    name = findings[0]["name"]
    assert "\t" not in name
    assert "vulners.com" not in name
    # Falls back to the CVE IDs already extracted from the same text.
    assert "CVE-2014-0160" in name and "CVE-2014-0224" in name


def test_parse_vulnerability_output_leaves_normal_names_alone():
    """Sanity check: a real 'VULNERABLE: <description>' name (prose on the
    same line, no raw table row) must pass through unchanged."""
    nse_output = (
        "| some-vuln-script: \n"
        "|   VULNERABLE: XML External Entity injection allows remote code execution\n"
        "|     State: VULNERABLE\n"
    )
    scanner = Scanner.__new__(Scanner)
    findings = scanner._parse_vulnerability_output(nse_output)
    assert len(findings) == 1
    assert findings[0]["name"] == "XML External Entity injection allows remote code execution"


# ── Bug E (risk tally): KEV-confirmed finding must not stay "unknown" ──────

def test_enrich_and_prioritize_cves_promotes_kev_finding_off_unknown_risk():
    import core.orchestrator as orch_mod

    orch = make_orch()
    s = make_session()
    s.vulnerabilities = [{
        "host": s.target_ip, "port": 21, "service": "ftp",
        "name": "CVE-2014-0160", "cve_ids": ["CVE-2014-0160"],
        "risk_level": "unknown", "source_tool": "nmap-vuln-script",
    }]
    orch.sessions[s.session_id] = s

    async def _fake_enrich(findings):
        for f in findings:
            f["kev"] = True
            f["epss"] = 0.97

    _orig_enrich = orch_mod.cve_lookup.enrich_findings
    _orig_resolve = orch_mod._msf_resolver.resolve_many
    orch_mod.cve_lookup.enrich_findings = _fake_enrich
    orch_mod._msf_resolver.resolve_many = AsyncMock(return_value={})
    try:
        _run(orch._enrich_and_prioritize_cves(s.session_id))
    finally:
        orch_mod.cve_lookup.enrich_findings = _orig_enrich
        orch_mod._msf_resolver.resolve_many = _orig_resolve

    assert s.vulnerabilities[0]["risk_level"] == "high"


# ── Steer "stop now" must hard-cancel, not just advise ──────────────────────

def test_steer_stop_instruction_hard_cancels_active_session():
    """'Skip last steps & end now' (the operator's actual wording) must
    trigger a real cancel_session(), not just get queued as advisory text
    for the AI's next turn - which is what let the loop keep running for
    many more commands after the operator asked it to stop."""
    orch = _cred_orch()
    s = make_session()
    s.status = "executing"
    orch.sessions[s.session_id] = s
    orch.cancel_session = AsyncMock(return_value={"status": "success"})

    async def _t():
        result = orch.add_operator_instruction(s.session_id, "Skip last steps & end now")
        await asyncio.sleep(0)  # let the scheduled cancel task run
        return result

    result = _run(_t())
    assert result.get("stopping") is True
    orch.cancel_session.assert_called_once_with(s.session_id)


def test_steer_stop_instruction_hard_cancels_from_needs_operator_too():
    """Previously ANY instruction sent while status=='needs_operator' reset
    the full auto-pivot/stagnation budget and resumed the loop - even one
    that explicitly asked it to stop. Must cancel instead of resuming."""
    orch = _cred_orch()
    s = make_session()
    s.status = "needs_operator"
    orch.sessions[s.session_id] = s
    orch.cancel_session = AsyncMock(return_value={"status": "success"})
    orch._analyze_with_ai = AsyncMock()

    async def _t():
        result = orch.add_operator_instruction(s.session_id, "please stop the engagement now")
        await asyncio.sleep(0)
        return result

    result = _run(_t())
    assert result.get("stopping") is True
    orch.cancel_session.assert_called_once_with(s.session_id)
    orch._analyze_with_ai.assert_not_called()
    # Status must not have been silently flipped back to "analyzing".
    assert s.status == "needs_operator"


def test_steer_ordinary_tactical_instruction_is_not_treated_as_a_stop():
    """A normal redirect ('focus on port 8080 next') must remain advisory -
    no cancel_session call, no 'stopping' flag."""
    orch = _cred_orch()
    s = make_session()
    s.status = "executing"
    orch.sessions[s.session_id] = s
    orch.cancel_session = AsyncMock(return_value={"status": "success"})

    result = orch.add_operator_instruction(s.session_id, "focus on port 8080 next")
    assert "stopping" not in result
    orch.cancel_session.assert_not_called()
    assert s.operator_instructions[-1] == "focus on port 8080 next"

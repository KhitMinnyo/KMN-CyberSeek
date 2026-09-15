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


# ── Second pass: issues flagged by an independent review of the same report ─
# (a) service "exploited" state cascading to every service a summary/closing
#     echo command's own text happens to mention, not just the one it tested
# (b) "objective achieved" (a foothold) vs "engagement complete" (assessment
#     coverage finished) were tracked internally but never surfaced in the
#     report, reading as if the AI were looping pointlessly after SYSTEM

def test_settle_service_states_exploit_only_promotes_the_service_actually_tested():
    """A 'final summary' echo command that recites every discovered port in
    its own text (e.g. '... & echo ftp:21 ssh:22 http:80 & whoami') must not
    get every one of those services marked 'exploited' off a single webshell
    whoami call that only actually touched one of them."""
    from tests._helpers import svc as _svc
    orch = make_orch()
    s = make_session(services=[_svc(21, "ftp"), _svc(22, "ssh"), _svc(80, "http")])
    orch.sessions[s.session_id] = s
    orch.add_evidence = lambda *a, **k: None

    command = (
        "curl -s -G 'http://10.0.0.5/cmd.php' --data-urlencode "
        "'cmd=echo ===SERVICES_CONFIRMED=== & echo ftp:21 ssh:22 http:80 & whoami'"
    )
    output = "===SERVICES_CONFIRMED===\nftp:21 ssh:22 http:80\nnt authority\\system"

    orch._settle_service_states(s, command, output, success=True)

    exploited = [sv for sv in s.discovered_services if sv.get("test_state") == "exploited"]
    assert len(exploited) == 1, f"expected exactly 1 service exploited, got {exploited}"
    # Only one compromise entry, not one per referenced service.
    assert len(s.compromise_evidence) == 1


def test_settle_service_states_normal_multi_service_scan_is_unaffected():
    """Sanity check: a normal (non-exploit) multi-service scan must still
    settle every service it touches to 'tested' - the fix only narrows the
    'exploited' case."""
    from tests._helpers import svc as _svc
    orch = make_orch()
    s = make_session(services=[_svc(21, "ftp"), _svc(22, "ssh"), _svc(80, "http")])
    orch.sessions[s.session_id] = s

    orch._settle_service_states(s, "nmap -p 21,22,80 -sV 10.0.0.5", "21/tcp open ftp\n22/tcp open ssh\n80/tcp open http", success=True)

    tested = [sv for sv in s.discovered_services if sv.get("test_state") == "tested"]
    assert len(tested) == 3


# ── "Objective achieved" vs "engagement complete" surfaced in the report ──

def test_validate_report_findings_is_identity_safe_on_clean_data():
    """Sanity check: a report with only genuine findings must pass through
    _validate_report_findings() unchanged."""
    import core.orchestrator as orch_mod
    report = {
        "session": {"session_id": "s1", "compromise_evidence": [
            {"service": "http", "port": 80, "command": "curl .../cmd.php?cmd=whoami",
             "proof": "nt authority\\system", "privilege": "root/SYSTEM"},
        ]},
        "credentials": [{"username": "admin", "secret": "hunter2"}],
        "vulnerabilities": [{"name": "Apache Struts RCE", "cve_ids": ["CVE-2017-5638"]}],
    }
    out = orch_mod._validate_report_findings(report)
    assert out["credentials"] == report["credentials"]
    assert out["vulnerabilities"][0]["name"] == "Apache Struts RCE"
    assert len(out["session"]["compromise_evidence"]) == 1


def test_validate_report_findings_drops_junk_and_self_referential_entries():
    import core.orchestrator as orch_mod
    report = {
        "session": {"session_id": "s1", "compromise_evidence": [
            {"service": "http", "port": 80, "command": "curl .../cmd.php?cmd=whoami",
             "proof": "nt authority\\system", "privilege": "root/SYSTEM"},
            {"service": "unknown", "port": "",
             "command": "echo '[KMN] OBJECTIVE ACHIEVED: SYSTEM (nt authority\\system)'",
             "proof": "[KMN] OBJECTIVE ACHIEVED: SYSTEM (nt authority\\system)",
             "privilege": "root/SYSTEM"},
        ]},
        "credentials": [
            {"username": "admin", "secret": "hunter2"},
            {"username": "and", "secret": "are"},
            {"username": "C:\\xampp\\passwords.txt:", "secret": "means no password!"},
        ],
        "vulnerabilities": [
            {"name": "1254\t7.5\thttps://vulners.com/vulnerlab/1254\t*EXPLOIT*",
             "cve_ids": ["CVE-2014-0160"]},
        ],
    }
    out = orch_mod._validate_report_findings(report)
    assert [c["username"] for c in out["credentials"]] == ["admin"]
    assert len(out["session"]["compromise_evidence"]) == 1
    assert out["vulnerabilities"][0]["name"] == "CVE-2014-0160"


def test_markdown_report_surfaces_engagement_status_after_privilege_achieved():
    """A foothold (SYSTEM/root) does not by itself mean the engagement is
    done - the report must say so explicitly instead of just listing a
    compromise count that could otherwise read as contradicting a still-
    running session."""
    from core.report_generator import generate_markdown_report
    session_report = {
        "session": {
            "session_id": "s1", "target_ip": "10.0.0.5", "target_domain": "",
            "created_at": "2026-09-15T02:25:17", "status": "needs_operator",
            "current_stage": "credential_reuse",
            "compromise_evidence": [{"service": "http", "port": 80, "host": "10.0.0.5",
                                      "privilege": "root/SYSTEM", "command": "whoami",
                                      "signal": "windows-rce", "proof": "nt authority\\system"}],
            "strategic_plan": [], "operator_instructions": [], "reflections": [],
            "exhausted_services": [],
            "objective_complete": False,
            "objective_progress": 0.74,
        },
        "discovered_services": [], "discovered_hosts": [],
        "vulnerabilities": [], "commands_executed": [], "credentials": [],
        "ai_decisions": [],
    }
    out_path = generate_markdown_report(session_report)
    md = open(out_path, encoding="utf-8").read()
    assert "Engagement Status" in md
    assert "Privilege Goal: **ACHIEVED**" in md
    assert "Assessment Goal: IN PROGRESS" in md
    assert "74%" in md
    assert "NEEDS OPERATOR INPUT" in md


def test_markdown_report_engagement_status_when_fully_complete():
    from core.report_generator import generate_markdown_report
    session_report = {
        "session": {
            "session_id": "s1", "target_ip": "10.0.0.5", "target_domain": "",
            "created_at": "2026-09-15T02:25:17", "status": "completed",
            "current_stage": "done",
            "compromise_evidence": [{"service": "http", "port": 80, "host": "10.0.0.5",
                                      "privilege": "root/SYSTEM", "command": "whoami",
                                      "signal": "windows-rce", "proof": "nt authority\\system"}],
            "strategic_plan": [], "operator_instructions": [], "reflections": [],
            "exhausted_services": [],
            "objective_complete": True,
            "objective_progress": 1.0,
        },
        "discovered_services": [], "discovered_hosts": [],
        "vulnerabilities": [], "commands_executed": [], "credentials": [],
        "ai_decisions": [],
    }
    out_path = generate_markdown_report(session_report)
    md = open(out_path, encoding="utf-8").read()
    assert "Assessment Goal: **SUFFICIENT**" in md
    assert "Engagement: **COMPLETE**" in md


# ── Third pass: the earlier _settle_service_states fix stopped 14-way
# cascade, but still picked the single service via naive list order, which
# could (and in the audited report, did) credit the wrong service ──────────

def test_settle_service_states_attributes_to_webshell_port_not_lowest_port():
    """Reproduces the actual misattribution in the audited report: a
    'final evidence' summary command run through the http:80 webshell
    (`curl ... -G 'http://<target>/cmd.php' ...`) that also echoes every
    other discovered port in a "services confirmed" banner got credited to
    ftp:21 (the lowest port number / first in the services list) instead
    of http:80 (the webshell it actually ran through)."""
    from tests._helpers import svc as _svc
    orch = make_orch()
    s = make_session(services=[
        _svc(21, "ftp"), _svc(22, "ssh"), _svc(80, "http"), _svc(135, "msrpc"),
    ])
    orch.sessions[s.session_id] = s
    orch.add_evidence = lambda *a, **k: None

    command = (
        "curl -s -m 60 -G 'http://10.0.0.5/cmd.php' --data-urlencode "
        "'cmd=echo ===FINAL_EVIDENCE=== & whoami & echo ===SERVICES_CONFIRMED=== "
        "& echo ftp:21 ssh:22 http:80 msrpc:135'"
    )
    output = "===FINAL_EVIDENCE===\nnt authority\\system\n===SERVICES_CONFIRMED===\nftp:21 ssh:22 http:80 msrpc:135"

    orch._settle_service_states(s, command, output, success=True)

    exploited = [sv for sv in s.discovered_services if sv.get("test_state") == "exploited"]
    assert len(exploited) == 1
    assert exploited[0]["service"] == "http" and exploited[0]["port"] == 80
    assert s.compromise_evidence[0]["service"] == "http"
    assert s.compromise_evidence[0]["port"] == 80


def test_settle_service_states_attributes_to_explicit_probed_port():
    """A webshell command that probes a SPECIFIC other service by explicit
    port (e.g. hitting the Tomcat manager on 127.0.0.1:8080) must credit
    that service, not the webshell's own port or the first in list order."""
    from tests._helpers import svc as _svc
    orch = make_orch()
    s = make_session(services=[_svc(80, "http"), _svc(8080, "http")])
    orch.sessions[s.session_id] = s
    orch.add_evidence = lambda *a, **k: None

    command = (
        "curl -s -m 90 -G 'http://10.0.0.5/cmd.php' --data-urlencode "
        "'cmd=echo ===WHOAMI=== & whoami & echo ===8080MGR=== & "
        "curl -s -m8 http://127.0.0.1:8080/manager/html'"
    )
    output = "===WHOAMI===\nnt authority\\system\n===8080MGR===\n401 Unauthorized"

    orch._settle_service_states(s, command, output, success=True)

    exploited = [sv for sv in s.discovered_services if sv.get("test_state") == "exploited"]
    assert len(exploited) == 1
    assert exploited[0]["port"] == 8080


def test_primary_exploited_service_falls_back_when_genuinely_ambiguous():
    """Two distinct explicit ports probed in one command (e.g. it hits two
    OTHER local services by port) can't be confidently disambiguated -
    must fall back to the first-referenced service rather than guess."""
    import core.orchestrator as orch_mod
    referenced = [{"service": "a", "port": 8009}, {"service": "b", "port": 8080}]
    command = "curl http://127.0.0.1:8009/ ; curl http://127.0.0.1:8080/"
    result = orch_mod._primary_exploited_service(command, referenced)
    assert result == referenced[:1]

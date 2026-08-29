"""Tests for the service test-state machine (untested -> in_progress -> tested ->
exploited) in the orchestrator. Verifies port-precise matching (the key fix over
the old substring heuristic), exploit-signal promotion, and no-downgrade."""

from tests._helpers import make_orch, make_session, svc


def _sess():
    return make_session(services=[
        svc(22, "ssh", version="OpenSSH 7.2"),
        svc(80, "http", version="Apache"),
        svc(8080, "http-proxy"),
        svc(445, "smb", version="Samba"),
    ])


def test_in_progress_on_command_start():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    orch._mark_services_in_progress(s, "nmap -p 22 --script ssh-auth-methods 10.0.0.5")
    assert s.discovered_services[0]["test_state"] == "in_progress"


def test_port_80_not_matched_by_8080():
    """The whole point of port-precise matching: :8080 must not touch port 80."""
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    orch._mark_services_in_progress(s, "gobuster dir -u http://10.0.0.5:8080")
    assert s.discovered_services[1]["test_state"] == "untested"   # port 80
    assert s.discovered_services[2]["test_state"] == "in_progress"  # port 8080


def test_settle_marks_tested_on_success():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    orch._settle_service_states(s, "nmap -p 22 10.0.0.5", "22/tcp open ssh", success=True)
    assert s.discovered_services[0]["test_state"] == "tested"


def test_settle_marks_exploited_on_signal():
    """Fix #5: exploit signals must be specific. 'Pwn3d!' is a real exploit signal."""
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    orch._settle_service_states(
        s, "crackmapexec smb 10.0.0.5 -u x -p y", "[+] Pwn3d!", success=True
    )
    assert s.discovered_services[3]["test_state"] == "exploited"


def test_exploit_signals_no_false_positive_on_web_output():
    """Fix #5: 'password', '200 ok', 'database' must NOT trigger exploited state —
    these appear in normal web enumeration output."""
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    innocent_outputs = [
        "Status: 200 OK [Size: 4096]",                        # gobuster
        "Apache database driven CMS | Password reset here",   # whatweb
        "HTTP/1.1 200 OK\nX-Powered-By: PHP/7.4",             # curl -I
        "Hash: sha256 content-type: text/html",               # nmap header
    ]
    for output in innocent_outputs:
        orch._settle_service_states(s, "curl http://10.0.0.5/80", output, success=True)
    # All services still 'tested', none promoted to 'exploited'
    for svc_obj in s.discovered_services:
        assert svc_obj["test_state"] != "exploited", \
            f"False exploit promotion for output: {output!r}"


def test_msf_banner_does_not_count_as_compromise():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    orch._settle_service_states(
        s,
        "msfconsole -q -x 'use exploit/linux/http/cups_browsed_rce; run'",
        "Payload: linux/x64/meterpreter/reverse_tcp\nExploit running",
        success=True,
    )
    assert s.compromise_evidence == []
    assert all(item.get("test_state") != "exploited" for item in s.discovered_services)


def test_failed_command_does_not_settle():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    orch._mark_services_in_progress(s, "curl http://10.0.0.5:8080")
    orch._settle_service_states(s, "curl http://10.0.0.5:8080", "", success=False)
    assert s.discovered_services[2]["test_state"] == "in_progress"


def test_no_downgrade():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    s.discovered_services[3]["test_state"] = "exploited"
    orch._settle_service_states(s, "smbclient -L //10.0.0.5", "ok", success=True)
    assert s.discovered_services[3]["test_state"] == "exploited"  # stays exploited


def test_service_name_fallback_when_no_port():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    # 'whatweb http://host' has no port -> name match should hit the http service
    orch._mark_services_in_progress(s, "whatweb http://10.0.0.5")
    assert s.discovered_services[1]["test_state"] == "in_progress"


def test_state_counts():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    s.discovered_services[0]["test_state"] = "tested"
    s.discovered_services[3]["test_state"] = "exploited"
    counts = orch._service_state_counts(s)
    assert counts["tested"] == 1 and counts["exploited"] == 1 and counts["untested"] == 2

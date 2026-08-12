"""Regression tests for agentic-loop reliability and exploitation capture.

These lock in the fixes that stop the autonomous loop from silently stalling:
  - empty / missing AI command  -> retry then visible halt (not a frozen session)
  - loop detection              -> auto-pivot marks the vector exhausted
  - stuck sessions              -> watchdog nudges then flags
  - strategist                  -> runs on stage change / bootstrap, not only every N
  - exploitation                -> privilege detection + evidence capture + dedup

Async orchestrator methods are driven with asyncio.run() inside sync test bodies
so the suite needs no pytest-asyncio plugin (matching the rest of the suite)."""

import asyncio
import contextlib
from unittest.mock import AsyncMock, MagicMock

from core.orchestrator import _detect_privilege_level, _detect_exhausted_target
from tests._helpers import make_orch, make_session, svc


def _run(coro):
    return asyncio.run(coro)


@contextlib.contextmanager
def _no_sleep():
    """Temporarily neutralise asyncio.sleep so pauses don't slow the tests.
    Used instead of the pytest monkeypatch fixture so the dependency-free
    tests/run_tests.py runner (which calls tests with no args) also works."""
    _orig = asyncio.sleep
    asyncio.sleep = AsyncMock()
    try:
        yield
    finally:
        asyncio.sleep = _orig


def _loop_orch():
    """make_orch + the persistence/no-op wiring the loop-reliability methods read."""
    orch = make_orch()
    orch._save_ai_decision = lambda *a, **k: None
    orch._save_session_status = lambda *a, **k: None
    orch.add_evidence = lambda *a, **k: None
    orch._last_activity = {}
    orch._watchdog_nudges = {}
    orch._WATCHDOG_STALL = 100
    orch._WATCHDOG_MAX_NUDGES = 2
    return orch


# ── pure helpers ────────────────────────────────────────────────────────────

def test_detect_privilege_root():
    assert _detect_privilege_level("uid=0(root) gid=0(root)") == "root/SYSTEM"
    assert _detect_privilege_level("root@victim:~#") == "root/SYSTEM"
    assert _detect_privilege_level("nt authority\\system") == "root/SYSTEM"


def test_detect_privilege_user_vs_none():
    assert _detect_privilege_level("uid=33(www-data) gid=33") == "user"
    assert _detect_privilege_level("meterpreter session 1 opened") == "user"
    assert _detect_privilege_level("PORT   STATE SERVICE\n80/tcp open http") is None


def test_detect_exhausted_target_labels():
    assert _detect_exhausted_target(["smbclient -L //10.0.0.5"], "enumeration") == "smb"
    assert _detect_exhausted_target(["curl http://10.0.0.5:8080/manager/html"], "enumeration") == "tomcat_8080"
    assert _detect_exhausted_target(["hydra -l root ssh://10.0.0.5"], "exploitation") == "ssh_bruteforce"
    # falls back to a stage-scoped label when nothing recognised
    assert _detect_exhausted_target(["echo hi"], "enumeration") == "enumeration_exhausted"


# ── empty / no-response recovery ────────────────────────────────────────────

def test_empty_command_retries_then_halts():
    orch = _loop_orch()
    s = make_session(); s._MAX_EMPTY_RETRIES = 2
    orch.sessions[s.session_id] = s
    orch._analyze_with_ai = AsyncMock()  # capture retry calls, don't recurse

    # First few calls retry (re-invoke analysis with force_command)...
    _run(orch._handle_empty_command(s.session_id, "test"))
    _run(orch._handle_empty_command(s.session_id, "test"))
    assert orch._analyze_with_ai.await_count == 2
    # ...then the (MAX+1)th surfaces a visible halt instead of retrying again.
    _run(orch._handle_empty_command(s.session_id, "test"))
    assert s.status == "ready"
    assert s.ai_decisions and s.ai_decisions[-1]["context"] == "no_next_step"
    assert s._empty_response_count == 0  # reset after halt


def test_empty_command_force_flag_passed_on_retry():
    orch = _loop_orch()
    s = make_session(); orch.sessions[s.session_id] = s
    orch._analyze_with_ai = AsyncMock()
    _run(orch._handle_empty_command(s.session_id, "test"))
    # retry must request a forced concrete command
    _, kwargs = orch._analyze_with_ai.call_args
    assert kwargs.get("force_command") is True


# ── auto-pivot ──────────────────────────────────────────────────────────────

def test_auto_pivot_marks_exhausted_and_continues():
    orch = _loop_orch()
    s = make_session(); orch.sessions[s.session_id] = s
    s.current_stage = "enumeration"
    s.commands_executed = [{"command": "smbclient -L //10.0.0.5", "output": ""}]
    orch._analyze_with_ai = AsyncMock()
    with _no_sleep():  # skip the 3s pause
        _run(orch._auto_pivot(s.session_id, "loop detected"))
    assert "smb" in s.exhausted_services
    assert s.ai_decisions[-1]["context"] == "auto_pivot"
    assert s.auto_depth_counter == 0
    orch._analyze_with_ai.assert_awaited()


def test_auto_pivot_limit_halts():
    orch = _loop_orch()
    s = make_session(); orch.sessions[s.session_id] = s
    s._MAX_AUTO_PIVOTS = 1
    s._auto_pivot_count = 1  # already at cap
    orch._analyze_with_ai = AsyncMock()
    with _no_sleep():
        _run(orch._auto_pivot(s.session_id, "loop detected"))
    assert s.status == "ready"
    assert s.ai_decisions[-1]["context"] == "pivot_limit_reached"
    orch._analyze_with_ai.assert_not_awaited()  # halted, did not continue


# ── watchdog ────────────────────────────────────────────────────────────────

def test_watchdog_nudges_stalled_session():
    orch = _loop_orch()
    s = make_session(); s.status = "executing"
    orch.sessions[s.session_id] = s
    orch._analyze_with_ai = AsyncMock()
    # Arm a stale timestamp well past the stall threshold.
    orch._last_activity[s.session_id] = -10_000

    _run(orch._watchdog_tick())
    assert orch._watchdog_nudges[s.session_id] == 1
    assert s.status == "analyzing"  # nudged back into motion


def test_watchdog_flags_after_max_nudges():
    orch = _loop_orch()
    s = make_session(); s.status = "analyzing"
    orch.sessions[s.session_id] = s
    orch._analyze_with_ai = AsyncMock()
    orch._watchdog_nudges[s.session_id] = orch._WATCHDOG_MAX_NUDGES
    orch._last_activity[s.session_id] = -10_000

    _run(orch._watchdog_tick())
    assert s.status == "ready"
    assert s.ai_decisions[-1]["context"] == "watchdog_stalled"


def test_watchdog_ignores_resting_sessions():
    orch = _loop_orch()
    s = make_session(); s.status = "ready"
    orch.sessions[s.session_id] = s
    orch._last_activity[s.session_id] = -10_000
    _run(orch._watchdog_tick())
    # ready is a legit resting state — no nudge, no flag decision
    assert s.session_id not in orch._watchdog_nudges
    assert not any(d.get("context") == "watchdog_stalled" for d in s.ai_decisions)


# ── strategist trigger ──────────────────────────────────────────────────────

def test_strategist_runs_on_stage_change():
    orch = _loop_orch()
    s = make_session(); orch.sessions[s.session_id] = s
    s.strategic_plan = [{"step": "x", "status": "pending"}]  # plan exists
    s._last_strategist_stage = "reconnaissance"
    s.current_stage = "enumeration"                          # advanced
    s._planner_cmd_count = 0
    orch._run_strategist = AsyncMock()

    _run(orch._maybe_run_strategist(s.session_id))
    orch._run_strategist.assert_awaited()
    assert s._last_strategist_stage == "enumeration"


def test_strategist_bootstraps_when_no_plan():
    orch = _loop_orch()
    s = make_session(); orch.sessions[s.session_id] = s
    s.strategic_plan = []                 # no plan yet
    s._last_strategist_stage = s.current_stage
    orch._run_strategist = AsyncMock()

    _run(orch._maybe_run_strategist(s.session_id))
    orch._run_strategist.assert_awaited()  # ran after first command, not at #5


def test_strategist_skips_when_nothing_changed():
    orch = _loop_orch()
    s = make_session(); orch.sessions[s.session_id] = s
    s.strategic_plan = [{"step": "x", "status": "pending"}]
    s._last_strategist_stage = s.current_stage
    s._planner_cmd_count = 0
    orch._run_strategist = AsyncMock()

    _run(orch._maybe_run_strategist(s.session_id))  # count -> 1, below interval
    orch._run_strategist.assert_not_awaited()


# ── exploitation evidence capture ───────────────────────────────────────────

def test_settle_captures_compromise_evidence():
    orch = _loop_orch()
    s = make_session(services=[svc(445, "smb")])
    orch.sessions[s.session_id] = s
    out = "Pwn3d! uid=0(root) gid=0(root)"
    orch._settle_service_states(s, "crackmapexec smb 10.0.0.5 -u a -p b", out, success=True)
    assert len(s.compromise_evidence) == 1
    ev = s.compromise_evidence[0]
    assert ev["privilege"] == "root/SYSTEM"
    assert ev["service"] == "smb"


def test_compromise_evidence_deduped():
    orch = _loop_orch()
    s = make_session(services=[svc(445, "smb")])
    orch.sessions[s.session_id] = s
    out = "uid=0(root)"
    orch._settle_service_states(s, "cmd1", out, success=True)
    orch._settle_service_states(s, "cmd2", out, success=True)  # same svc+priv
    assert len(s.compromise_evidence) == 1  # deduped


def test_no_evidence_without_signal():
    orch = _loop_orch()
    s = make_session(services=[svc(80, "http")])
    orch.sessions[s.session_id] = s
    orch._settle_service_states(s, "whatweb http://10.0.0.5", "Apache 2.4 detected", success=True)
    assert s.compromise_evidence == []


def test_compromise_context_block_tells_ai_to_pivot():
    orch = _loop_orch()
    s = make_session(services=[svc(445, "smb")])
    s.compromise_evidence = [{
        "service": "smb", "port": 445, "host": "10.0.0.5",
        "privilege": "root/SYSTEM", "command": "cme smb", "signal": "uid=0",
    }]
    block = orch._compromise_context_block(s)
    assert "CONFIRMED COMPROMISES" in block
    assert "post-exploitation" in block.lower()
    # empty when nothing proven
    assert orch._compromise_context_block(make_session()) == ""

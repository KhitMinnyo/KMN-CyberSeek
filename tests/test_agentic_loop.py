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
from ai.connector import AIResponse
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


# ── auto-handler for autonomous exploitation ────────────────────────────────

def test_guess_default_payload_windows_vs_linux():
    orch = _loop_orch()
    win = make_session(services=[svc(445, "microsoft-ds"), svc(3389, "ms-wbt-server")])
    lin = make_session(services=[svc(22, "ssh"), svc(80, "http")])
    assert "windows" in orch._guess_default_payload(win)
    assert "linux" in orch._guess_default_payload(lin)


def test_ensure_handler_starts_once_and_records_config():
    orch = _loop_orch()
    s = make_session(services=[svc(445, "microsoft-ds")])
    orch.sessions[s.session_id] = s
    orch.db_path = ":memory:"  # persistence writes are best-effort/no-op here

    # Fake ShellManager whose start_handler returns a handler-like object.
    fake_handler = MagicMock()
    fake_handler.handler_id = "h1"
    fake_handler.status = "listening"
    fake_handler.started_at = "t0"
    fake_handler.info = {"handler_id": "h1"}
    fake_mgr = MagicMock()
    fake_mgr.start_handler = AsyncMock(return_value=fake_handler)
    orch._get_shell_manager = lambda sid: fake_mgr

    _run(orch._ensure_exploitation_handler(s.session_id))
    assert s._auto_handler_started is True
    assert s.exploit_lhost and s.exploit_lport and s.exploit_payload
    assert s.ai_decisions[-1]["context"] == "handler_started"
    fake_mgr.start_handler.assert_awaited_once()

    # Second call is idempotent — no second handler.
    _run(orch._ensure_exploitation_handler(s.session_id))
    fake_mgr.start_handler.assert_awaited_once()


def test_handler_context_block_directs_payload_delivery():
    orch = _loop_orch()
    s = make_session()
    assert orch._handler_context_block(s) == ""  # nothing until handler is up
    s.exploit_lhost = "10.10.14.9"
    s.exploit_lport = 4444
    s.exploit_payload = "windows/x64/meterpreter/reverse_tcp"
    block = orch._handler_context_block(s)
    assert "10.10.14.9" in block and "4444" in block
    assert "do NOT" in block.lower() or "do not" in block.lower()
    assert "shells tab" in block.lower()


def test_persist_shell_session_logs_caught_shell_decision():
    orch = _loop_orch()
    s = make_session()
    orch.sessions[s.session_id] = s
    orch.db_path = ":memory:"
    info = {"shell_id": "abc", "msf_id": 1, "type": "meterpreter",
            "target_ip": "10.0.0.5", "status": "open", "opened_at": "t0"}
    orch._persist_shell_session(s.session_id, "h1", info)
    assert s.ai_decisions[-1]["context"] == "shell_caught"


# ── episode summary (regressions) ───────────────────────────────────────────

def test_full_auto_critique_reject_no_unbound_error():
    """Regression: in FULL_AUTO_MODE a critique-rejected high-risk command hit
    `elif not _queued_already` while _queued_already was never assigned →
    UnboundLocalError failed the whole loop turn ('Agentic loop error')."""
    import core.orchestrator as orch_mod
    orch = _loop_orch()
    s = make_session(services=[svc(80, "http")])
    orch.sessions[s.session_id] = s
    s.status = "executing"

    hi = AIResponse(reasoning="risky", suggested_command="msfvenom -p x LHOST=1",
                    risk_level="high", confidence=0.9, attack_phase="exploitation")
    orch.ai_connector.ask_ai_async = AsyncMock(return_value=hi)
    orch._build_ai_memory = MagicMock(return_value="")
    orch._plan_context_block = MagicMock(return_value="")
    orch._get_relevant_threat_intel_context = MagicMock(return_value="")
    orch._auto_parse_tool_output = MagicMock()
    orch._vet_command = AsyncMock(return_value={"verdict": "reject", "reason": "bogus"})
    queued = []
    orch.queue_for_approval = lambda sid, cmd: queued.append(cmd)

    _orig = orch_mod.FULL_AUTO_MODE
    orch_mod.FULL_AUTO_MODE = True
    try:
        _run(orch._process_command_output(s.session_id, "prev cmd", "some output", None))
    finally:
        orch_mod.FULL_AUTO_MODE = _orig

    # No exception, and the rejected command was routed to approval exactly once.
    assert queued == ["msfvenom -p x LHOST=1"]
    assert not any(d.get("context") == "loop_error" for d in s.ai_decisions)


def test_operator_instruction_injected_into_context():
    orch = _loop_orch()
    s = make_session()
    orch.sessions[s.session_id] = s
    assert orch._operator_context_block(s) == ""  # none yet
    res = orch.add_operator_instruction(s.session_id, "Focus on GlassFish 4848; skip SMB")
    assert res["status"] == "success"
    assert "Focus on GlassFish" in s.operator_instructions[-1]
    block = orch._operator_context_block(s)
    assert "OPERATOR INSTRUCTIONS" in block
    assert "GlassFish" in block
    # logged as a decision so it persists + shows in the timeline
    assert s.ai_decisions[-1]["context"] == "operator_instruction"


def test_operator_instruction_rejects_empty():
    orch = _loop_orch()
    s = make_session(); orch.sessions[s.session_id] = s
    assert orch.add_operator_instruction(s.session_id, "   ")["status"] == "error"
    assert s.operator_instructions == []


def test_answer_operator_question_uses_state():
    orch = _loop_orch()
    s = make_session(services=[svc(4848, "glassfish")])
    orch.sessions[s.session_id] = s
    orch.ai_connector.ask_raw_async = AsyncMock(
        return_value={"answer": "Found GlassFish on 4848; trying default creds next."}
    )
    res = _run(orch.answer_operator_question(s.session_id, "what have you found?"))
    assert res["status"] == "success"
    assert "GlassFish" in res["answer"]
    # the state summary must have been passed to the model
    _, kwargs = orch.ai_connector.ask_raw_async.call_args
    args = orch.ai_connector.ask_raw_async.call_args[0]
    assert any("glassfish" in str(a).lower() for a in args)


def test_create_episode_summary_uses_session_episode_size():
    """Regression: _create_episode_summary referenced self._EPISODE_SIZE (an
    orchestrator attr that doesn't exist) → AttributeError crashed the whole
    command loop and failed the session. Must read session._EPISODE_SIZE."""
    orch = _loop_orch()
    s = make_session(services=[svc(80, "http")])
    orch.sessions[s.session_id] = s
    s.commands_executed = [
        {"command": f"cmd{i}", "output": f"out{i}", "success": True}
        for i in range(6)
    ]
    summary = orch._create_episode_summary(s.session_id)  # must not raise
    assert summary and "EPISODE 1 SUMMARY" in summary
    assert s.episode_summaries and s.episode_summaries[-1] == summary

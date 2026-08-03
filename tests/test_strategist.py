"""Tests for the strategic layer: strategist reflection parsing, objective-progress
update, the spurious-completion guard, and the self-critique verdicts.

Async orchestrator methods are driven with asyncio.run() inside sync test bodies
so the suite needs no pytest-asyncio plugin."""

import asyncio
from unittest.mock import AsyncMock

from tests._helpers import make_orch, make_session, svc


def _run(coro):
    return asyncio.run(coro)


def _sess():
    s = make_session(services=[svc(80, "http", version="Apache")])
    s.objective = "Get root on the box"
    return s


def test_strategist_updates_plan_and_progress():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    orch.ai_connector.ask_raw_async = AsyncMock(return_value={
        "reflection": "Web service found, not yet enumerated.",
        "objective_progress": 0.2,
        "objective_complete": False,
        "completion_reason": "",
        "priority": "Fingerprint and dirbust the web app",
        "plan": [
            {"step": "whatweb http://10.0.0.5", "rationale": "fp", "status": "pending"},
            {"step": "gobuster dir", "rationale": "content", "status": "pending"},
        ],
    })
    _run(orch._run_strategist(s.session_id))
    assert abs(s.objective_progress - 0.2) < 1e-6
    assert len(s.strategic_plan) == 2
    assert s.objective_complete is False
    assert s.reflections and "Web service" in s.reflections[-1]


def test_completion_honored_when_progress_high():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    orch.ai_connector.ask_raw_async = AsyncMock(return_value={
        "reflection": "Root shell obtained via sudo GTFOBins.",
        "objective_progress": 0.95,
        "objective_complete": True,
        "completion_reason": "root shell confirmed: whoami=root",
        "priority": "done", "plan": [],
    })
    _run(orch._run_strategist(s.session_id))
    assert s.objective_complete is True


def test_spurious_completion_ignored_at_low_progress():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    orch.ai_connector.ask_raw_async = AsyncMock(return_value={
        "reflection": "unsure", "objective_progress": 0.3,
        "objective_complete": True, "completion_reason": "maybe",
        "priority": "p", "plan": [],
    })
    _run(orch._run_strategist(s.session_id))
    assert s.objective_complete is False


def test_strategist_bad_json_keeps_prior_plan():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    s.strategic_plan = [{"step": "keep me", "rationale": "", "status": "pending"}]
    orch.ai_connector.ask_raw_async = AsyncMock(return_value=None)  # parse failure
    _run(orch._run_strategist(s.session_id))
    assert s.strategic_plan == [{"step": "keep me", "rationale": "", "status": "pending"}]


def test_critique_reject():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    orch.ai_connector.ask_raw_async = AsyncMock(return_value={
        "verdict": "reject", "confidence": 0.9,
        "reason": "fabricated CVE not in scan", "revised_command": "",
    })
    r = _run(orch._vet_command(s.session_id, "msfconsole -q -x 'use fake'", "uses CVE-9999-0000"))
    assert r["verdict"] == "reject"


def test_critique_revise_swaps_command():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    orch.ai_connector.ask_raw_async = AsyncMock(return_value={
        "verdict": "revise", "confidence": 0.8, "reason": "add --batch",
        "revised_command": "wpscan --url http://x --batch",
    })
    r = _run(orch._vet_command(s.session_id, "wpscan --url http://x", "enumerate"))
    assert r["verdict"] == "revise" and "--batch" in r["command"]


def test_critique_fails_open_on_error():
    orch = make_orch()
    s = _sess(); orch.sessions[s.session_id] = s
    orch.ai_connector.ask_raw_async = AsyncMock(side_effect=RuntimeError("boom"))
    r = _run(orch._vet_command(s.session_id, "nmap 10.0.0.5", "recon"))
    assert r["verdict"] == "approve"  # fail-open

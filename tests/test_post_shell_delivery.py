"""Tests for automatic post-shell command delivery.

When a shell lands on the managed handler, _persist_shell_session schedules
_deliver_post_shell, which runs the canned recon/harvest batch through the
persistent handler exactly once per (handler, msf_id) pair.

No live Metasploit required — run_shell_command is mocked.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import core.orchestrator as orch_mod
from core import post_shell as _post_shell
from tests._helpers import make_orch, make_session


def _delivery_harness(target_os="linux", credentials=None, auto_post_shell=True):
    orch = make_orch()
    s = make_session(sid="s1", ip="10.0.0.5")
    s.authorization_confirmed = True
    s.target_os = target_os
    s.credentials = credentials or []
    s.auto_post_shell = auto_post_shell
    orch.sessions[s.session_id] = s
    orch._shell_managers = {"s1": MagicMock()}
    orch._post_shell_delivered = set()
    orch.run_shell_command = AsyncMock(return_value="uid=0(root)\n")
    return orch, s


def _run(coro):
    return asyncio.run(coro)


def test_delivers_linux_meterpreter_batch():
    orch, s = _delivery_harness(target_os="linux")
    info = {"msf_id": 1, "type": "meterpreter",
            "payload": "linux/x64/meterpreter/reverse_tcp"}

    _run(orch._deliver_post_shell(s.session_id, "h1", info))

    expected = [c for _, c in _post_shell.LINUX_RECON]
    called = [c.args[3] for c in orch.run_shell_command.await_args_list]
    assert called == expected
    # No cred harvest for a non-windows target without credentials.
    assert not any("hashdump" in c for c in called)


def test_windows_batch_includes_cred_harvest_when_credentials_present():
    orch, s = _delivery_harness(
        target_os="windows",
        credentials=[{"username": "admin", "secret": "pw",
                      "secret_type": "password"}],
    )
    info = {"msf_id": 2, "type": "meterpreter",
            "payload": "windows/x64/meterpreter/reverse_tcp"}

    _run(orch._deliver_post_shell(s.session_id, "h1", info))

    called = [c.args[3] for c in orch.run_shell_command.await_args_list]
    assert "hashdump" in called or any("hashdump" in c for c in called)
    # Windows recon + cred harvest + AD recon are all delivered.
    assert len(called) == (
        len(_post_shell.WINDOWS_RECON)
        + len(_post_shell.CRED_HARVEST)
        + len(_post_shell.AD_RECON)
    )


def test_dedup_same_handler_msf_id():
    orch, s = _delivery_harness(target_os="linux")
    info = {"msf_id": 3, "type": "meterpreter",
            "payload": "linux/x64/meterpreter/reverse_tcp"}

    _run(orch._deliver_post_shell(s.session_id, "h1", info))
    first_count = orch.run_shell_command.await_count
    _run(orch._deliver_post_shell(s.session_id, "h1", info))

    assert orch.run_shell_command.await_count == first_count


def test_opt_out_skips_delivery():
    orch, s = _delivery_harness(target_os="linux", auto_post_shell=False)
    info = {"msf_id": 4, "type": "meterpreter",
            "payload": "linux/x64/meterpreter/reverse_tcp"}

    _run(orch._deliver_post_shell(s.session_id, "h1", info))

    assert orch.run_shell_command.await_count == 0


def test_global_flag_off_skips_delivery(monkeypatch):
    orch, s = _delivery_harness(target_os="linux")
    info = {"msf_id": 5, "type": "meterpreter",
            "payload": "linux/x64/meterpreter/reverse_tcp"}
    monkeypatch.setattr(orch_mod, "AUTO_POST_SHELL", False)

    _run(orch._deliver_post_shell(s.session_id, "h1", info))

    assert orch.run_shell_command.await_count == 0

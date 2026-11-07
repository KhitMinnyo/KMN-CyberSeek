"""Offline execution-budget tests using only fakes and harmless Python processes."""

import asyncio
import shlex
import sys
from unittest.mock import MagicMock

import pytest

from core import command_runner, orchestrator
from core.command_runner import BackendConfig, ExecutionResult, execution_slot
from core.scanner import Scanner
from tests._helpers import make_orch, make_session


@pytest.fixture(autouse=True)
def trusted_environment(monkeypatch):
    monkeypatch.setenv("KMN_MAX_EXECUTIONS", "1")
    monkeypatch.setenv("KMN_MAX_QUEUED_EXECUTIONS", "32")
    monkeypatch.setenv("SCOPE_ALLOWLIST", "")
    monkeypatch.setenv("KMN_EXECUTION_BACKEND", "local")
    for key in ("KMN_DOCKER_IMAGE", "KMN_DOCKER_NETWORK",
                "KMN_DOCKER_NETWORK_POLICY_ATTESTED", "KMN_DOCKER_MEMORY_MB",
                "KMN_DOCKER_CPUS", "KMN_DOCKER_PIDS_LIMIT"):
        monkeypatch.delenv(key, raising=False)

    def no_shell(*args, **kwargs):
        pytest.fail("Unexpected shell process")

    monkeypatch.setattr(asyncio, "create_subprocess_shell", no_shell)


@pytest.fixture
def orch():
    instance = make_orch()
    instance.sessions["s1"] = make_session(authorization_confirmed=True)
    instance._watchdog_nudges = {}
    instance._execution_gate = MagicMock(return_value=None)
    for name in ("_save_command_result", "_record_event", "_extract_and_store_credentials",
                 "_settle_service_states", "_ensure_coverage", "_update_coverage_from_command",
                 "_recompute_coverage_progress", "_index_finding", "_touch_activity",
                 "_update_target_fingerprint_from_output"):
        setattr(instance, name, MagicMock())
    return instance


def prepared(orch, command="echo harmless"):
    return orch._execute_prepared_command("s1", command, "command", "job", "manual", orch.sessions["s1"])


@pytest.mark.parametrize("key,bad", [
    ("KMN_MAX_EXECUTIONS", value) for value in ("", "0", "-1", "1.5", "nan", " 3", "+3", "three")
] + [
    ("KMN_MAX_QUEUED_EXECUTIONS", value) for value in ("", "-1", "1.5", "inf", " 2", "+2", "none")
])
@pytest.mark.parametrize("boundary", ["runner", "scanner", "orchestrator"])
def test_invalid_config_never_spawns(monkeypatch, orch, key, bad, boundary):
    monkeypatch.setenv(key, bad)

    async def no_spawn(*args, **kwargs):
        pytest.fail("Invalid budget reached process creation")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", no_spawn)

    async def check():
        with pytest.raises(ValueError, match=key):
            if boundary == "runner":
                await command_runner.execute_command("echo harmless", "manual")
            elif boundary == "scanner":
                await Scanner()._run_command("nmap -sn 127.0.0.1", 10)
            else:
                await prepared(orch)

    asyncio.run(check())


def test_defaults_and_bounded_queue(monkeypatch):
    monkeypatch.delenv("KMN_MAX_EXECUTIONS")
    monkeypatch.delenv("KMN_MAX_QUEUED_EXECUTIONS")

    async def check():
        release = asyncio.Event()
        entered = 0

        async def hold():
            nonlocal entered
            async with execution_slot():
                entered += 1
                await release.wait()

        tasks = [asyncio.create_task(hold()) for _ in range(35)]
        await asyncio.sleep(0)
        assert entered == 3
        with pytest.raises(RuntimeError, match="saturated"):
            async with execution_slot():
                pytest.fail("Full queue admitted another execution")
        release.set()
        await asyncio.wait_for(asyncio.gather(*tasks), 3)
        assert entered == 35

    asyncio.run(check())


@pytest.mark.parametrize("handoff", [False, True])
def test_cancelled_waiter_returns_admission_and_permit(monkeypatch, handoff):
    monkeypatch.setenv("KMN_MAX_QUEUED_EXECUTIONS", "1")

    async def check():
        async def wait():
            async with execution_slot():
                pytest.fail("Cancelled waiter entered")

        async with execution_slot():
            waiter = asyncio.create_task(wait())
            await asyncio.sleep(0)
            with pytest.raises(RuntimeError, match="saturated"):
                async with execution_slot():
                    pass
            if not handoff:
                waiter.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiter
        # Cancel after release but before the signalled waiter resumes as well.
        if handoff:
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiter

        async def replacement():
            async with execution_slot():
                pass

        async with execution_slot():
            queued = asyncio.create_task(replacement())
            await asyncio.sleep(0)
            assert not queued.done()
        await asyncio.wait_for(queued, 1)

    asyncio.run(check())


def test_zero_queue_and_exception_release(monkeypatch):
    monkeypatch.setenv("KMN_MAX_QUEUED_EXECUTIONS", "0")

    async def check():
        with pytest.raises(LookupError):
            async with execution_slot():
                with pytest.raises(RuntimeError, match="saturated"):
                    async with execution_slot():
                        pass
                raise LookupError("fixture failure")
        async with execution_slot():
            pass

    asyncio.run(check())


@pytest.mark.parametrize("boundary", ["runner", "scanner", "orchestrator"])
def test_saturated_boundary_never_spawns(monkeypatch, orch, boundary):
    monkeypatch.setenv("KMN_MAX_QUEUED_EXECUTIONS", "0")

    async def no_spawn(*args, **kwargs):
        pytest.fail("Saturated budget reached process creation")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", no_spawn)

    async def check():
        async with execution_slot():
            with pytest.raises(RuntimeError, match="saturated"):
                if boundary == "runner":
                    await command_runner.execute_command("echo harmless", "manual")
                elif boundary == "scanner":
                    await Scanner()._run_command("nmap -sn 127.0.0.1", 3)
                else:
                    await prepared(orch)
        async with execution_slot():
            pass

    asyncio.run(check())


def test_configuration_cannot_replace_live_budget(monkeypatch):
    async def check():
        async with execution_slot():
            monkeypatch.setenv("KMN_MAX_EXECUTIONS", "2")
            with pytest.raises(ValueError, match="changed"):
                async with execution_slot():
                    pass
            monkeypatch.setenv("KMN_MAX_EXECUTIONS", "1")
        async with execution_slot():
            pass

    asyncio.run(check())


def test_new_event_loop_has_independent_budget(monkeypatch):
    async def check():
        async with execution_slot():
            pass

    asyncio.run(check())
    monkeypatch.setenv("KMN_MAX_EXECUTIONS", "2")
    asyncio.run(check())


@pytest.mark.parametrize("cap", [1, 2, 3])
def test_scanner_runner_and_orchestrator_share_actual_process_cap(monkeypatch, orch, cap):
    monkeypatch.setenv("KMN_MAX_EXECUTIONS", str(cap))
    real_spawn = asyncio.create_subprocess_exec
    processes = []
    peak = 0

    async def spawn(*argv, **kwargs):
        nonlocal peak
        assert argv[0] in {"echo", "nmap"}
        process = await real_spawn(sys.executable, "-c",
                                   "import time; print('harmless'); time.sleep(0.05)", **kwargs)
        processes.append(process)
        peak = max(peak, sum(p.returncode is None for p in processes))
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)

    async def check():
        calls = []
        for _ in range(3):
            calls.extend([command_runner.execute_command("echo harmless", "manual"),
                          Scanner()._run_command("nmap -sn 127.0.0.1", 3), prepared(orch)])
        results = await asyncio.wait_for(asyncio.gather(*calls), 10)
        assert len(results) == 9
        assert all(result["success"] for result in results[2::3])

    asyncio.run(check())
    assert peak == cap
    assert len(processes) == 9
    assert all(p.returncode == 0 for p in processes)


@pytest.mark.parametrize("boundary", ["runner", "orchestrator"])
@pytest.mark.parametrize("cancel", [False, True])
def test_slot_covers_docker_cleanup_even_when_cancelled(monkeypatch, orch, boundary, cancel):
    config = BackendConfig(backend="docker", image="fixture:offline")
    monkeypatch.setattr(orchestrator, "backend_config_from_env", lambda: config)
    real_spawn = asyncio.create_subprocess_exec

    async def check():
        cleaning, release = asyncio.Event(), asyncio.Event()
        launches = []

        async def spawn(*argv, **kwargs):
            launches.append(argv)
            return await real_spawn(sys.executable, "-c", "pass", **kwargs)

        async def remove(argv, **kwargs):
            assert argv[:3] == ["docker", "rm", "--force"]
            cleaning.set()
            await release.wait()
            return ExecutionResult(0, b"", b"")

        original_run = command_runner.run_subprocess

        async def run(argv, **kwargs):
            if argv[:2] == ["docker", "rm"]:
                return await remove(argv, **kwargs)
            return await original_run(argv, **kwargs)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        monkeypatch.setattr(command_runner, "run_subprocess", run)
        monkeypatch.setattr(orchestrator, "run_subprocess", remove)
        call = (prepared(orch) if boundary == "orchestrator" else
                command_runner.execute_command("echo harmless", "manual", config=config))
        task = asyncio.create_task(call)
        await asyncio.wait_for(cleaning.wait(), 3)
        if cancel:
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
        waiting = asyncio.create_task(Scanner(BackendConfig())._run_command("nmap -sn 127.0.0.1", 3))
        await asyncio.sleep(0)
        assert len(launches) == 1
        assert not task.done() and not waiting.done()
        release.set()
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 3)
        else:
            await asyncio.wait_for(task, 3)
        await asyncio.wait_for(waiting, 3)
        assert len(launches) == 2

    asyncio.run(check())


@pytest.mark.parametrize("boundary", ["runner", "scanner", "orchestrator"])
@pytest.mark.parametrize("cancel", [False, True])
def test_process_interruption_reaps_before_reusing_slot(monkeypatch, orch, boundary, cancel):
    real_spawn = asyncio.create_subprocess_exec
    processes = []
    timeout = 60 if cancel else 0.05
    orch._command_timeout = lambda command: timeout

    async def check():
        started = asyncio.Event()

        async def spawn(*argv, **kwargs):
            process = await real_spawn(sys.executable, "-c", "import time; time.sleep(30)", **kwargs)
            processes.append(process)
            started.set()
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        if boundary == "runner":
            call = command_runner.execute_command("echo harmless", "manual", timeout=timeout)
        elif boundary == "scanner":
            call = Scanner()._run_command("nmap -sn 127.0.0.1", timeout)
        else:
            call = prepared(orch)
        task = asyncio.create_task(call)
        await asyncio.wait_for(started.wait(), 3)
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 3)
        elif boundary == "runner":
            with pytest.raises(command_runner.CommandTimeoutError):
                await asyncio.wait_for(task, 3)
        elif boundary == "scanner":
            assert (await asyncio.wait_for(task, 3))[3] is True
        else:
            assert (await asyncio.wait_for(task, 3))["status"] == "timed_out"
        assert processes[0].returncode is not None
        async with execution_slot():
            pass

    asyncio.run(check())

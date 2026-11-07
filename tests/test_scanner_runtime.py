"""Offline scanner tests; real process coverage uses only Python sleepers."""

import asyncio
import signal
import sys

import pytest

from core import command_runner
from core.command_runner import BackendConfig, CommandTimeoutError, ExecutionResult
from core.scanner import Scanner


NETWORK_METHODS = [
    ("perform_nmap_scan", ()),
    ("perform_service_discovery", ([80, 443],)),
    ("perform_subnet_sweep", ()),
    ("perform_vulnerability_scan", ()),
    ("perform_vulnerability_scan_port", (80,)),
    ("check_port_status", (80,)),
]
OUTPUT = b"Nmap scan report for 10.0.0.1\nHost is up\n80/tcp open http\n"


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    real_spawn = asyncio.create_subprocess_exec

    def unexpected(*args, **kwargs):
        pytest.fail("An unmocked process launch was attempted")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", unexpected)
    monkeypatch.setattr(asyncio, "create_subprocess_shell", unexpected)
    for key in ("KMN_EXECUTION_BACKEND", "KMN_DOCKER_IMAGE", "KMN_DOCKER_NETWORK",
                "KMN_DOCKER_NETWORK_POLICY_ATTESTED", "KMN_DOCKER_MEMORY_MB",
                "KMN_DOCKER_CPUS", "KMN_DOCKER_PIDS_LIMIT"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("SCOPE_ALLOWLIST", "10.0.0.0/24")
    monkeypatch.setenv("NMAP_OS_DETECTION", "false")
    monkeypatch.setenv("SCAN_TIMEOUT", "300")
    monkeypatch.setenv("VULN_SCAN_TIMEOUT", "120")
    monkeypatch.setenv("VULN_PORT_TIMEOUT", "60")
    return real_spawn


@pytest.mark.parametrize("method,args", NETWORK_METHODS)
@pytest.mark.parametrize("target", ["203.0.113.1", "10.0.0.0/16", "2001:db8::/64"])
def test_every_network_entrypoint_rejects_out_of_scope(monkeypatch, method, args, target):
    async def unexpected(*args, **kwargs):
        pytest.fail("Scope rejection reached the subprocess runner")

    monkeypatch.setattr(command_runner, "run_subprocess", unexpected)
    result = asyncio.run(getattr(Scanner(), method)(target, *args))
    assert result["success"] is False
    assert result["error"]


@pytest.mark.parametrize("options", [
    "-sV 203.0.113.1", "-sV 10.0.0.0/16", "-iL targets.txt",
    "--script arbitrary.nse", "-sV ; ping 203.0.113.1",
])
def test_custom_options_cannot_add_unapproved_destinations(options):
    result = asyncio.run(Scanner().perform_nmap_scan("10.0.0.1", options))
    assert result["success"] is False
    assert result["error"]


@pytest.mark.parametrize("method,args,target", [
    ("perform_nmap_scan", (), "10.0.0.1"),
    ("perform_service_discovery", ([80, 443],), "10.0.0.1"),
    ("perform_subnet_sweep", (), "10.0.0.0/28"),
    ("check_port_status", (80,), "10.0.0.1"),
])
def test_scoped_supported_scans_reach_runner(monkeypatch, method, args, target):
    calls = []

    async def run(argv, **kwargs):
        calls.append(argv)
        return ExecutionResult(0, OUTPUT, b"")

    monkeypatch.setattr(command_runner, "run_subprocess", run)
    result = asyncio.run(getattr(Scanner(), method)(target, *args))
    assert result["success"] is True
    assert calls[0][-1] == target


@pytest.mark.parametrize("scope", [",", "10.0.0.0/24,", "not a host"])
def test_malformed_scope_is_not_unrestricted(monkeypatch, scope):
    monkeypatch.setenv("SCOPE_ALLOWLIST", scope)
    result = asyncio.run(Scanner().perform_nmap_scan("10.0.0.1", "quick"))
    assert result["success"] is False
    assert result["error"]


@pytest.mark.parametrize("settings", [
    {"KMN_EXECUTION_BACKEND": "unknown"},
    {"KMN_EXECUTION_BACKEND": ""},
    {"KMN_EXECUTION_BACKEND": "docker"},
    {"KMN_EXECUTION_BACKEND": "docker", "KMN_DOCKER_IMAGE": "tools:lab"},
    {"KMN_EXECUTION_BACKEND": "docker", "KMN_DOCKER_IMAGE": "tools:lab",
     "KMN_DOCKER_NETWORK": "scope-lab"},
    {"KMN_EXECUTION_BACKEND": "docker", "KMN_DOCKER_IMAGE": "tools:lab",
     "KMN_DOCKER_NETWORK": "host", "KMN_DOCKER_NETWORK_POLICY_ATTESTED": "true"},
    {"KMN_DOCKER_NETWORK_POLICY_ATTESTED": "yes"},
    {"KMN_DOCKER_MEMORY_MB": "0"},
    {"KMN_DOCKER_CPUS": "nan"},
    {"KMN_DOCKER_PIDS_LIMIT": "1.5"},
])
@pytest.mark.parametrize("method,args", NETWORK_METHODS)
def test_invalid_backend_never_falls_back_to_host(monkeypatch, settings, method, args):
    for key, value in settings.items():
        monkeypatch.setenv(key, value)
    target = "10.0.0.0/28" if method == "perform_subnet_sweep" else "10.0.0.1"
    result = asyncio.run(getattr(Scanner(), method)(target, *args))
    assert result["success"] is False
    assert result["error"]


@pytest.mark.parametrize("backend", ["local", "docker"])
def test_configured_backend_is_planned_and_docker_is_removed(monkeypatch, backend):
    monkeypatch.setenv("KMN_EXECUTION_BACKEND", backend)
    monkeypatch.setenv("KMN_DOCKER_IMAGE", "tools:lab")
    monkeypatch.setenv("KMN_DOCKER_NETWORK", "scope-lab")
    monkeypatch.setenv("KMN_DOCKER_NETWORK_POLICY_ATTESTED", "true")
    monkeypatch.setenv("KMN_DOCKER_MEMORY_MB", "768")
    monkeypatch.setenv("KMN_DOCKER_CPUS", "0.5")
    monkeypatch.setenv("KMN_DOCKER_PIDS_LIMIT", "32")
    calls = []

    async def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return ExecutionResult(0, OUTPUT, b"")

    monkeypatch.setattr(command_runner, "run_subprocess", run)
    result = asyncio.run(Scanner().perform_nmap_scan("10.0.0.1", "quick"))
    assert result["success"] is True
    assert result["parsed_results"]["hosts"][0]["ip"] == "10.0.0.1"
    assert calls[0][1]["timeout"] == 300
    assert "HOME" not in calls[0][1]["environment"]
    if backend == "docker":
        argv = calls[0][0]
        assert argv[:2] == ["docker", "run"]
        assert argv[argv.index("--network") + 1] == "scope-lab"
        assert argv[argv.index("--memory") + 1] == "768m"
        assert argv[argv.index("--cpus") + 1] == "0.5"
        assert argv[argv.index("--pids-limit") + 1] == "32"
        name = argv[argv.index("--name") + 1]
        assert calls[1][0] == ["docker", "rm", "--force", name]
    else:
        assert calls[0][0][0] == "nmap"
        assert len(calls) == 1


@pytest.mark.parametrize("method,args", NETWORK_METHODS)
@pytest.mark.parametrize("outcome", ["success", "nonzero", "timeout", "partial_timeout"])
def test_scan_result_status_and_partial_output(monkeypatch, method, args, outcome):
    # The scope grammar deliberately rejects NSE; this test isolates result handling.
    monkeypatch.setenv("SCOPE_ALLOWLIST", "")

    async def run(argv, **kwargs):
        if "timeout" in outcome:
            raise CommandTimeoutError(OUTPUT if outcome == "partial_timeout" else b"", b"partial stderr")
        return ExecutionResult(0 if outcome == "success" else 2, OUTPUT, b"tool failed")

    monkeypatch.setattr(command_runner, "run_subprocess", run)
    target = "10.0.0.0/28" if method == "perform_subnet_sweep" else "10.0.0.1"
    result = asyncio.run(getattr(Scanner(), method)(target, *args))
    assert result["success"] is (outcome == "success")
    if outcome != "success":
        assert result["error"]
    if outcome in {"nonzero", "partial_timeout"}:
        assert result["raw_output"] == OUTPUT.decode()
    if outcome == "partial_timeout" and "parsed_results" in result:
        assert result["parsed_results"]["hosts"]


@pytest.mark.parametrize("cancel", [False, True])
def test_scanner_timeout_and_cancellation_use_process_group_cleanup(monkeypatch, cancel):
    async def check():
        started, killed = asyncio.Event(), asyncio.Event()

        class Process:
            pid = 123456789
            returncode = None

            async def communicate(self):
                started.set()
                await killed.wait()
                self.returncode = -signal.SIGKILL
                return OUTPUT, b""

            async def wait(self):
                return self.returncode

        process = Process()

        async def spawn(*argv, **kwargs):
            assert argv[0] == "nmap"
            assert kwargs["start_new_session"] is True
            assert kwargs["stdin"] == asyncio.subprocess.DEVNULL
            return process

        def killpg(pid, sig):
            assert (pid, sig) == (process.pid, signal.SIGKILL)
            killed.set()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        monkeypatch.setattr(command_runner.os, "killpg", killpg)
        task = asyncio.create_task(Scanner()._run_command("nmap -sn 10.0.0.1", 10 if cancel else 0.01))
        await started.wait()
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            assert await task == (OUTPUT, b"", None, True)
        assert killed.is_set()
        assert process.returncode == -signal.SIGKILL

    asyncio.run(check())


def test_scanner_retains_real_process_timeout_output(monkeypatch, offline):
    processes = []
    monkeypatch.setenv("SCAN_TIMEOUT", "1")

    async def spawn(*argv, **kwargs):
        # Replace only the planned tool with a harmless fixture process.
        assert argv[0] == "nmap"
        code = (f"import sys,time; sys.stdout.buffer.write({OUTPUT!r}); sys.stdout.flush(); "
                "sys.stderr.buffer.write(b'partial diagnostic'); sys.stderr.flush(); time.sleep(30)")
        process = await offline(sys.executable, "-c", code, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    result = asyncio.run(Scanner().perform_nmap_scan("10.0.0.1", "quick"))
    assert result["success"] is False
    assert result["partial"] is True
    assert result["raw_output"] == OUTPUT.decode()
    assert result["parsed_results"]["hosts"][0]["ports"][0]["port"] == 80
    assert processes[0].returncode == -signal.SIGKILL


@pytest.mark.parametrize("outcome", ["timeout", "cancel"])
def test_scanner_docker_cleanup_on_interruption(monkeypatch, outcome):
    calls = []

    async def run(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "run":
            raise asyncio.TimeoutError if outcome == "timeout" else asyncio.CancelledError
        return ExecutionResult(0, b"", b"")

    monkeypatch.setattr(command_runner, "run_subprocess", run)
    config = BackendConfig(backend="docker", image="tools:lab", network="scope-lab",
                           network_policy_attested=True)
    invocation = Scanner(config).perform_nmap_scan("10.0.0.1", "quick")
    if outcome == "cancel":
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(invocation)
    else:
        assert asyncio.run(invocation)["success"] is False
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[1] == ["docker", "rm", "--force", name]


def test_searchsploit_uses_backend_and_preserves_list_shape(monkeypatch):
    monkeypatch.setenv("SCOPE_ALLOWLIST", "")
    calls = []

    async def run(argv, **kwargs):
        calls.append(argv)
        return ExecutionResult(0, b'{"RESULTS_EXPLOIT": [{"Title": "CVE-2020-1234", "Path": "entry"}]}', b"")

    monkeypatch.setattr(command_runner, "run_subprocess", run)
    result = asyncio.run(Scanner().searchsploit_lookup("service; literal", "1.0"))
    assert result[0]["cve_ids"] == ["CVE-2020-1234"]
    assert calls == [["searchsploit", "--json", "-t", "service; literal 1.0"]]


def test_scanner_constructor_does_not_probe_local_nmap():
    assert isinstance(Scanner(), Scanner)

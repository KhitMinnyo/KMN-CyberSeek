"""Offline scope/backend regressions. Real subprocess tests run only local sleepers."""

import asyncio
import os
import shlex
import signal
import sys
from dataclasses import replace

import pytest

from core import command_runner
from core.command_runner import (
    BackendConfig, CommandTimeoutError, ExecutionResult, backend_config_from_env,
    execute_command, plan_execution, run_subprocess,
)
from core.playbooks import PLAYBOOKS
from core.validators import (
    check_command_scope, extract_command_destinations, is_target_in_scope,
    is_valid_target,
)


SCOPE = "10.0.0.0/24,2001:db8::/48,example.test,*.example.test"
DOCKER = BackendConfig(backend="docker", image="kmn-tools:lab", network="scope-lab",
                       network_policy_attested=True)


@pytest.mark.parametrize("command,expected", [
    ("nmap -sV -p443 -T4 10.0.0.7", ["10.0.0.7"]),
    ("nmap -6 -p 443 2001:db8::/64", ["2001:db8::/64"]),
    ("nmap -- 10.0.0.0/28 app.example.test", ["10.0.0.0/28", "app.example.test"]),
    ("ping -c 1 APP.EXAMPLE.TEST.", ["app.example.test"]),
    ("/usr/bin/ping -c 1 example.test", ["example.test"]),
    ("ping6 -c 1 2001:db8::10", ["2001:db8::10"]),
    ("curl 'https://user:pass@[2001:db8::9]:8443/a%20b'", ["2001:db8::9"]),
    ("curl --url=https://example.test:443/ --proxy 'http://[2001:db8::1]:8080'",
     ["2001:db8::1", "example.test"]),
    ("wget --max-redirect=0 https://example.test/", ["example.test"]),
    ("smbclient '//[2001:db8::2]/share' -N", ["2001:db8::2"]),
    ("smbclient -L example.test -N", ["example.test"]),
    ("ftp -n example.test 21", ["example.test"]),
    ("nc -z -w 1 10.0.0.8 443", ["10.0.0.8"]),
    ("mysql --host=example.test --user lab", ["example.test"]),
    ("redis-cli -h 2001:db8::2 -p 6379", ["2001:db8::2"]),
    ("set RHOSTS 10.0.0.0/28", ["10.0.0.0/28"]),
])
def test_supported_destinations(command, expected):
    assert extract_command_destinations(command) == expected
    assert check_command_scope(command, SCOPE) is None


@pytest.mark.parametrize("command", [
    "nmap -sV 203.0.113.5", "nmap example.test outside.test",
    "nmap 10.0.0.0/16", "nmap 2001:db9::/64",
    "ping -c 1 outside.test", "nc -z outside.test 443", "ftp -n outside.test",
    "curl https://example.test https://outside.test",
    "curl --url=https://outside.test/",
    "curl https://example.test --proxy http://outside.test:8080",
    "smbclient //outside.test/share -N", "mysql -h outside.test",
    "curl http://[2001:db9::1]:80/",
])
def test_out_of_scope_positional_and_option_targets(command):
    assert check_command_scope(command, SCOPE) is not None


@pytest.mark.parametrize("command", [
    "", "unknown-tool 10.0.0.1", "unknown-tool --host 10.0.0.1",
    "ssh example.test", "env curl https://example.test", "sudo nmap 10.0.0.1",
    "/tmp/nmap 10.0.0.1", "python3 -c 'print(1)'", "bash -c 'echo local'",
    "nmap", "nmap -iL targets.txt", "nmap -sV -iL targets.txt 10.0.0.1",
    "nmap --script evil.nse 10.0.0.1", "nmap 10.0.0.1-200", "nmap -p",
    "curl --config data https://example.test", "curl -L https://example.test",
    "curl --resolve outside.test:443:10.0.0.1 https://example.test",
    "curl --connect-to example.test:443:outside.test:443 https://example.test",
    "curl 'https://{example,outside}.test/'", "curl 'https://[example].test/'",
    "curl http://[2001:db8::1", "curl http://example.test:99999/",
    "curl http://example.test:zero/", "curl http://example.test:0/",
    "curl http://%65xample.test/", "curl file:///etc/passwd",
    "curl --url example.test", "/usr/bin/../tmp/nmap 10.0.0.1",
    "wget https://example.test", "wget --max-redirect=1 https://example.test",
    "curl -H", "mysql", "redis-cli PING", "ftp", "smbclient",
    "nmap $TARGET", "nmap '$(echo 10.0.0.1)'", "nmap `echo 10.0.0.1`",
    "nmap 10.0.0.1; curl https://outside.test",
    "nmap 10.0.0.1 && curl https://outside.test",
    "nmap --host 10.0.0.1", "sort --compress-program='curl https://outside.test' data",
    "sort --compress-prog='curl https://outside.test' data",
    "echo local\nnmap outside.test", "echo local > /tmp/test",
    "nmap '10.0.0.1", "nmap 10.0.0.1\x00", "set RHOSTS file:targets.txt",
])
def test_ambiguous_or_uninspectable_commands_fail_closed(command):
    assert check_command_scope(command, SCOPE) is not None


@pytest.mark.parametrize("command", [
    "echo hello", "printf '%s' hello", "ls -la /tmp", "cat /tmp/report.txt",
    "head -n 10 /tmp/report.txt", "grep -i error /tmp/report.txt", "whoami",
    "id", "pwd", "uname -a", "date", "wc -l /tmp/report.txt", "/bin/echo local",
])
def test_common_hostless_local_commands(command):
    assert check_command_scope(command, SCOPE) is None


@pytest.mark.parametrize("step", [
    step for steps in PLAYBOOKS.values() for step in steps if step.tool == "nmap" and step.command
], ids=lambda step: step.id)
def test_generated_nmap_playbooks_are_scoped(step):
    command = step.render({"host": "10.0.0.7", "port": 443})
    assert extract_command_destinations(command) == ["10.0.0.7"]
    assert plan_execution(command, "playbook", scope_allowlist=SCOPE).error is None
    assert check_command_scope(step.render({"host": "203.0.113.7", "port": 443}), SCOPE)


@pytest.mark.parametrize("method,args,target", [
    ("perform_nmap_scan", (profile,), "10.0.0.7")
    for profile in ("quick", "default", "full", "stealth", "vuln", "allports")
] + [
    ("perform_service_discovery", ([80, 443],), "10.0.0.7"),
    ("perform_subnet_sweep", (), "10.0.0.0/28"),
    ("perform_vulnerability_scan", ([80, 443],), "10.0.0.7"),
    ("perform_vulnerability_scan_port", (443,), "10.0.0.7"),
    ("check_port_status", (443,), "10.0.0.7"),
])
def test_generated_scanner_commands_reach_scoped_runner(monkeypatch, method, args, target):
    from core.scanner import Scanner

    calls = []
    monkeypatch.setenv("SCOPE_ALLOWLIST", SCOPE)
    monkeypatch.setenv("NMAP_OS_DETECTION", "true")
    monkeypatch.setenv("SCAN_TIMEOUT", "300")
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)

    async def run(argv, **kwargs):
        calls.append(argv)
        return ExecutionResult(0, b"Nmap scan report for 10.0.0.7\nHost is up\n443/tcp open https\n", b"")

    monkeypatch.setattr(command_runner, "run_subprocess", run)
    result = asyncio.run(getattr(Scanner(backend_config=BackendConfig()), method)(target, *args))
    assert result["success"] is True, result
    assert len(calls) == 1
    assert calls[0][-1] == target
    if method == "perform_nmap_scan" and args[0] in {"default", "full", "allports"}:
        assert "-O" in calls[0] and "--osscan-guess" in calls[0]


def test_generated_udp_scan_command_is_scoped():
    from core.nmap_parser import build_udp_scan_command

    command = build_udp_scan_command("2001:db8::7", output_xml="/tmp/udp.xml")
    assert check_command_scope(command, SCOPE) is None
    assert check_command_scope(build_udp_scan_command("2001:db9::7"), SCOPE)


@pytest.mark.parametrize("selector", [
    "vuln", "vuln and not intrusive", "default", "http-title", "ftp-vuln*",
    "smb-protocols,smb-security-mode", "rmi-dumpregistry,jmx-info",
])
@pytest.mark.parametrize("assignment", [False, True])
def test_reviewed_nmap_script_selectors(selector, assignment):
    option = ["--script=" + selector] if assignment else ["--script", selector]
    command = shlex.join(["nmap", "-sT", "-Pn", "-sV", *option, "10.0.0.7"])
    assert check_command_scope(command, SCOPE) is None
    assert check_command_scope(command.replace("10.0.0.7", "203.0.113.7"), SCOPE)


@pytest.mark.parametrize("selector", [
    "evil.nse", "/tmp/http-title.nse", "./http-title", "../http-title",
    "http-title.nse", "http-title,/tmp/custom.nse", "http-title,evil",
    "http-title,,mysql-info", "http-title,", "*", "http-*", "ftp-*",
    "ftp-vuln*/../custom", "ftp-vuln-custom", "+http-title", "all", "external",
    "vuln or external", "vuln and not intrusive or /tmp/evil.nse",
    "not intrusive", "(vuln)", "vuln,http-title", "http-title 203.0.113.7",
])
def test_unreviewed_nmap_script_selectors_rejected(selector):
    command = shlex.join(["nmap", "--script", selector, "10.0.0.7"])
    assert check_command_scope(command, SCOPE)


@pytest.mark.parametrize("option", [
    "--script-args=http.host=203.0.113.7", "--script-args-file=/tmp/args",
    "--datadir=/tmp/custom", "--script-updatedb", "--proxies=http://203.0.113.7",
    "--resume=/tmp/scan", "--script-help=http-title", "--unknown-option",
])
def test_script_and_routing_overrides_stay_rejected(option):
    assert check_command_scope(f"nmap --script http-title {option} 10.0.0.7", SCOPE)


@pytest.mark.parametrize("option", [
    "--host-timeout", "--scan-delay", "--max-rtt-timeout", "--script-timeout",
])
@pytest.mark.parametrize("value", ["30", "500ms", "20s", "2m", "1h", "0.5s", ".5s"])
def test_nmap_numeric_time_suffixes(option, value):
    assert check_command_scope(f"nmap --script http-title {option} {value} 10.0.0.7", SCOPE) is None
    assert check_command_scope(f"nmap {option}={value} 10.0.0.7", SCOPE) is None


@pytest.mark.parametrize("value", ["NaN", "inf", "1e3", "-1s", "30seconds", "1s,evil", "203.0.113.7"])
def test_nmap_malformed_times_rejected(value):
    assert check_command_scope(f"nmap --script-timeout={value} --script http-title 10.0.0.7", SCOPE)


@pytest.mark.parametrize("query", ["OpenSSH 7.2", "service; literal 1.0", "http://outside.test", "/tmp/query"])
def test_local_searchsploit_query_is_not_a_network_target(query):
    command = shlex.join(["searchsploit", "--json", "-t", query])
    assert extract_command_destinations(command) == []
    assert plan_execution(command, "ai_auto", scope_allowlist=SCOPE).error is None


@pytest.mark.parametrize("command", [
    "searchsploit openssh 7.2", "searchsploit -j -t openssh",
    "searchsploit --exact --strict --case OpenSSH",
])
def test_local_searchsploit_search_options(command):
    assert check_command_scope(command, SCOPE) is None


@pytest.mark.parametrize("command", [
    "searchsploit", "searchsploit --json -t", "searchsploit -u",
    "searchsploit --update openssh", "searchsploit -x 12345",
    "searchsploit --examine 12345", "searchsploit -m 12345", "searchsploit --mirror 12345",
    "searchsploit --nmap /tmp/scan.xml", "searchsploit --unknown openssh",
    "searchsploit -- --update", "searchsploit '-u query'", "searchsploit --json=openssh",
])
def test_nonquery_searchsploit_modes_rejected(command):
    assert check_command_scope(command, SCOPE)


def test_generated_searchsploit_lookup_reaches_scoped_runner(monkeypatch):
    from core.scanner import Scanner

    calls = []
    monkeypatch.setenv("SCOPE_ALLOWLIST", SCOPE)

    async def run(argv, **kwargs):
        calls.append(argv)
        return ExecutionResult(0, b'{"RESULTS_EXPLOIT": [{"Title": "example", "Path": "entry"}]}', b"")

    monkeypatch.setattr(command_runner, "run_subprocess", run)
    result = asyncio.run(Scanner(backend_config=BackendConfig()).searchsploit_lookup("OpenSSH", "7.2"))
    assert result[0]["title"] == "example"
    assert calls == [["searchsploit", "--json", "-t", "OpenSSH 7.2"]]


@pytest.mark.parametrize("scope", [",", "10.0.0.0/24,", "not a host", "*",
                                       "*.10.0.0.1", "2001:db8::/999"])
def test_malformed_scope_never_unrestricted(scope):
    assert not is_target_in_scope("10.0.0.1", scope)
    assert check_command_scope("echo local", scope) is not None


def test_ip_family_subnet_and_dns_boundaries():
    assert is_target_in_scope("2001:db8::1", "2001:db8::/48")
    assert is_target_in_scope("2001:db8:0:1::/64", "2001:db8::/48")
    assert not is_target_in_scope("2001:db8::/32", "2001:db8::/48")
    assert not is_target_in_scope("2001:db8::1", "10.0.0.0/24")
    assert not is_target_in_scope("10.0.0.1", "2001:db8::/48")
    assert not is_target_in_scope("example.test", "*.example.test")
    assert not is_target_in_scope("evilexample.test", "*.example.test")
    assert not is_target_in_scope("app.example.test.evil", "*.example.test")
    assert is_target_in_scope("APP.Example.Test.", "*.EXAMPLE.TEST.")
    assert not is_target_in_scope("999.0.0.1", "*.0.0.1")
    assert not is_target_in_scope("example.test", "10.0.0.0/24")
    assert is_valid_target("example.test.")
    assert not is_valid_target("example.test..")
    assert not is_valid_target("fe80::1%eth0")
    assert not is_valid_target("999.0.0.1")
    assert not is_valid_target("127.000.000.001")


def test_no_scope_preserves_unrestricted_legacy_check():
    assert check_command_scope("unrecognized-tool --anything", None) is None
    assert check_command_scope("unrecognized-tool --anything", "") is None


def test_local_default_is_explicitly_unisolated(monkeypatch):
    monkeypatch.setenv("EXECUTION_BACKEND", "docker")
    plan = plan_execution("echo hello", "ai_auto", scope_allowlist=SCOPE,
                          environment={"LANG": "C", "HOME": "/secret", "API_KEY": "secret"})
    assert plan.error is None
    assert plan.backend == "local"
    assert "unisolated" in plan.isolation
    assert plan.argv == ["echo", "hello"]
    assert plan.environment["LANG"] == "C"
    assert "API_KEY" not in plan.environment and "HOME" not in plan.environment


def test_backend_environment_defaults_and_canonical_names(monkeypatch):
    assert backend_config_from_env({}) == BackendConfig()
    settings = {
        "KMN_EXECUTION_BACKEND": "docker", "KMN_DOCKER_IMAGE": "tools:lab",
        "KMN_DOCKER_NETWORK": "scope-lab", "KMN_DOCKER_NETWORK_POLICY_ATTESTED": "true",
        "KMN_DOCKER_MEMORY_MB": "768", "KMN_DOCKER_CPUS": "0.5",
        "KMN_DOCKER_PIDS_LIMIT": "32",
        "KMN_EXECUTION_IMAGE": "ignored:legacy", "KMN_EXECUTION_NETWORK": "host",
    }
    for key, value in settings.items():
        monkeypatch.setenv(key, value)
    config = backend_config_from_env()
    assert config == replace(DOCKER, image="tools:lab", memory_mb=768, cpus=0.5, pids_limit=32)
    assert backend_config_from_env({"KMN_EXECUTION_IMAGE": "ignored:legacy"}) == BackendConfig()
    assert backend_config_from_env({"KMN_DOCKER_NETWORK_POLICY_ATTESTED": "false"}).network_policy_attested is False


@pytest.mark.parametrize("key,value", [
    ("KMN_EXECUTION_BACKEND", value) for value in ("", "unknown", "Docker", " local")
] + [
    ("KMN_DOCKER_NETWORK_POLICY_ATTESTED", value)
    for value in ("", "TRUE", "False", "1", "0", "yes", " true ", "unknown")
] + [
    (key, value) for key in ("KMN_DOCKER_MEMORY_MB", "KMN_DOCKER_PIDS_LIMIT")
    for value in ("", "0", "-1", "1.5", "NaN", "inf", " 64", "+64", "1_000")
] + [
    ("KMN_DOCKER_CPUS", value)
    for value in ("", "0", "-1", "nan", "inf", "1e999", "1e-999", " 1", "1_000", "true")
] + [
    ("KMN_DOCKER_IMAGE", value) for value in ("--privileged", "tools lab", "tools\x00")
] + [
    ("KMN_DOCKER_NETWORK", value)
    for value in ("", "host", "bridge", "default", "container:other", "scope lab", "none\x00")
])
def test_backend_environment_invalid_values_fail_closed(key, value):
    # Validate even Docker settings supplied alongside the default local backend.
    with pytest.raises(ValueError, match=key):
        backend_config_from_env({key: value})


def test_backend_environment_docker_requires_canonical_image():
    with pytest.raises(ValueError, match="KMN_DOCKER_IMAGE"):
        backend_config_from_env({"KMN_EXECUTION_BACKEND": "docker",
                                 "KMN_EXECUTION_IMAGE": "ignored:legacy"})


def test_plan_reads_scope_environment(monkeypatch):
    monkeypatch.setenv("SCOPE_ALLOWLIST", SCOPE)
    assert plan_execution("ping outside.test", "manual").error
    assert plan_execution("ping outside.test", "manual", scope_allowlist="").error is None


@pytest.mark.parametrize("config", [
    replace(DOCKER, image=""), replace(DOCKER, image="--privileged"),
    replace(DOCKER, network="none"), replace(DOCKER, network="host"),
    replace(DOCKER, network="bridge"), replace(DOCKER, network="container:other"),
    replace(DOCKER, network="scope-lab --privileged"),
    replace(DOCKER, network_policy_attested=False),
    replace(DOCKER, network_policy_attested="true"),
    replace(DOCKER, memory_mb=0), replace(DOCKER, pids_limit=-1),
    replace(DOCKER, cpus=float("inf")), replace(DOCKER, cpus=float("nan")),
    replace(DOCKER, cpus=True),
    BackendConfig(backend="unrecognized"),
])
def test_invalid_or_unattested_docker_plans_fail(config):
    assert plan_execution("ping 10.0.0.1", "manual", config=config,
                          scope_allowlist=SCOPE).error


def test_docker_argv_hardening_and_environment_boundary():
    command = "curl -H 'X-Test: value; literal' 'https://example.test/a?x=1&y=2'"
    plan = plan_execution(command, "ai_auto", config=DOCKER, scope_allowlist=SCOPE,
                          environment={"LANG": "C", "HOME": "/secret", "DOCKER_HOST": "evil",
                                       "HTTP_PROXY": "evil", "OPENAI_API_KEY": "secret"})
    assert plan.error is None
    argv = plan.argv
    assert argv[0:2] == ["docker", "run"]
    for flag in ["--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--pull=never", "--init", "--rm", "--pids-limit", "--cpus", "--memory"]:
        assert flag in argv
    assert argv[argv.index("--user") + 1] == "65534:65534"
    assert argv[argv.index("--network") + 1] == "scope-lab"
    assert argv[argv.index("--entrypoint") + 1] == "curl"
    assert argv[argv.index(DOCKER.image) + 1:] == shlex.split(command)[1:]
    assert "LANG=C" in argv
    assert not any(flag in argv for flag in ["--privileged", "--cap-add", "-v", "--volume", "--mount", "-p", "--publish"])
    assert not any(value in " ".join(argv) for value in ["/secret", "OPENAI_API_KEY", "HTTP_PROXY", "DOCKER_HOST"])
    assert set(plan.environment) == {"PATH"}


def test_docker_network_none_only_for_unscoped_execution():
    config = BackendConfig(backend="docker", image="kmn-tools:lab")
    assert plan_execution("echo local", "manual", config=config, scope_allowlist="").error is None
    assert plan_execution("echo local", "manual", config=config, scope_allowlist=SCOPE).error


def test_backend_rejects_shell_even_when_autonomous_shell_opted_in(monkeypatch):
    monkeypatch.setenv("AUTONOMOUS_SHELL_COMPOSITION", "true")
    plan = plan_execution("echo hello | cat", "ai_auto", config=DOCKER, scope_allowlist="")
    assert plan.error and "single argv" in plan.error


def test_direct_api_keeps_autonomous_capability_checks():
    assert plan_execution("rm -rf /tmp/lab", "ai_auto", scope_allowlist="").error
    assert plan_execution("unknown-tool", "ai_auto", scope_allowlist="").error
    assert plan_execution("python3 -c 'print(1)'", "ai_auto", scope_allowlist="").error


def test_environment_allowlist_is_explicit_and_validated():
    config = replace(DOCKER, environment_allowlist=("LANG", "REPORT_MODE"))
    plan = plan_execution("echo local", "manual", config=config, scope_allowlist=SCOPE,
                          environment={"REPORT_MODE": "brief; literal", "API_KEY": "secret"})
    assert plan.error is None
    assert "REPORT_MODE=brief; literal" in plan.argv
    assert "API_KEY=secret" not in plan.argv
    assert plan_execution("echo local", "manual", config=replace(config, environment_allowlist=("BAD=KEY",)),
                          scope_allowlist=SCOPE).error


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_subprocess_invalid_timeouts_rejected(timeout):
    with pytest.raises(ValueError):
        asyncio.run(run_subprocess(["echo", "local"], timeout=timeout))


def test_subprocess_argv_is_literal_and_stdin_closed():
    async def check():
        result = await run_subprocess(
            [sys.executable, "-c", "import sys; print(repr(sys.argv[1])); print(repr(sys.stdin.read()))",
             "$(echo injected); literal"], timeout=5, environment={"PATH": os.defpath},
        )
        assert result.returncode == 0
        assert b"$(echo injected); literal" in result.stdout
        assert b"''" in result.stdout
    asyncio.run(check())


@pytest.mark.parametrize("cancel", [False, True])
def test_timeout_and_cancel_kill_process_group(monkeypatch, cancel):
    real_spawn = asyncio.create_subprocess_exec
    real_killpg = os.killpg
    processes, killed = [], []

    async def spawn(*args, **kwargs):
        process = await real_spawn(*args, **kwargs)
        processes.append(process)
        return process

    def killpg(pid, sig):
        killed.append((pid, sig))
        return real_killpg(pid, sig)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(os, "killpg", killpg)

    async def check():
        # A child inherits the pipes. Killing only the leader would leave
        # communicate() stuck until this child's sleep completes.
        code = ("import subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                "sys.stdout.buffer.write(b'partial stdout\\x00\\xff'); sys.stdout.flush(); "
                "sys.stderr.buffer.write(b'partial stderr\\x00\\xfe'); sys.stderr.flush(); time.sleep(30)")
        task = asyncio.create_task(run_subprocess([sys.executable, "-c", code], timeout=0.5 if not cancel else 10))
        if cancel:
            while not processes:
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.1)
            task.cancel()
        with pytest.raises(asyncio.CancelledError if cancel else CommandTimeoutError) as caught:
            await task
        if not cancel:
            assert isinstance(caught.value, TimeoutError)
            assert isinstance(caught.value, asyncio.TimeoutError)
            assert caught.value.stdout == b"partial stdout\x00\xff"
            assert caught.value.stderr == b"partial stderr\x00\xfe"
        assert processes[0].returncode is not None
        assert (processes[0].pid, signal.SIGKILL) in killed
    asyncio.run(check())


def test_cancel_during_startup_reaps_spawned_process(monkeypatch):
    real_spawn = asyncio.create_subprocess_exec
    processes = []

    async def check():
        started, release = asyncio.Event(), asyncio.Event()

        async def spawn(*args, **kwargs):
            process = await real_spawn(*args, **kwargs)
            processes.append(process)
            started.set()
            await release.wait()
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        task = asyncio.create_task(run_subprocess([sys.executable, "-c", "import time; time.sleep(30)"]))
        await started.wait()
        task.cancel()
        await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert processes[0].returncode is not None
    asyncio.run(check())


def test_execute_rejection_never_spawns(monkeypatch):
    async def unexpected(*args, **kwargs):
        pytest.fail("Rejected command spawned a process")
    monkeypatch.setattr(command_runner, "run_subprocess", unexpected)
    with pytest.raises(ValueError):
        asyncio.run(execute_command("ping outside.test", "manual", config=DOCKER,
                                    scope_allowlist=SCOPE))


@pytest.mark.parametrize("outcome", ["success", "timeout", "cancel"])
def test_docker_cleanup_removes_container_on_every_exit(monkeypatch, outcome):
    calls = []

    async def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "run":
            if outcome == "timeout":
                raise asyncio.TimeoutError
            if outcome == "cancel":
                raise asyncio.CancelledError
            return ExecutionResult(0, b"ok", b"")
        return ExecutionResult(0, b"", b"")

    monkeypatch.setattr(command_runner, "run_subprocess", fake_run)
    invocation = execute_command("ping 10.0.0.1", "manual", config=DOCKER, scope_allowlist=SCOPE)
    if outcome == "success":
        assert asyncio.run(invocation).stdout == b"ok"
    else:
        with pytest.raises(asyncio.TimeoutError if outcome == "timeout" else asyncio.CancelledError):
            asyncio.run(invocation)
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[1] == ["docker", "rm", "--force", name]


def test_docker_cleanup_failure_is_visible(monkeypatch):
    async def fake_run(argv, **kwargs):
        return ExecutionResult(0, b"ok", b"") if argv[1] == "run" else ExecutionResult(1, b"", b"daemon unavailable")
    monkeypatch.setattr(command_runner, "run_subprocess", fake_run)
    with pytest.raises(RuntimeError, match="cleanup failed"):
        asyncio.run(execute_command("echo local", "manual", config=DOCKER, scope_allowlist=SCOPE))


def test_cancellation_during_docker_removal_waits_and_propagates(monkeypatch):
    async def check():
        removing, release = asyncio.Event(), asyncio.Event()

        async def fake_run(argv, **kwargs):
            if argv[1] == "rm":
                removing.set()
                await release.wait()
            return ExecutionResult(0, b"ok", b"")

        monkeypatch.setattr(command_runner, "run_subprocess", fake_run)
        task = asyncio.create_task(execute_command("echo local", "manual", config=DOCKER,
                                                   scope_allowlist=SCOPE))
        await removing.wait()
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(check())

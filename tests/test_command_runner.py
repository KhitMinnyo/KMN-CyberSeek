from core.command_runner import plan_command


def test_simple_command_uses_argv_plan():
    plan = plan_command("nmap -sV 10.0.0.5", "ai_auto")
    assert plan.error is None
    assert plan.mode == "argv"
    assert plan.argv == ["nmap", "-sV", "10.0.0.5"]


def test_quoted_msf_x_command_is_still_argv():
    plan = plan_command("msfconsole -q -x 'use exploit/x; run -z'", "ai_auto")
    assert plan.error is None
    assert plan.mode == "argv"
    assert plan.argv[-1] == "use exploit/x; run -z"


def test_compound_shell_is_denied_for_autonomous_mode(monkeypatch):
    monkeypatch.delenv("AUTONOMOUS_SHELL_COMPOSITION", raising=False)
    plan = plan_command("nmap -sV 10.0.0.5 | tee /tmp/out", "ai_auto")
    assert plan.error and "Compound shell syntax" in plan.error


def test_compound_shell_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("AUTONOMOUS_SHELL_COMPOSITION", "true")
    plan = plan_command("nmap -sV 10.0.0.5 | tee /tmp/out", "ai_auto")
    assert plan.error is None and plan.mode == "shell"


def test_runtime_is_denied_for_autonomous_host_execution(monkeypatch):
    monkeypatch.delenv("AUTONOMOUS_RUNTIME_COMMANDS", raising=False)
    plan = plan_command("python3 -c 'print(1)'", "ai_auto")
    assert plan.error and "Runtime 'python3'" in plan.error

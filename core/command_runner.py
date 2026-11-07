"""Command execution planning for the autonomous gateway.

The planner prefers argv execution. Shell composition is an explicit capability
because a binary allowlist cannot make an unrestricted shell/interpreter safe.
"""

import os
import shlex
import asyncio
import math
import re
import signal
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import List, Optional, Mapping, Tuple


_RUNTIMES = {
    "bash", "sh", "zsh", "dash", "fish", "python", "python3", "python2",
    "perl", "ruby", "node", "nodejs", "php",
}


@dataclass
class _ExecutionBudget:
    semaphore: asyncio.Semaphore
    limits: Tuple[int, int]
    admitted: int = 0


@asynccontextmanager
async def execution_slot():
    """Bound actual executions and waiters across all callers on this event loop.

    Limits come only from the trusted process environment and are fixed for the
    loop's lifetime. Invalid or changed configuration fails closed. This is not
    a distributed limit across workers, nor a lock for an AI continuation loop.
    """
    limits = []
    for key, default, minimum in (("KMN_MAX_EXECUTIONS", "3", 1),
                                  ("KMN_MAX_QUEUED_EXECUTIONS", "32", 0)):
        raw = os.environ.get(key, default)
        if not re.fullmatch(r"[0-9]+", raw) or int(raw) < minimum:
            raise ValueError(f"{key} must be an integer >= {minimum}")
        limits.append(int(raw))
    limits = tuple(limits)
    loop = asyncio.get_running_loop()
    # Keep state on the loop so a contended semaphore cannot retain closed loops
    # through a module-level registry. All callers share this single budget.
    budget = getattr(loop, "_kmn_execution_budget", None)
    if budget is None:
        budget = _ExecutionBudget(asyncio.Semaphore(limits[0]), limits)
        loop._kmn_execution_budget = budget
    elif budget.limits != limits:
        raise ValueError("Execution budget configuration changed; restart the event loop")
    # No await between checking and reserving admission. Count active executions
    # plus waiters, including a waiter whose semaphore permit is being handed off.
    if budget.admitted >= sum(limits):
        raise RuntimeError("Execution queue is saturated")
    budget.admitted += 1
    try:
        async with budget.semaphore:
            yield
    finally:
        budget.admitted -= 1


@dataclass
class CommandPlan:
    mode: str  # argv | shell
    argv: Optional[List[str]] = None
    shell_command: str = ""
    error: Optional[str] = None


def _has_unquoted_shell_syntax(command: str) -> bool:
    quote = None
    escaped = False
    for char in command:
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            continue
        if char in ";|&<>`\n\r":
            return True
    return False


def plan_command(command: str, execution_mode: str) -> CommandPlan:
    """Build an argv-first execution plan or return a policy error."""
    command = (command or "").strip()
    if not command:
        return CommandPlan("argv", error="Empty command")

    autonomous = execution_mode in {"ai_auto", "playbook"}
    if _has_unquoted_shell_syntax(command):
        if autonomous and os.getenv("AUTONOMOUS_SHELL_COMPOSITION", "false").lower() != "true":
            return CommandPlan(
                "shell",
                error=(
                    "Compound shell syntax is disabled for autonomous execution. "
                    "Use a single argv command or explicitly enable "
                    "AUTONOMOUS_SHELL_COMPOSITION in an isolated lab."
                ),
            )
        return CommandPlan("shell", shell_command=command)

    try:
        argv = shlex.split(command, posix=True)
    except ValueError as exc:
        return CommandPlan("argv", error=f"Command parsing failed: {exc}")
    if not argv:
        return CommandPlan("argv", error="Empty command")

    binary = os.path.basename(argv[0])
    if autonomous and binary in _RUNTIMES:
        if os.getenv("AUTONOMOUS_RUNTIME_COMMANDS", "false").lower() != "true":
            return CommandPlan(
                "argv",
                error=(
                    f"Runtime '{binary}' is disabled for autonomous host execution. "
                    "Use a purpose-built tool or explicitly opt in inside an isolated lab."
                ),
            )
    return CommandPlan("argv", argv=argv)


@dataclass(frozen=True)
class BackendConfig:
    """Trusted operator configuration, never populated from model/tool output.

    Local is the shipped, unisolated default. The explicit environment loader
    can select Docker. Attestation asserts externally enforced scope egress;
    a Docker bridge or its `internal` flag alone is not that policy.
    """

    backend: str = "local"
    image: str = ""
    network: str = "none"
    network_policy_attested: bool = False
    environment_allowlist: Tuple[str, ...] = ("LANG", "LC_ALL", "TZ")
    docker_binary: str = "docker"
    memory_mb: int = 512
    cpus: float = 1.0
    pids_limit: int = 64


def backend_config_from_env(
    environment: Optional[Mapping[str, str]] = None,
) -> BackendConfig:
    """Load canonical trusted operator settings; invalid values raise ValueError.

    This source must never be populated from model, request, or tool output.
    Scope-dependent network attestation requirements remain in plan_execution.
    """
    source = os.environ if environment is None else environment
    backend = source.get("KMN_EXECUTION_BACKEND", "local")
    if backend not in {"local", "docker"}:
        raise ValueError("KMN_EXECUTION_BACKEND must be local or docker")
    image = source.get("KMN_DOCKER_IMAGE", "")
    if ((image and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]*", image))
            or (backend == "docker" and not image)):
        raise ValueError("KMN_DOCKER_IMAGE must name an explicit preprovisioned image")
    network = source.get("KMN_DOCKER_NETWORK", "none")
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", network)
            or network.lower() in {"host", "bridge", "default"}):
        raise ValueError("KMN_DOCKER_NETWORK must be none or a dedicated network name")
    attested = source.get("KMN_DOCKER_NETWORK_POLICY_ATTESTED", "false")
    if attested not in {"true", "false"}:
        raise ValueError("KMN_DOCKER_NETWORK_POLICY_ATTESTED must be true or false")
    limits = {}
    for name, default in (("MEMORY_MB", "512"), ("CPUS", "1.0"), ("PIDS_LIMIT", "64")):
        key = "KMN_DOCKER_" + name
        raw = source.get(key, default)
        pattern = (r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?"
                   if name == "CPUS" else r"[0-9]+")
        if not re.fullmatch(pattern, raw):
            raise ValueError(f"{key} must be a positive finite {'number' if name == 'CPUS' else 'integer'}")
        value = float(raw) if name == "CPUS" else int(raw)
        if value <= 0 or (name == "CPUS" and not math.isfinite(value)):
            raise ValueError(f"{key} must be positive and finite")
        limits[name.lower()] = value
    return BackendConfig(
        backend=backend, image=image, network=network,
        network_policy_attested=attested == "true", **limits,
    )


@dataclass
class ExecutionPlan:
    argv: List[str] = field(default_factory=list)
    backend: str = "local"
    isolation: str = "unisolated host execution"
    environment: Mapping[str, str] = field(default_factory=dict)
    container_name: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ExecutionResult:
    returncode: int
    stdout: bytes
    stderr: bytes


# Before Python 3.11 asyncio.TimeoutError is distinct from the built-in type.
if asyncio.TimeoutError is not TimeoutError:
    class _CommandTimeoutBase(asyncio.TimeoutError, TimeoutError):
        pass
else:
    _CommandTimeoutBase = TimeoutError


class CommandTimeoutError(_CommandTimeoutBase):
    """Command timed out; partial output is available after process cleanup."""

    def __init__(self, stdout: bytes, stderr: bytes):
        super().__init__("Command timed out")
        self.stdout = stdout
        self.stderr = stderr


def plan_execution(
    command: str,
    execution_mode: str,
    *,
    config: Optional[BackendConfig] = None,
    scope_allowlist: Optional[str] = None,
    environment: Optional[Mapping[str, str]] = None,
) -> ExecutionPlan:
    """Plan the optional backend without starting a process or contacting Docker.

    The existing gateway must still perform authorization and non-interactive
    checks. Autonomous binary/capability checks are also retained here so direct
    callers cannot accidentally omit them. None scope reads SCOPE_ALLOWLIST;
    an explicit empty string requests the existing unrestricted scope mode.
    """
    from core.validators import (
        automation_capability_error, check_command_scope, is_allowlisted_command,
    )

    config = config or BackendConfig()
    plan = ExecutionPlan(backend=config.backend)
    if config.backend not in {"local", "docker"}:
        plan.error = "Unknown execution backend"
        return plan
    if config.backend == "docker":
        plan.isolation = "Docker process isolation; network policy is external"
    scope = os.getenv("SCOPE_ALLOWLIST", "") if scope_allowlist is None else scope_allowlist
    plan.error = check_command_scope(command, scope)
    if not plan.error and execution_mode in {"ai_auto", "playbook"}:
        plan.error = automation_capability_error(command) or is_allowlisted_command(command)
    if plan.error:
        return plan
    command_plan = plan_command(command, execution_mode)
    if command_plan.error:
        plan.error = command_plan.error
        return plan
    source = os.environ if environment is None else environment
    # Never inherit proxy variables, loader hooks, runtime startup hooks, Docker
    # connection settings, HOME, or API credentials by default.
    allowed = config.environment_allowlist
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) for key in allowed):
        plan.error = "Invalid environment allowlist"
        return plan
    selected = {key: source[key] for key in allowed if key in source}
    if any("\x00" in value for value in selected.values()):
        plan.error = "Invalid environment value"
        return plan
    host_environment = {"PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin", **selected}
    if config.backend == "local":
        plan.argv = (command_plan.argv if command_plan.mode == "argv"
                     else ["/bin/sh", "-c", command_plan.shell_command])
        plan.environment = host_environment
        return plan
    if command_plan.mode != "argv":
        plan.error = "Docker backend requires a single argv command; shell composition is unsupported"
        return plan
    if not config.image or config.image.startswith("-") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]*", config.image):
        plan.error = "Docker backend requires an explicit preprovisioned image"
        return plan
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", config.network)
            or config.network.lower() in {"host", "bridge", "default"}):
        plan.error = "Docker requires 'none' or an explicit dedicated isolated network"
        return plan
    if scope and scope.strip() and (
        config.network == "none" or config.network_policy_attested is not True
    ):
        plan.error = "Scoped Docker execution requires an isolated network and explicit external scope-policy attestation"
        return plan
    if config.network != "none" and config.network_policy_attested is not True:
        plan.error = "Docker networking requires explicit external network-policy attestation"
        return plan
    if (type(config.memory_mb) is not int or config.memory_mb <= 0
            or type(config.pids_limit) is not int or config.pids_limit <= 0
            or type(config.cpus) not in (int, float)
            or not math.isfinite(config.cpus) or config.cpus <= 0):
        plan.error = "Docker resource limits must be positive and finite"
        return plan
    plan.container_name = "kmn-command-" + uuid.uuid4().hex
    argv = command_plan.argv
    plan.argv = [
        config.docker_binary, "run", "--rm", "--pull=never", "--init",
        "--name", plan.container_name, "--network", config.network,
        "--user", "65534:65534", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--workdir", "/tmp", "--pids-limit", str(config.pids_limit),
        "--memory", f"{config.memory_mb}m", "--memory-swap", f"{config.memory_mb}m",
        "--cpus", str(config.cpus), "--ulimit", "nofile=1024:1024",
        "--log-driver=none", "--entrypoint", argv[0],
    ]
    for key, value in selected.items():
        plan.argv.extend(["--env", f"{key}={value}"])
    plan.argv.extend([config.image, *argv[1:]])
    # Container env is separate from the Docker client environment. In
    # particular, allowlisting HOME/DOCKER_HOST must not redirect the client.
    plan.environment = {"PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin"}
    return plan


async def run_subprocess(
    argv: List[str], *, timeout: float = 300,
    environment: Optional[Mapping[str, str]] = None,
    cwd: Optional[str] = None,
) -> ExecutionResult:
    """Execute argv with bounded lifetime and POSIX process-group cleanup.

    Returns raw output bytes; raises CommandTimeoutError with partial bytes or
    CancelledError only after killing/reaping the group. No shell interpretation
    or inherited stdin.
    Callers supplying environment=None explicitly get the host environment.
    """
    if not argv or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("A nonempty argv and positive finite timeout are required")
    # Shield startup too: cancellation between fork and assignment must not
    # orphan a process whose handle was never received by the caller.
    startup = asyncio.create_task(asyncio.create_subprocess_exec(
        *argv, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=environment, cwd=cwd, start_new_session=True,
    ))
    process = None
    communication = None

    async def cleanup():
        nonlocal process
        if process is None:
            process = await startup
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if communication is not None:
            output = await communication
        else:
            output = await process.communicate()
        await process.wait()
        return output

    try:
        process = await asyncio.shield(startup)
        communication = asyncio.create_task(process.communicate())
        stdout, stderr = await asyncio.wait_for(asyncio.shield(communication), timeout)
        # A child may outlive its leader even after closing inherited pipes.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return ExecutionResult(process.returncode, stdout, stderr)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        cleanup_task = asyncio.create_task(cleanup())
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                continue
        stdout, stderr = cleanup_task.result()
        if isinstance(exc, asyncio.TimeoutError):
            raise CommandTimeoutError(stdout, stderr) from exc
        raise


async def execute_command(
    command: str, execution_mode: str, *, config: Optional[BackendConfig] = None,
    scope_allowlist: Optional[str] = None, timeout: float = 300,
    environment: Optional[Mapping[str, str]] = None,
) -> ExecutionResult:
    """Integration entry point for an authorized orchestrator/scanner call.

    Policy errors raise ValueError before spawning. Docker timeout/cancellation
    also force-removes the named container; killing only its client is not enough.
    """
    config = config or BackendConfig()
    plan = plan_execution(command, execution_mode, config=config,
                          scope_allowlist=scope_allowlist, environment=environment)
    if plan.error:
        raise ValueError(plan.error)
    async with execution_slot():
        try:
            return await run_subprocess(plan.argv, timeout=timeout, environment=plan.environment)
        finally:
            if plan.container_name:
                async def remove_container():
                    result = await run_subprocess(
                        [config.docker_binary, "rm", "--force", plan.container_name],
                        timeout=10, environment=plan.environment,
                    )
                    if result.returncode and b"No such container" not in result.stderr:
                        raise RuntimeError("Docker container cleanup failed: " + result.stderr.decode(errors="replace"))

                removal = asyncio.create_task(remove_container())
                cancelled = False
                while not removal.done():
                    try:
                        await asyncio.shield(removal)
                    except asyncio.CancelledError:
                        cancelled = True
                removal.result()
                if cancelled:
                    raise asyncio.CancelledError

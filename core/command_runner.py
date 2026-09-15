"""Command execution planning for the autonomous gateway.

The planner prefers argv execution. Shell composition is an explicit capability
because a binary allowlist cannot make an unrestricted shell/interpreter safe.
"""

import os
import shlex
from dataclasses import dataclass
from typing import List, Optional


_RUNTIMES = {
    "bash", "sh", "zsh", "dash", "fish", "python", "python3", "python2",
    "perl", "ruby", "node", "nodejs", "php",
}


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
        if char in ";|&<>`":
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

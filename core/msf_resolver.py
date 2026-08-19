"""
KMN-CyberSeek CVE -> Metasploit module resolver.

Bridges a discovered CVE to a ready-to-use Metasploit module deterministically,
instead of relying on the LLM to remember whether a module exists. When a finding
carries a CVE, we ask the local `msfconsole` whether it ships a module for it
(`search cve:<id>`) and surface the module path to the AI so it can jump straight
to a known exploit path rather than improvising.

Kept intentionally cheap and safe:
  - No-op (returns []) when `msfconsole` is not installed.
  - Per-CVE in-memory cache so a repeated lookup is free.
  - Only the top prioritised CVEs are resolved by the caller (msfconsole startup
    is slow and heavy), so this never runs for every keyword CVE.
  - Never raises; every failure yields an empty result.
"""

import asyncio
import logging
import os
import re
import shutil
from typing import Dict, List

logger = logging.getLogger(__name__)

# module-path lines in `search` output, e.g. "exploit/windows/smb/ms17_010_eternalblue"
_MODULE_RE = re.compile(
    r"\b((?:exploit|auxiliary|post|payload|encoder|nop|evasion)/[\w./-]+)"
)

_cache: Dict[str, List[str]] = {}   # CVE (upper) -> [module paths]

# Search can take a while on first msfconsole spin-up; bound it.
_MSF_TIMEOUT = float(os.getenv("MSF_SEARCH_TIMEOUT", "30"))


def msfconsole_available() -> bool:
    return shutil.which("msfconsole") is not None


def is_enabled() -> bool:
    """CVE->module resolution is on by default but can be disabled (e.g. on hosts
    without Metasploit, or to keep runs fast)."""
    return (
        os.getenv("MSF_CVE_RESOLVE", "true").strip().lower() in ("1", "true", "yes", "on")
        and msfconsole_available()
    )


async def search_cve(cve_id: str) -> List[str]:
    """Return Metasploit module paths that match ``cve_id`` (cached, best-effort).

    Runs `msfconsole -q -x "search cve:<id>; exit -y"` and scrapes module paths
    from the output. Returns [] if msfconsole is missing, the search times out,
    or nothing matches.
    """
    cve = (cve_id or "").strip().upper()
    if not cve or not _CVE_ID_OK(cve):
        return []
    if cve in _cache:
        return _cache[cve]
    if not is_enabled():
        _cache[cve] = []
        return []

    cmd = f'msfconsole -q -x "search cve:{cve}; exit -y"'
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=_MSF_TIMEOUT)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            logger.warning(f"msf search cve:{cve} timed out")
            _cache[cve] = []
            return []
    except Exception as e:
        logger.warning(f"msf search cve:{cve} failed (non-fatal): {e}")
        _cache[cve] = []
        return []

    text = (out or b"").decode("utf-8", errors="replace")
    modules: List[str] = []
    seen = set()
    for m in _MODULE_RE.finditer(text):
        path = m.group(1).rstrip(".,")
        if path not in seen:
            seen.add(path)
            modules.append(path)
    # Prefer exploit/ modules first, keep the list short for the prompt.
    modules.sort(key=lambda p: (not p.startswith("exploit/"), p))
    modules = modules[:5]
    _cache[cve] = modules
    if modules:
        logger.info(f"msf modules for {cve}: {modules}")
    return modules


async def resolve_many(cve_ids: List[str], limit: int = 3) -> Dict[str, List[str]]:
    """Resolve modules for up to ``limit`` CVEs (sequentially, since each msf
    launch is heavy). Returns {CVE: [module paths]}; CVEs with no module are
    omitted. Safe to call with an empty/oversized list."""
    if not is_enabled():
        return {}
    out: Dict[str, List[str]] = {}
    seen = set()
    for cve in cve_ids:
        c = (cve or "").strip().upper()
        if not c or c in seen:
            continue
        seen.add(c)
        if len(seen) > limit:
            break
        mods = await search_cve(c)
        if mods:
            out[c] = mods
    return out


_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def _CVE_ID_OK(cve: str) -> bool:
    return bool(_CVE_ID_RE.match(cve or ""))

"""
KMN-CyberSeek Vulnerability Validation (Coverage Engine — M2)

Cuts the false positives that dominated raw findings (e.g. Tomcat 3.x/4.x CVEs
surfaced by unfiltered NVD keyword search against a Tomcat 8.5 target, or
Heartbleed tagged on a plain FTP service) and separates *potential* leads from
*confirmed* findings.

Pure functions — no I/O — so they are easy to unit-test and safe to import.

Contract: `validate(finding, discovered_version)` returns a possibly-modified copy
with two normalised fields:
  - status:     "confirmed" | "potential"
  - confidence: float in [0, 1]
and may set finding["suppressed"] = True with a reason when it's almost certainly
a false positive (callers may skip suppressed findings).
"""

import re
from typing import Dict, List, Optional

# Sources whose findings are validated by an actual on-host check → confirmed.
_CONFIRMED_SOURCES = {"nmap-vuln-script", "exploit", "manual", "post_ex"}
# Sources that are heuristic keyword/version guesses → potential until validated.
_POTENTIAL_SOURCES = {"nvd", "searchsploit", "vulners"}

# CVEs that only apply to TLS/SSL-wrapped services. If the finding's service is a
# plain (non-TLS) service, the match is a false positive.
_TLS_ONLY_CVES = {
    "CVE-2014-0160",  # Heartbleed
    "CVE-2014-0224",  # CCS injection
    "CVE-2016-2107",  # padding oracle
    "CVE-2014-3566",  # POODLE
}
_TLS_SERVICE_HINTS = ("ssl", "tls", "https", "ftps", "smtps", "imaps", "pop3s")

_VER_RE = re.compile(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b")


def _major(version: str) -> Optional[int]:
    m = _VER_RE.search(version or "")
    return int(m.group(1)) if m else None


def _versions_in_text(text: str) -> List[tuple]:
    out = []
    for m in _VER_RE.finditer(text or ""):
        out.append((int(m.group(1)), int(m.group(2))))
    return out


def _is_tls_service(service: str, extra: str = "") -> bool:
    blob = f"{service} {extra}".lower()
    return any(h in blob for h in _TLS_SERVICE_HINTS)


def _version_major_mismatch(description: str, discovered_version: str) -> bool:
    """Heuristic: the finding's description only mentions product versions whose
    MAJOR differs from the discovered version's major (e.g. CVE says Tomcat 3.x/4.x
    but the target runs 8.5). Conservative — only fires when the discovered major
    is known and NONE of the description's versions share it."""
    dmaj = _major(discovered_version)
    if dmaj is None:
        return False
    desc_versions = _versions_in_text(description)
    if not desc_versions:
        return False
    majors = {maj for (maj, _minor) in desc_versions}
    # Only treat as mismatch when every mentioned major is clearly older/different.
    return dmaj not in majors and all(maj < dmaj for maj in majors)


def validate(finding: Dict, discovered_version: str = "") -> Dict:
    """Return a copy of `finding` with normalised status/confidence and possible
    suppression. Never raises."""
    f = dict(finding)
    source = (f.get("source_tool") or "").lower()
    cve_ids = f.get("cve_ids") or []
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    service = f.get("service") or ""
    version = discovered_version or f.get("service_version") or ""
    desc = f.get("description") or ""

    # 1) TLS-only CVE on a non-TLS service → almost certainly a false positive.
    tls_only = [c for c in cve_ids if c.upper() in _TLS_ONLY_CVES]
    if tls_only and not _is_tls_service(service, f.get("name", "")):
        f["status"] = "potential"
        f["confidence"] = 0.1
        f["suppressed"] = True
        f["validation_note"] = f"TLS-only CVE ({', '.join(tls_only)}) on non-TLS service '{service}'"
        return f

    # 2) Version-major mismatch on a heuristic source → downgrade to low potential.
    if source in _POTENTIAL_SOURCES and _version_major_mismatch(desc, version):
        f["status"] = "potential"
        f["confidence"] = 0.2
        f["validation_note"] = f"version mismatch: finding vs discovered '{version}'"
        return f

    # 3) Otherwise: confirmed sources are confirmed; heuristic sources are potential.
    if source in _CONFIRMED_SOURCES:
        f["status"] = f.get("status") or "confirmed"
        f["confidence"] = f.get("confidence", 0.9)
    else:
        # Keep an explicitly-confirmed status if a caller already validated it.
        if f.get("status") != "confirmed":
            f["status"] = "potential"
        f["confidence"] = f.get("confidence", 0.5)
    return f


def priority_score(finding: Dict) -> float:
    """Rank practical findings by evidence, impact, and exploitability.

    CVSS alone over-prioritizes theoretical issues. KEV/EPSS and confirmed
    evidence should move actionable findings ahead of noisy keyword matches.
    """
    confidence = float(finding.get("confidence") or 0.0)
    cvss = max(0.0, min(10.0, float(finding.get("cvss_score") or 0.0))) / 10.0
    epss = max(0.0, min(1.0, float(finding.get("epss") or 0.0)))
    kev = 1.0 if finding.get("kev") else 0.0
    confirmed = 1.0 if finding.get("status") == "confirmed" else 0.0
    score = (
        0.30 * confirmed
        + 0.25 * confidence
        + 0.20 * kev
        + 0.15 * epss
        + 0.10 * cvss
    )
    return round(min(1.0, max(0.0, score)), 3)

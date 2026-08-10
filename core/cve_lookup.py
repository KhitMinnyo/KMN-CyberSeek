"""
KMN-CyberSeek CVE Lookup Module
Optional, best-effort CVE enrichment for discovered services via the Vulners API.

IMPORTANT - honesty note about this module:
This was built against Vulners' documented general-purpose search endpoint
(POST /api/v3/search/lucene/ - X-Api-Key header auth, JSON body with a Lucene
`query` string), which is what could be verified from public docs. Vulners also
advertises a more precise CPE/software-version matching endpoint ("Software API")
that returns cleaner, higher-confidence matches - but at the time this was written
that appeared to require a paid/trial plan, and its exact request/response schema
could not be confirmed without an active API key, so it was not used here. The
Lucene-search approach used below is a reasonable substitute (full-text match on
service name + version among CVE records) but will be noisier and can miss or
mis-rank results compared to real CPE matching. Response field parsing below is
defensive (tries several plausible shapes) precisely because it hasn't been
exercised against a live key - if you configure VULNERS_API_KEY and results look
wrong/empty, check backend logs for the raw response shape and adjust
`_extract_hits()` accordingly.

Design principle: CVE enrichment is a nice-to-have, never a requirement. Every
function here is safe to call with no API key configured and will never raise -
failures are logged and an empty result is returned so the rest of the scan
pipeline is unaffected.
"""

import logging
import os
import re
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

VULNERS_API_URL = "https://vulners.com/api/v3/search/lucene/"
NVD_API_URL     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Keep this conservative: enrichment runs once per discovered service on every
# recon pass, so a slow/hanging API must not be allowed to stall the session.
_REQUEST_TIMEOUT_SECONDS = 15.0


def get_api_key() -> Optional[str]:
    """Read VULNERS_API_KEY from the environment. Returns None if unset/blank."""
    key = os.getenv("VULNERS_API_KEY", "").strip()
    return key or None


def is_configured() -> bool:
    return get_api_key() is not None


async def lookup_cves(service: str, version: str, max_results: int = 5,
                       api_key: Optional[str] = None) -> List[Dict]:
    """
    Look up candidate CVEs for a discovered service + version via Vulners.

    Args:
        service: service/product name as reported by Nmap (e.g. "Apache httpd", "OpenSSH")
        version: version string as reported by Nmap (e.g. "2.4.49")
        max_results: cap on how many CVE hits to return
        api_key: override for VULNERS_API_KEY (mainly for testing)

    Returns:
        List of dicts: {cve_id, cve_ids, title, description, cvss_score, published, url}
        Empty list if no key configured, inputs are unusable, or the request/parse
        fails for any reason. This function is designed to NEVER raise.
    """
    key = api_key or get_api_key()
    if not key:
        return []
    service = (service or "").strip()
    version = (version or "").strip()
    if not service or not version or service.lower() == "unknown":
        return []

    query = f'"{service}" AND "{version}" AND type:cve'
    payload = {
        "query": query,
        "skip": 0,
        "size": max_results,
        "fields": ["id", "title", "description", "cvelist", "cvss", "cvss2", "cvss3", "published", "href"],
    }
    headers = {"Content-Type": "application/json", "X-Api-Key": key}

    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.post(VULNERS_API_URL, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
    except Exception as e:
        logger.warning(
            f"Vulners CVE lookup failed for '{service}' {version} (non-fatal, "
            f"continuing without enrichment): {e}"
        )
        return []

    try:
        return _parse_response(data, max_results)
    except Exception as e:
        logger.warning(f"Failed to parse Vulners response for '{service}' {version} (non-fatal): {e}")
        return []


def _extract_hits(data: Dict) -> List[Dict]:
    """Try several plausible response shapes to find the list of result records.
    See module docstring - this is defensive because the exact shape of this
    particular endpoint's response was not confirmed against a live call."""
    if not isinstance(data, dict):
        return []

    candidates = [
        data.get("data", {}).get("search") if isinstance(data.get("data"), dict) else None,
        data.get("data", {}).get("documents") if isinstance(data.get("data"), dict) else None,
        data.get("data") if isinstance(data.get("data"), list) else None,
        data.get("result") if isinstance(data.get("result"), list) else None,
        data.get("search") if isinstance(data.get("search"), list) else None,
    ]
    for c in candidates:
        if c:
            return c
    return []


def _parse_response(data: Dict, max_results: int) -> List[Dict]:
    hits = _extract_hits(data)
    results: List[Dict] = []

    for hit in hits[:max_results]:
        if not isinstance(hit, dict):
            continue
        # Some Vulners endpoints wrap the real record in "_source"
        source = hit.get("_source", hit) if isinstance(hit.get("_source"), dict) else hit

        raw_id = str(source.get("id", "") or "")
        title = str(source.get("title", "") or "")
        description = str(source.get("description", "") or "")

        cve_ids = source.get("cvelist") or []
        if not cve_ids:
            cve_ids = _CVE_ID_RE.findall(f"{raw_id} {title} {description}")
        cve_ids = sorted({c.upper() for c in cve_ids if c})

        cvss_score = None
        for cvss_field in ("cvss3", "cvss2", "cvss"):
            cvss_obj = source.get(cvss_field)
            if isinstance(cvss_obj, dict) and cvss_obj.get("score") is not None:
                try:
                    cvss_score = float(cvss_obj["score"])
                    break
                except (TypeError, ValueError):
                    pass

        results.append({
            "cve_id": cve_ids[0] if cve_ids else raw_id,
            "cve_ids": cve_ids,
            "title": title,
            "description": description[:500],
            "cvss_score": cvss_score,
            "published": source.get("published", ""),
            "url": source.get("href", "") or (f"https://vulners.com/cve/{cve_ids[0]}" if cve_ids else "")
        })


async def lookup_cves_nvd(
    service: str,
    version: str,
    max_results: int = 5,
) -> List[Dict]:
    """Query the NIST National Vulnerability Database (NVD) API v2 for CVEs
    matching a service + version string.

    No API key required (public endpoint). Rate limit: 5 requests / 30 s
    without a key, 50 / 30 s with NVD_API_KEY in the environment. Callers
    are responsible for spacing out requests; this function does NOT sleep.

    Returns a list of dicts with the same shape as lookup_cves() so callers
    can treat both sources uniformly:
        {"cve_id", "cve_ids", "title", "description", "cvss_score",
         "published", "url"}

    Always returns [] on any error — never raises.
    """
    if not service:
        return []

    query = f"{service} {version}".strip()
    nvd_key = os.getenv("NVD_API_KEY", "").strip() or None
    headers = {"apiKey": nvd_key} if nvd_key else {}

    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                NVD_API_URL,
                params={"keywordSearch": query, "resultsPerPage": max_results},
                headers=headers,
            )
        if resp.status_code != 200:
            logger.warning(f"NVD API returned HTTP {resp.status_code} for {query!r}")
            return []

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        results: List[Dict] = []

        for item in vulnerabilities:
            cve_obj = item.get("cve", {})
            cve_id  = cve_obj.get("id", "")

            # Description — prefer English
            descriptions = cve_obj.get("descriptions", [])
            desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                next((d["value"] for d in descriptions), ""),
            )

            # CVSS score — try v3.1, then v3.0, then v2
            cvss_score: Optional[float] = None
            metrics = cve_obj.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    try:
                        cvss_score = float(
                            metric_list[0].get("cvssData", {}).get("baseScore", 0) or 0
                        )
                        break
                    except (TypeError, ValueError):
                        pass

            published = cve_obj.get("published", "")[:10]  # YYYY-MM-DD

            results.append({
                "cve_id":      cve_id,
                "cve_ids":     [cve_id] if cve_id else [],
                "title":       cve_id,
                "description": desc[:500],
                "cvss_score":  cvss_score,
                "published":   published,
                "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
            })

        logger.info(f"NVD lookup: {len(results)} CVE(s) for {query!r}")
        return results

    except Exception as e:
        logger.warning(f"NVD lookup failed for {query!r}: {e}")
        return []

    return results

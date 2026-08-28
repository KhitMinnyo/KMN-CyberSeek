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

import asyncio
import logging
import os
import re
import time
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

VULNERS_API_URL = "https://vulners.com/api/v3/search/lucene/"
NVD_API_URL     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# CISA Known Exploited Vulnerabilities catalog — CVEs confirmed exploited in the
# wild. The single best real-world prioritisation signal (better than CVSS alone).
KEV_FEED_URL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# FIRST EPSS — probability (0..1) a CVE will be exploited in the next 30 days.
EPSS_API_URL    = "https://api.first.org/data/v1/epss"
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Keep this conservative: enrichment runs once per discovered service on every
# recon pass, so a slow/hanging API must not be allowed to stall the session.
_REQUEST_TIMEOUT_SECONDS = 15.0

# ── NVD rate limiting ────────────────────────────────────────────────────────
# NVD's public rate limit is 5 requests per rolling 30 s WITHOUT an API key
# (≈6 s/request) and 50 per 30 s WITH one (≈0.6 s/request). The old caller waited
# only 0.7 s and got hammered with HTTP 429. We enforce the correct spacing here,
# behind a module-level lock, so it's correct regardless of the caller.
_nvd_lock = asyncio.Lock()
_nvd_last_request_ts: float = 0.0


def _nvd_min_interval() -> float:
    return 0.6 if (os.getenv("NVD_API_KEY", "").strip()) else float(
        os.getenv("NVD_MIN_INTERVAL", "6.5")
    )


def _clean_nvd_query(service: str, version: str) -> str:
    """Build a keyword query that NVD can actually match. Nmap version banners
    carry parenthetical noise (e.g. '((Win64) OpenSSL/1.0.2q PHP/5.6.40)') that
    tanks keyword search; strip it and keep product + version."""
    # Everything from the first '(' onward is Nmap's extra-info blob (OS, SSL,
    # PHP, etc.) — nested/unbalanced, so just cut it entirely.
    v = (version or "").split("(", 1)[0]
    q = re.sub(r"\s+", " ", f"{service} {v}").strip()
    return q


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

    return results


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
    if not re.search(r"\b\d+\.\d+(?:\.\d+)?\b", version or ""):
        logger.info(
            f"Skipping NVD lookup for {service!r}: no numeric version in banner"
        )
        return []

    query = _clean_nvd_query(service, version)
    if not query:
        return []
    nvd_key = os.getenv("NVD_API_KEY", "").strip() or None
    headers = {"apiKey": nvd_key} if nvd_key else {}

    # Rate-limited request with retry on 429. The lock serialises NVD calls so
    # concurrent sessions can't collectively blow the shared rate limit.
    async def _do_request() -> Optional[httpx.Response]:
        global _nvd_last_request_ts
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            async with _nvd_lock:
                wait = _nvd_min_interval() - (time.monotonic() - _nvd_last_request_ts)
                if wait > 0:
                    await asyncio.sleep(wait)
                try:
                    async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
                        r = await client.get(
                            NVD_API_URL,
                            params={"keywordSearch": query, "resultsPerPage": max_results},
                            headers=headers,
                        )
                finally:
                    _nvd_last_request_ts = time.monotonic()
            if r.status_code == 429:
                # Backoff grows with each attempt; NVD's window is 30s.
                backoff = min(30.0, _nvd_min_interval() * (attempt + 1) * 2)
                logger.warning(
                    f"NVD 429 for {query!r} (attempt {attempt}/{max_attempts}); "
                    f"backing off {backoff:.0f}s"
                )
                if attempt < max_attempts:
                    await asyncio.sleep(backoff)
                    continue
                return r
            return r
        return None

    try:
        resp = await _do_request()
        if resp is None or resp.status_code != 200:
            code = resp.status_code if resp is not None else "no response"
            logger.warning(f"NVD API returned HTTP {code} for {query!r}")
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


# ── Exploitability prioritisation: CISA KEV + FIRST EPSS ──────────────────────
# These turn a flat list of CVEs into a *ranked* one so the AI weaponises the
# CVEs that are actually exploited in the wild first, instead of chasing a high
# CVSS score that has no public exploit. Both are best-effort and never raise.

_KEV_CACHE_PATH = os.path.join(
    os.getenv("KMN_CACHE_DIR", "/tmp"), "kmn_kev_catalog.json"
)
_KEV_TTL_SECONDS = 24 * 3600
_kev_set: Optional[set] = None
_kev_loaded_ts: float = 0.0
_kev_lock = asyncio.Lock()


async def load_kev(force: bool = False) -> set:
    """Return the set of CVE IDs in the CISA KEV catalog (uppercased).

    Cached in memory for the process and on disk (KMN_CACHE_DIR, default /tmp)
    so it survives restarts and works offline after the first successful fetch.
    Refreshes at most once per day. Returns an empty set if it has never been
    fetched and cannot be reached — callers treat "not in set" as "not KEV".
    """
    global _kev_set, _kev_loaded_ts
    async with _kev_lock:
        fresh = _kev_set is not None and (time.time() - _kev_loaded_ts) < _KEV_TTL_SECONDS
        if fresh and not force:
            return _kev_set

        # Try a cached file first (offline-friendly).
        if _kev_set is None and not force:
            try:
                import json
                with open(_KEV_CACHE_PATH, "r") as fh:
                    cached = json.load(fh)
                age = time.time() - os.path.getmtime(_KEV_CACHE_PATH)
                _kev_set = {c.upper() for c in cached}
                _kev_loaded_ts = time.time()
                if age < _KEV_TTL_SECONDS:
                    return _kev_set
            except Exception:
                pass

        try:
            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
                r = await client.get(KEV_FEED_URL)
                r.raise_for_status()
                data = r.json()
            cve_ids = [
                v.get("cveID", "").upper()
                for v in data.get("vulnerabilities", [])
                if v.get("cveID")
            ]
            _kev_set = set(cve_ids)
            _kev_loaded_ts = time.time()
            try:
                import json
                with open(_KEV_CACHE_PATH, "w") as fh:
                    json.dump(sorted(_kev_set), fh)
            except Exception:
                pass
            logger.info(f"Loaded CISA KEV catalog: {len(_kev_set)} CVEs")
        except Exception as e:
            logger.warning(f"KEV catalog fetch failed (non-fatal): {e}")
            if _kev_set is None:
                _kev_set = set()
        return _kev_set


async def lookup_epss(cve_ids: List[str]) -> Dict[str, float]:
    """Return {CVE_ID: epss_probability} for the given CVEs via the FIRST EPSS
    API (batched in one request). Missing/failed CVEs are simply absent from the
    returned dict. Never raises."""
    ids = sorted({c.upper() for c in (cve_ids or []) if c})
    if not ids:
        return {}
    out: Dict[str, float] = {}
    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            # The API accepts a comma-separated cve list; cap to a sane batch size.
            r = await client.get(EPSS_API_URL, params={"cve": ",".join(ids[:100])})
            r.raise_for_status()
            data = r.json()
        for row in data.get("data", []):
            cve = (row.get("cve") or "").upper()
            try:
                out[cve] = float(row.get("epss", 0) or 0)
            except (TypeError, ValueError):
                pass
    except Exception as e:
        logger.warning(f"EPSS lookup failed (non-fatal): {e}")
    return out


async def enrich_findings(findings: List[Dict]) -> None:
    """Annotate vulnerability findings in place with exploitability signals:
      - finding['kev']  = True if any of its CVEs is in the CISA KEV catalog
      - finding['epss'] = the max EPSS probability across its CVEs (0..1)
    Findings with no CVE IDs are left untouched. Best-effort; never raises."""
    if not findings:
        return
    all_cves: set = set()
    for f in findings:
        for c in (f.get("cve_ids") or []):
            if c:
                all_cves.add(c.upper())
    if not all_cves:
        return

    kev_set = await load_kev()
    epss_map = await lookup_epss(list(all_cves))

    for f in findings:
        cves = [c.upper() for c in (f.get("cve_ids") or []) if c]
        if not cves:
            continue
        f["kev"] = any(c in kev_set for c in cves)
        epss_vals = [epss_map[c] for c in cves if c in epss_map]
        f["epss"] = round(max(epss_vals), 4) if epss_vals else f.get("epss", 0.0)

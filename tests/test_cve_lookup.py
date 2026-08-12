"""Tests for CVE-lookup helpers: NVD query cleaning, rate-limit interval, and
the Vulners response parser (regression: it used to fall off the end returning
None instead of the results list). No network — pure-logic units only."""

import os

from core import cve_lookup


def test_clean_nvd_query_strips_nmap_noise():
    # Everything from the first '(' — OS/SSL/PHP blob — must be dropped.
    q = cve_lookup._clean_nvd_query(
        "http", "Apache httpd 2.4.38 ((Win64) OpenSSL/1.0.2q PHP/5.6.40)"
    )
    assert q == "http Apache httpd 2.4.38"
    assert "(" not in q and "OpenSSL" not in q


def test_clean_nvd_query_keeps_clean_banner():
    q = cve_lookup._clean_nvd_query("ssl/http", "Sun GlassFish Open Source Edition  4.1.1")
    assert q == "ssl/http Sun GlassFish Open Source Edition 4.1.1"


def test_clean_nvd_query_handles_empty_version():
    assert cve_lookup._clean_nvd_query("mysql", "") == "mysql"


def test_nvd_min_interval_depends_on_key(monkeypatch=None):
    os.environ.pop("NVD_API_KEY", None)
    assert cve_lookup._nvd_min_interval() >= 6.0   # no key → slow (5 req/30s)
    os.environ["NVD_API_KEY"] = "dummy"
    try:
        assert cve_lookup._nvd_min_interval() == 0.6  # with key → fast (50 req/30s)
    finally:
        os.environ.pop("NVD_API_KEY", None)


def test_parse_response_returns_list_not_none():
    # Regression: _parse_response had no `return`, silently returning None.
    data = {
        "data": {"search": [
            {"_source": {"id": "CVE-2021-1234", "title": "t", "description": "d",
                         "cvelist": ["CVE-2021-1234"], "cvss3": {"score": 9.8}}}
        ]}
    }
    out = cve_lookup._parse_response(data, max_results=5)
    assert isinstance(out, list) and len(out) == 1
    assert out[0]["cve_id"] == "CVE-2021-1234"
    assert out[0]["cvss_score"] == 9.8


def test_parse_response_empty_is_empty_list():
    assert cve_lookup._parse_response({}, max_results=5) == []

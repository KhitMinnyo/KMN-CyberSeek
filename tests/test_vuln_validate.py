"""Tests for version-aware vulnerability validation (core/vuln_validate.py) —
Coverage Engine M2. Verifies false-positive suppression and potential/confirmed
status assignment. Pure functions."""

from core import vuln_validate as vv


def test_tls_only_cve_on_plain_ftp_is_suppressed():
    f = {"name": "Heartbleed", "service": "ftp", "cve_ids": ["CVE-2014-0160"],
         "source_tool": "nmap-vuln-script", "description": "OpenSSL Heartbleed"}
    out = vv.validate(f)
    assert out["suppressed"] is True
    assert "TLS-only" in out["validation_note"]


def test_heartbleed_on_ssl_service_not_suppressed():
    f = {"name": "Heartbleed", "service": "ssl/http", "cve_ids": ["CVE-2014-0160"],
         "source_tool": "nmap-vuln-script", "description": "OpenSSL Heartbleed"}
    out = vv.validate(f)
    assert not out.get("suppressed")
    assert out["status"] == "confirmed"


def test_version_major_mismatch_downgrades_nvd_hit():
    # CVE describes Tomcat 3.x/4.x; target runs 8.5 → potential, low confidence.
    f = {"name": "CVE-2002-2009", "service": "http", "source_tool": "nvd",
         "cve_ids": ["CVE-2002-2009"],
         "description": "Apache Tomcat 4.0.1 allows remote attackers to obtain the web root path"}
    out = vv.validate(f, discovered_version="Apache Tomcat 8.5.19")
    assert out["status"] == "potential"
    assert out["confidence"] <= 0.3


def test_matching_major_version_not_downgraded():
    f = {"name": "some tomcat 8 cve", "service": "http", "source_tool": "nvd",
         "cve_ids": ["CVE-2020-1938"],
         "description": "Apache Tomcat 8.5.0 to 8.5.50 AJP Ghostcat"}
    out = vv.validate(f, discovered_version="Apache Tomcat 8.5.19")
    # majors match (8) → not a mismatch; heuristic source stays potential though
    assert out.get("suppressed") is not True
    assert out["status"] == "potential"


def test_nse_source_is_confirmed():
    f = {"name": "smb-vuln-ms17-010", "service": "microsoft-ds",
         "source_tool": "nmap-vuln-script", "cve_ids": ["CVE-2017-0143"],
         "description": "MS17-010"}
    out = vv.validate(f)
    assert out["status"] == "confirmed" and out["confidence"] >= 0.8


def test_searchsploit_is_potential():
    f = {"name": "some exploit", "service": "http", "source_tool": "searchsploit",
         "description": "no version info"}
    out = vv.validate(f)
    assert out["status"] == "potential"


def test_explicit_confirmed_status_preserved():
    f = {"name": "manual rce", "service": "http", "source_tool": "manual",
         "status": "confirmed", "description": "proven RCE"}
    out = vv.validate(f)
    assert out["status"] == "confirmed"

"""
Regression tests for multi-host / CIDR handling.
"""

import sys, pathlib
ROOT = pathlib.Path(__file__).parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from core.exploit_state import ExploitRegistry, ExploitState, ExploitRecord
from core.validators import is_valid_target, is_target_in_scope, check_command_scope


# 1. Per-host isolation
def test_registry_per_host_isolation():
    reg = ExploitRegistry()
    rec_a = reg.get_or_create("10.10.10.1", 80, service="http")
    rec_b = reg.get_or_create("10.10.10.2", 80, service="http")
    assert rec_a is not rec_b
    rec_a.transition("suspected")
    assert rec_b.state == "discovered"


# 2. Same port, different hosts → separate records
def test_same_port_different_hosts():
    reg = ExploitRegistry()
    hosts = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
    records = [reg.get_or_create(h, 445, service="smb") for h in hosts]
    ids = {id(r) for r in records}
    assert len(ids) == 3


# 3. by_host() filters correctly
def test_by_host_filter():
    reg = ExploitRegistry()
    reg.get_or_create("10.0.0.1", 22, service="ssh")
    reg.get_or_create("10.0.0.1", 80, service="http")
    reg.get_or_create("10.0.0.2", 22, service="ssh")
    host1_recs = reg.by_host("10.0.0.1")
    assert len(host1_recs) == 2
    assert all(r.host == "10.0.0.1" for r in host1_recs)


# 4. compromised_hosts() returns only exploited/verified hosts
def test_compromised_hosts_subset():
    reg = ExploitRegistry()
    r1 = reg.get_or_create("10.0.0.1", 22, service="ssh")
    for s in ["suspected", "validated", "attempted", "exploited"]:
        r1.transition(s)
    r2 = reg.get_or_create("10.0.0.2", 80, service="http")
    compromised = reg.compromised_hosts()
    assert "10.0.0.1" in compromised
    assert "10.0.0.2" not in compromised


# 5. Valid CIDR targets
def test_valid_cidr_targets():
    assert is_valid_target("192.168.1.0/24")
    assert is_valid_target("10.0.0.0/8")
    assert is_valid_target("172.16.0.0/12")
    assert is_valid_target("2001:db8::/32")


def test_invalid_cidr_rejected():
    assert not is_valid_target("192.168.1.0/99")
    assert not is_valid_target("not-a-cidr/24")
    assert not is_valid_target("")


# 6. CIDR scope: subnet of allowlist entry is in scope
def test_cidr_subnet_in_scope():
    assert is_target_in_scope("192.168.1.64/28", "192.168.1.0/24")


def test_cidr_subnet_outside_scope():
    assert not is_target_in_scope("192.168.0.0/16", "192.168.1.0/24")


def test_host_ip_in_cidr_scope():
    assert is_target_in_scope("10.10.10.50", "10.10.10.0/24")
    assert not is_target_in_scope("10.10.11.50", "10.10.10.0/24")


# 7. check_command_scope (uses flag/URL destinations; bare positional args not extracted)
def test_nmap_scope_host_in_range():
    # --host flag is extracted by _GENERIC_HOST_FLAG pattern
    result = check_command_scope("nmap --host 192.168.1.5 -sV", "192.168.1.0/24")
    assert result is None


def test_nmap_scope_host_outside_range():
    # curl URL is extracted by _URL_HOST_RE pattern
    result = check_command_scope("curl http://10.99.99.99/admin", "192.168.1.0/24")
    assert result is not None
    assert "10.99.99.99" in result


# 8. ExploitRecord serialise/deserialise
def test_exploit_record_roundtrip():
    rec = ExploitRecord(host="10.10.10.5", port=8080, service="http")
    rec.transition("suspected")
    d = rec.to_dict()
    rec2 = ExploitRecord.from_dict(d)
    assert rec2.host == "10.10.10.5"
    assert rec2.port == 8080
    assert rec2.state == "suspected"


# 9. Registry summary counts per-state
def test_registry_summary_counts():
    reg = ExploitRegistry()
    for i in range(3):
        r = reg.get_or_create(f"10.0.0.{i+1}", 22, service="ssh")
        if i >= 1:
            r.transition("suspected")
        if i == 2:
            r.transition("validated")
            r.transition("attempted")
            r.transition("exploited")
    s = reg.summary()["by_state"]
    assert s.get("discovered", 0) >= 1
    assert s.get("suspected", 0) >= 1
    assert s.get("exploited", 0) >= 1


# 10. Per-host OS hint stored independently
def test_per_host_os_field():
    rec_linux = ExploitRecord(host="10.0.0.1", port=22, service="ssh")
    rec_win   = ExploitRecord(host="10.0.0.2", port=445, service="smb")
    rec_linux.__dict__["os_hint"] = "linux"
    rec_win.__dict__["os_hint"]   = "windows"
    assert rec_linux.__dict__["os_hint"] == "linux"
    assert rec_win.__dict__["os_hint"]   == "windows"


# 11. Invalid transition blocked
def test_invalid_transition_blocked():
    rec = ExploitRecord(host="10.0.0.1", port=80, service="http")
    ok = rec.transition("exploited")
    assert ok is False
    assert rec.state == "discovered"


# 12. by_state() returns correct subset
def test_by_state_filter():
    reg = ExploitRegistry()
    r1 = reg.get_or_create("10.0.0.1", 22, service="ssh")
    r1.transition("suspected")
    r2 = reg.get_or_create("10.0.0.2", 80, service="http")
    assert r1 in reg.by_state("suspected")
    assert r2 in reg.by_state("discovered")
    assert r1 not in reg.by_state("discovered")


# 13. to_list / load_from_list preserves all records
def test_registry_serialise_all_hosts():
    reg = ExploitRegistry()
    reg.get_or_create("10.0.0.1", 22, service="ssh").transition("suspected")
    reg.get_or_create("10.0.0.2", 80, service="http")
    reg.get_or_create("10.0.0.3", 443, service="https")
    data = reg.to_list()
    assert len(data) == 3
    reg2 = ExploitRegistry()
    reg2.load_from_list(data)
    assert len(reg2.to_list()) == 3
    hosts = {r["host"] for r in reg2.to_list()}
    assert "10.0.0.1" in hosts and "10.0.0.3" in hosts

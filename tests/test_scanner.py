"""Scanner parser fixtures for heterogeneous vulnerable lab machines."""

from core.scanner import Scanner, classify_os


def test_nmap_parser_keeps_versionless_ports_and_os_facts():
    scanner = Scanner.__new__(Scanner)
    output = """Nmap scan report for 192.168.56.10
Host is up (0.001s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh
445/tcp  open  microsoft-ds Samba smbd 4.3
Running: Linux 4.X
OS details: Linux 4.15 (92%)
Service Info: OS: Unix

Nmap scan report for 192.168.56.11
Host is up (0.002s latency).
PORT     STATE SERVICE VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
OS details: Microsoft Windows Server 2012 (96%)
"""
    hosts = scanner._parse_nmap_output(output)["hosts"]
    assert len(hosts) == 2
    assert hosts[0]["os_family"] == "linux"
    assert hosts[0]["os_confidence"] >= 0.9
    assert any(port["port"] == 22 for port in hosts[0]["ports"])
    assert hosts[1]["os_family"] == "windows"


def test_os_classifier_detects_x86_without_overriding_samba_linux():
    result = classify_os(
        "Linux 3.2 - 3.16 (x86)",
        [{"port": "445", "service": "microsoft-ds", "version": "Samba"}],
    )
    assert result["os_family"] == "linux"
    assert result["architecture"] == "x86"

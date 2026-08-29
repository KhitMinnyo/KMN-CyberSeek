"""Tests for core/nmap_parser.py Nmap XML parser — no live target."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.nmap_parser import (
    parse_nmap_xml, build_udp_scan_command, NmapScanResult,
    UDP_HIGH_VALUE_PORTS,
)

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun version="7.94" args="nmap -sV -oX - 10.0.0.1" start="1700000000"
         startstr="Tue Jan  1 00:00:00 2000" exit="success">
<runstats>
  <finished time="1700000060" elapsed="60.0" summary="done" exit="success"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
<host>
  <status state="up" reason="echo-reply"/>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <hostnames><hostname name="target.local" type="PTR"/></hostnames>
  <os>
    <osmatch name="Linux 5.4" accuracy="95"/>
  </os>
  <ports>
    <extraports state="closed" count="65500">
      <extrareasons reason="conn-refused" count="65500"/>
    </extraports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="8.9" extrainfo="Ubuntu"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="nginx" version="1.24.0"/>
      <script id="http-title" output="Welcome to nginx!"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="filtered" reason="no-response"/>
      <service name="https"/>
    </port>
  </ports>
</host>
</nmaprun>"""


def test_parse_basic():
    r = parse_nmap_xml(SAMPLE_XML)
    assert len(r.hosts) == 1
    host = r.hosts[0]
    assert host.address == "10.0.0.1"
    assert host.status == "up"
    assert host.hostname == "target.local"


def test_open_ports():
    r = parse_nmap_xml(SAMPLE_XML)
    host = r.hosts[0]
    open_ports = host.open_ports()
    assert len(open_ports) == 2
    ports = {p.port for p in open_ports}
    assert 22 in ports
    assert 80 in ports


def test_filtered_ports():
    r = parse_nmap_xml(SAMPLE_XML)
    host = r.hosts[0]
    filtered = host.filtered_ports()
    assert len(filtered) == 1
    assert filtered[0].port == 443


def test_service_fields():
    r = parse_nmap_xml(SAMPLE_XML)
    host = r.hosts[0]
    ssh = next(p for p in host.ports if p.port == 22)
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "8.9"


def test_script_output():
    r = parse_nmap_xml(SAMPLE_XML)
    host = r.hosts[0]
    http = next(p for p in host.ports if p.port == 80)
    assert "http-title" in http.script_output
    assert "nginx" in http.script_output["http-title"]


def test_os_match():
    r = parse_nmap_xml(SAMPLE_XML)
    host = r.hosts[0]
    assert len(host.os_matches) >= 1
    assert "Linux" in host.os_matches[0]


def test_completeness_meta():
    r = parse_nmap_xml(SAMPLE_XML)
    meta = r.completeness_meta()
    assert meta["scan_complete"] is True
    assert meta["elapsed_seconds"] == 60.0
    assert meta["hosts_up"] == 1
    assert meta["ports_open"] == 2
    assert meta["ports_filtered"] == 1


def test_service_list():
    r = parse_nmap_xml(SAMPLE_XML)
    services = r.to_service_list()
    assert len(services) == 2   # only open ports
    hosts = {s["host"] for s in services}
    assert "10.0.0.1" in hosts


def test_malformed_xml_returns_empty():
    r = parse_nmap_xml("<not valid xml!!!")
    assert r.scan_complete is False
    assert len(r.hosts) == 0


def test_udp_scan_command_default():
    cmd = build_udp_scan_command("10.0.0.1")
    assert "sU" in cmd or "-sU" in cmd
    assert "10.0.0.1" in cmd
    assert str(UDP_HIGH_VALUE_PORTS[0]) in cmd


def test_udp_scan_command_custom_ports():
    cmd = build_udp_scan_command("192.168.1.0/24", ports=[161, 162])
    assert "161" in cmd
    assert "162" in cmd
    assert "192.168.1.0/24" in cmd


def test_udp_scan_command_xml_output():
    cmd = build_udp_scan_command("10.0.0.1", output_xml="/tmp/scan.xml")
    assert "-oX /tmp/scan.xml" in cmd


def test_all_open_ports():
    r = parse_nmap_xml(SAMPLE_XML)
    pairs = r.all_open_ports()
    assert len(pairs) == 2
    assert all(addr == "10.0.0.1" for addr, _ in pairs)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS  {name}")
    print("All nmap_parser tests passed.")

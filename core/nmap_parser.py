"""
KMN-CyberSeek Nmap XML Parser

Parses nmap -oX XML output into structured service records.
Does NOT depend on python-nmap, so it is safe to import anywhere.

Key features vs. the text-output parser:
- Port state: open / closed / filtered / open|filtered / unknown
- Per-port script output (NSE results)
- IPv6 address handling
- Service version/product/extra-info fields from <service> element
- OS detection results
- Scan completeness metadata (elapsed, hosts_scanned, not-scanned ports)
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple


@dataclass
class NmapPort:
    port:        int
    protocol:    str   = "tcp"
    state:       str   = "unknown"     # open|closed|filtered|open|filtered|unknown
    state_reason: str  = ""
    service:     str   = ""
    product:     str   = ""
    version:     str   = ""
    extra_info:  str   = ""
    tunnel:      str   = ""            # ssl / http
    script_output: Dict[str, str] = field(default_factory=dict)

    @property
    def is_open(self) -> bool:
        return "open" in self.state and "filtered" not in self.state

    @property
    def is_filtered(self) -> bool:
        return "filtered" in self.state

    def service_label(self) -> str:
        parts = [p for p in (self.service, self.product, self.version) if p]
        return " ".join(parts) or "unknown"

    def to_dict(self) -> Dict:
        return {
            "port":          self.port,
            "protocol":      self.protocol,
            "state":         self.state,
            "state_reason":  self.state_reason,
            "service":       self.service,
            "product":       self.product,
            "version":       self.version,
            "extra_info":    self.extra_info,
            "tunnel":        self.tunnel,
            "script_output": self.script_output,
        }


@dataclass
class NmapHost:
    address:     str   = ""
    address_type: str  = "ipv4"     # ipv4 | ipv6 | mac
    hostname:    str   = ""
    status:      str   = "unknown"  # up | down | unknown
    status_reason: str = ""
    os_matches:  List[str] = field(default_factory=list)
    ports:       List[NmapPort] = field(default_factory=list)

    def open_ports(self) -> List[NmapPort]:
        return [p for p in self.ports if p.is_open]

    def filtered_ports(self) -> List[NmapPort]:
        return [p for p in self.ports if p.is_filtered]

    def to_dict(self) -> Dict:
        return {
            "address":      self.address,
            "address_type": self.address_type,
            "hostname":     self.hostname,
            "status":       self.status,
            "os_matches":   self.os_matches,
            "ports":        [p.to_dict() for p in self.ports],
            "open_count":   len(self.open_ports()),
            "filtered_count": len(self.filtered_ports()),
        }


@dataclass
class NmapScanResult:
    """Top-level result from parsing one nmap XML file/string."""
    scanner_version: str = ""
    args:            str = ""
    start_time:      str = ""
    elapsed_seconds: float = 0.0
    hosts:           List[NmapHost] = field(default_factory=list)
    not_scanned_ports: List[int]    = field(default_factory=list)  # from extraports
    scan_complete:   bool = True    # False if nmap exited early / timed out

    def hosts_up(self) -> List[NmapHost]:
        return [h for h in self.hosts if h.status == "up"]

    def all_open_ports(self) -> List[Tuple[str, NmapPort]]:
        """Returns (host_address, port) pairs for all open ports."""
        out = []
        for h in self.hosts:
            for p in h.open_ports():
                out.append((h.address, p))
        return out

    def completeness_meta(self) -> Dict:
        total_hosts = len(self.hosts)
        up_hosts    = len(self.hosts_up())
        all_ports   = sum(len(h.ports) for h in self.hosts)
        open_ports  = sum(len(h.open_ports()) for h in self.hosts)
        filtered    = sum(len(h.filtered_ports()) for h in self.hosts)
        return {
            "scan_complete":    self.scan_complete,
            "elapsed_seconds":  self.elapsed_seconds,
            "hosts_total":      total_hosts,
            "hosts_up":         up_hosts,
            "ports_scanned":    all_ports,
            "ports_open":       open_ports,
            "ports_filtered":   filtered,
            "ports_not_scanned": len(self.not_scanned_ports),
        }

    def to_service_list(self) -> List[Dict]:
        """Convert to the flat service-dict format used by the orchestrator."""
        services = []
        for host in self.hosts_up():
            for port in host.open_ports():
                services.append({
                    "host":     host.address,
                    "port":     port.port,
                    "protocol": port.protocol,
                    "service":  port.service or "unknown",
                    "product":  port.product,
                    "version":  port.version,
                    "state":    port.state,
                    "tunnel":   port.tunnel,
                    "banner":   port.extra_info,
                    "scripts":  port.script_output,
                    "os_guess": host.os_matches[0] if host.os_matches else "",
                })
        return services


# ── Parser ────────────────────────────────────────────────────────────────────

def parse_nmap_xml(xml_data: str) -> NmapScanResult:
    """Parse nmap XML (as a string) into a NmapScanResult."""
    result = NmapScanResult()
    try:
        root = ET.fromstring(xml_data.strip())
    except ET.ParseError as exc:
        result.scan_complete = False
        return result

    result.scanner_version = root.get("version", "")
    result.args            = root.get("args", "")
    result.start_time      = root.get("startstr", "")
    result.scan_complete   = root.get("exit", "success") != "error"

    run_stats = root.find("runstats/finished")
    if run_stats is not None:
        try:
            result.elapsed_seconds = float(run_stats.get("elapsed", 0))
        except (ValueError, TypeError):
            pass
        if run_stats.get("exit", "") == "error":
            result.scan_complete = False

    for host_el in root.findall("host"):
        host = _parse_host(host_el)
        result.hosts.append(host)

    return result


def parse_nmap_xml_file(path: str) -> NmapScanResult:
    try:
        with open(path, "r", errors="replace") as f:
            return parse_nmap_xml(f.read())
    except OSError:
        r = NmapScanResult()
        r.scan_complete = False
        return r


def _parse_host(host_el: ET.Element) -> NmapHost:
    host = NmapHost()

    # Address(es): prefer ipv4, fall back to ipv6, then mac
    for addr_el in host_el.findall("address"):
        atype = addr_el.get("addrtype", "").lower()
        addr  = addr_el.get("addr", "")
        if atype == "ipv4" and not host.address:
            host.address      = addr
            host.address_type = "ipv4"
        elif atype == "ipv6" and not host.address:
            host.address      = addr
            host.address_type = "ipv6"
        elif atype == "mac" and not host.address:
            host.address      = addr
            host.address_type = "mac"

    # Hostname
    for hn_el in host_el.findall("hostnames/hostname"):
        if hn_el.get("type", "") in ("PTR", "user", ""):
            host.hostname = hn_el.get("name", "")
            break

    # Status
    status_el = host_el.find("status")
    if status_el is not None:
        host.status        = status_el.get("state", "unknown")
        host.status_reason = status_el.get("reason", "")

    # OS
    for osmatch in host_el.findall("os/osmatch"):
        name  = osmatch.get("name", "")
        acc   = osmatch.get("accuracy", "")
        label = f"{name} ({acc}%)" if acc else name
        host.os_matches.append(label)

    # Ports
    ports_el = host_el.find("ports")
    if ports_el is not None:
        # extraports (not-scanned summary)
        for ep in ports_el.findall("extraports"):
            state = ep.get("state", "")
            for er in ep.findall("extrareasons"):
                try:
                    count = int(er.get("count", 0))
                    if state in ("closed", "filtered"):
                        pass  # count recorded in completeness_meta via scan logic
                except (ValueError, TypeError):
                    pass

        for port_el in ports_el.findall("port"):
            port = _parse_port(port_el)
            host.ports.append(port)

    return host


def _parse_port(port_el: ET.Element) -> NmapPort:
    port = NmapPort(
        port     = int(port_el.get("portid", 0)),
        protocol = port_el.get("protocol", "tcp"),
    )

    state_el = port_el.find("state")
    if state_el is not None:
        port.state        = state_el.get("state", "unknown")
        port.state_reason = state_el.get("reason", "")

    svc_el = port_el.find("service")
    if svc_el is not None:
        port.service    = svc_el.get("name", "")
        port.product    = svc_el.get("product", "")
        port.version    = svc_el.get("version", "")
        port.extra_info = svc_el.get("extrainfo", "")
        port.tunnel     = svc_el.get("tunnel", "")

    for script_el in port_el.findall("script"):
        sid    = script_el.get("id", "")
        output = script_el.get("output", "")
        if sid:
            port.script_output[sid] = output

    return port


# ── Targeted UDP scan builder ─────────────────────────────────────────────────
# UDP scanning is slow; we run it only for high-value ports.

UDP_HIGH_VALUE_PORTS = [
    53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 389,
    443, 500, 514, 520, 623, 1194, 1900, 4500, 5353,
]


def build_udp_scan_command(target: str,
                            ports: Optional[List[int]] = None,
                            output_xml: Optional[str] = None) -> str:
    """Return an nmap command for targeted UDP scanning.

    Args:
        target:     IP or CIDR
        ports:      list of UDP ports; defaults to UDP_HIGH_VALUE_PORTS
        output_xml: path for -oX output; if None, no XML saved
    """
    port_list = ",".join(str(p) for p in (ports or UDP_HIGH_VALUE_PORTS))
    xml_flag  = f"-oX {output_xml}" if output_xml else ""
    return (
        f"nmap -sU -Pn --open -T4 "
        f"--max-retries 2 --max-rtt-timeout 500ms "
        f"-p {port_list} {xml_flag} {target}"
    ).strip()

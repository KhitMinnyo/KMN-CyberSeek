"""Validated building blocks for authorized Meterpreter network pivots.

This module only validates pivot state and builds non-interactive commands. The
orchestrator is responsible for authorization, execution, evidence, and cleanup.
Keeping the builders pure makes them safe to test without contacting a target.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class PivotRoute:
    subnet: str
    netmask: str
    handler_id: str
    msf_id: int
    status: str = "active"


@dataclass
class PortForward:
    remote_host: str
    remote_port: int
    local_host: str
    local_port: int
    handler_id: str
    msf_id: int
    status: str = "active"


@dataclass
class SocksProxy:
    local_host: str
    local_port: int
    handler_id: str
    msf_id: int
    version: int = 5
    status: str = "active"


def _valid_host(host: str) -> bool:
    if not host or len(host) > 253 or any(ch in host for ch in "\r\n;&|`$"):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9.-]+", host))


def validate_route(subnet: str) -> Optional[PivotRoute]:
    """Normalize an IPv4/IPv6 route into subnet/netmask form."""
    try:
        network = ipaddress.ip_network((subnet or "").strip(), strict=False)
    except ValueError:
        return None
    return PivotRoute(
        subnet=str(network.network_address),
        netmask=str(network.netmask),
        handler_id="",
        msf_id=0,
    )


def validate_port(port) -> bool:
    try:
        return 1 <= int(port) <= 65535
    except (TypeError, ValueError):
        return False


def build_autoroute_command(subnet: str, netmask: Optional[str] = None,
                            remove: bool = False) -> Optional[str]:
    route = validate_route(subnet)
    if not route:
        return None
    mask = netmask or route.netmask
    try:
        ipaddress.ip_network(f"{route.subnet}/{mask}", strict=False)
    except ValueError:
        return None
    action = "delete" if remove else "add"
    return f"run post/multi/manage/autoroute CMD={action} SUBNET={route.subnet} NETMASK={mask}"


def build_portfwd_command(remote_host: str, remote_port: int, local_port: int,
                          local_host: str = "127.0.0.1", remove: bool = False) -> Optional[str]:
    if not _valid_host(remote_host) or not _valid_host(local_host):
        return None
    if not validate_port(remote_port) or not validate_port(local_port):
        return None
    action = "delete" if remove else "add"
    return (
        f"portfwd {action} -L {local_host} -l {int(local_port)} "
        f"-p {int(remote_port)} -r {remote_host}"
    )


def build_socks_proxy_command(local_port: int, local_host: str = "127.0.0.1",
                              version: int = 5, remove: bool = False) -> Optional[str]:
    if not _valid_host(local_host) or not validate_port(local_port) or version not in (4, 5):
        return None
    if remove:
        # A SOCKS proxy is a specific MSF job; stopping every job with `jobs -K`
        # would be unsafe. The caller must use the tracked job id instead.
        return None
    return (
        "use auxiliary/server/socks_proxy; "
        f"set SRVHOST {local_host}; set SRVPORT {int(local_port)}; "
        f"set VERSION {version}; run -j"
    )


# ── Internal subnet discovery from shell output ────────────────────────────────

import re as _pre
import ipaddress as _ipaddress


_ROUTE_RE = _pre.compile(
    r"(?:^|\s)(\d{1,3}(?:\.\d{1,3}){3})"
    r"(?:\s+(\d{1,3}(?:\.\d{1,3}){3}))?",   # optional netmask
    _pre.MULTILINE,
)
_CIDR_RE = _pre.compile(r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})")
_LINK_LOCAL = _pre.compile(r"^(127\.|169\.254\.|0\.0\.0\.0)")


def discover_internal_subnets(shell_output: str,
                               exclude_public: bool = True) -> list:
    """Parse route/ARP/ifconfig/ip-addr output and return private subnets.

    Returns a list of CIDR strings suitable for build_autoroute_command().
    Filters out loopback, link-local, and (optionally) routable public subnets.
    """
    found = set()

    # CIDR notation first (ip route / ip addr output)
    for m in _CIDR_RE.finditer(shell_output):
        try:
            net = _ipaddress.ip_network(m.group(1), strict=False)
            if net.is_private and not net.is_loopback and not net.is_link_local:
                found.add(str(net))
        except ValueError:
            pass

    # IP + optional netmask pairs (route print / netstat -rn)
    for m in _ROUTE_RE.finditer(shell_output):
        ip_str  = m.group(1)
        mask    = m.group(2) or ""
        if _LINK_LOCAL.match(ip_str):
            continue
        try:
            addr = _ipaddress.ip_address(ip_str)
            if not addr.is_private:
                continue
            if mask:
                net = _ipaddress.ip_network(f"{ip_str}/{mask}", strict=False)
            else:
                # Guess prefix: RFC 1918 class heuristic
                first = int(ip_str.split(".")[0])
                prefix = 8 if first == 10 else (16 if first == 172 else 24)
                net = _ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
            if not net.is_loopback and not net.is_link_local:
                found.add(str(net))
        except ValueError:
            pass

    return sorted(found)


# ── Multi-hop pivot state ──────────────────────────────────────────────────────

from dataclasses import dataclass as _dc, field as _field
from typing import List as _List, Optional as _Opt, Dict as _Dict
import uuid as _uuid


@_dc
class PivotHop:
    """One hop in a multi-hop pivot chain."""
    hop_index:    int           = 0
    source_host:  str           = ""
    dest_host:    str           = ""
    route:        _Opt[str]     = None   # CIDR added via autoroute
    proxy_port:   _Opt[int]     = None   # local SOCKS port for this hop
    port_fwds:    _List[str]    = _field(default_factory=list)
    msf_session:  int           = 0      # MSF session ID at this hop
    handler_id:   str           = ""
    status:       str           = "active"  # active | closed | failed


@_dc
class PivotChain:
    """Tracks the full pivot chain for one pentest session."""
    chain_id:   str           = _field(default_factory=lambda: _uuid.uuid4().hex[:8])
    hops:       _List[PivotHop] = _field(default_factory=list)
    socks_jobs: _List[_Dict]  = _field(default_factory=list)  # {port, msf_job_id, hop}
    status:     str           = "active"

    def add_hop(self, source_host: str, dest_host: str,
                msf_session: int, handler_id: str,
                route: _Opt[str] = None) -> PivotHop:
        hop = PivotHop(
            hop_index=len(self.hops),
            source_host=source_host,
            dest_host=dest_host,
            route=route,
            msf_session=msf_session,
            handler_id=handler_id,
        )
        self.hops.append(hop)
        return hop

    def register_socks(self, port: int, msf_job_id: str, hop_index: int):
        self.socks_jobs.append({
            "port": port, "msf_job_id": msf_job_id, "hop": hop_index, "status": "active"
        })

    def cleanup_commands(self) -> _List[str]:
        """Return MSF commands needed to tear down this pivot chain (LIFO order)."""
        cmds = []
        # Kill SOCKS proxy jobs
        for sj in reversed(self.socks_jobs):
            if sj.get("msf_job_id"):
                cmds.append(f"jobs -k {sj['msf_job_id']}")
        # Remove autoroutes and port-fwds (hop LIFO)
        for hop in reversed(self.hops):
            if hop.route:
                cmd = build_autoroute_command(hop.route, remove=True)
                if cmd:
                    cmds.append(cmd)
            for pf in reversed(hop.port_fwds):
                cmds.append(pf)   # caller built the delete form already
        return cmds

    def guard_direct_access(self, dest_host: str) -> bool:
        """Return True if dest_host is only reachable via this pivot chain
        (i.e., at least one hop covers its subnet). Used as a guard to prevent
        direct tool invocation against internal hosts without routing first."""
        import ipaddress as _ia
        try:
            addr = _ia.ip_address(dest_host)
        except ValueError:
            return False
        for hop in self.hops:
            if hop.route and hop.status == "active":
                try:
                    if addr in _ia.ip_network(hop.route, strict=False):
                        return True
                except ValueError:
                    pass
        return False

    def to_dict(self) -> _Dict:
        return {
            "chain_id": self.chain_id,
            "status":   self.status,
            "hops": [{
                "hop_index":   h.hop_index,
                "source_host": h.source_host,
                "dest_host":   h.dest_host,
                "route":       h.route,
                "proxy_port":  h.proxy_port,
                "msf_session": h.msf_session,
                "handler_id":  h.handler_id,
                "status":      h.status,
            } for h in self.hops],
            "socks_jobs": self.socks_jobs,
        }

    @classmethod
    def from_dict(cls, d: _Dict) -> "PivotChain":
        chain = cls(chain_id=d.get("chain_id", _uuid.uuid4().hex[:8]),
                    status=d.get("status", "active"))
        for h in d.get("hops", []):
            chain.hops.append(PivotHop(
                hop_index=h.get("hop_index", 0),
                source_host=h.get("source_host", ""),
                dest_host=h.get("dest_host", ""),
                route=h.get("route"),
                proxy_port=h.get("proxy_port"),
                msf_session=h.get("msf_session", 0),
                handler_id=h.get("handler_id", ""),
                status=h.get("status", "active"),
            ))
        chain.socks_jobs = d.get("socks_jobs", [])
        return chain

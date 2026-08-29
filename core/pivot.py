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

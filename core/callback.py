"""
KMN-CyberSeek callback-endpoint resolution.

A reverse shell only works if the TARGET can route back to the operator's
listener. On a LAN lab the operator's LAN IP is reachable, so the current
`get_local_ip()` is fine. Against a real internet target the operator is usually
behind NAT, so a private LAN IP (192.168.x / 10.x / 172.16-31.x / 127.x) is
unroutable and the reverse shell never arrives — the exact "we never get the
real traffic back" failure the operator hit when testing real-world targets from
a workstation.

The fix is to separate two addresses that the old code conflated:

    advertised (payload LHOST:LPORT) — what the TARGET connects back to
    bind       (listener host:port)  — where msfconsole actually LISTENS

and to pick the advertised address so it is actually reachable from the target,
using a public IP, an ngrok TCP tunnel, or a manual reverse-SSH tunnel.

Modes (env ``CALLBACK_MODE``):

    local  — advertise the LAN IP and bind the same. LAN labs, or an operator
             running on a public VPS whose primary IP is already routable.
    public — advertise this host's public egress IP, bind 0.0.0.0. Requires the
             LPORT to be port-forwarded to this host (home router / cloud
             security group).
    ngrok  — start an ngrok TCP tunnel to the local LPORT and advertise the
             ngrok public host:port, binding 127.0.0.1:LPORT. Works from behind
             NAT with no port-forward. Needs `ngrok` installed and an authtoken
             configured (`ngrok config add-authtoken ...` or NGROK_AUTHTOKEN).
    manual — advertise EXPLOIT_LHOST:EXPLOIT_LPORT. Use this with a reverse-SSH
             tunnel you set up yourself, e.g. on a VPS:
                 ssh -R 4444:localhost:4444 user@vps
             then EXPLOIT_LHOST=<vps_public_ip> EXPLOIT_LPORT=4444. The listener
             binds 127.0.0.1:LPORT; the target connects to the VPS which forwards.
    auto   — EXPLOIT_LHOST set -> manual; else a public target with ngrok
             available -> ngrok; else a public target -> public IP; else local.

Everything here is best-effort and never raises: resolution always returns a
usable Callback, degrading to the LAN IP with an honest ``reachable=False`` and a
``note`` the AI is shown so it can choose a non-callback technique instead.
"""

import ipaddress
import json
import logging
import os
import shutil
import socket
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── Primitives ────────────────────────────────────────────────────────────────

def get_local_ip(target: Optional[str] = None) -> str:
    """Return the local address used to reach ``target`` when possible.

    The old 8.8.8.8 probe always selected the default interface, which can be
    wrong for multi-homed labs (for example, a VPN/eth0 target reached through
    a different interface). A UDP connect does not send traffic, but lets the
    kernel choose the correct route and source address.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        route_target = (target or "8.8.8.8").strip()
        try:
            route_target = socket.gethostbyname(route_target)
        except (OSError, socket.gaierror):
            route_target = "8.8.8.8"
        s.connect((route_target, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def is_private_ip(host: str) -> bool:
    """True if ``host`` is a private/loopback/link-local IPv4/IPv6 literal.

    A hostname (not an IP literal) is treated as NOT private — a real domain
    target lives on the public internet.
    """
    host = (host or "").strip()
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # hostname → assume public
    return ip.is_private or ip.is_loopback or ip.is_link_local


def get_public_ip(timeout: float = 4.0) -> Optional[str]:
    """Best-effort public egress IP via a couple of well-known echo services."""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip",
                "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                ip = resp.read().decode().strip()
            ipaddress.ip_address(ip)  # validate
            return ip
        except Exception:
            continue
    return None


# ── ngrok TCP tunnel ──────────────────────────────────────────────────────────

def ngrok_available() -> bool:
    return shutil.which("ngrok") is not None


def ngrok_start_tcp(port: int, wait: float = 15.0):
    """Start `ngrok tcp <port>` and return (host, public_port, process) once the
    tunnel is up, or (None, None, None) on failure. The ngrok agent exposes its
    tunnels on the local API at 127.0.0.1:4040; we poll it for the public URL.

    Best-effort and non-fatal: a missing binary, missing authtoken, or a slow
    tunnel just yields a None result and the caller falls back to another mode.
    """
    if not ngrok_available():
        logger.info("ngrok not installed — cannot start TCP tunnel")
        return None, None, None

    authtoken = os.getenv("NGROK_AUTHTOKEN", "").strip()
    if authtoken:
        try:
            subprocess.run(["ngrok", "config", "add-authtoken", authtoken],
                           capture_output=True, timeout=10)
        except Exception:
            pass

    try:
        proc = subprocess.Popen(
            ["ngrok", "tcp", str(port), "--log=stdout"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        logger.warning(f"ngrok failed to launch: {e}")
        return None, None, None

    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:4040/api/tunnels", timeout=2
            ) as resp:
                data = json.loads(resp.read().decode())
            for tun in data.get("tunnels", []):
                pub = tun.get("public_url", "")
                if pub.startswith("tcp://"):
                    hostport = pub[len("tcp://"):]
                    host, _, p = hostport.partition(":")
                    if host and p:
                        logger.info(f"ngrok TCP tunnel up: {pub} -> localhost:{port}")
                        return host, int(p), proc
        except Exception:
            pass
        time.sleep(0.7)

    logger.warning("ngrok tunnel did not come up within timeout — aborting it")
    try:
        proc.terminate()
    except Exception:
        pass
    return None, None, None


def stop_tunnel(cb: "Callback") -> None:
    """Terminate a tunnel process attached to a resolved Callback (best-effort)."""
    proc = getattr(cb, "tunnel_proc", None)
    if proc is None:
        return
    try:
        proc.terminate()
    except Exception:
        pass


# ── Resolution ────────────────────────────────────────────────────────────────

@dataclass
class Callback:
    mode: str
    advertised_host: str          # payload LHOST — what the target connects to
    advertised_port: int          # payload LPORT
    bind_host: str                # listener bind address (msf ReverseListenerBindAddress)
    bind_port: int                # listener bind port
    reachable: bool               # confident the target can route back to advertised
    note: str = ""                # human/AI explanation of the choice
    tunnel_proc: object = field(default=None, repr=False)

    @property
    def needs_bind_override(self) -> bool:
        """True when the listener must bind somewhere other than the advertised
        address (tunnel / port-forward), so msf needs ReverseListenerBind*."""
        return (self.bind_host, self.bind_port) != (self.advertised_host, self.advertised_port)


def resolve_callback(target: str, default_lport: Optional[int] = None) -> Callback:
    """Resolve the reverse-shell callback endpoint for ``target``.

    Honours CALLBACK_MODE, EXPLOIT_LHOST/EXPLOIT_LPORT, and NGROK_AUTHTOKEN. See
    the module docstring for the mode semantics. Never raises.
    """
    lport = default_lport or int(os.getenv("EXPLOIT_LPORT", "4444") or "4444")
    mode = os.getenv("CALLBACK_MODE", "auto").strip().lower()
    explicit_lhost = os.getenv("EXPLOIT_LHOST", "").strip()
    target_public = not is_private_ip(target)

    # Resolve 'auto' to a concrete mode.
    if mode == "auto":
        if explicit_lhost:
            mode = "manual"
        elif target_public and ngrok_available():
            mode = "ngrok"
        elif target_public:
            mode = "public"
        else:
            mode = "local"

    # Select the source address for the target's route, not merely the default
    # internet route. This matters on Kali hosts with eth0 + VPN/tunnel NICs.
    lan_ip = get_local_ip(target)

    # ── manual (explicit LHOST — reverse-SSH tunnel or known public IP) ────────
    if mode == "manual" or (explicit_lhost and mode not in ("ngrok", "public", "local")):
        host = explicit_lhost or lan_ip
        return Callback(
            mode="manual", advertised_host=host, advertised_port=lport,
            bind_host="127.0.0.1", bind_port=lport,
            reachable=bool(explicit_lhost),
            note=(
                f"Manual callback {host}:{lport} (e.g. a reverse-SSH tunnel: "
                f"ssh -R {lport}:localhost:{lport} user@{host}). Listener binds "
                "127.0.0.1 and the tunnel forwards inbound connections to it."
            ),
        )

    # ── ngrok TCP tunnel ──────────────────────────────────────────────────────
    if mode == "ngrok":
        host, pub_port, proc = ngrok_start_tcp(lport)
        if host and pub_port:
            return Callback(
                mode="ngrok", advertised_host=host, advertised_port=pub_port,
                bind_host="127.0.0.1", bind_port=lport, reachable=True,
                note=(
                    f"ngrok TCP tunnel: target connects to {host}:{pub_port}, "
                    f"forwarded to the local listener on 127.0.0.1:{lport}. "
                    "Works from behind NAT with no port-forward."
                ),
                tunnel_proc=proc,
            )
        # ngrok requested but unavailable → fall through to public/local.
        logger.info("ngrok requested but unavailable — falling back")
        mode = "public" if target_public else "local"

    # ── public egress IP (requires a port-forward to this host) ───────────────
    if mode == "public":
        pub = get_public_ip()
        if pub:
            return Callback(
                mode="public", advertised_host=pub, advertised_port=lport,
                bind_host="0.0.0.0", bind_port=lport,
                # Only truly reachable if LPORT is forwarded to this host; we
                # cannot verify that, so flag it so the AI stays cautious.
                reachable=False,
                note=(
                    f"Public egress IP {pub}:{lport}. This is only reachable if "
                    f"port {lport} is forwarded to this host (home router / cloud "
                    "security group). If it is not, prefer a tunnel (CALLBACK_MODE="
                    "ngrok) or a non-callback technique (bind shell / web shell)."
                ),
            )
        mode = "local"  # no public IP resolvable

    # ── local LAN IP (labs, or operator directly on a public VPS) ─────────────
    return Callback(
        mode="local", advertised_host=lan_ip, advertised_port=lport,
        bind_host=lan_ip, bind_port=lport,
        # Reachable when the target is on the same private network, OR when this
        # host's LAN IP is itself public (operator on a VPS).
        reachable=(not target_public) or (not is_private_ip(lan_ip)),
        note=(
            f"LAN IP {lan_ip}:{lport}. Reachable from same-network (lab) targets "
            "or when this host is a public VPS. A private LAN IP is NOT reachable "
            "from an internet target behind NAT — set CALLBACK_MODE=ngrok or "
            "EXPLOIT_LHOST to a reverse-SSH/public endpoint for real-world targets."
        ),
    )

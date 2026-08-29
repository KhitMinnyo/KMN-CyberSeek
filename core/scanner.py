"""
KMN-CyberSeek Scanner Module
Handles network scanning and reconnaissance operations.
"""

import asyncio
import json
import logging
import os
import re
import shlex
import signal
import subprocess
from typing import Dict, List, Optional, Tuple

import nmap  # python-nmap

from core.validators import is_valid_target, is_cidr

logger = logging.getLogger(__name__)


async def _kill_process_group(process) -> None:
    """Kill the entire process group of a shell-launched command.

    CRITICAL: commands are launched via create_subprocess_shell, so `process`
    is the `/bin/sh` wrapper and the real tool (nmap, etc.) is its CHILD.
    Calling process.kill() alone kills only the shell — the child keeps running
    and holds the stdout pipe open, so a following communicate() BLOCKS until the
    child finishes on its own (this made scan timeouts never actually fire).
    Killing the whole process group (requires start_new_session=True at launch)
    terminates the child too. Best-effort — never raises.
    """
    if process.returncode is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except ProcessLookupError:
            pass


async def _run_shell_bounded(cmd: str, timeout: int, cwd: str = "/tmp"
                             ) -> Tuple[bytes, bytes, Optional[int], bool]:
    """Run a shell command in its own process group with a hard timeout that
    kills the whole tree. Returns (stdout, stderr, returncode, timed_out).
    On timeout, whatever output the tool already produced is collected
    best-effort so partial scan results are not lost."""
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        start_new_session=True,   # own process group → killable as a unit
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return stdout, stderr, process.returncode, False
    except asyncio.TimeoutError:
        await _kill_process_group(process)
        stdout, stderr = b"", b""
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
        except Exception:
            pass
        return stdout, stderr, process.returncode, True

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def classify_os(os_guess: str = "", ports: Optional[List[Dict]] = None) -> Dict:
    """Classify a host using explicit OS and service evidence.

    SMB is deliberately not treated as a Windows signal by itself: Samba is
    common on Linux lab targets, including Metasploitable.  The result is a
    hypothesis with evidence and confidence, not an assertion that an LLM can
    silently override.
    """
    guess = (os_guess or "").lower()
    ports = ports or []
    linux_score = 0
    windows_score = 0
    linux_evidence: List[str] = []
    windows_evidence: List[str] = []

    def add(family: str, score: int, evidence: str) -> None:
        nonlocal linux_score, windows_score
        if family == "linux":
            linux_score += score
            linux_evidence.append(evidence)
        else:
            windows_score += score
            windows_evidence.append(evidence)

    for marker in ("linux", "unix", "ubuntu", "debian", "red hat", "centos",
                   "fedora", "freebsd", "openbsd", "suse"):
        if marker in guess:
            add("linux", 5, f"Nmap OS guess contains {marker}")
    for marker in ("windows", "microsoft", "windows server", "win32", "win64"):
        if marker in guess:
            add("windows", 5, f"Nmap OS guess contains {marker}")

    linux_services = ("openssh", "ssh", "vsftpd", "proftpd", "apache", "nginx",
                      "httpd", "cups", "rpcbind", "postfix", "dovecot", "samba")
    windows_services = ("ms-wbt-server", "msrpc", "microsoft-ds", "netbios-ssn",
                        "winrm", "iis")
    for port in ports:
        service = f"{port.get('service', '')} {port.get('version', '')}".lower()
        try:
            number = int(port.get("port"))
        except (TypeError, ValueError):
            number = 0
        if any(marker in service for marker in linux_services):
            add("linux", 2, f"Linux service/banner: {service.strip()[:90]}")
        if any(marker in service for marker in windows_services):
            # Generic SMB service names are weak evidence and are outweighed by
            # an explicit Unix/Linux service or OS fingerprint.
            weight = 3 if any(marker in service for marker in ("ms-wbt-server", "msrpc", "winrm", "iis")) else 1
            add("windows", weight, f"Windows service/banner: {service.strip()[:90]}")
        if number in (22, 21, 631):
            add("linux", 1, f"Unix-typical open port: {number}")
        if number in (3389, 5985, 5986):
            add("windows", 2, f"Windows-typical open port: {number}")

    if linux_score == windows_score:
        family = "unknown"
        confidence = 0.0
    else:
        family = "linux" if linux_score > windows_score else "windows"
        lead = abs(linux_score - windows_score)
        confidence = min(0.98, 0.55 + (0.08 * lead))
        # A weak service-only result should remain visibly uncertain.
        if max(linux_score, windows_score) < 3:
            confidence = min(confidence, 0.60)

    evidence = linux_evidence if family == "linux" else windows_evidence
    if family == "unknown":
        evidence = linux_evidence + windows_evidence
    arch_text = f"{guess} " + " ".join(
        f"{port.get('service', '')} {port.get('version', '')}" for port in ports
    ).lower()
    if re.search(r"\b(?:x86_64|amd64|x64|64-bit|64 bit)\b", arch_text):
        architecture = "x64"
        architecture_confidence = 0.90
        architecture_evidence = "OS/service evidence contains x64/64-bit marker"
    elif re.search(r"\b(?:i[3-6]86|x86|i386|32-bit|32 bit)\b", arch_text):
        architecture = "x86"
        architecture_confidence = 0.85
        architecture_evidence = "OS/service evidence contains x86/32-bit marker"
    elif re.search(r"\b(?:aarch64|arm64)\b", arch_text):
        architecture = "arm64"
        architecture_confidence = 0.90
        architecture_evidence = "OS/service evidence contains arm64 marker"
    elif re.search(r"\b(?:armv[5-8]|arm)\b", arch_text):
        architecture = "arm"
        architecture_confidence = 0.75
        architecture_evidence = "OS/service evidence contains ARM marker"
    else:
        architecture = "unknown"
        architecture_confidence = 0.0
        architecture_evidence = ""

    return {
        "os_family": family,
        "os_confidence": round(confidence, 2),
        "os_evidence": list(dict.fromkeys(evidence))[:12],
        "architecture": architecture,
        "architecture_confidence": architecture_confidence,
        "architecture_evidence": architecture_evidence,
    }


def _invalid_target_result(target: str, extra_fields: Optional[Dict] = None) -> Dict:
    """Build a standard failure response for a target that fails validation,
    instead of ever letting it reach a shell command string."""
    logger.error(f"Rejected invalid/unsafe target: {target!r}")
    result = {
        "target": target,
        "success": False,
        "error": "Invalid target: must be a plain IP address or hostname (no shell metacharacters).",
        "raw_output": "",
        "parsed_results": {},
    }
    if extra_fields:
        result.update(extra_fields)
    return result


class Scanner:
    """Network scanner for reconnaissance operations."""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        logger.info("Scanner initialized")
    
    async def perform_nmap_scan(self, target: str, scan_type: str = "default") -> Dict:
        """
        Perform Nmap scan on target.
        
        Args:
            target: IP address or domain to scan
            scan_type: Type of scan (default, quick, full, stealth)
        
        Returns:
            Dictionary with scan results
        """
        logger.info(f"Starting Nmap scan on {target} (type: {scan_type})")

        if not is_valid_target(target):
            return _invalid_target_result(target)

        # Scan timeout: default 300s, configurable via SCAN_TIMEOUT env var.
        # -p- (all 65535 ports) on internet targets can run for hours — we cap
        # each subprocess call so a slow/filtered target never blocks forever.
        import os as _os
        SCAN_TIMEOUT = int(_os.getenv("SCAN_TIMEOUT", "300"))

        # Per-host nmap-internal time cap. Set a bit below SCAN_TIMEOUT so nmap
        # bounds ITSELF and returns graceful partial results, rather than relying
        # only on our external hard kill (which yields empty output). --max-retries
        # keeps slow/filtered ports from dragging the whole scan out.
        _host_timeout = max(60, SCAN_TIMEOUT - 60)
        _bound = f"--host-timeout {_host_timeout}s --max-retries 2"

        # Define scan profiles.
        # NOTE: the initial recon ("default") deliberately drops -sC (default
        # scripts). On hosts with many/slow services (RMI, JMX, GIOP, GlassFish)
        # -sC version+script probing can take 10+ minutes; the AI queues targeted
        # script/vuln scans later, and the background vuln pass runs NSE per port.
        # -Pn (skip host discovery) on every profile: most internet hosts block
        # ICMP/ping, so without it nmap declares them "down" and returns 0 ports —
        # the engagement then has no attack surface and the loop fast-forwards
        # through every stage with nothing to do. -Pn makes nmap scan the ports
        # regardless. (Subnet ping-sweep uses -sn separately and is unaffected.)
        # OS fingerprinting needs raw-packet privileges.  Keep service/banner
        # classification available for unprivileged runs instead of making the
        # whole scan fail with Nmap's "requires root" error.
        _os_detection = ""
        if os.getenv("NMAP_OS_DETECTION", "true").lower() == "true":
            try:
                _os_detection = "-O --osscan-guess" if os.geteuid() == 0 else ""
            except AttributeError:
                _os_detection = ""

        scan_profiles = {
            "quick":    f"-Pn -T4 -F --open {_bound}",                          # top 100, fast
            "default":  f"-Pn -T4 -sV {_os_detection} --top-ports 1000 --open {_bound}",
            "full":     f"-Pn -T4 -sV -sC {_os_detection} --top-ports 5000 --open {_bound}",
            "stealth":  f"-Pn -sS -T2 -sV --top-ports 1000 --open {_bound}",    # stealth SYN
            "vuln":     f"-Pn -T4 -sV --script vuln --top-ports 1000 {_bound}", # vuln NSE
            "allports": f"-Pn -T4 -sV -sC {_os_detection} -p- --open {_bound}", # all 65535 (slow!)
        }

        # perform_service_discovery() may pass a fully formed option string for
        # a known port set; do not silently replace it with the default top-1000
        # profile.
        scan_options = (
            scan_type if isinstance(scan_type, str) and scan_type.lstrip().startswith("-")
            else scan_profiles.get(scan_type, scan_profiles["default"])
        )

        try:
            # target is validated above; shlex.quote is defense-in-depth against injection.
            cmd = f"nmap {scan_options} {shlex.quote(target)}"

            stdout, stderr, returncode, timed_out = await _run_shell_bounded(
                cmd, SCAN_TIMEOUT
            )
            raw_output = (stdout or b"").decode(errors="replace")

            if timed_out:
                # nmap was force-killed at the hard cap. If it printed partial
                # results before dying, parse and return them instead of nothing.
                logger.warning(
                    f"Nmap scan hit hard timeout ({SCAN_TIMEOUT}s) for {target}; "
                    f"{'parsing partial output' if raw_output.strip() else 'no output captured'}"
                )
                if raw_output.strip():
                    parsed_results = self._parse_nmap_output(raw_output)
                    return {
                        "target": target,
                        "success": True,
                        "scan_type": scan_type,
                        "scan_options": scan_options,
                        "partial": True,
                        "raw_output": raw_output,
                        "parsed_results": parsed_results,
                        "timestamp": self._get_timestamp(),
                    }
                return {
                    "target": target,
                    "success": False,
                    "error": f"Scan timed out after {SCAN_TIMEOUT}s with no output. "
                             "Increase SCAN_TIMEOUT or use a quicker scan type.",
                    "raw_output": "",
                    "parsed_results": {}
                }

            if returncode != 0:
                logger.error(f"Nmap scan failed: {(stderr or b'').decode(errors='replace')}")
                return {
                    "target": target,
                    "success": False,
                    "error": (stderr or b"").decode(errors="replace"),
                    "raw_output": raw_output,
                    "parsed_results": {}
                }

            # Parse the results
            parsed_results = self._parse_nmap_output(raw_output)

            logger.info(f"Nmap scan completed for {target}, found {len(parsed_results.get('hosts', []))} hosts")
            
            return {
                "target": target,
                "success": True,
                "scan_type": scan_type,
                "scan_options": scan_options,
                "raw_output": raw_output,
                "parsed_results": parsed_results,
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            logger.error(f"Nmap scan error for {target}: {e}")
            return {
                "target": target,
                "success": False,
                "error": str(e),
                "raw_output": "",
                "parsed_results": {}
            }
    
    def _parse_nmap_output(self, nmap_output: str) -> Dict:
        """
        Parse Nmap output to extract structured information.
        
        Args:
            nmap_output: Raw Nmap command output
        
        Returns:
            Structured dictionary with scan results
        """
        results = {
            "hosts": [],
            "summary": {
                "total_hosts": 0,
                "up_hosts": 0,
                "open_ports": 0,
                "services_found": 0
            }
        }
        
        try:
            lines = nmap_output.split('\n')
            current_host = None
            
            for line in lines:
                line = line.strip()
                
                # Detect Nmap scan report header
                nmap_report_match = re.match(r'Nmap scan report for (.*)', line)
                if nmap_report_match:
                    if current_host:
                        results["hosts"].append(current_host)
                    
                    host_info = nmap_report_match.group(1)
                    current_host = {
                        "host": host_info,
                        "ip": self._extract_ip(host_info),
                        "hostname": self._extract_hostname(host_info),
                        "status": "unknown",
                        "ports": [],
                        "os_guess": None,
                        "os_accuracy": 0,
                        "os_family": "unknown",
                        "os_confidence": 0.0,
                        "os_evidence": []
                    }
                    continue
                
                # Check if we're processing a host
                if current_host:
                    # Check host status
                    if "Host is up" in line:
                        current_host["status"] = "up"
                        results["summary"]["up_hosts"] += 1
                    elif "Host seems down" in line:
                        current_host["status"] = "down"
                    
                    # Parse port information
                    port_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)', line)
                    if port_match:
                        port, protocol, state, service, version = port_match.groups()
                        
                        port_info = {
                            "port": int(port),
                            "protocol": protocol,
                            "state": state,
                            "service": service,
                            "version": version.strip() if version else "",
                            "scripts": []
                        }
                        
                        current_host["ports"].append(port_info)
                        results["summary"]["open_ports"] += 1
                        
                        if service != "closed" and service != "filtered":
                            results["summary"]["services_found"] += 1
                    
                    # Parse OS detection.  -O is optional on unprivileged hosts,
                    # so also consume Running/Service Info lines emitted by -sV.
                    if ("OS details:" in line or "Aggressive OS guesses:" in line
                            or line.startswith("Running:")
                            or line.startswith("Service Info: OS:")):
                        os_info = line.split(":", 1)[1].strip()
                        if line.startswith("Service Info: OS:"):
                            os_info = os_info.split(";", 1)[0].strip()
                        current_host["os_guess"] = (
                            f"{current_host['os_guess']}; {os_info}"
                            if current_host.get("os_guess") else os_info
                        )
                        
                        # Try to extract accuracy
                        accuracy_match = re.search(r'\((\d+)%\)', os_info)
                        if accuracy_match:
                            current_host["os_accuracy"] = int(accuracy_match.group(1))
            
            # Add the last host if exists
            if current_host:
                results["hosts"].append(current_host)

            for host in results["hosts"]:
                host.update(classify_os(host.get("os_guess", ""), host.get("ports", [])))
            
            results["summary"]["total_hosts"] = len(results["hosts"])
            
        except Exception as e:
            logger.error(f"Failed to parse Nmap output: {e}")
        
        return results
    
    def _extract_ip(self, host_info: str) -> str:
        """Extract IP address from host information."""
        # Handle cases like "scanme.nmap.org (45.33.32.156)"
        ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', host_info)
        if ip_match:
            return ip_match.group(1)
        
        # Check if it's already an IP
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        if re.match(ip_pattern, host_info):
            return host_info
        
        return host_info
    
    def _extract_hostname(self, host_info: str) -> Optional[str]:
        """Extract hostname from host information."""
        # Handle cases like "scanme.nmap.org (45.33.32.156)"
        if '(' in host_info and ')' in host_info:
            return host_info.split('(')[0].strip()
        
        # Check if it's a hostname (not IP)
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        if not re.match(ip_pattern, host_info):
            return host_info
        
        return None
    
    def parse_nmap_results(self, scan_results: Dict) -> List[Dict]:
        """
        Parse scan results from previous scans.
        
        Args:
            scan_results: Dictionary from perform_nmap_scan
        
        Returns:
            List of discovered hosts
        """
        if not scan_results.get("success"):
            return []
        
        parsed = scan_results.get("parsed_results", {})
        return parsed.get("hosts", [])
    
    async def perform_service_discovery(self, target: str, ports: List[int] = None) -> Dict:
        """
        Perform service discovery on specific ports.
        
        Args:
            target: IP address or domain
            ports: List of ports to scan (None for default)
        
        Returns:
            Service discovery results
        """
        if ports:
            port_range = ','.join(str(p) for p in ports)
            options = f"-sV -p {port_range}"
        else:
            options = "-sV --top-ports 100"
        
        return await self.perform_nmap_scan(target, options)
    
    async def perform_subnet_sweep(self, cidr: str) -> Dict:
        """Run a fast nmap ping sweep (-sn) on a CIDR subnet to discover live hosts.
        Returns the same structure as perform_nmap_scan so callers can use
        parse_nmap_results() on the result.

        Only callable with CIDR targets — plain IPs are rejected to enforce the
        semantic distinction (ping sweep on a /32 would be an ordinary host scan,
        which is confusing; use perform_nmap_scan for that).
        """
        if not is_cidr(cidr):
            return _invalid_target_result(cidr, {"vulnerabilities": []})

        logger.info(f"Starting subnet ping sweep: {cidr}")
        cmd = f"nmap -sn -T4 {shlex.quote(cidr)}"
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/tmp"
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            raw_output = stdout.decode()
            parsed = self._parse_nmap_output(raw_output)
            logger.info(
                f"Subnet sweep of {cidr} found "
                f"{parsed.get('summary', {}).get('up_hosts', 0)} live host(s)"
            )
            return {
                "target": cidr,
                "success": process.returncode == 0,
                "scan_type": "subnet_sweep",
                "scan_options": "-sn -T4",
                "raw_output": raw_output,
                "parsed_results": parsed,
                "timestamp": self._get_timestamp()
            }
        except Exception as e:
            logger.error(f"Subnet sweep failed for {cidr}: {e}")
            return {
                "target": cidr,
                "success": False,
                "error": str(e),
                "raw_output": "",
                "parsed_results": {}
            }

    async def perform_vulnerability_scan(self, target: str, ports: Optional[List[int]] = None) -> Dict:
        """
        Perform targeted vulnerability scan using a curated subset of Nmap NSE scripts.

        Uses "vuln and not intrusive" category (skips slow/destructive scripts) plus a
        per-script timeout cap so a single hanging script cannot stall the whole scan.
        A dedicated VULN_SCAN_TIMEOUT env var (default 120s) controls the total wall-clock
        limit — kept separate from the general SCAN_TIMEOUT so recon scans and vuln scans
        can be tuned independently.

        Args:
            target: IP address or domain
            ports: Optional list of specific ports to target (e.g. the open ports
                already found during recon). Scanning only known-open ports is much
                faster than re-scanning the default/full range. If omitted, Nmap's
                own default port selection is used.

        Returns:
            Vulnerability scan results
        """
        import os as _os
        VULN_SCAN_TIMEOUT = int(_os.getenv("VULN_SCAN_TIMEOUT", "120"))

        logger.info(f"Starting vulnerability scan on {target}" + (f" (ports: {ports})" if ports else ""))

        if not is_valid_target(target):
            return _invalid_target_result(target, {"vulnerabilities": []})

        try:
            # "vuln and not intrusive" skips slow/noisy/destructive scripts.
            # --script-timeout 30 caps any single script so a hung check cannot
            # block the whole scan. -T4 aggressive timing keeps service probing fast.
            port_flag = f"-p {','.join(str(int(p)) for p in ports)} " if ports else ""
            cmd = (
                f"nmap -Pn -sV -T4 {port_flag}"
                f'--script "vuln and not intrusive" --script-timeout 30 '
                f"{shlex.quote(target)}"
            )

            stdout, stderr, returncode, timed_out = await _run_shell_bounded(
                cmd, VULN_SCAN_TIMEOUT
            )
            raw_output = (stdout or b"").decode(errors="replace")

            if timed_out and not raw_output.strip():
                logger.warning(
                    f"Vulnerability scan timed out after {VULN_SCAN_TIMEOUT}s for {target} — "
                    "continuing without NSE vuln findings"
                )
                return {
                    "target": target,
                    "success": False,
                    "error": f"Scan timed out after {VULN_SCAN_TIMEOUT}s",
                    "vulnerabilities": [],
                }

            if not timed_out and returncode not in (0, None):
                logger.error(f"Vulnerability scan failed: {(stderr or b'').decode(errors='replace')}")
                return {
                    "target": target,
                    "success": False,
                    "error": (stderr or b"").decode(errors="replace"),
                    "vulnerabilities": []
                }

            # Parse whatever we got (full result, or partial output on timeout).
            vulnerabilities = self._parse_vulnerability_output(raw_output)

            logger.info(f"Vulnerability scan completed for {target}, found {len(vulnerabilities)} issues")

            return {
                "target": target,
                "success": True,
                "raw_output": raw_output,
                "vulnerabilities": vulnerabilities,
                "timestamp": self._get_timestamp()
            }

        except Exception as e:
            logger.error(f"Vulnerability scan error for {target}: {e}")
            return {
                "target": target,
                "success": False,
                "error": str(e),
                "vulnerabilities": []
            }
    
    async def perform_vulnerability_scan_port(
        self, target: str, port: int, timeout: int = 60
    ) -> Dict:
        """Run nmap vuln NSE scripts against a single port.

        Scoped to one port at a time so:
        - Each port gets a generous individual timeout (default 60s) without
          one slow port starving all others.
        - Callers can check a completion marker before calling and skip ports
          already scanned, enabling true resume across backend restarts.

        Returns the same shape as perform_vulnerability_scan():
          {"target": ..., "port": int, "success": bool,
           "vulnerabilities": [...], "raw_output": "..."}
        """
        import os as _os
        timeout = int(_os.getenv("VULN_PORT_TIMEOUT", str(timeout)))

        if not is_valid_target(target):
            return _invalid_target_result(target, {"vulnerabilities": [], "port": port})

        logger.info(f"Starting per-port vuln scan: {target}:{port}")
        try:
            cmd = (
                f"nmap -Pn -sV -T4 -p {int(port)} "
                f'--script "vuln and not intrusive" --script-timeout 20 '
                f"{shlex.quote(target)}"
            )
            stdout, stderr, returncode, timed_out = await _run_shell_bounded(cmd, timeout)
            raw = (stdout or b"").decode(errors="replace")
            if timed_out and not raw.strip():
                logger.warning(f"Per-port vuln scan timed out after {timeout}s: {target}:{port}")
                return {
                    "target": target, "port": port,
                    "success": False, "error": f"timed out after {timeout}s",
                    "vulnerabilities": [], "raw_output": "",
                }

            vulns = self._parse_vulnerability_output(raw)
            logger.info(f"Per-port vuln scan done: {target}:{port} — {len(vulns)} finding(s)")
            return {
                "target": target, "port": port,
                "success": True, "raw_output": raw,
                "vulnerabilities": vulns,
            }
        except Exception as e:
            logger.warning(f"Per-port vuln scan error {target}:{port}: {e}")
            return {
                "target": target, "port": port,
                "success": False, "error": str(e),
                "vulnerabilities": [], "raw_output": "",
            }

    async def searchsploit_lookup(self, service: str, version: str) -> List[Dict]:
        """
        Query the local ExploitDB via `searchsploit` for exploits matching a
        service + version string.  Returns an empty list (never raises) when
        searchsploit is not installed or the query returns nothing.

        Each hit is returned as:
            {"title": str, "path": str, "type": str, "cve_ids": List[str]}

        where `path` is the ExploitDB relative path (e.g.
        "exploits/linux/remote/12345.py") and `type` is "exploit" or "shellcode".
        """
        if not service:
            return []
        query = f"{service} {version}".strip()
        try:
            proc = await asyncio.create_subprocess_exec(
                "searchsploit", "--json", "-t", query,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                logger.warning(f"searchsploit timed out for query: {query!r}")
                return []

            if proc.returncode != 0 or not stdout:
                return []

            data = json.loads(stdout.decode())
            hits = []
            for entry in data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", []):
                title = entry.get("Title", "")
                path  = entry.get("Path", "")
                etype = "shellcode" if "shellcode" in path.lower() else "exploit"
                cves  = _CVE_ID_RE.findall(title + " " + path)
                hits.append({
                    "title": title,
                    "path": path,
                    "type": etype,
                    "cve_ids": [c.upper() for c in dict.fromkeys(cves)],
                })
            logger.info(f"searchsploit: {len(hits)} hits for {query!r}")
            return hits

        except FileNotFoundError:
            # searchsploit not installed — silently skip
            return []
        except Exception as e:
            logger.warning(f"searchsploit lookup failed for {query!r}: {e}")
            return []

    def _parse_vulnerability_output(self, output: str) -> List[Dict]:
        """Parse vulnerability scan output."""
        vulnerabilities = []
        
        try:
            lines = output.split('\n')
            current_vuln = None
            
            for line in lines:
                line = line.strip()
                
                # Look for vulnerability script results
                if line.startswith('|'):
                    # Remove the leading '|' and any whitespace
                    vuln_line = line[1:].strip()
                    
                    # Check for common vulnerability patterns
                    if 'VULNERABLE:' in vuln_line:
                        if current_vuln:
                            vulnerabilities.append(current_vuln)
                        
                        current_vuln = {
                            "name": vuln_line.replace('VULNERABLE:', '').strip(),
                            "description": "",
                            "risk": "unknown",
                            "ports": [],
                            "references": [],
                            "cve_ids": []
                        }
                    elif current_vuln:
                        # Add details to current vulnerability
                        if 'State:' in vuln_line:
                            current_vuln["risk"] = self._extract_risk_level(vuln_line)
                        elif 'Ports:' in vuln_line:
                            ports = vuln_line.replace('Ports:', '').strip()
                            current_vuln["ports"] = self._extract_ports(ports)
                        elif not current_vuln["description"]:
                            current_vuln["description"] = vuln_line
                        elif 'References:' in vuln_line:
                            pass  # Skip references line
                        elif vuln_line.startswith('http'):
                            current_vuln["references"].append(vuln_line)

                        # NSE vuln scripts often name the finding after its CVE (e.g.
                        # "CVE-2021-41773") or list CVEs in the description/refs - capture
                        # any that appear anywhere in this finding's text so far.
                        found_cves = _CVE_ID_RE.findall(
                            current_vuln["name"] + " " + vuln_line
                        )
                        for cve in found_cves:
                            cve_upper = cve.upper()
                            if cve_upper not in current_vuln["cve_ids"]:
                                current_vuln["cve_ids"].append(cve_upper)

            # Add the last vulnerability if exists
            if current_vuln:
                vulnerabilities.append(current_vuln)

        except Exception as e:
            logger.error(f"Failed to parse vulnerability output: {e}")

        return vulnerabilities
    
    def _extract_risk_level(self, state_line: str) -> str:
        """Extract risk level from state line."""
        state_line = state_line.lower()
        
        if 'vulnerable' in state_line:
            return "high"
        elif 'potentially' in state_line:
            return "medium"
        elif 'not vulnerable' in state_line:
            return "low"
        else:
            return "unknown"
    
    def _extract_ports(self, ports_str: str) -> List[int]:
        """Extract port numbers from string."""
        ports = []
        
        try:
            # Handle various port formats: "80/tcp, 443/tcp" or "21,22,23"
            parts = re.findall(r'(\d+)/', ports_str)
            if parts:
                ports = [int(p) for p in parts]
            else:
                # Try comma-separated numbers
                numbers = re.findall(r'\d+', ports_str)
                ports = [int(n) for n in numbers]
                
        except Exception as e:
            logger.error(f"Failed to extract ports: {e}")
        
        return ports
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    async def check_port_status(self, target: str, port: int) -> Dict:
        """
        Check status of a specific port.
        
        Args:
            target: IP address or domain
            port: Port number to check
        
        Returns:
            Port status information
        """
        if not is_valid_target(target):
            return _invalid_target_result(target, {"port": port})

        if not isinstance(port, int) or not (0 < port < 65536):
            logger.error(f"Rejected invalid port: {port!r}")
            return {
                "target": target,
                "port": port,
                "success": False,
                "error": "Invalid port: must be an integer between 1 and 65535."
            }

        try:
            cmd = f"nmap -Pn -p {port} {shlex.quote(target)}"

            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/tmp"
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "target": target,
                    "port": port,
                    "success": False,
                    "error": stderr.decode()
                }
            
            output = stdout.decode()
            
            # Parse simple output
            status = "unknown"
            if f"{port}/tcp open" in output:
                status = "open"
            elif f"{port}/tcp closed" in output:
                status = "closed"
            elif f"{port}/tcp filtered" in output:
                status = "filtered"
            
            return {
                "target": target,
                "port": port,
                "success": True,
                "status": status,
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            logger.error(f"Port check failed for {target}:{port}: {e}")
            return {
                "target": target,
                "port": port,
                "success": False,
                "error": str(e)
            }


# Helper function for backward compatibility
def get_scanner() -> Scanner:
    """Factory function to get scanner instance."""
    return Scanner()

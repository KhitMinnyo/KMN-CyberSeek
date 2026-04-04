"""
KMN-CyberSeek Scanner Module
Handles network scanning and reconnaissance operations.
"""

import asyncio
import json
import logging
import re
import subprocess
from typing import Dict, List, Optional

import nmap  # python-nmap

logger = logging.getLogger(__name__)


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
        
        # Define scan profiles (updated with Windows ports and vulnerabilities)
        scan_profiles = {
            "quick": "-T4 -F",  # Fast scan, only top 100 ports
            "default": "-sV -sC -O --top-ports 1000",  # Service version, default scripts, OS detection, top 1000 ports
            "full": "-sV -sC -O -p-",  # Full scan with scripts, OS detection, all ports
            "stealth": "-sS -sV --top-ports 100",  # Stealth SYN scan
            "vuln": "-sV --script vuln --top-ports 1000",  # Vulnerability scan on top 1000 ports
        }
        
        scan_options = scan_profiles.get(scan_type, scan_profiles["default"])
        
        try:
            # Run Nmap scan asynchronously
            loop = asyncio.get_event_loop()
            
            # Use subprocess for better control and async execution
            cmd = f"nmap {scan_options} {target}"
            
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/tmp"
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Nmap scan failed: {stderr.decode()}")
                return {
                    "target": target,
                    "success": False,
                    "error": stderr.decode(),
                    "raw_output": "",
                    "parsed_results": {}
                }
            
            raw_output = stdout.decode()
            
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
                        "os_accuracy": 0
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
                    
                    # Parse OS detection
                    if "OS details:" in line or "Aggressive OS guesses:" in line:
                        os_info = line.split(":", 1)[1].strip()
                        current_host["os_guess"] = os_info
                        
                        # Try to extract accuracy
                        accuracy_match = re.search(r'\((\d+)%\)', os_info)
                        if accuracy_match:
                            current_host["os_accuracy"] = int(accuracy_match.group(1))
            
            # Add the last host if exists
            if current_host:
                results["hosts"].append(current_host)
            
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
    
    async def perform_vulnerability_scan(self, target: str) -> Dict:
        """
        Perform basic vulnerability scan using Nmap scripts.
        
        Args:
            target: IP address or domain
        
        Returns:
            Vulnerability scan results
        """
        logger.info(f"Starting vulnerability scan on {target}")
        
        try:
            # Use Nmap with vulnerability scripts
            cmd = f"nmap -sV --script vuln {target}"
            
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/tmp"
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Vulnerability scan failed: {stderr.decode()}")
                return {
                    "target": target,
                    "success": False,
                    "error": stderr.decode(),
                    "vulnerabilities": []
                }
            
            raw_output = stdout.decode()
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
                            "references": []
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
        try:
            cmd = f"nmap -p {port} {target}"
            
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
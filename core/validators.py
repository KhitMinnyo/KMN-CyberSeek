"""
KMN-CyberSeek Validators Module
Centralized safety checks: target format validation, scope allowlisting, and a
binary allowlist used to gate the fully-autonomous (zero-human-review) auto-execute path.

These are defense-in-depth controls, not a claim of perfect shell parsing. They exist to
shrink blast radius for two realistic failure modes of an LLM-driven agent that shells out:
1. A malformed/hostile "target" string reaching a shell command via string interpolation.
2. The LLM being steered (via misclassification or indirect prompt injection from
   attacker-controlled scan/tool output) into suggesting a command that should never
   run without a human looking at it first.
"""

import ipaddress
import os
import re
from typing import Optional

# --- Target format validation -------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_cidr(value: str) -> bool:
    """Return True if value is a valid IPv4/IPv6 CIDR network (e.g. 192.168.1.0/24).
    strict=False so host bits set (192.168.1.5/24) are still accepted."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
        # Reject host addresses presented as plain IPs with no prefix — those
        # are handled by ip_address() in is_valid_target(). A valid CIDR must
        # contain a "/" character.
        return "/" in value
    except ValueError:
        return False


def is_valid_target(value: Optional[str]) -> bool:
    """Return True if value is a plain IP address, hostname, or CIDR network
    with no shell metacharacters. CIDR notation (192.168.1.0/24) is now
    accepted to support subnet-level scanning.
    """
    if not value or not isinstance(value, str):
        return False
    value = value.strip()
    if not value or len(value) > 253:
        return False

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    if is_cidr(value):
        return True

    return bool(_HOSTNAME_RE.match(value))


# --- Scope allowlisting ---------------------------------------------------------

def is_target_in_scope(target: Optional[str], allowlist_str: Optional[str]) -> bool:
    """Check a target against an optional SCOPE_ALLOWLIST (comma-separated IPs,
    CIDR ranges, exact hostnames, or "*.suffix" wildcard hostnames).

    If allowlist_str is empty/unset, scope is unrestricted (default, backward
    compatible for solo/homelab use). Set SCOPE_ALLOWLIST in .env to enforce a
    hard technical boundary on what this tool is permitted to target.
    """
    if not target:
        return False
    if not allowlist_str or not allowlist_str.strip():
        return True  # No allowlist configured -> unrestricted

    entries = [e.strip() for e in allowlist_str.split(",") if e.strip()]
    if not entries:
        return True

    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        target_ip = None

    # Handle CIDR target: check that the target subnet is contained within
    # or equal to at least one allowlist entry.
    try:
        target_net = ipaddress.ip_network(target, strict=False) if "/" in target else None
    except ValueError:
        target_net = None

    target_lower = target.lower()
    for entry in entries:
        if target_ip is not None:
            try:
                if target_ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass  # entry wasn't an IP/CIDR, fall through to hostname checks

        if target_net is not None:
            try:
                allowlist_net = ipaddress.ip_network(entry, strict=False)
                # Target subnet must be a subnet of (or equal to) the allowlist entry
                if target_net.subnet_of(allowlist_net):
                    return True
            except (ValueError, TypeError):
                pass

        entry_lower = entry.lower()
        if entry_lower == target_lower:
            return True
        if entry_lower.startswith("*.") and target_lower.endswith(entry_lower[1:]):
            return True

    return False


# --- Binary allowlist for the autonomous auto-execute path ----------------------

# Comprehensive Kali Linux toolset allowlist for the autonomous auto-execute path.
# Covers recon, web-app, brute-force, exploitation, AD/SMB, post-exploitation,
# wireless, forensics, scripting, and standard shell utilities.
# When FULL_AUTO_MODE=true this list is bypassed entirely — see is_allowlisted_command().
ALLOWED_BINARIES = {
    # ── Reconnaissance & scanning ───────────────────────────────────────
    "nmap", "masscan", "rustscan", "unicornscan",
    "netdiscover", "arp-scan", "hping3", "fping", "p0f",
    "tcpdump", "tshark", "wireshark", "netstat", "ss", "iptables", "ip",
    "ping", "ping6", "traceroute", "traceroute6", "mtr",
    "whois", "dig", "nslookup", "host",
    "fierce", "dnsrecon", "dnsenum", "dnswalk", "dnsmap",
    "sublist3r", "amass", "subfinder", "assetfinder", "dnsx", "httpx",
    "aquatone", "eyewitness", "gowitness",

    # ── Web application ─────────────────────────────────────────────────
    "whatweb", "nikto", "gobuster", "dirb", "dirsearch", "ffuf",
    "wfuzz", "feroxbuster",
    "wpscan", "joomscan", "droopescan", "cmseek",
    "sqlmap", "ghauri", "commix", "xsser", "dalfox", "arjun",
    "nuclei", "jaeles",
    "nosqlmap", "jwt_tool", "jwttool",
    "burpsuite", "zaproxy", "mitmproxy",
    "cutycapt", "wkhtmltoimage",

    # ── Brute-force & credential attacks ───────────────────────────────
    "hydra", "ncrack", "medusa", "crowbar", "patator",
    "crackmapexec", "cme",
    "cewl", "crunch", "cupp", "rsmangler", "mentalist",
    "hashcat", "john", "hash-identifier", "hashid", "haiti",
    "ophcrack", "samdump2", "chntpw",

    # ── Exploitation & frameworks ───────────────────────────────────────
    "msfconsole", "msfvenom", "msfdb", "msfrpc",
    "searchsploit",
    "nc", "ncat", "netcat", "socat",
    "pwncat", "pwncat-cs",
    "rlwrap",
    "beef-xss",

    # ── SMB / Windows / Active Directory ────────────────────────────────
    "smbclient", "smbmap", "smbget",
    "enum4linux", "enum4linux-ng",
    "rpcclient", "net", "rpcinfo",
    "ldapsearch", "ldapdomaindump", "ldapmodify", "ldapadd",
    "kinit", "klist", "kdestroy", "kvno",
    "bloodhound", "bloodhound-python", "neo4j",
    "kerbrute",
    "impacket-secretsdump", "impacket-psexec", "impacket-wmiexec",
    "impacket-smbexec", "impacket-getuserspns", "impacket-getnpusers",
    "impacket-ntlmrelayx", "impacket-smbserver", "impacket-lookupsid",
    "impacket-reg", "impacket-dcomexec", "impacket-atexec",
    "impacket-ticketer", "impacket-goldenPac", "impacket-rpcdump",
    "evil-winrm",
    "xfreerdp", "rdesktop", "freerdp",
    "winexe",

    # ── Post-exploitation & pivoting ────────────────────────────────────
    "proxychains", "proxychains4",
    "chisel", "ligolo-ng", "ligolo",
    "pspy", "pspy32", "pspy64",
    "linpeas", "winpeas", "linenum",
    "unix-privesc-check", "linux-exploit-suggester",
    "gtfobins",

    # ── Wireless ────────────────────────────────────────────────────────
    "aircrack-ng", "airmon-ng", "aireplay-ng", "airodump-ng",
    "airdecap-ng", "packetforge-ng", "airbase-ng",
    "kismet", "wifite", "bettercap",
    "hostapd", "hostapd-wpe",
    "hcxtools", "hcxdumptool",
    "reaver", "bully", "pixiewps",
    "wpa_supplicant", "iw", "iwconfig", "iwlist",

    # ── Vulnerability analysis ──────────────────────────────────────────
    "openvas", "openvas-start", "gvm-cli", "gvm-check-setup",
    "lynis", "chkrootkit", "rkhunter",
    "testssl", "sslscan", "sslyze",
    "certutil", "openssl",

    # ── Network utilities ───────────────────────────────────────────────
    "curl", "wget",
    "ssh", "ssh-keyscan", "ssh-keygen", "ssh-copy-id", "scp", "sftp",
    "responder", "mitm6", "arpspoof", "ettercap",
    "tcpflow", "ngrep", "dsniff", "sslstrip",
    "nfqueue", "scapy",
    "proxytunnel", "corkscrew",

    # ── Forensics & reverse engineering ─────────────────────────────────
    "binwalk", "strings", "file", "hexdump", "xxd",
    "objdump", "readelf", "nm", "strace", "ltrace",
    "radare2", "r2", "r2pm",
    "gdb", "gdbserver",
    "volatility", "volatility3",
    "foremost", "scalpel", "bulk_extractor", "photorec",
    "exiftool", "steghide", "stegcracker", "zsteg",
    "pdfinfo", "pdfcrack",

    # ── Scripting runtimes ──────────────────────────────────────────────
    "python3", "python", "python2",
    "bash", "sh", "zsh", "dash", "fish",
    "perl", "ruby", "php",
    "node", "nodejs", "npm",
    "go", "java", "javac", "jar",
    "gcc", "g++", "make", "cmake",
    "powershell", "pwsh",

    # ── Standard shell utilities ─────────────────────────────────────────
    "echo", "printf", "cat", "tac",
    "ls", "ll", "la", "dir",
    "mkdir", "cp", "mv", "rm", "rmdir", "ln", "touch",
    "grep", "egrep", "fgrep", "rg", "ag",
    "awk", "gawk", "sed", "head", "tail", "less", "more",
    "sort", "uniq", "wc", "tr", "cut", "paste", "join",
    "find", "locate", "which", "whereis", "type",
    "xargs", "parallel",
    "chmod", "chown", "chgrp", "stat", "lsattr", "chattr", "getfacl", "setfacl",
    "id", "whoami", "groups", "uname", "hostname", "uptime", "uname",
    "ps", "pstree", "top", "htop", "kill", "pkill", "killall", "signal",
    "jobs", "fg", "bg", "nohup", "disown",
    "screen", "tmux",
    "date", "cal", "bc", "expr",
    "base64", "base32",
    "zip", "unzip", "tar", "gzip", "gunzip", "bzip2", "xz", "lzma",
    "7z", "7za", "rar", "unrar",
    "tee", "timeout", "watch", "time",
    "env", "printenv",
    "diff", "patch", "cmp",
    "wget", "curl",

    # ── Package management ───────────────────────────────────────────────
    "apt-get", "apt", "apt-cache", "dpkg",
    "pip", "pip3", "pip2",
    "gem", "bundle",

    # ── OSINT ────────────────────────────────────────────────────────────
    "theharvester", "recon-ng", "maltego",
    "shodan",

    # ── Version control / misc ───────────────────────────────────────────
    "git", "svn",
    "docker", "kubectl",
    "jq", "yq", "xmllint",
    "nc", "ncat",
}

# "curl/wget SOMETHING | bash/sh/python" is a classic download-and-execute chain.
# Block it outright even though the individual binaries are each allowlisted
# (bash/python are legitimately needed for non-interactive `-c` one-liners).
_DOWNLOAD_EXEC_RE = re.compile(
    r"\b(curl|wget)\b[^;&|\n]*\|\s*(bash|sh|python3?|perl|ruby)\b", re.IGNORECASE
)

_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def is_allowlisted_command(command: Optional[str]) -> Optional[str]:
    """Gate for the fully-autonomous auto-execute path (no human review).

    Returns None if the command is allowed to run, or a short human-readable
    rejection reason if it should instead be routed to manual approval.

    When FULL_AUTO_MODE=true in the environment this check is bypassed entirely —
    the operator has explicitly opted into unrestricted AI-driven execution.

    NOT applied to commands a human explicitly typed or clicked "approve" on —
    that's a legitimate trust boundary and operators should retain full
    flexibility to run any tool they choose to review themselves.
    """
    if not command or not command.strip():
        return "Empty command"

    # FULL_AUTO_MODE bypasses the allowlist entirely.
    if os.getenv("FULL_AUTO_MODE", "false").lower() == "true":
        return None

    if "`" in command or "$(" in command:
        return "Command substitution (backticks or $()) is not allowed in auto-executed commands"

    if _DOWNLOAD_EXEC_RE.search(command):
        return "Download-and-execute pattern (curl/wget piped into a shell/interpreter) is not allowed in auto-executed commands"

    segments = re.split(r"&&|\|\||;|\||\n", command)
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        tokens = segment.split()
        idx = 0
        # Skip leading environment variable assignments (FOO=bar cmd ...)
        while idx < len(tokens) and _ENV_ASSIGNMENT_RE.match(tokens[idx]):
            idx += 1
        # Skip a leading sudo
        if idx < len(tokens) and tokens[idx] == "sudo":
            idx += 1
        if idx >= len(tokens):
            continue
        binary = os.path.basename(tokens[idx])
        if binary not in ALLOWED_BINARIES:
            return f"Binary '{binary}' is not in the auto-execute allowlist"

    return None

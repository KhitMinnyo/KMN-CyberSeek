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
from typing import Optional, List

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
# The list is enforced for every automated execution path, including
# FULL_AUTO_MODE. Explicit operator approval is the only path that may run a
# command outside this list.
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
    "davtest",
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
    "smbclient", "smbmap", "smbget", "ftp", "mysql", "psql", "redis-cli", "showmount",
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


def _split_shell_segments(command: str):
    """Split top-level shell operators without splitting quoted arguments."""
    segments = []
    current = []
    quote = None
    escaped = False
    i = 0
    while i < len(command):
        char = command[i]
        if escaped:
            current.append(char)
            escaped = False
            i += 1
            continue
        if char == "\\" and quote != "'":
            current.append(char)
            escaped = True
            i += 1
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            i += 1
            continue
        if char in ("'", '"'):
            quote = char
            current.append(char)
            i += 1
            continue
        if char in ";|\n":
            if current:
                segments.append("".join(current))
                current = []
            if char in "|" and i + 1 < len(command) and command[i + 1] == char:
                i += 1
            i += 1
            continue
        current.append(char)
        i += 1
    if current:
        segments.append("".join(current))
    return segments


def is_allowlisted_command(command: Optional[str]) -> Optional[str]:
    """Gate for the fully-autonomous auto-execute path (no human review).

    Returns None if the command is allowed to run, or a short human-readable
    rejection reason if it should instead be routed to manual approval.

    This check is intentionally independent of FULL_AUTO_MODE. Automated
    execution must never turn an environment flag into an arbitrary shell
    execution bypass. Commands explicitly approved by an operator are handled
    by the execution gateway and may use the reviewed manual trust boundary.
    """
    if not command or not command.strip():
        return "Empty command"

    if "`" in command or "$(" in command:
        return "Command substitution (backticks or $()) is not allowed in auto-executed commands"

    if _DOWNLOAD_EXEC_RE.search(command):
        return "Download-and-execute pattern (curl/wget piped into a shell/interpreter) is not allowed in auto-executed commands"

    # A here-document is one command body. Validate its launcher, but do not
    # mistake protocol words inside the body for local binaries.
    heredoc_prefix = command.split("<<", 1)[0] if "<<" in command else None
    segments = _split_shell_segments(heredoc_prefix or command)
    shell_words = {
        "if", "then", "else", "elif", "fi", "for", "while", "until",
        "do", "done", "case", "esac", "in", "function", "select",
        "time", "!", "[", "]", "test", "true", "false",
    }
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        tokens = segment.split()
        idx = 0
        # Skip leading environment variable assignments (FOO=bar cmd ...)
        while idx < len(tokens) and _ENV_ASSIGNMENT_RE.match(tokens[idx]):
            idx += 1
        if idx < len(tokens) and tokens[idx] in {"for", "while", "until"}:
            # The loop declaration has no executable binary yet. Its body is
            # validated when the following `do` segment is encountered.
            continue
        # Shell keywords can precede a command-local assignment, e.g.
        # `do user="..."; echo ...`. Skip both in that order before checking
        # the actual executable binary.
        while idx < len(tokens) and tokens[idx] in shell_words:
            idx += 1
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


# ── Tool-specific verification engine ─────────────────────────────────────────
# Each validator receives the raw tool output string and returns True when the
# tool's own success criteria are satisfied.  Return False means inconclusive
# or failure; the caller should NOT upgrade status to "exploited/verified" on
# False.  These replace the legacy single-keyword heuristic.

import re as _re

def validate_msf_session_open(output: str) -> bool:
    """Meterpreter or shell session opened via Metasploit."""
    pat = _re.compile(
        r"(Meterpreter session \d+ opened"
        r"|Command shell session \d+ opened"
        r"|session \d+ created)",
        _re.IGNORECASE,
    )
    return bool(pat.search(output or ""))


def validate_ssh_auth(output: str) -> bool:
    """SSH authentication succeeded — we got a prompt or banner, not a denial."""
    out = output or ""
    # Common failure markers
    fail_pats = _re.compile(
        r"(Permission denied|Authentication failed"
        r"|Connection refused|Could not resolve|Too many authentication failures"
        r"|Host key verification failed)",
        _re.IGNORECASE,
    )
    if fail_pats.search(out):
        return False
    # Success indicators: shell prompt, banner grab, or hydra success line
    ok_pats = _re.compile(
        r"(\$\s*$|#\s*$|\[SUCCESS\]|login:\s*\[\d+\]"
        r"|Welcome to|Last login|OpenSSH)",
        _re.IGNORECASE,
    )
    return bool(ok_pats.search(out))


def validate_winrm_auth(output: str) -> bool:
    """WinRM / evil-winrm authentication succeeded."""
    out = output or ""
    fail_pats = _re.compile(
        r"(WinRM::WinRMAuthorizationError|401 Unauthorized"
        r"|Connection refused|HTTPAUTH_CREDS_UNAVAILABLE"
        r"|Logon failure)",
        _re.IGNORECASE,
    )
    if fail_pats.search(out):
        return False
    ok_pats = _re.compile(
        r"(Evil-WinRM shell|PS .+>|\*Evil-WinRM\*)",
        _re.IGNORECASE,
    )
    return bool(ok_pats.search(out))


def validate_smb_auth(output: str) -> bool:
    """SMB authentication and share access succeeded."""
    out = output or ""
    fail_pats = _re.compile(
        r"(NT_STATUS_LOGON_FAILURE|NT_STATUS_ACCESS_DENIED"
        r"|NT_STATUS_INVALID_PARAMETER|NT_STATUS_CONNECTION_REFUSED"
        r"|STATUS_LOGON_FAILURE|Login failed)",
        _re.IGNORECASE,
    )
    if fail_pats.search(out):
        return False
    ok_pats = _re.compile(
        r"(Sharename|Domain=|\[+\]\s+Authenticated"
        r"|smb: \\\\>|tree connect andx response)",
        _re.IGNORECASE,
    )
    return bool(ok_pats.search(out))


_WEB_RCE_NONCE_RE = _re.compile(r"KMN_RCE_[A-F0-9]{8}", _re.IGNORECASE)

def validate_web_rce(output: str, nonce: Optional[str] = None) -> bool:
    """Web RCE confirmed — check nonce echo or known execution indicators."""
    out = output or ""
    if nonce:
        return nonce in out
    # Fallback: common execution evidence
    ok_pats = _re.compile(
        r"(uid=\d+|root:|www-data|apache|nginx"
        r"|Linux .*#\d+|Microsoft Windows|\[System Process\]"
        r"|Successfully uploaded|shell uploaded)",
        _re.IGNORECASE,
    )
    return bool(ok_pats.search(out))


def validate_sql_query(output: str, expected_table: str = "") -> bool:
    """SQL query returned real rows (not an auth/connection error)."""
    out = output or ""
    fail_pats = _re.compile(
        r"(Access denied for user|ERROR \d+|authentication failed"
        r"|Connection refused|could not connect|FATAL:)",
        _re.IGNORECASE,
    )
    if fail_pats.search(out):
        return False
    if expected_table:
        return expected_table.lower() in out.lower()
    ok_pats = _re.compile(
        r"(rows in set|row affected|\+[-+]+\+|\|.*\||SELECT|INSERT|UPDATE)",
        _re.IGNORECASE,
    )
    return bool(ok_pats.search(out))


def validate_ftp_access(output: str) -> bool:
    """FTP login and directory listing succeeded."""
    out = output or ""
    fail_pats = _re.compile(
        r"(530 Login|530 Not logged|Connection refused|Login failed|Auth failed)",
        _re.IGNORECASE,
    )
    if fail_pats.search(out):
        return False
    ok_pats = _re.compile(
        r"(230 Login|drwx|[-r][-w][-x]|ftp>|\[\+\] anonymous|total \d+)",
        _re.IGNORECASE,
    )
    return bool(ok_pats.search(out))


def validate_root_privilege(output: str) -> bool:
    """Confirm root (Linux) or SYSTEM (Windows) privilege from shell output."""
    out = output or ""
    linux_root = _re.compile(
        r"(uid=0\(root\)|euid=0|\broot\b.*\broot\b|#\s*$)",
        _re.IGNORECASE,
    )
    win_system = _re.compile(
        r"(NT AUTHORITY\\\\SYSTEM|User Name.*SYSTEM"
        r"|SeDebugPrivilege.*Enabled|BUILTIN\\\\Administrators)",
        _re.IGNORECASE,
    )
    return bool(linux_root.search(out) or win_system.search(out))


def validate_credential(output: str) -> bool:
    """Credential validity — at least one tool-agnostic success indicator."""
    ok_pats = _re.compile(
        r"(\[\+\].*valid|\[\+\].*success|230 Login|Authenticated"
        r"|Valid credentials|Password OK|Login successful"
        r"|\[SUCCESS\]|STATUS_SUCCESS)",
        _re.IGNORECASE,
    )
    fail_pats = _re.compile(
        r"(Invalid|incorrect|failed|denied|FAILED|BAD)",
        _re.IGNORECASE,
    )
    out = output or ""
    if ok_pats.search(out):
        return True
    # If only failure patterns found, definitively False; otherwise ambiguous=False
    return False


def validate_callback_delivery(output: str, expected_lhost: str = "") -> bool:
    """Payload callback reached the handler."""
    out = output or ""
    ok_pats = _re.compile(
        r"(session \d+ opened|Meterpreter session|Command shell session"
        r"|Sending stage|Payload Handler Started)",
        _re.IGNORECASE,
    )
    if not ok_pats.search(out):
        return False
    if expected_lhost and expected_lhost not in out:
        return False
    return True


# Dispatcher: map tool name -> validator function
_TOOL_VALIDATORS = {
    "msf_session":  validate_msf_session_open,
    "ssh":          validate_ssh_auth,
    "winrm":        validate_winrm_auth,
    "smb":          validate_smb_auth,
    "web_rce":      validate_web_rce,
    "sql":          validate_sql_query,
    "ftp":          validate_ftp_access,
    "root_priv":    validate_root_privilege,
    "credential":   validate_credential,
    "callback":     validate_callback_delivery,
}


def tool_validate(tool_name: str, output: str, **kwargs) -> bool:
    """Route output to the appropriate tool-specific validator.

    Args:
        tool_name: one of the keys in _TOOL_VALIDATORS
        output:    raw stdout/stderr from the tool
        **kwargs:  extra args forwarded to the specific validator (e.g. nonce=)
    Returns:
        True  = success confirmed by this tool's own criteria
        False = failure or inconclusive (do NOT upgrade exploit state)
    """
    fn = _TOOL_VALIDATORS.get(tool_name)
    if fn is None:
        return False
    try:
        return fn(output, **kwargs)
    except Exception:
        return False


# ── Command-level scope enforcement ───────────────────────────────────────────
# Extracts every destination host embedded in a command string and checks each
# against the scope allowlist.  Covers MSF option flags, URL host parts, and
# common tool argument patterns.

_MSF_HOST_FLAGS = _re.compile(
    r"(?:set\s+(?:RHOSTS?|LHOST|TARGET|SRVHOST)|"
    r"-H|-h|--host|--target|-t|RHOSTS?=|TARGET=)"
    r"\s+([\w.:-]+)",
    _re.IGNORECASE,
)
_URL_HOST_RE = _re.compile(
    r"https?://([\w.-]+(?::\d+)?)",
    _re.IGNORECASE,
)
_GENERIC_HOST_FLAG = _re.compile(
    r"(?:-H|-h|--host|--rhost|--target|-T)\s+([\w.:/+-]+)",
    _re.IGNORECASE,
)
_FTP_DEST   = _re.compile(r"(?:ftp|sftp)(?:-?cli)?\s+(?:[^@]+@)?([\w.-]+)", _re.IGNORECASE)
_SMB_DEST   = _re.compile(r"//([\w.:-]+)/", _re.IGNORECASE)
_PROXY_DEST = _re.compile(r"--proxy[=\s]+(?:socks[45]?://|http://)?([\w.:-]+)", _re.IGNORECASE)
_CIDR_ARG   = _re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")


def _strip_port(host: str) -> str:
    if host.startswith("["):  # IPv6 bracket notation
        return host.split("]")[0].lstrip("[")
    return host.split(":")[0] if ":" in host else host


def extract_command_destinations(command: str) -> List[str]:
    """Return every unique destination host found in *command*."""
    out = set()
    for pat in (_MSF_HOST_FLAGS, _URL_HOST_RE, _GENERIC_HOST_FLAG,
                _FTP_DEST, _SMB_DEST, _PROXY_DEST):
        for m in pat.finditer(command or ""):
            host = _strip_port(m.group(1).strip())
            if host:
                out.add(host)
    # CIDR arguments
    for m in _CIDR_ARG.finditer(command or ""):
        out.add(m.group(1))
    return list(out)


def check_command_scope(command: str, allowlist_str: Optional[str]) -> Optional[str]:
    """Return None if every destination in *command* is in scope, or a
    human-readable rejection reason if any destination is out of scope.

    Fail-closed: if allowlist_str is set and any extracted host fails
    is_target_in_scope(), the command is blocked.
    """
    if not allowlist_str or not allowlist_str.strip():
        return None  # no allowlist configured, unrestricted

    destinations = extract_command_destinations(command)
    for dest in destinations:
        if not is_target_in_scope(dest, allowlist_str):
            return f"Out-of-scope destination in command: {dest!r}"
    return None

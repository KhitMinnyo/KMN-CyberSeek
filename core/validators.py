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
import shlex
from typing import Optional, List

# --- Target format validation -------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_cidr(value: str) -> bool:
    """Return True if value is a valid IPv4/IPv6 CIDR network (e.g. 192.168.1.0/24).
    strict=False so host bits set (192.168.1.5/24) are still accepted."""
    if not isinstance(value, str) or "%" in value:
        return False
    try:
        ipaddress.ip_network(value.strip(), strict=False)
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
    if not value or len(value) > 253 or "%" in value:
        return False

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    if is_cidr(value):
        return True

    # A trailing dot is the DNS root, not a different authorization identity.
    hostname = value.rstrip(".") if value.endswith(".") else value
    if value.endswith("..") or re.fullmatch(r"[0-9.]+", hostname):
        return False
    return bool(_HOSTNAME_RE.fullmatch(hostname))


# --- Scope allowlisting ---------------------------------------------------------

def _scope_entries(allowlist_str: str) -> List[str]:
    entries = [entry.strip() for entry in allowlist_str.split(",")]
    for entry in entries:
        value = entry[2:] if entry.startswith("*.") else entry
        if not is_valid_target(value):
            raise ValueError("Invalid scope allowlist configuration")
        if entry.startswith("*."):
            if not _HOSTNAME_RE.fullmatch(value.rstrip(".")):
                raise ValueError("Scope wildcards require a DNS suffix")
            try:
                ipaddress.ip_address(value.rstrip("."))
            except ValueError:
                pass
            else:
                raise ValueError("Scope wildcards cannot match IP addresses")
    return entries


def is_target_in_scope(target: Optional[str], allowlist_str: Optional[str]) -> bool:
    """Check a target against an optional SCOPE_ALLOWLIST (comma-separated IPs,
    CIDR ranges, exact hostnames, or "*.suffix" wildcard hostnames).

    Empty/unset scope is unrestricted. This is lexical authorization, not DNS
    resolution or a network firewall. Invalid configured entries fail closed.
    """
    if not is_valid_target(target):
        return False
    target = target.strip()
    if not allowlist_str or not allowlist_str.strip():
        return True  # No allowlist configured -> unrestricted

    try:
        entries = _scope_entries(allowlist_str)
    except ValueError:
        return False

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

    target_lower = target.lower().rstrip(".")
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

        # IP literals must never fall through into DNS wildcard matching.
        if target_ip is not None or target_net is not None:
            continue
        entry_lower = entry.lower().rstrip(".")
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

_AUTOMATION_DENY_PATTERNS = (
    (re.compile(r"\brm\s+-[a-z]*f", re.I), "recursive forced deletion"),
    (re.compile(r"\bdd\s+if=", re.I), "raw disk overwrite"),
    (re.compile(r"\b(?:mkfs|fdisk|parted)\b", re.I), "disk formatting/partitioning"),
    (re.compile(r"\b(?:shutdown|reboot|poweroff|halt)\b", re.I), "host shutdown"),
    (re.compile(r":\(\)\s*\{", re.I), "fork bomb"),
    (re.compile(r"\b(?:drop|truncate)\s+(?:table|database)", re.I), "database destruction"),
    (re.compile(r"\bdelete\s+from\b", re.I), "bulk database deletion"),
    (re.compile(r"\b(?:curl|wget)\b[^;&|\n]*\|\s*(?:bash|sh|python3?|perl|ruby)\b", re.I),
     "download-and-execute"),
)


def automation_capability_error(command: str) -> Optional[str]:
    """Return a capability-policy denial for destructive autonomous commands.

    Operator-approved commands retain the reviewed escape hatch; automated
    execution must not turn FULL_AUTO_MODE into unrestricted host control.
    """
    for pattern, label in _AUTOMATION_DENY_PATTERNS:
        if pattern.search(command or ""):
            return f"Automation capability denied: {label}"
    return None


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
        r"(NT AUTHORITY\\SYSTEM|User Name.*SYSTEM"
        r"|SeDebugPrivilege.*Enabled|BUILTIN\\Administrators)",
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
# Deliberately small grammars: an unrecognized option may load targets, change
# routing, execute code, follow redirects, or select a default remote service.
# Never infer safety merely from finding one authorized host in the text.
_LOCAL_ONLY = {
    "echo", "printf", "pwd", "ls", "cat", "head", "tail", "wc", "sort",
    "uniq", "cut", "tr", "id", "whoami", "uname", "date", "stat", "file",
    "strings", "grep", "egrep", "fgrep", "true", "false",
}
_TOOL_OPTIONS = {
    # (flags with no value, options with an ordinary non-destination value)
    "nmap": ({"-sV", "-sT", "-sS", "-sU", "-sC", "-sn", "-Pn", "-n", "-6", "-v", "-vv", "-O", "--osscan-guess", "--open", "--reason"},
             {"-p", "--top-ports", "--max-retries", "--host-timeout", "--scan-delay", "--max-rtt-timeout", "--script", "--script-timeout", "-oN", "-oX", "-oG", "-oA", "-T"}),
    "ping": ({"-4", "-6", "-n", "-q"}, {"-c", "-W", "-w", "-i", "-s", "-t"}),
    "ping6": ({"-n", "-q"}, {"-c", "-W", "-w", "-i", "-s"}),
    "traceroute": ({"-4", "-6", "-n", "-I", "-T"}, {"-m", "-q", "-w", "-p"}),
    "nc": ({"-4", "-6", "-n", "-v", "-z", "-u"}, {"-w", "-p"}),
    "ftp": ({"-n", "-v", "-i", "-p"}, set()),
    "curl": ({"-s", "-S", "-sS", "--silent", "--show-error", "-I", "--head", "-k", "--insecure", "-4", "-6", "--fail", "-f"},
             {"-o", "--output", "--max-time", "--connect-timeout", "-A", "--user-agent", "-H", "--header", "-X", "--request", "-d", "--data", "--data-raw"}),
    "wget": ({"-q", "--quiet", "-S", "--server-response", "--spider", "-4", "-6"},
             {"-O", "--output-document", "-T", "--timeout", "--tries", "--max-redirect"}),
    "smbclient": ({"-N", "-g"}, {"-U", "--user", "-W", "--workgroup", "-p", "--port"}),
    "mysql": ({"--batch", "--skip-column-names"}, {"-u", "--user", "-P", "--port"}),
    "redis-cli": ({"--raw", "--no-auth-warning"}, {"-p", "-a", "--user"}),
}

# These selectors are shipped by scanner.py/playbooks.py, not a general NSE
# expression/path allowlist. They assume a trusted installed NSE database and
# still require external egress policy; built-in scripts are not a firewall.
_NMAP_SCRIPT_SELECTORS = {"vuln", "vuln and not intrusive", "default"}
_NMAP_SCRIPT_NAMES = {
    "smb-protocols", "smb-security-mode", "ftp-anon", "ftp-bounce", "ftp-vuln*",
    "ssh2-enum-algos", "ssh-auth-methods", "mysql-empty-password", "mysql-info",
    "ajp-headers", "ajp-methods", "http-title", "rdp-ntlm-info",
    "rdp-enum-encryption", "pgsql-info", "rmi-dumpregistry", "jmx-info",
    "vnc-info", "vnc-title",
}
_NMAP_TIME_OPTIONS = {"--host-timeout", "--scan-delay", "--max-rtt-timeout", "--script-timeout"}


def _destination(value: str) -> str:
    """Parse one literal IP/CIDR, hostname, URL authority, or bracketed endpoint."""
    from urllib.parse import urlsplit

    if not value or any(c.isspace() for c in value) or any(c in value for c in "\\$`"):
        raise ValueError(f"Invalid or dynamic destination: {value!r}")
    if "://" in value or value.startswith("//"):
        parsed = urlsplit(value if "://" in value else "smb:" + value)
        if parsed.scheme.lower() not in {"http", "https", "ftp", "ftps", "smb", "socks4", "socks5", "socks5h"}:
            raise ValueError("Unsupported destination URL scheme")
        # Accessing port also validates malformed and out-of-range ports.
        port = parsed.port
        if port is not None and port == 0:
            raise ValueError("Invalid URL port")
        host = parsed.hostname
        if not host or not is_valid_target(host) or "/" in host:
            raise ValueError(f"Invalid URL destination: {value!r}")
        return host.lower().rstrip(".")
    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)\](?::([0-9]+))?", value)
        if not match or (match[2] and not 0 < int(match[2]) <= 65535):
            raise ValueError("Invalid bracketed endpoint")
        ipaddress.IPv6Address(match[1])
        return match[1]
    if is_valid_target(value):
        return value.lower().rstrip(".")
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if is_valid_target(host) and port.isdigit() and 0 < int(port) <= 65535:
            return host.lower().rstrip(".")
    raise ValueError(f"Invalid destination: {value!r}")


def _command_destinations(command: str) -> List[str]:
    from core.command_runner import _has_unquoted_shell_syntax

    if not command or not command.strip():
        raise ValueError("Empty command")
    if (_has_unquoted_shell_syntax(command) or "\n" in command or "\r" in command
            or "$" in command or "`" in command or "\x00" in command):
        raise ValueError("Shell composition or expansion cannot be scope-checked")
    argv = shlex.split(command, posix=True)
    executable, args = argv[0], argv[1:]
    binary = os.path.basename(executable)
    if executable != binary and os.path.dirname(executable) not in {
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/opt/homebrew/bin",
    }:
        raise ValueError("Executable path is outside trusted tool directories")
    if binary == "searchsploit":
        query_found = False
        for arg in args:
            if arg.startswith("-"):
                if arg not in {"--json", "-j", "--title", "-t", "--exact", "-e", "--strict", "-s", "--case", "-c"}:
                    raise ValueError("Only local SearchSploit query options are supported")
            elif arg.strip():
                query_found = True
        if not query_found:
            raise ValueError("SearchSploit requires a local query")
        return []
    if binary in _LOCAL_ONLY:
        if binary == "sort" and any(
            arg.startswith("--") and arg != "--"
            and "--compress-program".startswith(arg.partition("=")[0]) for arg in args
        ):
            raise ValueError("Local sort cannot launch an external compression program")
        return []
    if binary == "set" and len(args) == 2 and args[0].upper() in {"RHOST", "RHOSTS", "LHOST", "SRVHOST", "TARGET"}:
        return [_destination(args[1])]
    if binary not in _TOOL_OPTIONS:
        raise ValueError(f"Scope checking unsupported for command: {binary!r}")
    flags, values = _TOOL_OPTIONS[binary]
    destinations, positional = [], []
    i = 0
    options_done = False
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--" and not options_done:
            options_done = True
            continue
        if not options_done and arg.startswith("-"):
            option, sep, value = arg.partition("=")
            if option in flags and not sep:
                continue
            host_options = {
                "curl": {"--url", "--proxy", "-x"},
                "smbclient": {"-I", "--ip-address", "-L", "--list"},
                "mysql": {"-h", "--host"}, "redis-cli": {"-h"},
            }.get(binary, set())
            if option not in values | host_options:
                # Common attached nmap port/timing arguments are unambiguous.
                if binary == "nmap" and re.fullmatch(r"(?:-p(?:-|[0-9,\-]+)|-T[0-5])", arg):
                    continue
                raise ValueError(f"Unsupported scope-sensitive option: {arg!r}")
            if not sep:
                if i >= len(args):
                    raise ValueError(f"Missing option value: {option}")
                value = args[i]
                i += 1
            if not value or value.startswith("-"):
                raise ValueError(f"Invalid option value: {option}")
            if binary == "nmap":
                if option == "--script" and value not in _NMAP_SCRIPT_SELECTORS:
                    if any(name not in _NMAP_SCRIPT_NAMES for name in value.split(",")):
                        raise ValueError("Unsupported Nmap script selector; custom scripts and expressions are forbidden")
                if option in _NMAP_TIME_OPTIONS and not re.fullmatch(
                    r"(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:ms|s|m|h)?", value
                ):
                    raise ValueError(f"Nmap {option} requires a numeric time with optional ms/s/m/h suffix")
            if option in host_options:
                if binary == "curl" and option == "--url" and not value.lower().startswith(
                    ("http://", "https://", "ftp://", "ftps://")
                ):
                    raise ValueError("Explicit URL scheme required")
                destinations.append(_destination(value))
            if binary == "wget" and option == "--max-redirect" and value != "0":
                raise ValueError("Redirect following cannot be scope-checked")
            continue
        positional.append(arg)
    if binary in {"curl", "wget"}:
        for value in positional:
            if not value.lower().startswith(("http://", "https://", "ftp://", "ftps://")):
                raise ValueError("Explicit URL scheme required")
            # curl URL globbing expands into additional, unchecked hosts.
            authority = value.split("://", 1)[1].split("/", 1)[0]
            if any(c in authority for c in "{}*,"):
                raise ValueError("URL destination expansion is unsupported")
            destinations.append(_destination(value))
        if binary == "wget":
            # wget follows redirects by default, unlike curl.
            if "--max-redirect=0" not in args and not any(
                args[j:j + 2] == ["--max-redirect", "0"] for j in range(len(args))
            ):
                raise ValueError("Scoped wget requires --max-redirect=0")
    elif binary in {"nc", "ftp"}:
        if len(positional) not in {1, 2} or (len(positional) == 2 and not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", positional[1])):
            raise ValueError("Expected destination and optional numeric port")
        destinations.append(_destination(positional[0]))
    elif binary in {"mysql", "redis-cli"}:
        if positional or not destinations:
            raise ValueError("Explicit host required; command/query bodies are unsupported")
    else:
        if binary != "nmap" and len(positional) > 1:
            raise ValueError("Ambiguous positional destinations")
        destinations.extend(_destination(value) for value in positional)
    if not destinations:
        raise ValueError("No explicit destination found for network command")
    return sorted(set(destinations))


def extract_command_destinations(command: str) -> List[str]:
    """Extract supported literal destinations. Invalid/ambiguous syntax raises.

    Use check_command_scope() for authorization, never an empty-list fallback.
    """
    return _command_destinations(command) if command and command.strip() else []


def check_command_scope(command: str, allowlist_str: Optional[str]) -> Optional[str]:
    """Return None if every destination in *command* is in scope, or a
    human-readable rejection reason if any destination is out of scope.

    Configured scope rejects unknown/ambiguous syntax as well as out-of-scope
    hosts. Only explicitly classified local commands may have no destination.
    """
    if not allowlist_str or not allowlist_str.strip():
        return None  # no allowlist configured, unrestricted

    # Validate the entire configuration even for hostless commands.
    try:
        _scope_entries(allowlist_str)
        destinations = _command_destinations(command)
    except (ValueError, IndexError) as exc:
        return f"Cannot safely determine command destinations: {exc}"
    for dest in destinations:
        if not is_target_in_scope(dest, allowlist_str):
            return f"Out-of-scope destination in command: {dest!r}"
    return None

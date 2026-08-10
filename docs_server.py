#!/usr/bin/env python3
"""Standalone documentation server for KMN-CyberSeek.

Serves the full documentation as a self-contained HTML page on port 3500.
No Streamlit dependency — runs independently from start.sh.
"""

import http.server
import os
import socketserver

DOCS_PORT = int(os.environ.get("DOCS_PORT", 3500))


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _c(title: str, body: str, accent: str = "#4f8ef7") -> str:
    return (f'<div class="card" style="border-left-color:{accent}">'
            f'<div class="ct">{title}</div>'
            f'<div class="cb">{body}</div></div>')


def _s(text: str) -> str:
    return f'<div class="sh">{text}</div>'


def _note(text: str, cls: str = "ai") -> str:
    return f'<div class="alert {cls}">{text}</div>'


def _pre(text: str) -> str:
    return f'<pre>{text}</pre>'


def _exp(q: str, a: str) -> str:
    return (f'<details class="exp"><summary>{q}</summary>'
            f'<div class="exb">{a}</div></details>')


# ---------------------------------------------------------------------------
# Tab content
# ---------------------------------------------------------------------------

def _tab0() -> str:
    h = ""
    h += _s("Quick Start")
    h += _c("1. Run <code>./start.sh</code>", "Starts FastAPI (port 6000) and Streamlit (port 8501).", "#4caf50")
    h += _c("2. Settings &#8594; AI Configuration", "Connect Ollama or enter a DeepSeek API key.", "#4caf50")
    h += _c("3. Click New Session", "Enter a target IP or domain and confirm authorization.", "#4caf50")
    h += _c("4. Watch Session Timeline", "Phases progress automatically as the AI works.", "#4caf50")
    h += _c("5. Review results", "Check Vulnerabilities, AI Decisions, and Credentials tabs.", "#4caf50")
    h += _s("System Architecture")
    h += _pre(
        "Streamlit Frontend  (port 8501)  ←  Operator Dashboard\n"
        "         │\n"
        "         ▼\n"
        "FastAPI Backend  (port 6000)\n"
        "  Orchestrator │ Scanner │ AI Connector │ SQLite DB\n"
        "         │              │               │\n"
        "    AI Engine      Nmap/NSE        Shell Exec\n"
        "  (Ollama/API)   (Scanner)        (Kali env)"
    )
    h += _s("Attack Chain &#8212; Phase Order")
    h += _c("<code>osint</code>", "Passive intel: whois, dig, theHarvester, crt.sh, Google Dorks &#8212; domain targets only", "#7e57c2")
    h += _c("<code>reconnaissance</code>", "Active scanning: Nmap top-1000 ports with service/version detection", "#1976d2")
    h += _c("<code>enumeration</code>", "Subdomain, endpoint, user, and share enumeration", "#0288d1")
    h += _c("<code>vulnerability_analysis</code>", "CVE mapping, nuclei, nikto, sqlmap", "#00838f")
    h += _c("<code>exploitation</code>", "Exploit execution via Metasploit or standalone tools", "#f57c00")
    h += _c("<code>post_exploitation</code>", "Shell stabilisation, local data collection", "#e64a19")
    h += _c("<code>privilege_escalation</code>", "linpeas, sudo -l, SUID checks, kernel exploits", "#c62828")
    h += _c("<code>lateral_movement</code>", "Pivoting to adjacent hosts using found credentials", "#6a1b9a")
    h += _c("<code>credential_reuse</code>", "Credential spraying, pass-the-hash, Kerberoasting", "#2e7d32")
    h += _note(
        "Local IP targets (10.x, 192.168.x, 172.16&#8211;31.x): OSINT phase is automatically "
        "skipped &#8212; Google Dorks return nothing useful for private addresses."
    )
    return h


def _tab1() -> str:
    h = ""
    h += _s("Session Buttons")
    h += _c("&#9654;&#65039; Resume", "Continues AI analysis from current state &#8212; no re-scan. Safe on an already-running session (idempotent).", "#4caf50")
    h += _c("&#128260; Reset AI", "Keeps nmap <b>scan data</b>. Clears AI decisions, commands, vulnerabilities. Re-runs AI from existing scan. Use when AI went off-track.", "#1976d2")
    h += _c("&#128257; Full Rescan", "Clears everything &#8212; scan data + AI history. Runs nmap from scratch. Use when days have passed or target may have changed.", "#f57c00")
    h += _c("&#128465;&#65039; Delete", "Permanently removes the session and all its data. Cannot be undone.", "#c62828")
    h += _s("Session Tabs")
    h += _c("&#128202; Overview", "Session Timeline, controls, Strategic Layer AI planner with objective + progress %.", "#4f8ef7")
    h += _c("&#128269; Scan Results", "All discovered hosts, open ports, running services with version info.", "#4f8ef7")
    h += _c("&#128737;&#65039; Vulnerabilities", "CVEs and weaknesses &#8212; from scanner, threat intel cache, and AI analysis.", "#4f8ef7")
    h += _c("&#129302; AI Decisions", "Every AI reasoning step: what the AI was thinking, which command it chose and why.", "#4f8ef7")
    h += _c("&#9889; Commands", "Full command history with output. Pending approval queue shown when manual review is needed.", "#4f8ef7")
    h += _c("&#128193; Evidence", "Raw tool output saved as evidence: screenshots, file listings, service banners.", "#4f8ef7")
    h += _c("&#128273; Credentials", "Extracted credentials &#8212; auto-parsed from john, hashcat, hydra output.", "#4f8ef7")
    h += _s("Timeline &#8212; Status Icons")
    h += _c("&#9989; Done", "Stage completed &#8212; AI decisions exist for this phase.", "#455a64")
    h += _c("&#128260; Now", "Current active stage.", "#455a64")
    h += _c("&#9889; &#8212;", "Stage was skipped (AI jumped past it).", "#455a64")
    h += _c("&#9203; Next", "Not yet reached.", "#455a64")
    h += _s("Auto-Approve Explained")
    h += _c("OFF (default)", "All commands go to the pending queue for manual review before execution.", "#c62828")
    h += _c("ON", "All risk levels (LOW / MEDIUM / HIGH) execute automatically without waiting.", "#4caf50")
    h += _note(
        "Two safeguards always apply:<br>"
        "(1) Allowlist gate &#8212; dangerous commands are always blocked.<br>"
        "(2) Depth checkpoint &#8212; after 15 auto-commands, one manual approval is required."
    )
    return h


def _tab2() -> str:
    h = ""
    h += _s("Risk Classification")
    h += _c("&#129001; LOW &#8212; Read-only / passive", "No impact. Examples: <code>nmap</code>, <code>curl -I</code>, <code>whois</code>, <code>dig</code>. Auto-executes when auto-approve is ON.", "#4caf50")
    h += _c("&#128993; MEDIUM &#8212; Active / leaves traces", "Enumeration &#8212; traces but no damage. Examples: <code>nikto</code>, <code>gobuster</code>, <code>nuclei</code>. Auto-executes when auto-approve is ON.", "#f9a825")
    h += _c("&#128308; HIGH &#8212; Destructive / irreversible", "May crash services or exfiltrate data. Examples: <code>hydra</code>, <code>msfconsole</code>, <code>sqlmap --dump</code>. Requires manual approval.", "#c62828")
    h += _note("Risk level is determined by keyword + regex rules &#8212; not by the LLM. The AI cannot self-classify its command as LOW to bypass review.")
    h += _s("Strategic Layer (AI Planner)")
    h += _c("Runs every 5 commands", "Evaluates overall progress, updates the multi-step plan, writes a reflection, and declares objective complete when root/SYSTEM/Domain Admin is reached &#8212; halting the agentic loop.", "#7e57c2")
    h += _c("Progress % frozen?", "Progress updates only when the strategist runs (every 5 commands). Wait for the next batch of 5.", "#455a64")
    h += _s("AI Decisions &#8212; Notable Findings")
    h += _c("High-value keywords", "Commands whose output contains: <code>password</code>, <code>hash</code>, <code>CVE</code>, <code>shell</code>, <code>admin</code>, <code>root</code>, <code>credential</code>, <code>exploit</code>, <code>vulnerable</code> &#8212; shown at the top of AI Decisions tab.", "#00838f")
    h += _s("Command Console")
    h += _c("Manual command injection", "Enter arbitrary commands against the session target &#8212; outside the AI loop. Useful for running a specific tool the AI has not tried, or verifying a finding.", "#1976d2")
    h += _s("OSINT &#8212; Google Dorks")
    h += _pre(
        "site:<domain> filetype:pdf|xlsx|docx|pptx|sql|bak|env|config|log\n"
        "site:<domain> inurl:admin|login|portal|dashboard\n"
        'site:<domain> "index of" | "parent directory"\n'
        '"<domain>" ext:sql|bak|env|config|log\n'
        'site:<domain> intext:"password"|"api_key"|"secret"'
    )
    h += _note("OSINT / Google Dorks only run for domain targets. Private/local IPs (10.x, 192.168.x) skip OSINT automatically.")
    return h


def _tab3() -> str:
    h = ""
    h += _s("What is Threat Intel?")
    h += _c("Standalone research tool", "The Threat Intel page builds a local vulnerability knowledge base over time. Completely separate from live pentest sessions &#8212; never issues shell commands.", "#7e57c2")
    h += _s("How It Works")
    h += _c("1. Enter a search topic", "Software name, version, or CVE query &#8212; e.g. <code>Apache httpd 2.4.49</code>, <code>GlassFish 4.1</code>.", "#1976d2")
    h += _c("2. DuckDuckGo search", "Searches for <code>[topic] CVE vulnerability</code> and fetches up to 5 result pages.", "#1976d2")
    h += _c("3. AI extraction", "Each page&#39;s text is sent to the AI using an isolated prompt &#8212; separate from the pentest AI.", "#1976d2")
    h += _c("4. Structured storage", "CVE IDs, title, description, severity stored in SQLite <code>threat_intel_cache</code> with <code>verified=False</code>.", "#1976d2")
    h += _c("5. Auto cross-reference", "After every nmap scan, orchestrator cross-references service names against the cache. Matches are added to the Vulnerabilities tab.", "#1976d2")
    h += _note("All findings are unverified by design. Web pages can be wrong or outdated. Cross-check CVE IDs against NVD, Vulners, or CISA KEV before acting.", "aw")
    h += _s("Useful Search Topics")
    h += _c("<code>Apache httpd 2.4.49</code>", "Example finding: CVE-2021-41773 path traversal RCE", "#00838f")
    h += _c("<code>ProFTPD 1.3.5</code>", "Example finding: mod_copy unauthenticated RCE", "#00838f")
    h += _c("<code>OpenSSH 7.2p2</code>", "Example finding: Username enumeration CVE", "#00838f")
    h += _c("<code>GlassFish 4.1</code>", "Example finding: CVE-2017-1000028 unauthenticated RCE", "#00838f")
    h += _c("<code>Tomcat 7.0</code>", "Example finding: CVE-2020-1938 Ghostcat AJP RCE", "#00838f")
    return h


def _tab4() -> str:
    h = ""
    h += _s("What the AI Needs to Do Well")
    h += _c("1. Structured JSON output", "Every AI response must be valid JSON. A model that garbles this causes parse failures and halts the session.", "#1976d2")
    h += _c("2. Multi-step reasoning", "The model must plan a full attack chain without skipping phases after just 3 commands.", "#1976d2")
    h += _c("3. Security command vocabulary", "Knows nmap flags, CVE identifiers, Metasploit modules, GlassFish/Tomcat/SMB quirks.", "#1976d2")
    h += _s("DeepHat vs qwen2.5 &#8212; Which to Use?")
    h += _c("DeepHat V1-7B",
            "<b>Base:</b> Qwen2.5-Coder-7B cybersecurity fine-tune | <b>7.61B parameters</b><br>"
            "OK Security vocab &#8212; CVE IDs natively understood<br>"
            "Weaker reasoning &#8594; stage-skipping | JSON inconsistent &#8594; parse errors | NOT fully uncensored",
            "#f57c00")
    h += _c("qwen2.5:14b &#8212; Recommended",
            "<b>Base:</b> Qwen2.5 14B (Alibaba) | <b>14.7B parameters</b><br>"
            "2&#215; parameters &#8594; better JSON reliability | Better multi-step reasoning | Fewer stage-skip bugs<br>"
            "Not cybersecurity-specialized | Requires ~11 GB RAM",
            "#4caf50")
    h += _note("Use <code>qwen2.5:14b</code> as primary. The #1 cause of session failures is bad JSON output and premature stage advancement &#8212; both are reasoning problems a larger model solves.", "ao")
    h += _s("Hardware Recommendations")
    h += _c("M2 Mac Mini &#8212; 24 GB RAM (current)",
            "Primary: <code>qwen2.5:14b</code> &#8212; ~9 GB disk, ~11 GB RAM, context 32,768<br>"
            "Alt: <code>deepseek-r1:14b</code><br>"
            "Stretch: <code>qwen2.5:32b</code> &#8212; ~19 GB disk, ~21 GB RAM",
            "#1976d2")
    h += _c("M4 Pro &#8212; 64 GB RAM (upcoming)",
            "Primary: <code>qwen2.5:72b</code> &#8212; ~42 GB disk, ~45 GB RAM, context 131,072<br>"
            "Alt: <code>deepseek-r1:70b</code><br>"
            "Lighter: <code>qwen2.5:32b</code> &#8212; ~19 GB disk, context 65,536",
            "#7e57c2")
    h += _s("Quick Setup")
    h += (
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:10px 0">'
        '<div><div class="card" style="border-left-color:#1976d2">'
        '<div class="ct">M2 Mac Mini 24GB</div>'
        '<div class="cb">Model <code>qwen2.5:14b</code>, Context <code>32768</code></div>'
        '</div><pre><code>ollama pull qwen2.5:14b</code></pre></div>'
        '<div><div class="card" style="border-left-color:#7e57c2">'
        '<div class="ct">M4 Pro 64GB</div>'
        '<div class="cb">Model <code>qwen2.5:72b</code>, Context <code>65536</code></div>'
        '</div><pre><code>ollama pull qwen2.5:72b</code></pre></div></div>'
    )
    h += _s("Context Window &#8212; Why It Matters")
    h += _c("What happens when context overflows",
            "Local models have a fixed context window. When session history exceeds it, the model silently "
            "forgets old content &#8212; causing repeated commands, stage regression, or hallucinated progress.",
            "#f57c00")
    h += _c("Built-in mitigations",
            "1. Episode summaries &#8212; every N commands, old history is compressed and re-injected.<br>"
            "2. Configurable context window &#8212; Settings &#8594; AI Configuration &#8594; "
            "Context window controls Ollama&#39;s <code>num_ctx</code>.",
            "#4caf50")
    h += (
        '<table class="tbl"><tr><th>Model size</th><th>Safe context window</th></tr>'
        "<tr><td>7&#8211;8B</td><td>16,384</td></tr>"
        "<tr><td>13&#8211;14B</td><td>32,768</td></tr>"
        "<tr><td>32B</td><td>32,768&#8211;65,536</td></tr>"
        "<tr><td>70&#8211;72B</td><td>65,536&#8211;131,072</td></tr></table>"
    )
    return h


def _tab5() -> str:
    h = ""
    h += _s("Common Issues")
    h += _exp("Session status FAILED but terminal still active",
              "Asyncio tasks queued before failure finish running after status changed. Normal &#8212; backend drains queue then stops. Wait a few seconds, refresh, then use Reset AI.")
    h += _exp("&#39;AI response parsing error&#39; in command history",
              "AI returned invalid JSON. Session now halts cleanly on parse failure. If seen on an old session, do a Reset AI. Switching to qwen2.5:14b reduces parse failures.")
    h += _exp("All stages Done after only 5 commands",
              "Old bug: AI jumped to credential_reuse immediately. Fixed &#8212; stage gate prevents advancing more than 1 phase per AI decision. Do a Reset AI.")
    h += _exp("Progress % frozen at 5%",
              "Strategic Layer runs every 5 completed commands. Wait for next batch of 5, or do a Reset AI.")
    h += _exp("Resume button showing on active session",
              "Fixed &#8212; &#39;ready&#39; now shows Session Active instead. Update and restart the frontend.")
    h += _exp("Pending commands piling up",
              "Two causes: (1) auto_approve OFF &#8212; commands go to queue by design. (2) Max auto-depth reached (15 commands) &#8212; one manual approval resets the counter.")
    h += _exp("AI keeps suggesting the same command repeatedly",
              "Context overflow &#8212; model forgot it ran that command. Increase context window in Settings (try 32768 or 65536). Switch to a larger model (14B+).")
    h += _exp("Session History shows &#39;No sessions recorded yet&#39;",
              "Fixed &#8212; caused by FastAPI route order bug. Update to latest and restart backend.")
    h += _exp("OSINT running on local/private IP targets",
              "Fixed &#8212; private IPs (10.x, 192.168.x, 172.16&#8211;31.x, localhost) now skip OSINT automatically.")
    h += _exp("Backend not starting / port conflict",
              "start.sh auto-detects port conflicts and finds the next free port. Set BACKEND_PORT / FRONTEND_PORT in .env to override.")
    h += _s("Port Configuration")
    h += _pre("# .env\nBACKEND_PORT=6000    # FastAPI backend\nFRONTEND_PORT=8501   # Streamlit frontend\nDOCS_PORT=3500       # Documentation server")
    h += _s("API Reference &#8212; Key Endpoints")
    h += (
        '<table class="tbl">'
        "<tr><th>Method</th><th>Endpoint</th><th>Description</th></tr>"
        "<tr><td>POST</td><td>/api/sessions</td><td>Create new session</td></tr>"
        "<tr><td>GET</td><td>/api/sessions/history</td><td>List all sessions</td></tr>"
        "<tr><td>POST</td><td>/api/sessions/{id}/resume</td><td>Resume AI (idempotent)</td></tr>"
        "<tr><td>POST</td><td>/api/sessions/{id}/restart</td><td>Reset AI, keep scan data</td></tr>"
        "<tr><td>POST</td><td>/api/sessions/{id}/rescan</td><td>Full rescan &#8212; clear all, re-run nmap</td></tr>"
        "<tr><td>POST</td><td>/api/sessions/{id}/approve/{cmd_id}</td><td>Approve pending command</td></tr>"
        "<tr><td>DELETE</td><td>/api/sessions/{id}</td><td>Delete session</td></tr>"
        "<tr><td>GET</td><td>/api/stats</td><td>Dashboard stats</td></tr>"
        "</table>"
    )
    return h


# ---------------------------------------------------------------------------
# Full HTML assembly
# ---------------------------------------------------------------------------

_CSS = (
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#0e1117;color:#e8eaf6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
    "padding:24px 32px;font-size:14px;line-height:1.5;max-width:1100px;margin:0 auto}"
    "h1{color:#e8eaf6;font-size:1.6rem;margin-bottom:22px}"
    ".tabs{display:flex;gap:4px;margin-bottom:20px;flex-wrap:wrap}"
    ".tb{background:#1e2530;color:#90caf9;border:1px solid #2a3040;padding:8px 14px;"
    "border-radius:6px;cursor:pointer;font-size:.85rem;transition:all .15s}"
    ".tb.ta{background:#4f8ef7;color:#fff;border-color:#4f8ef7}"
    ".card{background:#1e2530;border-left:4px solid #4f8ef7;padding:14px 18px;border-radius:6px;margin:8px 0}"
    ".ct{color:#e8eaf6;font-weight:600;font-size:1rem;margin-bottom:5px}"
    ".cb{color:#b0bec5;line-height:1.7}"
    ".sh{color:#90caf9;font-size:1.1rem;font-weight:700;margin:22px 0 8px;padding-bottom:4px;border-bottom:1px solid #2a3040}"
    ".alert{padding:12px 16px;border-radius:6px;margin:10px 0;line-height:1.6}"
    ".ai{background:#1a2744;border:1px solid #2196f3;color:#90caf9}"
    ".aw{background:#2d1f00;border:1px solid #f57c00;color:#ffb74d}"
    ".ao{background:#1a2d1a;border:1px solid #4caf50;color:#81c784}"
    "code{background:#2a3040;padding:2px 5px;border-radius:3px;font-family:monospace;font-size:.88em}"
    "pre{background:#1e2530;border:1px solid #2a3040;padding:12px;border-radius:6px;"
    "overflow-x:auto;margin:10px 0;font-size:.83rem;color:#b0bec5;white-space:pre}"
    "details.exp{border:1px solid #2a3040;border-radius:6px;margin:6px 0;overflow:hidden}"
    "details.exp summary{background:#1e2530;padding:12px 16px;cursor:pointer;color:#90caf9;"
    "list-style:none;user-select:none}"
    "details.exp summary::-webkit-details-marker{display:none}"
    "details.exp summary::after{content:' ▼';font-size:.75rem;float:right;opacity:.7}"
    "details[open].exp summary::after{content:' ▲'}"
    ".exb{padding:14px 16px;background:#141920;color:#b0bec5;line-height:1.7}"
    ".tbl{width:100%;border-collapse:collapse;margin:12px 0;font-size:.85rem}"
    ".tbl th{background:#1e2530;color:#90caf9;padding:9px 12px;text-align:left;border:1px solid #2a3040}"
    ".tbl td{padding:8px 12px;border:1px solid #2a3040;color:#b0bec5}"
    ".tbl tr:nth-child(even) td{background:#141920}"
    "</style>"
)

_JS = (
    "<script>"
    "function sT(n){"
    "var ps=document.querySelectorAll('.tp');"
    "var bs=document.querySelectorAll('.tb');"
    "for(var i=0;i<ps.length;i++){ps[i].style.display=i===n?'block':'none';}"
    "for(var i=0;i<bs.length;i++){bs[i].className=i===n?'tb ta':'tb';}"
    "}"
    "</script>"
)

_TABS_CONTENT = [_tab0, _tab1, _tab2, _tab3, _tab4, _tab5]
_TAB_LABELS = [
    "&#128640; Getting Started",
    "&#128203; Session Guide",
    "&#129302; AI &amp; Commands",
    "&#128376;&#65039; Threat Intel",
    "&#129504; Ollama Models",
    "&#128295; Troubleshooting",
]


def _build_html() -> str:
    buttons = "".join(
        f'<button class="tb{" ta" if i == 0 else ""}" onclick="sT({i})">{label}</button>'
        for i, label in enumerate(_TAB_LABELS)
    )
    panels = "".join(
        f'<div class="tp" style="display:{"block" if i == 0 else "none"}">{fn()}</div>'
        for i, fn in enumerate(_TABS_CONTENT)
    )
    return (
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>KMN-CyberSeek Documentation</title>"
        + _CSS
        + "</head><body>"
        "<h1>&#128218; KMN-CyberSeek Documentation</h1>"
        '<div class="tabs">' + buttons + "</div>"
        + panels
        + _JS
        + "</body></html>"
    )


# Build once at import time.
_PAGE = _build_html()


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = _PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:  # type: ignore[override]
        pass  # suppress per-request logs


class _ReuseServer(socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    with _ReuseServer(("", DOCS_PORT), _Handler) as httpd:
        print(f"Docs server listening on http://0.0.0.0:{DOCS_PORT}")
        httpd.serve_forever()

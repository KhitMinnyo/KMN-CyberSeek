#!/usr/bin/env python3
"""Standalone English documentation server for KMN-CyberSeek."""

import http.server
import html
import os
import socketserver

DOCS_PORT = int(os.environ.get("DOCS_PORT", "3500"))


def card(title: str, body: str, accent: str = "#4f8ef7") -> str:
    return (
        f'<div class="card" style="border-left-color:{accent}">'
        f'<div class="ct">{title}</div><div class="cb">{body}</div></div>'
    )


def section(title: str) -> str:
    return f'<div class="sh">{title}</div>'


def alert(text: str, cls: str = "info") -> str:
    return f'<div class="alert {cls}">{text}</div>'


def pre(text: str) -> str:
    return f"<pre>{html.escape(text)}</pre>"


def tab_getting_started() -> str:
    return (
        section("Quick Start")
        + card("1. Start the application", "Run <code>./start.sh</code>.", "#4caf50")
        + card(
            "2. Configure AI",
            "Open Settings and configure local Ollama or the DeepSeek API.",
            "#4caf50",
        )
        + card(
            "3. Create a session",
            "Enter a target, confirm authorization, and define the engagement objective.",
            "#4caf50",
        )
        + card(
            "4. Review execution",
            "Follow the timeline, pending approvals, findings, evidence, and durable jobs.",
            "#4caf50",
        )
        + section("Architecture")
        + pre(
            "Streamlit Frontend (8501)\n"
            "        |\n"
            "FastAPI Backend (6000)\n"
            "        |\n"
            "Orchestrator | Scanner | AI Connector | SQLite\n"
            "        |\n"
            "Nmap/NSE | Playbooks | Job/Event Store | Evidence"
        )
        + section("Engagement Phases")
        + card("OSINT", "Passive intelligence for public domains and hosts.", "#7e57c2")
        + card("Reconnaissance", "Network discovery and service/version detection.", "#1976d2")
        + card("Enumeration", "Service-specific playbooks, endpoints, users, shares, and applications.", "#0288d1")
        + card("Vulnerability Analysis", "NSE checks, NVD, ExploitDB, Vulners, KEV, and EPSS enrichment.", "#00838f")
        + card("Exploitation", "Evidence-driven exploit attempts subject to execution policy and approval.", "#f57c00")
        + card("Post-Exploitation", "Identity, system, credential, defense, network, and loot checks after a confirmed foothold.", "#e64a19")
        + card("Privilege Escalation", "Local privilege escalation methodology after access is proven.", "#c62828")
        + card("Lateral Movement", "Scoped movement based on discovered services and validated credentials.", "#6a1b9a")
        + card("Credential Reuse", "Controlled reuse checks against other in-scope services.", "#2e7d32")
        + alert(
            "Only test systems you own or have explicit written permission to test. "
            "Use full-auto and brute-force features only in isolated, authorized environments.",
            "warning",
        )
    )


def tab_sessions() -> str:
    return (
        section("Session Controls")
        + card("Resume", "Continue from the durable session state without repeating completed work.", "#4caf50")
        + card("Reset AI", "Clear tactical AI state while preserving scan data.", "#1976d2")
        + card("Full Rescan", "Clear engagement data and start a new reconnaissance pass.", "#f57c00")
        + card("Session Archive", "Download a portable ZIP containing the report, event stream, jobs, and manifest.", "#00838f")
        + card("Delete", "Permanently delete session data after confirming the action.", "#c62828")
        + section("Durability")
        + card(
            "Event stream",
            "Lifecycle events record state transitions, command starts and finishes, job updates, and operator actions.",
        )
        + card(
            "Job records",
            "Background work records status, target, PID, timestamps, exit code, errors, and retry metadata.",
        )
        + card(
            "Asset graph",
            "Targets, hosts, services, web applications, subdomains, and findings are linked for traceable reporting.",
        )
        + card(
            "Recovery",
            "Interrupted active sessions are restored from SQLite and resumed after the backend event loop starts.",
        )
        + section("Session APIs")
        + pre(
            "GET  /api/sessions/{id}/events\n"
            "GET  /api/sessions/{id}/jobs\n"
            "GET  /api/sessions/{id}/archive\n"
            "POST /api/sessions/{id}/resume"
        )
    )


def tab_ai() -> str:
    return (
        section("Execution Policy")
        + card(
            "Single gateway",
            "API, AI, playbook, and manual execution paths pass the same backend policy gate.",
            "#4caf50",
        )
        + card(
            "Automated execution",
            "Automated commands require authorization, non-interactive safety, and the binary allowlist.",
            "#1976d2",
        )
        + card(
            "Operator approval",
            "Explicitly approved commands use the reviewed manual trust boundary and remain subject to session safety checks.",
            "#f57c00",
        )
        + card(
            "Full-auto mode",
            "Full-auto skips approval prompts but never bypasses the execution gateway or automated binary policy.",
            "#c62828",
        )
        + section("AI Providers")
        + card("Ollama", "Local inference with context-window-aware prompts and an offline lexical memory fallback.")
        + card("DeepSeek API", "Remote inference with structured JSON responses and deterministic repair retries.")
        + card("Strategist", "Maintains objective progress, plan steps, reflections, and completion checks.")
        + card("Verifier", "Reviews high-risk automated decisions before execution; invalid verifier results fail closed.")
        + section("Coverage Engine")
        + alert(
            "Deterministic playbook steps are rendered and dispatched by the framework. "
            "AI remains responsible for context-dependent exploratory steps.",
            "success",
        )
        + pre(
            "COVERAGE_ENGINE=true\n"
            "VULN_SCAN_CONCURRENCY=4\n"
            "MAX_COMMANDS_NO_PROGRESS=60\n"
            "MAX_AUTO_PIVOTS=12"
        )
    )


def tab_threat_intel() -> str:
    return (
        section("Threat Intelligence")
        + card(
            "Vulnerability enrichment",
            "NVD, ExploitDB, Vulners, CISA KEV, and FIRST EPSS enrich discovered services and rank practical candidates.",
            "#7e57c2",
        )
        + card(
            "Research cache",
            "Open-web research is stored as unverified reference data and is never treated as proof by itself.",
            "#1976d2",
        )
        + card(
            "Finding status",
            "NVD and search results remain potential until validated; host-side evidence can promote a finding.",
            "#00838f",
        )
        + alert(
            "Always cross-check external research against authoritative sources and target evidence before acting.",
            "warning",
        )
        + section("Recommended Metrics")
        + pre(
            "Time to first valid finding\n"
            "Time to first confirmed finding\n"
            "Confirmed findings per 100 commands\n"
            "False-positive rate\n"
            "Service coverage percentage\n"
            "Session recovery success rate"
        )
    )


def tab_operations() -> str:
    return (
        section("Operational Configuration")
        + card("Callback routing", "Use local routing for labs, an explicit public endpoint, ngrok, or a manually configured tunnel. Public targets must not receive a private workstation callback address.")
        + card("Parallel scanning", "Independent per-port NSE and local ExploitDB lookups run in bounded batches. State-dependent exploitation remains ordered.")
        + card("Timeouts", "Set SCAN_TIMEOUT, VULN_PORT_TIMEOUT, ENUM_COMMAND_TIMEOUT, COMMAND_TIMEOUT, and WATCHDOG settings for the lab environment.")
        + card("Retention", "Use session archives for long-term storage. Keep databases, logs, reports, and credential-bearing artifacts access-controlled.")
        + section("Useful Commands")
        + pre(
            "./start.sh\n"
            "pytest -q\n"
            "python benchmarks/score.py report.md --json\n"
            "python3 -m compileall -q core ai main.py frontend.py"
        )
        + alert(
            "This software is for authorized security testing and education only. "
            "The operator is responsible for scope, legality, and impact control.",
            "warning",
        )
    )


CSS = """
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0e1117;color:#e8eaf6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:24px 32px;font-size:14px;line-height:1.5;max-width:1100px;margin:0 auto}
h1{color:#e8eaf6;font-size:1.6rem}.hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px}
.tabs{display:flex;gap:4px;margin-bottom:20px;flex-wrap:wrap}.tb{background:#1e2530;color:#90caf9;border:1px solid #2a3040;padding:8px 14px;border-radius:6px;cursor:pointer;font-size:.85rem}.tb.ta{background:#4f8ef7;color:#fff}
.card{background:#1e2530;border-left:4px solid #4f8ef7;padding:14px 18px;border-radius:6px;margin:8px 0}.ct{color:#e8eaf6;font-weight:600;font-size:1rem;margin-bottom:5px}.cb{color:#b0bec5;line-height:1.7}.sh{color:#90caf9;font-size:1.1rem;font-weight:700;margin:22px 0 8px;padding-bottom:4px;border-bottom:1px solid #2a3040}
.alert{padding:12px 16px;border-radius:6px;margin:10px 0;line-height:1.6}.info{background:#1a2744;border:1px solid #2196f3;color:#90caf9}.warning{background:#2d1f00;border:1px solid #f57c00;color:#ffb74d}.success{background:#1a2d1a;border:1px solid #4caf50;color:#81c784}
code{background:#2a3040;padding:2px 5px;border-radius:3px;font-family:monospace;font-size:.88em}pre{background:#1e2530;border:1px solid #2a3040;padding:12px;border-radius:6px;overflow-x:auto;margin:10px 0;font-size:.83rem;color:#b0bec5;white-space:pre}
</style>
"""

TABS = [
    ("Getting Started", tab_getting_started),
    ("Sessions", tab_sessions),
    ("AI and Commands", tab_ai),
    ("Threat Intel", tab_threat_intel),
    ("Operations", tab_operations),
]


def build_html() -> str:
    buttons = "".join(
        f'<button class="tb{" ta" if i == 0 else ""}" onclick="showTab({i})">{title}</button>'
        for i, (title, _) in enumerate(TABS)
    )
    panels = "".join(
        f'<div class="panel" style="display:{"block" if i == 0 else "none"}">{fn()}</div>'
        for i, (_, fn) in enumerate(TABS)
    )
    return (
        "<!doctype html><html lang='en'><head>"
        "<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>KMN-CyberSeek Documentation</title>"
        + CSS
        + "</head><body>"
        "<div class='hdr'><h1>KMN-CyberSeek Documentation</h1></div>"
        f"<div class='tabs'>{buttons}</div>{panels}"
        "<script>function showTab(n){const p=document.querySelectorAll('.panel');const b=document.querySelectorAll('.tb');p.forEach((x,i)=>x.style.display=i===n?'block':'none');b.forEach((x,i)=>x.className=i===n?'tb ta':'tb');}</script>"
        "</body></html>"
    )


PAGE = build_html().encode("utf-8")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, fmt: str, *args) -> None:
        return


class ReuseServer(socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    with ReuseServer(("", DOCS_PORT), Handler) as server:
        print(f"Documentation server listening on http://0.0.0.0:{DOCS_PORT}")
        server.serve_forever()

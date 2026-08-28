# KMN-CyberSeek

![Version](https://img.shields.io/badge/Version-2.6.0-brightgreen)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

AI-driven autonomous penetration testing framework. Executes a full offensive engagement pipeline — OSINT → exploitation — using an LLM (DeepSeek API or local Ollama) with human-in-the-loop approval for high-risk actions.

**Repository:** [https://github.com/KhitMinnyo/KMN-CyberSeek](https://github.com/KhitMinnyo/KMN-CyberSeek)

---

## Recommended OS

**Kali Linux** (all pentest tools pre-installed). Any Debian/Ubuntu-based distro with the standard security toolchain also works. macOS and plain Windows are not recommended.

---

## Architecture

```
Streamlit Frontend  (port 8501)
         │
FastAPI Backend     (port 6000)
   Orchestrator │ Scanner │ AI Connector │ SQLite DB
         │               │               │
   AI Engine         Nmap/NSE        Shell Exec
  DeepSeek/Ollama   VulnScripts      (Kali env)
```

---

## Installation

**Prerequisites:** Python 3.8+, Nmap (`sudo apt install nmap`), Ollama or DeepSeek API key.

```bash
git clone https://github.com/KhitMinnyo/KMN-CyberSeek.git
cd KMN-CyberSeek
./start.sh
```

`start.sh` creates the venv, installs dependencies, resolves port conflicts, and launches both services.

---

## Quick Start

1. Run `./start.sh`
2. Open `http://localhost:8501`
3. **Settings → AI Configuration** — connect Ollama or DeepSeek API key
4. **New Session** — enter target IP / domain and confirm authorization
5. Watch the session timeline advance through engagement phases
6. Review **AI Decisions** — approve or let auto-approve handle it
7. Monitor **Scan Results**, **Vulnerabilities**, **Credentials** as findings accumulate

---

## Configuration

### AI — Ollama (local or remote)

```env
AI_PROVIDER=local
OLLAMA_URL=http://192.168.1.50:11434
OLLAMA_MODEL=deepseek-r1:8b
OLLAMA_CONTEXT_WINDOW=8192
```

Remote Ollama host: `OLLAMA_HOST=0.0.0.0 ollama serve`

### AI — DeepSeek API

```env
AI_PROVIDER=api
DEEPSEEK_API_KEY=sk-...
DEEPSEEK_MODEL=deepseek-chat
```

### Ports

```env
BACKEND_PORT=6000
FRONTEND_PORT=8501
```

### Security

```env
API_AUTH_TOKEN=          # auto-generated on first run
BACKEND_HOST=127.0.0.1
REQUIRE_APPROVAL_HIGH_RISK=true
APPROVAL_TIMEOUT_MINUTES=15
SCOPE_ALLOWLIST=10.0.0.0/8,lab.local
```

### Full Auto Mode

```env
FULL_AUTO_MODE=false   # true = no approval prompts — isolated labs only
# Automated execution policy and the binary allowlist remain active in full-auto mode.
```

### Advanced tuning (optional)

All have sensible defaults; set only if needed.

# AI reply budget + determinism (DeepSeek API / Ollama)
AI_MAX_TOKENS=4096        # cap on a single AI reply; too small truncates the JSON
TACTICAL_TEMPERATURE=0.2  # low = fewer hallucinated flags/CVEs for command choice

# Reverse-shell callback routing — a shell only works if the TARGET can reach your
# listener. On a LAN lab the local IP works; a real internet target behind NAT needs
# a reachable callback (public IP, ngrok tunnel, or a reverse-SSH endpoint).
CALLBACK_MODE=auto        # auto | local | public | ngrok | manual
EXPLOIT_LHOST=            # explicit callback host (VPS public IP / tunnel endpoint)
EXPLOIT_LPORT=4444        # callback + local listener port
EXPLOIT_PAYLOAD=          # default: guessed from target OS
NGROK_AUTHTOKEN=          # required for CALLBACK_MODE=ngrok

# CVE enrichment + exploitability ranking.
NVD_API_KEY=             # https://nvd.nist.gov/developers/request-an-api-key
NVD_MIN_INTERVAL=6.5     # seconds between NVD calls when no key is set
MSF_CVE_RESOLVE=true     # resolve CVE -> Metasploit module via local msfconsole
MSF_CVE_RESOLVE_LIMIT=3  # how many top-priority CVEs to resolve per pass

# Scan / command timeouts (seconds)
SCAN_TIMEOUT=300
VULN_SCAN_TIMEOUT=120
VULN_SCAN_CONCURRENCY=4  # bounded parallel per-port NSE scans
COMMAND_TIMEOUT=600

# Agentic-loop safety
MAX_AUTO_PIVOTS=12       # auto-pivots before pausing for manual review
MAX_EMPTY_RETRIES=3      # retries when the model returns no command
WATCHDOG_STALL_SECONDS=  # default: COMMAND_TIMEOUT + 180 (stuck-session revival)

# OSINT stage hold (public domain/host targets) — stops OSINT being skipped after
# one turn. Advances once enough OSINT tools have run, or the turn cap is hit.
OSINT_MIN_ACTIONS=3      # distinct OSINT tools before leaving the OSINT stage
OSINT_MAX_TURNS=6        # hard cap so a low-OSINT target still advances

# Coverage engine — methodology-driven per-service playbooks, known-exploit hints,
# coverage-derived progress. ON by default; toggle live in Settings → Engine Features
# (no .env editing needed). Target-agnostic.
COVERAGE_ENGINE=true

# Decoupled brute-force worker — background credential brute-force on discovered
# auth services (SSH/FTP/RDP/MySQL/SMB/WinRM). Explicit opt-in; toggle in Settings.
BRUTEFORCE_ENABLED=false   # explicit opt-in; may trigger account lockouts
BRUTEFORCE_TIER=default            # default | rockyou | full
BRUTEFORCE_MAX_SECONDS_PER_SERVICE=600
BRUTEFORCE_CONCURRENCY=2
```

> **Tip:** Coverage Engine, Brute-force, and Full-Auto mode can be toggled at
> runtime from **Settings → Engine Features** — changes apply immediately and are
> saved to `.env` automatically, so end users never need to edit files.

---

## Further Reading

- [Features & Architecture Detail](features.md)
- [Changelog](change_log.md)

## Session Retention

Sessions persist their lifecycle events, background jobs, scan state, findings,
and asset relationships in SQLite. The dashboard can export a portable session
archive containing the report, event timeline, job records, and manifest:

```text
GET /api/sessions/{session_id}/archive
GET /api/sessions/{session_id}/events
GET /api/sessions/{session_id}/jobs
POST /api/sessions/{session_id}/cancel
```

Independent NSE and ExploitDB lookups use bounded concurrency. State-dependent
exploitation and post-exploitation actions remain ordered. Public targets do not
receive a private workstation callback address unless a reachable callback mode
or explicit public endpoint is configured.

---

## Disclaimer

**For authorised security testing and educational purposes only.**

Only use against systems you own or have explicit written permission to test. The developers assume no liability for misuse or damage. `FULL_AUTO_MODE=true` executes destructive commands without confirmation — isolated lab environments only.

---

## License

MIT — see [LICENSE](LICENSE).

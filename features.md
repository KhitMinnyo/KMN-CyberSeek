# KMN-CyberSeek — Features & Architecture

## Engagement Phases (Attack Chain)

Each session follows this ordered pipeline:

| Phase | What happens |
|-------|-------------|
| `osint` | Passive intelligence: `whois`, `dig`, `theHarvester`, `crt.sh`, Google Dorks |
| `reconnaissance` | Active scanning: Nmap top-1000 ports with service detection |
| `enumeration` | Subdomain, endpoint, and user enumeration |
| `vulnerability_analysis` | Per-port NSE vuln scripts + CVE lookup (NVD, searchsploit, Vulners) |
| `exploitation` | Exploit execution via Metasploit or standalone tools |
| `post_exploitation` | Shell stabilisation, data collection |
| `privilege_escalation` | Local privesc (`linpeas`, `sudo -l`, SUID checks) |
| `lateral_movement` | Pivoting to adjacent systems |
| `credential_reuse` | Credential spraying, pass-the-hash, Kerberoasting |

---

## Key Features

### Plan-Act-Observe-Reflect Loop

Every AI cycle runs two separate passes:

1. **Tactical engine** — selects the next command based on current scan data, service state, and session memory.
2. **Strategist (AI Planner)** — separately evaluates overall objective progress, updates the multi-step plan, and writes a reflection. Visible on the **Strategic Layer** panel in the dashboard.

### Risk Classification

Every AI-suggested command is classified before execution via deterministic keyword + regex rules — not LLM output — so it cannot be bypassed via prompt injection.

| Risk Level | Meaning | Auto-execute? |
|-----------|---------|--------------|
| **LOW** | Read-only / passive. Examples: `nmap`, `curl -I`, `whois` | ✅ Yes (if `auto_approve=True`) |
| **MEDIUM** | Active interaction, leaves traces. Examples: `nikto`, `gobuster`, `sqlmap --dbs` | ✅ Yes (if `auto_approve=True`) |
| **HIGH** | Destructive or irreversible. Examples: `hydra`, `msfconsole exploit`, `hashcat` | ❌ Always requires manual approval |

### True Resume (Scan Dedup)

Per-port nmap NSE scans and per-service CVE lookups (NVD, searchsploit) write completion markers to the `scan_results` table. On resume, already-completed work is skipped — only missing pieces run. Stage and status are persisted to DB at every transition so the session restarts at the correct point after a backend restart.

### Non-Interactive Execution (stdin closed)

Every command runs with `stdin=DEVNULL` — no interactive input is possible. The AI is instructed to embed all credentials directly in command flags. Known credentials are automatically injected into tool invocations (`smbclient -U 'user%pass'`, `enum4linux-ng -u/-p`, CrackMapExec, rpcclient, evil-winrm, mysql, impacket tools) before the subprocess launches.

### Deterministic Credential Reuse

When credentials are extracted from tool output (john, hashcat, hydra, impacket), the orchestrator automatically queues reuse attempts against every other discovered service — SSH, SMB, MySQL, WinRM — without relying on the LLM to remember. Hashes use pass-the-hash. Duplicates are suppressed. Secrets are `shlex.quote()`-escaped.

### Vulnerability Analysis Pipeline (True Resume)

`_run_vulnerability_analysis()` runs as a 5-step pipeline:

1. **Per-port Nmap NSE** — `--script "vuln and not intrusive" --script-timeout 20` per open port. Marker: `nmap_vuln_p{port}`.
2. **searchsploit** — local ExploitDB query per service+version. Zero network, no key. Marker: `ss_{svc}_{ver}`.
3. **NVD NIST API v2** — free public API, no key required. Rate-limited 0.7s between requests. Marker: `nvd_{svc}_{ver}`.
4. **Vulners** — optional, requires `VULNERS_API_KEY`. Marker: `vul_{svc}_{ver}`.
5. **Threat-intel cache cross-reference** — matches discovered services against `threat_intel` table.

Each step checks its completion marker first — resume skips already-done work.

### Threat Intel

The **Threat Intel** page has two sections:

**📊 Structured Vulnerability Database** — pulls from the `vulnerabilities` table across all sessions. Findings sourced from NVD (✅ verified), ExploitDB (searchsploit), and Nmap NSE vuln scripts. Filter by source, risk level, and service. Direct deep-links to NVD detail pages.

**🕸️ Open-Web Research Cache** — AI searches the web for a topic you specify, extracts CVE/vulnerability info, and stores results in `threat_intel_cache`. Unverified by design — treat as leads, cross-check against NVD/CISA KEV before acting.

Sessions automatically cross-reference their discovered services against the research cache and fire background research tasks for uncached services.

### OSINT — Google Dorks

Five passive Google Dork queries run during OSINT (no direct target contact):

```
site:<domain> filetype:pdf|xlsx|docx|sql|bak|env|config|log
site:<domain> inurl:admin|login|portal|dashboard
site:<domain> "index of" | "parent directory"
"<domain>" ext:sql|bak|env|config|log
site:<domain> intext:"password"|"api_key"|"secret"
```

For private/local IP targets, internet OSINT is automatically suppressed — only local-network tools run (`arp-scan`, `nbtscan`, `enum4linux`, etc.).

### Context-Aware Memory (Local Ollama)

| Context window | System prompt | Output budget |
|----------------|--------------|---------------|
| < 4 K tokens | Compact | 800 chars |
| 4 – 8 K | Compact | 2 000 chars |
| 8 – 16 K | Full | 5 000 chars |
| > 16 K | Full | 12 000 chars |

Every 5 commands, recent history is compressed into a structured episode summary to prevent context overflow.

### Scan Timeout

Nmap scans are capped at `SCAN_TIMEOUT` seconds (default 300). NSE vuln scans use a separate `VULN_SCAN_TIMEOUT` (default 120s) and per-port `VULN_PORT_TIMEOUT` (default 60s). Configure in `.env`:

```env
SCAN_TIMEOUT=300
VULN_SCAN_TIMEOUT=120
VULN_PORT_TIMEOUT=60
```

### Anti-Loop Guardrail

If the AI suggests a command already in the last 5 executed commands, auto-execution halts and a `loop_prevention` decision is logged. The UI shows a warning banner on the Overview tab. Manual intervention is required to continue.

---

## How It Works

### Tactical Engine Loop

```
start_reconnaissance()
  └─ Nmap top-1000 ports → parse services
       └─ _analyze_with_ai()
            ├─ Build context (scan data + episode summaries + hybrid memory)
            ├─ Tactical AI → suggested_command + risk_level + attack_phase
            ├─ Strategist AI → plan update + objective_progress + reflection
            ├─ VERIFIER AI → critique suggested command; may revise it
            ├─ requires_approval() gate
            │    ├─ HIGH → queue for manual approval
            │    └─ LOW/MEDIUM → execute_command()
            └─ loop via _process_command_output()
```

### Prompt-Injection Defence

All tool output is passed to the AI inside a `<<<TOOL_OUTPUT_START>>>` fence. The system prompt instructs the model to never follow instructions found inside tool output. The VERIFIER pass adds an independent second check.

---

## Dashboard Guide

### Session Tabs

| Tab | Contents |
|-----|---------|
| **Overview** | Host/service/command counts, session timeline, action-required banners, Strategic Layer |
| **Scan Results** | Discovered hosts and open ports with service versions |
| **Vulnerabilities** | CVE findings from Nmap NSE, searchsploit, NVD, and Vulners |
| **AI Decisions** | Every AI reasoning step: reasoning text, suggested command, risk level, Execute button |
| **Commands** | Full output of every executed command |
| **Evidence** | Structured evidence artefacts (domain recon, OSINT) |
| **Credentials** | Extracted username/secret pairs with source command |

### Session Timeline

| Icon | Meaning |
|------|---------|
| ✅ Done | Phase completed |
| 🔄 Now | Currently active |
| ⏳ Next | Queued, not yet reached |

### Strategic Layer

Displayed at the bottom of the Overview tab. Shows the Strategist AI's current view:

- **Objective** — engagement goal
- **Progress bar** — 0–100% estimated by the Strategist AI
- **Plan steps** — multi-step plan with per-step status
- **Latest Reflection** — Strategist notes from the last 3 cycles

All strategic state persists to DB and survives backend restarts.

---

## API Reference

All `/api/*` routes require the `X-API-Key` header (value from `API_AUTH_TOKEN` in `.env`).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth) |
| POST | `/api/start` | Start a new session |
| GET | `/api/sessions` | List active in-memory sessions |
| GET | `/api/sessions/{id}` | Full session report |
| DELETE | `/api/sessions/{id}` | Delete a session |
| POST | `/api/sessions/{id}/resume` | Resume a paused/interrupted session |
| POST | `/api/sessions/{id}/complete` | Mark session completed |
| GET | `/api/sessions/{id}/vulnerabilities` | Session vulnerability findings |
| GET | `/api/sessions/{id}/credentials` | Extracted credentials |
| GET | `/api/sessions/history` | All sessions including completed/failed |
| POST | `/api/execute` | Execute a command in a session |
| POST | `/api/approve` | Approve or deny a queued command |
| GET | `/api/vulnerabilities` | Global vulnerability DB (all sessions) |
| GET | `/api/ollama/models` | List available Ollama models |
| POST | `/api/settings/ai` | Update AI settings (live) |
| POST | `/api/settings/security` | Update security settings |
| GET | `/api/schedules` | List recurring scan schedules |
| POST | `/api/schedules` | Create a recurring scan |
| GET | `/api/stats` | Aggregate dashboard statistics |
| GET | `/api/threat-intel` | Cached threat-intel findings |
| POST | `/api/threat-intel/research` | Start a threat-intel research task |
| WS | `/api/ws?token=<API_AUTH_TOKEN>` | WebSocket for real-time updates |
| GET | `/api/docs` | Swagger UI |

---

## Project Structure

```
KMN-CyberSeek/
├── main.py                  # FastAPI backend — API routes, startup, scheduler
├── frontend.py              # Streamlit dashboard
├── start.sh                 # Startup script (port management, venv, services)
├── requirements.txt
├── .env.example
├── ai/
│   ├── connector.py         # AI connector — Ollama + DeepSeek API, memory, async
│   └── prompts.py           # System prompts (tactical, strategist, critique, compact)
├── core/
│   ├── orchestrator.py      # Session lifecycle, AI loop, credential reuse, state machine
│   ├── scanner.py           # Nmap wrapper — async subprocess, timeout, per-port NSE
│   ├── validators.py        # Target validation, scope allowlist, command allowlist
│   ├── report_generator.py  # DOCX / PDF report generation
│   ├── threat_intel.py      # Open-web threat intelligence research
│   ├── cve_lookup.py        # NVD API v2 + Vulners CVE enrichment + CISA KEV/EPSS ranking
│   ├── msf_resolver.py      # CVE → Metasploit module resolution (msfconsole search)
│   └── callback.py          # Reverse-shell callback routing (local/public/ngrok/reverse-SSH)
├── tests/
│   ├── run_tests.py
│   ├── _helpers.py
│   ├── test_credential_reuse.py
│   ├── test_memory_index.py
│   ├── test_safety_and_injection.py
│   ├── test_service_state.py
│   ├── test_strategist.py
│   └── test_validators.py
├── features.md              # Feature detail + API reference + project structure
├── change_log.md            # Version history
└── kmn_cyberseek.db         # SQLite database (auto-created on first run)
```

# Changelog

All notable changes are documented here. Follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) conventions.

---

## [2.1.3] — 2026-08-10

### Added
- **Auto-pivot on loop detection** (`core/orchestrator.py`) — when the anti-loop guardrail fires, the session no longer halts. Instead it automatically:
  1. Detects which attack vector was being looped on (`_detect_exhausted_target()` heuristic).
  2. Adds it to `session.exhausted_services` (persisted to DB, survives restarts).
  3. Logs an `auto_pivot` decision in the AI Decisions tab.
  4. Resets the auto-execution depth counter and re-invokes the AI with the exhausted vector injected as context — so the AI skips it and picks the next viable target.
- **`_detect_exhausted_target()`** — module-level heuristic that classifies recent commands into a named vector label (`smb`, `ftp`, `tomcat_8080`, `glassfish`, `ssh_bruteforce`, `web_dir_enum`, etc.).
- **`_auto_pivot()` method** — orchestrator method driving the pivot flow. Enforces a configurable `MAX_AUTO_PIVOTS` cap (default 6, via env var). When the cap is hit, logs a `pivot_limit_reached` decision and falls back to manual-wait.
- **`EXHAUSTED ATTACK VECTORS` block in AI context** — injected at the top of every `_analyze_with_ai()` call when `session.exhausted_services` is non-empty. AI receives a hard instruction not to suggest any command targeting an exhausted vector.
- **`exhausted_services` DB column** — added to `sessions` table via migration. Saved on every status transition. Restored on backend restart.
- **Frontend — exhausted services display** (Overview tab):
  - Auto-pivot in progress → `🔄 Auto-pivoting` info banner listing which vectors were exhausted.
  - Pivot limit reached → `🛑 Auto-pivot limit reached` error banner.
  - Always-visible caption listing all exhausted vectors when non-empty.
- **AI Decisions log badges** — context-specific badges on each decision row: `🔁 loop`, `🔄 pivot`, `🛑 pivot-limit`, `🛡 vetoed`.
- **`MAX_AUTO_PIVOTS` env var** — operator-configurable cap on consecutive auto-pivots before falling back to manual. Default `6`.

---

## [2.1.2] — 2026-08-10

### Added
- **Shell Session Manager** (`core/shell_manager.py`) — new module managing persistent Metasploit `multi/handler` processes.
  - `MsfHandlerProcess`: long-running `msfconsole` subprocess with `stdin=PIPE` for command injection and stdout monitoring for session-opened events.
  - `ShellSession`: tracks one active meterpreter/shell session with full command history (last 100 commands).
  - `ShellManager`: per-pentest-session container for all handlers.
  - Echo-marker output capture with `CMD_OUTPUT_TIMEOUT` (20 s).
  - `get_local_ip()` helper auto-detects LHOST suggestion.
  - `COMMON_PAYLOADS` list covers Windows/Linux x86/x64 meterpreter and shell payloads.

- **Shell API endpoints** (main.py):
  - `POST /api/sessions/{id}/shells/handler` — start listener
  - `DELETE /api/sessions/{id}/shells/handler/{handler_id}` — stop listener
  - `GET /api/sessions/{id}/shells/handlers` — list live + DB-persisted handlers
  - `GET /api/sessions/{id}/shells` — list active shell sessions
  - `POST /api/sessions/{id}/shells/{handler_id}/{msf_id}/exec` — run command in session
  - `GET /api/sessions/{id}/shells/{handler_id}/{msf_id}/history` — command history
  - `GET /api/shells/local-ip` — LHOST suggestion

- **🐚 Shells tab** (Active Sessions, tab 8):
  - Listener management: LHOST/LPORT/payload form with auto-detected LHOST and live msfvenom command preview.
  - Active session panel: quick-action buttons (whoami, sysinfo, ipconfig, ps), free-form command input, output display, command history.
  - Usage guide with meterpreter command reference.
  - Session count badge on tab label.

- **AI shell awareness** — active shell sessions injected into `_analyze_with_ai()` context so the AI uses existing shells for post-exploitation instead of re-exploiting.

- **DB tables**: `shell_handlers` (persists LHOST/LPORT/payload for restart), `shell_sessions_log` (session history).

- **Threat Intel page — Structured Vulnerability Database section** — pulls from `vulnerabilities` table across all sessions. Filterable by source (NVD, searchsploit, nmap-vuln-script, Vulners), risk level, and service substring. Source trust badges, CVSS scores, NVD/ExploitDB deep-links.

- **Global `/api/vulnerabilities` endpoint** — cross-session vulnerability query with optional filters.

- **Action-required banners on Overview tab** — orange banner with inline ✅/❌ approve/deny buttons for pending commands; yellow warning for loop-prevention decisions.

### Fixed
- **Anti-loop guardrail bypassed by flag/suffix variations** — previous exact-match check was evaded by appending `2>&1 | tee /tmp/...` or changing `-R` to `-r`. New `_norm_cmd()` strips output-redirection suffixes and normalises before comparison. Window expanded from last-5 to last-8 commands.
- **Stage stagnation not detected** — added second check: if 8+ consecutive AI decisions share the same `attack_phase` without advancing, auto-execution halts with a `loop_prevention` decision.
- **Reset AI left vulnerability analysis incomplete** — `restart_session` cleared `session.vulnerabilities` in memory but did not: (a) delete DB rows, (b) clear NSE/NVD/searchsploit completion markers, or (c) re-trigger `_run_vulnerability_analysis()`. All three now happen on Reset AI.
- **Vulnerabilities tab always empty after Reset AI** — consequence of the above; fixed by the same changes.
- **Vulnerabilities tab empty message mentioned Vulners only** — updated to accurately describe the free sources (Nmap NSE, NIST NVD, local searchsploit).
- **Session control buttons hidden while executing** — Reset AI, Delete, Full Rescan were inside the `else` branch of `if in_progress`, making them invisible during active execution. Now always visible; only Resume/Start are hidden while the AI loop is running (to prevent duplicate spawning).
- **README bloat** — removed Key Features, How It Works, API Reference, Project Structure from README.md. Extracted to `features.md`. Created `change_log.md`.

---

## [2.1.1] — 2026-08-10

### Added
- **True resume for vulnerability analysis** — per-port Nmap NSE scans and per-service CVE lookups (NVD, searchsploit, Vulners) write completion markers to `scan_results`. Resume skips already-done work.
- **NVD NIST API v2 integration** (`cve_lookup.py`) — free public CVE lookup, no API key required. Rate-limited at 0.7 s/request. Falls back silently on error.
- **searchsploit integration** — local ExploitDB query per discovered service+version. Zero network dependency.
- **Per-port Nmap NSE vuln scan** (`scanner.py`) — `--script "vuln and not intrusive" --script-timeout 20` per open port, with separate `VULN_PORT_TIMEOUT` env var.
- **stdin=DEVNULL on all subprocesses** — eliminates terminal hijacking by interactive tools (smbclient, enum4linux, etc.).
- **Credential injection** (`_inject_credentials`) — pre-execution rewrite embeds known credentials into tool flags for smbclient, enum4linux/ng, crackmapexec, rpcclient, evil-winrm, mysql, impacket tools.
- **AI context: discovered credentials** — actual `user:pass` pairs shown to AI with per-tool embedding examples.
- **Stage + status persistence** (`_save_session_status`) — `current_stage` and `status` written to DB at every transition. Sessions no longer revert to `reconnaissance` on restart.
- **Threat Intel — Structured DB section** — new top section on the Threat Intel page shows NVD, searchsploit, and Nmap NSE findings from the `vulnerabilities` table across all sessions. Filterable by source, risk level, and service.
- **Global `/api/vulnerabilities` endpoint** — queries `vulnerabilities` table across all sessions with optional filters.
- **AI decisions persistence** — all 6 `session.ai_decisions.append()` sites now also write to `ai_decisions` DB table immediately. Restored on session reload. Cleared on restart/rescan.
- **Action-required banners on Overview tab** — orange banner with inline approve/deny buttons when commands are pending; yellow warning when loop prevention was triggered.

### Fixed
- Vulnerability analysis timing out — `--script vuln` was running all NSE scripts. Changed to `"vuln and not intrusive"` with `--script-timeout 30`.
- Vulnerability scan blocking AI analysis — was `await`ed inline; changed to `asyncio.create_task()`.
- Stage regression on restart — post-nmap stage was incorrectly set to `"vulnerability_analysis"` (skipping enumeration). Fixed to `"enumeration"`.
- smbclient `Password:` prompt hanging sessions permanently — fixed by `stdin=DEVNULL` + `_inject_credentials`.
- `_CRED_PATTERNS` IndexError — john regex had only 1 capture group, expected 2.
- `ask_ai_local` missing `memory` parameter for Ollama context.
- `_compute_next_run` crash on month-end datetime arithmetic.
- `requires_approval` substring false positives — added word-boundary matching.
- `_EXPLOIT_SIGNALS` false positives — "password", "200 ok", "database" were matching normal recon output.
- Strategic state not persisted to DB — plan was lost on backend restart.
- API system prompt using wrong message role.

---

## [2.1.0] — 2026-07-xx

### Added
- Strategic layer (AI Planner) — separate Strategist AI pass updates multi-step plan and writes reflection after each command.
- Hybrid memory retrieval (FindingsIndex) — Ollama embeddings + TF-IDF lexical fallback for semantically relevant finding lookup.
- Context-aware memory for local Ollama — adapts system prompt and output budget to model's context window size.
- Episode compression — every 5 commands, recent history is compressed to a structured summary.
- Anti-loop guardrail — halts auto-execution if AI suggests a recently-executed command; logs `loop_prevention` decision.
- VERIFIER pass — independent AI critique of high-risk commands before execution in FULL_AUTO_MODE.
- Service test-state machine — `untested → in_progress → tested → exploited` tracked deterministically.
- Deterministic credential reuse — auto-queues reuse against all discovered services when credentials are extracted.
- Scheduled scans — recurring scan schedules with cron-style configuration.
- DOCX / PDF report generation.
- Threat Intel page — AI-directed open-web research cache (`threat_intel` table).
- Scope allowlist enforcement.

---

## [2.0.0] — Initial public release

- FastAPI backend (port 6000) + Streamlit frontend (port 8501).
- SQLite persistence: sessions, commands, scan_results, vulnerabilities, credentials.
- Nmap integration with async subprocess and configurable timeout.
- DeepSeek API + local Ollama AI providers.
- Risk classification (LOW / MEDIUM / HIGH) with deterministic keyword rules.
- Manual approval workflow for HIGH-risk commands.
- OSINT phase with Google Dorks.
- `start.sh` with automatic port conflict resolution and venv management.

# Changelog

All notable changes are documented here. Follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) conventions.

---

## [2.6.0] — 2026-08-28 — Durable sessions, safer execution, and parallel analysis

### Added
- **Unified execution gateway.** API, AI, playbook, and manual command paths now
  share server-side authorization, non-interactive checks, and automated binary
  policy. Explicit approval is the only manual escape hatch.
- **Deterministic playbook dispatch.** Framework-owned playbook steps are rendered
  and dispatched one at a time before the AI improvises, while respecting the
  current stage, installed tools, approval state, and duplicate queue protection.
- **Durable session timeline.** Added lifecycle events, background job records,
  activity timestamps, immutable session scope snapshots, asset graph nodes and
  relationships, and portable ZIP session archives.
- **Session cancellation and archive APIs.** Operators can cancel active sessions,
  inspect events/jobs, and export a replayable session bundle from the dashboard.
- **Prioritised findings.** Findings now receive a practical priority score based
  on confirmation, confidence, KEV, EPSS, and CVSS rather than CVSS alone.
- **Bounded parallel vulnerability analysis.** Independent per-port NSE scans and
  local ExploitDB lookups run concurrently while persistence and state-dependent
  exploitation remain ordered.
- **Reachable callback selection.** Local callback discovery now follows the
  target route, and automatic public-target handlers are skipped when no reachable
  callback endpoint is configured.

### Changed
- Full-auto mode no longer bypasses the automated binary allowlist.
- Brute-force workers are opt-in by default because they can trigger account
  lockouts; temporary credential wordlists are deleted after each job.
- Explicit local Ollama selection is no longer overridden by a stale API key in
  the environment.
- Exported reports redact secrets by default. Set
  `INCLUDE_SECRETS_IN_REPORT=true` only for an explicitly controlled report.
- Shell handler inputs are validated and Metasploit is launched with argument
  arrays instead of a shell command string.
- Documentation is English-only and includes session retention, archive, and
  concurrency guidance.

### Fixed
- Python 3.9 worker initialization failure caused by creating an asyncio
  semaphore outside a running event loop.
- Stale auto-pivot test expectations and incomplete test fixtures.
- Credential injection quoting for SMB, RPC, and Impacket command forms.
- Public-target callback flows that advertised a private workstation address.

### Verification
- `pytest -q`: 139 passed.
- `python3 -m compileall -q core ai main.py frontend.py docs_server.py` passed.

---

## [2.5.0] — 2026-08-20 — Efficiency, stuck-detection & enrichment

Grounded in a 6-hour field run (78 commands, no foothold): the engine reached a
real target (HestiaCP + phpMyAdmin + mail stack) but wasted hours on junk creds,
600 s tool timeouts, a silent stream crash, and endless spinning with no escape.

### Fixed
- **Command output crash.** A single output line over ~64 KB (ffuf/gobuster,
  minified JS) raised "Separator is not found, and chunk exceed the limit" and
  silently failed the whole command. The subprocess stream limit is raised to
  10 MB and the reader now survives over-limit lines instead of crashing.
- **Junk credentials.** The extractor captured `5.2.3 : 2025-10-07` (a version
  number + a date) as a login and burned hours reusing it. Version-, date-,
  time- and pure-number-shaped tokens are now rejected (real brute-forced creds,
  which arrive via a different path, are unaffected).

### Added
- **Per-tool timeouts + wordlist discipline.** Directory/DNS brute-forcers
  (gobuster/ffuf/dnsrecon/nikto/…) get a tighter `ENUM_COMMAND_TIMEOUT`
  (default 180 s) instead of the full 600 s, and oversized wordlists
  (`directory-list-2.3-medium/big`) are swapped for smaller ones — a single scan
  can no longer burn 10 minutes.
- **Escalate-when-stuck.** Hitting the auto-pivot limit, or `MAX_COMMANDS_NO_PROGRESS`
  (default 60) commands with no foothold, now HALTS the session to a firm
  `needs_operator` state (the watchdog no longer revives it) with a clear ask for
  guidance. Sending an operator instruction or approving a command resumes it.
- **Missing-tool preflight.** Key tools are checked once (sshpass, gobuster, ffuf,
  seclists, …); missing ones are surfaced to the AI with alternatives so it stops
  retrying uninstalled tools. `start.sh` also warns / offers to apt-install them.
- **Plan→act coupling.** The strategist's top pending plan step is now injected as
  an explicit "DO THIS NEXT" directive, so planned steps (e.g. SQL `INTO OUTFILE`)
  actually get executed instead of being re-enumerated around.
- **Version enrichment + CVE follow-through.** nmap output truncation now preserves
  the full PORT/SERVICE/VERSION table (naive truncation was cutting it, leaving
  services version-less and CVE lookup empty); a later `-sV` fills missing versions
  on already-known ports; and newly discovered services trigger a background
  vuln-analysis (searchsploit/NVD/KEV/EPSS) pass.
- **Target playbooks.** Exploit-map entries for phpMyAdmin (SQL→RCE), HestiaCP/
  VestaCP panels (8083, CVE-2022-31126), Exim (CVE-2019-10149) and Dovecot; panel
  ports (8083, cPanel 2082-2087, Webmin 10000) now classify as web targets.
- **Report exploitability columns.** The Markdown report's findings table adds
  KEV / EPSS / CVSS / Metasploit-module columns and ranks by real-world
  exploitability.

New env: `ENUM_COMMAND_TIMEOUT`, `MAX_COMMANDS_NO_PROGRESS`, `TERMINAL_LOG_FILE`.

## [2.4.2] — 2026-08-20 — Register AI-run nmap results

### Fixed
- **Services the AI discovered itself were invisible to the state machine.** Only
  the initial scanner-pipeline nmap populated `discovered_services`; when the AI
  ran its own `nmap` (e.g. after resolving a parked domain — `drhmonegyi.cc`, on
  `dns-parking.com` nameservers — to its real server IP `207.90.192.124` running
  HestiaCP on 8083), those open ports never entered the session, so coverage/stage
  stayed empty and the engagement was correctly-but-permanently gated at
  `vulnerability_analysis`. `_auto_parse_tool_output` now parses AI-run nmap output
  and merges the hosts/services (and seeds coverage), so the loop can progress on a
  host the AI found on its own. Tip: for a parked domain, point the session at the
  real server IP directly for the cleanest run.

## [2.4.1] — 2026-08-20 — Scan reachability, stage gating & credential sanity

Fixes a field run where a public domain scan returned **0 open ports** and the
engagement then fast-forwarded through every stage with nothing to do.

### Fixed
- **Nmap returned 0 ports on ping-blocking hosts.** Every scan profile (and the
  per-port NSE scans) now uses **`-Pn`** (skip host discovery). Most internet
  hosts block ICMP, so without it nmap declared them "down" and found no ports,
  leaving the engagement with no attack surface (`core/scanner.py`).
- **Stages fast-forwarded on a mislabeled phase.** Stage progression was driven
  purely by the AI's self-reported `attack_phase`; when the model kept reporting
  `credential_reuse`, the loop marched through recon→…→credential_reuse one step
  per decision without doing any stage's work. Added `_gate_stage` /
  `_stage_prereqs_met`: a stage is entered only when its prerequisites exist
  (services/vulns for exploitation; a foothold for post-ex/privesc; a foothold or
  real credential + a service for lateral movement / credential reuse). A
  mislabeled phase can no longer skip ahead of the real attack surface.
- **Guessed credentials no longer ingested.** A "credential" whose secret is
  derived from the target/domain name (e.g. password `DrHmoneGyi` for
  `drhmonegyi.cc`, echoed by a python/echo command) is now rejected
  (`_looks_guessed_credential`), so the loop no longer fixates on
  credential-reuse against a login that never existed.

## [2.4.0] — 2026-08-19 — Effectiveness, callback routing & CVE weaponisation

Focus of this release: raise the **confirmed** rate (the engine used to touch ~48%
of a lab's vulns but confirm only ~3%), make reverse shells work against real
internet targets, and rank CVEs by real-world exploitability.

### Added
- **CVE exploitability ranking (KEV + EPSS).** Findings are now enriched with
  **CISA KEV** (exploited-in-the-wild) and **FIRST EPSS** (exploit probability),
  cached and best-effort (`core/cve_lookup.py`: `load_kev`, `lookup_epss`,
  `enrich_findings`). A new **PRIORITISED CVEs** prompt block ranks findings
  KEV → EPSS → CVSS so the AI weaponises what is actually exploitable instead of
  chasing a high CVSS with no public exploit.
- **CVE → Metasploit module resolver** (`core/msf_resolver.py`). For the top
  prioritised CVEs, the local `msfconsole` is queried (`search cve:<id>`) and any
  ready module path is surfaced to the AI (and in the findings summary), so it
  jumps to a known exploit instead of improvising. Cached, bounded, and a no-op
  when Metasploit is absent. New env: `MSF_CVE_RESOLVE`, `MSF_CVE_RESOLVE_LIMIT`,
  `MSF_SEARCH_TIMEOUT`.
- **Reachable reverse-shell callbacks for real-world / VPS targets**
  (`core/callback.py`). Separates the *advertised* payload LHOST (what the target
  dials) from the local *bind* address, so a listener behind NAT still catches a
  shell. Modes via `CALLBACK_MODE`: `auto | local | public | ngrok | manual` —
  supporting an ngrok TCP tunnel (`NGROK_AUTHTOKEN`), the host's public egress IP,
  or a manual reverse-SSH endpoint (`EXPLOIT_LHOST`). The msf handler emits
  `ReverseListenerBindAddress/Port` when advertised ≠ bind; tunnels are torn down
  on session end. The AI prompt now reasons about reachability and falls back to
  bind shells / web shells when no callback is reachable. Unit-tested
  (`tests/test_callback.py`).

### Changed
- **AI reply reliability (DeepSeek API).** `max_tokens` 2000 → `AI_MAX_TOKENS`
  (default 4096) with a truncation/JSON-repair retry — fixes the frequent
  phantom "empty command" stalls caused by a JSON reply truncated mid-object.
  Tactical sampling temperature 0.7 → `TACTICAL_TEMPERATURE` (default 0.2) for
  fewer hallucinated flags/CVEs.
- **Coverage now measures success, not attempts** (`core/coverage.py`).
  `match_and_mark(..., success=)` — exploitation/post-ex steps only count as done
  on a confirmed exploit signal, so a failed attempt no longer marks a service
  "covered" and gets it abandoned. Progress reweighted toward footholds
  (FOOTHOLD 0.25 → 0.40, ENUM 0.35 → 0.22).
- **Finding-aware anti-loop.** The stagnation guard resets on any new finding
  (credential, service, foothold, subdomain, coverage step) and uses a higher
  threshold (18 vs 8) for exploitation-family stages, so a service being actively
  worked toward a shell is not abandoned mid-exploit. `MAX_AUTO_PIVOTS` 6 → 12.
- **OSINT stage is no longer skipped.** A public domain/host target is now *held*
  in the OSINT stage until real open-source recon has run (or a turn cap), instead
  of leaving after a single turn the moment the AI sees the initial nmap data.
  New env: `OSINT_MIN_ACTIONS` (default 3), `OSINT_MAX_TURNS` (default 6).
- **Autonomy defaults for unattended runs.** `max_auto_depth` default 5 → 25
  (the counter still resets on any critical finding), so an auto-approved session
  doesn't stall for a manual checkpoint every 5 commands.

- **Single-file terminal log.** All backend terminal output is now mirrored to
  one `.txt` file (`TERMINAL_LOG_FILE`, default `terminal_output.txt`) opened in
  `w` mode, so each backend start **truncates and replaces** it — a single rolling
  log for the current run, not a growing pile of per-run files. `uvicorn` output is
  included (`log_config=None` routes it through the root logger). Gitignored.

### Fixed
- **Report export not working.** The Markdown / DOCX / PDF / HTML / JSON download
  buttons put `st.download_button` inside the `if st.button(...)` handler, so the
  save button disappeared on the rerun the click triggered and the file never
  downloaded. Fetched/generated bytes are now stashed in `st.session_state` and the
  download button is rendered persistently from that state (each with a stable
  `key`), so exports download reliably. The Markdown endpoint/generator were fine;
  this was purely a UI-flow bug.

### Notes
- `AI_PROVIDER` example default is now `api` (DeepSeek). Local Ollama still works.
- Re-run `python benchmarks/score.py <report>.md` against the lab ground truth to
  measure the **confirmed %** delta from this release.

## [2.3.3] — 2026-08-14

### Fixed
- **OSINT stage skipped for domain targets.** A session always started at
  `reconnaissance` and (with `_advance_stage` never regressing) could never enter
  the `osint` stage — so a real domain target (e.g. `drhmonegyi.cc`) skipped
  subdomain enumeration, crt.sh, Google dorking, theHarvester, etc. Now a public
  domain/host target **starts in the OSINT stage** and is held there after the
  initial scan, with an injected OSINT checklist (subfinder/amass, crt.sh, DNS +
  zone transfer, dorks, theHarvester, whatweb/wafw00f, wayback) guiding the AI
  before deeper scanning. A bare **private IP still skips OSINT** (correct — no
  internet OSINT on a lab host). `_should_run_osint()` decides; unit-tested.

## [2.3.2] — 2026-08-14

### Fixed
- **Terminal flooded with polling logs** — the Streamlit auto-refresh polls a
  handful of read-only endpoints every few seconds, and (a) `GET /api/sessions/{id}`
  logged three debug INFO lines per poll, plus (b) uvicorn logged every
  `GET ... 200 OK`. Together they buried real events. Removed the debug logs and
  added a `uvicorn.access` filter that drops successful GET polls of the noisy
  read endpoints (keeps POST/DELETE, non-2xx, and app logs). The terminal is now
  quiet enough to see actual scan/AI/error events.
- **Session names with spaces/special chars** (e.g. "Dr HG") produced a session_id
  with a space (`Dr HG_...`), awkward in URLs/paths. Names are now slugified
  (`Dr-HG_...`).

## [2.3.1] — 2026-08-13

### Changed
- **Coverage Engine and Brute-force worker now default ON**, and are toggleable
  live from the UI — **Settings → 🚀 Engine Features** (Coverage Engine, Brute-force,
  Full-Auto mode). Changes apply immediately (mutate the live flag) **and** persist
  to `.env` (`POST /api/settings/features`), so end users never edit files. Field
  note that prompted this: a v2.3.0 lab run still stopped early / didn't lift
  coverage because the flags were left OFF in `.env`; defaulting ON + a Settings
  toggle removes that footgun. New API: `GET/POST /api/settings/features`,
  `orchestrator.get_feature_flags()/set_feature_flag()`. Unit-tested.

## [2.3.0] — 2026-08-13 — Coverage Engine

The shift from opportunistic LLM-guessing to **methodology-driven coverage**
(design: `docs/coverage-engine-design.md`, plan: `docs/coverage-engine-buildplan.md`).
Target-agnostic — everything keys on service type, not a specific lab. All new
capability is additive and, where it changes loop behaviour, gated behind flags
(`COVERAGE_ENGINE`, `BRUTEFORCE_ENABLED`), both default OFF.

### Added
- **M0 — Benchmark harness.** `benchmarks/score.py` scores an engagement report
  against a lab's ground-truth vulnerability set (`benchmarks/labs/kmn_training_win.json`,
  35 items) — turning "did it improve?" into a number (touched % + confirmed %,
  per-category, missed list). Dependency-free; unit-tested (`tests/test_benchmark.py`).
  **Baseline (v2.2.7 run):** touched 16/35 (45.7%), confirmed 1/35 (2.9%); web_cms
  and windows_system at 0 — recorded in `benchmarks/README.md`.
- **M1 (part 1) — Playbook registry** (`core/playbooks.py`). Declarative per-service
  methodology: `PlaybookStep` schema (deterministic vs AI steps), playbooks for
  http/tomcat/glassfish/jenkins/smb/ftp/ssh/mysql/winrm/rdp/generic, service→playbook
  classification, and command rendering. Pure data (no orchestrator coupling yet) —
  unit-tested (`tests/test_playbooks.py`). Not yet wired into the live loop; that
  integration lands behind a `COVERAGE_ENGINE` flag next.
- **M1 (part 2) — Coverage model** (`core/coverage.py`). Per-service step tracking
  (pending/done/skipped), monotonic service state
  (untested→enumerated→tested→exploited→post_ex), coverage ratio, and a
  **coverage-derived objective progress** formula plus an `is_objective_complete()`
  guard that blocks premature completion (requires a foothold **and** ≥85% service
  coverage **and** ≥85% progress). Targets a field bug: a run marked "OBJECTIVE
  COMPLETE 100%" on a single MySQL foothold while ~30 vulns were untouched.
  Unit-tested (`tests/test_coverage.py`).
  **Benchmark check (2026-08-13 completed run, pre-engine):** touched 17/35
  (48.6%), confirmed 1/35 (2.9%) — barely above baseline; the number the engine
  must beat.
- **M2 — Vulnerability validation** (`core/vuln_validate.py`, always on). Version-aware
  filtering + `confidence` + `potential`/`confirmed` status. Suppresses TLS-only CVEs
  on plain services (Heartbleed-on-FileZilla) and downgrades version-major-mismatch
  keyword hits (Tomcat 3.x CVE on a 8.5 target). NSE/exploit sources = confirmed;
  NVD/searchsploit = potential until validated. Unit-tested.
- **M3 — Exploit mapping** (`core/exploit_map.py`). Curated, target-agnostic
  knowledge base mapping service/tech → concrete exploit candidates (Ghostcat,
  WAR deploy, INTO OUTFILE/UDF, EternalBlue, BlueKeep, vsftpd backdoor, WP plugin
  RCE, WebDAV…). Surfaced to the AI as a "KNOWN EXPLOIT CANDIDATES" prompt block
  so it attempts known paths (COVERAGE_ENGINE-gated).
- **M4 — Post-exploitation + Windows RCE capture.** `_is_windows_rce_proof()` +
  `windows-rce` signal capture a web-shell/exec SYSTEM foothold that the
  Unix/msf-centric signals missed (guarded against enumeration output that merely
  lists the SYSTEM SID). New `POSTEX_STEPS` checklist (identity, host, users,
  AV/firewall/UAC, network/LLMNR/IPv6, cred harvest, privesc, loot) activates on a
  foothold and is injected as a POST-EXPLOITATION block — this is what surfaces the
  host/system-level findings. Post-ex coverage feeds the progress formula.
- **M5 — Brute-force worker** (`core/bruteforce_worker.py`, `BRUTEFORCE_ENABLED`).
  Decoupled credential **producer**: submits discovered auth services (ssh/ftp/
  rdp/mysql/smb/winrm), brute-forces in the background with tiered wordlists
  (built-in defaults → rockyou top-N → full), and pushes hits to the credential
  store (`_ingest_credential`) which the main loop reuses — never blocking the
  tactical loop. Bounded (per-service timeout, concurrency), scope-gated, safe when
  tools are missing. Injectable runner → unit-tested without hydra.
  API: `GET /api/sessions/{id}/bruteforce`.
- **M6 — Coverage & brute-force UI.** Overview shows a **methodology coverage
  matrix** (per-service % + state + pending steps, plus post-ex) and a
  **brute-force panel** (per-service job status + creds found). Objective progress
  is now coverage-derived.

New env: `COVERAGE_ENGINE`, `BRUTEFORCE_ENABLED`, `BRUTEFORCE_TIER`,
`BRUTEFORCE_MAX_SECONDS_PER_SERVICE`, `BRUTEFORCE_CONCURRENCY`. Suite: 125 passed.
- **M1 (part 3) — Live wiring behind `COVERAGE_ENGINE` flag** (default OFF, so
  existing behaviour is unchanged). When enabled, the orchestrator: seeds
  per-service playbook coverage after the scan (`_ensure_coverage`); injects a
  **METHODOLOGY COVERAGE** block into the AI prompt listing each service's pending
  steps ("work every step; do not skip a service"); marks steps done from executed
  commands (`match_and_mark`, tool/signal based); and **derives objective progress
  + completion from coverage** (`_recompute_coverage_progress`), overriding the
  strategist's estimate so a run can't hit 100% while services are untouched.
  Target-agnostic — playbooks key on service type, not a specific lab.
  `service_coverage` (per-service % + state + pending intents) exposed in the
  session report. New env: `COVERAGE_ENGINE`. Suite: 113 passed.

---

## [2.2.7] — 2026-08-13

### Fixed
- **Session silently went idle at `ready` and never recovered** (log showed ~9 minutes of pure UI polling — no AI calls, no commands — while the header still said "Session Active"). The stuck-session watchdog only revived `analyzing`/`executing` sessions and deliberately left `ready` alone, so a FULL_AUTO session that stopped at `ready` (e.g. after an auto-pivot or a soft loop) was never restarted. The watchdog now also revives an idle `ready` session — quickly (`WATCHDOG_STALL_IDLE_SECONDS`, default 120s) — **unless** it has a command awaiting manual approval (a legitimate wait, left untouched). `analyzing`/`executing` keep the long stall so genuinely-running work isn't interrupted. New env var: `WATCHDOG_STALL_IDLE_SECONDS`.

## [2.2.6] — 2026-08-13

### Fixed
- **Session view froze on "Scanning" while the AI was actually running.** The `pref_auto_refresh` setting was saved but never actually used — nothing re-ran the page — so the Overview showed whatever snapshot was first loaded and never reflected backend progress (hosts/services/commands/decisions/stage). The AI loop was working fine in the backend the whole time; only the UI was stale. Live auto-refresh is now implemented: while a session is active (scanning/analyzing/executing/ready) the page re-runs every `Refresh interval` seconds (default 5). Added a manual **🔄 Refresh** button + a `🟢 live`/`⏸ manual` indicator. Turn auto-refresh off in **Settings** for uninterrupted chatting.

## [2.2.5] — 2026-08-13

### Changed
- **Single source of truth for the version.** The version now lives only in `_version.py`; the frontend sidebar/About and the FastAPI backend (`/`, OpenAPI) import it at runtime, so they can no longer drift out of sync (previously the sidebar showed a stale `2.1.1` while the API said `2.0.0`). To release, edit `_version.py` or run `python bump_version.py X.Y.Z` — which also updates the README badge in one step. Only the changelog entry stays manual.

## [2.2.4] — 2026-08-12

### Added
- **Persistent chat transcript (messenger-style).** The AI chat now keeps a full per-session conversation instead of overwriting a single answer. Messages are stored in a new `chat_messages` table, reloaded on restart, and rendered as scrollable right/left bubbles so you can review the whole conversation. Exposed via `session.chat_history` in the session report.
- **Enter-to-send.** Both the chat and steer inputs are now `st.form`s, so pressing **Enter** submits (no longer requires clicking the button).

### Changed
- **Steering is now limited to active sessions.** The 🎯 Steer input only appears while a session is actually running (scanning/analyzing/executing/ready); for inactive sessions the chat shows a note instead. Keeps the chat clean and instructions scoped to the live engagement.

### Fixed
- **After `./start.sh` restart, sessions showed `ready` but the AI wasn't actually running** (no Resume, no activity in the log). Restored sessions with status `ready` weren't queued for auto-resume (only scanning/analyzing/executing were), so `ready` looked active but nothing ran. `ready` is now included in auto-resume, so a restored session genuinely continues.

## [2.2.3] — 2026-08-12

### Fixed
- **"Agentic loop error" on every turn — `UnboundLocalError: _queued_already`.** In `_process_command_output`, `_queued_already` was only assigned in the non-FULL_AUTO branch, but the trailing `elif not _queued_already` ran in all modes — so under `FULL_AUTO_MODE` (and on the critique-reject path) it raised `UnboundLocalError`, which the handler turned into a `loop_error` and paused the session. Now initialised before the branch and set on the FULL_AUTO critique-reject path. Regression-tested.
- **Resume button did nothing when a session was paused.** A recovery/pause state (`loop_error`, `no_next_step`, `watchdog_stalled`, `pivot_limit_reached`, `loop_prevention`) leaves `status="ready"`, which both the frontend and the `/resume` endpoint treated as "already running" — so Resume was greyed out and the endpoint no-op'd. Both now detect the paused context from the last decision and make Resume clickable and functional.
- **`name 'shlex' is not defined` during command execution.** `_inject_credentials` used `shlex.quote` but `shlex` was only imported locally in another method. Added the top-level import.

## [2.2.2] — 2026-08-12

### Added
- **Markdown report (zero-dependency)** — new `📝 Download Markdown Report` button + `GET /api/sessions/{id}/report/md`. Pure Python, no `python-docx`/`fpdf2` needed, so it always works. Renders the FULL engagement in order: metadata, executive summary, services, vulnerability findings (+ details), credentials, **confirmed compromises with proof snippets**, attack plan + operator steering + exhausted vectors, the **complete executed-command log (chronological, with output)**, and **every attack decision/idea (chronological, with pivot/operator/shell tags)**. Regression-tested (`tests/test_report.py`).

### Fixed
- **DOCX/PDF reports were incomplete or broken.** DOCX truncated the AI decision log to the last 10 and omitted confirmed compromises, the attack plan, and operator steering. The PDF read the wrong session keys (`commands`/`services` instead of `commands_executed`/`discovered_services`) — producing empty command/service sections — and crashed on `cve_ids` (already a list, not JSON). All now render every finding, command, and decision in order; DOCX adds Confirmed Compromises + Attack Plan & Operator Steering sections and the full chronological decision log.

## [2.2.1] — 2026-08-12

### Changed
- **Steer & Ask is now a floating chat bubble** (Facebook-style) pinned bottom-right, open from **any** tab of a session — not just the Overview. Click **💬 AI Chat** to pop open the Steer + Ask box; the bubble shows a badge with the count of active operator instructions. Implemented with `st.popover` + fixed-position CSS; on older Streamlit (< 1.31, no `st.popover`) it gracefully falls back to the inline panel on the Overview tab.

## [2.2.0] — 2026-08-12

### Added
- **Live operator steering** — send the running AI a free-text instruction mid-engagement ("Focus on GlassFish 4848", "skip SMB", "try Ghostcat on 8009"). It's injected as a **HIGHEST-PRIORITY** block into every subsequent AI decision, so you can redirect the autonomous loop without stopping it. Applies on the AI's next decision (doesn't interrupt a running command). Persists across restarts (rebuilt from the logged `operator_instruction` decisions). Endpoint: `POST /api/sessions/{id}/steer`.
- **Status chat** — ask the AI about the current engagement ("What have you found?", "What's blocking you?", "What next?") and get a concise, state-grounded answer. Read-only: it runs a one-off summary call over live session state and never executes anything or touches the loop. Endpoint: `POST /api/sessions/{id}/ask`.
- **Frontend "🧭 Steer & Ask" panel** on the session Overview: a Steer input + an Ask input with the AI's answer inline, plus a line showing the active operator instructions. New AI-Decision badge `🧭 steer`.

## [2.1.9] — 2026-08-12

### Fixed
- **NVD CVE lookups hammered the API and got HTTP 429 (Too Many Requests).** NVD's public limit is 5 requests / 30 s without a key (≈6 s apart), but the caller waited only 0.7 s — so after ~10 services every lookup 429'd and returned nothing. Rate limiting now lives inside `cve_lookup.lookup_cves_nvd()` behind a module-level lock (`NVD_MIN_INTERVAL`, default 6.5 s; 0.6 s when `NVD_API_KEY` is set) with exponential backoff + retry on 429. The redundant caller-side sleep was removed.
- **NVD keyword queries returned 0 hits from noisy banners.** Nmap version strings like `Apache httpd 2.4.38 ((Win64) OpenSSL/1.0.2q PHP/5.6.40)` were sent verbatim and matched nothing. `_clean_nvd_query()` now trims everything from the first `(` so NVD sees `Apache httpd 2.4.38`.
- **Wasted NVD requests on generic services.** `msrpc`, `netbios-ssn`, `microsoft-ds`, `ms-wbt-server`, etc. never yield keyword CVEs; they're now skipped, cutting request volume (and 429 pressure) substantially.
- **`_parse_response()` (Vulners) returned `None`.** The function built its `results` list but never returned it, so `lookup_cves()` yielded `None` instead of a list. Added the missing `return` (regression-tested).

### Note
- The `429`/`0 CVE` lines in earlier logs are the symptom above — the free NVD path now paces itself correctly. For faster/looser limits, set `NVD_API_KEY` in `.env` (free from nvd.nist.gov).

## [2.1.8] — 2026-08-12

### Fixed
- **Every session failed at ~5 commands: `'Orchestrator' object has no attribute '_EPISODE_SIZE'`.** `_create_episode_summary()` referenced `self._EPISODE_SIZE`, but `_EPISODE_SIZE` is a **Session** attribute — so once a session reached the episode-summary interval (5 commands), `execute_command` raised `AttributeError`, was caught by its outer handler, and the session was marked `failed` (the loop stopped and the UI stopped updating). Now reads `session._EPISODE_SIZE`. Regression test added.
- **`GET /api/vulnerabilities` → 500 (`no such column: s.target_hostname`).** The global vulnerabilities query joined non-existent columns `s.target_hostname` and `s.name`. The `sessions` table has `target_ip` + `target_domain` (and `session_id` doubles as the name). Query corrected — the Threat Intel structured-vuln table and dashboard vuln widget load again.

## [2.1.7] — 2026-08-12

### Added
- **Session History management** — the History page now lets you clean up recorded sessions (previously they could only accumulate):
  - Per-session **🗑️ Delete** button on every card (failed/completed included), with an inline confirm.
  - **🗑️ Clear ALL History** (two-step confirm) and **🧹 Clear Failed (N)** bulk actions.

### Fixed
- **Session delete left orphaned shell rows** — `delete_session` / `delete_all_sessions` now also clear the `shell_handlers` and `shell_sessions_log` tables and stop any live `ShellManager` for the deleted session(s).

## [2.1.6] — 2026-08-12

### Fixed
- **Session stuck at "scanning" long past the timeout (scan never returned).** Scans launch via `create_subprocess_shell`, so the process handle is the `/bin/sh` wrapper and nmap is its child. On timeout the old code called `process.kill()` (kills only the shell) then `await process.communicate()` — which **blocked until nmap finished on its own** because the still-running child held the stdout pipe open. Effect: the 5-minute `SCAN_TIMEOUT` never actually fired; on a host with many slow services (RMI/JMX/GIOP/GlassFish) the session sat in `scanning` for as long as nmap ran (10+ minutes). Fixes:
  - New `_run_shell_bounded()` / `_kill_process_group()` helpers launch scans with `start_new_session=True` and, on timeout, `killpg` the **whole process group** (child included), then collect output with a bounded 5s wait.
  - `perform_nmap_scan`, `perform_vulnerability_scan`, and `perform_vulnerability_scan_port` all use the bounded runner and now **parse partial output** on timeout instead of discarding it.
  - nmap profiles gained `--host-timeout` (SCAN_TIMEOUT − 60s) + `--max-retries 2` so nmap self-bounds and returns graceful partial results before the hard kill.
  - Initial recon (`default` profile) dropped `-sC` default scripts — the slowest phase on service-heavy hosts; targeted script/vuln scans still run in the background NSE pass and via AI-proposed commands.
  - `orchestrator.execute_command` had the same shell-wrapper bug (a hung tool orphaned the real process); it now launches with `start_new_session=True` and `killpg`s the group on timeout.

## [2.1.5] — 2026-08-12

### Added
- **Autonomous shell capture — AI catches its own sessions in the Shells tab.** Previously an exploit the AI fired opened its session inside a throwaway `msfconsole` process the manager never monitored, so it never appeared in the UI. Now the loop wires exploitation to the managed handler end-to-end:
  - **Auto-started listener** — when the engagement reaches an exploitation stage (`exploitation`/`post_exploitation`/`privilege_escalation`/`lateral_movement`/`credential_reuse`), `_ensure_exploitation_handler()` spins up one managed `multi/handler` (idempotent per session). LHOST defaults to the local IP (`EXPLOIT_LHOST` override), LPORT to `4444` (`EXPLOIT_LPORT`), payload auto-guessed from the target OS (`_guess_default_payload()`; `EXPLOIT_PAYLOAD` override).
  - **AI payload directive** — `_handler_context_block()` injects the live LHOST/LPORT/payload into every AI prompt with hard rules: deliver reverse shells to this listener, use these values in msfvenom / MSF modules, and never start your own handler.
  - **Session-opened callback** — `MsfHandlerProcess` now fires `on_session_opened`; the orchestrator persists each caught session to `shell_sessions_log` and logs a visible `shell_caught` decision. Caught sessions surface in the **🐚 Shells** tab automatically (no polling).
  - **Frontend** — Overview shows a green "Live shell caught!" banner (and a "Listener up" info banner when the handler starts); new AI-Decision badges `🎧 listener`, `🐚 shell!`.
  - New env vars: `EXPLOIT_LHOST`, `EXPLOIT_LPORT`, `EXPLOIT_PAYLOAD`.

## [2.1.4] — 2026-08-12

### Added
- **Stuck-session watchdog** (`watchdog_loop` / `_watchdog_tick`) — background task (started at API startup) that detects sessions wedged in an active status (`analyzing`/`executing`) with no progress for `WATCHDOG_STALL_SECONDS` (default `COMMAND_TIMEOUT + 180`). It nudges them back into motion up to `WATCHDOG_MAX_NUDGES` (default 2), then logs a visible `watchdog_stalled` decision and returns to `ready`. `_touch_activity()` records progress at command start/finish and on every AI decision. Env-tunable: `WATCHDOG_INTERVAL`, `WATCHDOG_STALL_SECONDS`, `WATCHDOG_MAX_NUDGES`.
- **Exploitation evidence capture** — when a command's output proves code execution/shell access, `_capture_exploitation_evidence()` records the service, host, port, command, **privilege level** (`_detect_privilege_level()` → root/SYSTEM, administrator, or user), matched signal, and a proof snippet. Persisted to the evidence table and deduped per (service, privilege).
- **AI post-exploitation awareness** — confirmed compromises are injected into the AI context (`_compromise_context_block`) with an instruction to move to privilege-escalation/pivoting instead of re-running an exploit that already worked (a common enumeration-loop cause). Exhausted-vector context is now also shared with the tactical loop (`_exhausted_context_block`).
- **Frontend — confirmed compromises panel** on the Overview tab: green success banner with per-compromise expanders (privilege icon, command, proof snippet). New AI-Decision badges: `🐕 watchdog`.
- **Regression suite** `tests/test_agentic_loop.py` — 17 tests covering empty/no-response recovery, auto-pivot + limit, watchdog nudge/flag/rest, strategist triggers, and exploitation evidence capture + dedup.

### Fixed
- **Agentic loop silently stalled at `ready` (reason-and-continue never progressed)** — the root cause was the LLM occasionally returning valid JSON with an **empty `suggested_command`**. Both `_analyze_with_ai()` and `_process_command_output()` handled this by doing nothing, leaving the session at `status=ready` with no pending command and no error — indistinguishable from "frozen." Now:
  - Empty commands route to `_handle_empty_command()`, which retries the analysis up to `MAX_EMPTY_RETRIES` (default 3) with a hard "you MUST return a concrete command" directive, then logs a visible `no_next_step` decision and returns to `ready`.
  - `_process_command_output()`'s previously-silent `except Exception` now records a visible `loop_error` decision instead of dying quietly.
  - Frontend surfaces both new states with banners and AI-Decision badges (`🤔 no-step`, `⚠️ error`).
- **`None` AI response was a non-resumable dead-end** — a model timeout / JSON-parse failure set `status=error` and stopped. Both sites now route through the same retry+visible-halt recovery, so a transient hiccup self-heals.
- **Strategist never ran → objective progress frozen** — the strategist only fired every `PLANNER_INTERVAL` (5) completed commands, so sessions that stalled before command #5 never advanced progress. It now also runs on the first command (bootstrap, when no plan exists) and whenever the engagement advances a stage.
- **Unit tests broke on DB writes** — `make_orch` now stubs `_save_ai_decision` / `_save_session_status`, fixing `credential_reuse` and `strategist` tests that failed once AI-decision DB persistence was added.

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

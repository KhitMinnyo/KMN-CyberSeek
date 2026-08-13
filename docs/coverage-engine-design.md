# Coverage Engine — Design Document

**Status:** Draft (pre-implementation)
**Target version:** 2.3.0
**Author:** KMN-CyberSeek
**Last updated:** 2026-08-13

---

## 1. Motivation

### 1.1 The problem

The current agent is **opportunistic / greedy**: the LLM picks the next command
based on whatever looks most promising in the moment. It has no notion of
*coverage* — it never asks "have I run the standard playbook against every
discovered service?" — and it abandons a service (`exhausted_services`) when the
**loop-detection** guard fires, not when a methodology is complete.

A professional pentester works the opposite way: they follow a **methodology**
(a per-service / per-technology checklist) and do not consider a service "done"
until every applicable step has been attempted.

### 1.2 Evidence (KMN-Training-Win lab, 2026-08-13)

Against a Windows Server 2019 lab with ~35 seeded vulnerabilities, an autonomous
run confirmed **1** (MySQL root → file read + WP hash dump), had active leads on
~3 (Ghostcat AJP read, GlassFish default creds, WordPress), and **missed ~30**,
including:

- **SMB** (SMBv1, null session, anonymous `SecretShare` RW) — *marked exhausted
  and abandoned* before `enum4linux`/`smbmap` were ever run.
- **WordPress** WP File Manager RCE (CVE-2020-25213), Reflex Gallery upload — no
  `wpscan`/plugin enumeration was performed.
- **WebDAV** PUT / arbitrary-upload RCE — no WebDAV probe (`davtest`).
- **Jenkins** Groovy console RCE (port 8888) — seen but not exploited.
- **Weak credentials** across SSH/FTP/RDP/Tomcat/WinRM/MySQL — no systematic
  brute-force; only a handful of default creds tried via ad-hoc `curl` loops.
- **Windows system-level** (Defender disabled, weak `Administrator` password,
  `guest` in Administrators, LLMNR/NBT-NS, IPv6/mitm6) — require a foothold +
  internal enumeration that was never reached.

The vulnerability table was also dominated by **false positives**: five ancient
Tomcat 3.x/4.x CVEs (2001–2002) surfaced by unfiltered NVD keyword search against
a **Tomcat 8.5** target, plus a FileZilla FTP service tagged with Heartbleed.

### 1.3 The shift

> From **opportunistic LLM-guessing** → **methodology-driven coverage**, where a
> deterministic framework guarantees every service receives its full playbook and
> the LLM supplies judgment and nuance on top.

This single change is the backbone of everything below.

---

## 2. Goals / Non-goals

### Goals
- Guarantee **coverage**: every discovered service is driven through a standard,
  per-service playbook before it is considered complete.
- Replace loop-based `exhausted_services` with **playbook completion**.
- Systematic **credential brute-forcing** as a decoupled, parallel worker
  (producer of credentials), so it never blocks the main engine.
- **Validate** vulnerabilities (version-aware) to cut false positives; separate
  "potential" from "confirmed".
- **Post-exploitation** playbook: on any foothold, run internal enumeration to
  surface host/system-level findings.
- **Exploit mapping**: map (service, version) → concrete exploits (searchsploit /
  Metasploit / nuclei) and actually attempt them — not just list CVEs.
- **Accurate progress**: derive objective progress from coverage, not from the
  LLM's subjective estimate.

### Non-goals
- 100% real-world coverage. Business-logic, chained, and custom-application vulns
  still require human insight. The goal is comprehensive coverage of the
  **standard/known-pattern attack surface**.
- Replacing the LLM tactical loop. The LLM stays; it now operates *within* a
  coverage framework.

---

## 3. Core concepts

### 3.1 Playbook
A declarative, per-service checklist of steps. Each step is either:
- **deterministic** — a fixed command template (e.g. `enum4linux-ng -A {host}`), or
- **AI-assisted** — the framework specifies the *intent* ("enumerate WordPress
  plugins and users") and the LLM generates the concrete command.

The framework guarantees each **step is attempted**; the LLM handles nuance.
(Decision: **hybrid** — see §11 Q1.)

### 3.2 Coverage
Per-service tracking of which playbook steps are done / pending / skipped, plus a
technique-level service state machine. A service is **complete** only when its
playbook is exhausted (all applicable steps attempted), *not* when a loop fires.

### 3.3 Coverage-derived progress
`objective_progress` becomes a deterministic function of coverage (recon done +
enumeration coverage + validated vulns + footholds + post-ex depth), so the
progress bar is meaningful and reproducible.

---

## 4. Architecture overview

```
                         ┌───────────────────────────────────────────┐
                         │              Orchestrator                  │
                         │                                            │
  discovered services →  │  Playbook Engine ──seeds──► Task Queue     │
                         │        │                        │          │
                         │        ▼                        ▼          │
                         │  Coverage Model ◄──updates── Tactical Loop │
                         │        │                    (LLM + exec)   │
                         │        ▼                        │          │
                         │  Progress (coverage-derived)    │          │
                         └────────┼────────────────────────┼──────────┘
                                  │                        │
                    new creds ────┼──────────────┐         │ compromise
                                  ▼              │         ▼
                          Credential Store ◄─hits─┤   Post-Exploitation
                                  ▲              │      Playbook
                                  │              │
                        ┌─────────┴──────────┐   │
                        │ Brute-force Worker │   │  (decoupled, parallel)
                        │  (parallel/subproc)│   │
                        │  hydra / nxc /     │   │
                        │  SecLists + rockyou│   │
                        └────────────────────┘   │
                                                 │
              Vuln Validation (version-aware) ◄──┘  filters NVD/searchsploit/NSE
              Exploit Mapping (searchsploit/msf/nuclei) → attempts
```

Key property: the **brute-force worker is decoupled** — it produces credentials
into the shared Credential Store; the main loop consumes them via the existing
credential-reuse mechanism. Neither blocks the other.

---

## 5. Component designs

### 5.1 Playbook Engine (M1)

**Registry** — `core/playbooks.py`:

```python
@dataclass
class PlaybookStep:
    id: str                     # stable id, e.g. "http.wpscan"
    intent: str                 # human/LLM description of the goal
    kind: str                   # "deterministic" | "ai"
    command: Optional[str]      # template for deterministic steps, e.g. "enum4linux-ng -A {host}"
    tool: Optional[str]         # required binary (checked for availability)
    applies_if: Optional[Callable[[dict], bool]]  # extra gate (e.g. tech == wordpress)
    phase: str                  # enumeration | vuln | exploitation | post_ex
    produces: List[str]         # tags of expected outputs (creds, shares, cve, rce...)

PLAYBOOKS: Dict[str, List[PlaybookStep]] = {
    "http":     [...],   # whatweb, nikto, gobuster/feroxbuster, nuclei, CMS detect,
                         # wpscan (if wordpress), davtest (if webdav), ...
    "smb":      [...],   # enum4linux-ng, smbmap, null session, share list, SMBv1, nxc
    "ftp":      [...],   # anon login, list, upload test, (brute → worker)
    "ssh":      [...],   # banner, algos, (brute → worker)
    "mysql":    [...],   # auth check, (brute → worker), db enum, file r/w, UDF
    "tomcat":   [...],   # manager brute, ghostcat (AJP), WAR deploy
    "glassfish":[...],   # default creds, LFI, WAR deploy
    "jenkins":  [...],   # script console, RCE
    "winrm":    [...],   # (brute → worker), evil-winrm exec
    "rdp":      [...],   # NLA check, (brute → worker)
}
```

**Service classification** — a discovered service is mapped to one or more
playbook keys using service name + version + banners (e.g. `http` on 8080 with
"Tomcat" → both `http` and `tomcat`; `http` returning WordPress → adds WP steps).

**Seeding** — when a service is discovered (or its tech is fingerprinted), the
engine enqueues its playbook steps as tasks. Steps whose `tool` is missing on the
host are marked `skipped(tool_missing)` and logged as a tooling recommendation.

**Execution** — deterministic steps run their command template directly;
AI steps inject the `intent` into the tactical LLM prompt as the *current
objective* and let the model produce the command. Either way the step is marked
`done` when it completes (success or failure both count as "attempted").

### 5.2 Coverage Model & Service State (M1)

Extend the per-service record:

```python
service["coverage"] = {
    "steps": { "http.whatweb": "done", "http.wpscan": "pending", ... },
    "state": "enumerated",   # untested → enumerated → tested → exploited → post_ex_done
}
```

- `_service_playbook_complete(service)` → all non-skipped steps `done`.
- **Replace** `exhausted_services` semantics: a service is set aside only when its
  playbook is complete (renamed conceptually to *covered*), or by an explicit
  operator instruction. Loop-detection still exists as a *safety* net but now
  triggers "advance within the playbook / next step", not "abandon the service".

### 5.3 Coverage-derived Progress (M1)

```
progress = 0.10 * recon_done
         + 0.35 * mean(service_enumeration_coverage)
         + 0.15 * validated_vuln_ratio
         + 0.25 * (footholds > 0 ? scaled(footholds) : 0)
         + 0.15 * post_ex_coverage
```

Weights configurable. This replaces the strategist's free-form estimate as the
**source of truth** for the progress bar; the strategist still writes narrative
reflections but no longer owns the number.

### 5.4 Brute-force Worker — decoupled (M5, parallelizable)

**Rationale:** brute-force is slow; if it runs inline it blocks the whole
engagement. It is therefore a **separate worker** that produces credentials.

- **Trigger:** when an auth service (ssh/ftp/rdp/winrm/mysql/tomcat/smb) is
  discovered, enqueue a brute job.
- **Isolation:** run as a **dedicated subprocess-backed worker** (preferred over a
  bare asyncio task) so long runs are isolated and killable. (Decision: see §11 Q2.)
- **Tools:** `hydra`, `crackmapexec`/`netexec`, `medusa`, per service.
- **Wordlists:** Kali-provided — SecLists + `rockyou`. **Tiered** to stay bounded:
  1. curated default-creds / top-100 (fast),
  2. `rockyou` top-N (configurable),
  3. full (opt-in only).
  (Decision: see §11 Q3.)
- **Bounds:** per-service wall-clock timeout, global concurrency cap, rate limit,
  scope allowlist honored. Never runs unbounded.
- **Output:** on a hit → `add_credential(session, ...)` into the shared store.
  The existing credential-reuse deterministically dispatches reuse across other
  services; the tactical loop consumes the new creds automatically.
- **State/progress:** the worker tracks its own per-service status
  (`queued | running | done | found`) and creds-found count, surfaced separately
  in the UI (not mixed into the main progress).

**Env:** `BRUTEFORCE_ENABLED`, `BRUTEFORCE_TIER` (default/topN/full),
`BRUTEFORCE_MAX_SECONDS_PER_SERVICE`, `BRUTEFORCE_CONCURRENCY`,
`BRUTEFORCE_USERLIST`, `BRUTEFORCE_PASSLIST`.

### 5.5 Vuln Validation — version-aware (M2)

- For NVD / searchsploit / Vulners results, compare the CVE's affected version
  range against the discovered version. Out-of-range → **drop** or downgrade to
  `potential (unverified)` rather than `confirmed`.
- Add a `confidence` field and a clear `status` split:
  `potential` (keyword/version heuristic) vs `confirmed` (validated by an actual
  check or exploit).
- Fix known NSE false positives (e.g. Heartbleed tagged on FileZilla FTP) via a
  small allow/deny heuristic keyed on service+script.
- The report/UI shows confirmed findings prominently and potentials separately.

### 5.6 Post-Exploitation Playbook (M4)

- **Trigger:** a new `compromise_evidence` entry (foothold/shell), or a usable
  high-priv credential (e.g. MySQL root, SMB admin).
- **Steps (OS-aware):** identity & privileges (`whoami /all`, `id`), local users
  & groups, AV/firewall posture (Defender, firewall profiles), UAC settings,
  scheduled tasks/services, network posture (LLMNR/NBT-NS, IPv6/mitm6 opportunity),
  credential harvesting, sensitive file loot, and — where a shell exists — a
  local privesc scan (winPEAS/linPEAS style).
- Feeds new findings back into the vulnerability/evidence store (this is what
  surfaces the Windows system-level items).

### 5.7 Exploit Mapping (M3)

- For each `(service, version)` build a candidate exploit set from: `searchsploit`,
  Metasploit module search (`msfconsole -x "search ..."`), and `nuclei` templates.
- **Attempt** the top candidates (gated by risk/approval + the existing VERIFIER
  critique), delivering shells to the managed multi/handler (already implemented).
- Distinguishes "known exploit exists" (mapped) from "exploit succeeded"
  (confirmed compromise).

---

## 6. Data model / DB changes

- `services`: add `coverage` JSON (steps + state) — persisted with scan results.
- `vulnerabilities`: add `confidence` (0–1) and refine `status`
  (`potential | confirmed`).
- New table `bruteforce_jobs`: `(session_id, service, host, port, tier, status,
  started_at, finished_at, creds_found)`.
- New table `playbook_steps` (optional) or embed step state in the services JSON.
- Migrations are additive (`ALTER TABLE ... ADD COLUMN`, `CREATE TABLE IF NOT
  EXISTS`) consistent with existing patterns.

---

## 7. UI / progress display

- **Coverage matrix** (Overview): rows = services, columns = playbook phases /
  key steps, cells = ✓ done / ⏳ pending / ⤫ skipped(tool missing). One glance
  shows exactly what has and hasn't been run.
- **Brute-force panel** (separate): per-service `queued/running/done`, creds
  found, current tier, elapsed. Kept out of the main progress bar.
- **Accurate overall progress**: coverage-derived (§5.3).
- **Findings split**: `Confirmed` vs `Potential (unverified)`.

---

## 8. Integration with the existing loop

- The tactical loop (`_process_command_output` / `_analyze_with_ai`) becomes a
  **consumer of the task queue**: prefer the next pending playbook step for the
  current focus service; the LLM may still propose creative steps, which are
  recorded as ad-hoc coverage.
- `auto_pivot` / loop-detection is retained as a **safety net** but now advances
  *within* the playbook (skip a stuck step, move to the next) instead of
  abandoning the whole service.
- The strategist keeps writing reflections but no longer owns the progress number.
- Operator steering (already implemented) can force focus onto a service or step.

---

## 9. Milestones / build order

| # | Milestone | Depends on |
|---|-----------|------------|
| **M1** | Playbook engine + coverage model + coverage-derived progress (#1, #2) | foundation |
| **M2** | Vuln validation / version-aware false-positive filtering (#4) | standalone |
| **M3** | Exploit mapping — searchsploit + msf + nuclei, actually attempt (#6) | M1 |
| **M4** | Post-exploitation playbook (#5) | M1 + foothold |
| **M5** | Brute-force worker (parallel, decoupled) (#3) | credential store — buildable in parallel with M1 |
| **M6** | Coverage + brute-force UI + accurate progress display | M1, M5 |

M1 is the foundation — without playbook + coverage there is no frame to hang the
rest on. M5 is decoupled and can be built in parallel with M1.

---

## 10. Trade-offs & risks

- **Comprehensiveness vs runtime:** full playbooks = many more commands = longer
  runs. Mitigate with prioritization (confirmed high-value paths first),
  parallelism (brute worker), and per-step timeouts.
- **Noise vs coverage:** nuclei/brute increase time and noise. Tiered/opt-in.
- **AI cost:** more steps → more LLM calls. Deterministic steps don't call the LLM.
- **Safety / real-world:** brute-force and aggressive scans can cause lockouts or
  trip defenses. Honor `SCOPE_ALLOWLIST`, rate limits, and approval gates; keep
  destructive steps behind `FULL_AUTO_MODE` / manual approval.

### Tooling dependencies (Kali)
`nmap`, `whatweb`, `nikto`, `gobuster`/`feroxbuster`, `nuclei`, `wpscan`,
`enum4linux-ng`, `smbmap`, `crackmapexec`/`netexec`, `hydra`, `medusa`,
`davtest`, `searchsploit`, `msfconsole`, `evil-winrm`, SecLists, `rockyou`.
Missing tools → step `skipped(tool_missing)` + a recommendation surfaced in the UI.

---

## 11. Open questions & proposed decisions

1. **Playbook step model** — deterministic vs AI-assisted.
   **Proposed: hybrid.** Framework guarantees the step is attempted; deterministic
   where a fixed command is correct, AI-assisted where nuance/parsing is needed.
2. **Brute-force execution** — asyncio task vs subprocess worker.
   **Proposed: subprocess-backed worker** for isolation and killability on long runs.
3. **Wordlist policy** — **Proposed: tiered** (default/top-100 → rockyou top-N →
   full opt-in), env-tunable, using Kali's SecLists + rockyou.

*(These are proposals to confirm before M1/M5 implementation.)*

---

## 12. Testing strategy

- Unit-test the playbook registry (every service maps to a non-empty playbook;
  every step has a valid schema and tool).
- Unit-test coverage completion + the progress formula (deterministic inputs →
  expected number).
- Unit-test version-aware vuln filtering (in-range vs out-of-range CVE).
- Unit-test the brute-force worker's producer contract with a mocked runner
  (hit → credential appears in the store; bounds respected).
- Keep all tests dependency-free (mock external tools), consistent with the
  existing suite.

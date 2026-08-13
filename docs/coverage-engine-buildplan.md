# Coverage Engine — Build Plan

Companion to `coverage-engine-design.md`. This is the execution order and the
principles we build by. Target: v2.3.0.

## Principles
1. **Measure first.** Every milestone is judged by the benchmark coverage number
   against the KMN-Training-Win lab — not by feeling.
2. **Vertical slices.** Prove a pattern on 2–3 services before widening.
3. **Additive & modular.** New capability goes in new modules (`core/playbooks.py`,
   `core/coverage.py`, `core/bruteforce_worker.py`), never bloating
   `orchestrator.py` further. Additive DB migrations only.
4. **Test-driven & dependency-free.** Unit tests (mock external tools) per change;
   changelog + version bump; no Burmese in code.
5. **Keep `main` usable.** Additive foundation lands on `main`; the riskier live-loop
   integration is gated behind a flag (`COVERAGE_ENGINE=true`) until stable.

## Milestones & order

| # | Milestone | Deliverables | Gate |
|---|-----------|--------------|------|
| **M0** | Benchmark harness | `benchmarks/labs/kmn_training_win.json`, `benchmarks/score.py`, tests | baseline number recorded |
| **M1** | Playbook engine + coverage + progress | `core/playbooks.py`, `core/coverage.py`, progress formula, flag-gated wiring | coverage ↑ vs baseline on lab |
| **M2** | Vuln validation (version-aware) | filter in `cve_lookup`/analysis, `confidence` + `potential/confirmed` | false-positive CVEs drop |
| **M5** | Brute-force worker (parallel) | `core/bruteforce_worker.py`, producer→credential store | creds found on lab |
| **M3** | Exploit mapping | searchsploit+msf+nuclei attempt | RCE footholds ↑ |
| **M4** | Post-exploitation playbook | internal enum on foothold | system-level findings ↑ |
| **M6** | Coverage/brute UI + accurate progress | coverage matrix, brute panel | progress bar meaningful |

M0 and M5 are decoupled and can proceed in parallel with M1.

## Definition of done (per milestone)
- New module(s) with unit tests passing in `tests/run_tests.py`.
- Changelog entry + version bump via `bump_version.py`.
- Benchmark coverage re-measured and recorded in the milestone's changelog note.
- No regression in the existing suite.

## Baseline (pre-M1)
Recorded by M0 against the last KMN-Training-Win report: see
`benchmarks/README.md` after the first scoring run.

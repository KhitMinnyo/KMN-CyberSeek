# Coverage Benchmarks

Turns "did the engagement get better?" into a number. Each lab has a ground-truth
vulnerability set; `score.py` compares an engagement report against it and reports
coverage. This is the yardstick for every coverage-engine milestone (see
`docs/coverage-engine-buildplan.md`).

This is currently a **self-scored project benchmark**, not an independent or
third-party benchmark. It must not be used to claim that KMN-CyberSeek is better
than PentestGPT, CAI, XBOW, or any other system. See `benchmarks/manifest.json` for
the reproducibility and comparison policy.

## Structured Verification Scoring

Use an internal, evidence-bearing JSON report or a fixture with a `findings` or
`vulnerabilities` array. Assign exact `ground_truth_id` values from the lab manifest
to findings during independent review. The scorer recomputes verification from
linked lifecycle events, evidence, and artifact declarations; precomputed verified
flags are not authority. It cannot independently authenticate artifact contents.

```bash
python benchmarks/score.py internal-report.json --structured --lab benchmarks/labs/kmn_training_win.json --json
```

Structured output includes verified IDs, true/false-positive IDs, false negatives,
precision and recall. Verified findings without ground-truth labels make precision
unavailable rather than silently counting as correct. Sanitized public
`report.json` exports omit the raw verification contract and are intentionally
insufficient for this scoring mode. Do not reconstruct evidence from report prose.

Record the commit, model/configuration, authorized lab image, request/time/cost
budget, and repeated-run variance alongside scores. Include known-safe cases when
measuring false positives. These remain engineering measurements, not independent
validation or proof of superiority over another system.

## Legacy Markdown Usage

```bash
# Score a downloaded Markdown report
python benchmarks/score.py /path/to/kmn_report_<id>.md

# Choose a lab explicitly / machine-readable output
python benchmarks/score.py report.md --lab benchmarks/labs/kmn_training_win.json --json

# Print the explicit code-level capability inventory (not a leaderboard)
python benchmarks/compare_capabilities.py
```

**Heuristic Metrics, Not Verification**
- **touched** — the AI at least attempted / mentioned the vuln (signal anywhere in the report).
- **confirmed** — a signal appears in a selected section (Confirmed Compromises / Credentials Captured / Vulnerability Findings). This historical field name does not establish a verified finding or validated credential.

## Labs
- `labs/kmn_training_win.json` — Windows Server 2019 training lab (192.168.100.194), 35 ground-truth items across 5 categories.

## Baseline (pre-coverage-engine, v2.2.7)

Scored against the 2026-08-13 autonomous run (`Win-Server_3f66b862`):

| Metric | Score |
|--------|-------|
| Touched | **16 / 35 (45.7%)** |
| Confirmed | **1 / 35 (2.9%)** |

By category (touched / total):

| Category | Touched | Notes |
|----------|---------|-------|
| web_cms | 0 / 6 | WebDAV + WordPress completely missed (no wpscan/davtest) |
| app_servers | 6 / 8 | Tomcat/GlassFish/Jenkins probed, none confirmed |
| network_fileshare | 5 / 6 | SMB/FTP touched, abandoned early, none confirmed |
| remote_admin_db | 5 / 9 | MySQL root **confirmed**; no brute-force (SSH/RDP/WinRM) |
| windows_system | 0 / 6 | no post-exploitation → no internal findings |

These numbers are a historical baseline only. They are not an independent
validation result and they do not prove successful VM compromise. Re-run
`score.py` after each milestone and record the exact run metadata and delta in the
changelog.

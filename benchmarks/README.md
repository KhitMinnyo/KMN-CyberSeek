# Coverage Benchmarks

Turns "did the engagement get better?" into a number. Each lab has a ground-truth
vulnerability set; `score.py` compares an engagement report against it and reports
coverage. This is the yardstick for every coverage-engine milestone (see
`docs/coverage-engine-buildplan.md`).

This is currently a **self-scored project benchmark**, not an independent or
third-party benchmark. It must not be used to claim that KMN-CyberSeek is better
than PentestGPT, CAI, XBOW, or any other system. See `benchmarks/manifest.json` for
the reproducibility and comparison policy.

## Usage

```bash
# Score a downloaded Markdown report
python benchmarks/score.py /path/to/kmn_report_<id>.md

# Choose a lab explicitly / machine-readable output
python benchmarks/score.py report.md --lab benchmarks/labs/kmn_training_win.json --json
```

**Metrics**
- **touched** — the AI at least attempted / mentioned the vuln (signal anywhere in the report).
- **confirmed** — a signal appears in a confirmed section (Confirmed Compromises / Credentials Captured / Vulnerability Findings).

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

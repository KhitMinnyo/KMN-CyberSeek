# KMN-CyberSeek

![Version](https://img.shields.io/badge/Version-2.6.2-brightgreen)
![Python](https://img.shields.io/badge/Python-3.10%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

KMN-CyberSeek is a self-hosted security assessment framework for authorized network and application testing. It combines deterministic playbooks, security tools, optional LLM guidance, operator approval, and evidence-backed reporting.

Use only against systems you own or have explicit written permission to test. Local command execution is **not isolated by default**. A Docker backend alone does not enforce target scope; deployment-level egress controls are required. See [Security and Operations](docs/reliability.md) before running an assessment.

## Quick Start

**Requirements:** Python 3.10+, Nmap, and either an LLM API key or a local Ollama model. Kali Linux or a Debian-based security-testing environment is recommended.

```bash
git clone https://github.com/KhitMinnyo/KMN-CyberSeek.git
cd KMN-CyberSeek
./start.sh
```

Open `http://localhost:8501`, configure an AI provider in **Settings**, then create a session for an authorized target. Review and approve proposed actions unless you have deliberately configured an isolated lab for automated execution.

The backend listens on port `6000` by default. `start.sh` creates the Python environment, installs dependencies, and starts the backend and dashboard.

## What It Does

- Discovers hosts and services with Nmap and supported local security tools.
- Tracks session jobs, events, findings, and evidence in SQLite.
- Separates observed findings from operator-reviewed verification and retest results.
- Reports assessment completeness separately from objective achievement.
- Provides dashboard and headless CLI workflows, JSON/SARIF exports, and optional API inventory.

Verification is not automatic for every scanner result. Reports distinguish operator review from command/attempt-bound evidence; neither is a substitute for professional validation.

## Configuration

Copy `.env.example` to `.env` only if you need to change defaults. Configure an AI provider, target scope, authentication, and storage through environment variables. Keep API keys, access tokens, encryption keys, and engagement data out of Git.

The backend binds to localhost by default. The legacy `API_AUTH_TOKEN` mode is a single service-admin identity. Multi-user deployments can configure hashed bearer-token principals with `KMN_AUTH_PRINCIPALS_FILE`.

## Documentation

- [Security, evidence, preflight, and operations](docs/reliability.md)
- [Execution sandbox and scope controls](docs/sandbox.md)
- [OpenAPI inventory and assessment coverage](docs/assessment.md)
- [Optional browser observations](docs/browser.md)
- [Features and architecture](features.md)
- [Changelog](change_log.md)

## CLI

`cli.py` is an HTTP client for session status, evidence, inventory, verification, reports, and automation. Configure `KMN_API_URL` and `API_AUTH_TOKEN`, then run `python cli.py --help` for commands. Explicit authorization is required to start a session; full automation is never implied by headless mode.

## Evaluation

Repository benchmark results are self-scored engineering measurements, not independent validation or evidence of superiority over another tool. See [Benchmark Methodology](benchmarks/README.md).

## License

MIT. See [LICENSE](LICENSE).

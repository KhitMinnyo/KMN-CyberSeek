# KMN-CyberSeek

![Version](https://img.shields.io/badge/Version-2.2.3-brightgreen)
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
```

---

## Further Reading

- [Features & Architecture Detail](features.md)
- [Changelog](change_log.md)

---

## Disclaimer

**For authorised security testing and educational purposes only.**

Only use against systems you own or have explicit written permission to test. The developers assume no liability for misuse or damage. `FULL_AUTO_MODE=true` executes destructive commands without confirmation — isolated lab environments only.

---

## License

MIT — see [LICENSE](LICENSE).

# KMN-CyberSeek: AI-Driven Autonomous Red Team Operator

![KMN-CyberSeek Banner](https://img.shields.io/badge/KMN--CyberSeek-AI%20Red%20Team%20Operator-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

**KMN-CyberSeek** is a superior AI-driven autonomous penetration testing framework designed specifically for security professionals. It doesn't just suggest attacks - it actually executes them using strict, advanced methodological approaches with human-in-the-loop approval when needed.

**Official Repository:** [https://github.com/KhitMinnyo/KMN-CyberSeek](https://github.com/KhitMinnyo/KMN-CyberSeek)

**Key Methodology:** KMN-CyberSeek follows strict penetration testing methodologies with context-aware tool selection, mandatory fingerprinting for web applications, and non-interactive execution patterns for complete automation.

## 🔥 Advanced AI Methodologies

KMN-CyberSeek uses sophisticated AI-driven penetration testing methodologies:

### 🎯 Web Application Methodology
- **Mandatory Fingerprinting**: When Port 80/443 is found, FIRST step must be fingerprinting using `curl -I -s` or `whatweb`
- **Context-Aware Tooling**: If fingerprinting reveals 'WordPress', NEXT step must be `wpscan --url <target> --batch --enumerate u,vp,vt`
- **Generic Web Servers**: Use `nikto -h <target> -Tuning 123` or `gobuster` for Apache/Nginx/IIS

### ⚡ Non-Interactive Execution (Critical)
- **Metasploit One-Liner Format**: `msfconsole -q -x "use <module>; set RHOSTS <target>; set LHOST <ip>; exploit -z"`
- **WPScan Always Append `--batch`**: `wpscan --url <target> --batch --enumerate u,vp,vt`
- **Standard Commands**: Always add `-y` or `--force` where applicable (e.g., `apt-get install -y <package>`)

### 🌐 Domain Target Methodology
When the target is a hostname/domain (not a raw IP), KMN-CyberSeek automatically fires a parallel domain recon pipeline:

1. **Passive OSINT** — `whois`, `dig ANY/NS/MX/TXT`, DNS hint extraction
2. **Subdomain Enumeration** — `subfinder`, `amass`, `gobuster dns`, `zone-transfer`, dedup + resolve
3. **Live Web Discovery** — `httpx` to identify live hosts; results parsed into the session's web_applications list automatically
4. **API & Endpoint Discovery** — `ffuf`, Swagger/OpenAPI paths, JS recon (`gau`, `waybackurls`), `arjun`
5. **Vulnerability Scanning** — `nuclei`, `nikto`, `sqlmap` per discovered service
6. **Cloud Surface** — AWS S3, Azure Blob, GCP Storage enumeration; metadata SSRF checks

Tool output from subdomain/web/API tools is **automatically parsed** and stored in session state — the AI's next reasoning step always has the up-to-date attack surface.

### 🎯 Attack Chain Examples
**IP Targets:**
1. **WordPress**: Nmap → whatweb → wpscan → msfconsole
2. **Generic Web**: Nmap → curl → nikto → gobuster → sqlmap
3. **SMB/Port 445**: Nmap → smbclient → crackmapexec → msfconsole (EternalBlue/PrintNightmare)
4. **SSH/Port 22**: Nmap → hydra → searchsploit → msfconsole

**Domain Targets:**
5. **Full Domain Recon**: whois/dig → subfinder → httpx → nuclei → ffuf → exploit chain
6. **Credential Reuse**: Discovered creds → spray via CrackMapExec → Kerberoasting → BloodHound


## 🎯 Recommended Operating System

**KMN-CyberSeek is designed specifically for security-focused operating systems.** 

### Primary Recommendation: Kali Linux
- Pre-installed with all required penetration testing tools
- Full toolchain compatibility (nmap, metasploit, wpscan, etc.)
- Proper environment configuration out of the box
- Best performance and reliability for security testing

### Alternative Security OS Options:
- Parrot Security OS
- BlackArch Linux
- BackBox Linux
- Any Debian/Ubuntu-based distribution with security tools

### ❌ Not Recommended:
- Standard desktop distributions without security tools
- Windows Subsystem for Linux (WSL) - limited tool compatibility
- macOS - requires extensive tool installation and configuration

## 🎯 Core Concept

An autonomous hacking framework that:
- Takes a target IP/Domain
- Performs automated reconnaissance
- Reasons using LLMs (DeepSeek API or local Ollama)
- Executes subsequent exploitation steps automatically
- Maintains session state and context-aware reasoning

## 🏗️ System Architecture

```
KMN-CyberSeek Architecture:
┌─────────────────────────────────────────────────────────────┐
│                    Streamlit Frontend (8501)                │
│                 Real-time Dashboard & Controls              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   FastAPI Backend (8000)                    │
│        Orchestrator │ Scanner │ AI Connector │ Database    │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐     ┌──────────────┐     ┌──────────────┐
│  AI Engine    │     │   Scanner    │     │  Execution   │
│  - DeepSeek   │     │   - Nmap     │     │  Environment │
│  - Ollama     │     │   - VulnScan │     │  (Kali/VM)   │
└───────────────┘     └──────────────┘     └──────────────┘
```

## ✨ Key Features 

### 🚀 Zero-Copy Execution
- System runs terminal commands directly
- Feeds output back to AI without manual input
- Fully automated reconnaissance-to-exploitation pipeline

### 🧠 Context-Aware Reasoning
- AI maintains a "Knowledge Base" of target information
- Remembers open ports, service versions, discovered credentials
- Uses ReAct pattern (Thought-Action-Observation loop)

### 🔄 Self-Healing Attacks
- AI analyzes command failures
- Tries different flags or attack vectors automatically
- Adaptive attack strategies

### 🎨 Modern Web Dashboard
- Target input field with session management
- Real-time terminal output logs
- AI "Thought Process" display
- "Approve/Deny" buttons for sensitive exploits
- Visual kill chain progress tracking

### 🧩 Context-Aware Memory (Local Ollama)
Local models have limited context windows. KMN-CyberSeek handles this automatically with a 4-layer system:
- **Compact system prompt** — when context window < 8 K tokens, a 427-token core prompt replaces the full 4000-token one
- **Episode summaries** — every 5 commands, recent history is compressed into a structured narrative and stored separately; the AI always sees the last 3 episode summaries + current episode
- **Output budget scaling** — command output is truncated to a window-appropriate limit (800 → 12 000 chars) so the model never overflows
- **`num_ctx` passthrough** — the exact context window is sent to Ollama on every request, preventing silent truncation

This is **not needed for DeepSeek API** — the API always receives the full system prompt with no budget limits.

### 🛡️ Operational Integrity
- SQLite database for session persistence
- Evidence collection for reporting
- Action approval workflow (high-risk vs low-risk)
- Automatic evidence logging

## 📋 Installation

### Prerequisites
- Python 3.8+
- Nmap (`apt install nmap` on Kali/Debian)
- An AI backend — either a remote/local [Ollama](https://ollama.ai) instance **or** a [DeepSeek API key](https://platform.deepseek.com)

### Step 1: Clone Repository
```bash
git clone https://github.com/KhitMinnyo/KMN-CyberSeek.git
cd KMN-CyberSeek
```

### Step 2: Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 3: Configure Environment
```bash
cp .env.example .env
# Open .env and set your AI backend (see "AI Configuration" below)
```

### Step 4: Start
```bash
./start.sh
```

That's it. The script creates the venv, installs deps, checks ports, and launches both the FastAPI backend and the Streamlit frontend. Press `Ctrl+C` to stop both.

## 🚀 Quick Start

1. **Access the Dashboard:** Open `http://localhost:8501`
2. **Create New Session:** Enter target IP/domain
3. **Monitor Reconnaissance:** Watch real-time Nmap scans
4. **Review AI Decisions:** See AI's reasoning and suggested commands
5. **Approve/Execute:** Approve low-risk commands, review high-risk ones
6. **Track Progress:** Follow the kill chain stages

## 🧩 Technical Workflow

```
1. Reconnaissance
   └─ Nmap scan via Python subprocess
   
2. Analysis
   └─ Send results to DeepSeek AI
   └─ AI generates JSON with reasoning + command
   
3. Planning
   └─ Risk assessment (low/medium/high)
   └─ Approval workflow decision
   
4. Execution
   └─ Run approved commands
   └─ Capture output
   
5. Iteration
   └─ Feed new data to AI
   └─ Repeat until goal achieved
```

## 🔧 Configuration

### AI Configuration

KMN-CyberSeek supports two AI backends, configured via `.env` or the **Settings** page in the UI.

#### Option A — Remote / local Ollama (default)

Ollama does **not** have to run on the same machine as KMN-CyberSeek. The typical setup is:

| Machine | Role |
|---|---|
| Kali Linux (VM / bare-metal) | Runs KMN-CyberSeek (backend + frontend) |
| Mac M-series (host) | Runs Ollama with your chosen model |

1. On your **Mac**, allow Ollama to accept connections from the network:
   ```bash
   OLLAMA_HOST=0.0.0.0 ollama serve
   ```
2. In `.env` on Kali, point `OLLAMA_URL` at your Mac's LAN IP:
   ```env
   AI_PROVIDER=local
   OLLAMA_URL=http://192.168.1.50:11434   # ← IP of the machine running Ollama
   OLLAMA_MODEL=deepseek-r1:8b
   ```
3. That's all. You can also change these live from the **Settings → AI Configuration** page without restarting.

#### Ollama Model Picker
The **Settings → AI Configuration** page has a live model picker instead of a manual text field:
- **"📋 Load Models"** — queries your Ollama host's `/api/tags` and lists all available models with download size
- **Auto context window detection** — on model selection, KMN-CyberSeek queries `/api/show` and extracts the context window from the model's architecture metadata; falls back to a built-in lookup table of 30+ common models, then 8192 as a safe default
- **Manual override** — tick "Override context window" to set a specific value if the auto-detected one is wrong

> **Model choice** — any model on the Ollama host works. Security-focused options: `deepseek-r1:8b`, `deepseek-coder-v2`, `DeepHat/DeepHat-V1-7B`.

#### Ollama Context Window (`OLLAMA_CONTEXT_WINDOW`)
Set this to match your model's actual `num_ctx`. The system auto-selects the right system prompt and output budget. Ignored when using the DeepSeek API.

```env
OLLAMA_CONTEXT_WINDOW=8192   # 4096 | 8192 | 16384 | 32768 | 65536 | 131072
```

| Value | System prompt | Output budget |
|-------|--------------|---------------|
| < 4 K | Compact (427 tokens) | 800 chars |
| 4 – 8 K | Compact | 2 000 chars |
| 8 – 16 K | Full (4 000 tokens) | 5 000 chars |
| > 16 K | Full | 12 000 chars |

#### Option B — DeepSeek API
```env
AI_PROVIDER=api
DEEPSEEK_API_KEY=sk-...
DEEPSEEK_MODEL=deepseek-chat
```

### Attack Phase Tracking

The session timeline tracks these phases:

| Phase | Description |
|-------|-------------|
| `osint` | Passive intelligence gathering (whois, DNS, crt.sh) |
| `reconnaissance` | Active scanning (Nmap, service fingerprinting) |
| `enumeration` | Subdomain/endpoint/user enumeration |
| `vulnerability_analysis` | CVE mapping, vuln scanning |
| `exploitation` | Exploit execution |
| `post_exploitation` | Shell stabilization, data collection |
| `privilege_escalation` | Local privilege escalation |
| `lateral_movement` | Pivoting to adjacent systems |
| `credential_reuse` | Credential spraying, Kerberoasting |

### Risk Thresholds / Auto-Execute Behavior

By default the AI auto-executes **low/medium** risk commands and routes **high** risk ones to the Approve/Deny queue.

#### FULL_AUTO_MODE

Set `FULL_AUTO_MODE=true` in `.env` (or toggle **Settings → Advanced → Full Auto Mode** in the UI) to let the AI execute every suggested command — including high-risk ones — with no approval gate. The session `authorization_confirmed` flag is the only gate that cannot be bypassed.

```env
FULL_AUTO_MODE=true  # default: false
```

> **Lab networks only.** Only enable this on isolated systems you own or have explicit written permission to test. The AI will execute destructive commands (exploits, lateral movement, data exfiltration simulations) without asking.

### Database
- SQLite database: `kmn_cyberseek.db`
- Automatic session persistence
- Evidence storage
- Command history

## 📁 Project Structure

```
KMN-CyberSeek/
├── main.py                 # FastAPI backend server
├── frontend.py            # Streamlit web dashboard
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── .env.example          # Environment template
├── ai/
│   ├── connector.py      # AI integration (DeepSeek/Ollama)
│   └── prompts.py        # System prompts
├── core/
│   ├── orchestrator.py   # Session and workflow management
│   └── scanner.py        # Nmap and vulnerability scanning
└── kmn_cyberseek.db     # SQLite database (auto-created)
```

## 🔌 API Endpoints

### Backend API (FastAPI)
- `GET /` - API information
- `GET /health` - Health check
- `POST /api/start` - Start new session
- `GET /api/sessions` - List all sessions
- `GET /api/sessions/{id}` - Get session details
- `POST /api/execute` - Execute command
- `POST /api/approve` - Approve/deny command
- `WS /api/ws` - WebSocket for real-time updates

### Frontend (Streamlit)
- `http://localhost:8501` - Main dashboard
- Auto-refresh every 5 seconds
- Real-time WebSocket updates



### Code Structure
```python
# Core components:
# 1. Orchestrator: Manages sessions, coordinates components
# 2. Scanner: Handles reconnaissance (Nmap, vulnerability scans)
# 3. AI Connector: Interfaces with DeepSeek/Ollama
# 4. Frontend: Streamlit UI with real-time updates
```

### Adding New Tools
1. Add tool to scanner module
2. Update AI prompts to recognize tool
3. Add to risk classification
4. Update frontend UI if needed

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

## ⚠️ Disclaimer

**KMN-CyberSeek is for authorized security testing and educational purposes only.**

- The developers assume no liability and are not responsible for any misuse or damage caused by this program
- Only use on systems you own or have explicit permission to test
- Compliance with all applicable laws is the user's responsibility

## 🙏 Acknowledgments

- DeepSeek for their excellent AI models
- Nmap project for the industry-standard scanner
- Streamlit for the amazing dashboard framework
- FastAPI for the high-performance backend

## 📞 Support

- Issues: [GitHub Issues](https://github.com/KhitMinnyo/KMN-CyberSeek/issues)
- Discussions: [GitHub Discussions](https://github.com/KhitMinnyo/KMN-CyberSeek/discussions)
- Documentation: [Wiki](https://github.com/KhitMinnyo/KMN-CyberSeek/wiki)

---

**"Automating the art of penetration testing, one AI decision at a time."**


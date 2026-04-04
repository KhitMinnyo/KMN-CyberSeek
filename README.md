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

### 🎯 Attack Chain Examples
1. **WordPress Target**: Nmap → whatweb → wpscan → msfconsole
2. **Generic Web Server**: Nmap → curl → nikto → gobuster → sqlmap
3. **SMB/Port 445**: Nmap → smbclient → crackmapexec → msfconsole
4. **SSH/Port 22**: Nmap → hydra → searchsploit → msfconsole


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

### 🛡️ Operational Integrity
- SQLite database for session persistence
- Evidence collection for reporting
- Action approval workflow (high-risk vs low-risk)
- Automatic evidence logging

## 📋 Installation

### Prerequisites
- Python 3.8+
- Nmap installed (`brew install nmap` on macOS, `apt install nmap` on Ubuntu)
- Ollama (for local AI) - [Install Ollama](https://ollama.ai)
- DeepSeek API key (optional, for cloud AI)

### Step 1: Clone Repository
```bash
git clone https://github.com/KhitMinnyo/KMN-CyberSeek.git
cd KMN-CyberSeek
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Configure Environment
```bash
cp .env.example .env
# Edit .env with your settings
```

### Step 4: Install Ollama (Optional - for local AI only)
**Note**: This step is ONLY required if you plan to use local AI with Ollama. If you're using DeepSeek API with an API key, you can skip this step.

```bash
# macOS/Linux installation
curl -fsSL https://ollama.ai/install.sh | sh

# Pull DeepSeek model (choose one)
ollama pull deepseek-coder
# OR
ollama pull deepseek-v2
```

### Step 5: Start the System
```bash
# Easy method: Use the startup script (recommended)
./start.sh

# Alternative method: Manual startup in separate terminals
# Terminal 1: Start FastAPI Backend
python main.py

# Terminal 2: Start Streamlit Frontend
streamlit run frontend.py
```

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

### AI Provider Options
1. **Local Ollama** (Default): `provider="local"`
   - Privacy-focused
   - No internet required
   - Use `deepseek-coder` or `deepseek-v2` models

2. **DeepSeek API**: `provider="api"`
   - Higher performance
   - Requires API key
   - Set `DEEPSEEK_API_KEY` in .env

### Risk Thresholds
```python
# Low-risk (auto-execute): nmap, dirb, whois, curl
# Medium-risk (notification): vulnerability scans
# High-risk (manual approval): exploits, brute force
```

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

## 🔒 Security Considerations

### Safe Execution
- Commands run in isolated environment
- High-risk commands require manual approval
- Session timeouts and limits
- Audit logging enabled by default

### Data Protection
- SQLite database with proper permissions
- Optional evidence encryption
- Secure credential handling
- Session isolation

### Ethical Use
- **ONLY** use on systems you own or have permission to test
- Compliance with local laws and regulations
- Proper authorization documentation
- Responsible disclosure practices

## 📈 Roadmap

### Phase 1 (Current)
- [x] Basic reconnaissance automation
- [x] AI integration with DeepSeek
- [x] Streamlit dashboard
- [x] Command approval workflow

### Phase 2 (Next)
- [ ] Active Directory Exploitation & Automation
- [ ] Metasploit automation
- [ ] Advanced evidence collection
- [ ] PDF report generation

### Phase 3 (Future)
- [ ] Multi-target operations
- [ ] Team collaboration features
- [ ] Plugin system for new tools
- [ ] Cloud deployment options

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

### Development Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install development dependencies
pip install -r requirements.txt
pip install black flake8 pytest

# Run code formatter
black .
```

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


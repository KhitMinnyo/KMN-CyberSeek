#!/usr/bin/env python3
"""
KMN-CyberSeek Streamlit Frontend
Web dashboard for AI-driven autonomous red team operations.
"""

APP_VERSION = "2.1.0"

import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Optional

import requests
import streamlit as st
from dotenv import dotenv_values
from streamlit_autorefresh import st_autorefresh
from streamlit_option_menu import option_menu

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Backend API configuration — reads BACKEND_PORT from .env so changing the
# port in one place (.env or start.sh) is enough; no need to edit this file.
_backend_port = int(os.getenv("BACKEND_PORT", "6000"))
BACKEND_URL = f"http://localhost:{_backend_port}"
API_BASE = f"{BACKEND_URL}/api"


def _load_api_token() -> str:
    """Read the shared API_AUTH_TOKEN from .env (the backend generates and
    persists it there on first run). Re-read on every call since Streamlit
    re-executes this module on each rerun, so it self-heals once the backend
    has written the token."""
    env_path = os.path.join(os.getcwd(), ".env")
    if os.path.exists(env_path):
        token = dotenv_values(env_path).get("API_AUTH_TOKEN")
        if token:
            return token
    return os.getenv("API_AUTH_TOKEN", "")


# Shared session so every backend request automatically carries the API key.
# The backend rejects any /api/* request without a matching X-API-Key header.
api_session = requests.Session()
api_session.headers.update({"X-API-Key": _load_api_token()})

# Session selectbox callback functions
def sync_sidebar():
    st.session_state.selected_session = st.session_state.sidebar_select

def sync_main():
    st.session_state.selected_session = st.session_state.main_select

# Page configuration
st.set_page_config(
    page_title="KMN-CyberSeek",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #4CAF50;
        text-align: center;
        margin-bottom: 2rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #2196F3;
        margin-top: 1.5rem;
        margin-bottom: 1rem;
    }
    .session-card {
        background-color: #262730;
        color: #f0f0f0 !important;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
        border-left: 4px solid #4CAF50;
    }
    .command-card {
        background-color: #262730;
        color: #f0f0f0 !important;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 0.5rem;
        border-left: 4px solid #ff9800;
    }
    .high-risk {
        border-left: 4px solid #f44336 !important;
    }
    .medium-risk {
        border-left: 4px solid #ff9800 !important;
    }
    .low-risk {
        border-left: 4px solid #4CAF50 !important;
    }
    .terminal-output {
        background-color: #263238;
        color: #00ff00;
        font-family: 'Courier New', monospace;
        padding: 1rem;
        border-radius: 0.5rem;
        max-height: 400px;
        overflow-y: auto;
        white-space: pre-wrap;
        font-size: 0.9rem;
    }
    .status-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 1rem;
        font-size: 0.8rem;
        font-weight: bold;
        display: inline-block;
        margin-left: 0.5rem;
    }
    .status-initialized { background-color: #2d3748; color: #e2e8f0 !important; }
    .status-scanning { background-color: #975a16; color: #fed7aa !important; }
    .status-analyzing { background-color: #22543d; color: #9ae6b4 !important; }
    .status-executing { background-color: #702459; color: #fbb6ce !important; }
    .status-ready { background-color: #4caf50; color: white; }
    .status-completed { background-color: #388e3c; color: white; }
    .status-failed { background-color: #d32f2f; color: white; }
    /* Ensure markdown text inside cards is readable */
    .session-card p, .session-card li, .session-card td, .session-card th,
    .command-card p, .command-card li, .command-card td, .command-card th {
        color: #f0f0f0 !important;
    }
    .session-card code, .command-card code {
        color: #f0f0f0 !important;
        background-color: rgba(255, 255, 255, 0.1);
    }
</style>
""", unsafe_allow_html=True)

# Session state initialization
if 'selected_session' not in st.session_state:
    st.session_state.selected_session = None
if 'ws_connected' not in st.session_state:
    st.session_state.ws_connected = False
if 'pending_commands' not in st.session_state:
    st.session_state.pending_commands = {}
if 'command_history' not in st.session_state:
    st.session_state.command_history = []
if 'force_nav_to_active' not in st.session_state:
    st.session_state.force_nav_to_active = False


def check_backend_health():
    """Check if backend is available."""
    try:
        response = api_session.get(f"{BACKEND_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        return False


def get_sessions():
    """Get list of active sessions from backend."""
    try:
        response = api_session.get(f"{API_BASE}/sessions", timeout=5)
        if response.status_code == 200:
            return response.json().get("sessions", [])
    except Exception as e:
        logger.error(f"Failed to get sessions: {e}")
    return []


def start_session(target_ip: str, target_domain: str = "", session_name: str = "",
                 auto_approve: bool = False, max_auto_depth: int = 5,
                 authorization_confirmed: bool = False):
    """Start a new session. Returns the parsed response on success, or a dict
    with an "error" key (never raises) so callers can surface the real reason
    a session was rejected (e.g. invalid target, scope, missing authorization)."""
    try:
        payload = {
            "ip": target_ip,
            "domain": target_domain if target_domain else None,
            "session_name": session_name if session_name else None,
            "auto_approve": auto_approve,
            "max_auto_depth": max_auto_depth,
            "authorization_confirmed": authorization_confirmed
        }
        response = api_session.post(f"{API_BASE}/start", json=payload, timeout=30)
        if response.status_code == 200:
            return response.json()
        try:
            detail = response.json().get("detail", response.text)
        except Exception:
            detail = response.text
        logger.error(f"Failed to start session: {response.status_code} {detail}")
        return {"error": detail}
    except Exception as e:
        logger.error(f"Failed to start session: {e}")
        return {"error": str(e)}


def get_session_details(session_id: str):
    """Get details of a specific session."""
    try:
        response = api_session.get(f"{API_BASE}/sessions/{session_id}", timeout=5)
        if response.status_code == 200:
            session_report = response.json()
            session_data = session_report.get("session", {})
            summary = session_report.get("summary", {})

            return {
                **session_data,
                "scan_results": session_report.get("scan_results", []),
                "discovered_hosts": session_report.get("discovered_hosts", []),
                "discovered_services": session_report.get("discovered_services", []),
                "commands_executed": session_report.get("commands_executed", []),
                "ai_decisions": session_report.get("ai_decisions", []),
                "evidence": session_report.get("evidence", []),
                "vulnerabilities": session_report.get("vulnerabilities", []),
                "credentials": session_report.get("credentials", []),
                "summary": summary,
                "discovered_hosts_count": summary.get("total_hosts", len(session_report.get("discovered_hosts", []))),
                "discovered_services_count": summary.get("total_services", len(session_report.get("discovered_services", []))),
                "commands_executed_count": summary.get("total_commands", len(session_report.get("commands_executed", []))),
                "ai_decisions_count": summary.get("ai_decisions_count", len(session_report.get("ai_decisions", []))),
            }
    except Exception as e:
        logger.error(f"Failed to get session details: {e}")
    return None


def get_pending_commands(session_id: str):
    """Get pending commands for a specific session."""
    try:
        response = api_session.get(f"{API_BASE}/sessions/{session_id}/pending_commands", timeout=5)
        if response.status_code == 200:
            return response.json().get("pending_commands", [])
    except Exception as e:
        logger.error(f"Failed to get pending commands: {e}")
    return []


def execute_command(session_id: str, command: str, auto_approve: bool = False):
    """Execute a command in a session."""
    try:
        payload = {
            "session_id": session_id,
            "command": command,
            "auto_approve": auto_approve
        }
        response = api_session.post(f"{API_BASE}/execute", json=payload, timeout=30)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.error(f"Failed to execute command: {e}")
    return None


def approve_command(session_id: str, command_id: str):
    """Approve a pending command."""
    try:
        payload = {
            "session_id": session_id,
            "command_id": command_id,
            "approve": True
        }
        response = api_session.post(f"{API_BASE}/approve", json=payload, timeout=30)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.error(f"Failed to approve command: {e}")
    return None


def deny_command(session_id: str, command_id: str):
    """Deny a pending command."""
    try:
        payload = {
            "session_id": session_id,
            "command_id": command_id,
            "approve": False
        }
        response = api_session.post(f"{API_BASE}/approve", json=payload, timeout=30)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.error(f"Failed to deny command: {e}")
    return None


def resume_session(session_id: str):
    """Manually resume AI analysis for a session."""
    try:
        response = api_session.post(f"{API_BASE}/sessions/{session_id}/resume", timeout=30)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.error(f"Failed to resume session: {e}")
    return None


def get_credentials_api(session_id: str):
    """Fetch captured credentials for a session from the backend."""
    try:
        response = api_session.get(f"{API_BASE}/sessions/{session_id}/credentials", timeout=5)
        if response.status_code == 200:
            return response.json().get("credentials", [])
    except Exception as e:
        logger.error(f"Failed to get credentials: {e}")
    return []


def start_threat_intel_research(topic: str):
    """Kick off AI-directed open-web research for a topic."""
    try:
        response = api_session.post(f"{API_BASE}/threat-intel/research", json={"topic": topic}, timeout=15)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.error(f"Failed to start threat-intel research: {e}")
    return None


def get_threat_intel(topic: str = None):
    """Get cached threat-intel findings, optionally filtered by topic."""
    try:
        params = {"topic": topic} if topic else {}
        response = api_session.get(f"{API_BASE}/threat-intel", params=params, timeout=10)
        if response.status_code == 200:
            return response.json().get("findings", [])
    except Exception as e:
        logger.error(f"Failed to get threat intel: {e}")
    return []


def get_stats_api():
    try:
        r = api_session.get(f"{API_BASE}/stats", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        logger.error(f"get_stats_api: {e}")
    return None


def get_schedules_api():
    try:
        r = api_session.get(f"{API_BASE}/schedules", timeout=5)
        if r.status_code == 200:
            return r.json().get("schedules", [])
    except Exception as e:
        logger.error(f"get_schedules_api: {e}")
    return []


def create_schedule_api(payload: dict):
    try:
        r = api_session.post(f"{API_BASE}/schedules", json=payload, timeout=10)
        if r.status_code == 200:
            return r.json()
        return {"error": r.json().get("detail", r.text)}
    except Exception as e:
        return {"error": str(e)}


def update_schedule_status_api(scan_id: int, status: str):
    try:
        r = api_session.patch(f"{API_BASE}/schedules/{scan_id}", params={"status": status}, timeout=5)
        return r.status_code == 200
    except Exception as e:
        logger.error(f"update_schedule_status: {e}")
        return False


def get_session_history():
    """Get all sessions from DB (including completed/failed) via /api/sessions/history."""
    try:
        response = api_session.get(f"{API_BASE}/sessions/history", timeout=10)
        if response.status_code == 200:
            return response.json().get("sessions", [])
    except Exception as e:
        logger.error(f"Failed to get session history: {e}")
    return []


def complete_session(session_id: str):
    """Mark a session as completed."""
    try:
        response = api_session.post(f"{API_BASE}/sessions/{session_id}/complete", timeout=10)
        if response.status_code == 200:
            return response.json()
        try:
            detail = response.json().get("detail", response.text)
        except Exception:
            detail = response.text
        return {"status": "error", "message": detail}
    except Exception as e:
        logger.error(f"Failed to complete session: {e}")
        return {"status": "error", "message": str(e)}


def main():
    """Main Streamlit application."""
    
    # Auto-refresh every 5 seconds
    st_autorefresh(interval=5000, key="auto_refresh")
    
    # Sidebar navigation
    with st.sidebar:
        st.markdown("## 🛡️ KMN-CyberSeek")
        st.caption(f"v{APP_VERSION} — AI-Driven Red Team Operator")
        st.markdown("---")
        
        # Backend status
        backend_healthy = check_backend_health()
        status_color = "🟢" if backend_healthy else "🔴"
        status_text = "Connected" if backend_healthy else "Disconnected"
        st.markdown(f"### Backend Status: {status_color} {status_text}")

        if not backend_healthy:
            st.warning("Backend is not available. Please start the FastAPI server.")
            if st.button("🔄 Retry Connection"):
                st.rerun()

        # AI status — check .env directly (no extra API call needed)
        if backend_healthy:
            _ev = dotenv_values(".env")
            _provider   = _ev.get("AI_PROVIDER", "").strip()
            _api_key    = _ev.get("DEEPSEEK_API_KEY", "").strip()
            _ollama_mdl = _ev.get("OLLAMA_MODEL", "").strip()
            _bad = ("your_deepseek", "your-api-key", "sk-xxx", "placeholder",
                    "example", "changeme", "insert_key")
            _api_ok   = (_provider == "api" and _api_key and len(_api_key) > 10
                         and not any(p in _api_key.lower() for p in _bad))
            _local_ok = (_provider == "local" and bool(_ollama_mdl))
            _ai_ready = _api_ok or _local_ok
            ai_icon   = "🟢" if _ai_ready else "🟡"
            ai_label  = "AI Ready" if _ai_ready else "AI Not Configured"
            st.markdown(f"**AI Status:** {ai_icon} {ai_label}")
            if not _ai_ready:
                st.caption("⚙️ Settings → AI Configuration")
        
        # Navigation menu
        selected = option_menu(
            menu_title="Navigation",
            options=["Dashboard", "New Session", "Active Sessions", "Command Console",
                     "Threat Intel", "Schedules", "History", "Settings"],
            icons=["speedometer2", "plus-circle", "list-task", "terminal",
                   "search", "calendar-check", "clock-history", "gear"],
            menu_icon="cast",
            default_index=0,
            styles={
                "container": {"padding": "0!important"},
                "icon": {"color": "orange", "font-size": "20px"},
                "nav-link": {"font-size": "16px", "text-align": "left", "margin": "0px"},
                "nav-link-selected": {"background-color": "#4CAF50"},
            }
        )
        
        # Quick stats
        if backend_healthy:
            sessions = get_sessions()
            st.markdown("---")
            st.markdown("### 📊 Quick Stats")
            st.markdown(f"**Active Sessions:** {len(sessions)}")
            
            # Session selector
            if sessions:
                session_options = {s['session_id']: f"{s['target_ip']} ({s['status']})" for s in sessions}
                selected_session_id = st.selectbox(
                    "Select Session:",
                    options=list(session_options.keys()),
                    format_func=lambda x: session_options[x],
                    key="sidebar_select",
                    on_change=sync_sidebar
                )
                st.session_state.selected_session = selected_session_id
            else:
                st.info("No active sessions")
                st.session_state.selected_session = None
        
        st.markdown("---")
        st.markdown("### ℹ️ About")
        st.markdown("""
        KMN-CyberSeek is an AI-driven autonomous red team operator.
        
        **Features:**
        - AI-powered reconnaissance
        - Automated attack execution
        - Real-time monitoring
        - Manual approval workflow
        
        **Version:** {APP_VERSION}
        """)
    
    # Check if force navigation to active sessions is requested
    if st.session_state.force_nav_to_active:
        st.session_state.force_nav_to_active = False
        show_active_sessions()
    else:
        # Main content based on selected navigation
        if selected == "Dashboard":
            show_dashboard()
        elif selected == "New Session":
            show_new_session()
        elif selected == "Active Sessions":
            show_active_sessions()
        elif selected == "Command Console":
            show_command_console()
        elif selected == "Threat Intel":
            show_threat_intel()
        elif selected == "Schedules":
            show_schedules()
        elif selected == "History":
            show_history()
        elif selected == "Settings":
            show_settings()


def show_dashboard():
    """Dashboard — live metrics + charts from /api/stats."""
    st.markdown("<h1 class='main-header'>📊 Dashboard</h1>", unsafe_allow_html=True)

    if not check_backend_health():
        st.error("Backend is not available. Please start the FastAPI server.")
        return

    stats = get_stats_api()
    sessions = get_sessions()  # active in-memory sessions

    # ── Top metrics row ────────────────────────────────────────────────────
    vuln = stats.get("vuln_distribution", {}) if stats else {}
    status_dist = stats.get("status_distribution", {}) if stats else {}

    total_sessions = sum(status_dist.values()) if status_dist else len(sessions)
    total_vulns = sum(vuln.values())
    scanning_now = len([s for s in sessions if s.get("status") == "scanning"])
    pending_cmds = len(st.session_state.get("pending_commands", []))

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Total Sessions", total_sessions)
    m2.metric("Active In-Memory", len(sessions))
    m3.metric("Scanning Now", scanning_now)
    m4.metric("Pending Approvals", pending_cmds)
    m5.metric("Total Vulns", total_vulns)
    m6.metric("Credentials Found", stats.get("credentials_total", 0) if stats else 0)

    st.divider()

    if not stats:
        st.warning("Could not load stats from backend.")
        return

    # ── Charts row 1: vuln distribution + status breakdown ────────────────
    c1, c2 = st.columns(2)

    with c1:
        st.markdown("#### Vulnerability Distribution")
        vuln_labels = ["High", "Medium", "Low", "Info"]
        vuln_values = [vuln.get("high", 0), vuln.get("medium", 0), vuln.get("low", 0), vuln.get("info", 0)]
        if any(vuln_values):
            import pandas as pd
            df_vuln = pd.DataFrame({"Risk": vuln_labels, "Count": vuln_values})
            st.bar_chart(df_vuln.set_index("Risk"))
        else:
            st.info("No vulnerability data yet.")

    with c2:
        st.markdown("#### Session Status Breakdown")
        if status_dist:
            import pandas as pd
            df_status = pd.DataFrame(
                {"Status": list(status_dist.keys()), "Count": list(status_dist.values())}
            )
            st.bar_chart(df_status.set_index("Status"))
        else:
            st.info("No session data yet.")

    # ── Charts row 2: sessions per day timeline ───────────────────────────
    st.markdown("#### Sessions Per Day (Last 14 Days)")
    spd = stats.get("sessions_per_day", [])
    if spd:
        import pandas as pd
        from datetime import datetime, timedelta

        # Fill in missing days so the timeline is continuous
        all_days = {
            (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d"): 0
            for i in range(13, -1, -1)
        }
        for row in spd:
            all_days[row["day"]] = row["count"]
        df_spd = pd.DataFrame({"Date": list(all_days.keys()), "Sessions": list(all_days.values())})
        st.bar_chart(df_spd.set_index("Date"))
    else:
        st.info("No session timeline data yet.")

    # ── Top targets table ────────────────────────────────────────────────
    top_targets = stats.get("top_targets", [])
    if top_targets:
        st.markdown("#### Top Scanned Targets")
        import pandas as pd
        df_top = pd.DataFrame(top_targets)
        df_top.columns = ["Target", "Session Count"]
        st.dataframe(df_top, use_container_width=True, hide_index=True)

    # ── System status ────────────────────────────────────────────────────
    st.divider()
    st.markdown("#### System Status")
    components = {
        "API Server": ("Running", True),
        "Database": ("Connected", True),
        "AI Engine": ("Local (Ollama)", True),
        "Scanner": ("Ready", True),
    }
    sc1, sc2, sc3, sc4 = st.columns(4)
    for col, (name, (label, ok)) in zip([sc1, sc2, sc3, sc4], components.items()):
        icon = "🟢" if ok else "🔴"
        col.markdown(f"{icon} **{name}**  \n{label}")
    
def show_new_session():
    """New session creation page."""
    st.markdown("<h1 class='main-header'>🆕 New Session</h1>", unsafe_allow_html=True)
    
    if not check_backend_health():
        st.error("Backend is not available. Please start the FastAPI server.")
        return
    
    with st.form("new_session_form"):
        st.markdown("<h3 class='sub-header'>🎯 Target Information</h3>", unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            target_ip = st.text_input(
                "Target IP / Domain / Subnet *",
                placeholder="192.168.1.1  or  example.com  or  192.168.1.0/24",
                help="Single IP, hostname, or CIDR subnet (e.g. 192.168.1.0/24). "
                     "For subnets, a ping sweep runs first to discover live hosts."
            )
        
        with col2:
            target_domain = st.text_input(
                "Domain Name (Optional)",
                placeholder="corp.internal",
                help="Optional domain name for the target"
            )
        
        st.markdown("<h3 class='sub-header'>⚙️ Session Configuration</h3>", unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            session_name = st.text_input(
                "Session Name (Optional)",
                placeholder="Pentest-2024-Q1",
                help="Custom name for this session"
            )
        
        with col2:
            scan_type = st.selectbox(
                "Initial Scan Type",
                ["Quick", "Default", "Full", "Stealth"],
                index=1,
                help="Type of initial reconnaissance scan"
            )
        
        # Advanced options
        with st.expander("🔧 Advanced Options"):
            col1, col2 = st.columns(2)
            
            with col1:
                auto_approval = st.checkbox(
                    "Auto-approve low-risk commands",
                    value=True,
                    help="Automatically execute low-risk commands without manual approval"
                )
                
                parallel_scans = st.checkbox(
                    "Enable parallel scanning",
                    value=False,
                    help="Scan multiple targets simultaneously (if applicable)"
                )
            
            with col2:
                evidence_collection = st.checkbox(
                    "Auto-collect evidence",
                    value=True,
                    help="Automatically collect and store evidence from successful commands"
                )
                
                detailed_logging = st.checkbox(
                    "Enable detailed logging",
                    value=False,
                    help="Record detailed logs for debugging and analysis"
                )

        st.markdown("<h3 class='sub-header'>✅ Authorization</h3>", unsafe_allow_html=True)
        authorization_confirmed = st.checkbox(
            "I confirm I own this target or have explicit written authorization to test it, "
            "and I accept responsibility for this engagement.",
            value=False,
            help="Required. KMN-CyberSeek will actively scan and may attempt exploitation against this target."
        )

        st.markdown("---")

        # Submit button
        submit_col1, submit_col2, submit_col3 = st.columns([1, 2, 1])
        with submit_col2:
            submitted = st.form_submit_button(
                "🚀 Start New Session",
                use_container_width=True,
                type="primary"
            )
        
        if submitted:
            if not target_ip:
                st.error("Please enter a target IP address or domain.")
                return
            if not authorization_confirmed:
                st.error("You must confirm authorization to test this target before starting a session.")
                return

            # Show loading spinner
            with st.spinner("Creating new session and starting reconnaissance..."):
                result = start_session(
                    target_ip, target_domain, session_name,
                    auto_approve=auto_approval,
                    authorization_confirmed=authorization_confirmed
                )

                if result and result.get("error"):
                    st.error(f"Failed to create session: {result['error']}")
                elif result:
                    st.success(f"✅ Session created successfully!")
                    st.balloons()
                    
                    # Show session details
                    with st.container():
                        st.markdown("### 📋 Session Details")
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown(f"**Session ID:** `{result['session_id']}`")
                            st.markdown(f"**Target:** `{result['target']}`")
                            st.markdown(f"**Status:** `{result['status']}`")
                        
                        with col2:
                            st.markdown(f"**Message:** {result['message']}")
                            st.markdown(f"**Started:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    # Auto-select this session
                    st.session_state.selected_session = result['session_id']
                    
                    # Show next steps
                    st.markdown("### 👣 Next Steps")
                    st.markdown("""
                    1. **Monitor progress** in the Active Sessions tab
                    2. **Review AI decisions** as they come in
                    3. **Approve/deny** high-risk commands when prompted
                    4. **Execute manual commands** in the Command Console
                    """)
                    
                    # Button to go to active sessions - removed due to Streamlit form constraints
                    # Users can navigate using the sidebar menu
                    st.info("Use the sidebar menu to navigate to Active Sessions")
                else:
                    st.error("Failed to create session. Please check backend logs.")


def show_active_sessions():
    """Active sessions management page."""
    st.markdown("<h1 class='main-header'>📋 Active Sessions</h1>", unsafe_allow_html=True)
    
    if not check_backend_health():
        st.error("Backend is not available. Please start the FastAPI server.")
        return
    
    # Get sessions
    sessions = get_sessions()
    
    if not sessions:
        st.info("👈 Please click on 'New Session' in the sidebar navigation to get started.")
        return
    
    # Session selector
    session_options = {s['session_id']: f"{s['target_ip']} - {s['status']} - {s['session_id'][:8]}" 
                      for s in sessions}
    
    selected_session = st.selectbox(
        "Select Session to Manage:",
        options=list(session_options.keys()),
        format_func=lambda x: session_options[x],
        index=0 if sessions else None
    )
    
    if selected_session:
        st.session_state.selected_session = selected_session
        session_details = get_session_details(selected_session)
        
        if session_details:
            display_session_details(session_details)
        else:
            st.error("Failed to load session details.")
    else:
        st.info("Select a session to view details.")


def display_session_details(session_details: Dict):
    """Display detailed information about a session."""
    # Session header
    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown(f"### Session: `{session_details['session_id']}`")
        st.markdown(f"**Target:** `{session_details['target_ip']}`")
        if session_details.get('target_domain'):
            st.markdown(f"**Domain:** `{session_details['target_domain']}`")
        st.markdown(f"**Created:** {session_details.get('created_at', 'N/A')}")

    with col2:
        status = session_details.get('status', 'unknown')
        status_class = f"status-{status}"
        st.markdown(f"**Status:** <span class='status-badge {status_class}'>{status.upper()}</span>", unsafe_allow_html=True)
        stage_display = session_details.get('current_stage', 'N/A').replace('_', ' ').title()
        st.markdown(f"**Stage:** {stage_display}")

    st.markdown("---")
    
    # Session tabs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(
        ["📊 Overview", "🔍 Scan Results", "🛡️ Vulnerabilities", "🤖 AI Decisions",
         "⚡ Commands", "📁 Evidence", "🔑 Credentials"]
    )

    with tab1:
        show_session_overview(session_details)

    with tab2:
        show_scan_results(session_details)

    with tab3:
        show_vulnerabilities(session_details)

    with tab4:
        show_ai_decisions(session_details)

    with tab5:
        show_commands(session_details)

    with tab6:
        show_evidence(session_details)

    with tab7:
        show_credentials(session_details)


def show_session_overview(session_details: Dict):
    """Show session overview."""
    session_id = session_details.get("session_id")
    
    # Statistics grid
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Hosts Found", session_details.get('discovered_hosts_count', 0))

    with col2:
        st.metric("Services Found", session_details.get('discovered_services_count', 0))

    with col3:
        st.metric("Commands Executed", session_details.get('commands_executed_count', 0))

    with col4:
        st.metric("AI Decisions", session_details.get('ai_decisions_count', 0))

    st.markdown("---")

    # Check if session is in analyzing state and show loading indicator
    if session_details.get("status") == "analyzing":
        st.info("⏳ **AI is analyzing vulnerabilities and formulating the attack plan...**")
        st.markdown("<br>", unsafe_allow_html=True)

    status = session_details.get("status", "").lower()

    in_progress = status in ("scanning", "analyzing", "executing")
    has_data = (
        session_details.get("discovered_hosts_count", 0) > 0
        or session_details.get("commands_executed_count", 0) > 0
    )

    if in_progress:
        st.button(f"⏳ {status.title()} in progress...", disabled=True, use_container_width=True)
        if status == "executing":
            try:
                live_resp = api_session.get(f"{API_BASE}/sessions/{session_id}/live_output", timeout=3)
                if live_resp.status_code == 200:
                    live_data = live_resp.json()
                    if live_data.get("is_live") and live_data.get("live_output"):
                        st.markdown("##### 📡 Live Output (streaming)")
                        st.markdown(
                            f"<div class='terminal-output'>{live_data['live_output']}</div>",
                            unsafe_allow_html=True
                        )
            except Exception:
                pass
    else:
        btn_col1, btn_col2, btn_col3 = st.columns(3)

        with btn_col1:
            if status == "initialized" and not has_data:
                label, tip = "🚀 Start", "Run initial nmap scan and begin AI analysis"
                endpoint = f"{API_BASE}/sessions/{session_id}/start"
            else:
                label, tip = "▶️ Resume", "Continue AI analysis from current scan data (no re-scan)"
                endpoint = f"{API_BASE}/sessions/{session_id}/resume"
            if st.button(label, help=tip, type="primary", use_container_width=True):
                api_session.post(endpoint)
                time.sleep(0.5)
                st.rerun()

        with btn_col2:
            if st.button("🔄 Restart", help="Clear all data and re-run nmap scan from scratch",
                         use_container_width=True):
                api_session.post(f"{API_BASE}/sessions/{session_id}/restart")
                time.sleep(0.5)
                st.rerun()

        with btn_col3:
            if st.button("🗑️ Delete", help="Permanently delete this session and all its data",
                         use_container_width=True):
                response = api_session.delete(f"{API_BASE}/sessions/{session_id}")
                if response.status_code == 200:
                    st.session_state.selected_session = None
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error(f"Failed to delete session: {response.status_code}")

    # Report download
    if st.button("📄 Download DOCX Report", use_container_width=True):
        with st.spinner("Generating report…"):
            try:
                resp = api_session.get(f"{API_BASE}/sessions/{session_id}/report", timeout=60)
                if resp.status_code == 200:
                    st.download_button(
                        label="💾 Save DOCX",
                        data=resp.content,
                        file_name=f"kmn_report_{session_id[:12]}.docx",
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        use_container_width=True,
                    )
                else:
                    st.error(f"Report generation failed ({resp.status_code}): {resp.text[:200]}")
            except Exception as e:
                st.error(f"Could not reach backend: {e}")
    
    # Session timeline - dynamically determined based on current_stage
    st.markdown("### 📅 Session Timeline")
    
    # Get current stage from session details
    current_stage = session_details.get('current_stage', '').lower()
    
    # Define the typical flow of stages - must match AI's attack_phase outputs exactly
    stages = [
        {"event": "Session created",       "stage_key": "created"},
        {"event": "OSINT",                 "stage_key": "osint"},
        {"event": "Reconnaissance",        "stage_key": "reconnaissance"},
        {"event": "Enumeration",           "stage_key": "enumeration"},
        {"event": "Vulnerability Analysis","stage_key": "vulnerability_analysis"},
        {"event": "Exploitation",          "stage_key": "exploitation"},
        {"event": "Post-Exploitation",     "stage_key": "post_exploitation"},
        {"event": "Privilege Escalation",  "stage_key": "privilege_escalation"},
        {"event": "Lateral Movement",      "stage_key": "lateral_movement"},
        {"event": "Credential Reuse",      "stage_key": "credential_reuse"},
    ]
    
    # Determine status for each stage based on current_stage
    timeline_data = []
    
    # Find the index of the current stage in the stages array
    current_stage_index = None
    for i, stage in enumerate(stages):
        if current_stage == stage["stage_key"]:
            current_stage_index = i
            break
    
    for i, stage in enumerate(stages):
        # Determine status first, then derive label from it
        if i == 0:
            status = "completed"
        elif current_stage_index is None:
            if i == 1 and session_details.get('discovered_hosts_count', 0) > 0:
                status = "in_progress"
            else:
                status = "pending"
        elif i < current_stage_index:
            status = "completed"
        elif i == current_stage_index:
            status = "in_progress"
        else:
            status = "pending"

        # Derive time label from status
        if i == 0:
            time_label = session_details.get('created_at', 'N/A')
        elif status == "completed":
            time_label = "Done"
        elif status == "in_progress":
            time_label = "Now"
        else:
            time_label = "Next"

        timeline_data.append({
            "time": time_label,
            "event": stage["event"],
            "status": status
        })
    
    for item in timeline_data:
        status_icon = "✅" if item["status"] == "completed" else "🔄" if item["status"] == "in_progress" else "⏳"
        st.markdown(f"{status_icon} **{item['time']}** - {item['event']}")

    # ── Strategic Layer Panel ──────────────────────────────────────────────────
    objective = session_details.get("objective", "")
    progress  = session_details.get("objective_progress", 0.0)
    prog_note = session_details.get("objective_progress_note", "")
    complete  = session_details.get("objective_complete", False)
    plan      = session_details.get("strategic_plan", [])
    refs      = session_details.get("reflections", [])

    if objective or plan or refs:
        st.markdown("---")
        st.markdown("### 🧠 Strategic Layer (AI Planner)")

        # Objective + progress bar
        if objective:
            if complete:
                st.success(f"✅ **OBJECTIVE COMPLETE** — {objective}")
            else:
                st.info(f"🎯 **Objective:** {objective}")
            pct = int(progress * 100)
            st.progress(progress, text=f"Progress: {pct}% — {prog_note or 'n/a'}")

        # Strategic plan steps
        if plan:
            st.markdown("**Current Plan:**")
            for i, step in enumerate(plan, 1):
                step_status = step.get("status", "pending")
                icon = "✅" if step_status == "done" else "🔄" if step_status == "in_progress" else "⏳"
                rationale = step.get("rationale", "")
                st.markdown(
                    f"{icon} **{i}.** {step.get('step', '')}  \n"
                    + (f"  ↳ *{rationale}*" if rationale else ""),
                    unsafe_allow_html=False,
                )

        # Latest reflection
        if refs:
            with st.expander("💬 Latest Strategist Reflection"):
                # Show last 3 reflections newest-first
                for r in reversed(refs[-3:]):
                    st.markdown(f"- {r}")


def show_scan_results(session_details: Dict):
    """Show scan results."""
    discovered_hosts = session_details.get("discovered_hosts", [])

    if not discovered_hosts:
        st.info("No discovered hosts are available for this session yet.")
        return

    for host in discovered_hosts:
        host_label = host.get("host") or host.get("ip") or "Unknown Host"
        ports = host.get("ports", [])

        with st.expander(f"🔍 {host_label} ({len(ports)} open ports)"):
            st.markdown(f"**IP:** `{host.get('ip', 'Unknown')}`")
            if host.get("hostname"):
                st.markdown(f"**Hostname:** `{host['hostname']}`")
            st.markdown(f"**Status:** {host.get('status', 'unknown').upper()}")
            if host.get("os_guess"):
                st.markdown(f"**OS Guess:** {host['os_guess']}")

            if not ports:
                st.caption("No open ports recorded for this host.")
                continue

            for port in ports:
                port_number = port.get("port", 0)
                risk = "high" if port_number in [445, 139] else "medium" if port_number == 22 else "low"
                risk_class = f"{risk}-risk"

                st.markdown(f"""
                <div class='command-card {risk_class}'>
                    <strong>Port {port_number}/{port.get('protocol', 'tcp')}</strong><br>
                    Service: {port.get('service', 'unknown')}<br>
                    Version: {port.get('version') or 'Unknown'}<br>
                    State: {port.get('state', 'unknown')}<br>
                    Risk: <strong>{risk.upper()}</strong>
                </div>
                """, unsafe_allow_html=True)


def show_vulnerabilities(session_details: Dict):
    """Show structured vulnerability findings (Nmap NSE vuln scripts + optional
    Vulners CVE enrichment - see core/orchestrator.py _run_vulnerability_analysis)."""
    vulnerabilities = session_details.get("vulnerabilities", [])

    if not vulnerabilities:
        session_status = session_details.get("status", "")
        if session_status in ("scanning", "analyzing", "executing"):
            st.info("⏳ Vulnerability scan in progress — findings will appear here automatically.")
        else:
            st.info(
                "No vulnerability findings for this target. This is normal if the target has "
                "no services vulnerable to Nmap NSE vuln scripts. "
                "CVE enrichment via Vulners requires `VULNERS_API_KEY` in Settings. "
                "Use the **Threat Intel** tab to manually research specific services."
            )
        return

    high = [v for v in vulnerabilities if v.get("risk_level") == "high"]
    medium = [v for v in vulnerabilities if v.get("risk_level") == "medium"]
    low = [v for v in vulnerabilities if v.get("risk_level") == "low"]

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Findings", len(vulnerabilities))
    with col2:
        st.metric("High Risk", len(high))
    with col3:
        st.metric("Medium Risk", len(medium))
    with col4:
        st.metric("Low Risk", len(low))

    st.markdown("---")

    # Highest risk first
    risk_order = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    sorted_vulns = sorted(vulnerabilities, key=lambda v: risk_order.get(v.get("risk_level"), 3))

    for v in sorted_vulns:
        risk = v.get("risk_level", "unknown")
        risk_class = f"{risk}-risk" if risk in ("high", "medium", "low") else ""
        cve_ids = v.get("cve_ids") or []
        cve_label = ", ".join(cve_ids) if cve_ids else "No CVE assigned"
        location = f"{v.get('host', '?')}:{v.get('port')}" if v.get("port") else v.get("host", "?")

        with st.expander(f"{'🔴' if risk=='high' else '🟠' if risk=='medium' else '🟢'} {v.get('name', 'Unnamed finding')} — {cve_label}"):
            st.markdown(f"""
            <div class='command-card {risk_class}'>
                <strong>Location:</strong> {location} ({v.get('service') or 'unknown service'} {v.get('service_version') or ''})<br>
                <strong>Risk:</strong> {risk.upper()}{f" (CVSS {v['cvss_score']})" if v.get('cvss_score') is not None else ""}<br>
                <strong>CVE(s):</strong> {cve_label}<br>
                <strong>Source:</strong> {v.get('source_tool', 'unknown')}<br>
                <strong>Status:</strong> {v.get('status', 'confirmed')}<br>
                <strong>Discovered:</strong> {v.get('discovered_at', 'Unknown')}
            </div>
            """, unsafe_allow_html=True)

            if v.get("description"):
                st.markdown("**Description:**")
                st.write(v["description"])

            refs = v.get("reference_urls") or []
            if refs:
                st.markdown("**References:**")
                for url in refs:
                    st.markdown(f"- {url}")


def show_ai_decisions(session_details: Dict):
    """Show AI command log — compact list with notable findings surfaced."""
    ai_decisions = session_details.get("ai_decisions", [])
    commands_executed = session_details.get("commands_executed", [])

    if not ai_decisions:
        st.info("AI decisions will appear here as the AI analyzes scan results.")
        return

    # Build lookup: command string -> execution record
    cmd_lookup: Dict = {}
    for rec in commands_executed:
        key = (rec.get("command") or "").strip()
        if key:
            cmd_lookup[key] = rec

    _notable_kw = [
        "password", "credential", "hash", "token", "secret", "api_key",
        "vulnerability", "cve-", "found", "admin", "root", "shell",
        "exploit", "login successful", "authentication success",
    ]

    risk_icon = {"low": "🟢", "medium": "🟡", "high": "🔴"}

    # --- Notable findings (top) -------------------------------------------
    notable = []
    for dec in ai_decisions:
        cmd = (dec.get("suggested_command") or "").strip()
        rec = cmd_lookup.get(cmd)
        if rec and rec.get("success"):
            out = ((rec.get("output") or "") + (rec.get("error") or "")).lower()
            if any(kw in out for kw in _notable_kw):
                notable.append((dec, rec))

    if notable:
        st.markdown("### 🔍 Notable Findings")
        for dec, rec in notable:
            cmd = dec.get("suggested_command", "")
            out = (rec.get("output") or "").strip()
            phase = dec.get("attack_phase", dec.get("context", ""))
            st.markdown(f"**`{cmd}`** — _{phase}_")
            st.code(out[:2000] + ("…" if len(out) > 2000 else ""), language="text")
        st.markdown("---")

    # --- Compact command log ------------------------------------------------
    st.markdown(f"### 🤖 AI Command Log &nbsp; `{len(ai_decisions)} decisions`")

    for index, decision in enumerate(reversed(ai_decisions), start=1):
        cmd = (decision.get("suggested_command") or "no command").strip()
        risk = str(decision.get("risk_level", "unknown")).lower()
        phase = decision.get("attack_phase", decision.get("context", "—"))
        ts = (decision.get("timestamp") or "")[:16].replace("T", " ")
        icon = risk_icon.get(risk, "⚪")

        rec = cmd_lookup.get(cmd)
        if rec is None:
            status_icon = "⏳"
        elif rec.get("success"):
            status_icon = "✅"
        else:
            status_icon = "❌"

        label = (
            f"{status_icon} {icon} `{cmd[:90]}{'…' if len(cmd) > 90 else ''}`"
            f" — {phase} &nbsp; `{ts}`"
        )
        with st.expander(label, expanded=False):
            st.caption(f"Risk: **{risk.upper()}**  ·  Phase: **{phase}**  ·  {ts}")
            if rec is not None:
                out = (rec.get("output") or "").strip()
                if out:
                    st.code(out[:3000] + ("…" if len(out) > 3000 else ""), language="text")
                elif rec.get("error"):
                    st.code((rec.get("error") or "")[:1000], language="text")
                else:
                    st.caption("_No output captured._")
            else:
                st.caption("_Pending execution._")
            with st.expander("🧠 AI Reasoning", expanded=False):
                st.text(decision.get("reasoning") or "No reasoning recorded.")


def show_commands(session_details: Dict):
    """Show command execution history and pending commands."""
    st.markdown("### ⏳ Pending Commands")

    pending_commands = get_pending_commands(session_details["session_id"])

    for cmd in pending_commands:
        risk = cmd.get("risk_level")
        if not risk:
            risk = "high" if cmd.get("requires_approval") else "low"
        risk_class = f"{risk}-risk"

        col1, col2 = st.columns([3, 1])

        with col1:
            st.markdown(f"""
            <div class='command-card {risk_class}'>
                <strong>Command ID:</strong> <code>{cmd['command_id']}</code><br>
                <strong>Command:</strong> <code>{cmd['command']}</code><br>
                <strong>Risk:</strong> {risk.upper()}<br>
                <strong>Queued:</strong> {cmd.get('timestamp', 'Unknown')}
            </div>
            """, unsafe_allow_html=True)

        with col2:
            approve_col, deny_col = st.columns(2)
            with approve_col:
                if st.button("✅", key=f"approve_{cmd['command_id']}", help="Approve command"):
                    result = approve_command(session_details["session_id"], cmd["command_id"])
                    if result:
                        st.success(f"Command {cmd['command_id']} approved.")
                        st.rerun()
                    else:
                        st.error("Failed to approve command.")
            with deny_col:
                if st.button("❌", key=f"deny_{cmd['command_id']}", help="Deny command"):
                    result = deny_command(session_details["session_id"], cmd["command_id"])
                    if result:
                        st.warning(f"Command {cmd['command_id']} denied.")
                        st.rerun()
                    else:
                        st.error("Failed to deny command.")

    if not pending_commands:
        st.info("No pending commands requiring approval.")

    st.markdown("---")
    st.markdown("### 📜 Command History")

    command_history = session_details.get("commands_executed", [])

    # ── Search / filter bar ────────────────────────────────────────────────
    sf1, sf2 = st.columns([3, 1])
    with sf1:
        search_kw = st.text_input(
            "🔍 Search commands & output",
            placeholder="e.g. 80/tcp, login, hydra …",
            key=f"cmd_search_{session_details.get('session_id', '')}",
            label_visibility="collapsed",
        )
    with sf2:
        filter_status = st.selectbox(
            "Status",
            ["All", "Success", "Failed"],
            key=f"cmd_filter_{session_details.get('session_id', '')}",
            label_visibility="collapsed",
        )

    # Apply filters
    filtered = command_history
    if filter_status == "Success":
        filtered = [c for c in filtered if c.get("success")]
    elif filter_status == "Failed":
        filtered = [c for c in filtered if not c.get("success")]
    if search_kw:
        kw_lower = search_kw.lower()
        filtered = [
            c for c in filtered
            if kw_lower in (c.get("command") or "").lower()
            or kw_lower in (c.get("output") or "").lower()
            or kw_lower in (c.get("error") or "").lower()
        ]

    st.caption(f"Showing {len(filtered)} / {len(command_history)} commands")

    for cmd in filtered:
        success = cmd.get("success", False)
        status_icon = "✅" if success else "❌"
        status_label = "success" if success else "failed"
        command_preview = cmd.get("command", "Unknown command")

        with st.expander(f"{status_icon} {command_preview[:80]}"):
            st.markdown(f"**Command:** `{command_preview}`")
            st.markdown(f"**Status:** {status_label}")
            st.markdown(f"**Timestamp:** {cmd.get('timestamp', 'Unknown')}")
            st.markdown(f"**Return Code:** {cmd.get('return_code', 'N/A')}")
            st.markdown("**Output:**")
            output_text = cmd.get("output") or "No stdout captured."
            # Highlight search keyword in displayed output
            if search_kw and search_kw.lower() in output_text.lower():
                # Show a snippet around the first match for large outputs
                idx = output_text.lower().find(search_kw.lower())
                start = max(0, idx - 200)
                end = min(len(output_text), idx + 500)
                snippet = output_text[start:end]
                if start > 0:
                    snippet = "…" + snippet
                if end < len(output_text):
                    snippet = snippet + "…"
                st.code(snippet, language="text")
                if len(output_text) > 700:
                    with st.expander("Show full output"):
                        st.code(output_text, language="text")
            else:
                st.code(output_text, language="text")
            if cmd.get("error"):
                st.markdown("**Error:**")
                st.code(cmd["error"], language="text")

    if not filtered:
        if search_kw or filter_status != "All":
            st.info("No commands match the current filter.")
        else:
            st.info("No commands have been executed for this session yet.")

    st.markdown("---")
    st.markdown("### 💻 Manual Command Execution")
    
    # Manual command execution
    manual_command = st.text_area(
        "Enter command to execute:",
        placeholder="nmap -sV 192.168.1.1",
        height=100
    )
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        auto_approve = st.checkbox("Auto-approve", value=True)

    with col2:
        if st.button("▶️ Execute", use_container_width=True) and manual_command:
            result = execute_command(session_details["session_id"], manual_command, auto_approve)
            if not result:
                st.error("Failed to submit command.")
            elif result.get("status") == "pending_approval":
                st.info(f"Command submitted for approval. ID: {result.get('command_id')}")
            else:
                st.success("Command executed successfully.")
            st.rerun()

    with col3:
        st.caption("Uncheck Auto-approve to queue for manual review before execution.")


def show_evidence(session_details: Dict):
    """Show collected evidence."""
    st.info("Evidence collection is automatic. All successful command outputs are stored as evidence.")
    
    # Get real evidence from backend
    evidence_list = session_details.get('evidence', [])
    commands_executed = session_details.get('commands_executed', [])
    
    # Filter successful commands to only show "interesting" artifacts
    noise_commands = ['curl -i', 'curl -s', 'whatweb', 'ping', 'whoami', 'id', 'pwd']
    interesting_artifacts = []
    
    for cmd in commands_executed:
        if not cmd.get('success', False):
            continue
            
        cmd_text = cmd.get('command', '').lower()
        output_len = len(cmd.get('output', ''))
        
        # Check if it's a basic noise command
        is_noise = any(noise in cmd_text for noise in noise_commands)
        
        # Include it if it's NOT noise, OR if it produced a significantly large output (potential finding)
        if not is_noise or output_len > 500:
            interesting_artifacts.append(cmd)
            
    # Check if we have any evidence or successful commands
    if not evidence_list and not interesting_artifacts:
        st.info("No evidence or significant artifacts collected yet.")
        return
    
    # Display evidence
    if evidence_list:
        st.markdown(f"### 📁 Collected Evidence ({len(evidence_list)} items)")
        for i, evidence in enumerate(evidence_list):
            with st.expander(f"Evidence #{i+1} - {evidence.get('type', 'Unknown')}"):
                st.markdown(f"**Type:** {evidence.get('type', 'N/A')}")
                st.markdown(f"**Description:** {evidence.get('description', 'No description')}")
                st.markdown(f"**Timestamp:** {evidence.get('timestamp', 'Unknown')}")
                st.markdown("**Content:**")
                st.code(evidence.get('content', 'No content available'), language="text")
    else:
        st.info("No evidence items collected yet.")
    
    # Display successful command outputs as artifacts
    if interesting_artifacts:
        st.markdown("---")
        st.markdown(f"### 📋 Significant Command Artifacts ({len(interesting_artifacts)} items)")
        for cmd in interesting_artifacts:
            with st.expander(f"✅ {cmd.get('command', 'Unknown command')[:50]}..."):
                st.markdown(f"**Command:** `{cmd.get('command', 'Unknown')}`")
                st.markdown(f"**Timestamp:** {cmd.get('timestamp', 'Unknown')}")
                st.markdown(f"**Return Code:** {cmd.get('return_code', 'N/A')}")
                st.markdown("**Output:**")
                st.code(cmd.get('output', 'No output captured.'), language="text")
                if cmd.get('error'):
                    st.markdown("**Error:**")
                    st.code(cmd['error'], language="text")
    else:
        st.info("No significant command artifacts available.")
    
    st.markdown("---")
    st.markdown("### 📤 Evidence Export")

    sid = session_details.get("session_id", "")
    col1, col2, col3 = st.columns(3)

    # ── JSON export ────────────────────────────────────────────────────────
    with col1:
        if st.button("📄 Export as JSON", use_container_width=True):
            import json as _json
            payload = {
                "session_id": sid,
                "target_ip": session_details.get("target_ip"),
                "created_at": session_details.get("created_at"),
                "status": session_details.get("status"),
                "vulnerabilities": session_details.get("vulnerabilities", []),
                "commands_executed": session_details.get("commands_executed", []),
                "ai_decisions": session_details.get("ai_decisions", []),
                "discovered_services": session_details.get("discovered_services", []),
                "credentials": session_details.get("credentials", []),
            }
            st.download_button(
                label="💾 Save JSON",
                data=_json.dumps(payload, indent=2, default=str),
                file_name=f"kmn_report_{sid[:12]}.json",
                mime="application/json",
                use_container_width=True,
            )

    # ── PDF export ─────────────────────────────────────────────────────────
    with col2:
        if st.button("📊 Export as PDF", use_container_width=True):
            with st.spinner("Generating PDF…"):
                try:
                    resp = api_session.get(f"{API_BASE}/sessions/{sid}/report/pdf", timeout=60)
                    if resp.status_code == 200:
                        st.download_button(
                            label="💾 Save PDF",
                            data=resp.content,
                            file_name=f"kmn_report_{sid[:12]}.pdf",
                            mime="application/pdf",
                            use_container_width=True,
                        )
                    elif resp.status_code == 501:
                        st.warning("fpdf2 not installed on backend. Run: pip install fpdf2")
                    else:
                        st.error(f"PDF generation failed ({resp.status_code}): {resp.text[:200]}")
                except Exception as e:
                    st.error(f"Could not reach backend: {e}")

    # ── HTML report export ─────────────────────────────────────────────────
    with col3:
        if st.button("🌐 Export as HTML", use_container_width=True):
            vulns = session_details.get("vulnerabilities", [])
            services = session_details.get("discovered_services", [])
            creds = session_details.get("credentials", [])
            cmds = session_details.get("commands_executed", [])

            _rc = {"high": "#d32f2f", "medium": "#f57f17", "low": "#2e7d32"}
            _risk_order = {"high": 0, "medium": 1, "low": 2}

            def _vuln_row(v):
                rl = v.get("risk_level", "")
                color = _rc.get(rl, "#555")
                return (
                    f"<tr><td style='color:{color}'><b>{rl.upper()}</b></td>"
                    f"<td>{v.get('name','')}</td><td>{v.get('host','')}</td>"
                    f"<td>{v.get('port','')}</td><td>{v.get('service','')}</td></tr>"
                )

            def _cred_row(c):
                secret = "*" * 8 if c.get("secret_type") == "password" else c.get("secret", "")[:30]
                return (
                    f"<tr><td>{c.get('username','')}</td><td><code>{secret}</code></td>"
                    f"<td>{c.get('secret_type','')}</td><td>{c.get('service','')}</td></tr>"
                )

            def _cmd_row(c):
                ok = "✓" if c.get("success") else "✗"
                return (
                    f"<tr><td>{ok}</td>"
                    f"<td><code>{c.get('command','')[:120]}</code></td>"
                    f"<td>{c.get('timestamp','')}</td></tr>"
                )

            vuln_rows = "".join(
                _vuln_row(v)
                for v in sorted(vulns, key=lambda x: _risk_order.get(x.get("risk_level", ""), 3))
            )
            svc_rows = "".join(
                f"<tr><td>{s.get('host','')}</td><td>{s.get('port','')}</td>"
                f"<td>{s.get('service','')}</td><td>{s.get('version','')}</td></tr>"
                for s in services[:50]
            )
            cred_rows = "".join(_cred_row(c) for c in creds)
            cmd_rows  = "".join(_cmd_row(c)  for c in cmds[-30:])

            html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>KMN-CyberSeek Report — {session_details.get('target_ip','')}</title>
<style>
  body{{font-family:sans-serif;margin:2rem;color:#222;}}
  h1{{background:#1a237e;color:#fff;padding:1rem;border-radius:4px;}}
  h2{{background:#37474f;color:#fff;padding:.5rem .8rem;border-radius:3px;margin-top:2rem;}}
  table{{border-collapse:collapse;width:100%;margin-bottom:1rem;}}
  th{{background:#eceff1;text-align:left;padding:.4rem .6rem;border:1px solid #ccc;}}
  td{{padding:.35rem .6rem;border:1px solid #ddd;font-size:.9em;}}
  .meta td:first-child{{font-weight:bold;width:160px;}}
  footer{{margin-top:3rem;font-size:.8em;color:#888;border-top:1px solid #ddd;padding-top:.5rem;}}
</style></head>
<body>
<h1>KMN-CyberSeek &mdash; Penetration Test Report</h1>
<table class="meta">
  <tr><td>Session ID</td><td>{sid[:12]}</td></tr>
  <tr><td>Target</td><td>{session_details.get('target_ip','—')}</td></tr>
  <tr><td>Status</td><td>{session_details.get('status','—')}</td></tr>
  <tr><td>Started</td><td>{session_details.get('created_at','—')}</td></tr>
  <tr><td>Vulns (H/M/L)</td><td>{sum(1 for v in vulns if v.get("risk_level")=="high")} / {sum(1 for v in vulns if v.get("risk_level")=="medium")} / {sum(1 for v in vulns if v.get("risk_level")=="low")}</td></tr>
</table>
<h2>Vulnerabilities ({len(vulns)})</h2>
<table><tr><th>Risk</th><th>Name</th><th>Host</th><th>Port</th><th>Service</th></tr>{vuln_rows or "<tr><td colspan='5'>None found</td></tr>"}</table>
<h2>Discovered Services ({len(services)})</h2>
<table><tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th></tr>{svc_rows or "<tr><td colspan='4'>None</td></tr>"}</table>
<h2>Credentials ({len(creds)})</h2>
<table><tr><th>Username</th><th>Secret</th><th>Type</th><th>Service</th></tr>{cred_rows or "<tr><td colspan='4'>None captured</td></tr>"}</table>
<h2>Commands Log (last 30)</h2>
<table><tr><th>OK</th><th>Command</th><th>Timestamp</th></tr>{cmd_rows or "<tr><td colspan='3'>None</td></tr>"}</table>
<footer>Generated by KMN-CyberSeek &mdash; FOR AUTHORISED USE ONLY</footer>
</body></html>"""
            st.download_button(
                label="💾 Save HTML",
                data=html,
                file_name=f"kmn_report_{sid[:12]}.html",
                mime="text/html",
                use_container_width=True,
            )


def show_command_console():
    """Command console for manual execution."""
    st.markdown("<h1 class='main-header'>💻 Command Console</h1>", unsafe_allow_html=True)

    if not check_backend_health():
        st.error("Backend is not available. Please start the FastAPI server.")
        return

    # Session selection
    sessions = get_sessions()
    if not sessions:
        st.info("👈 Please click on 'New Session' in the sidebar navigation to get started.")
        return

    session_options = {s['session_id']: f"{s['target_ip']} ({s['status']})" for s in sessions}
    selected_session = st.selectbox(
        "Select Session:",
        options=list(session_options.keys()),
        format_func=lambda x: session_options[x],
        key="command_console_session_select"
    )

    if selected_session:
        st.session_state.selected_session = selected_session

        # Fetch real session data using get_session_details as requested
        session_details = get_session_details(selected_session)
        if not session_details:
            st.error("Failed to load session details. Please try again.")
            return

        # Extract base info securely to avoid KeyErrors
        base_info = session_details.get('session', session_details)

        # Command input
        st.markdown("### ⌨️ Command Input")

        col1, col2 = st.columns([3, 1])

        with col1:
            command = st.text_input(
                "Enter command:",
                placeholder="nmap -sV 192.168.1.1",
                label_visibility="collapsed"
            )

        with col2:
            auto_approve = st.checkbox("Auto-approve", value=True,
                                       help="Execute immediately. Uncheck to queue for manual approval.")

        # Execute button
        execute_clicked = st.button("▶️ Execute Command", type="primary", use_container_width=True)
        if execute_clicked and command:
            with st.spinner("Executing command..."):
                result = execute_command(selected_session, command, auto_approve)

                if result:
                    if result.get('status') == 'pending_approval':
                        st.warning(f"Command requires approval. Command ID: {result.get('command_id')}")
                        st.session_state.pending_commands[result.get('command_id')] = {
                            'session_id': selected_session,
                            'command': command
                        }
                    else:
                        st.success(f"Command executed successfully!")
                        # Add to history
                        st.session_state.command_history.append({
                            'timestamp': datetime.now().isoformat(),
                            'session_id': selected_session,
                            'command': command,
                            'result': result
                        })
                    st.rerun()  # Refresh UI immediately after execution
                else:
                    st.error("Failed to execute command. Check backend logs.")
                    st.rerun()

        st.markdown("---")

        # Terminal output - Show real output from most recent command
        st.markdown("### 📟 Terminal Output")

        # Display actual command output from the most recent command in session details
        if session_details:
            commands_executed = session_details.get('commands_executed', [])
            if commands_executed:
                # Find the most recent command (assuming commands are ordered chronologically)
                most_recent = commands_executed[-1]
                terminal_output = f"$ {most_recent.get('command', 'Unknown command')}\n"
                output = most_recent.get('output', '')
                if output:
                    terminal_output += f"Output:\n{output}"
                error = most_recent.get('error', '')
                if error:
                    terminal_output += f"\n\nError:\n{error}"
                if not output and not error:
                    terminal_output += "No output captured."
                
                # Add status and return code info
                success = most_recent.get('success', False)
                return_code = most_recent.get('return_code', 'N/A')
                status_line = f"\n\n[Status: {'✅ Success' if success else '❌ Failed'} | Return Code: {return_code}]"
                terminal_output += status_line
            else:
                terminal_output = "No commands executed yet. Enter a command above to see output here."
        else:
            terminal_output = "Failed to load session details."

        st.markdown(f'<div class="terminal-output">{terminal_output}</div>', unsafe_allow_html=True)

        # Command history - real data from session details using session_details.get('commands_executed', [])
        st.markdown("---")
        st.markdown("### 📜 Recent Commands")

        if session_details:
            commands_executed = session_details.get('commands_executed', [])
            if commands_executed:
                # Show last 5 commands in reverse order (most recent first)
                for cmd in reversed(commands_executed[-5:]):
                    success = cmd.get('success', False)
                    status_icon = "✅" if success else "❌"
                    command_preview = cmd.get('command', 'Unknown command')
                    timestamp = cmd.get('timestamp', 'Unknown time')

                    with st.expander(f"{status_icon} {timestamp} - {command_preview[:50]}..."):
                        st.markdown(f"**Command:** `{command_preview}`")
                        st.markdown(f"**Status:** {'Success' if success else 'Failed'}")
                        st.markdown(f"**Timestamp:** {timestamp}")
                        st.markdown(f"**Return Code:** {cmd.get('return_code', 'N/A')}")
                        if cmd.get('output'):
                            st.markdown("**Output:**")
                            st.code(cmd['output'][:1000] + ("..." if len(cmd['output']) > 1000 else ""), language="text")
                        if cmd.get('error'):
                            st.markdown("**Error:**")
                            st.code(cmd['error'][:1000] + ("..." if len(cmd['error']) > 1000 else ""), language="text")
            else:
                st.info("No commands have been executed for this session yet.")
        else:
            st.info("Failed to load command history.")

        # Common commands quick buttons
        st.markdown("---")
        st.markdown("### ⚡ Quick Commands")

        # Get target IP from session details to use in commands - try multiple sources
        target_ip = ''
        target_domain = ''
        target_ip_sources = [
            (base_info, 'target_ip'),
            (session_details, 'target_ip'),
            (base_info, 'ip'),
            (session_details, 'ip')
        ]
        
        target_domain_sources = [
            (base_info, 'target_domain'),
            (session_details, 'target_domain'),
            (base_info, 'domain'),
            (session_details, 'domain')
        ]

        for source_dict, key in target_ip_sources:
            if source_dict and source_dict.get(key):
                target_ip = source_dict.get(key)
                break
        
        for source_dict, key in target_domain_sources:
            if source_dict and source_dict.get(key):
                target_domain = source_dict.get(key)
                break

        # Use domain if available, otherwise IP
        target = target_domain if target_domain else target_ip

        # Warn if no target found
        if not target:
            st.warning("⚠️ No target IP or domain found in session details. Quick commands are disabled.")
            # Try to get from session selection if available
            if selected_session:
                st.info(f"Session ID: {selected_session}")

        quick_commands = [
            {"name": "Nmap Quick Scan", "command": f"nmap -T4 -F {target}", "description": "Fast scan of top 100 ports"},
            {"name": "Service Detection", "command": f"nmap -sV {target}", "description": "Detect service versions"},
            {"name": "Vulnerability Scan", "command": f"nmap --script vuln {target}", "description": "Run vulnerability scripts"},
            {"name": "Directory Enumeration", "command": f"dirb http://{target}", "description": "Find web directories"},
            {"name": "SSL Scan", "command": f"sslscan {target}", "description": "Check SSL/TLS configuration"},
        ]

        cols = st.columns(3)
        for idx, qcmd in enumerate(quick_commands):
            with cols[idx % 3]:
                # Disable button if no target is available
                if st.button(
                    qcmd["name"], 
                    use_container_width=True, 
                    help=qcmd["description"] if target else "Disabled: No target IP/domain found",
                    key=f"quick_cmd_{idx}",
                    disabled=not target
                ):
                    # Actually execute the quick command using execute_command as requested
                    with st.spinner(f"Executing {qcmd['name']}..."):
                        result = execute_command(selected_session, qcmd["command"], False)
                        if result:
                            if result.get('status') == 'pending_approval':
                                st.warning(f"Command requires approval. Command ID: {result.get('command_id')}")
                                st.session_state.pending_commands[result.get('command_id')] = {
                                    'session_id': selected_session,
                                    'command': qcmd["command"]
                                }
                                st.success(f"{qcmd['name']} submitted for approval!")
                            else:
                                st.success(f"{qcmd['name']} executed successfully!")
                            st.rerun()  # Refresh UI immediately
                        else:
                            st.error(f"Failed to execute {qcmd['name']}.")
                            st.rerun()

        # Custom command templates
        with st.expander("🔧 Custom Command Templates"):
            template = st.selectbox(
                "Select template:",
                ["SSH Brute Force", "SMB Enumeration", "Web Fuzzing", "SQL Injection Test"]
            )

            if template == "SSH Brute Force":
                st.code("hydra -l {username} -P {wordlist} ssh://{target}", language="bash")
            elif template == "SMB Enumeration":
                st.code("enum4linux -a {target}", language="bash")
            elif template == "Web Fuzzing":
                st.code("ffuf -w /usr/share/wordlists/dirb/common.txt -u http://{target}/FUZZ", language="bash")
            elif template == "SQL Injection Test":
                st.code("sqlmap -u 'http://{target}/page.php?id=1' --batch", language="bash")


def show_credentials(session_details: Dict):
    """🔑 Credentials tab - auto-captured username/secret pairs from tool output."""
    session_id = session_details.get("session_id")
    # Prefer fresh API data (captures anything since the report was last fetched)
    credentials = get_credentials_api(session_id) if session_id else []
    # Fall back to whatever came with the session_details dict
    if not credentials:
        credentials = session_details.get("credentials", [])

    if not credentials:
        st.info(
            "No credentials captured yet. Run brute-force tools (hydra, medusa, ncrack, "
            "crackmapexec) or credential-dump tools and any found username/password pairs "
            "will appear here automatically."
        )
        return

    passwords = [c for c in credentials if c.get("secret_type") != "hash"]
    hashes = [c for c in credentials if c.get("secret_type") == "hash"]

    st.success(f"🎯 {len(passwords)} password(s) and {len(hashes)} hash(es) captured")

    if passwords:
        st.markdown("#### 🔓 Cleartext Passwords")
        for cred in passwords:
            service = cred.get("service") or "unknown"
            host = cred.get("host") or ""
            st.markdown(f"""
            <div class='command-card high-risk'>
                <strong>Username:</strong> <code>{cred['username']}</code> &nbsp;
                <strong>Password:</strong> <code>{cred['secret']}</code><br>
                <strong>Service:</strong> {service} &nbsp; <strong>Host:</strong> {host}<br>
                <small>Captured: {cred.get('discovered_at','?')[:19]}</small>
            </div>
            """, unsafe_allow_html=True)
            if cred.get("source_command"):
                with st.expander("Source command"):
                    st.code(cred["source_command"], language="bash")

    if hashes:
        st.markdown("#### 🔒 Hashes (not yet cracked)")
        for cred in hashes:
            st.markdown(f"""
            <div class='command-card medium-risk'>
                <strong>Username:</strong> <code>{cred['username']}</code><br>
                <strong>Hash:</strong> <code style='word-break:break-all'>{cred['secret']}</code><br>
                <small>Captured: {cred.get('discovered_at','?')[:19]}</small>
            </div>
            """, unsafe_allow_html=True)


def show_threat_intel():
    """Threat Intel page - AI-directed open-web vulnerability research (core/threat_intel.py).
    Builds a shared local reference cache that future pentest sessions automatically
    cross-reference against (see core/orchestrator.py _run_vulnerability_analysis)."""
    st.markdown("<h1 class='main-header'>🔬 Threat Intel</h1>", unsafe_allow_html=True)

    if not check_backend_health():
        st.error("Backend is not available. Please start the FastAPI server.")
        return

    st.warning(
        "⚠️ **Unverified by design.** The AI searches the open web (no domain restriction) and "
        "extracts vulnerability info with another AI call. Pages can be wrong, outdated, or "
        "deliberately misleading (SEO spam, prompt-injection attempts). Treat every result below "
        "as a lead to verify, not a confirmed fact - cross-check against Vulners/NVD/CISA KEV before "
        "acting on it. This research runs independently of any live session and never issues shell "
        "commands on its own."
    )

    with st.form("threat_intel_research_form"):
        topic = st.text_input(
            "Topic to research",
            placeholder="e.g. Apache httpd, WordPress plugins, latest critical CVEs 2026",
            help="The AI will search the web for this topic and extract any CVE/vulnerability info it finds."
        )
        submitted = st.form_submit_button("🔎 Research", type="primary")
        if submitted:
            if not topic.strip():
                st.error("Enter a topic first.")
            else:
                result = start_threat_intel_research(topic.strip())
                if result:
                    st.success(f"Research started for '{topic}'. This runs in the background - results appear below in a moment (page auto-refreshes every 5s).")
                else:
                    st.error("Failed to start research. Check backend logs.")

    st.markdown("---")
    st.markdown("### 📚 Cached Findings")

    filter_topic = st.text_input("Filter by topic (optional)", key="ti_filter", placeholder="e.g. apache")
    findings = get_threat_intel(filter_topic.strip() if filter_topic else None)

    if not findings:
        st.info("No cached findings yet. Research a topic above to get started.")
        return

    st.caption(f"{len(findings)} cached finding(s)")

    for f in findings:
        cve_label = ", ".join(f.get("cve_ids") or []) or "No CVE ID extracted"
        with st.expander(f"🕸️ {f.get('title', 'Untitled')} — {cve_label}"):
            st.markdown(f"""
            <div class='command-card'>
                <strong>⚠️ Status:</strong> Unverified (web research)<br>
                <strong>Topic:</strong> {f.get('topic', 'N/A')}<br>
                <strong>CVE(s):</strong> {cve_label}<br>
                <strong>Affected Software:</strong> {f.get('affected_software') or 'Not specified'}<br>
                <strong>Severity (as reported):</strong> {f.get('severity') or 'Not specified'}<br>
                <strong>Discovered:</strong> {f.get('discovered_at', 'Unknown')}
            </div>
            """, unsafe_allow_html=True)

            if f.get("description"):
                st.markdown("**Description:**")
                st.write(f["description"])

            if f.get("source_url"):
                st.markdown(f"**Source:** [{f['source_url']}]({f['source_url']})")


def show_schedules():
    """Scheduled / recurring scans management page."""
    st.title("🕐 Scheduled Scans")

    # ── Create new schedule ────────────────────────────────────────────────
    with st.expander("➕ Create New Schedule", expanded=False):
        with st.form("new_schedule_form", clear_on_submit=True):
            col1, col2 = st.columns(2)
            with col1:
                sched_target = st.text_input("Target (IP / hostname / CIDR)", placeholder="192.168.1.0/24")
                sched_freq = st.selectbox("Frequency", ["once", "daily", "weekly"])
            with col2:
                sched_day = st.selectbox(
                    "Day of week (weekly only)",
                    ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"],
                )
                sched_hour = st.number_input("Hour (0–23, local server time)", min_value=0, max_value=23, value=2)

            sched_note = st.text_input("Note / label (optional)", placeholder="Nightly prod sweep")
            submitted = st.form_submit_button("Schedule Scan")

            if submitted:
                if not sched_target:
                    st.error("Target is required.")
                else:
                    payload = {
                        "target": sched_target.strip(),
                        "frequency": sched_freq,
                        "day_of_week": sched_day if sched_freq == "weekly" else None,
                        "hour_of_day": int(sched_hour),
                        "note": sched_note.strip() or None,
                    }
                    result = create_schedule_api(payload)
                    if "error" in result:
                        st.error(f"Failed: {result['error']}")
                    else:
                        st.success(f"✅ Schedule created (ID {result.get('scan_id', '?')})")
                        st.rerun()

    st.divider()

    # ── List existing schedules ────────────────────────────────────────────
    schedules = get_schedules_api()

    if not schedules:
        st.info("No scheduled scans yet. Create one above.")
        return

    # Metrics row
    active_count = sum(1 for s in schedules if s.get("status") == "active")
    paused_count = sum(1 for s in schedules if s.get("status") == "paused")
    m1, m2, m3 = st.columns(3)
    m1.metric("Total Schedules", len(schedules))
    m2.metric("Active", active_count)
    m3.metric("Paused", paused_count)

    st.divider()

    for sched in schedules:
        sid = sched.get("scan_id") or sched.get("id")
        target = sched.get("target", "—")
        freq = sched.get("frequency", "—")
        day = sched.get("day_of_week") or "—"
        hour = sched.get("hour_of_day", 0)
        status = sched.get("status", "active")
        next_run = sched.get("next_run_at") or "—"
        last_run = sched.get("last_run_at") or "never"
        note = sched.get("note") or ""

        label = f"[{status.upper()}] {target}  •  {freq}"
        if note:
            label += f"  •  {note}"

        with st.expander(label, expanded=False):
            c1, c2 = st.columns(2)
            c1.markdown(f"**Target:** `{target}`")
            c1.markdown(f"**Frequency:** {freq}" + (f" ({day})" if freq == "weekly" else ""))
            c1.markdown(f"**Hour:** {hour:02d}:00")
            c2.markdown(f"**Status:** `{status}`")
            c2.markdown(f"**Next run:** {next_run}")
            c2.markdown(f"**Last run:** {last_run}")

            btn_col1, btn_col2 = st.columns(2)
            with btn_col1:
                if status == "active":
                    if st.button("⏸ Pause", key=f"pause_{sid}"):
                        if update_schedule_status_api(sid, "paused"):
                            st.success("Paused.")
                            st.rerun()
                        else:
                            st.error("Failed to pause.")
                else:
                    if st.button("▶ Resume", key=f"resume_{sid}"):
                        if update_schedule_status_api(sid, "active"):
                            st.success("Resumed.")
                            st.rerun()
                        else:
                            st.error("Failed to resume.")
            with btn_col2:
                if st.button("🗑 Delete", key=f"del_sched_{sid}"):
                    if update_schedule_status_api(sid, "deleted"):
                        st.success("Deleted.")
                        st.rerun()
                    else:
                        st.error("Failed to delete.")


def show_history():
    """Session History page - all sessions from DB including completed/failed ones.
    Unlike Active Sessions (in-memory only), this queries the DB directly so
    historical sessions survive backend restarts."""
    st.markdown("<h1 class='main-header'>🕐 Session History</h1>", unsafe_allow_html=True)

    if not check_backend_health():
        st.error("Backend is not available. Please start the FastAPI server.")
        return

    history = get_session_history()

    if not history:
        st.info("No sessions recorded yet. Start a new session to build history.")
        return

    # Summary metrics row
    active = sum(1 for s in history if s.get("active_in_memory"))
    completed = sum(1 for s in history if s.get("status") == "completed")
    failed = sum(1 for s in history if s.get("status") == "failed")
    total_vulns = sum(s.get("vuln_count", 0) for s in history)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Sessions", len(history))
    c2.metric("Active", active)
    c3.metric("Completed", completed)
    c4.metric("Total Vulns Found", total_vulns)

    st.markdown("---")

    # Status filter
    status_filter = st.selectbox(
        "Filter by status",
        ["All", "active", "initialized", "scanning", "analyzing", "executing", "ready", "completed", "failed"],
        key="history_status_filter"
    )

    filtered = history if status_filter == "All" else [
        s for s in history
        if (status_filter == "active" and s.get("active_in_memory"))
        or (status_filter != "active" and s.get("status") == status_filter)
    ]

    st.caption(f"Showing {len(filtered)} of {len(history)} session(s)")

    _STATUS_COLORS = {
        "initialized": "#2d3748", "scanning": "#975a16", "analyzing": "#22543d",
        "executing": "#702459", "ready": "#4caf50", "completed": "#388e3c", "failed": "#d32f2f"
    }

    for s in filtered:
        status = s.get("status", "unknown")
        color = _STATUS_COLORS.get(status, "#555")
        in_mem = " 🟢 active" if s.get("active_in_memory") else ""
        target = s.get("target_ip", "?")
        domain = f" / {s['target_domain']}" if s.get("target_domain") else ""
        created = (s.get("created_at") or "")[:19].replace("T", " ")

        with st.expander(
            f"🎯 {target}{domain}  |  status: {status}{in_mem}  |  {created}"
        ):
            col_l, col_r = st.columns([3, 1])
            with col_l:
                st.markdown(f"""
                <div class='session-card' style='border-left-color: {color}'>
                    <strong>Session ID:</strong> <code>{s['session_id']}</code><br>
                    <strong>Target:</strong> {target}{domain}<br>
                    <strong>Status:</strong> <span style='color:{color};font-weight:bold'>{status.upper()}</span><br>
                    <strong>Stage:</strong> {s.get('current_stage', 'N/A')}<br>
                    <strong>Created:</strong> {created}<br>
                    <strong>Scans:</strong> {s.get('scan_count', 0)} &nbsp;
                    <strong>Commands:</strong> {s.get('command_count', 0)} &nbsp;
                    <strong>Vulnerabilities:</strong> {s.get('vuln_count', 0)}<br>
                    <strong>Auto-approve:</strong> {'Yes' if s.get('auto_approve') else 'No'} &nbsp;
                    <strong>Auth confirmed:</strong> {'Yes' if s.get('authorization_confirmed') else 'No'}
                </div>
                """, unsafe_allow_html=True)

            with col_r:
                sid = s['session_id']
                if s.get("active_in_memory"):
                    if st.button("📂 Open", key=f"open_{sid}"):
                        st.session_state.selected_session = sid
                        st.session_state.force_nav_to_active = True
                        st.rerun()

                    if status not in ("scanning", "analyzing", "executing"):
                        if st.button("▶️ Resume", key=f"resume_{sid}",
                                     help="Continue AI analysis from current data"):
                            api_session.post(f"{API_BASE}/sessions/{sid}/resume")
                            st.success("Resumed.")
                            time.sleep(0.5)
                            st.rerun()

                        if st.button("🔄 Restart", key=f"restart_{sid}",
                                     help="Re-run nmap scan from scratch"):
                            api_session.post(f"{API_BASE}/sessions/{sid}/restart")
                            st.success("Restarting...")
                            time.sleep(0.5)
                            st.rerun()

                    if status not in ("completed", "failed"):
                        if st.button("✅ Mark Complete", key=f"complete_{sid}"):
                            result = complete_session(sid)
                            if result.get("status") == "success":
                                st.success("Session marked as completed.")
                            else:
                                st.error(result.get("message", "Failed to complete session."))
                            st.rerun()


def show_settings():
    """Settings page."""
    st.markdown("<h1 class='main-header'>⚙️ Settings</h1>", unsafe_allow_html=True)
    
    # Configuration tabs
    tab1, tab2, tab3, tab4 = st.tabs(["General", "AI Configuration", "Security", "Advanced"])
    
    with tab1:
        st.markdown("### 🌐 General Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            auto_refresh = st.checkbox("Enable auto-refresh", value=True)
            refresh_interval = st.slider("Refresh interval (seconds)", 1, 60, 5, disabled=not auto_refresh)
            
            theme = st.selectbox("Theme", ["Light", "Dark", "System"])
            
            results_per_page = st.number_input("Results per page", 10, 100, 25)
        
        with col2:
            notification_sound = st.checkbox("Enable notification sounds", value=True)
            show_timestamps = st.checkbox("Show timestamps in logs", value=True)
            compact_view = st.checkbox("Compact view mode", value=False)
        
        if st.button("💾 Save General Settings", type="primary"):
            # General settings are frontend-only (display preferences).
            # Persist to session_state so they survive reruns within this browser session.
            st.session_state["pref_auto_refresh"] = auto_refresh
            st.session_state["pref_refresh_interval"] = int(refresh_interval)
            st.session_state["pref_results_per_page"] = int(results_per_page)
            st.session_state["pref_show_timestamps"] = show_timestamps
            st.session_state["pref_compact_view"] = compact_view
            st.success("Display preferences saved for this session.")
    
    with tab2:
        st.markdown("### 🤖 AI Configuration")
        st.caption(
            "These settings write directly to .env on the backend (created automatically if it "
            "doesn't exist yet) - no manual file editing needed."
        )

        # Read current settings from .env (works fine if the file is empty/missing - all fields
        # just fall back to defaults below)
        env_path = os.path.join(os.getcwd(), '.env')
        env_vars = dotenv_values(env_path) if os.path.exists(env_path) else {}

        current_provider = env_vars.get("AI_PROVIDER", "local")
        current_ds_key = env_vars.get("DEEPSEEK_API_KEY", "")
        current_ds_model = env_vars.get("DEEPSEEK_MODEL", "deepseek-chat")
        current_ollama_url = env_vars.get("OLLAMA_URL", "http://localhost:11434")
        current_ollama_model = env_vars.get("OLLAMA_MODEL", "deepseek-r1:8b")

        ai_provider = st.selectbox(
            "AI Provider",
            ["Local (Ollama)", "DeepSeek API"],
            index=1 if current_provider == "api" else 0,
            help="Local (Ollama) keeps everything on your machine. DeepSeek API is faster but sends data to DeepSeek's servers."
        )

        if ai_provider == "Local (Ollama)":
            api_key = ""  # not used for local provider
            ollama_url = st.text_input("Ollama URL", value=current_ollama_url)

            # ── Live model picker ─────────────────────────────────────────────
            st.markdown("#### 🔍 Available Models")

            col_btn, col_status = st.columns([1, 3])
            with col_btn:
                fetch_models = st.button("📋 Load Models", use_container_width=True)
            with col_status:
                st.caption("Queries the Ollama server for installed models")

            if fetch_models or st.session_state.get("_ollama_models"):
                if fetch_models:
                    try:
                        resp = api_session.get(f"{API_BASE}/ollama/models", timeout=10)
                        if resp.status_code == 200:
                            data = resp.json()
                            models_raw = data.get("models", [])
                            if models_raw:
                                st.session_state["_ollama_models"] = models_raw
                                st.session_state["_ollama_models_error"] = None
                            else:
                                err = data.get("error", "No models found — is Ollama running?")
                                st.session_state["_ollama_models_error"] = err
                        else:
                            st.session_state["_ollama_models_error"] = f"Backend error {resp.status_code}"
                    except Exception as e:
                        st.session_state["_ollama_models_error"] = str(e)

                err_msg = st.session_state.get("_ollama_models_error")
                if err_msg:
                    st.warning(f"Could not reach Ollama: {err_msg}")

                models_list = st.session_state.get("_ollama_models", [])
                if models_list:
                    # Build display labels: "deepseek-r1:8b (4.7 GB)"
                    def _model_label(m):
                        name = m.get("name", "")
                        gb = m.get("size_gb")
                        return f"{name} ({gb} GB)" if gb else name

                    model_labels = [_model_label(m) for m in models_list]
                    model_names  = [m.get("name", "") for m in models_list]

                    # Pre-select the currently configured model if it's in the list
                    default_idx = 0
                    if current_ollama_model in model_names:
                        default_idx = model_names.index(current_ollama_model)

                    selected_label = st.selectbox(
                        "Select model",
                        model_labels,
                        index=default_idx,
                        key="_ollama_model_select",
                    )
                    model_name = model_names[model_labels.index(selected_label)]

                    # Auto-detect context window when model changes
                    if (fetch_models
                            or st.session_state.get("_ctx_for_model") != model_name):
                        try:
                            info_resp = api_session.get(
                                f"{API_BASE}/ollama/model-info",
                                params={"model": model_name},
                                timeout=12,
                            )
                            if info_resp.status_code == 200:
                                info_data = info_resp.json()
                                st.session_state["_ctx_for_model"]  = model_name
                                st.session_state["_detected_ctx"]   = info_data.get("context_window", 8192)
                                st.session_state["_ctx_source"]     = info_data.get("source", "?")
                                st.session_state["_ctx_arch"]       = info_data.get("architecture") or ""
                        except Exception:
                            pass

                    detected_ctx  = st.session_state.get("_detected_ctx", 8192)
                    ctx_source    = st.session_state.get("_ctx_source", "default")
                    ctx_arch      = st.session_state.get("_ctx_arch", "")

                    col_ctx, col_src = st.columns([1, 2])
                    with col_ctx:
                        st.metric("Context window", f"{detected_ctx:,} tokens")
                    with col_src:
                        st.caption(
                            f"Source: **{ctx_source}**"
                            + (f"  ·  arch: `{ctx_arch}`" if ctx_arch else "")
                        )

                    # Allow manual override
                    override = st.checkbox("Override context window", value=False)
                    if override:
                        detected_ctx = st.number_input(
                            "Custom context window (tokens)",
                            min_value=512, max_value=2_000_000,
                            value=detected_ctx, step=512,
                        )
                    ollama_context_window = detected_ctx

                else:
                    # No models yet — fall back to manual entry
                    model_name = st.text_input("Model Name (manual)", value=current_ollama_model)
                    ollama_context_window = int(os.getenv("OLLAMA_CONTEXT_WINDOW", "8192"))
            else:
                # Before "Load Models" is clicked — show manual fallback
                st.caption("Click **Load Models** to pick from installed models, or type manually below.")
                model_name = st.text_input(
                    "Model Name",
                    value=current_ollama_model,
                    help="Any model installed via `ollama pull <name>`",
                )
                ollama_context_window = int(os.getenv("OLLAMA_CONTEXT_WINDOW", "8192"))

            col1, col2 = st.columns(2)
            with col1:
                temperature = st.slider("Temperature", 0.0, 2.0, 0.7, 0.1)
            with col2:
                max_tokens = st.number_input("Max Tokens", 100, 10000, 2000)

        else:  # DeepSeek API
            # Automatically populate the key if it exists in .env
            api_key = st.text_input("API Key", value=current_ds_key, type="password")
            model_name = st.text_input(
                "Model",
                value=current_ds_model,
                help="e.g. deepseek-chat or deepseek-coder"
            )
            ollama_url = ""              # not applicable for this provider
            ollama_context_window = None # not applicable

            st.info("DeepSeek API provides high-performance AI with specialized security knowledge.")

        # AI behavior settings
        st.markdown("### 🧠 AI Behavior")
        
        col1, col2 = st.columns(2)
        
        with col1:
            risk_tolerance = st.select_slider(
                "Risk Tolerance",
                options=["Very Conservative", "Conservative", "Balanced", "Aggressive", "Very Aggressive"],
                value="Balanced"
            )
            
            max_command_complexity = st.select_slider(
                "Max Command Complexity",
                options=["Simple", "Moderate", "Complex", "Very Complex"],
                value="Complex"
            )
        
        with col2:
            auto_escalate = st.checkbox("Auto-escalate after success", value=True)
            learn_from_mistakes = st.checkbox("Learn from failed commands", value=True)
            maintain_context = st.checkbox("Maintain session context", value=True)
        
        if st.button("💾 Save AI Settings", type="primary"):
            if not check_backend_health():
                st.error(
                    "⚠️ Backend is not running. Start it first with `./start.sh`, "
                    "then retry saving settings."
                )
            else:
                with st.spinner("Saving configuration..."):
                    payload = {
                        "provider": ai_provider,
                        "api_key": api_key if ai_provider == "DeepSeek API" else "",
                        "model_name": model_name,
                        "ollama_url": ollama_url if ai_provider == "Local (Ollama)" else "",
                        "ollama_context_window": ollama_context_window if ai_provider == "Local (Ollama)" else None,
                    }
                    try:
                        response = api_session.post(f"{API_BASE}/settings/ai", json=payload)
                        if response.status_code == 200:
                            info = response.json()
                            ctx_info = (
                                f", context: **{info['context_window']:,} tokens**"
                                if info.get("context_window") else ""
                            )
                            st.success(
                                f"AI settings saved! Now using **{info.get('provider', payload['provider'])}** "
                                f"with model **{info.get('model', model_name)}**{ctx_info}."
                            )
                            time.sleep(1)
                            st.rerun()
                        else:
                            try:
                                detail = response.json().get("detail", response.text)
                            except Exception:
                                detail = f"HTTP {response.status_code} — backend may not be running on port 8000"
                            st.error(f"Failed to save settings: {detail}")
                    except Exception as e:
                        st.error(f"Connection error: {e}")
    
    with tab3:
        st.markdown("### 🔒 Security Settings")
        
        st.markdown("#### Command Approval")
        col1, col2 = st.columns(2)
        
        with col1:
            require_approval = st.checkbox("Require approval for high-risk commands", value=True)
            approval_timeout = st.number_input("Approval timeout (minutes)", 1, 60, 15)
            
            audit_logging = st.checkbox("Enable audit logging", value=True)
            encrypt_evidence = st.checkbox("Encrypt evidence files", value=False)
        
        with col2:
            session_timeout = st.number_input("Session timeout (hours)", 1, 72, 24)
            max_parallel_commands = st.number_input("Max parallel commands", 1, 10, 3)
            
            auto_cleanup = st.checkbox("Auto-cleanup old sessions", value=True)
            cleanup_days = st.number_input("Cleanup after (days)", 1, 365, 30)
        
        st.markdown("#### API Authentication")
        st.caption(
            "The backend API requires this key on every request (auto-generated on first run, "
            "stored in .env as API_AUTH_TOKEN). You'll need it if you call the API directly (e.g. curl)."
        )
        current_token = _load_api_token()
        if current_token:
            st.text_input("Current API Key", value=current_token, type="password", disabled=True)
        else:
            st.warning("No API_AUTH_TOKEN found yet - start the backend once to generate it.")

        st.markdown("#### Vulnerability Intelligence (optional)")
        st.caption(
            "Adds CVE/CVSS enrichment to scan findings via the [Vulners](https://vulners.com) API, "
            "on top of Nmap's built-in vuln scripts. Leave blank to skip - findings still work "
            "without it, just without CVE matching. Get a key at vulners.com/api-keys."
        )
        env_path_vulners = os.path.join(os.getcwd(), '.env')
        env_vars_vulners = dotenv_values(env_path_vulners) if os.path.exists(env_path_vulners) else {}
        current_vulners_key = env_vars_vulners.get("VULNERS_API_KEY", "")
        vulners_key_input = st.text_input(
            "Vulners API Key", value=current_vulners_key, type="password", key="vulners_api_key_input"
        )
        if st.button("💾 Save Vulners API Key"):
            try:
                resp = api_session.post(f"{API_BASE}/settings/vulners", json={"api_key": vulners_key_input})
                if resp.status_code == 200:
                    st.success(resp.json().get("message", "Saved."))
                else:
                    st.error(f"Failed to save: {resp.text}")
            except Exception as e:
                st.error(f"Connection error: {e}")

        st.markdown("#### Access Control")
        enable_auth = st.checkbox("Enable authentication", value=False)
        
        if enable_auth:
            auth_method = st.selectbox("Authentication Method", ["Local Users", "LDAP", "OAuth"])
            
            if auth_method == "Local Users":
                st.info("Configure local users in the admin panel.")
            elif auth_method == "LDAP":
                ldap_server = st.text_input("LDAP Server")
                ldap_domain = st.text_input("LDAP Domain")
            elif auth_method == "OAuth":
                client_id = st.text_input("Client ID")
                client_secret = st.text_input("Client Secret", type="password")
        
        if st.button("💾 Save Security Settings", type="primary"):
            payload = {
                "require_approval_high_risk": require_approval,
                "approval_timeout_minutes": int(approval_timeout),
                "audit_logging": audit_logging,
                "session_timeout_hours": int(session_timeout),
                "max_parallel_commands": int(max_parallel_commands),
                "auto_cleanup": auto_cleanup,
                "cleanup_after_days": int(cleanup_days),
            }
            try:
                resp = api_session.post(f"{API_BASE}/settings/security", json=payload, timeout=10)
                if resp.status_code == 200:
                    st.success(resp.json().get("message", "Security settings saved."))
                else:
                    st.error(f"Failed to save ({resp.status_code}): {resp.text[:200]}")
            except Exception as e:
                st.error(f"Connection error: {e}")
    
    with tab4:
        st.markdown("### ⚙️ Advanced Settings")
        
        st.markdown("#### Backend Configuration")
        backend_url = st.text_input("Backend API URL", BACKEND_URL)
        api_timeout = st.number_input("API Timeout (seconds)", 1, 300, 30)
        
        st.markdown("#### Database")
        db_path = st.text_input("Database Path", "kmn_cyberseek.db")
        backup_interval = st.selectbox("Backup Interval", ["Never", "Daily", "Weekly", "Monthly"])
        
        if backup_interval != "Never":
            backup_path = st.text_input("Backup Path", "./backups")
            keep_backups = st.number_input("Keep backups (days)", 1, 365, 30)
        
        st.markdown("#### Logging")
        log_level = st.selectbox("Log Level", ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        log_file = st.text_input("Log File", "kmn_cyberseek.log")
        log_rotation = st.checkbox("Enable log rotation", value=True)
        
        if log_rotation:
            max_log_size = st.number_input("Max log size (MB)", 1, 1000, 100)
            backup_count = st.number_input("Backup count", 1, 50, 5)
        
        st.markdown("#### Development")
        debug_mode = st.checkbox("Debug mode", value=False)
        enable_metrics = st.checkbox("Enable performance metrics", value=True)

        st.markdown("#### 🧠 Local LLM Context Window")
        st.info(
            "Set this to your Ollama model's `num_ctx` value. "
            "The system auto-selects a compact system prompt for smaller windows "
            "and scales command-output truncation so the AI never runs out of context.",
            icon="ℹ️",
        )
        ctx_options = {
            "4 096  — small/fast (llama3.2:3b, deepseek-r1:7b)": 4096,
            "8 192  — default (deepseek-r1:8b, llama3.1:8b) ★": 8192,
            "16 384 — mid (mistral, codellama:13b)": 16384,
            "32 768 — large (qwen2.5:14b, deepseek-r1:14b)": 32768,
            "65 536 — xlarge (qwen2.5:32b, deepseek-r1:32b)": 65536,
            "131 072 — huge (qwen2.5:72b, deepseek-r1:70b)": 131072,
        }
        ctx_default_label = "8 192  — default (deepseek-r1:8b, llama3.1:8b) ★"
        selected_ctx_label = st.selectbox(
            "Model context window (tokens)",
            list(ctx_options.keys()),
            index=list(ctx_options.keys()).index(ctx_default_label),
        )
        ollama_context_window = ctx_options[selected_ctx_label]
        st.caption(
            f"Selected: **{ollama_context_window:,} tokens**. "
            "For DeepSeek API provider this setting is ignored (API has large context)."
        )

        st.markdown("#### 🤖 Autonomous Execution")
        st.warning(
            "**FULL_AUTO_MODE** — The AI will execute *every* suggested command without "
            "human approval, regardless of risk level. Use only on isolated lab networks "
            "where you have explicit written authorization to test.",
            icon="⚠️",
        )
        full_auto_mode = st.checkbox(
            "Enable Full Auto Mode",
            value=False,
            help="Bypasses keyword backstop, binary allowlist, and depth limit. "
                 "authorization_confirmed still required per session.",
        )

        if st.button("💾 Save Advanced Settings", type="primary"):
            payload = {
                "log_level": log_level,
                "log_file": log_file,
                "debug": debug_mode,
                "db_path": db_path,
                "full_auto_mode": full_auto_mode,
                "ollama_context_window": ollama_context_window,
            }
            try:
                resp = api_session.post(f"{API_BASE}/settings/advanced", json=payload, timeout=10)
                if resp.status_code == 200:
                    info = resp.json()
                    mode_label = "ON ⚠️" if info.get("full_auto_mode") else "off"
                    ctx_val = info.get("ollama_context_window", ollama_context_window)
                    st.success(
                        f"{info.get('message', 'Advanced settings saved.')} "
                        f"(log: {info.get('log_level', log_level)}, "
                        f"full_auto: {mode_label}, "
                        f"ctx: {ctx_val:,} tokens)"
                    )
                else:
                    st.error(f"Failed to save ({resp.status_code}): {resp.text[:200]}")
            except Exception as e:
                st.error(f"Connection error: {e}")
        
        st.markdown("---")
        
        # Danger zone
        st.subheader("Danger Zone")
        st.warning("These actions cannot be undone.")
        if st.button("🗑️ Clear ALL Sessions and Data", type="primary"):
            response = api_session.delete(f"{API_BASE}/sessions")
            if response.status_code == 200:
                st.session_state.selected_session = None
                st.success("All database records cleared!")
                time.sleep(1)
                st.rerun()
            else:
                st.error(f"Failed to clear all sessions: {response.status_code}")


if __name__ == "__main__":
    main()
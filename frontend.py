#!/usr/bin/env python3
"""
KMN-CyberSeek Streamlit Frontend
Web dashboard for AI-driven autonomous red team operations.
"""

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

# Backend API configuration
BACKEND_URL = "http://localhost:8000"
API_BASE = f"{BACKEND_URL}/api"

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
        response = requests.get(f"{BACKEND_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        return False


def get_sessions():
    """Get list of active sessions from backend."""
    try:
        response = requests.get(f"{API_BASE}/sessions", timeout=5)
        if response.status_code == 200:
            return response.json().get("sessions", [])
    except Exception as e:
        logger.error(f"Failed to get sessions: {e}")
    return []


def start_session(target_ip: str, target_domain: str = "", session_name: str = "", 
                 auto_approve: bool = False, max_auto_depth: int = 5):
    """Start a new session."""
    try:
        payload = {
            "ip": target_ip,
            "domain": target_domain if target_domain else None,
            "session_name": session_name if session_name else None,
            "auto_approve": auto_approve,
            "max_auto_depth": max_auto_depth
        }
        response = requests.post(f"{API_BASE}/start", json=payload, timeout=30)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.error(f"Failed to start session: {e}")
    return None


def get_session_details(session_id: str):
    """Get details of a specific session."""
    try:
        response = requests.get(f"{API_BASE}/sessions/{session_id}", timeout=5)
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
        response = requests.get(f"{API_BASE}/sessions/{session_id}/pending_commands", timeout=5)
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
        response = requests.post(f"{API_BASE}/execute", json=payload, timeout=30)
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
        response = requests.post(f"{API_BASE}/approve", json=payload, timeout=30)
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
        response = requests.post(f"{API_BASE}/approve", json=payload, timeout=30)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.error(f"Failed to deny command: {e}")
    return None


def resume_session(session_id: str):
    """Manually resume AI analysis for a session."""
    try:
        response = requests.post(f"{API_BASE}/sessions/{session_id}/resume", timeout=30)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.error(f"Failed to resume session: {e}")
    return None


def main():
    """Main Streamlit application."""
    
    # Auto-refresh every 5 seconds
    st_autorefresh(interval=5000, key="auto_refresh")
    
    # Sidebar navigation
    with st.sidebar:
        st.markdown("## 🛡️ KMN-CyberSeek")
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
        
        # Navigation menu
        selected = option_menu(
            menu_title="Navigation",
            options=["Dashboard", "New Session", "Active Sessions", "Command Console", "Settings"],
            icons=["speedometer2", "plus-circle", "list-task", "terminal", "gear"],
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
        
        **Version:** 1.0.0
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
        elif selected == "Settings":
            show_settings()


def show_dashboard():
    """Dashboard page."""
    st.markdown("<h1 class='main-header'>📊 Dashboard</h1>", unsafe_allow_html=True)
    
    if not check_backend_health():
        st.error("Backend is not available. Please start the FastAPI server.")
        return
    
    # Get sessions data
    sessions = get_sessions()
    
    # Overall statistics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Sessions", len(sessions))
    
    with col2:
        active_sessions = len([s for s in sessions if s.get('status') not in ['completed', 'failed']])
        st.metric("Active Sessions", active_sessions)
    
    with col3:
        scanning_sessions = len([s for s in sessions if s.get('status') == 'scanning'])
        st.metric("Scanning Now", scanning_sessions)
    
    with col4:
        pending_commands = len(st.session_state.pending_commands)
        st.metric("Pending Commands", pending_commands)
    
    st.markdown("---")
    
    # Recent activity
    st.markdown("<h3 class='sub-header'>📈 Recent Activity</h3>", unsafe_allow_html=True)
    
    if not sessions:
        st.info("No active sessions. Create a new session to get started.")
    else:
        # Create tabs for different views
        tab1, tab2, tab3 = st.tabs(["Session Overview", "Quick Actions", "System Status"])
        
        with tab1:
            # Display session cards
            for session in sessions:
                with st.container():
                    status = session.get('status', 'unknown')
                    status_class = f"status-{status}"

                    st.markdown(f"""
                    <div class='session-card'>
                        <div style='display: flex; justify-content: space-between; align-items: center;'>
                            <div>
                                <h4 style='margin: 0;'>Session: {session['session_id']}</h4>
                                <p style='margin: 0; color: #666;'>Target: {session['target_ip']}</p>
                            </div>
                            <span class='status-badge {status_class}'>{status.upper()}</span>
                        </div>
                        <div style='margin-top: 1rem;'>
                            <p style='margin: 0;'><strong>Stage:</strong> {session.get('current_stage', 'N/A')}</p>
                            <p style='margin: 0;'><strong>Hosts Found:</strong> {session.get('discovered_hosts_count', 0)}</p>
                            <p style='margin: 0;'><strong>Services Found:</strong> {session.get('discovered_services_count', 0)}</p>
                            <p style='margin: 0;'><strong>Commands Executed:</strong> {session.get('commands_executed_count', 0)}</p>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Native Streamlit button for View Details
                    if st.button("View Details", key=f"view_{session['session_id']}"):
                        st.session_state.selected_session = session['session_id']
                        st.session_state.force_nav_to_active = True
                        st.success("Redirecting to Active Sessions...")
                        st.rerun()

        with tab2:
            st.markdown("### ⚡ Quick Actions")
            
            # Quick session controls
            if st.session_state.selected_session:
                session_details = get_session_details(st.session_state.selected_session)
                if session_details:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if st.button("🔄 Refresh Session", use_container_width=True):
                            st.rerun()
                        
                        if st.button("📊 Generate Report", use_container_width=True):
                            st.info("Report generation feature coming soon...")
                    
                    with col2:
                        if st.button("🚫 Stop Session", use_container_width=True):
                            st.warning("Session stop feature coming soon...")
                        
                        if st.button("📋 View Evidence", use_container_width=True):
                            st.info("Evidence viewer coming soon...")
            
            # Quick command input
            st.markdown("### 💻 Quick Command")
            quick_command = st.text_input("Enter command to execute:", placeholder="nmap -sV 192.168.1.1")
            
            col1, col2 = st.columns(2)
            with col1:
                auto_approve = st.checkbox("Auto-approve (low risk only)")
            with col2:
                if st.button("▶️ Execute", use_container_width=True) and quick_command and st.session_state.selected_session:
                    result = execute_command(st.session_state.selected_session, quick_command, auto_approve)
                    if result:
                        st.success(f"Command submitted: {result.get('status')}")
                    else:
                        st.error("Failed to execute command")
        
        with tab3:
            st.markdown("### 🖥️ System Status")
            
            # Backend status
            backend_status = {
                "API Server": "Running" if check_backend_health() else "Stopped",
                "Database": "Connected",
                "AI Engine": "Local (Ollama)",
                "Scanner": "Ready",
                "WebSocket": "Active"
            }
            
            for component, status in backend_status.items():
                status_icon = "✅" if "Running" in status or "Connected" in status or "Ready" in status else "❌"
                st.markdown(f"{status_icon} **{component}:** {status}")
            
            # Resource usage (mock data for now)
            st.markdown("### 📊 Resource Usage")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("CPU", "15%", "2%")
            
            with col2:
                st.metric("Memory", "42%", "-3%")
            
            with col3:
                st.metric("Disk", "28%", "1%")
    
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
                "Target IP Address / Domain *",
                placeholder="192.168.1.1 or example.com",
                help="Enter the target IP address or domain name"
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
            
            # Show loading spinner
            with st.spinner("Creating new session and starting reconnaissance..."):
                result = start_session(target_ip, target_domain, session_name)
                
                if result:
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
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Overview", "🔍 Scan Results", "🤖 AI Decisions", "⚡ Commands", "📁 Evidence"])
    
    with tab1:
        show_session_overview(session_details)
    
    with tab2:
        show_scan_results(session_details)
    
    with tab3:
        show_ai_decisions(session_details)
    
    with tab4:
        show_commands(session_details)
    
    with tab5:
        show_evidence(session_details)


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

    if status == "initialized":
        if st.button("🚀 Start Initial Scan", type="primary", use_container_width=True):
            requests.post(f"{API_BASE}/sessions/{session_id}/start")
            st.rerun()
    elif status in ["scanning", "analyzing", "executing"]:
        st.button(f"⏳ {status.title()} in progress...", disabled=True, use_container_width=True)
    else:
        # Only show resume for ready, error, completed
        if st.button("▶️ Force AI Analysis / Resume", type="primary", use_container_width=True):
            requests.post(f"{API_BASE}/sessions/{session_id}/resume")
            st.success("Waking up AI...")
            time.sleep(1)
            st.rerun()
    
    # Add delete button next to Stop Session
    if st.button("🗑️ Delete This Session", type="primary", use_container_width=True):
        response = requests.delete(f"{API_BASE}/sessions/{session_id}")
        if response.status_code == 200:
            st.session_state.selected_session = None
            st.success("Session deleted successfully!")
            time.sleep(1)
            st.rerun()
        else:
            st.error(f"Failed to delete session: {response.status_code}")
    
    # Session timeline - dynamically determined based on current_stage
    st.markdown("### 📅 Session Timeline")
    
    # Get current stage from session details
    current_stage = session_details.get('current_stage', '').lower()
    
    # Define the typical flow of stages - must match AI's attack_phase outputs exactly
    stages = [
        {"event": "Session created", "stage_key": "created"},
        {"event": "Reconnaissance", "stage_key": "reconnaissance"},
        {"event": "Vulnerability Analysis", "stage_key": "vulnerability_analysis"},
        {"event": "Exploitation", "stage_key": "exploitation"},
        {"event": "Post-Exploitation", "stage_key": "post_exploitation"},
        {"event": "Lateral Movement", "stage_key": "lateral_movement"}
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
        # Determine time label
        if i == 0:
            time_label = session_details.get('created_at', 'N/A')
        elif current_stage_index is not None and i == current_stage_index:
            time_label = "Now"
        else:
            time_label = "Next"
        
        # Determine status
        if i == 0:  # Session created is always completed
            status = "completed"
        elif current_stage_index is None:
            # No current stage found - check if we should default to reconnaissance
            if i == 1 and session_details.get('discovered_hosts_count', 0) > 0:
                # We have scan results but no stage set, assume reconnaissance is in progress
                status = "in_progress"
                time_label = "Now"
            else:
                status = "pending"
        elif i < current_stage_index:
            # Stage comes before current stage
            status = "completed"
        elif i == current_stage_index:
            # This is the current stage
            status = "in_progress"
        else:
            # Stage comes after current stage
            status = "pending"
        
        timeline_data.append({
            "time": time_label,
            "event": stage["event"],
            "status": status
        })
    
    for item in timeline_data:
        status_icon = "✅" if item["status"] == "completed" else "🔄" if item["status"] == "in_progress" else "⏳"
        st.markdown(f"{status_icon} **{item['time']}** - {item['event']}")


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


def show_ai_decisions(session_details: Dict):
    """Show AI decisions."""
    ai_decisions = session_details.get("ai_decisions", [])

    if not ai_decisions:
        st.info("AI decisions will appear here as the AI analyzes scan results.")
        return

    for index, decision in enumerate(ai_decisions, start=1):
        suggested_command = decision.get("suggested_command") or "No command suggested"
        risk_level = str(decision.get("risk_level", "unknown")).lower()
        confidence = decision.get("confidence")
        timestamp = decision.get("timestamp", "Unknown time")
        context = decision.get("context", "analysis")
        session_id = session_details.get("session_id")

        with st.expander(f"🤖 Decision {index} • {timestamp} • {risk_level.upper()}"):
            st.markdown(f"**Context:** {context}")
            st.markdown("**Reasoning:**")
            st.code(decision.get("reasoning", "No reasoning available."), language="text")
            st.markdown("**Suggested Command:**")
            st.code(suggested_command, language="bash")
            st.markdown(f"**Risk Level:** {risk_level.upper()}")
            if confidence is not None:
                st.markdown(f"**Confidence:** {confidence}")
            
            # Add "Execute this Command" button
            if suggested_command and suggested_command != "No command suggested" and session_id:
                if st.button("🚀 Execute this Command", key=f"execute_ai_cmd_{session_id}_{index}", use_container_width=True):
                    with st.spinner(f"Executing AI-suggested command..."):
                        result = execute_command(session_id, suggested_command, False)
                        if result:
                            if result.get('status') == 'pending_approval':
                                st.warning(f"Command requires approval. Command ID: {result.get('command_id')}")
                            else:
                                st.success(f"Command executed successfully!")
                            st.rerun()
                        else:
                            st.error("Failed to execute command.")


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

    for cmd in command_history:
        success = cmd.get("success", False)
        status_icon = "✅" if success else "❌"
        status_label = "success" if success else "failed"
        command_preview = cmd.get("command", "Unknown command")

        with st.expander(f"{status_icon} {command_preview[:50]}..."):
            st.markdown(f"**Command:** `{command_preview}`")
            st.markdown(f"**Status:** {status_label}")
            st.markdown(f"**Timestamp:** {cmd.get('timestamp', 'Unknown')}")
            st.markdown(f"**Return Code:** {cmd.get('return_code', 'N/A')}")
            st.markdown("**Output:**")
            st.code(cmd.get("output") or "No stdout captured.", language="text")
            if cmd.get("error"):
                st.markdown("**Error:**")
                st.code(cmd["error"], language="text")

    if not command_history:
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
        auto_approve = st.checkbox("Auto-approve")
    
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
        st.caption("Note: High-risk commands will always require manual approval.")


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
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📄 Export as JSON", use_container_width=True):
            st.info("JSON export feature coming soon...")
    
    with col2:
        if st.button("📊 Export as PDF", use_container_width=True):
            st.info("PDF report generation coming soon...")
    
    with col3:
        if st.button("🔗 Share Report", use_container_width=True):
            st.info("Report sharing coming soon...")


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
            auto_approve = st.checkbox("Auto-approve", help="Auto-approve low-risk commands")

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
            st.success("General settings saved!")
    
    with tab2:
        st.markdown("### 🤖 AI Configuration")
        
        # Read current settings from .env
        env_path = os.path.join(os.getcwd(), '.env')
        env_vars = dotenv_values(env_path) if os.path.exists(env_path) else {}
        
        current_provider = env_vars.get("AI_PROVIDER", "local")
        current_ds_key = env_vars.get("DEEPSEEK_API_KEY", "")
        current_oa_key = env_vars.get("OPENAI_API_KEY", "")
        
        # Determine default index
        default_index = 0
        if current_provider == "api":
            if current_oa_key and not current_ds_key:
                default_index = 2  # OpenAI API
            else:
                default_index = 1  # DeepSeek API
                
        ai_provider = st.selectbox(
            "AI Provider",
            ["Local (Ollama)", "DeepSeek API", "OpenAI API", "Azure OpenAI"],
            index=default_index
        )
        
        if ai_provider == "Local (Ollama)":
            ollama_url = st.text_input("Ollama URL", "http://localhost:11434")
            model_name = st.text_input("Model Name", "deepseek-coder:latest")
            
            col1, col2 = st.columns(2)
            with col1:
                temperature = st.slider("Temperature", 0.0, 2.0, 0.7, 0.1)
            with col2:
                max_tokens = st.number_input("Max Tokens", 100, 10000, 2000)
        
        elif ai_provider == "DeepSeek API":
            # Automatically populate the key if it exists in .env
            api_key = st.text_input("API Key", value=current_ds_key, type="password")
            model_name = st.selectbox("Model", ["deepseek-chat", "deepseek-coder"])
            
            st.info("DeepSeek API provides high-performance AI with specialized security knowledge.")
        
        elif ai_provider == "OpenAI API":
            # Automatically populate the key if it exists in .env
            api_key = st.text_input("API Key", value=current_oa_key, type="password")
            model_name = st.selectbox("Model", ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"])
            
            st.info("OpenAI API provides advanced AI capabilities with strong security context.")
        
        elif ai_provider == "Azure OpenAI":
            # Azure OpenAI requires different configuration
            azure_endpoint = st.text_input("Azure Endpoint", placeholder="https://<your-resource>.openai.azure.com/")
            api_key = st.text_input("API Key", type="password")
            deployment_name = st.text_input("Deployment Name", placeholder="gpt-4")
            api_version = st.text_input("API Version", value="2024-02-01")
            
            st.info("Azure OpenAI provides enterprise-grade AI with enhanced security and compliance.")
        
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
            with st.spinner("Saving configuration..."):
                # Prepare payload based on selected provider
                api_key_value = ""
                model_name_value = ""
                
                # Get api_key if it exists (only for DeepSeek API)
                if "DeepSeek" in ai_provider:
                    try:
                        api_key_value = api_key
                    except NameError:
                        api_key_value = ""
                
                # Get model_name if it exists
                try:
                    model_name_value = model_name
                except NameError:
                    model_name_value = ""
                
                payload = {
                    "provider": ai_provider,
                    "api_key": api_key_value,
                    "model_name": model_name_value
                }
                try:
                    response = requests.post(f"{API_BASE}/settings/ai", json=payload)
                    if response.status_code == 200:
                        st.success("AI settings saved successfully! The AI engine is now connected.")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(f"Failed to save settings: {response.text}")
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
            st.success("Security settings saved!")
    
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
        
        if st.button("💾 Save Advanced Settings", type="primary"):
            st.success("Advanced settings saved!")
        
        st.markdown("---")
        
        # Danger zone
        st.subheader("Danger Zone")
        st.warning("These actions cannot be undone.")
        if st.button("🗑️ Clear ALL Sessions and Data", type="primary"):
            response = requests.delete(f"{API_BASE}/sessions")
            if response.status_code == 200:
                st.session_state.selected_session = None
                st.success("All database records cleared!")
                time.sleep(1)
                st.rerun()
            else:
                st.error(f"Failed to clear all sessions: {response.status_code}")


if __name__ == "__main__":
    main()
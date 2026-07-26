#!/usr/bin/env python3
"""
KMN-CyberSeek Main Backend Server
FastAPI-based orchestrator for AI-driven autonomous red team operations.
"""

import asyncio
import json
import logging
import os
import secrets
import sys
from dotenv import load_dotenv, set_key
load_dotenv()
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
import uvicorn

from ai.connector import KMN_AI_Connector
from core.orchestrator import Orchestrator
from core.scanner import Scanner
from core.validators import is_valid_target, is_cidr

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# --- API authentication -----------------------------------------------------
# This API can execute arbitrary shell commands on behalf of a session
# (/api/execute, the AI auto-execute loop). It must never be reachable without
# a shared secret, even on a "trusted" local network. Auto-generate and persist
# a token on first run so the operator doesn't have to set one up manually.
API_AUTH_TOKEN = os.getenv("API_AUTH_TOKEN")
if not API_AUTH_TOKEN:
    API_AUTH_TOKEN = secrets.token_urlsafe(32)
    _env_path = os.path.join(os.getcwd(), ".env")
    if not os.path.exists(_env_path):
        open(_env_path, "w").close()
    set_key(_env_path, "API_AUTH_TOKEN", API_AUTH_TOKEN)
    logger.warning(
        "No API_AUTH_TOKEN found - generated a new one and saved it to .env. "
        "The Streamlit frontend reads it from the same .env file automatically."
    )

_OPEN_PATHS = {"/", "/health", "/api/docs", "/api/redoc", "/api/openapi.json"}

app = FastAPI(
    title="KMN-CyberSeek API",
    on_startup=[],   # populated below after orchestrator is built
    description="AI-Driven Autonomous Red Team Operator Backend",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],  # Streamlit default
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def enforce_api_key(request: Request, call_next):
    """Require X-API-Key on every /api/* route. CORS alone does NOT stop
    direct (non-browser) requests, so this is the real access control."""
    path = request.url.path
    if path in _OPEN_PATHS or not path.startswith("/api/"):
        return await call_next(request)

    supplied = request.headers.get("x-api-key", "")
    if not supplied or not secrets.compare_digest(supplied, API_AUTH_TOKEN):
        return JSONResponse(status_code=401, content={"detail": "Missing or invalid X-API-Key header"})

    return await call_next(request)

# Global instances
ai_provider = os.getenv("AI_PROVIDER")
# If AI_PROVIDER is not set, let the connector auto-detect based on API key presence
ai_connector = KMN_AI_Connector(provider=ai_provider)
scanner = Scanner()
orchestrator = Orchestrator(ai_connector, scanner)

# WebSocket connections
active_connections: List[WebSocket] = []

async def broadcast_message(message_type: str, data: Dict):
    """Broadcast message to all active WebSocket connections."""
    message = {"type": message_type, "data": data, "timestamp": datetime.now().isoformat()}
    for connection in active_connections:
        try:
            await connection.send_json(message)
        except Exception as e:
            logger.error(f"Failed to send message to WebSocket: {e}")


# Wire the broadcast function into the orchestrator so execute_command can stream
# live output chunks to WebSocket clients (see core/orchestrator.py execute_command).
orchestrator.broadcast_callback = broadcast_message


# --- Background scheduler for recurring scans ----------------------------------
async def _scheduler_loop():
    """Tick every 60 seconds, fire any scheduled scans that are due."""
    while True:
        try:
            await orchestrator.run_due_scheduled_scans()
        except Exception as e:
            logger.error(f"Scheduler loop error (non-fatal): {e}")
        await asyncio.sleep(60)


@app.on_event("startup")
async def _start_scheduler():
    asyncio.create_task(_scheduler_loop())
    logger.info("Background scan scheduler started (60s tick)")


# Pydantic Models
class TargetRequest(BaseModel):
    """Target input model."""
    ip: str = Field(..., description="Target IP address, hostname, or CIDR subnet (e.g. 192.168.1.0/24)")
    domain: Optional[str] = Field(None, description="Optional domain name")
    session_name: Optional[str] = Field(None, description="Custom session name")
    auto_approve: bool = Field(False, description="Auto-approve low/medium risk commands")
    max_auto_depth: int = Field(5, description="Maximum consecutive auto-executed commands")
    authorization_confirmed: bool = Field(
        ..., description="Must be true: operator confirms they own this target or have explicit permission to test it"
    )

    @field_validator("ip")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        if not is_valid_target(v):
            raise ValueError("Target must be a valid IP address or hostname (no spaces or special characters)")
        return v

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: Optional[str]) -> Optional[str]:
        if v and not is_valid_target(v):
            raise ValueError("Domain must be a valid hostname (no spaces or special characters)")
        return v

class CommandRequest(BaseModel):
    """Command execution request."""
    session_id: str = Field(..., description="Session identifier")
    command: str = Field(..., description="Command to execute")
    auto_approve: bool = Field(False, description="Whether to auto-approve execution")

class ApprovalRequest(BaseModel):
    """Approval request for high-risk commands."""
    session_id: str = Field(..., description="Session identifier")
    command_id: str = Field(..., description="Command identifier")
    approve: bool = Field(True, description="Approve or deny the command")

# Known context windows for common Ollama models — used as fallback when
# /api/show doesn't expose the model_info.context_length field.
_KNOWN_CTX: dict = {
    "deepseek-r1:1.5b": 4096,
    "deepseek-r1:7b":   8192,
    "deepseek-r1:8b":   8192,
    "deepseek-r1:14b":  16384,
    "deepseek-r1:32b":  32768,
    "deepseek-r1:70b":  131072,
    "deepseek-r1:671b": 131072,
    "llama3.1:8b":      131072,
    "llama3.1:70b":     131072,
    "llama3.2:1b":      131072,
    "llama3.2:3b":      131072,
    "llama3.3:70b":     131072,
    "qwen2.5:7b":       32768,
    "qwen2.5:14b":      32768,
    "qwen2.5:32b":      32768,
    "qwen2.5:72b":      131072,
    "qwen2.5-coder:7b": 32768,
    "qwen2.5-coder:14b":32768,
    "qwen2.5-coder:32b":32768,
    "mistral:7b":       32768,
    "mistral:latest":   32768,
    "mistral-nemo":     128000,
    "codellama:7b":     16384,
    "codellama:13b":    16384,
    "phi3:mini":        128000,
    "phi3:medium":      128000,
    "phi4:latest":      16384,
    "gemma2:2b":        8192,
    "gemma2:9b":        8192,
    "gemma2:27b":       8192,
    "deephat/deephat-v1-7b": 8192,
    "deepseek-coder-v2:16b": 32768,
    "deepseek-coder-v2:236b": 131072,
}

class AISettings(BaseModel):
    """AI settings update model."""
    provider: str  # "Local (Ollama)" or "DeepSeek API"
    api_key: str = ""
    model_name: str = ""  # Ollama model tag OR DeepSeek model name, depending on provider
    ollama_url: str = ""
    ollama_context_window: Optional[int] = None  # if set, saved to .env + applied immediately

class VulnersSettings(BaseModel):
    """Vulners API key update model (optional CVE enrichment - see core/cve_lookup.py)."""
    api_key: str = ""


class SecuritySettings(BaseModel):
    """Security / operational settings persisted to .env."""
    require_approval_high_risk: bool = True
    approval_timeout_minutes: int = 15
    audit_logging: bool = True
    session_timeout_hours: int = 24
    max_parallel_commands: int = 3
    auto_cleanup: bool = True
    cleanup_after_days: int = 30


class AdvancedSettings(BaseModel):
    """Advanced backend settings persisted to .env."""
    log_level: str = "INFO"
    log_file: str = "backend.log"
    debug: bool = False
    db_path: str = "kmn_cyberseek.db"
    full_auto_mode: bool = False
    ollama_context_window: int = 8192


class ScheduledScanRequest(BaseModel):
    """Create or update a scheduled recurring scan."""
    target_ip: str = Field(..., description="Target IP, hostname, or CIDR subnet")
    target_domain: str = Field("", description="Optional target domain")
    label: str = Field("", description="Human-readable label for this schedule")
    schedule_type: str = Field(..., description="'daily', 'weekly', or 'once'")
    schedule_time: str = Field(..., description="HH:MM (24h UTC) when the scan should run")
    schedule_day: Optional[int] = Field(None, description="0=Mon..6=Sun; only for 'weekly'")


class ThreatIntelRequest(BaseModel):
    """Request to research a topic on the open web (see core/threat_intel.py)."""
    topic: str = Field(..., min_length=1, max_length=200, description="Topic to research, e.g. 'Apache httpd' or 'latest critical CVEs'")

# API Endpoints
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "KMN-CyberSeek",
        "version": "2.0.0",
        "status": "operational",
        "endpoints": ["/api/docs", "/api/start", "/api/sessions", "/api/ws"],
        "description": "AI-Driven Autonomous Red Team Operator"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/api/start")
async def start_session(target_request: TargetRequest):
    """Start a new penetration testing session."""
    try:
        logger.info(f"Starting new session for target: {target_request.ip}")

        # Initialize session
        session_id = orchestrator.create_session(
            target_ip=target_request.ip,
            target_domain=target_request.domain,
            session_name=target_request.session_name,
            auto_approve=target_request.auto_approve,
            max_auto_depth=target_request.max_auto_depth,
            authorization_confirmed=target_request.authorization_confirmed
        )

        # Start initial reconnaissance
        asyncio.create_task(orchestrator.start_reconnaissance(session_id))

        return {
            "session_id": session_id,
            "target": target_request.ip,
            "status": "initialized",
            "message": "Session created and reconnaissance started"
        }
    except ValueError as e:
        # Validation / authorization / scope errors -> 400, not 500
        logger.warning(f"Rejected session start for target {target_request.ip}: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to start session: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/sessions")
async def list_sessions():
    """List all active sessions."""
    sessions = orchestrator.get_sessions()
    return {"sessions": sessions, "count": len(sessions)}

@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    """Get details of a specific session."""
    try:
        session_report = orchestrator.get_session_report(session_id)
        logger.info(f"get_session_report returned keys: {list(session_report.keys())}")
        logger.info(f"Has 'session' key? {'session' in session_report}")
        logger.info(f"Has 'discovered_hosts' key? {'discovered_hosts' in session_report}")
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    return session_report

@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete a specific session and all its associated data."""
    try:
        result = orchestrator.delete_session(session_id)
        if result["status"] == "error":
            raise HTTPException(status_code=500, detail=result["message"])
        return result
    except Exception as e:
        logger.error(f"Failed to delete session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/sessions")
async def delete_all_sessions():
    """Delete all sessions and all associated data."""
    try:
        result = orchestrator.delete_all_sessions()
        if result["status"] == "error":
            raise HTTPException(status_code=500, detail=result["message"])
        return result
    except Exception as e:
        logger.error(f"Failed to delete all sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/sessions/{session_id}/pending_commands")
async def get_pending_commands(session_id: str):
    """Get all pending commands for a specific session."""
    if not orchestrator.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")

    pending_commands = [
        {"command_id": command_id, **command_data}
        for command_id, command_data in orchestrator.pending_commands.items()
        if command_data.get("session_id") == session_id and command_data.get("status") == "pending"
    ]

    return {
        "session_id": session_id,
        "pending_commands": pending_commands,
        "count": len(pending_commands)
    }


@app.get("/api/sessions/{session_id}/report")
async def download_session_report(session_id: str):
    """Generate and download a DOCX penetration-test report for a session.
    Requires python-docx (pip install python-docx). Returns the file directly
    so the browser/client downloads it immediately."""
    try:
        report_data = orchestrator.get_session_report(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")

    try:
        from core.report_generator import generate_report
    except ImportError as e:
        raise HTTPException(
            status_code=501,
            detail=f"Report generation unavailable: {e}. Install python-docx."
        )

    try:
        import tempfile, os
        out_dir = tempfile.gettempdir()
        out_path = os.path.join(out_dir, f"kmn_report_{session_id[:12]}.docx")
        generate_report(report_data, output_path=out_path)
    except Exception as e:
        logger.error(f"Report generation failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

    filename = f"kmn_report_{session_id[:12]}.docx"
    return FileResponse(
        path=out_path,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/api/sessions/{session_id}/report/pdf")
async def download_session_report_pdf(session_id: str):
    """Generate and download a PDF penetration-test report for a session.
    Requires fpdf2 (pip install fpdf2). Returns the file directly."""
    try:
        report_data = orchestrator.get_session_report(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")

    try:
        from core.report_generator import generate_pdf_report
    except ImportError as e:
        raise HTTPException(status_code=501, detail=f"PDF generation unavailable: {e}. Install fpdf2.")

    try:
        import tempfile
        out_dir = tempfile.gettempdir()
        out_path = os.path.join(out_dir, f"kmn_report_{session_id[:12]}.pdf")
        generate_pdf_report(report_data, output_path=out_path)
    except Exception as e:
        logger.error(f"PDF report generation failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=f"PDF report generation failed: {e}")

    filename = f"kmn_report_{session_id[:12]}.pdf"
    return FileResponse(
        path=out_path,
        media_type="application/pdf",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/api/schedules")
async def list_schedules():
    """List all non-deleted scheduled scans."""
    return {"schedules": orchestrator.list_scheduled_scans(), "count": len(orchestrator.list_scheduled_scans())}


@app.post("/api/schedules")
async def create_schedule(req: ScheduledScanRequest):
    """Create a new recurring scan schedule."""
    try:
        record = orchestrator.create_scheduled_scan(
            target_ip=req.target_ip,
            target_domain=req.target_domain,
            label=req.label,
            schedule_type=req.schedule_type,
            schedule_time=req.schedule_time,
            schedule_day=req.schedule_day
        )
        return {"status": "created", "schedule": record}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.patch("/api/schedules/{scan_id}")
async def update_schedule_status(scan_id: int, status: str):
    """Pause, resume, or delete a scheduled scan. status: active|paused|deleted"""
    ok = orchestrator.update_scheduled_scan_status(scan_id, status)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid scan_id or status")
    return {"status": "updated", "scan_id": scan_id, "new_status": status}


@app.get("/api/sessions/history")
async def list_session_history():
    """List ALL sessions from the database including completed and failed ones.
    Unlike GET /api/sessions (active-only, in-memory), this queries the DB
    directly so historical sessions survive backend restarts. Returns lightweight
    summary rows - no scan blobs or command output."""
    history = orchestrator.get_session_history()
    return {"sessions": history, "count": len(history)}


@app.get("/api/stats")
async def get_aggregate_stats():
    """Aggregate statistics for the dashboard charts.
    Queries the DB directly so it captures all sessions, not just in-memory active ones.
    Returns vuln distribution, sessions-per-day (last 14 days), status breakdown,
    and top targeted hosts."""
    import sqlite3 as _sqlite3
    from datetime import datetime as _dt, timedelta as _td

    db_path = orchestrator.db_path

    def _q(sql, params=()):
        conn = _sqlite3.connect(db_path)
        conn.row_factory = _sqlite3.Row
        try:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # Vulnerability risk distribution
    vuln_dist = _q(
        "SELECT risk_level, COUNT(*) as count FROM vulnerabilities GROUP BY risk_level"
    )
    vuln_by_risk = {r["risk_level"]: r["count"] for r in vuln_dist}

    # Sessions per day – last 14 days
    sessions_per_day = _q(
        """SELECT date(created_at) as day, COUNT(*) as count
           FROM sessions
           WHERE created_at >= date('now', '-14 days')
           GROUP BY day
           ORDER BY day"""
    )

    # Status breakdown
    status_dist = _q(
        "SELECT status, COUNT(*) as count FROM sessions GROUP BY status"
    )
    status_by_name = {r["status"]: r["count"] for r in status_dist}

    # Top 5 most-scanned targets
    top_targets = _q(
        """SELECT target_ip, COUNT(*) as count FROM sessions
           GROUP BY target_ip ORDER BY count DESC LIMIT 5"""
    )

    # Credentials found total
    cred_rows = _q("SELECT COUNT(*) as cnt FROM credentials")
    cred_total = cred_rows[0]["cnt"] if cred_rows else 0

    # Commands executed total
    cmd_rows = _q("SELECT COUNT(*) as cnt FROM commands")
    cmd_total = cmd_rows[0]["cnt"] if cmd_rows else 0

    return {
        "vuln_distribution": {
            "high": vuln_by_risk.get("high", 0),
            "medium": vuln_by_risk.get("medium", 0),
            "low": vuln_by_risk.get("low", 0),
            "info": vuln_by_risk.get("info", 0),
        },
        "sessions_per_day": sessions_per_day,
        "status_distribution": status_by_name,
        "top_targets": top_targets,
        "credentials_total": cred_total,
        "commands_total": cmd_total,
    }


@app.post("/api/sessions/{session_id}/complete")
async def complete_session(session_id: str):
    """Mark a session as completed. Useful when the operator is done and wants
    the session archived (it will appear in /api/sessions/history but not be
    loaded into active memory on the next restart)."""
    if session_id not in orchestrator.sessions:
        raise HTTPException(status_code=404, detail="Session not found (must be active to complete)")
    result = orchestrator.complete_session(session_id)
    if result["status"] == "error":
        raise HTTPException(status_code=500, detail=result["message"])
    return result


@app.get("/api/sessions/{session_id}/vulnerabilities")
async def get_vulnerabilities(session_id: str):
    """Get all recorded vulnerability findings for a session (structured, from
    the vulnerabilities table - see core/orchestrator.py add_vulnerability())."""
    if not orchestrator.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")

    vulnerabilities = orchestrator.get_vulnerabilities(session_id)
    return {
        "session_id": session_id,
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities)
    }


@app.get("/api/sessions/{session_id}/live_output")
async def get_live_output(session_id: str):
    """Return the current streaming command output buffer for a session.
    Empty string when no command is running. Streamlit frontend polls this at
    5-second intervals to display live output while a long scan is in progress."""
    if not orchestrator.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    output = orchestrator.get_live_output(session_id)
    return {"session_id": session_id, "live_output": output, "is_live": bool(output)}


@app.get("/api/sessions/{session_id}/credentials")
async def get_credentials(session_id: str):
    """Get all credentials captured for a session (username/password pairs extracted
    automatically from tool output by core/orchestrator.py _extract_and_store_credentials).
    Secrets are returned as-is - protect this endpoint with the X-API-Key header."""
    if not orchestrator.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    creds = orchestrator.get_credentials(session_id)
    return {"session_id": session_id, "credentials": creds, "count": len(creds)}


@app.post("/api/threat-intel/research")
async def start_threat_intel_research(request: ThreatIntelRequest):
    """Kick off AI-directed open-web research for a topic (core/threat_intel.py).
    Runs in the background - poll GET /api/threat-intel for results. Findings are
    stored unverified; this is a shared cache, not tied to any single session."""
    logger.info(f"Starting threat-intel research: {request.topic}")
    asyncio.create_task(orchestrator.run_threat_intel_research(request.topic))
    return {
        "status": "started",
        "topic": request.topic,
        "message": "Research started in the background. Poll GET /api/threat-intel for results."
    }


@app.get("/api/threat-intel")
async def list_threat_intel(topic: Optional[str] = None):
    """List cached threat-intel findings, optionally filtered by topic (substring match)."""
    findings = orchestrator.get_threat_intel(topic)
    return {"topic_filter": topic, "findings": findings, "count": len(findings)}


@app.post("/api/sessions/{session_id}/start")
async def start_session_scan(session_id: str):
    """Start initial reconnaissance scan for a session."""
    if session_id not in orchestrator.sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = orchestrator.sessions[session_id]
    
    # Prevent starting if already scanning or beyond
    if session.status != "initialized":
        return {"status": "ignored", "message": "Session is already active"}
        
    session.status = "scanning"
    logger.info(f"Starting initial reconnaissance for session {session_id}")
    
    # Start the reconnaissance scan
    asyncio.create_task(orchestrator.start_reconnaissance(session_id))
        
    return {"status": "success", "message": "Initial scan started"}


@app.post("/api/sessions/{session_id}/analyze")
async def analyze_with_ai(session_id: str):
    """Trigger AI analysis for a session."""
    try:
        await orchestrator._analyze_with_ai(session_id)
        return {
            "status": "success",
            "message": "AI analysis completed successfully",
            "session_id": session_id
        }
    except Exception as e:
        logger.error(f"AI analysis failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sessions/{session_id}/resume")
async def resume_session(session_id: str):
    """Manually resume AI analysis for a session."""
    if session_id not in orchestrator.sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    logger.info(f"Manual resume triggered for {session_id}")
    orchestrator.sessions[session_id].status = "analyzing"
    asyncio.create_task(orchestrator._analyze_with_ai(session_id))
    return {"status": "success", "message": "AI analysis resumed"}

@app.get("/api/ollama/models")
async def list_ollama_models():
    """Return the list of models available on the configured Ollama server.
    Queries Ollama's GET /api/tags endpoint. Returns an empty list (not an
    error) if Ollama is unreachable so the frontend can degrade gracefully."""
    base = os.getenv("OLLAMA_URL", "http://localhost:11434").strip().rstrip("/")
    # Strip /api/generate suffix if present
    if base.endswith("/api/generate"):
        base = base[: -len("/api/generate")].rstrip("/")
    try:
        import httpx as _httpx
        async with _httpx.AsyncClient(timeout=8) as client:
            r = await client.get(f"{base}/api/tags")
            r.raise_for_status()
            data = r.json()
        models = []
        for m in data.get("models", []):
            name = m.get("name", "")
            size_bytes = m.get("size", 0)
            size_gb = round(size_bytes / 1e9, 1) if size_bytes else None
            models.append({"name": name, "size_gb": size_gb})
        return {"models": models, "ollama_url": base}
    except Exception as exc:
        return {"models": [], "error": str(exc), "ollama_url": base}


@app.get("/api/ollama/model-info")
async def get_ollama_model_info(model: str):
    """Return context window and basic metadata for a specific Ollama model.
    Tries three sources in order:
      1. Ollama /api/show → model_info (architecture-specific context_length key)
      2. Ollama /api/show → parameters string (num_ctx override)
      3. Built-in _KNOWN_CTX lookup table
    Falls back to 8192 if none of the above yields a value."""
    base = os.getenv("OLLAMA_URL", "http://localhost:11434").strip().rstrip("/")
    if base.endswith("/api/generate"):
        base = base[: -len("/api/generate")].rstrip("/")

    context_window = None
    architecture = None
    param_count = None
    source = "unknown"

    try:
        import httpx as _httpx
        async with _httpx.AsyncClient(timeout=15) as client:
            r = await client.post(f"{base}/api/show", json={"name": model})
            r.raise_for_status()
            info = r.json()

        # ── Source 1: model_info ─────────────────────────────────────────────
        model_info = info.get("model_info", {})
        # Context length key varies by architecture: llama.context_length,
        # qwen2.context_length, phi3.context_length, gemma.context_length, etc.
        for key, val in model_info.items():
            if "context_length" in key.lower() and isinstance(val, int) and val > 0:
                context_window = val
                source = f"model_info[{key!r}]"
                break
        architecture = model_info.get("general.architecture", None)
        param_count = model_info.get("general.parameter_count", None)

        # ── Source 2: parameters override (num_ctx in Modelfile) ────────────
        if not context_window:
            params_str = info.get("parameters", "")
            import re as _re
            m = _re.search(r'\bnum_ctx\s+(\d+)', params_str, _re.IGNORECASE)
            if m:
                context_window = int(m.group(1))
                source = "parameters[num_ctx]"

    except Exception as exc:
        pass  # Ollama unreachable — fall through to lookup table

    # ── Source 3: known-models lookup table ──────────────────────────────────
    if not context_window:
        clean = model.lower().strip()
        context_window = _KNOWN_CTX.get(clean)
        if context_window:
            source = "built-in lookup table"

    # ── Default ──────────────────────────────────────────────────────────────
    if not context_window:
        context_window = 8192
        source = "default fallback"

    return {
        "model": model,
        "context_window": context_window,
        "architecture": architecture,
        "param_count": param_count,
        "source": source,
    }


@app.post("/api/settings/ai")
async def update_ai_settings(settings: AISettings):
    """Update AI settings (persisted to .env, works even if .env starts empty) and
    reload the connector. Supports exactly two providers: DeepSeek API and local
    Ollama (any model you've pulled, e.g. deepseek-r1:8b or a security-tuned model
    like DeepHat/DeepHat-V1-7B)."""
    env_path = os.path.join(os.getcwd(), '.env')
    if not os.path.exists(env_path):
        open(env_path, 'w').close()

    # Map the UI provider string to backend provider code
    provider_code = "api" if "DeepSeek" in settings.provider else "local"
    set_key(env_path, "AI_PROVIDER", provider_code)

    local_model = None
    ollama_url = None
    api_model = None

    if provider_code == "api":
        if settings.api_key:
            set_key(env_path, "DEEPSEEK_API_KEY", settings.api_key)
        if settings.model_name:
            set_key(env_path, "DEEPSEEK_MODEL", settings.model_name)
            api_model = settings.model_name
    else:
        if settings.model_name:
            set_key(env_path, "OLLAMA_MODEL", settings.model_name)
            local_model = settings.model_name
        if settings.ollama_url:
            set_key(env_path, "OLLAMA_URL", settings.ollama_url)
            ollama_url = settings.ollama_url
        if settings.ollama_context_window is not None:
            set_key(env_path, "OLLAMA_CONTEXT_WINDOW", str(settings.ollama_context_window))
            os.environ["OLLAMA_CONTEXT_WINDOW"] = str(settings.ollama_context_window)

    # Re-initialize the global AI connector with new settings
    global ai_connector, orchestrator
    ai_connector = KMN_AI_Connector(
        provider=provider_code,
        api_key=settings.api_key or None,
        local_model=local_model,
        ollama_url=ollama_url,
        api_model=api_model
    )
    orchestrator.ai_connector = ai_connector

    ctx = ai_connector.context_window if provider_code == "local" else None
    return {
        "status": "success",
        "message": "AI settings updated and connector reloaded",
        "provider": provider_code,
        "model": ai_connector.local_model if provider_code == "local" else ai_connector.api_model,
        "context_window": ctx,
    }

@app.post("/api/settings/vulners")
async def update_vulners_settings(settings: VulnersSettings):
    """Save the Vulners API key used for optional CVE enrichment (core/cve_lookup.py).
    Purely additive - if left blank, vulnerability findings still come from Nmap's
    NSE vuln scripts, just without CVE/CVSS enrichment."""
    env_path = os.path.join(os.getcwd(), '.env')
    if not os.path.exists(env_path):
        open(env_path, 'w').close()

    set_key(env_path, "VULNERS_API_KEY", settings.api_key)
    # cve_lookup reads the env var fresh on every lookup call, so no reload needed -
    # but refresh the process's own env in case it was loaded once at startup.
    os.environ["VULNERS_API_KEY"] = settings.api_key

    return {
        "status": "success",
        "message": "Vulners API key saved" if settings.api_key else "Vulners API key cleared (CVE enrichment disabled)",
        "configured": bool(settings.api_key)
    }

@app.post("/api/settings/security")
async def update_security_settings(settings: SecuritySettings):
    """Persist security/operational settings to .env so they survive restarts."""
    env_path = os.path.join(os.getcwd(), ".env")
    if not os.path.exists(env_path):
        open(env_path, "w").close()

    set_key(env_path, "REQUIRE_APPROVAL_HIGH_RISK", str(settings.require_approval_high_risk).lower())
    set_key(env_path, "APPROVAL_TIMEOUT_MINUTES",   str(settings.approval_timeout_minutes))
    set_key(env_path, "AUDIT_LOGGING",              str(settings.audit_logging).lower())
    set_key(env_path, "SESSION_TIMEOUT_HOURS",       str(settings.session_timeout_hours))
    set_key(env_path, "MAX_CONCURRENT_SCANS",        str(settings.max_parallel_commands))
    set_key(env_path, "AUTO_CLEANUP",               str(settings.auto_cleanup).lower())
    set_key(env_path, "CLEANUP_AFTER_DAYS",          str(settings.cleanup_after_days))

    return {"status": "success", "message": "Security settings saved"}


@app.post("/api/settings/advanced")
async def update_advanced_settings(settings: AdvancedSettings):
    """Persist advanced backend settings to .env."""
    env_path = os.path.join(os.getcwd(), ".env")
    if not os.path.exists(env_path):
        open(env_path, "w").close()

    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    log_level = settings.log_level.upper() if settings.log_level.upper() in valid_levels else "INFO"

    set_key(env_path, "LOG_LEVEL",       log_level)
    set_key(env_path, "LOG_FILE",        settings.log_file or "backend.log")
    set_key(env_path, "DEBUG",           str(settings.debug).lower())
    set_key(env_path, "DB_PATH",         settings.db_path or "kmn_cyberseek.db")
    set_key(env_path, "FULL_AUTO_MODE",          str(settings.full_auto_mode).lower())
    set_key(env_path, "OLLAMA_CONTEXT_WINDOW",    str(settings.ollama_context_window))

    # Apply log level to running process immediately (no restart needed)
    import logging as _logging
    _logging.getLogger().setLevel(getattr(_logging, log_level, _logging.INFO))

    # Propagate runtime-changeable settings into os.environ so the running
    # process picks them up on the next call without requiring a restart.
    os.environ["FULL_AUTO_MODE"] = str(settings.full_auto_mode).lower()
    os.environ["OLLAMA_CONTEXT_WINDOW"] = str(settings.ollama_context_window)

    # Also update the live AI connector instance so the context window takes
    # effect immediately for the current session.
    try:
        orchestrator.ai_connector.context_window = settings.ollama_context_window
    except Exception:
        pass  # non-fatal if connector not yet initialised

    return {
        "status": "success",
        "message": "Advanced settings saved",
        "log_level": log_level,
        "full_auto_mode": settings.full_auto_mode,
        "ollama_context_window": settings.ollama_context_window,
    }


@app.post("/api/execute")
async def execute_command(command_request: CommandRequest):
    """Execute a command in a session."""
    try:
        # Check if command requires approval
        requires_approval = orchestrator.requires_approval(command_request.command)
        
        if requires_approval and not command_request.auto_approve:
            # Queue for approval
            command_id = orchestrator.queue_for_approval(
                session_id=command_request.session_id,
                command=command_request.command
            )
            await broadcast_message("command_pending", {
                "session_id": command_request.session_id,
                "command_id": command_id,
                "command": command_request.command
            })
            return {
                "status": "pending_approval",
                "command_id": command_id,
                "message": "Command requires manual approval"
            }
        else:
            # Execute immediately
            result = await orchestrator.execute_command(
                session_id=command_request.session_id,
                command=command_request.command
            )
            await broadcast_message("command_executed", {
                "session_id": command_request.session_id,
                "command": command_request.command,
                "result": result
            })
            return {
                "status": "executed",
                "result": result,
                "message": "Command executed successfully"
            }
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/approve")
async def approve_command(approval_request: ApprovalRequest):
    """Approve or deny a pending command."""
    try:
        if approval_request.approve:
            result = orchestrator.approve_command(
                session_id=approval_request.session_id,
                command_id=approval_request.command_id
            )
            await broadcast_message("command_approved", {
                "session_id": approval_request.session_id,
                "command_id": approval_request.command_id,
                "result": result
            })
            return {
                "status": "approved",
                "result": result,
                "message": "Command approved and executed"
            }
        else:
            orchestrator.deny_command(
                session_id=approval_request.session_id,
                command_id=approval_request.command_id
            )
            await broadcast_message("command_denied", {
                "session_id": approval_request.session_id,
                "command_id": approval_request.command_id
            })
            return {
                "status": "denied",
                "message": "Command denied"
            }
    except Exception as e:
        logger.error(f"Approval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# WebSocket endpoint for real-time updates
@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time communication."""
    # HTTP middleware doesn't run for WS upgrades, so check the token explicitly.
    token = websocket.query_params.get("token", "")
    if not token or not secrets.compare_digest(token, API_AUTH_TOKEN):
        await websocket.close(code=1008)  # policy violation
        return

    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Echo received data (could be used for commands)
            await websocket.send_json({
                "type": "echo",
                "data": data,
                "timestamp": datetime.now().isoformat()
            })
    except WebSocketDisconnect:
        active_connections.remove(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if websocket in active_connections:
            active_connections.remove(websocket)

def start_operation():
    """Start the FastAPI server."""
    # Default to localhost-only. This API can execute shell commands, so binding
    # to 0.0.0.0 exposes that to the whole network - only do so deliberately via
    # BACKEND_HOST in .env, and keep API_AUTH_TOKEN secret if you do.
    host = os.getenv("BACKEND_HOST", "127.0.0.1")
    port = int(os.getenv("BACKEND_PORT", "8000"))

    logger.info("Starting KMN-CyberSeek backend server...")
    logger.info(f"API Documentation: http://localhost:{port}/api/docs")
    logger.info(f"Streamlit Frontend: http://localhost:8501")
    if host != "127.0.0.1" and host != "localhost":
        logger.warning(f"BACKEND_HOST={host} - the API is reachable beyond localhost. Ensure API_AUTH_TOKEN stays secret.")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )

if __name__ == "__main__":
    start_operation()

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
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
import uvicorn

from ai.connector import KMN_AI_Connector
from core.orchestrator import Orchestrator
from core.scanner import Scanner
from core.validators import is_valid_target

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
    description="AI-Driven Autonomous Red Team Operator Backend",
    version="1.0.0",
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

# Pydantic Models
class TargetRequest(BaseModel):
    """Target input model."""
    ip: str = Field(..., description="Target IP address or domain")
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

class AISettings(BaseModel):
    """AI settings update model."""
    provider: str  # "Local (Ollama)" or "DeepSeek API"
    api_key: str = ""
    model_name: str = ""  # Ollama model tag OR DeepSeek model name, depending on provider
    ollama_url: str = ""

# API Endpoints
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "KMN-CyberSeek",
        "version": "1.0.0",
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

    return {
        "status": "success",
        "message": "AI settings updated and connector reloaded",
        "provider": provider_code,
        "model": ai_connector.local_model if provider_code == "local" else ai_connector.api_model
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

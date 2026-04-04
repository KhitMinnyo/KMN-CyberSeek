#!/usr/bin/env python3
"""
KMN-CyberSeek Main Backend Server
FastAPI-based orchestrator for AI-driven autonomous red team operations.
"""

import asyncio
import json
import logging
import os
import sys
from dotenv import load_dotenv, set_key
load_dotenv()
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

from ai.connector import KMN_AI_Connector
from core.orchestrator import Orchestrator
from core.scanner import Scanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

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
    provider: str
    api_key: str = ""
    model_name: str = ""

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
            session_name=target_request.session_name
        )
        
        # Start initial reconnaissance
        asyncio.create_task(orchestrator.start_reconnaissance(session_id))
        
        return {
            "session_id": session_id,
            "target": target_request.ip,
            "status": "initialized",
            "message": "Session created and reconnaissance started"
        }
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
    """Update AI settings and reload connector."""
    env_path = os.path.join(os.getcwd(), '.env')
    if not os.path.exists(env_path):
        open(env_path, 'w').close()
    
    # Map the UI provider string to backend provider code
    provider_code = "api" if "API" in settings.provider else "local"
    
    # Update .env file
    set_key(env_path, "AI_PROVIDER", provider_code)
    if "DeepSeek" in settings.provider:
        set_key(env_path, "DEEPSEEK_API_KEY", settings.api_key)
    elif "OpenAI" in settings.provider:
        set_key(env_path, "OPENAI_API_KEY", settings.api_key)
    
    # Re-initialize the global AI connector with new settings
    global ai_connector, orchestrator
    ai_connector = KMN_AI_Connector(provider=provider_code, api_key=settings.api_key)
    orchestrator.ai_connector = ai_connector
    
    return {"status": "success", "message": "AI settings updated and connector reloaded"}

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
    logger.info("Starting KMN-CyberSeek backend server...")
    logger.info(f"API Documentation: http://localhost:8000/api/docs")
    logger.info(f"Streamlit Frontend: http://localhost:8501")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )

if __name__ == "__main__":
    start_operation()

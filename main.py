#!/usr/bin/env python3
"""
KMN-CyberSeek Main Backend Server
FastAPI-based orchestrator for AI-driven autonomous red team operations.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import stat
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
from dotenv import load_dotenv, set_key
load_dotenv()
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.background import BackgroundTask
from pydantic import BaseModel, Field, field_validator
import uvicorn

from ai.connector import KMN_AI_Connector
from core.orchestrator import Orchestrator
from core.scanner import Scanner
from core.shell_manager import validate_handler_config
from core.validators import is_valid_target, is_cidr
from core.report_export import build_report_snapshot, export_sarif
from core.assessment import Assessment, AssessmentError, CoverageKey, MAX_BYTES
from core.artifact_store import ArtifactStore, ArtifactStoreError
from core.access_control import AccessControl, AccessStore, AccessError

# Single source of truth for the version (see _version.py / bump_version.py).
try:
    from _version import __version__ as APP_VERSION
except Exception:  # pragma: no cover
    APP_VERSION = "0.0.0"

# Configure logging.
# In addition to the terminal (stdout), mirror everything to ONE terminal-log
# file. It is opened in 'w' mode so each backend start TRUNCATES and replaces it —
# a single rolling log of the current run, never a growing pile of per-run files.
# Path is configurable via TERMINAL_LOG_FILE; default terminal_output.txt.
_TERMINAL_LOG_FILE = (os.getenv("TERMINAL_LOG_FILE", "").strip() or "terminal_output.txt")
_log_handlers = [logging.StreamHandler(sys.stdout)]
try:
    _log_handlers.append(logging.FileHandler(_TERMINAL_LOG_FILE, mode="w", encoding="utf-8"))
except OSError as _e:  # pragma: no cover - disk/permission issue must not break startup
    print(f"[warn] could not open terminal log file {_TERMINAL_LOG_FILE}: {_e}", file=sys.stderr)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=_log_handlers,
)
logger = logging.getLogger(__name__)


class _AccessLogNoiseFilter(logging.Filter):
    """The Streamlit frontend polls a handful of read-only endpoints every few
    seconds (auto-refresh), which floods the terminal with identical
    'GET ... 200 OK' access lines and buries real events. Drop those successful
    GET polls; keep POST/DELETE, errors, and everything else."""

    _NOISY = (
        "/health", "/api/sessions", "/api/shells/local-ip",
        "/shells", "/pending_commands", "/credentials", "/bruteforce",
        "/handlers", "/live_output", "/settings/features", "/api/stats",
        "/api/schedules", "/api/threat-intel",
    )

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        if '"GET ' not in msg:
            return True  # keep POST/DELETE/etc.
        # Only suppress successful (2xx/304) polls of the noisy read endpoints.
        if not (' 200 ' in msg or ' 304 ' in msg):
            return True
        return not any(p in msg for p in self._NOISY)


# Attach to uvicorn's access logger (created when the server runs).
logging.getLogger("uvicorn.access").addFilter(_AccessLogNoiseFilter())

# --- API authentication -----------------------------------------------------
# This API can execute arbitrary shell commands on behalf of a session
# (/api/execute, the AI auto-execute loop). It must never be reachable without
# a shared secret, even on a "trusted" local network. Auto-generate and persist
# a token on first run so the operator doesn't have to set one up manually.
API_AUTH_TOKEN = os.getenv("API_AUTH_TOKEN")
if not API_AUTH_TOKEN and "KMN_AUTH_PRINCIPALS_FILE" not in os.environ:
    API_AUTH_TOKEN = secrets.token_urlsafe(32)
    _env_path = os.path.join(os.getcwd(), ".env")
    if not os.path.exists(_env_path):
        open(_env_path, "w").close()
    set_key(_env_path, "API_AUTH_TOKEN", API_AUTH_TOKEN)
    logger.warning(
        "No API_AUTH_TOKEN found - generated a new one and saved it to .env. "
        "The Streamlit frontend reads it from the same .env file automatically."
    )

app = FastAPI(
    title="KMN-CyberSeek API",
    on_startup=[],   # populated below after orchestrator is built
    description="AI-Driven Autonomous Red Team Operator Backend",
    version=APP_VERSION,
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
    """Authenticate every HTTP route and authorize all supplied session references."""
    try:
        principal = access_control.authenticate(request.headers)
        request.state.principal = principal
        path = request.url.path.rstrip("/") or "/"
        references = []
        match = re.match(r"^/api/sessions/([^/]+)", path)
        if match and match.group(1) != "history":
            references.append(match.group(1))
        for key, value in request.query_params.multi_items():
            references.extend(access_control.session_references({key: value}))
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            limit = 16384 if path.endswith(("/verification", "/waivers", "/handoffs", "/preflight")) else MAX_BYTES
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > limit:
                    raise AccessError(413, "JSON exceeds size limit")
                body.extend(chunk)
            request._body = bytes(body)
            if body:
                try:
                    payload = json.loads(body)
                except (ValueError, UnicodeError, RecursionError):
                    raise AccessError(400, "Expected JSON request") from None
                references.extend(access_control.session_references(payload))
        if match and any(sid != match.group(1) for sid in references):
            raise AccessError(403, "Conflicting session references")
        if path in {"/api/execute", "/api/approve"} and not references:
            raise AccessError(400, "Session reference required")
        access_control.authorize(principal, request.method, path, references)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            access_control.store.audit(principal, request.method + " " + path,
                                       references[0] if references else None, "authorized")
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Identity-Mode"] = principal.mode
        return response
    except AccessError as exc:
        return JSONResponse(status_code=exc.status, content={"detail": exc.detail})
    except (OSError, sqlite3.Error):
        return JSONResponse(status_code=503, content={"detail": "Access storage unavailable"})

# Global instances
ai_provider = os.getenv("AI_PROVIDER")
# If AI_PROVIDER is not set, let the connector auto-detect based on API key presence
ai_connector = KMN_AI_Connector(provider=ai_provider)
scanner = Scanner()
orchestrator = Orchestrator(ai_connector, scanner)
access_control = AccessControl(API_AUTH_TOKEN, AccessStore(
    os.getenv("KMN_ACCESS_DB") or str(Path(orchestrator.db_path).with_suffix(".access.sqlite3"))))

# WebSocket connections
active_connections: Dict[WebSocket, object] = {}

async def broadcast_message(message_type: str, data: Dict):
    """Raw events require sensitive-read and an explicit accessible session."""
    message = {"type": message_type, "data": data, "timestamp": datetime.now().isoformat()}
    for connection, principal in list(active_connections.items()):
        try:
            # Reauthenticate to honor operator revocation on an existing socket.
            principal = access_control.authenticate(connection.headers, connection.query_params)
            references = access_control.session_references(data)
            if not principal.admin and (not principal.sensitive or not references):
                continue
            if any(not access_control.can_access(principal, sid) for sid in references):
                continue
            await connection.send_json(message)
        except AccessError:
            active_connections.pop(connection, None)
            await connection.close(code=1008)
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
    # Stuck-session watchdog — revives sessions wedged in an active state.
    asyncio.create_task(orchestrator.watchdog_loop())
    # Resume any sessions that were mid-flight when the backend last shut down.
    # Runs after the event loop is up so asyncio.create_task() works inside.
    await orchestrator.auto_resume_sessions()


# Pydantic Models
class TargetRequest(BaseModel):
    """Target input model."""
    ip: str = Field(..., description="Target IP address, hostname, or CIDR subnet (e.g. 192.168.1.0/24)")
    domain: Optional[str] = Field(None, description="Optional domain name")
    session_name: Optional[str] = Field(None, description="Custom session name")
    auto_approve: bool = Field(True, description="Auto-run routine low/medium risk commands")
    max_auto_depth: int = Field(25, description="Maximum consecutive auto-executed commands before an automatic strategic re-plan in full-auto mode or an approval checkpoint in convenience auto-approve mode")
    objective: Optional[str] = Field(
        None,
        description="Engagement goal in plain language (e.g. 'get root', 'reach Domain Admin', "
                    "'find and confirm SQL injection'). Drives the strategist's plan and "
                    "'objective complete' detection. Defaults to reaching highest privilege.",
    )
    full_auto: bool = Field(
        False,
        description="Fully Autonomous mode for THIS session only: never pause for manual "
                    "command approval, including HIGH-risk commands (the self-critique "
                    "VERIFIER safety check still runs and still blocks a command it cannot "
                    "vet). Intended for isolated lab targets only.",
    )
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

class FullAutoRequest(BaseModel):
    """Toggle per-session Fully Autonomous mode on an existing session."""
    enabled: bool = Field(..., description="True: never pause this session for manual approval (HIGH-risk still passes through the self-critique VERIFIER). False: restore normal approval gating.")

class SteerRequest(BaseModel):
    """Free-text operator steering instruction, injected into the AI's next decision."""
    instruction: str = Field(..., description="Natural-language directive for the AI")

class AskRequest(BaseModel):
    """Operator question about the current session (read-only status chat)."""
    question: str = Field(..., description="Natural-language question about the engagement")

class FeatureFlagsRequest(BaseModel):
    """Toggle user-facing feature flags from the Settings UI (no .env editing)."""
    coverage_engine: Optional[bool] = None
    bruteforce_enabled: Optional[bool] = None
    full_auto_mode: Optional[bool] = None

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
    provider: str  # Local (Ollama), DeepSeek, OpenAI, Anthropic, OpenRouter
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
        "version": APP_VERSION,
        "status": "operational",
        "endpoints": ["/api/docs", "/api/start", "/api/sessions", "/api/ws"],
        "description": "AI-Driven Autonomous Red Team Operator"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.get("/api/identity")
async def get_identity(request: Request):
    """Describe the authenticated identity, including explicit legacy-admin mode."""
    return request.state.principal.identity()


@app.post("/api/preflight")
async def evaluate_configuration_preflight(request: Request):
    """Configuration-only readiness; never start a scan or probe a provider."""
    from core.preflight import evaluate_preflight
    payload = await _bounded_json_body(request, limit=16384)
    if (set(payload) - {"target", "authorization_confirmed", "scope_allowlist"}
            or not isinstance(payload.get("target"), str)
            or type(payload.get("authorization_confirmed")) is not bool
            or ("scope_allowlist" in payload and not isinstance(payload["scope_allowlist"], str))):
        raise HTTPException(400, "Invalid preflight configuration")
    return await asyncio.to_thread(evaluate_preflight, payload["target"], payload["authorization_confirmed"],
                                   payload.get("scope_allowlist"), ai_connector, scanner)


def _require_session_report(session_id):
    try:
        return orchestrator.get_session_report(session_id)
    except ValueError:
        raise HTTPException(404, "Session not found") from None


@app.get("/api/sessions/{session_id}/completeness")
async def get_session_completeness(session_id: str, request: Request):
    report = _require_session_report(session_id)
    result = await asyncio.to_thread(orchestrator.get_session_completeness, session_id)
    if request.state.principal.sensitive:
        return result
    return {**build_report_snapshot({**report, "completeness": result})["completeness"],
            **{key + "_count": len(result[key]) for key in ("missing_checks", "blockers", "waived_checks")}}


@app.get("/api/sessions/{session_id}/preflight")
async def get_session_preflight(session_id: str, request: Request):
    _require_session_report(session_id)
    result = await asyncio.to_thread(orchestrator.get_session_preflight, session_id)
    if request.state.principal.sensitive:
        return result
    return {"version": 1, "ready": result["ready"],
            "checks": [{key: check[key] for key in ("name", "ready", "required", "status")} for check in result["checks"]]}


@app.get("/api/sessions/{session_id}/operations")
async def get_session_operations(session_id: str):
    _require_session_report(session_id)
    operations = await asyncio.to_thread(orchestrator.get_session_operations, session_id)
    return {"session_id": session_id, "operations": operations, "count": len(operations)}


@app.post("/api/sessions/{session_id}/waivers")
async def record_session_waiver(session_id: str, request: Request):
    _require_session_report(session_id)
    payload = await _bounded_json_body(request, limit=16384)
    if set(payload) != {"endpoint_id", "role", "category", "reason"}:
        raise HTTPException(400, "Expected an explicit completeness waiver; reviewer is server attributed")
    payload["reviewer"] = request.state.principal.id
    try:
        result = await asyncio.to_thread(orchestrator.record_completeness_waiver, session_id, payload)
    except ValueError:
        raise HTTPException(400, "Invalid completeness waiver") from None
    return result if request.state.principal.sensitive else {"session_id": session_id, "status": "recorded"}


@app.get("/api/sessions/{session_id}/telemetry/summary")
async def get_session_model_summary(session_id: str):
    _require_session_report(session_id)
    store = orchestrator.ai_connector.telemetry_store
    return {"session_id": session_id, "summary": await asyncio.to_thread(store.summary, session_id)}


@app.get("/api/sessions/{session_id}/telemetry/events")
async def get_session_model_events(session_id: str, limit: int = 100):
    _require_session_report(session_id)
    if not 1 <= limit <= 10000:
        raise HTTPException(400, "Limit must be between 1 and 10000")
    store = orchestrator.ai_connector.telemetry_store
    events = await asyncio.to_thread(store.events, session_id, limit)
    return {"session_id": session_id, "events": events, "count": len(events)}


@app.get("/api/sessions/{session_id}/sources")
async def get_session_sources(session_id: str):
    _require_session_report(session_id)
    sources = await asyncio.to_thread(access_control.store.sources, session_id)
    return {"session_id": session_id, "sources": sources, "count": len(sources)}


@app.post("/api/sessions/{session_id}/sources/import")
async def import_session_source(session_id: str, request: Request):
    """Local JSON metadata only. No repository paths, source reads, or fetching."""
    async def import_source():
        payload = await _bounded_json_body(request)
        # A cancelled to_thread worker must finish before deletion can purge stores.
        worker = asyncio.create_task(asyncio.to_thread(_import_source_snapshot, session_id, payload, epoch))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            if worker.done() and not worker.cancelled():
                worker.exception()
            raise

    _require_session_report(session_id)
    epoch = orchestrator._session_epoch(session_id)
    return await _run_session_work(session_id, import_source(), "source_import", epoch)


def _import_source_snapshot(session_id, payload, epoch):
    from core.source_inventory import check_source_revision, import_source_manifest, import_sarif
    with _assessment_lock:
        if orchestrator._stale_execution(session_id, epoch):
            raise HTTPException(409, "Session work invalidated")
        report = _require_session_report(session_id)
        try:
            if set(payload) == {"kind", "document"} and payload["kind"] == "manifest":
                document = import_source_manifest(payload["document"], allowlist=report["session"]["scope_allowlist"])
            elif set(payload) == {"kind", "document", "source_id", "revision", "digest"} and payload["kind"] == "sarif":
                document = import_sarif(payload["document"], source_id=payload["source_id"],
                                        revision=payload["revision"], digest=payload["digest"])
            else:
                raise AssessmentError("Invalid source metadata")
            previous = next((source for source in access_control.store.sources(session_id)
                             if source["source_id"] == document["source_id"] and source["kind"] == document["kind"]), None)
            disposition = check_source_revision(
                {key: value for key, value in previous.items() if key != "revision_disposition"} if previous else document,
                document)
        except (AssessmentError, ValueError, TypeError, KeyError):
            raise HTTPException(400, "Invalid source metadata") from None
        if disposition["changed"]:
            try:
                # No durable source-to-cell mapping exists for SARIF. Conservatively
                # invalidate all verified cells when operation IDs cannot bound it.
                _assessment_snapshot(session_id, invalidate_endpoint_ids=disposition["invalidated_endpoint_ids"] or None,
                                     superseded_source=previous)
            except HTTPException as exc:
                if exc.status_code != 404 or exc.detail != "Assessment inventory not found":
                    raise
                _revoke_source_evidence(session_id, previous)
        if orchestrator._stale_execution(session_id, epoch):
            raise HTTPException(409, "Session work invalidated")
        document["revision_disposition"] = disposition
        access_control.store.put_source(session_id, document)
        return {"session_id": session_id, "source": document}


async def _run_session_work(session_id, coroutine, label, epoch):
    try:
        task = orchestrator._track_task(session_id, coroutine, label)
        return await task
    except asyncio.CancelledError:
        if orchestrator._stale_execution(session_id, epoch):
            raise HTTPException(409, "Session work invalidated") from None
        raise


_specialist_slots = asyncio.Semaphore(1)


@app.get("/api/sessions/{session_id}/handoffs")
async def get_session_handoffs(session_id: str):
    from core.specialists import SpecialistService
    report = _require_session_report(session_id)
    service = SpecialistService(ai_connector, access_control.store.path, session_id, credentials=report.get("credentials"))
    try:
        records = service.records()
        return {"session_id": session_id, "handoffs": records, "count": len(records)}
    finally:
        service.close()


@app.post("/api/sessions/{session_id}/handoffs")
async def run_session_handoff(session_id: str, request: Request):
    _require_session_report(session_id)
    epoch = orchestrator._session_epoch(session_id)
    return await _run_session_work(session_id, _session_handoff(session_id, request, epoch), "specialist_handoff", epoch)


async def _session_handoff(session_id, request, epoch):
    from core.specialists import ContextReference, SpecialistRequest, SpecialistService
    from core.model_telemetry import model_call_context
    report = _require_session_report(session_id)
    payload = await _bounded_json_body(request, limit=16384)
    if (set(payload) - {"role", "question", "references"}
            or not {"role", "question"} <= payload.keys()
            or not isinstance(payload.get("references", []), list)):
        raise HTTPException(400, "Invalid specialist request")
    allowed = {"source:" + source["source_id"] for source in access_control.store.sources(session_id)}
    allowed.update("finding:" + str(finding["finding_id"]) for finding in report.get("vulnerabilities", []) if "finding_id" in finding)
    allowed.update("evidence:" + str(evidence["evidence_id"]) for evidence in report.get("evidence", []) if "evidence_id" in evidence)
    references = []
    for reference in payload.get("references", []):
        if (not isinstance(reference, dict) or set(reference) != {"ref", "summary"}
                or not isinstance(reference["ref"], str) or reference["ref"] not in allowed):
            raise HTTPException(400, "Specialist references must belong to this session")
        references.append(ContextReference(reference["ref"], reference["summary"]))
    async with _specialist_slots:
        if orchestrator._stale_execution(session_id, epoch):
            raise HTTPException(409, "Session work invalidated")
        report = _require_session_report(session_id)
        service = SpecialistService(ai_connector, access_control.store.path, session_id, credentials=report.get("credentials"))
        try:
            with model_call_context(session_id, "specialist"):
                result = await service.run(SpecialistRequest(payload["role"], payload["question"], tuple(references)))
            if orchestrator._stale_execution(session_id, epoch):
                raise HTTPException(409, "Session work invalidated")
            return {"session_id": session_id, "result": result.to_dict()}
        except ValueError:
            raise HTTPException(400, "Invalid or exhausted specialist request") from None
        finally:
            service.close()

@app.post("/api/start")
async def start_session(target_request: TargetRequest, request: Request):
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
            authorization_confirmed=target_request.authorization_confirmed,
            objective=target_request.objective,
            full_auto=target_request.full_auto,
        )

        # Persist ownership before any background work can start.
        access_control.store.own(session_id, request.state.principal)
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
async def list_sessions(request: Request):
    """List all active sessions."""
    sessions = orchestrator.get_sessions()
    principal = request.state.principal
    if not principal.admin:
        sessions = [build_report_snapshot(orchestrator.get_session_report(row["session_id"]))["session"]
                    for row in sessions if access_control.can_access(principal, row["session_id"])]
    return {"sessions": sessions, "count": len(sessions)}


@app.get("/api/sessions/history")
async def list_session_history(request: Request):
    """List ALL sessions from the database including completed and failed ones.
    Unlike GET /api/sessions (active-only, in-memory), this queries the DB
    directly so historical sessions survive backend restarts. Returns lightweight
    summary rows - no scan blobs or command output.

    IMPORTANT: this route MUST be registered before /api/sessions/{session_id}
    so FastAPI does not treat 'history' as a session_id."""
    history = orchestrator.get_session_history()
    principal = request.state.principal
    if not principal.admin:
        history = [build_report_snapshot(orchestrator.get_session_report(row["session_id"]))["session"]
                   for row in history if access_control.can_access(principal, row["session_id"])]
    return {"sessions": history, "count": len(history)}


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str, request: Request):
    """Get details of a specific session."""
    try:
        session_report = orchestrator.get_session_report(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    return session_report if request.state.principal.sensitive else build_report_snapshot(session_report)


@app.post("/api/sessions/{session_id}/full_auto")
async def set_session_full_auto(session_id: str, request: FullAutoRequest):
    """Turn per-session Fully Autonomous mode on/off for an existing session.

    ON: this session never pauses for manual command approval, including
    HIGH-risk commands -- the self-critique VERIFIER still runs and still
    blocks (routes to manual approval) a command it cannot vet, since that is
    a safety invariant, not a convenience setting. Intended for isolated lab
    targets only.
    """
    if not orchestrator.set_session_full_auto(session_id, request.enabled):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"session_id": session_id, "full_auto": request.enabled}


@app.get("/api/sessions/{session_id}/events")
async def get_session_events(session_id: str):
    """Return the append-only lifecycle timeline for a session."""
    try:
        orchestrator.get_session_report(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    events = orchestrator.get_session_events(session_id)
    return {"session_id": session_id, "events": events, "count": len(events)}


@app.get("/api/sessions/{session_id}/jobs")
async def get_session_jobs(session_id: str):
    """Return durable background jobs and their recovery state."""
    try:
        orchestrator.get_session_report(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    jobs = orchestrator.get_session_jobs(session_id)
    return {"session_id": session_id, "jobs": jobs, "count": len(jobs)}

@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete a specific session and all its associated data."""
    try:
        preparation = await orchestrator.prepare_session_deletion(session_id)
    except Exception:
        logger.exception("Session cleanup failed before deletion")
        raise HTTPException(status_code=503, detail="Session cleanup failed; session data was not deleted") from None
    if not isinstance(preparation, dict) or preparation.get("status") != "success":
        raise HTTPException(status_code=409, detail="Session cleanup pending or incomplete; session data was not deleted")
    try:
        result = await asyncio.to_thread(_delete_sessions, session_id)
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
        preparation = await orchestrator.prepare_session_deletion(None)
    except Exception:
        logger.exception("Session cleanup failed before bulk deletion")
        raise HTTPException(status_code=503, detail="Session cleanup failed; session data was not deleted") from None
    if not isinstance(preparation, dict) or preparation.get("status") != "success":
        raise HTTPException(status_code=409, detail="Session cleanup pending or incomplete; session data was not deleted")
    try:
        result = await asyncio.to_thread(_delete_sessions)
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


@app.get("/api/sessions/{session_id}/report.json")
async def download_session_report_json(session_id: str):
    """Versioned, sanitized snapshot; raw commands and credentials are omitted."""
    try:
        report = orchestrator.get_session_report(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    snapshot = await asyncio.to_thread(build_report_snapshot, report)
    return JSONResponse(content=snapshot, headers={"Cache-Control": "no-store"})


_assessment_lock = threading.RLock()
_assessment_cache = {}


def _session_evidence_bindings(session_id):
    connection = sqlite3.connect(orchestrator.db_path)
    try:
        rows = connection.execute("SELECT id,evidence_type,evidence_data FROM evidence WHERE session_id=?", (session_id,)).fetchall()
    finally:
        connection.close()
    bindings = []
    for identity, kind, encoded in rows:
        try:
            data = json.loads(encoded)
        except (ValueError, TypeError):
            raise RuntimeError("Durable evidence metadata unavailable") from None
        references, provenance = {"evidence:" + str(identity)}, []
        if isinstance(data, dict):
            references.update("evidence:" + data[key] for key in ("id", "evidence_id") if isinstance(data.get(key), str) and data[key])
            linked = data.get("artifact_refs", [])
            if not isinstance(linked, list) or any(not isinstance(ref, str) for ref in linked):
                raise RuntimeError("Invalid durable evidence aliases")
            references.update("evidence:" + ref for ref in linked)
            for declared in (data, data.get("provenance")):
                if isinstance(declared, dict) and ("source_id" in declared or (kind == "source_review" and any(key in declared for key in ("revision", "digest")))):
                    provenance.append({key: declared[key] for key in ("source_id", "revision", "digest") if key in declared})
        bindings.append((references, provenance))
    return bindings


def _expand_evidence_refs(references, bindings):
    references = set(references)
    while True:
        expanded = references | {ref for aliases, _ in bindings if aliases & references for ref in aliases}
        if expanded == references:
            return references
        references = expanded


def _revoke_source_evidence(session_id, source, references=()):
    bindings = _session_evidence_bindings(session_id)
    references = set(references)
    for aliases, provenance in bindings:
        if any(declared.get("source_id") == source["source_id"]
               and all(key not in declared or declared[key] == source[key] for key in ("revision", "digest"))
               for declared in provenance):
            references.update(aliases)
    access_control.store.revoke_evidence_refs(session_id, source, _expand_evidence_refs(references, bindings))


def _filter_session_evidence_refs(session_id, references):
    revoked, sources = access_control.store.evidence_reference_state(session_id)
    bindings = _session_evidence_bindings(session_id)
    for aliases, provenance in bindings:
        if any(not any(declared.get("source_id") == source["source_id"]
                       and all(key not in declared or declared[key] == source[key] for key in ("revision", "digest"))
                       for source in sources) for declared in provenance):
            revoked.update(aliases)
    revoked = _expand_evidence_refs(revoked, bindings)
    return [reference for reference in references if reference not in revoked]


with access_control.store.connect():
    pass
orchestrator.register_evidence_reference_filter(_filter_session_evidence_refs)


def _purge_session_access(session_id):
    """Runtime invokes this only after all session-owned work has stopped."""
    from core.specialists import SpecialistService
    service = SpecialistService(ai_connector, access_control.store.path, session_id)
    try:
        service.purge_session()
    finally:
        service.close()
    access_control.store.forget(session_id)
    name = hashlib.sha256(session_id.encode()).hexdigest() + ".json"
    for path in list(_assessment_cache):
        if path.name == name:
            _assessment_cache.pop(path)


orchestrator.register_session_purge_hook(_purge_session_access)


def _delete_sessions(session_id=None):
    """Serialize deletion and snapshot admission without blocking the event loop."""
    with _assessment_lock:
        result = (orchestrator.delete_all_sessions() if session_id is None
                  else orchestrator.delete_session(session_id))
        if result["status"] == "success" and session_id is None:
            access_control.store.forget()
            _assessment_cache.clear()
        return result


async def _bounded_json_body(request: Request, limit=MAX_BYTES):
    """Bound JSON before decoding; no file paths, URLs or reference fetching."""
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > limit:
            raise HTTPException(status_code=413, detail="JSON exceeds size limit")
        data.extend(chunk)
    try:
        payload = json.loads(data)
        if not isinstance(payload, dict):
            raise ValueError
        return payload
    except (ValueError, UnicodeError, RecursionError):
        raise HTTPException(status_code=400, detail="Expected bounded JSON object") from None


def _assessment_snapshot(session_id, payload=None, *, update=False, invalidate_endpoint_ids=(), superseded_source=None):
    with _assessment_lock:
        # Check admission under the deletion lock so a queued import cannot
        # recreate a snapshot after its active or historical session was deleted.
        try:
            report = orchestrator.get_session_report(session_id)
        except ValueError:
            raise HTTPException(status_code=404, detail="Session not found") from None
        root = Path(os.getenv("KMN_ASSESSMENT_DIR") or Path(orchestrator.db_path).parent / "assessments").absolute()
        path = root / (hashlib.sha256(session_id.encode()).hexdigest() + ".json")
        try:
            if any(parent.is_symlink() for parent in (root, *root.parents)):
                raise OSError("Unsafe snapshot location")
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if root.stat().st_uid != os.getuid():
                raise OSError("Unsafe snapshot location")
            if os.path.lexists(path):
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                    raise OSError("Unsafe snapshot file")
            if payload is not None and not update:
                if (set(payload) - {"document", "base_url", "roles", "categories"}
                        or not isinstance(payload.get("document"), dict)
                        or not isinstance(payload.get("base_url"), str)
                        or not isinstance(payload.get("categories", ["observation"]), list)):
                    raise AssessmentError("Invalid inventory import fields")
                if path.exists():
                    raise HTTPException(status_code=409, detail="Assessment inventory already exists")
                assessment = Assessment.from_openapi(
                    payload["document"], base_url=payload["base_url"],
                    allowlist=report["session"]["scope_allowlist"],
                    roles=payload.get("roles"), categories=payload.get("categories", ["observation"]))
            else:
                assessment = _assessment_cache.get(path)
                if assessment is None:
                    assessment = Assessment.load(path, allowlist=report["session"]["scope_allowlist"])
                else:
                    # Revalidate cached inventory too, without resetting live attempts.
                    Assessment.from_json(assessment.to_json(), allowlist=report["session"]["scope_allowlist"])
            invalidating = invalidate_endpoint_ids is None or bool(invalidate_endpoint_ids)
            if invalidating:
                snapshot = json.loads(assessment.to_json())
                affected = [row for row in snapshot["coverage"] if invalidate_endpoint_ids is None or row["endpoint_id"] in invalidate_endpoint_ids]
                _revoke_source_evidence(session_id, superseded_source,
                                        [row["evidence_ref"] for row in affected if row["evidence_ref"] is not None])
                for row in affected:
                    row.update(status="pending", attempts=0, evidence_ref=None)
                assessment = Assessment.from_json(snapshot, allowlist=report["session"]["scope_allowlist"])
            if update:
                if (set(payload) - {"endpoint_id", "role", "category", "status", "evidence_ref"}
                        or not all(isinstance(payload.get(k), str)
                                   for k in ("endpoint_id", "role", "category", "status"))):
                    raise AssessmentError("Invalid coverage update fields")
                key = CoverageKey(payload["endpoint_id"], payload["role"], payload["category"])
                if payload["status"] == "attempted":
                    if payload.get("evidence_ref") is not None:
                        raise AssessmentError("An attempt cannot attach evidence")
                    assessment.begin_attempt(key)
                else:
                    if payload["status"] == "verified":
                        reference = payload.get("evidence_ref")
                        if not isinstance(reference, str) or reference not in orchestrator.get_session_committed_evidence_refs(session_id):
                            raise AssessmentError("Evidence must be committed to this session")
                    assessment.mark(key, payload["status"], evidence_ref=payload.get("evidence_ref"))
            if payload is not None or invalidating:
                try:
                    assessment.save(path)
                except (AssessmentError, OSError):
                    # Never retain an update that failed to reach durable storage.
                    _assessment_cache.pop(path, None)
                    raise
            _assessment_cache[path] = assessment
            return JSONResponse({"session_id": session_id, "snapshot": json.loads(assessment.to_json()),
                                 "summary": assessment.summary()}, headers={"Cache-Control": "no-store"})
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Assessment inventory not found") from None
        except (AssessmentError, KeyError, TypeError):
            raise HTTPException(status_code=400, detail="Invalid assessment inventory or coverage state") from None
        except (OSError, sqlite3.Error, RuntimeError):
            raise HTTPException(status_code=503, detail="Assessment storage unavailable") from None


@app.post("/api/sessions/{session_id}/assessment/import")
async def import_session_assessment(session_id: str, request: Request):
    """Import local OpenAPI JSON with explicit base_url and credential references only."""
    payload = await _bounded_json_body(request)
    return await asyncio.to_thread(_assessment_snapshot, session_id, payload)


@app.get("/api/sessions/{session_id}/assessment")
async def get_session_assessment(session_id: str):
    """Return inventory, role/category coverage and summary, without executing tests."""
    return await asyncio.to_thread(_assessment_snapshot, session_id)


@app.patch("/api/sessions/{session_id}/assessment/coverage")
async def update_session_coverage(session_id: str, request: Request):
    """Reviewer-only verification requires a durable evidence:<id> from this session."""
    payload = await _bounded_json_body(request)
    if payload.get("status") == "verified" and request.state.principal.role not in {"reviewer", "admin"}:
        raise HTTPException(403, "Verified coverage requires reviewer permission")
    response = await asyncio.to_thread(_assessment_snapshot, session_id, payload, update=True)
    return response if request.state.principal.sensitive else {"session_id": session_id, "status": "recorded"}


def _session_artifacts(session_id):
    try:
        orchestrator.get_session_report(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found") from None
    try:
        store = ArtifactStore(os.getenv("KMN_EVIDENCE_DIR") or Path(orchestrator.db_path).parent / "evidence",
                              key=os.getenv("KMN_EVIDENCE_KEY") or None)
        manifests = store.manifests(orchestrator._artifact_session_id(session_id))
        return store, manifests
    except (ArtifactStoreError, OSError, ValueError):
        raise HTTPException(status_code=503, detail="Artifact storage unavailable") from None


@app.get("/api/sessions/{session_id}/artifacts")
def get_session_artifacts(session_id: str):
    """List manifests only, never raw artifact content or filesystem paths."""
    _, manifests = _session_artifacts(session_id)
    return JSONResponse({"session_id": session_id, "artifacts": manifests, "count": len(manifests)},
                        headers={"Cache-Control": "no-store"})


@app.get("/api/sessions/{session_id}/artifacts/{artifact_id}/content")
def download_artifact_content(session_id: str, artifact_id: str, acknowledge_sensitive: bool = False):
    """Sensitive raw bytes may contain credentials. Explicit acknowledgement is required."""
    if not acknowledge_sensitive:
        raise HTTPException(status_code=400, detail="Raw evidence is sensitive; set acknowledge_sensitive=true")
    store, manifests = _session_artifacts(session_id)
    if not any(manifest.get("id") == artifact_id for manifest in manifests):
        raise HTTPException(status_code=404, detail="Artifact not found")
    try:
        content = store.read(artifact_id)
    except (ArtifactStoreError, OSError, ValueError):
        raise HTTPException(status_code=503, detail="Artifact content unavailable") from None
    return Response(content, media_type="application/octet-stream", headers={
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        "Content-Disposition": 'attachment; filename="sensitive-evidence.bin"',
    })


@app.post("/api/sessions/{session_id}/vulnerabilities/{finding_id}/verification")
async def record_finding_verification(session_id: str, finding_id: str, request: Request):
    """Record explicit operator review, not an automatic source-label verification.

    Required: acknowledge_review=true, result (positive/negative/inconclusive),
    method (1-200 characters), artifact_refs (1-32 distinct committed artifact IDs).
    Optional kind defaults to verification; remediation requires applied, and
    retest accepts positive/negative/inconclusive.
    Optional command_id and attempt_id must be supplied together and resolve to
    a persisted command attempt containing the declared session artifacts.
    Reviewer identity and provenance are always supplied by the server.
    Optional evidence is operator prose, at most 4096 characters. The orchestrator
    resolves the finding target and creates evidence/events from actual artifacts.
    """
    payload = await _bounded_json_body(request, limit=16384)
    refs = payload.get("artifact_refs")
    kind = payload.get("kind", "verification")
    if (set(payload) - {"kind", "acknowledge_review", "result", "method", "artifact_refs", "evidence", "command_id", "attempt_id"}
            or payload.get("acknowledge_review") is not True
            or not isinstance(kind, str) or kind not in {"verification", "remediation", "retest"}
            or not isinstance(payload.get("result"), str)
            or payload["result"] not in ({"applied"} if kind == "remediation" else {"positive", "negative", "inconclusive"})
            or not isinstance(payload.get("method"), str)
            or not 1 <= len(payload["method"].strip()) <= 200
            or len(payload["method"]) > 200
            or any(ord(char) < 32 or ord(char) == 127 for char in payload["method"])
            or not isinstance(refs, list) or not 1 <= len(refs) <= 32
            or any(not isinstance(ref, str) or not re.fullmatch(r"[0-9a-f]{64}\.[0-9a-f]{32}", ref) for ref in refs)
            or len(set(refs)) != len(refs)
            or ("evidence" in payload and (not isinstance(payload["evidence"], str) or len(payload["evidence"]) > 4096))
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", finding_id)):
        raise HTTPException(status_code=400, detail="Invalid operator verification review")
    runtime = "command_id" in payload or "attempt_id" in payload
    if runtime and any(not isinstance(payload.get(key), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", payload[key])
                       for key in ("command_id", "attempt_id")):
        raise HTTPException(400, "Runtime verification requires command_id and attempt_id")
    _, manifests = await asyncio.to_thread(_session_artifacts, session_id)
    if not set(refs).issubset({manifest["id"] for manifest in manifests}):
        raise HTTPException(status_code=400, detail="Review requires this session's committed artifacts")
    if runtime:
        with sqlite3.connect(orchestrator.db_path) as connection:
            rows = connection.execute("SELECT record_json FROM commands WHERE session_id=? AND command_id=? AND attempt_id=?",
                                      (session_id, payload["command_id"], payload["attempt_id"])).fetchall()
        linked = {artifact["id"] for row in rows for artifact in json.loads(row[0]).get("artifacts", [])}
        if not rows or not set(refs) <= linked:
            raise HTTPException(400, "Artifacts must belong to the durable command attempt")
    payload["reviewer"] = request.state.principal.id
    payload["provenance"] = {"type": "runtime", "source": "command_result"} if runtime else {"type": "review_only", "source": "operator_review"}
    try:
        result = await asyncio.to_thread(orchestrator.record_verification, session_id, finding_id, payload)
    except KeyError:
        raise HTTPException(status_code=404, detail="Finding not found") from None
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid operator verification review") from None
    except (ArtifactStoreError, OSError):
        raise HTTPException(status_code=503, detail="Verification storage unavailable") from None
    if not request.state.principal.sensitive:
        result = {"session_id": session_id, "finding_id": finding_id, "status": "recorded"}
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.get("/api/sessions/{session_id}/report.sarif")
async def download_session_report_sarif(session_id: str):
    """SARIF 2.1.0 using the same sanitized snapshot and verification rules."""
    try:
        report = orchestrator.get_session_report(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    content = await asyncio.to_thread(lambda: export_sarif(build_report_snapshot(report)))
    return JSONResponse(content=content, media_type="application/sarif+json",
                        headers={"Cache-Control": "no-store"})


def _temporary_download(generate, data, suffix, media_type, filename=None):
    """Run in a worker; each request owns its file until response cleanup."""
    fd, path = tempfile.mkstemp(prefix="kmn_report_", suffix=suffix)
    os.close(fd)
    try:
        generate(data, output_path=path)
        return FileResponse(path=path, media_type=media_type,
                            filename=filename or "kmn_report" + suffix,
                            headers={"Cache-Control": "no-store"},
                            background=BackgroundTask(os.unlink, path))
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


async def _download_response(generate, data, suffix, media_type, filename=None):
    """Retain ownership of generated files even when the route is cancelled."""
    worker = asyncio.create_task(asyncio.to_thread(
        _temporary_download, generate, data, suffix, media_type, filename))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        # Threads cannot be cancelled. Repeated route cancellation must not orphan
        # either the worker or its completed response's unserved temporary file.
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not worker.cancelled() and worker.exception() is None:
            Path(worker.result().path).unlink(missing_ok=True)
        raise


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
        return await _download_response(
            generate_report, report_data, ".docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            f"kmn_report_{session_id[:12]}.docx",
        )
    except Exception as e:
        logger.error(f"Report generation failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")


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
        return await _download_response(
            generate_pdf_report, report_data, ".pdf", "application/pdf",
            f"kmn_report_{session_id[:12]}.pdf",
        )
    except Exception as e:
        logger.error(f"PDF report generation failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=f"PDF report generation failed: {e}")


@app.get("/api/settings/features")
async def get_feature_flags():
    """Current feature-flag values for the Settings UI."""
    import core.orchestrator as _orch
    return {"flags": _orch.get_feature_flags()}


@app.post("/api/settings/features")
async def set_feature_flags(req: FeatureFlagsRequest):
    """Toggle feature flags live AND persist to .env so they survive a restart."""
    import core.orchestrator as _orch
    env_path = os.path.join(os.getcwd(), ".env")
    if not os.path.exists(env_path):
        open(env_path, "w").close()
    changed = {}
    for ui_name in ("coverage_engine", "bruteforce_enabled", "full_auto_mode"):
        val = getattr(req, ui_name)
        if val is None:
            continue
        gname = _orch.set_feature_flag(ui_name, val)
        if gname:
            try:
                set_key(env_path, gname, "true" if val else "false")
            except Exception as e:
                logger.warning(f"Failed to persist {gname} to .env: {e}")
            changed[ui_name] = bool(val)
    logger.info(f"Feature flags updated: {changed}")
    return {"status": "success", "changed": changed, "flags": _orch.get_feature_flags()}


@app.get("/api/sessions/{session_id}/bruteforce")
async def get_bruteforce_status(session_id: str):
    """Decoupled brute-force worker status for a session (per-service jobs)."""
    if not orchestrator.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"jobs": orchestrator.get_bruteforce_status(session_id)}


@app.get("/api/sessions/{session_id}/report/md")
async def download_session_report_md(session_id: str):
    """Generate and download a Markdown penetration-test report. Pure Python —
    no external dependencies, so this always works even when python-docx / fpdf2
    are not installed. Includes all findings, every executed command, and every
    attack decision in chronological order."""
    try:
        report_data = orchestrator.get_session_report(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")

    try:
        from core.report_generator import generate_markdown_report
        return await _download_response(
            generate_markdown_report, report_data, ".md", "text/markdown",
            f"kmn_report_{session_id[:12]}.md",
        )
    except Exception as e:
        logger.error(f"Markdown report generation failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Markdown report generation failed: {e}")


@app.get("/api/sessions/{session_id}/archive")
async def download_session_archive(session_id: str):
    """Sensitive report/events/jobs/metadata may contain secrets; raw files omitted."""
    try:
        return await _download_response(
            _metadata_archive, session_id, ".zip", "application/zip",
            f"kmn_archive_{session_id[:12]}.zip",
        )
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    except Exception as exc:
        logger.error(f"Session archive failed for {session_id}: {exc}")
        raise HTTPException(status_code=500, detail=f"Session archive failed: {exc}")


def _metadata_archive(session_id, output_path):
    """Exclude raw files, not secrets in legacy report/events/jobs/manifest metadata."""
    report = orchestrator.get_session_report(session_id)
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in (("session", report), ("events", orchestrator.get_session_events(session_id)),
                           ("jobs", orchestrator.get_session_jobs(session_id)),
                           ("manifest", {"format": 1, "session_id": session_id,
                                         "artifacts": report.get("artifacts", []), "raw_artifacts": "omitted"})):
            archive.writestr(name + ".json", json.dumps(data, indent=2, ensure_ascii=True, default=str))


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


@app.get("/api/stats")
async def get_aggregate_stats(request: Request):
    """Aggregate statistics for the dashboard charts.
    Queries the DB directly so it captures all sessions, not just in-memory active ones.
    Returns vuln distribution, sessions-per-day (last 14 days), status breakdown,
    and top targeted hosts."""
    from datetime import datetime as _dt, timedelta as _td
    if not request.state.principal.admin:
        sessions = [row for row in orchestrator.get_session_history()
                    if access_control.can_access(request.state.principal, row["session_id"])]
        statuses, risks, days, targets = {}, {}, {}, {}
        cutoff = (_dt.now() - _td(days=14)).date().isoformat()
        for row in sessions:
            snapshot = build_report_snapshot(orchestrator.get_session_report(row["session_id"]))
            status = snapshot["session"].get("status", "unknown")
            statuses[status] = statuses.get(status, 0) + 1
            created = snapshot["session"].get("created_at")
            if isinstance(created, str) and re.match(r"^\d{4}-\d{2}-\d{2}", created) and created[:10] >= cutoff:
                days[created[:10]] = days.get(created[:10], 0) + 1
            target = snapshot["session"].get("target_ip")
            if target:
                targets[target] = targets.get(target, 0) + 1
            for finding in snapshot["findings"]:
                risk = finding["severity"]
                risks[risk] = risks.get(risk, 0) + 1
        return {"vuln_distribution": risks, "status_distribution": statuses,
                "sessions_total": len(sessions),
                "sessions_per_day": [{"day": day, "count": count} for day, count in sorted(days.items())],
                "top_targets": [{"target_ip": target, "count": count}
                                for target, count in sorted(targets.items(), key=lambda item: (-item[1], item[0]))[:5]]}
    import sqlite3 as _sqlite3

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


@app.post("/api/sessions/{session_id}/cancel")
async def cancel_session(session_id: str):
    """Cancel an active session and stop its owned handlers."""
    result = await orchestrator.cancel_session(session_id)
    if result["status"] == "error":
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@app.get("/api/sessions/{session_id}/vulnerabilities")
async def get_vulnerabilities(session_id: str, request: Request):
    """Get all recorded vulnerability findings for a session (structured, from
    the vulnerabilities table - see core/orchestrator.py add_vulnerability())."""
    if not orchestrator.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")

    vulnerabilities = orchestrator.get_vulnerabilities(session_id)
    if not request.state.principal.sensitive:
        vulnerabilities = build_report_snapshot(orchestrator.get_session_report(session_id))["findings"]
    return {
        "session_id": session_id,
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities)
    }


# ── Shell session endpoints ────────────────────────────────────────────────────

class StartHandlerRequest(BaseModel):
    lhost: str
    lport: int = 4444
    payload: str = "windows/x64/meterpreter/reverse_tcp"

    @field_validator("lhost", "lport", "payload")
    @classmethod
    def _validate_handler_values(cls, value, info):
        values = info.data
        lhost = value if info.field_name == "lhost" else values.get("lhost", "")
        lport = value if info.field_name == "lport" else values.get("lport", 4444)
        payload = value if info.field_name == "payload" else values.get(
            "payload", "windows/x64/meterpreter/reverse_tcp"
        )
        error = validate_handler_config(lhost, lport, payload)
        if error:
            raise ValueError(error)
        return value


class ShellExecRequest(BaseModel):
    command: str


class PivotRouteRequest(BaseModel):
    handler_id: str
    msf_id: int
    subnet: str


class PortForwardRequest(BaseModel):
    handler_id: str
    msf_id: int
    remote_host: str
    remote_port: int
    local_port: int
    local_host: str = "127.0.0.1"


class SocksProxyRequest(BaseModel):
    handler_id: str
    msf_id: int
    local_port: int
    local_host: str = "127.0.0.1"


@app.post("/api/sessions/{session_id}/shells/handler")
async def start_handler(session_id: str, req: StartHandlerRequest):
    """Start a Metasploit multi/handler listener for this session."""
    if not orchestrator.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        info = await orchestrator.start_shell_handler(
            session_id, req.lhost, req.lport, req.payload
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "started", "handler": info}


@app.delete("/api/sessions/{session_id}/shells/handler/{handler_id}")
async def stop_handler(session_id: str, handler_id: str):
    """Stop a running multi/handler."""
    ok = await orchestrator.stop_shell_handler(session_id, handler_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Handler not found")
    return {"status": "stopped", "handler_id": handler_id}


@app.get("/api/sessions/{session_id}/shells/handlers")
async def list_handlers(session_id: str):
    """List all handlers (live + persisted config) for a session."""
    live    = orchestrator.get_shell_handlers(session_id)
    saved   = orchestrator.get_persisted_handlers(session_id)
    # Merge: live state takes precedence over saved state
    live_ids = {h["handler_id"] for h in live}
    merged  = live + [s for s in saved if s["handler_id"] not in live_ids]
    return {"handlers": merged, "count": len(merged)}


@app.get("/api/sessions/{session_id}/shells")
async def list_shell_sessions(session_id: str):
    """List active meterpreter/shell sessions for a pentest session."""
    sessions = orchestrator.get_shell_sessions(session_id)
    return {"sessions": sessions, "count": len(sessions)}


@app.post("/api/sessions/{session_id}/shells/{handler_id}/{msf_id}/exec")
async def exec_in_shell(session_id: str, handler_id: str, msf_id: int,
                        req: ShellExecRequest):
    """Run a command inside an active meterpreter or shell session."""
    output = await orchestrator.run_shell_command(
        session_id, handler_id, msf_id, req.command
    )
    return {
        "session_id": session_id,
        "handler_id": handler_id,
        "msf_id":     msf_id,
        "command":    req.command,
        "output":     output,
    }


@app.post("/api/sessions/{session_id}/pivot/route")
async def add_pivot_route(session_id: str, req: PivotRouteRequest):
    result = await orchestrator.add_pivot_route(
        session_id, req.handler_id, req.msf_id, req.subnet
    )
    if result.get("status") != "success":
        raise HTTPException(status_code=400, detail=result.get("message", "Pivot route failed"))
    return result


@app.post("/api/sessions/{session_id}/pivot/portfwd")
async def add_port_forward(session_id: str, req: PortForwardRequest):
    result = await orchestrator.add_port_forward(
        session_id, req.handler_id, req.msf_id, req.remote_host,
        req.remote_port, req.local_port, req.local_host,
    )
    if result.get("status") != "success":
        raise HTTPException(status_code=400, detail=result.get("message", "Port forward failed"))
    return result


@app.delete("/api/sessions/{session_id}/pivot/portfwd/{local_port}")
async def remove_port_forward(session_id: str, local_port: int,
                              handler_id: str, msf_id: int):
    result = await orchestrator.remove_port_forward(
        session_id, handler_id, msf_id, local_port
    )
    if result.get("status") != "success":
        raise HTTPException(status_code=400, detail=result.get("message", "Port forward removal failed"))
    return result


@app.post("/api/sessions/{session_id}/pivot/socks")
async def start_socks_proxy(session_id: str, req: SocksProxyRequest):
    result = await orchestrator.start_socks_proxy(
        session_id, req.handler_id, req.msf_id, req.local_port, req.local_host
    )
    if result.get("status") != "success":
        raise HTTPException(status_code=400, detail=result.get("message", "SOCKS proxy failed"))
    return result


@app.get("/api/sessions/{session_id}/pivot")
async def get_pivot_state(session_id: str):
    if not orchestrator.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"session_id": session_id, **orchestrator.get_pivot_state(session_id)}


@app.get("/api/sessions/{session_id}/shells/{handler_id}/{msf_id}/history")
async def shell_command_history(session_id: str, handler_id: str, msf_id: int):
    """Return the command history for an active shell session."""
    history = orchestrator.get_shell_command_history(session_id, handler_id, msf_id)
    return {"history": history, "count": len(history)}


@app.get("/api/shells/local-ip")
async def get_local_ip():
    """Return the primary non-loopback IP of this machine (suggested LHOST)."""
    from core.shell_manager import get_local_ip as _local_ip
    return {"local_ip": _local_ip()}


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


@app.get("/api/vulnerabilities")
async def list_all_vulnerabilities(
    request: Request,
    source_tool: Optional[str] = None,
    service: Optional[str] = None,
    risk_level: Optional[str] = None,
):
    """Return structured vulnerability findings across ALL sessions from the DB.

    Optional query params (all substring / exact match):
      source_tool  – e.g. 'nvd', 'searchsploit', 'nmap-vuln-script', 'vulners'
      service      – e.g. 'http', 'ssh'  (substring, case-insensitive)
      risk_level   – 'high' | 'medium' | 'low' | 'unknown'
    """
    if not request.state.principal.admin:
        findings = []
        for row in orchestrator.get_session_history():
            sid = row["session_id"]
            if not access_control.can_access(request.state.principal, sid):
                continue
            for finding in build_report_snapshot(orchestrator.get_session_report(sid))["findings"]:
                if source_tool and finding.get("source_tool") != source_tool:
                    continue
                if service and service.lower() not in str(finding.get("service", "")).lower():
                    continue
                if risk_level and finding["severity"] != risk_level:
                    continue
                findings.append({**finding, "session_id": sid})
        return {"vulnerabilities": findings, "count": len(findings)}
    import sqlite3 as _sqlite3
    import json as _json

    rows: list = []
    try:
        conn = _sqlite3.connect(orchestrator.db_path)
        conn.row_factory = _sqlite3.Row
        # NOTE: the sessions table has target_ip + target_domain (no
        # target_hostname / name columns). session_id doubles as the display name.
        query = """
            SELECT v.*, s.target_ip, s.target_domain,
                   s.session_id AS session_name
            FROM vulnerabilities v
            LEFT JOIN sessions s ON s.session_id = v.session_id
            WHERE 1=1
        """
        params: list = []
        if source_tool:
            query += " AND v.source_tool = ?"
            params.append(source_tool)
        if service:
            query += " AND v.service LIKE ?"
            params.append(f"%{service}%")
        if risk_level:
            query += " AND v.risk_level = ?"
            params.append(risk_level)
        query += " ORDER BY v.discovered_at DESC"
        cur = conn.execute(query, params)
        for row in cur.fetchall():
            d = dict(row)
            for json_field in ("cve_ids", "reference_urls"):
                raw = d.get(json_field)
                if isinstance(raw, str):
                    try:
                        d[json_field] = _json.loads(raw)
                    except Exception:
                        d[json_field] = []
            rows.append(d)
        conn.close()
    except Exception as exc:
        logger.error(f"Failed to query global vulnerabilities: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))

    return {"vulnerabilities": rows, "count": len(rows)}


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
    """Manually resume AI analysis for a session.

    Idempotent: if the session is already active (scanning/analyzing/executing/ready),
    returns 200 without spawning a duplicate analysis task.  Clicking Resume on an
    already-running session is a no-op rather than a source of duplicate commands.
    """
    if session_id not in orchestrator.sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = orchestrator.sessions[session_id]

    # A recovery/pause context on the last decision means the loop halted and is
    # waiting for the operator — even though status may still read "ready". In that
    # case Resume must actually restart analysis (not no-op).
    _PAUSED_CTX = {
        "loop_error", "no_next_step", "watchdog_stalled",
        "pivot_limit_reached", "loop_prevention",
    }
    _last_ctx = session.ai_decisions[-1].get("context") if session.ai_decisions else ""
    _is_paused = _last_ctx in _PAUSED_CTX

    already_active = (
        session.status in ("scanning", "analyzing", "executing", "ready")
        and not _is_paused
    )
    if already_active:
        logger.info(f"Resume called on already-active session {session_id} (status={session.status}) — no-op")
        return {"status": "already_running", "message": f"Session is already active (status: {session.status})"}

    logger.info(f"Manual resume triggered for {session_id} (paused_ctx={_last_ctx or 'none'})")
    if _is_paused or session.status == "needs_operator":
        # A resumed session must receive a fresh no-progress budget. Otherwise
        # the next completed command sees the old MAX_COMMANDS_NO_PROGRESS value
        # and immediately enters needs_operator again.
        session._commands_since_progress = 0
        session._last_effort_marker = None
        session._stagnation_counter = 0
        session._auto_pivot_count = 0
        session.pause_reason = ""
    session.status = "analyzing"
    asyncio.create_task(orchestrator._analyze_with_ai(session_id))
    return {"status": "success", "message": "AI analysis resumed"}


@app.post("/api/sessions/{session_id}/steer")
async def steer_session(session_id: str, request: SteerRequest):
    """Send a live natural-language steering instruction to the running AI.
    Takes effect on the next AI decision — does not interrupt the current command."""
    if session_id not in orchestrator.sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    result = orchestrator.add_operator_instruction(session_id, request.instruction)
    if result.get("status") != "success":
        raise HTTPException(status_code=400, detail=result.get("message", "Failed"))
    return result


@app.post("/api/sessions/{session_id}/ask")
async def ask_session(session_id: str, request: AskRequest):
    """Ask the AI about the current engagement (read-only status chat). Does not
    execute anything or alter the loop."""
    if session_id not in orchestrator.sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    result = await orchestrator.answer_operator_question(session_id, request.question)
    if result.get("status") != "success":
        raise HTTPException(status_code=400, detail=result.get("message", "Failed"))
    return result


@app.post("/api/sessions/{session_id}/restart")
async def restart_session(session_id: str):
    """Smart restart — keeps existing nmap scan data (hosts/services/ports) but
    clears all AI decisions, commands, and vulnerabilities, then re-runs AI
    analysis from the existing scan data.

    Use this when the AI loop failed or went off-track but the scan data is
    still valid (e.g. session failed within hours of the last scan). Avoids an
    expensive nmap re-scan when the port state hasn't had time to change.

    For a full re-scan (e.g. days have passed and port state may have changed),
    use POST /api/sessions/{session_id}/rescan instead.
    """
    if session_id not in orchestrator.sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = orchestrator.sessions[session_id]
    reset = await orchestrator.reset_session_state(session_id, full_scan=False)
    if reset.get("status") != "success":
        raise HTTPException(status_code=500, detail=reset.get("message", "Reset failed"))
    logger.info(f"Smart restart for session {session_id} — keeping scan data, resetting AI + vuln state")
    # Re-run both AI analysis and vulnerability analysis from scratch.
    orchestrator._track_task(session_id, orchestrator._analyze_with_ai(session_id), "restart_ai")
    orchestrator._track_task(
        session_id, orchestrator._run_vulnerability_analysis(session_id), "restart_vulnerability"
    )
    return {"status": "success", "message": "AI state reset — re-analyzing existing scan data"}


@app.post("/api/sessions/{session_id}/rescan")
async def rescan_session(session_id: str):
    """Full rescan — clears ALL data (scan results, commands, AI decisions,
    vulnerabilities, credentials) and re-runs the complete nmap + AI pipeline.

    Use this when port state may have changed (e.g. days since last scan) or
    you want a completely fresh start. For a faster reset that keeps scan data,
    use POST /api/sessions/{session_id}/restart instead.
    """
    if session_id not in orchestrator.sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    reset = await orchestrator.reset_session_state(session_id, full_scan=True)
    if reset.get("status") != "success":
        raise HTTPException(status_code=500, detail=reset.get("message", "Reset failed"))
    logger.info(f"Full rescan for session {session_id} — all data cleared")
    asyncio.create_task(orchestrator.start_reconnaissance(session_id))
    return {"status": "success", "message": "Full rescan started from scratch"}


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
    """Update AI settings, persist them, and reload the connector.
    Supports Ollama, DeepSeek, OpenAI/ChatGPT, Anthropic Claude, and OpenRouter."""
    env_path = os.path.join(os.getcwd(), '.env')
    if not os.path.exists(env_path):
        open(env_path, 'w').close()

    provider_map = {
        "Local (Ollama)": "local", "DeepSeek API": "deepseek",
        "OpenAI / ChatGPT API": "openai", "Anthropic Claude API": "anthropic",
        "OpenRouter API": "openrouter",
    }
    provider_code = provider_map.get(settings.provider, settings.provider.strip().lower())
    if provider_code not in {"local", "deepseek", "openai", "anthropic", "openrouter", "none"}:
        raise HTTPException(status_code=400, detail="Unsupported AI provider")
    set_key(env_path, "AI_PROVIDER", provider_code)

    local_model = None
    ollama_url = None
    api_model = None

    if provider_code in {"deepseek", "openai", "anthropic", "openrouter"}:
        key_name = {
            "deepseek": "DEEPSEEK_API_KEY", "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY", "openrouter": "OPENROUTER_API_KEY",
        }[provider_code]
        model_name = {
            "deepseek": "DEEPSEEK_MODEL", "openai": "OPENAI_MODEL",
            "anthropic": "ANTHROPIC_MODEL", "openrouter": "OPENROUTER_MODEL",
        }[provider_code]
        if settings.api_key:
            set_key(env_path, key_name, settings.api_key)
        if settings.model_name:
            set_key(env_path, model_name, settings.model_name)
            api_model = settings.model_name
    elif provider_code == "local":
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
async def execute_command(command_request: CommandRequest, request: Request):
    """Execute a command in a session."""
    try:
        # API requests are never allowed to self-grant an approval. The
        # auto_approve field is retained for client compatibility, but the
        # backend decides whether this is a safe direct execution.
        base_error = orchestrator.validate_command(
            command_request.session_id,
            command_request.command,
            execution_mode="approved",
        )
        if base_error:
            raise HTTPException(status_code=400, detail=base_error)

        requires_approval = orchestrator.requires_approval(command_request.command)
        automated_error = orchestrator.validate_command(
            command_request.session_id,
            command_request.command,
            execution_mode="manual",
        )
        
        # High-risk commands and commands outside the automated allowlist are
        # queued. Only /api/approve can move them to the explicit approved path.
        if requires_approval or automated_error:
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
                command=command_request.command,
                execution_mode="manual",
            )
            await broadcast_message("command_executed", {
                "session_id": command_request.session_id,
                "command": command_request.command,
                "result": result
            })
            return {
                "status": "executed",
                "result": result if request.state.principal.sensitive else {"status": "executed"},
                "message": "Command executed successfully"
            }
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        raise HTTPException(status_code=500, detail="Command execution failed") from None

@app.post("/api/approve")
async def approve_command(approval_request: ApprovalRequest, request: Request):
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
                "result": result if request.state.principal.sensitive else {"status": "approved"},
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
        raise HTTPException(status_code=500, detail="Command approval failed") from None

# WebSocket endpoint for real-time updates
@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time communication."""
    try:
        principal = access_control.authenticate(websocket.headers, websocket.query_params)
        references = []
        for key, value in websocket.query_params.multi_items():
            references.extend(access_control.session_references({key: value}))
        for sid in references:
            access_control.authorize(principal, "GET", f"/api/sessions/{sid}", [sid])
    except (AccessError, OSError, sqlite3.Error):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    active_connections[websocket] = principal
    
    try:
        while True:
            data = await websocket.receive_json()
            try:
                principal = access_control.authenticate(websocket.headers, websocket.query_params)
                if not isinstance(data, dict):
                    raise AccessError(400, "Expected message object")
                references = access_control.session_references(data)
                action = data.get("action", data.get("type"))
                if action == "ping":
                    access_control.authorize(principal, "GET", "/api/identity", references)
                    await websocket.send_json({"type": "pong"})
                elif action in {"get_session", "subscribe"} and isinstance(data.get("session_id"), str):
                    sid = data["session_id"]
                    if any(ref != sid for ref in references):
                        raise AccessError(403, "Conflicting session references")
                    access_control.authorize(principal, "GET", f"/api/sessions/{sid}", references)
                    report = orchestrator.get_session_report(sid)
                    await websocket.send_json({"type": "session", "data": report if principal.sensitive else build_report_snapshot(report)})
                else:
                    # No hidden execution/approval channel. Use the authorized HTTP API.
                    raise AccessError(403, "Unsupported WebSocket action; use HTTP API")
            except AccessError as exc:
                await websocket.send_json({"type": "error", "status": exc.status, "detail": exc.detail})
            except ValueError:
                await websocket.send_json({"type": "error", "status": 404, "detail": "Session not found"})
    except WebSocketDisconnect:
        active_connections.pop(websocket, None)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if websocket in active_connections:
            active_connections.pop(websocket, None)

def start_operation():
    """Start the FastAPI server."""
    # Default to localhost-only. This API can execute shell commands, so binding
    # to 0.0.0.0 exposes that to the whole network - only do so deliberately via
    # BACKEND_HOST in .env, and keep API_AUTH_TOKEN secret if you do.
    host = os.getenv("BACKEND_HOST", "127.0.0.1")
    port = int(os.getenv("BACKEND_PORT", "6000"))

    logger.info("Starting KMN-CyberSeek backend server...")
    logger.info(f"API Documentation: http://localhost:{port}/api/docs")
    logger.info(f"Streamlit Frontend: http://localhost:8501")
    if host != "127.0.0.1" and host != "localhost":
        logger.warning(f"BACKEND_HOST={host} - the API is reachable beyond localhost. Ensure API_AUTH_TOKEN stays secret.")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        # log_config=None → don't let uvicorn install its own logging handlers.
        # Its loggers then propagate to the root logger we configured above, so
        # uvicorn's output (startup, errors, non-noise access) is mirrored into the
        # single terminal-log file alongside the app logs.
        log_config=None,
    )

if __name__ == "__main__":
    start_operation()

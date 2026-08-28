"""Test helpers: build a lightweight Orchestrator/Session without touching the
database, filesystem, or network. We construct via __new__ and set only the
attributes the reasoning helpers under test actually read, so unit tests stay
fast and isolated from I/O."""

from unittest.mock import MagicMock

from core.orchestrator import Orchestrator, Session


def make_orch(provider="api"):
    """A bare Orchestrator wired with a mock AI connector and no DB/file I/O.
    `provider` controls the memory index mode ('api' -> lexical, 'local' -> may
    attempt embeddings; tests force lexical where needed)."""
    ai = MagicMock()
    ai.provider = provider
    ai.ollama_url = "http://localhost:11434/api/generate"

    orch = Orchestrator.__new__(Orchestrator)
    orch.sessions = {}
    orch.ai_connector = ai
    orch.threat_intel_cache = []
    orch.pending_commands = {}
    orch._live_output = {}
    orch._findings_indexes = {}
    orch._missing_tools = []
    orch._background_tasks = {}
    # No-op the persistence + evidence side effects so unit tests stay DB-free.
    orch.add_evidence = lambda *a, **k: None
    orch._save_credential_db = lambda *a, **k: None
    orch._save_ai_decision = lambda *a, **k: None
    orch._save_session_status = lambda *a, **k: None

    # Capture queued commands so tests can assert on them.
    orch.queued = []
    orch.queue_for_approval = lambda sid, cmd: (orch.queued.append(cmd) or "cid")
    return orch


def make_session(sid="s1", ip="10.0.0.5", services=None, **kw):
    s = Session(sid, ip, **kw)
    if services:
        s.discovered_services = services
    return s


def svc(port, service, host="10.0.0.5", state="untested", version=""):
    return {
        "host": host,
        "port": port,
        "service": service,
        "version": version,
        "state": "open",
        "test_state": state,
    }

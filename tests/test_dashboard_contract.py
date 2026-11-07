"""Offline dashboard contracts: execute AST definitions, never import Streamlit/main."""

import ast
import asyncio
import html
import inspect
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
from types import SimpleNamespace
from typing import Dict, List, Optional
from urllib.parse import quote, urlsplit

import pytest


SOURCE = Path(__file__).parents[1] / "frontend.py"
FINDING_ID = "12345678-1234-4234-8234-123456789abc"
ARTIFACT_ID = "a" * 64 + "." + "b" * 32


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Dashboard contract tests must remain offline")
    monkeypatch.setattr("socket.create_connection", blocked)
    monkeypatch.setattr("socket.socket.connect", blocked)


class FakeStreamlit:
    def __init__(self):
        self.session_state = {"dashboard_identity": {"role": "admin", "sensitive_read": True}}
        self.values = {}
        self.output = []
        self.downloads = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def checkbox(self, label, value=False, key=None, **kwargs):
        return self.values.get(key, self.values.get(label, value))

    def button(self, label, key=None, disabled=False, **kwargs):
        return not disabled and self.values.get(key, self.values.get(label, False))

    form_submit_button = button

    def selectbox(self, label, options, **kwargs):
        return self.values.get(label, next(iter(options), None))

    def multiselect(self, label, options, **kwargs):
        return self.values.get(label, [])

    def text_input(self, label, value="", **kwargs):
        return self.values.get(label, value)

    text_area = text_input

    def file_uploader(self, label, **kwargs):
        return self.values.get(label)

    def form(self, *args, **kwargs):
        return self

    expander = form
    spinner = form
    container = form

    def columns(self, spec):
        return [self] * (spec if isinstance(spec, int) else len(spec))

    def download_button(self, label, data, **kwargs):
        self.downloads.append((label, data, kwargs))

    def __getattr__(self, name):
        if name in {"info", "warning", "error", "success", "caption", "write", "markdown", "dataframe", "metric"}:
            return lambda *args, **kwargs: self.output.append((name, args))
        raise AttributeError(name)


@pytest.fixture
def dashboard():
    st = FakeStreamlit()
    transport = []

    class Response:
        status_code = 200
        _content = b'{}'
        encoding = "utf-8"

        @property
        def content(self):
            return self._content

        def json(self):
            return json.loads(self._content)

    class Session:
        def request(self, method, url, **kwargs):
            transport.append((method, url, kwargs))
            return Response()

    requests = SimpleNamespace(Session=Session, Response=Response, RequestException=type("RequestException", (Exception,), {}))
    tree = ast.parse(SOURCE.read_text())
    definitions = ast.Module(body=[node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))], type_ignores=[])
    namespace = {"st": st, "requests": requests, "json": json, "re": re, "quote": quote, "urlsplit": urlsplit, "html": html,
                 "Dict": Dict, "List": List, "Optional": Optional, "API_BASE": "http://offline/api"}
    exec(compile(definitions, str(SOURCE), "exec"), namespace)
    namespace["_load_api_token"] = lambda: "shared-secret"
    namespace["api_session"] = namespace["DashboardSession"]()
    namespace["transport"] = transport
    return namespace


def test_principal_override_is_browser_local_and_exclusive(dashboard):
    d = dashboard
    session = d["api_session"]
    d["st"].session_state["principal_token"] = "browser-secret"
    session.request("GET", "http://offline/api/identity", headers={"X-API-Key": "stale", "Authorization": "stale"})
    assert d["transport"][-1][2]["headers"] == {"Authorization": "Bearer browser-secret"}
    d["st"].session_state["principal_token"] = ""
    session.request("GET", "http://offline/api/identity")
    assert d["transport"][-1][2]["headers"] == {"X-API-Key": "shared-secret"}


def test_identity_change_clears_sensitive_state_and_acknowledgements(dashboard):
    st = dashboard["st"]
    st.session_state.update(principal_token="new-token", raw_artifact_s1={"content": b"secret"}, legacy_ack_overview_s1=True)
    dashboard["principal_changed"]()
    assert st.session_state == {"principal_token": "new-token"}


@pytest.mark.parametrize("role,operate,review", [("viewer", False, False), ("operator", True, False),
                                                 ("reviewer", False, True), ("admin", True, True), ("", False, False)])
def test_roles_are_distinct_and_unknown_is_not_admin(dashboard, role, operate, review):
    dashboard["st"].session_state["dashboard_identity"] = {"role": role}
    assert dashboard["can_operate"]() is operate
    assert dashboard["can_review"]() is review


def test_viewer_ui_guard_never_posts(dashboard):
    dashboard["st"].session_state["dashboard_identity"] = {"role": "viewer"}
    response = dashboard["api_session"].request("POST", "http://offline/api/start")
    assert response.status_code == 403
    assert not dashboard["transport"]


@pytest.mark.parametrize("payload,ready", [({}, False), ({"error": "private-secret"}, False),
    ({"ready": True}, False), ({"ready": True, "checks": [{"name": "scope", "status": "fail"}]}, False),
    ({"ready": False, "checks": [{"status": "ready"}]}, False),
    ({"ready": True, "checks": [{"status": "ready"}, {"status": "warn"}]}, True)])
def test_preflight_fails_closed(dashboard, payload, ready):
    assert dashboard["render_checks"](payload) is ready
    assert "private-secret" not in repr(dashboard["st"].output)


def test_new_session_preflight_is_before_start_and_authorization_is_explicit():
    tree = ast.parse(SOURCE.read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "show_new_session")
    source = ast.get_source_segment(SOURCE.read_text(), function)
    assert source.index('"/preflight"') < source.index("result = start_session(")
    assert '"authorization_confirmed": authorization_confirmed' in source
    assert 'if not render_checks(preflight):\n                return' in source
    assert 'value=False' in source[source.index('"Auto-run routine'):source.index('full_auto_checkbox')]


@pytest.mark.parametrize("authorized,preflight_ready,starts", [(False, True, 0), (True, False, 0), (True, True, 1)])
def test_session_creation_runtime_gates(dashboard, authorized, preflight_ready, starts):
    calls = []
    start_calls = []
    dashboard["check_backend_health"] = lambda: True
    dashboard["dashboard_api"] = lambda *args: calls.append(args) or {
        "ready": preflight_ready, "checks": [{"name": "scope", "status": "ready" if preflight_ready else "blocked"}]}
    dashboard["start_session"] = lambda *args, **kwargs: start_calls.append((args, kwargs)) or {"error": "test rejected"}
    st = dashboard["st"]
    st.values.update({"Target IP / Domain / Subnet *": "127.0.0.1", "🚀 Start New Session": True,
        "I confirm I own this target or have explicit written authorization to test it, and I accept responsibility for this engagement.": authorized})
    dashboard["show_new_session"]()
    assert len(start_calls) == starts
    if authorized:
        assert calls[0][0:2] == ("POST", "/preflight")
        assert calls[0][2] == {"target": "127.0.0.1", "authorization_confirmed": True}
    else:
        assert not calls
    if starts:
        assert start_calls[0][1]["authorization_confirmed"] is True
        assert start_calls[0][1]["auto_approve"] is False


def test_completeness_is_not_objective_or_closure(dashboard):
    dashboard["render_report_status"]({"session": {"status": "completed", "objective_complete": True},
                                        "completeness": {"verdict": "incomplete", "missing_checks": [{"category": "auth"}]}})
    output = dashboard["st"].output
    assert any(kind == "warning" and "Partial/incomplete" in args[0] for kind, args in output)
    assert "missing_checks" in repr(output)
    dashboard["st"].output.clear()
    dashboard["render_report_status"]({"completeness": {"verdict": "complete"}})
    assert not any(kind == "warning" for kind, _ in dashboard["st"].output)


def test_safe_json_uses_only_server_snapshot_and_survives_rerun(dashboard):
    calls = []
    snapshot = {"schema_version": "1.0", "findings": []}
    dashboard["dashboard_api"] = lambda *args, **kwargs: calls.append(args) or snapshot
    st = dashboard["st"]
    st.values["safe_report_s1"] = True
    dashboard["show_safe_report"]("s1")
    assert calls == [("GET", "/sessions/s1/report.json")]
    assert json.loads(st.downloads[-1][1]) == snapshot
    st.values.clear()
    dashboard["show_safe_report"]("s1")
    assert len(calls) == 1 and len(st.downloads) == 2


def test_legacy_exports_do_not_fetch_or_download_without_ack(dashboard):
    dashboard["dashboard_api"] = lambda *args, **kwargs: pytest.fail("Unexpected API fetch")
    st = dashboard["st"]
    st.session_state["_export_json_s1"] = "old-sensitive-data"
    dashboard["show_legacy_evidence_exports"]({"session_id": "s1", "credentials": [{"secret": "secret"}]})
    assert "_export_json_s1" not in st.session_state
    assert not st.downloads


def test_legacy_export_requires_ack_and_keeps_secrets_out_of_rendering(dashboard):
    st = dashboard["st"]
    st.values.update({"legacy_ack_evidence_s1": True, "📄 Export as JSON": True})
    dashboard["show_legacy_evidence_exports"]({"session_id": "s1", "credentials": [{"secret": "sensitive-secret"}]})
    assert json.loads(st.downloads[-1][1])["credentials"] == [{"secret": "sensitive-secret"}]
    assert "sensitive-secret" not in repr(st.output)
    st.values.clear()
    st.downloads.clear()
    dashboard["show_legacy_evidence_exports"]({"session_id": "s1"})
    assert "_export_json_s1" not in st.session_state and not st.downloads


def test_html_export_escapes_metadata_without_shadowing_html_module(dashboard):
    st = dashboard["st"]
    st.values.update({"legacy_ack_evidence_s1": True, "🌐 Export as HTML": True})
    dashboard["show_legacy_evidence_exports"]({"session_id": "s1", "target_ip": "<script>bad</script>"})
    assert "<script>bad</script>" not in st.downloads[-1][1]
    assert "&lt;script&gt;bad&lt;/script&gt;" in st.downloads[-1][1]


@pytest.mark.parametrize("ack,prepare,fetches,downloads", [(False, False, 0, 0), (True, False, 0, 0), (True, True, 1, 1)])
def test_raw_evidence_requires_ack_and_explicit_prepare(dashboard, ack, prepare, fetches, downloads):
    calls = []
    def api(method, path, **kwargs):
        calls.append((method, path, kwargs))
        if path.endswith("/artifacts"):
            return {"artifacts": [{"id": ARTIFACT_ID, "truncated": True, "content": "must-not-render"}]}
        return {"content": b"raw-secret"}
    dashboard["dashboard_api"] = api
    st = dashboard["st"]
    st.values.update(raw_ack_s1=ack, raw_prepare_s1=prepare)
    dashboard["show_evidence"]({"session_id": "s1", "evidence": [{"content": "must-not-render"}]})
    assert sum("/content" in path for _, path, _ in calls) == fetches
    assert len(st.downloads) == downloads
    assert "must-not-render" not in repr(st.output) and "raw-secret" not in repr(st.output)
    if prepare:
        assert calls[-1][2] == {"params": {"acknowledge_sensitive": "true"}, "raw": True}
        st.values.update(raw_ack_s1=False, raw_prepare_s1=False)
        dashboard["show_evidence"]({"session_id": "s1"})
        assert "raw_artifact_s1" not in st.session_state


@pytest.mark.parametrize("kind,result", [("verification", "positive"), ("remediation", "applied"), ("retest", "negative")])
def test_reviews_use_uuid_and_actual_committed_refs(dashboard, kind, result):
    calls = []
    dashboard["dashboard_api"] = lambda *args, **kwargs: calls.append(args) or {"status": "recorded"}
    response = dashboard["submit_finding_review"]("s1", FINDING_ID, [{"id": ARTIFACT_ID}], kind, result,
                                                 "Operator inspected artifact", [ARTIFACT_ID], True)
    assert response == {"status": "recorded"}
    method, path, payload = calls[0]
    assert method == "POST" and path == f"/sessions/s1/vulnerabilities/{FINDING_ID}/verification"
    assert payload == {"kind": kind, "result": result, "method": "Operator inspected artifact",
                       "artifact_refs": [ARTIFACT_ID], "acknowledge_review": True}


@pytest.mark.parametrize("finding,method,refs,ack", [("finding-1", "review", [ARTIFACT_ID], True),
    (FINDING_ID, "", [ARTIFACT_ID], True), (FINDING_ID, "review", [], True),
    (FINDING_ID, "review", ["foreign-artifact"], True), (FINDING_ID, "review", [ARTIFACT_ID], False)])
def test_invalid_review_never_posts(dashboard, finding, method, refs, ack):
    dashboard["dashboard_api"] = lambda *args, **kwargs: pytest.fail("Invalid review sent")
    assert dashboard["submit_finding_review"]("s1", finding, [{"id": ARTIFACT_ID}], "verification", "positive", method, refs, ack).get("error")


def test_api_errors_never_echo_backend_text_or_tokens(dashboard):
    class BadResponse:
        status_code = 403
        text = "private-token-echo"
    dashboard["api_session"] = SimpleNamespace(request=lambda *args, **kwargs: BadResponse())
    assert dashboard["dashboard_api"]("GET", "/identity") == {"error": "Unavailable (HTTP 403)."}
    def failed(*args, **kwargs):
        raise RuntimeError("private-token-echo")
    dashboard["api_session"].request = failed
    assert "private-token-echo" not in repr(dashboard["dashboard_api"]("GET", "/identity"))


def test_operations_use_requested_endpoints_and_never_render_payloads(dashboard):
    calls = []
    def api(method, path):
        calls.append((method, path))
        return {"operations": [{"status": "running", "payload": "secret-command"}]}
    dashboard["dashboard_api"] = api
    dashboard["show_operations"]("s1")
    assert calls == [("GET", "/sessions/s1/telemetry/summary"), ("GET", "/sessions/s1/telemetry/events"),
                     ("GET", "/sessions/s1/preflight"), ("GET", "/sessions/s1/operations")]
    assert "secret-command" not in repr(dashboard["st"].output)


def test_assessment_updates_exact_cell_with_evidence_ref(dashboard):
    calls = []
    def api(method, path, payload=None):
        calls.append((method, path, payload))
        return {"snapshot": {"endpoints": [{"id": "e1", "method": "GET", "path": "/items"}],
                             "coverage": [{"endpoint_id": "e1", "role": "anonymous", "category": "observation", "status": "attempted", "attempts": 1}]}}
    dashboard["dashboard_api"] = api
    dashboard["st"].values.update({"Record Attempt / Status": True, "New coverage status": "verified",
                                    "Evidence reference (evidence:..., required for verified)": "evidence:review1"})
    dashboard["show_assessment"]("s1")
    assert calls[-1] == ("PATCH", "/sessions/s1/assessment/coverage", {"endpoint_id": "e1", "role": "anonymous",
        "category": "observation", "status": "verified", "evidence_ref": "evidence:review1"})


def test_openapi_import_is_an_explicit_bounded_json_post(dashboard):
    calls = []
    document = {"openapi": "3.0.0", "paths": {}}
    upload = SimpleNamespace(size=42, getvalue=lambda: json.dumps(document).encode())
    dashboard["dashboard_api"] = lambda *args: calls.append(args) or {"snapshot": {}}
    dashboard["st"].values.update({"OpenAPI 3.x JSON (maximum 2 MiB)": upload,
                                    "Explicit base URL (no credentials)": "https://example.test",
                                    "Import Declared Inventory": True})
    dashboard["show_assessment"]("s1")
    assert calls[0] == ("POST", "/sessions/s1/assessment/import", {"document": document,
        "base_url": "https://example.test", "roles": {"anonymous": None}, "categories": ["observation"]})


def test_operation_checkpoint_state_and_unknown_model_usage_are_visible(dashboard):
    dashboard["dashboard_api"] = lambda method, path: {
        "summary": {"calls": 2, "unknown_usage_calls": 1, "cost_usd": None},
        "events": [{"total_tokens": None, "reserved_tokens": 10, "prompt": "secret-prompt"}],
        "operations": [{"state": "needs_reconciliation", "result": "secret-output"}]}
    dashboard["show_operations"]("s1")
    output = repr(dashboard["st"].output)
    assert "unknown_usage_calls" in output and "needs_reconciliation" in output
    assert "secret-prompt" not in output and "secret-output" not in output


@pytest.fixture
def routes(tmp_path, monkeypatch):
    """Execute actual main route/validator ASTs, without FastAPI or importing main."""
    from core.access_control import AccessStore, Principal
    from core.assessment import AssessmentError
    from core.model_telemetry import ModelTelemetryStore
    from core.report_export import build_report_snapshot

    class HTTPException(Exception):
        def __init__(self, status_code, detail):
            self.status_code, self.detail = status_code, detail

    class Request:
        def __init__(self, payload):
            self.payload = payload
            self.state = SimpleNamespace(principal=Principal("reviewer1", "reviewer", True, ("s1",)))

        async def stream(self):
            yield json.dumps(self.payload).encode()

    report = {"session": {"session_id": "s1", "target_ip": "127.0.0.1", "scope_allowlist": ""},
              "vulnerabilities": [{"finding_id": FINDING_ID, "name": "Example"}], "credentials": []}
    recorded = []
    def get_report(sid):
        if sid != "s1":
            raise ValueError("Session not found")
        return report

    async def ask_raw_async(system_prompt, user_prompt):
        context = json.loads(user_prompt)
        return {"hypotheses": ["Independent testing is needed."], "missing_evidence": ["Runtime evidence"],
                "citations": [r["ref"] for r in context["references"]], "uncertainty": 0.9}

    store = AccessStore(tmp_path / "access.sqlite")
    connector = SimpleNamespace(ask_raw_async=ask_raw_async,
                                telemetry_store=ModelTelemetryStore(tmp_path / "usage.sqlite"))
    with sqlite3.connect(tmp_path / "sessions.sqlite") as connection:
        connection.execute("CREATE TABLE commands (session_id TEXT, command_id TEXT, attempt_id TEXT, record_json TEXT)")
        connection.execute("INSERT INTO commands VALUES (?,?,?,?)", (
            "s1", "cmd1", "attempt1", json.dumps({"artifacts": [{"id": ARTIFACT_ID}]})))
    namespace = {"Request": Request, "HTTPException": HTTPException, "MAX_BYTES": 2 * 1024 * 1024,
                 "asyncio": asyncio, "json": json, "re": re, "os": os, "Path": Path, "sqlite3": sqlite3,
                 "_assessment_lock": threading.RLock(),
                 "JSONResponse": lambda content, **kwargs: content,
                 "ArtifactStoreError": type("ArtifactStoreError", (Exception,), {}),
                 "ai_connector": connector, "scanner": object(), "AssessmentError": AssessmentError,
                 "build_report_snapshot": build_report_snapshot,
                 "access_control": SimpleNamespace(store=store),
                 "orchestrator": SimpleNamespace(db_path=str(tmp_path / "sessions.sqlite"), ai_connector=connector,
                     _session_epoch=lambda sid: 0, _stale_execution=lambda sid, epoch: False,
                     _track_task=lambda sid, coroutine, label: asyncio.create_task(coroutine),
                     get_session_report=get_report, get_session_operations=lambda sid: [{"state": "prepare", "command_id": "cmd1", "attempt_id": "attempt1"}],
                     record_verification=lambda sid, fid, payload: recorded.append(payload) or {"status": "recorded"}),
                 "_session_artifacts": lambda sid: (None, [{"id": ARTIFACT_ID}])}
    names = {"_bounded_json_body", "_require_session_report", "evaluate_configuration_preflight",
             "get_session_model_summary", "get_session_model_events", "get_session_operations",
             "import_session_source", "get_session_sources", "get_session_handoffs", "run_session_handoff",
             "record_finding_verification", "download_session_report_json", "_run_session_work",
             "_import_source_snapshot", "_session_handoff"}
    tree = ast.parse((SOURCE.parent / "main.py").read_text())
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]
    assert {n.name for n in nodes} == names
    for node in nodes:
        node.decorator_list = []
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "main-route-contracts", "exec"), namespace)
    monkeypatch.setenv("KMN_MODEL_TELEMETRY_DB", str(tmp_path / "usage.sqlite"))
    monkeypatch.setattr("core.preflight.evaluate_preflight", lambda *args: {
        "ready": True, "checks": [{"name": "target", "status": "ready"}]})

    def call(name, payload=None, **kwargs):
        function = namespace[name]
        if "request" in inspect.signature(function).parameters:
            kwargs["request"] = Request(payload)
        async def invoke():
            namespace["_specialist_slots"] = asyncio.Semaphore(1)
            return await function(**kwargs)
        return asyncio.run(invoke())

    return SimpleNamespace(call=call, namespace=namespace, error=HTTPException, report=report, recorded=recorded)


def test_dashboard_preflight_payload_passes_actual_main_validator(dashboard, routes):
    submitted = []
    dashboard["check_backend_health"] = lambda: True
    def api(method, path, payload):
        assert (method, path) == ("POST", "/preflight")
        submitted.append(payload)
        return routes.call("evaluate_configuration_preflight", payload=payload)
    dashboard["dashboard_api"] = api
    dashboard["start_session"] = lambda *args, **kwargs: {"error": "Do not start scans in tests"}
    dashboard["st"].values.update({"Target IP / Domain / Subnet *": "127.0.0.1", "🚀 Start New Session": True,
        "I confirm I own this target or have explicit written authorization to test it, and I accept responsibility for this engagement.": True})
    dashboard["show_new_session"]()
    assert submitted == [{"target": "127.0.0.1", "authorization_confirmed": True}]
    with pytest.raises(routes.error) as rejected:
        routes.call("evaluate_configuration_preflight", payload={"ip": "127.0.0.1", "authorization_confirmed": True})
    assert rejected.value.status_code == 400


@pytest.mark.parametrize("bound", [False, True])
def test_review_payload_passes_actual_route_and_receives_server_provenance(dashboard, routes, bound):
    dashboard["dashboard_api"] = lambda method, path, payload: routes.call(
        "record_finding_verification", session_id="s1", finding_id=FINDING_ID, payload=payload)
    args = {"command_id": "cmd1", "attempt_id": "attempt1"} if bound else {}
    result = dashboard["submit_finding_review"]("s1", FINDING_ID, [{"id": ARTIFACT_ID}], "verification", "positive",
                                               "Manual review", [ARTIFACT_ID], True, **args)
    assert result == {"status": "recorded"}
    assert routes.recorded[-1]["provenance"] == ({"type": "runtime", "source": "command_result"} if bound
                                                 else {"type": "review_only", "source": "operator_review"})
    assert routes.recorded[-1]["reviewer"] == "reviewer1"


@pytest.mark.parametrize("command,attempt", [("cmd1", ""), ("", "attempt1"), ("bad id", "attempt1")])
def test_runtime_binding_pair_is_explicit_and_validated(dashboard, command, attempt):
    dashboard["dashboard_api"] = lambda *args, **kwargs: pytest.fail("Invalid pair must not be sent")
    assert dashboard["submit_finding_review"]("s1", FINDING_ID, [{"id": ARTIFACT_ID}], "verification", "positive",
        "Manual review", [ARTIFACT_ID], True, command, attempt).get("error")


def test_operations_render_actual_telemetry_route_shapes(dashboard, routes):
    store = routes.namespace["orchestrator"].ai_connector.telemetry_store
    store.reserve(session_id="s1", purpose="tactical", operation_id="op1", retry_ordinal=0,
                  provider="local", model="offline", estimated_input_tokens=1, max_tokens=4)
    calls = []
    def api(method, path):
        calls.append(path)
        names = {"/sessions/s1/telemetry/summary": "get_session_model_summary",
                 "/sessions/s1/telemetry/events": "get_session_model_events",
                 "/sessions/s1/operations": "get_session_operations"}
        if path.endswith("/preflight"):
            return {"ready": True, "checks": [{"name": "target", "status": "ready"}]}
        return routes.call(names[path], session_id="s1")
    dashboard["dashboard_api"] = api
    dashboard["show_operations"]("s1")
    output = repr(dashboard["st"].output)
    assert "unknown_usage_calls" in output and "offline" in output and "prepare" in output
    tree = ast.parse((SOURCE.parent / "main.py").read_text())
    paths = {decorator.args[0].value for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
             for decorator in node.decorator_list if isinstance(decorator, ast.Call) and decorator.args
             and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str)}
    assert all("/api" + path.replace("/s1/", "/{session_id}/") in paths for path in calls)


@pytest.mark.parametrize("bound", [False, True])
@pytest.mark.parametrize("retested", [False, True])
def test_sanitized_report_route_renders_completeness_and_finding_lifecycle(dashboard, routes, bound, retested):
    from tests.test_verified_findings import finding_with_events

    checks = [("verification", "positive")]
    if retested:
        checks.extend([("remediation", "applied"), ("retest", "negative")])
    finding = finding_with_events(*checks)
    finding.update(finding_id=FINDING_ID, name="Example captured-password")
    provenance = {"type": "runtime" if bound else "review_only",
                  "source": "command_result" if bound else "operator_review"}
    commands = []
    for index, (event, evidence) in enumerate(zip(finding["verification_events"], finding["evidence"])):
        event["provenance"] = provenance
        if bound:
            binding = {"command_id": f"cmd{index}", "attempt_id": f"attempt{index}"}
            evidence.update(binding)
            commands.append({**binding, "artifacts": [finding["artifacts"][index]],
                             "command": "private-command", "output": "private-output"})
    missing = {"endpoint_id": "endpoint1", "role": "reader", "category": "authorization", "status": "blocked"}
    routes.report.update({
        "session": {"session_id": "s1", "status": "completed", "objective_complete": True},
        "completeness": {"verdict": "incomplete", "missing_checks": [{**missing, "note": "private-note"}],
                         "blockers": [{**missing, "reason": "private-reason"}], "waived_checks": []},
        "vulnerabilities": [finding], "commands_executed": commands,
        "credentials": [{"secret": "captured-password"}],
    })
    snapshot = routes.call("download_session_report_json", session_id="s1")
    assert snapshot["completeness"] == {"version": 1, "verdict": "incomplete", "missing_checks": [missing],
                                         "blockers": [missing], "waived_checks": []}
    safe_finding = snapshot["findings"][0]
    assert safe_finding["provenance"] == {**provenance, "runtime_bound": bound, "independent_reproduction": False}
    assert safe_finding["lifecycle"] == ("retested" if retested else "verified")
    assert safe_finding["remediation_verified"] is retested

    # A viewer must see these sanitized fields without fetching any sensitive panels.
    dashboard["st"].session_state["dashboard_identity"] = {"role": "viewer"}
    dashboard["dashboard_api"] = lambda *args, **kwargs: pytest.fail("Safe report rendering must not fetch sensitive data")
    dashboard["render_report_status"](snapshot)
    dashboard["show_finding_lifecycle"]("s1", snapshot)
    output = dashboard["st"].output
    assert ("write", ({"completeness": "incomplete", "objective_complete": True, "closure": "completed"},)) in output
    assert ("write", ({"missing_checks": [missing]},)) in output
    assert any(kind == "warning" and "Partial/incomplete report" in args[0] for kind, args in output)
    rendered_findings = next(args[0] for kind, args in output if kind == "dataframe")
    for field in ("provenance", "lifecycle", "remediation_verified"):
        assert rendered_findings[0][field] == safe_finding[field]
    for secret in ("captured-password", "private-command", "private-output", "private-note", "private-reason"):
        assert secret not in repr(output)


def test_sanitized_report_route_complete_verdict_is_separate_from_objective(dashboard, routes):
    routes.report.update({"session": {"status": "ready", "objective_complete": False},
                          "completeness": {"verdict": "complete", "missing_checks": [], "blockers": [], "waived_checks": []}})
    snapshot = routes.call("download_session_report_json", session_id="s1")
    dashboard["render_report_status"](snapshot)
    output = dashboard["st"].output
    assert ("write", ({"completeness": "complete", "objective_complete": False, "closure": "ready"},)) in output
    assert not any(kind == "warning" for kind, _ in output)


@pytest.mark.parametrize("role", ["viewer", "operator", "reviewer", "admin"])
@pytest.mark.parametrize("sensitive", [False, True])
def test_ui_capabilities_match_actual_access_control(dashboard, role, sensitive):
    from core.access_control import AccessControl, AccessError, Principal
    principal = Principal("test1", role, sensitive, ("s1",))
    control = AccessControl("", None)
    dashboard["st"].session_state["dashboard_identity"] = principal.identity()
    requests = [("GET", "/api/identity"), ("GET", "/api/sessions/s1/report.json"),
                ("GET", "/api/sessions/s1/artifacts"), ("GET", "/api/sessions/s1/telemetry/summary"),
                ("GET", "/api/sessions/s1/telemetry/events"), ("GET", "/api/sessions/s1/preflight"),
                ("GET", "/api/sessions/s1/completeness"), ("GET", "/api/sessions/s1/operations"),
                ("POST", "/api/preflight"), ("POST", "/api/start"), ("POST", "/api/execute"),
                ("POST", "/api/approve"), ("POST", f"/api/sessions/s1/vulnerabilities/{FINDING_ID}/verification"),
                ("POST", "/api/sessions/s1/assessment/import"), ("PATCH", "/api/sessions/s1/assessment/coverage"),
                ("POST", "/api/sessions/s1/sources/import"), ("POST", "/api/sessions/s1/handoffs"),
                ("POST", "/api/sessions/s1/ask"), ("POST", "/api/sessions/s1/steer"),
                ("DELETE", "/api/sessions/s1"), ("POST", "/api/settings/features")]
    for method, path in requests:
        try:
            control.authorize(principal, method, path, ("s1",) if "/s1" in path else ())
            allowed = True
        except AccessError:
            allowed = False
        assert dashboard["ui_allows"](method, path) is allowed, (role, sensitive, method, path)


@pytest.mark.parametrize("entered", ["invalid-principal", "   "])
def test_invalid_entered_principal_never_falls_back_to_admin(dashboard, monkeypatch, tmp_path, entered):
    import hashlib
    from core.access_control import AccessControl, AccessError, AccessStore
    config = tmp_path / "principals.json"
    config.write_text(json.dumps({"principals": [{"id": "alice", "role": "viewer",
        "token_sha256": hashlib.sha256(b"valid-token").hexdigest()}]}))
    monkeypatch.setenv("KMN_AUTH_PRINCIPALS_FILE", str(config))
    control = AccessControl("shared-secret", AccessStore(tmp_path / "auth.sqlite"))
    dashboard["_load_api_token"] = lambda: pytest.fail("An entered principal must never load the shared admin token")
    dashboard["st"].session_state["principal_token"] = entered
    dashboard["api_session"].request("GET", "http://offline/api/identity")
    headers = {k.lower(): v for k, v in dashboard["transport"][-1][2]["headers"].items()}
    assert "x-api-key" not in headers
    with pytest.raises(AccessError):
        control.authenticate(headers)


def test_bearer_override_authenticates_real_configured_principal(dashboard, monkeypatch, tmp_path):
    import hashlib
    from core.access_control import AccessControl, AccessStore
    config = tmp_path / "principals.json"
    config.write_text(json.dumps({"principals": [{"id": "alice", "role": "reviewer",
        "token_sha256": hashlib.sha256(b"browser-secret").hexdigest()}]}))
    monkeypatch.setenv("KMN_AUTH_PRINCIPALS_FILE", str(config))
    dashboard["st"].session_state["principal_token"] = "browser-secret"
    dashboard["api_session"].request("GET", "http://offline/api/identity")
    headers = {k.lower(): v for k, v in dashboard["transport"][-1][2]["headers"].items()}
    identity = AccessControl("shared-secret", AccessStore(tmp_path / "auth.sqlite")).authenticate(headers).identity()
    assert identity["id"] == "alice" and identity["role"] == "reviewer" and identity["identity_mode"] == "principals_file"


def test_runtime_binding_rejected_when_attempt_is_not_durable(dashboard, routes):
    dashboard["dashboard_api"] = lambda method, path, payload: routes.call(
        "record_finding_verification", session_id="s1", finding_id=FINDING_ID, payload=payload)
    with pytest.raises(routes.error) as rejected:
        dashboard["submit_finding_review"]("s1", FINDING_ID, [{"id": ARTIFACT_ID}], "verification", "positive",
            "Manual review", [ARTIFACT_ID], True, "cmd1", "other-attempt")
    assert rejected.value.status_code == 400 and not routes.recorded


@pytest.mark.parametrize("kind", ["manifest", "sarif"])
def test_source_upload_passes_actual_import_route(dashboard, routes, kind):
    if kind == "manifest":
        document = {"version": 1, "source_id": "app1", "revision": "rev1", "digest": "a" * 64,
                    "base_url": "https://example.test", "operations": [{"method": "GET", "path": "/items",
                    "locations": [{"file": "src/api.py", "line": 4}]}]}
    else:
        document = {"version": "2.1.0", "runs": []}
    encoded = json.dumps(document).encode()
    upload = SimpleNamespace(size=len(encoded), getvalue=lambda: encoded)
    dashboard["dashboard_api"] = lambda method, path, payload: routes.call("import_session_source", session_id="s1", payload=payload)
    result = dashboard["import_source_upload"]("s1", kind, upload, "app1", "rev1", "a" * 64)
    assert result["source"]["source_id"] == "app1" and result["source"]["trust"] == "untrusted"
    persisted = routes.call("get_session_sources", session_id="s1")
    assert persisted["count"] == 1 and persisted["sources"][0]["coverage"]["verified"] is False


@pytest.mark.parametrize("data", [b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'not-json', b' ' * (2 * 1024 * 1024 + 1)])
def test_source_upload_rejects_unbounded_or_ambiguous_json(dashboard, data):
    dashboard["dashboard_api"] = lambda *args, **kwargs: pytest.fail("Invalid local input must not be posted")
    upload = SimpleNamespace(size=len(data), getvalue=lambda: data)
    assert dashboard["import_source_upload"]("s1", "manifest", upload).get("error")


def test_handoff_form_uses_actual_request_and_result_contract(dashboard, routes):
    routes.namespace["access_control"].store.put_source("s1", {"source_id": "app1", "kind": "source_manifest"})
    calls = []
    def api(method, path, payload=None):
        calls.append((method, path, payload))
        if path.endswith("/sources"):
            return routes.call("get_session_sources", session_id="s1")
        return routes.call("run_session_handoff" if method == "POST" else "get_session_handoffs", session_id="s1", payload=payload)
    dashboard["dashboard_api"] = api
    dashboard["st"].values.update({"Specialist question (no credentials)": "What evidence is missing?",
        "Session-owned context references (maximum 16)": ["source:app1"], "Run Analysis-Only Handoff": True})
    dashboard["show_sources_and_handoffs"]("s1", {"findings": [{"id": FINDING_ID}]})
    post = next(call for call in calls if call[0] == "POST")
    assert post == ("POST", "/sessions/s1/handoffs", {"role": "authorization", "question": "What evidence is missing?",
                                                       "references": [{"ref": "source:app1", "summary": ""}]})
    output = repr(dashboard["st"].output)
    assert "Independent testing is needed." in output and "hypothesis_count" in output
    assert dashboard["st"].session_state["handoff_result_s1"]["verified"] is False


def test_reviewers_cannot_dispatch_handoffs_and_viewers_do_not_fetch_sensitive_panels(dashboard):
    calls = []
    dashboard["dashboard_api"] = lambda *args, **kwargs: calls.append(args) or {}
    st = dashboard["st"]
    st.session_state["dashboard_identity"] = {"role": "reviewer", "sensitive_read": True}
    st.values["Run Analysis-Only Handoff"] = True
    dashboard["show_sources_and_handoffs"]("s1", {})
    assert all(call[0] == "GET" for call in calls)
    calls.clear()
    st.session_state["dashboard_identity"] = {"role": "viewer", "sensitive_read": True}
    dashboard["show_sources_and_handoffs"]("s1", {})
    dashboard["show_finding_lifecycle"]("s1", {"findings": [{"id": FINDING_ID}]})
    assert not calls

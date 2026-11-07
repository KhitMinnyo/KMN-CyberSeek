"""Real HTTP/WS middleware contracts, with no backend startup or live providers."""

import hashlib
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from core.access_control import AccessControl, AccessStore, Principal
from tests.test_report_export import api, persisted_api, report, review


def bearer(name):
    return {"Authorization": "Bearer " + name + "-token"}


@pytest.fixture
def identities(api, monkeypatch, tmp_path):
    client, namespace, _, _ = api
    records = [
        {"id": name, "role": role, "token_sha256": hashlib.sha256((name + "-token").encode()).hexdigest(),
         "sensitive_read": sensitive, "sessions": sessions}
        for name, role, sensitive, sessions in [
            ("viewer", "viewer", True, ["s1"]),
            ("operator", "operator", False, ["s1"]),
            ("ops", "operator", True, ["s1"]),
            ("reviewer", "reviewer", False, ["s1"]),
            ("review", "reviewer", True, ["s1"]),
            ("outsider", "operator", True, []),
            ("admin", "admin", False, []),
        ]]
    path = tmp_path / "principals.json"
    path.write_text(json.dumps({"principals": records}), encoding="utf-8")
    monkeypatch.setenv("KMN_AUTH_PRINCIPALS_FILE", str(path))
    return client, namespace, path


@pytest.fixture
def scoped_api(persisted_api, identities, monkeypatch):
    client, namespace, instance, _ = persisted_api
    _, _, path = identities
    monkeypatch.setenv("SCOPE_ALLOWLIST", "192.0.2.0/24")
    sid = instance.create_session("192.0.2.10", authorization_confirmed=True)
    document = json.loads(path.read_text())
    for principal in document["principals"]:
        principal["sessions"].append(sid)
    path.write_text(json.dumps(document))
    return client, namespace, instance, sid


@pytest.fixture
def source_assessment(scoped_api):
    client, namespace, instance, sid = scoped_api
    prefix = f"/api/sessions/{sid}"
    inventory = {"document": {"openapi": "3.0.3", "paths": {path: {"get": {}} for path in ("/users", "/removed", "/added", "/other")}},
                 "base_url": "https://192.0.2.10"}
    imported = client.post(prefix + "/assessment/import", json=inventory, headers=bearer("ops"))
    assert imported.status_code == 200, imported.text
    manifest = {"kind": "manifest", "document": {"version": 1, "source_id": "repo", "revision": "r1", "digest": "a" * 64,
                "base_url": "https://192.0.2.10", "operations": [
                    {"method": "GET", "path": path, "locations": [{"file": "app.py", "line": 1}]}
                    for path in ("/users", "/removed")]}}
    assert client.post(prefix + "/sources/import", json=manifest, headers=bearer("ops")).status_code == 200
    instance.add_evidence(sid, "source_review", {"id": "source-check", "source_id": "repo", "revision": "r1"})
    source_ids = {endpoint["id"] for endpoint in instance._assessment_snapshot(sid)["endpoints"] if endpoint["path"] in {"/users", "/removed"}}
    for row in imported.json()["snapshot"]["coverage"]:
        reference = "evidence:source-check"
        if row["endpoint_id"] not in source_ids:
            identity = "independent-" + row["endpoint_id"]
            instance.add_evidence(sid, "manual_observation", {"id": identity})
            reference = "evidence:" + identity
        check = {key: row[key] for key in ("endpoint_id", "role", "category")}
        assert client.patch(prefix + "/assessment/coverage", json={**check, "status": "attempted"}, headers=bearer("ops")).status_code == 200
        response = client.patch(prefix + "/assessment/coverage", json={**check, "status": "verified", "evidence_ref": reference}, headers=bearer("review"))
        assert response.status_code == 200, response.text
    assert client.get(prefix + "/completeness", headers=bearer("viewer")).json()["verdict"] == "complete"
    return client, namespace, instance, sid, manifest


@pytest.mark.parametrize("path", ["/", "/health", "/api/docs", "/api/redoc", "/openapi.json", "/api/identity", "/not-an-api"])
def test_every_http_route_requires_auth(api, path):
    client, _, _, _ = api
    assert client.get(path).status_code == 401


def test_identity_modes_and_no_file_token_fallback(identities, monkeypatch):
    client, _, _ = identities
    identity = client.get("/api/identity", headers=bearer("viewer"))
    assert identity.json() == {"id": "viewer", "role": "viewer", "sensitive_read": False, "identity_mode": "principals_file"}
    assert identity.headers["x-identity-mode"] == "principals_file"
    assert identity.headers["cache-control"] == "no-store"
    assert client.get("/api/identity", headers={"X-API-Key": "test-api-key"}).status_code == 401
    assert client.get("/api/identity", headers={"X-API-Key": "viewer-token"}).status_code == 401
    monkeypatch.delenv("KMN_AUTH_PRINCIPALS_FILE")
    response = client.get("/api/identity", headers={"X-API-Key": "test-api-key"})
    assert response.json()["identity_mode"] == "legacy_service_admin"
    assert response.json()["role"] == "admin"


@pytest.mark.parametrize("document", ["", "{", "[]", "{}", '{"principals": []}',
    '{"principals": [{"id":"alice","role":"admin","token_sha256":"plaintext"}]}',
    '{"principals": [{"id":"alice","role":"owner","token_sha256":"' + "a" * 64 + '"}]}'])
def test_bad_config_fails_closed_even_for_legacy_admin(identities, document):
    client, _, path = identities
    path.write_text(document, encoding="utf-8")
    for headers in (bearer("admin"), {"X-API-Key": "test-api-key"}, {}):
        response = client.get("/health", headers=headers)
        assert response.status_code == 503
        assert str(path) not in response.text


def test_missing_config_and_blank_config_do_not_fall_back(identities, monkeypatch):
    client, _, path = identities
    path.unlink()
    assert client.get("/", headers=bearer("admin")).status_code == 503
    monkeypatch.setenv("KMN_AUTH_PRINCIPALS_FILE", "")
    assert client.get("/", headers={"X-API-Key": "test-api-key"}).status_code == 503


@pytest.mark.parametrize("change", ["duplicate_identity", "duplicate_token", "unknown_field", "wildcard", "wrong_boolean", "invalid_role"])
def test_entire_principal_file_is_validated_not_just_matching_token(identities, change):
    client, _, path = identities
    document = json.loads(path.read_text())
    records = document["principals"]
    if change == "duplicate_identity":
        records[-1]["id"] = records[0]["id"]
    elif change == "duplicate_token":
        records[-1]["token_sha256"] = records[0]["token_sha256"]
    elif change == "unknown_field":
        records[-1]["token"] = "plaintext-is-not-accepted"
    elif change == "wildcard":
        records[-1]["sessions"] = ["*"]
    elif change == "wrong_boolean":
        records[-1]["sensitive_read"] = "false"
    else:
        records[-1]["role"] = ["admin"]
    path.write_text(json.dumps(document))
    assert client.get("/api/identity", headers=bearer("viewer")).status_code == 503


def test_store_ownership_is_persistent_and_not_automatically_shared(tmp_path):
    path = tmp_path / "acl.sqlite3"
    owner, other = Principal("owner", "operator"), Principal("other", "operator")
    store = AccessStore(path)
    assert not path.exists()
    store.own("private", owner)
    control = AccessControl("legacy", AccessStore(path))
    assert control.can_access(owner, "private")
    assert not control.can_access(other, "private")
    assert not control.can_access(owner, "historical-unowned")
    assert control.can_access(Principal("reader", "viewer", sessions=("private",)), "private")
    store.forget("private")
    assert not control.can_access(owner, "private")


@pytest.mark.parametrize("suffix", ["report", "report/pdf", "report/md", "archive", "events", "jobs", "artifacts",
    "artifacts/fake/content?acknowledge_sensitive=true", "credentials", "live_output", "shells", "pending_commands",
    "operations", "assessment", "sources", "handoffs", "telemetry/events"])
@pytest.mark.parametrize("identity", ["viewer", "operator", "reviewer"])
def test_sensitive_reads_need_separate_grant(identities, suffix, identity):
    client, _, _ = identities
    assert client.get("/api/sessions/s1/" + suffix, headers=bearer(identity)).status_code == 403


def test_viewer_only_gets_sanitized_report_and_findings(identities, report):
    client, namespace, _ = identities
    namespace["orchestrator"].get_session = lambda sid: True
    namespace["orchestrator"].get_vulnerabilities = lambda sid: report["vulnerabilities"]
    for path in ("/api/sessions/s1", "/api/sessions/s1/report.json", "/api/sessions/s1/report.sarif", "/api/sessions/s1/vulnerabilities"):
        response = client.get(path, headers=bearer("viewer"))
        assert response.status_code == 200
        assert "captured-password" not in response.text
        assert "private-output" not in response.text
        assert "command-secret" not in response.text
    assert client.get("/api/sessions/s1", headers=bearer("ops")).json() == report


@pytest.mark.parametrize("path", ["/api/sessions/foreign", "/api/sessions/foreign/report.json", "/api/sessions/foreign/telemetry/summary"])
def test_foreign_session_is_denied_before_lookup(identities, path):
    client, namespace, _ = identities
    namespace["orchestrator"].get_session_report = lambda sid: pytest.fail("Foreign session was accessed")
    assert client.get(path, headers=bearer("ops")).status_code == 403


@pytest.mark.parametrize("payload", [{"session_id": "foreign"}, {"nested": {"source_session_id": "foreign"}},
    {"nested": [{"destination_session_id": "foreign"}]}, {"session_ids": ["s1", "foreign"]}])
def test_nested_body_references_cannot_cross_sessions(identities, payload):
    client, _, _ = identities
    assert client.post("/api/sessions/s1/waivers", json=payload, headers=bearer("review")).status_code == 403


def test_query_and_conflicting_path_references(identities):
    client, _, _ = identities
    assert client.get("/api/sessions/s1/report.json?session_id=foreign", headers=bearer("ops")).status_code == 403
    assert client.get("/api/sessions/s1/report.json?session_id=s1&session_id=foreign", headers=bearer("ops")).status_code == 403
    assert client.post("/api/execute", json={"session_id": "foreign", "command": "id"}, headers=bearer("ops")).status_code == 403
    assert client.post("/api/approve", json={"session_id": "foreign", "command_id": "c"}, headers=bearer("review")).status_code == 403


@pytest.mark.parametrize("identity", ["viewer", "operator", "ops", "reviewer", "review"])
@pytest.mark.parametrize("method,path", [("GET", "/api/settings/features"), ("POST", "/api/settings/security"),
    ("DELETE", "/api/sessions"), ("GET", "/api/schedules"), ("GET", "/api/threat-intel"), ("GET", "/api/ollama/models")])
def test_global_administration_is_admin_only(identities, identity, method, path):
    client, _, _ = identities
    assert client.request(method, path, headers=bearer(identity)).status_code == 403


def test_role_separation_execute_approve_and_attributed_audit(identities):
    client, namespace, _ = identities
    instance = namespace["orchestrator"]
    instance.validate_command = lambda *args, **kwargs: None
    instance.requires_approval = lambda command: False
    instance.execute_command = AsyncMock(return_value={"output": "private-output"})
    instance.approve_command = lambda **kwargs: {"output": "private-output"}
    command = {"session_id": "s1", "command": "id"}
    approval = {"session_id": "s1", "command_id": "command1"}
    for identity in ("viewer", "reviewer", "review"):
        assert client.post("/api/execute", json=command, headers=bearer(identity)).status_code == 403
    response = client.post("/api/execute", json=command, headers=bearer("operator"))
    assert response.status_code == 200
    assert "private-output" not in response.text
    assert client.post("/api/execute", json=command, headers=bearer("ops")).status_code == 200
    for identity in ("viewer", "operator", "ops"):
        assert client.post("/api/approve", json=approval, headers=bearer(identity)).status_code == 403
    response = client.post("/api/approve", json=approval, headers=bearer("reviewer"))
    assert response.status_code == 200
    assert "private-output" not in response.text
    with sqlite3.connect(namespace["access_control"].store.path) as connection:
        assert connection.execute("SELECT principal_id,session_id FROM access_audit WHERE action='POST /api/approve'").fetchall() == [("reviewer", "s1")]


def test_audit_failure_blocks_dispatch_and_acl_failure_fails_closed(identities, monkeypatch):
    client, namespace, _ = identities
    store = namespace["access_control"].store
    execute = AsyncMock()
    namespace["orchestrator"].execute_command = execute

    def unavailable(*args):
        raise sqlite3.OperationalError("private-storage-path")
    monkeypatch.setattr(store, "audit", unavailable)
    response = client.post("/api/execute", json={"session_id": "s1", "command": "id"}, headers=bearer("ops"))
    assert response.status_code == 503
    assert "private-storage-path" not in response.text
    execute.assert_not_called()
    monkeypatch.setattr(store, "owns", unavailable)
    assert client.get("/api/sessions/foreign/report.json", headers=bearer("ops")).status_code == 503


def test_session_create_assigns_persistent_owner_before_running(identities):
    client, namespace, _ = identities
    instance, control = namespace["orchestrator"], namespace["access_control"]
    instance.create_session = lambda **kwargs: "new-private-session"

    async def recon(sid):
        assert control.can_access(Principal("operator", "operator"), sid)
    instance.start_reconnaissance = recon
    payload = {"ip": "192.0.2.1", "authorization_confirmed": True}
    assert client.post("/api/start", json=payload, headers=bearer("viewer")).status_code == 403
    response = client.post("/api/start", json=payload, headers=bearer("operator"))
    assert response.status_code == 200
    assert client.get("/api/sessions/new-private-session/report.json", headers=bearer("operator")).status_code == 200
    assert client.get("/api/sessions/new-private-session/report.json", headers=bearer("outsider")).status_code == 403


def test_lists_stats_and_global_findings_are_scoped_and_sanitized(identities, report):
    client, namespace, _ = identities
    instance = namespace["orchestrator"]
    rows = [{"session_id": "s1", "password": "private-list"}, {"session_id": "hidden", "password": "foreign-secret"}]
    instance.get_sessions = lambda: rows
    instance.get_session_history = lambda: rows
    original = instance.get_session_report
    instance.get_session_report = lambda sid: original(sid) if sid == "s1" else pytest.fail("Unscoped report accessed")
    for path in ("/api/sessions", "/api/sessions/history", "/api/stats", "/api/vulnerabilities"):
        response = client.get(path, headers=bearer("viewer"))
        assert response.status_code == 200
        for secret in ("hidden", "foreign-secret", "private-list", "captured-password", "command-secret"):
            assert secret not in response.text
    assert client.get("/api/sessions", headers=bearer("outsider")).json() == {"sessions": [], "count": 0}
    assert client.get("/api/stats", headers=bearer("outsider")).json()["sessions_total"] == 0


def test_verification_is_reviewer_only_and_cannot_spoof_reviewer(identities, review):
    client, payload, calls = review
    path = "/api/sessions/s1/vulnerabilities/42/verification"
    for identity in ("viewer", "operator", "ops"):
        assert client.post(path, json=payload, headers=bearer(identity)).status_code == 403
    assert client.post(path, json={**payload, "reviewer": "admin"}, headers=bearer("review")).status_code == 400
    assert client.post(path, json=payload, headers=bearer("review")).status_code == 200
    assert calls[-1][2]["reviewer"] == "review"
    assert calls[-1][2]["provenance"] == {"type": "review_only", "source": "operator_review"}


def test_websocket_auth_and_session_action_policy(identities):
    from starlette.websockets import WebSocketDisconnect
    client, _, _ = identities
    for path in ("/api/ws", "/api/ws?token=test-api-key", "/api/ws?token=viewer-token"):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(path):
                pytest.fail("Unauthenticated socket accepted")
    with client.websocket_connect("/api/ws", headers=bearer("viewer")) as socket:
        socket.send_json({"action": "get_session", "session_id": "s1"})
        response = socket.receive_json()
        assert response["data"]["schema_version"] == "1.0"
        assert "captured-password" not in json.dumps(response)
        for action in ("get_session", "execute", "approve", "all_sessions"):
            socket.send_json({"action": action, "session_id": "foreign"})
            assert socket.receive_json()["status"] == 403
        socket.send_json({"action": "ping", "nested": {"session_id": "foreign"}})
        assert socket.receive_json()["status"] == 403


def test_websocket_broadcasts_never_leak_global_or_foreign_events(identities):
    client, namespace, _ = identities
    with client.websocket_connect("/api/ws", headers=bearer("ops")) as ops:
        with client.websocket_connect("/api/ws", headers=bearer("viewer")) as viewer:
            client.portal.call(namespace["broadcast_message"], "event", {"session_id": "foreign", "output": "foreign-secret"})
            client.portal.call(namespace["broadcast_message"], "event", {"output": "global-secret"})
            client.portal.call(namespace["broadcast_message"], "event", {"session_id": "s1", "output": "owned-output"})
            assert ops.receive_json()["data"]["output"] == "owned-output"
            viewer.send_json({"action": "ping"})
            assert viewer.receive_json() == {"type": "pong"}
            ops.send_json({"action": "ping"})
            assert ops.receive_json() == {"type": "pong"}


def test_websocket_revokes_tokens_and_checks_duplicate_query_references(identities):
    from starlette.websockets import WebSocketDisconnect
    client, namespace, path = identities
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/ws?session_id=foreign&session_id=s1", headers=bearer("ops")):
            pytest.fail("Foreign duplicate query reference was ignored")
    with client.websocket_connect("/api/ws", headers=bearer("ops")) as socket:
        document = json.loads(path.read_text())
        document["principals"] = [record for record in document["principals"] if record["id"] != "ops"]
        path.write_text(json.dumps(document))
        client.portal.call(namespace["broadcast_message"], "event", {"session_id": "s1", "output": "must-not-arrive"})
        with pytest.raises(WebSocketDisconnect):
            socket.receive_json()


def test_configuration_preflight_uses_real_offline_evaluator(identities, monkeypatch):
    client, namespace, _ = identities
    # Readiness is config-only; even a usable connector must not be invoked.
    connector = SimpleNamespace(provider="openai", api_key="private-provider-key", ask_raw_async=AsyncMock())
    namespace["ai_connector"] = connector
    monkeypatch.setenv("KMN_EXECUTION_BACKEND", "local")
    response = client.post("/api/preflight", json={"target": "192.0.2.1", "authorization_confirmed": True}, headers=bearer("operator"))
    assert response.status_code == 200
    assert response.json()["provider"]["ready"] is True
    assert "private-provider-key" not in response.text
    connector.ask_raw_async.assert_not_called()


def test_runtime_routes_use_real_persisted_methods_and_attributed_waiver(persisted_api, identities):
    client, namespace, instance, sid = persisted_api
    _, _, path = identities
    document = json.loads(path.read_text())
    for record in document["principals"]:
        if record["id"] in {"ops", "review"}:
            record["sessions"].append(sid)
    path.write_text(json.dumps(document))
    prefix = f"/api/sessions/{sid}"
    payload = {"document": {"openapi": "3.0.3", "paths": {"/users": {"get": {}}}}, "base_url": "https://example.com"}
    imported = client.post(prefix + "/assessment/import", json=payload, headers=bearer("ops"))
    assert imported.status_code == 200
    row = imported.json()["snapshot"]["coverage"][0]
    for suffix, expected in (("completeness", instance.get_session_completeness(sid)), ("preflight", instance.get_session_preflight(sid))):
        response = client.get(prefix + "/" + suffix, headers=bearer("ops"))
        assert response.status_code == 200
        assert response.json() == expected
    assert client.get(prefix + "/operations", headers=bearer("ops")).json()["operations"] == instance.get_session_operations(sid)
    waiver = {key: row[key] for key in ("endpoint_id", "role", "category")}
    waiver["reason"] = "Explicitly excluded by engagement review"
    assert client.post(prefix + "/waivers", json=waiver, headers=bearer("ops")).status_code == 403
    assert client.post(prefix + "/waivers", json={**waiver, "reviewer": "spoof"}, headers=bearer("review")).status_code == 400
    assert client.post(prefix + "/waivers", json=waiver, headers=bearer("review")).status_code == 200
    with sqlite3.connect(instance.db_path) as connection:
        stored = json.loads(connection.execute("SELECT waiver_json FROM completeness_waivers WHERE session_id=?", (sid,)).fetchone()[0])
    assert stored["reviewer"] == "review"


def test_telemetry_metadata_is_session_scoped(scoped_api, tmp_path, monkeypatch):
    from core.model_telemetry import ModelTelemetryStore
    client, _, instance, sid = scoped_api
    path = tmp_path / "telemetry.sqlite3"
    monkeypatch.setenv("KMN_MODEL_TELEMETRY_DB", str(path))
    store = ModelTelemetryStore(path)
    instance.ai_connector.telemetry_store = store
    # A different environment path must not override the connector's actual store.
    monkeypatch.setenv("KMN_MODEL_TELEMETRY_DB", str(tmp_path / "not-the-ledger.sqlite3"))
    for session in (sid, "foreign"):
        event = store.reserve(session_id=session, purpose="tactical", operation_id="op-" + session, retry_ordinal=0,
                              provider="local", model="model-" + session, estimated_input_tokens=10, max_tokens=20)
        store.finish(event, latency_ms=1, result={"prompt_eval_count": 3, "eval_count": 4})
    response = client.get(f"/api/sessions/{sid}/telemetry/summary", headers=bearer("viewer"))
    assert response.json()["summary"] == store.summary(sid)
    response = client.get(f"/api/sessions/{sid}/telemetry/events", headers=bearer("ops"))
    assert response.json()["events"] == store.events(sid)
    assert "model-foreign" not in response.text
    assert client.get(f"/api/sessions/{sid}/telemetry/events?limit=10001", headers=bearer("ops")).status_code == 400


def test_real_source_inventory_and_analysis_only_handoffs(identities, persisted_api):
    client, namespace, path = identities
    _, _, instance, sid = persisted_api
    document = json.loads(path.read_text())
    for record in document["principals"]:
        if record["id"] == "ops":
            record["sessions"].append(sid)
    path.write_text(json.dumps(document))
    connector = SimpleNamespace(ask_raw_async=AsyncMock(return_value={"hypotheses": ["Review routing"],
        "missing_evidence": ["Independent runtime evidence"], "citations": ["source:repo"], "uncertainty": 0.8}))
    namespace["ai_connector"] = connector
    document = {"version": 1, "source_id": "repo", "revision": "r1", "digest": "a" * 64,
                "base_url": "https://192.0.2.1", "operations": [{"method": "GET", "path": "/users",
                "locations": [{"file": "app.py", "line": 1}]}]}
    prefix = f"/api/sessions/{sid}"
    response = client.post(prefix + "/sources/import", json={"kind": "manifest", "document": document}, headers=bearer("ops"))
    assert response.status_code == 200
    assert response.json()["source"]["trust"] == "untrusted"
    assert client.get(prefix + "/sources", headers=bearer("ops")).json()["count"] == 1
    request = {"role": "source", "question": "Review authorization assumptions", "references": [{"ref": "source:repo", "summary": "Routing metadata"}]}
    response = client.post(prefix + "/handoffs", json=request, headers=bearer("ops"))
    assert response.status_code == 200, response.text
    assert response.json()["result"]["verified"] is False
    records = client.get(prefix + "/handoffs", headers=bearer("ops")).json()["handoffs"]
    assert len(records) == 1
    assert "Review routing" not in json.dumps(records)
    for foreign in ("source:foreign", "finding:foreign", "evidence:foreign"):
        request["references"][0]["ref"] = foreign
        assert client.post(prefix + "/handoffs", json=request, headers=bearer("ops")).status_code == 400
    assert client.get("/api/sessions/foreign/handoffs", headers=bearer("ops")).status_code == 403
    assert connector.ask_raw_async.await_count == 1


def test_assessment_uses_frozen_scope_for_import_cached_and_loaded_updates(scoped_api, monkeypatch):
    client, namespace, instance, sid = scoped_api
    prefix = f"/api/sessions/{sid}/assessment"
    payload = {"document": {"openapi": "3.0.3", "paths": {"/users": {"get": {}}}}, "base_url": "https://192.0.2.10"}
    monkeypatch.setenv("SCOPE_ALLOWLIST", "198.51.100.0/24")
    response = client.post(prefix + "/import", json=payload, headers=bearer("ops"))
    assert response.status_code == 200, response.text
    row = response.json()["snapshot"]["coverage"][0]
    update = {key: row[key] for key in ("endpoint_id", "role", "category")}
    for cached in (True, False):
        if not cached:
            namespace["_assessment_cache"].clear()
            instance.sessions.clear()
        assert client.get(prefix, headers=bearer("ops")).status_code == 200
        assert client.patch(prefix + "/coverage", json={**update, "status": "attempted"}, headers=bearer("ops")).status_code == 200
    monkeypatch.setenv("SCOPE_ALLOWLIST", "")
    other = instance.create_session("192.0.2.11", authorization_confirmed=True)
    # Persist the actual frozen scope on creation, not an HTTP/report double.
    assert instance.get_session_report(sid)["session"]["scope_allowlist"] == "192.0.2.0/24"
    assert client.post(f"/api/sessions/{other}/assessment/import", json={**payload, "base_url": "https://198.51.100.1"}, headers=bearer("admin")).status_code == 200
    path = Path(namespace["os"].environ["KMN_ASSESSMENT_DIR"]) / (hashlib.sha256(sid.encode()).hexdigest() + ".json")
    invalid = namespace["Assessment"].from_openapi(payload["document"], base_url="https://198.51.100.1", allowlist="")
    invalid.save(path)
    for cached in (True, False):
        namespace["_assessment_cache"].clear()
        if cached:
            namespace["_assessment_cache"][path] = invalid
        before = path.read_bytes()
        assert client.get(prefix, headers=bearer("ops")).status_code == 400
        assert client.patch(prefix + "/coverage", json={**update, "status": "attempted"}, headers=bearer("ops")).status_code == 400
        assert path.read_bytes() == before


def test_out_of_frozen_scope_import_is_rejected_even_when_global_scope_broadens(scoped_api, monkeypatch):
    client, _, _, sid = scoped_api
    monkeypatch.setenv("SCOPE_ALLOWLIST", "")
    payload = {"document": {"openapi": "3.0.3", "paths": {"/users": {"get": {}}}}, "base_url": "https://198.51.100.1"}
    assert client.post(f"/api/sessions/{sid}/assessment/import", json=payload, headers=bearer("ops")).status_code == 400


@pytest.mark.parametrize("reference_kind", ["invented", "foreign_evidence", "memory_only", "foreign_artifact", "missing_bytes", "owned_evidence", "owned_artifact"])
def test_verified_coverage_requires_real_owned_durable_evidence(scoped_api, reference_kind):
    client, namespace, instance, sid = scoped_api
    other = instance.create_session("192.0.2.20", authorization_confirmed=True)
    prefix = f"/api/sessions/{sid}/assessment"
    payload = {"document": {"openapi": "3.0.3", "paths": {"/users": {"get": {}}}}, "base_url": "https://192.0.2.10"}
    response = client.post(prefix + "/import", json=payload, headers=bearer("ops"))
    assert response.status_code == 200
    update = {key: response.json()["snapshot"]["coverage"][0][key] for key in ("endpoint_id", "role", "category")}
    assert client.patch(prefix + "/coverage", json={**update, "status": "attempted"}, headers=bearer("ops")).status_code == 200
    reference = "evidence:invented"
    if reference_kind in {"foreign_evidence", "owned_evidence"}:
        owner = other if reference_kind == "foreign_evidence" else sid
        instance.add_evidence(owner, "manual_observation", {"id": "retained-observation", "result": "observed"})
        reference = "evidence:retained-observation"
    elif reference_kind == "memory_only":
        instance.sessions[sid].evidence.append({"evidence_id": "uncommitted", "data": {"id": "uncommitted"}})
        reference = "evidence:uncommitted"
    elif reference_kind in {"foreign_artifact", "owned_artifact", "missing_bytes"}:
        store = instance._get_artifact_store()
        owner = other if reference_kind == "foreign_artifact" else sid
        capture = store.capture(instance._artifact_session_id(owner), "coverage-check", "stdout")
        capture.write(b"retained runtime observation")
        manifest = capture.finalize()
        reference = "evidence:" + manifest["id"]
        if reference_kind == "missing_bytes":
            store.purge_session(instance._artifact_session_id(sid))
    patch = {**update, "status": "verified", "evidence_ref": reference}
    assert client.patch(prefix + "/coverage", json=patch, headers=bearer("ops")).status_code == 403
    snapshot_path = Path(namespace["os"].environ["KMN_ASSESSMENT_DIR"]) / (hashlib.sha256(sid.encode()).hexdigest() + ".json")
    before = snapshot_path.read_bytes()
    response = client.patch(prefix + "/coverage", json=patch, headers=bearer("review"))
    expected = 200 if reference_kind in {"owned_evidence", "owned_artifact"} else 400
    assert response.status_code == expected, response.text
    if expected == 400:
        assert snapshot_path.read_bytes() == before
        assert client.get(prefix, headers=bearer("ops")).json()["snapshot"]["coverage"][0]["status"] == "attempted"
    else:
        namespace["_assessment_cache"].clear()
        assert client.get(prefix, headers=bearer("review")).json()["snapshot"]["coverage"][0]["status"] == "verified"


def test_safe_completeness_and_preflight_exclude_waiver_and_error_text(scoped_api, monkeypatch):
    client, _, instance, sid = scoped_api
    prefix = f"/api/sessions/{sid}"
    payload = {"document": {"openapi": "3.0.3", "paths": {"/users": {"get": {}}}}, "base_url": "https://192.0.2.10"}
    imported = client.post(prefix + "/assessment/import", json=payload, headers=bearer("ops"))
    row = imported.json()["snapshot"]["coverage"][0]
    waiver = {key: row[key] for key in ("endpoint_id", "role", "category")}
    waiver["reason"] = "private-waiver-text"
    assert client.post(prefix + "/waivers", json=waiver, headers=bearer("reviewer")).status_code == 200
    monkeypatch.setenv("KMN_EXECUTION_BACKEND", "private-backend-error")
    for identity in ("viewer", "operator", "reviewer"):
        response = client.get(prefix + "/completeness", headers=bearer(identity))
        assert response.status_code == 200
        assert response.json()["verdict"] == "complete"
        assert response.json()["waived_checks_count"] == 1
        assert response.json()["waived_checks"] == [{key: row[key] for key in ("endpoint_id", "role", "category")}]
        assert "private-waiver-text" not in response.text
        assert "reviewer" not in response.text
        response = client.get(prefix + "/preflight", headers=bearer(identity))
        assert response.status_code == 200
        assert "private-backend-error" not in response.text
        assert all("detail" not in check for check in response.json()["checks"])
    assert "private-waiver-text" in client.get(prefix + "/completeness", headers=bearer("review")).text
    assert instance.get_session_completeness(sid)["waived_checks"][0]["reviewer"] == "reviewer"


def test_runtime_verification_uses_real_durable_attempt_and_server_provenance(scoped_api):
    client, _, instance, sid = scoped_api
    finding = instance.add_vulnerability(sid, {"name": "Runtime observation", "host": "192.0.2.10", "port": 443,
        "target": "https://192.0.2.10/users", "risk_level": "high", "source_tool": "manual"})
    store = instance._get_artifact_store()
    capture = store.capture(instance._artifact_session_id(sid), "attempt-real", "stdout")
    capture.write(b"retained protocol evidence")
    manifest = capture.finalize()
    instance._save_command_result(sid, "command-real", "observation", "retained result", "", 0,
                                  metadata={"attempt_id": "attempt-real", "artifacts": [manifest]})
    path = f"/api/sessions/{sid}/vulnerabilities/{finding['finding_id']}/verification"
    payload = {"acknowledge_review": True, "result": "positive", "method": "manual protocol review",
               "artifact_refs": [manifest["id"]], "command_id": "command-real", "attempt_id": "attempt-real"}
    invalid = [{**payload, "attempt_id": "invented"}, {**payload, "command_id": "invented"},
               {key: value for key, value in payload.items() if key != "attempt_id"},
               {key: value for key, value in payload.items() if key != "command_id"},
               {**payload, "provenance": {"type": "runtime", "source": "command_result"}},
               {**payload, "reviewer": "spoofed-admin"}]
    for forged in invalid:
        assert client.post(path, json=forged, headers=bearer("review")).status_code == 400
    assert client.post(path, json=payload, headers=bearer("ops")).status_code == 403
    response = client.post(path, json=payload, headers=bearer("review"))
    assert response.status_code == 200, response.text
    evidence = response.json()["evidence"][-1]
    assert evidence["reviewer"] == "review"
    assert evidence["command_id"] == "command-real" and evidence["attempt_id"] == "attempt-real"
    assert evidence["provenance"] == {"type": "runtime", "source": "command_result"}
    instance.sessions.clear()
    assert instance.get_session_report(sid)["vulnerabilities"][0]["evidence"][-1] == evidence


@pytest.mark.parametrize("queued", [True, False])
def test_deletion_cancels_owned_handoffs_and_purges_specialist_records(scoped_api, queued):
    client, namespace, instance, sid = scoped_api
    started, cancelled = threading.Event(), threading.Event()

    async def blocked_connector(*args):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
    connector = SimpleNamespace(ask_raw_async=AsyncMock(side_effect=blocked_connector))
    namespace["ai_connector"] = connector
    if queued:
        client.portal.call(namespace["_specialist_slots"].acquire)

    async def wait_for_owner():
        for _ in range(200):
            if instance._background_tasks.get(sid):
                return
            await asyncio.sleep(0.01)
        raise AssertionError("HTTP handoff was not registered as session-owned work")

    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(client.post, f"/api/sessions/{sid}/handoffs", json={"role": "api", "question": "Review assumptions"}, headers=bearer("ops"))
        try:
            client.portal.call(wait_for_owner)
            if not queued:
                assert started.wait(3)
            response = client.delete(f"/api/sessions/{sid}", headers=bearer("admin"))
            assert response.status_code == 200, response.text
            assert pending.result(timeout=3).status_code == 409
        finally:
            if queued:
                client.portal.call(namespace["_specialist_slots"].release)
    assert connector.ask_raw_async.await_count == (0 if queued else 1)
    assert queued or cancelled.is_set()
    assert not instance._background_tasks.get(sid)
    with sqlite3.connect(namespace["access_control"].store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM specialist_handoffs WHERE session_id=?", (sid,)).fetchone()[0] == 0
    assert client.post(f"/api/sessions/{sid}/handoffs", json={"role": "api", "question": "After deletion"}, headers=bearer("ops")).status_code == 404


@pytest.mark.parametrize("phase", ["queued", "committing"])
def test_source_import_cannot_survive_session_deletion(scoped_api, monkeypatch, phase):
    client, namespace, instance, sid = scoped_api
    started, release = threading.Event(), threading.Event()
    original_lock = namespace["_assessment_lock"]
    store = namespace["access_control"].store
    original_put = store.put_source

    class BarrierLock:
        def __enter__(self):
            if phase == "queued" and not threading.current_thread() is threading.main_thread():
                started.set()
            return original_lock.__enter__()

        def __exit__(self, *args):
            return original_lock.__exit__(*args)

    def blocked_put(*args):
        started.set()
        assert release.wait(5)
        original_put(*args)

    namespace["_assessment_lock"] = BarrierLock()
    if phase == "queued":
        original_lock.acquire()
    else:
        monkeypatch.setattr(store, "put_source", blocked_put)
    document = {"version": 1, "source_id": "repo", "revision": "r1", "digest": "a" * 64,
                "base_url": "https://192.0.2.10", "operations": [{"method": "GET", "path": "/users",
                "locations": [{"file": "app.py", "line": 1}]}]}

    async def wait_for_invalidation():
        for _ in range(200):
            if instance._stale_execution(sid, 0):
                return
            await asyncio.sleep(0.01)
        raise AssertionError("Deletion did not invalidate the source task")

    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = executor.submit(client.post, f"/api/sessions/{sid}/sources/import", json={"kind": "manifest", "document": document}, headers=bearer("ops"))
        deletion = None
        try:
            assert started.wait(3)
            assert instance._background_tasks.get(sid)
            deletion = executor.submit(client.delete, f"/api/sessions/{sid}", headers=bearer("admin"))
            client.portal.call(wait_for_invalidation)
            assert not deletion.done(), "Deletion must wait for its noncancellable worker"
        finally:
            if phase == "queued":
                original_lock.release()
            release.set()
        assert pending.result(timeout=5).status_code == 409
        response = deletion.result(timeout=5)
        assert response.status_code == 200, response.text
    assert store.sources(sid) == []
    assert not instance._background_tasks.get(sid)
    assert client.get(f"/api/sessions/{sid}/sources", headers=bearer("ops")).status_code == 404


@pytest.mark.parametrize("bulk", [False, True])
def test_http_deletion_purges_actual_connector_ledger_sources_and_specialists(scoped_api, bulk):
    client, namespace, instance, sid = scoped_api
    other = instance.create_session("192.0.2.20", authorization_confirmed=True)
    namespace["ai_connector"] = SimpleNamespace(ask_raw_async=AsyncMock(return_value={
        "hypotheses": [], "missing_evidence": ["Independent evidence required"], "citations": [], "uncertainty": 1}))
    ledger = instance.ai_connector.telemetry_store
    access = namespace["access_control"].store
    for session_id, target in ((sid, "192.0.2.10"), (other, "192.0.2.20")):
        access.own(session_id, Principal("ops", "operator"))
        access.revoke_evidence_refs(session_id, {"source_id": "repo", "revision": "r0", "digest": "0" * 64}, ["evidence:retired"])
        event = ledger.reserve(session_id=session_id, purpose="tactical", operation_id="op-" + session_id,
                               retry_ordinal=0, provider="local", model="offline", estimated_input_tokens=1, max_tokens=2)
        ledger.finish(event, latency_ms=1, result={"prompt_eval_count": 1, "eval_count": 1})
        prefix = f"/api/sessions/{session_id}"
        document = {"version": 1, "source_id": "repo", "revision": "r1", "digest": "a" * 64,
                    "base_url": "https://" + target, "operations": []}
        assert client.post(prefix + "/sources/import", json={"kind": "manifest", "document": document}, headers=bearer("admin")).status_code == 200
        assert client.post(prefix + "/handoffs", json={"role": "api", "question": "Review assumptions"}, headers=bearer("admin")).status_code == 200
        assert client.get(prefix + "/handoffs", headers=bearer("admin")).json()["count"] == 1
    response = client.delete("/api/sessions" if bulk else f"/api/sessions/{sid}", headers=bearer("admin"))
    assert response.status_code == 200, response.text
    for session_id in (sid, other):
        deleted = bulk or session_id == sid
        assert ledger.summary(session_id)["events"] == (0 if deleted else 1)
        assert len(access.sources(session_id)) == (0 if deleted else 1)
        assert access.owns(session_id, Principal("ops", "operator")) == (not deleted)
        with sqlite3.connect(access.path) as connection:
            count = connection.execute("SELECT COUNT(*) FROM specialist_handoffs WHERE session_id=?", (session_id,)).fetchone()[0]
            revoked = connection.execute("SELECT COUNT(*) FROM access_invalidated_evidence WHERE session_id=?", (session_id,)).fetchone()[0]
        assert count == (0 if deleted else 1)
        assert revoked == (0 if deleted else 1)


def test_specialist_purge_failure_retains_session_for_retry(scoped_api, monkeypatch):
    from core.specialists import SpecialistService
    client, namespace, instance, sid = scoped_api
    access = namespace["access_control"].store
    access.own(sid, Principal("ops", "operator"))
    original = SpecialistService.purge_session

    def fail_purge(self):
        raise sqlite3.OperationalError("private-store-error")
    monkeypatch.setattr(SpecialistService, "purge_session", fail_purge)
    response = client.delete(f"/api/sessions/{sid}", headers=bearer("admin"))
    assert response.status_code == 500
    assert "private-store-error" not in response.text
    with sqlite3.connect(instance.db_path) as connection:
        assert connection.execute("SELECT 1 FROM sessions WHERE session_id=?", (sid,)).fetchone()
    assert access.owns(sid, Principal("ops", "operator"))
    monkeypatch.setattr(SpecialistService, "purge_session", original)
    assert client.delete(f"/api/sessions/{sid}", headers=bearer("admin")).status_code == 200


def test_identical_source_reimports_preserve_verified_coverage(source_assessment, monkeypatch):
    client, namespace, instance, sid, manifest = source_assessment
    prefix = f"/api/sessions/{sid}"
    path = Path(namespace["os"].environ["KMN_ASSESSMENT_DIR"]) / (hashlib.sha256(sid.encode()).hexdigest() + ".json")
    before = path.read_bytes()
    # Neither import nor cached/load validation may use the changed global scope.
    monkeypatch.setenv("SCOPE_ALLOWLIST", "198.51.100.0/24")
    for _ in range(2):
        response = client.post(prefix + "/sources/import", json=manifest, headers=bearer("ops"))
        assert response.status_code == 200, response.text
        disposition = response.json()["source"]["revision_disposition"]
        assert disposition["changed"] is False and disposition["coverage_valid"] is True
        assert disposition["invalidated_endpoint_ids"] == []
        assert path.read_bytes() == before
        namespace["_assessment_cache"].clear()
        instance.sessions.clear()
        assert client.get(prefix + "/assessment", headers=bearer("review")).json()["summary"]["counts"]["verified"] == 4
        assert client.get(prefix + "/completeness", headers=bearer("viewer")).json()["verdict"] == "complete"
        assert client.get(prefix + "/report.json", headers=bearer("viewer")).json()["completeness"]["verdict"] == "complete"
    stored = AccessStore(namespace["access_control"].store.path).sources(sid)
    assert stored == [response.json()["source"]]


@pytest.mark.parametrize("change", ["revision", "digest", "metadata", "operations"])
def test_changed_sources_invalidate_old_and_new_endpoint_ids_before_publication(source_assessment, monkeypatch, change):
    client, namespace, instance, sid, manifest = source_assessment
    prefix = f"/api/sessions/{sid}"
    previous = client.get(prefix + "/sources", headers=bearer("ops")).json()["sources"][0]
    current = json.loads(json.dumps(manifest))
    if change == "revision":
        current["document"]["revision"] = "r2"
    elif change == "digest":
        current["document"]["digest"] = "b" * 64
    elif change == "metadata":
        current["document"]["operations"][0]["locations"][0]["line"] = 2
    else:
        current["document"]["operations"][1]["path"] = "/added"
    original_put = namespace["access_control"].store.put_source

    def assert_safe_then_publish(session_id, document):
        assert namespace["_assessment_lock"]._is_owned()
        snapshot = instance._assessment_snapshot(session_id)
        invalidated = set(document["revision_disposition"]["invalidated_endpoint_ids"])
        assert invalidated
        assert all(row["status"] != "verified" and row["evidence_ref"] is None
                   for row in snapshot["coverage"] if row["endpoint_id"] in invalidated)
        original_put(session_id, document)

    monkeypatch.setattr(namespace["access_control"].store, "put_source", assert_safe_then_publish)
    response = client.post(prefix + "/sources/import", json=current, headers=bearer("ops"))
    assert response.status_code == 200, response.text
    source = response.json()["source"]
    expected = {operation["id"] for operation in previous["operations"] + source["operations"]}
    disposition = source["revision_disposition"]
    assert disposition["changed"] is True and disposition["coverage_valid"] is False
    assert disposition["invalidated_endpoint_ids"] == sorted(expected)
    assert disposition["coverage"]["verified"] is False
    assert source["coverage"]["verified"] is False
    namespace["_assessment_cache"].clear()
    instance.sessions.clear()
    snapshot = client.get(prefix + "/assessment", headers=bearer("review")).json()["snapshot"]
    for row in snapshot["coverage"]:
        assert row["status"] == ("pending" if row["endpoint_id"] in expected else "verified")
        if row["endpoint_id"] in expected:
            assert row["attempts"] == 0
    assert client.get(prefix + "/completeness", headers=bearer("viewer")).json()["verdict"] == "incomplete"
    report = client.get(prefix + "/report.json", headers=bearer("viewer")).json()
    assert report["completeness"]["verdict"] == "incomplete"
    assert {row["endpoint_id"] for row in report["completeness"]["missing_checks"]} == expected
    assert report["summary"]["assessment_complete"] is False
    assert AccessStore(namespace["access_control"].store.path).sources(sid) == [source]
    # Stored disposition is not compared as source metadata on subsequent imports.
    monkeypatch.setattr(namespace["access_control"].store, "put_source", original_put)
    response = client.post(prefix + "/sources/import", json=current, headers=bearer("ops"))
    assert response.status_code == 200
    assert response.json()["source"]["revision_disposition"]["changed"] is False
    assert client.get(prefix + "/assessment", headers=bearer("review")).json()["snapshot"] == snapshot


@pytest.mark.parametrize("failure", ["before_invalidation_save", "after_invalidation_save", "source_publish", "after_source_commit"])
def test_source_revision_partial_failures_never_publish_stale_verified_coverage(source_assessment, monkeypatch, failure):
    client, namespace, instance, sid, manifest = source_assessment
    prefix = f"/api/sessions/{sid}"
    current = json.loads(json.dumps(manifest))
    current["document"]["revision"] = "r2"
    original_put = namespace["access_control"].store.put_source
    original_save = namespace["Assessment"].save

    def fail_save(assessment, path):
        if failure == "after_invalidation_save":
            original_save(assessment, path)
        raise OSError("private-invalidation-storage-error")

    def fail_publish(*args):
        if failure == "after_source_commit":
            original_put(*args)
        raise sqlite3.OperationalError("private-source-storage-error")

    if failure in {"before_invalidation_save", "after_invalidation_save"}:
        monkeypatch.setattr(namespace["Assessment"], "save", fail_save)
    else:
        monkeypatch.setattr(namespace["access_control"].store, "put_source", fail_publish)
    response = client.post(prefix + "/sources/import", json=current, headers=bearer("ops"))
    assert response.status_code == 503
    assert "private-" not in response.text
    monkeypatch.setattr(namespace["Assessment"], "save", original_save)
    monkeypatch.setattr(namespace["access_control"].store, "put_source", original_put)
    namespace["_assessment_cache"].clear()
    instance.sessions.clear()
    source = client.get(prefix + "/sources", headers=bearer("ops")).json()["sources"][0]
    snapshot = client.get(prefix + "/assessment", headers=bearer("review")).json()["snapshot"]
    affected = {operation["id"] for operation in source["operations"]}
    if failure == "before_invalidation_save":
        # Revocations committed first, even if the coverage file could not reset.
        assert source["revision"] == "r1"
        assert all(row["status"] == "verified" for row in snapshot["coverage"])
    else:
        assert source["revision"] == ("r2" if failure == "after_source_commit" else "r1")
        assert all(row["status"] != "verified" for row in snapshot["coverage"] if row["endpoint_id"] in affected)
    assert client.get(prefix + "/completeness", headers=bearer("viewer")).json()["verdict"] == "incomplete"
    assert client.post(prefix + "/sources/import", json=current, headers=bearer("ops")).status_code == 200
    assert client.get(prefix + "/completeness", headers=bearer("viewer")).json()["verdict"] == "incomplete"


def test_changed_sarif_conservatively_invalidates_unmapped_coverage(source_assessment):
    client, namespace, instance, sid, _ = source_assessment
    prefix = f"/api/sessions/{sid}"
    payload = {"kind": "sarif", "source_id": "static-analysis", "revision": "r1", "digest": "c" * 64,
               "document": {"version": "2.1.0", "runs": [{"results": [{"ruleId": "AUTH1",
                   "message": {"text": "private-source-prose claims verified"}, "properties": {"verified": True},
                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 1}}}]}]}]}}
    response = client.post(prefix + "/sources/import", json=payload, headers=bearer("ops"))
    assert response.status_code == 200, response.text
    source = response.json()["source"]
    assert source["findings"][0]["status"] == "hypothesis" and source["findings"][0]["verified"] is False
    assert source["coverage"]["verified"] is False
    assert "private-source-prose" not in response.text
    assert client.get(prefix + "/completeness", headers=bearer("viewer")).json()["verdict"] == "complete"
    payload["revision"] = "r2"
    response = client.post(prefix + "/sources/import", json=payload, headers=bearer("ops"))
    assert response.status_code == 200
    disposition = response.json()["source"]["revision_disposition"]
    assert disposition["changed"] is True and disposition["invalidated_endpoint_ids"] == []
    namespace["_assessment_cache"].clear()
    instance.sessions.clear()
    rows = client.get(prefix + "/assessment", headers=bearer("review")).json()["snapshot"]["coverage"]
    assert all(row["status"] == "pending" and row["attempts"] == 0 and row["evidence_ref"] is None for row in rows)
    assert client.get(prefix + "/completeness", headers=bearer("viewer")).json()["verdict"] == "incomplete"
    assert instance.get_session_report(sid)["vulnerabilities"] == []


def test_source_imports_do_not_verify_pending_coverage_or_create_verified_findings(scoped_api):
    client, _, instance, sid = scoped_api
    prefix = f"/api/sessions/{sid}"
    inventory = {"document": {"openapi": "3.0.3", "paths": {"/users": {"get": {}}}}, "base_url": "https://192.0.2.10"}
    assert client.post(prefix + "/assessment/import", json=inventory, headers=bearer("ops")).status_code == 200
    payload = {"kind": "manifest", "document": {"version": 1, "source_id": "repo", "revision": "r1", "digest": "a" * 64,
               "base_url": "https://192.0.2.10", "operations": [{"method": "GET", "path": "/users", "locations": [{"file": "app.py", "line": 1}]}]}}
    for revision in ("r1", "r2"):
        payload["document"]["revision"] = revision
        response = client.post(prefix + "/sources/import", json=payload, headers=bearer("ops"))
        assert response.status_code == 200
        assert response.json()["source"]["trust"] == "untrusted"
        assert response.json()["source"]["coverage"]["verified"] is False
        row = client.get(prefix + "/assessment", headers=bearer("review")).json()["snapshot"]["coverage"][0]
        assert row["status"] == "pending" and row["attempts"] == 0 and row["evidence_ref"] is None
        assert instance.get_session_report(sid)["vulnerabilities"] == []


def test_source_revision_invalidation_cannot_change_another_sessions_matching_ids(source_assessment):
    client, namespace, instance, sid, manifest = source_assessment
    foreign = instance.create_session("192.0.2.10", authorization_confirmed=True)
    prefix = f"/api/sessions/{foreign}/assessment"
    inventory = {"document": {"openapi": "3.0.3", "paths": {"/users": {"get": {}}}}, "base_url": "https://192.0.2.10"}
    imported = client.post(prefix + "/import", json=inventory, headers=bearer("admin"))
    assert client.post(f"/api/sessions/{foreign}/sources/import", json=manifest, headers=bearer("admin")).status_code == 200
    row = imported.json()["snapshot"]["coverage"][0]
    check = {key: row[key] for key in ("endpoint_id", "role", "category")}
    instance.add_evidence(foreign, "source_review", {"id": "foreign-check", "source_id": "repo", "revision": "r1"})
    assert client.patch(prefix + "/coverage", json={**check, "status": "attempted"}, headers=bearer("admin")).status_code == 200
    assert client.patch(prefix + "/coverage", json={**check, "status": "verified", "evidence_ref": "evidence:foreign-check"}, headers=bearer("admin")).status_code == 200
    path = Path(namespace["os"].environ["KMN_ASSESSMENT_DIR"]) / (hashlib.sha256(foreign.encode()).hexdigest() + ".json")
    before = path.read_bytes()
    manifest["document"]["revision"] = "r2"
    assert client.post(f"/api/sessions/{sid}/sources/import", json=manifest, headers=bearer("ops")).status_code == 200
    assert path.read_bytes() == before
    assert client.get(prefix, headers=bearer("admin")).json()["snapshot"]["coverage"][0]["status"] == "verified"
    assert client.get(f"/api/sessions/{foreign}/completeness", headers=bearer("admin")).json()["verdict"] == "complete"
    assert client.get(prefix, headers=bearer("ops")).status_code == 403


def test_scoped_lists_stats_and_pending_commands_exclude_foreign_sessions(scoped_api):
    client, _, instance, sid = scoped_api
    foreign = instance.create_session("192.0.2.99", authorization_confirmed=True)
    for session_id, name in ((sid, "Owned observation"), (foreign, "foreign-finding-secret")):
        instance.add_vulnerability(session_id, {"name": name, "host": "192.0.2.10" if session_id == sid else "192.0.2.99",
            "port": 443, "target": "https://192.0.2.10" if session_id == sid else "https://192.0.2.99", "risk_level": "high"})
        instance.queue_for_approval(session_id, "id" if session_id == sid else "curl http://192.0.2.99/foreign-command-secret")
    for path in ("/api/sessions", "/api/sessions/history", "/api/stats", "/api/vulnerabilities", f"/api/sessions/{sid}/report.json"):
        response = client.get(path, headers=bearer("viewer"))
        assert response.status_code == 200
        for value in (foreign, "192.0.2.99", "foreign-finding-secret", "foreign-command-secret"):
            assert value not in response.text
    assert client.get("/api/stats", headers=bearer("viewer")).json()["sessions_total"] == 1
    assert client.get("/api/vulnerabilities", headers=bearer("viewer")).json()["count"] == 1
    assert client.get(f"/api/sessions/{sid}/report.json", headers=bearer("viewer")).json()["summary"]["pending_approval_count"] == 1
    assert client.get(f"/api/sessions/{sid}/pending_commands", headers=bearer("viewer")).status_code == 403
    response = client.get(f"/api/sessions/{sid}/pending_commands", headers=bearer("ops"))
    assert response.status_code == 200 and response.json()["count"] == 1
    assert "foreign-command-secret" not in response.text
    assert client.get(f"/api/sessions/{foreign}/pending_commands", headers=bearer("ops")).status_code == 403


def test_superseded_refs_stay_revoked_after_restart_and_need_fresh_evidence_and_attempt(source_assessment):
    client, namespace, instance, sid, manifest = source_assessment
    prefix = f"/api/sessions/{sid}"
    before = client.get(prefix + "/assessment", headers=bearer("review")).json()["snapshot"]
    affected_ids = {operation["id"] for operation in namespace["access_control"].store.sources(sid)[0]["operations"]}
    manifest["document"]["revision"] = "r2"
    response = client.post(prefix + "/sources/import", json=manifest, headers=bearer("ops"))
    assert response.status_code == 200, response.text
    reset = client.get(prefix + "/assessment", headers=bearer("review")).json()["snapshot"]
    affected = [row for row in reset["coverage"] if row["endpoint_id"] in affected_ids]
    assert all(row["status"] == "pending" and row["attempts"] == 0 and row["evidence_ref"] is None for row in affected)
    for row in affected:
        check = {key: row[key] for key in ("endpoint_id", "role", "category")}
        assert client.patch(prefix + "/assessment/coverage", json={**check, "status": "verified", "evidence_ref": "evidence:source-check"}, headers=bearer("review")).status_code == 400
    assert "evidence:source-check" not in instance.get_session_committed_evidence_refs(sid)

    # Reopen the actual SQLite stores and a real orchestrator, re-registering the
    # same mandatory integration hook used by production startup.
    reopened = AccessStore(namespace["access_control"].store.path)
    with reopened.connect():
        pass
    namespace["access_control"].store = reopened
    restored = instance.__class__(instance.ai_connector, instance.scanner)
    namespace["orchestrator"] = restored
    restored.register_evidence_reference_filter(namespace["_filter_session_evidence_refs"])
    restored.register_session_purge_hook(namespace["_purge_session_access"])
    namespace["_assessment_cache"].clear()
    assert "evidence:source-check" not in restored.get_session_committed_evidence_refs(sid)
    assert client.get(prefix + "/completeness", headers=bearer("viewer")).json()["verdict"] == "incomplete"

    # Restoring an old assessment cannot restore the authority of its references.
    path = Path(namespace["os"].environ["KMN_ASSESSMENT_DIR"]) / (hashlib.sha256(sid.encode()).hexdigest() + ".json")
    namespace["Assessment"].from_json(before, allowlist="192.0.2.0/24").save(path)
    assert restored.get_session_completeness(sid)["verdict"] == "incomplete"
    assert client.get(prefix + "/report.json", headers=bearer("viewer")).json()["completeness"]["verdict"] == "incomplete"
    namespace["Assessment"].from_json(reset, allowlist="192.0.2.0/24").save(path)
    namespace["_assessment_cache"].clear()
    restored.add_evidence(sid, "source_review", {"id": "current-r2", "source_id": "repo", "revision": "r2", "digest": "a" * 64})
    for row in affected:
        check = {key: row[key] for key in ("endpoint_id", "role", "category")}
        current = {**check, "status": "verified", "evidence_ref": "evidence:current-r2"}
        assert client.patch(prefix + "/assessment/coverage", json=current, headers=bearer("review")).status_code == 400
        assert client.patch(prefix + "/assessment/coverage", json={**check, "status": "attempted"}, headers=bearer("ops")).status_code == 200
        assert client.patch(prefix + "/assessment/coverage", json={**current, "evidence_ref": "evidence:source-check"}, headers=bearer("review")).status_code == 400
        assert client.patch(prefix + "/assessment/coverage", json=current, headers=bearer("review")).status_code == 200
    assert client.get(prefix + "/completeness", headers=bearer("viewer")).json()["verdict"] == "complete"
    with sqlite3.connect(restored.db_path) as connection:
        raw = [json.loads(row[0]) for row in connection.execute("SELECT evidence_data FROM evidence WHERE session_id=?", (sid,))]
    assert any(row.get("id") == "source-check" and row["revision"] == "r1" for row in raw)


def test_revision_revoke_covers_unused_source_review_and_all_durable_aliases(source_assessment):
    client, namespace, instance, sid, manifest = source_assessment
    store = instance._get_artifact_store()
    capture = store.capture(instance._artifact_session_id(sid), "old-source-review", "stdout")
    capture.write(b"retained r1 audit bytes")
    artifact = capture.finalize()
    instance.add_evidence(sid, "source_review", {"id": "unused-r1", "evidence_id": "alias-r1", "source_id": "repo",
        "revision": "r1", "digest": "a" * 64, "artifact_refs": [artifact["id"]]})
    instance.add_evidence(sid, "manual_observation", {"id": "audit-bridge", "artifact_refs": [artifact["id"]]})
    with sqlite3.connect(instance.db_path) as connection:
        rows = connection.execute("SELECT id,evidence_data FROM evidence WHERE session_id=?", (sid,)).fetchall()
    aliases = {"evidence:unused-r1", "evidence:alias-r1", "evidence:audit-bridge", "evidence:" + artifact["id"]}
    aliases.update("evidence:" + str(identity) for identity, encoded in rows if json.loads(encoded).get("id") in {"unused-r1", "audit-bridge"})
    assert aliases <= set(instance.get_session_committed_evidence_refs(sid))
    manifest["document"]["revision"] = "r2"
    assert client.post(f"/api/sessions/{sid}/sources/import", json=manifest, headers=bearer("ops")).status_code == 200
    assert not aliases & set(instance.get_session_committed_evidence_refs(sid))
    revoked, _ = namespace["access_control"].store.evidence_reference_state(sid)
    assert aliases <= revoked
    check = {key: client.get(f"/api/sessions/{sid}/assessment", headers=bearer("review")).json()["snapshot"]["coverage"][0][key]
             for key in ("endpoint_id", "role", "category")}
    assert client.patch(f"/api/sessions/{sid}/assessment/coverage", json={**check, "status": "attempted"}, headers=bearer("ops")).status_code == 200
    for reference in sorted(aliases):
        assert client.patch(f"/api/sessions/{sid}/assessment/coverage", json={**check, "status": "verified", "evidence_ref": reference}, headers=bearer("review")).status_code == 400
    assert store.read(artifact["id"]) == b"retained r1 audit bytes"
    with sqlite3.connect(instance.db_path) as connection:
        assert connection.execute("SELECT id,evidence_data FROM evidence WHERE session_id=?", (sid,)).fetchall() == rows


@pytest.mark.parametrize("field,value", [("source_id", "unknown-source"), ("revision", "r1"), ("digest", "b" * 64)])
def test_new_evidence_must_match_current_source_provenance(source_assessment, field, value):
    client, namespace, instance, sid, manifest = source_assessment
    manifest["document"]["revision"] = "r2"
    prefix = f"/api/sessions/{sid}"
    assert client.post(prefix + "/sources/import", json=manifest, headers=bearer("ops")).status_code == 200
    rows = client.get(prefix + "/assessment", headers=bearer("review")).json()["snapshot"]["coverage"]
    row = next(row for row in rows if row["status"] == "pending")
    check = {key: row[key] for key in ("endpoint_id", "role", "category")}
    assert client.patch(prefix + "/assessment/coverage", json={**check, "status": "attempted"}, headers=bearer("ops")).status_code == 200
    declared = {"source_id": "repo", "revision": "r2", "digest": "a" * 64}
    for nested in (False, True):
        provenance = {**declared, field: value}
        evidence = {"id": "bad-provenance-" + str(nested), **({"provenance": provenance} if nested else provenance)}
        instance.add_evidence(sid, "source_review", evidence)
        reference = "evidence:" + evidence["id"]
        assert reference not in instance.get_session_committed_evidence_refs(sid)
        response = client.patch(prefix + "/assessment/coverage", json={**check, "status": "verified", "evidence_ref": reference}, headers=bearer("review"))
        assert response.status_code == 400
    assert client.get(prefix + "/completeness", headers=bearer("viewer")).json()["verdict"] == "incomplete"


def test_revocation_transaction_failure_cannot_publish_revision_or_partial_tombstones(source_assessment):
    client, namespace, instance, sid, manifest = source_assessment
    store = namespace["access_control"].store
    with sqlite3.connect(store.path) as connection:
        connection.execute("CREATE TRIGGER reject_revocation BEFORE INSERT ON access_invalidated_evidence "
                           "WHEN NEW.reference='evidence:source-check' BEGIN SELECT RAISE(ABORT, 'private-trigger-error'); END")
    manifest["document"]["revision"] = "r2"
    response = client.post(f"/api/sessions/{sid}/sources/import", json=manifest, headers=bearer("ops"))
    assert response.status_code == 503 and "private-trigger-error" not in response.text
    assert store.sources(sid)[0]["revision"] == "r1"
    assert store.evidence_reference_state(sid)[0] == set()
    assert instance.get_session_completeness(sid)["verdict"] == "complete"
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER reject_revocation")
    assert client.post(f"/api/sessions/{sid}/sources/import", json=manifest, headers=bearer("ops")).status_code == 200
    assert "evidence:source-check" not in instance.get_session_committed_evidence_refs(sid)


@pytest.mark.parametrize("failure", ["missing_table", "missing_database", "filter_error"])
def test_missing_revocation_state_and_filter_errors_fail_closed(source_assessment, monkeypatch, failure):
    client, namespace, instance, sid, _ = source_assessment
    store = namespace["access_control"].store
    row = client.get(f"/api/sessions/{sid}/assessment", headers=bearer("review")).json()["snapshot"]["coverage"][0]
    if failure == "missing_table":
        with sqlite3.connect(store.path) as connection:
            connection.execute("DROP TABLE access_invalidated_evidence")
    elif failure == "missing_database":
        Path(store.path).unlink()
    else:
        def fail_filter(*args):
            raise RuntimeError("private-reference-store-error")
        monkeypatch.setattr(store, "evidence_reference_state", fail_filter)
    assert instance.get_session_completeness(sid)["verdict"] == "unknown"
    response = client.get(f"/api/sessions/{sid}/completeness", headers=bearer("viewer"))
    assert response.status_code == 200 and response.json()["verdict"] == "unknown"
    assert "private-" not in response.text
    check = {key: row[key] for key in ("endpoint_id", "role", "category")}
    response = client.patch(f"/api/sessions/{sid}/assessment/coverage", json={**check, "status": "verified", "evidence_ref": row["evidence_ref"]}, headers=bearer("review"))
    assert response.status_code == 503
    assert "private-" not in response.text


def test_source_change_revokes_affected_reference_without_source_provenance(source_assessment):
    client, namespace, instance, sid, manifest = source_assessment
    prefix = f"/api/sessions/{sid}"
    source_ids = {operation["id"] for operation in namespace["access_control"].store.sources(sid)[0]["operations"]}
    row = next(row for row in instance._assessment_snapshot(sid)["coverage"] if row["endpoint_id"] in source_ids)
    check = {key: row[key] for key in ("endpoint_id", "role", "category")}
    instance.add_evidence(sid, "manual_observation", {"id": "unbound-r1-proof"})
    patch = {**check, "status": "verified", "evidence_ref": "evidence:unbound-r1-proof"}
    assert client.patch(prefix + "/assessment/coverage", json=patch, headers=bearer("review")).status_code == 200
    manifest["document"]["revision"] = "r2"
    assert client.post(prefix + "/sources/import", json=manifest, headers=bearer("ops")).status_code == 200
    assert "evidence:unbound-r1-proof" in namespace["access_control"].store.evidence_reference_state(sid)[0]
    assert "evidence:unbound-r1-proof" not in instance.get_session_committed_evidence_refs(sid)
    assert client.patch(prefix + "/assessment/coverage", json={**check, "status": "attempted"}, headers=bearer("ops")).status_code == 200
    assert client.patch(prefix + "/assessment/coverage", json=patch, headers=bearer("review")).status_code == 400


def test_source_change_revokes_explicit_old_review_without_assessment(scoped_api):
    client, namespace, instance, sid = scoped_api
    payload = {"kind": "manifest", "document": {"version": 1, "source_id": "repo", "revision": "r1", "digest": "a" * 64,
               "base_url": "https://192.0.2.10", "operations": []}}
    prefix = f"/api/sessions/{sid}"
    assert client.post(prefix + "/sources/import", json=payload, headers=bearer("ops")).status_code == 200
    instance.add_evidence(sid, "source_review", {"id": "unattached-r1", "source_id": "repo", "revision": "r1"})
    assert "evidence:unattached-r1" in instance.get_session_committed_evidence_refs(sid)
    payload["document"]["revision"] = "r2"
    assert client.post(prefix + "/sources/import", json=payload, headers=bearer("ops")).status_code == 200
    assert "evidence:unattached-r1" in namespace["access_control"].store.evidence_reference_state(sid)[0]
    assert "evidence:unattached-r1" not in instance.get_session_committed_evidence_refs(sid)
    assert client.get(prefix + "/assessment", headers=bearer("review")).status_code == 404

"""Pure export tests and isolated HTTP contracts, without backend startup."""

import ast
import asyncio
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import sys
import tempfile
import threading
import hashlib
import io
import re
import zipfile
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from core.report_export import build_report_snapshot, exceeds_threshold, export_sarif
from core.assessment import Assessment, AssessmentError, CoverageKey, MAX_BYTES
from core.artifact_store import ArtifactStore, ArtifactStoreError


def verification_fields():
    return {"target": "https://example.com/api", "artifacts": [{"id": "a1", "uri": "artifact://a1"}],
            "evidence": [{"id": "e1", "target": "https://example.com/api", "method": "check",
                          "result": "positive", "artifact_refs": ["a1"]}],
            "verification_events": [{"kind": "verification", "target": "https://example.com/api",
                                     "method": "check", "result": "positive", "evidence_refs": ["e1"]}]}


@pytest.fixture
def report():
    return {
        "session": {"session_id": "s1", "status": "completed", "target_ip": "192.0.2.1",
                    "api_token": "session-token", "compromise_evidence": [{"proof": "private-proof"}]},
        "summary": {"pending_approval_count": 0},
        "credentials": [{"username": "admin", "secret": "captured-password"}],
        "commands_executed": [{"command": "curl --password command-secret", "output": "private-output"}],
        "evidence": [{"evidence_id": 7, "data": {"proof": "private-proof"}}],
        "ai_decisions": [{"reasoning": "private-reasoning"}],
        "events": [{"payload": {"api_key": "event-token"}}],
        "jobs": [{"error": "private-job-error"}],
        "vulnerabilities": [
            {"name": "TLS issue", "status": "confirmed", "verification": {"verified": True}, "risk_level": "high",
              "cve_ids": ["CVE-2024-12345"], "source_command": "curl --password command-secret", "evidence_id": 7,
              **verification_fields()},
            {"name": "Version match", "risk_level": "critical", "confidence": 1, "source_tool": "nvd"},
            {"name": "Leak captured-password token=inline-secret Bearer bearer-secret", "status": "potential",
             "risk_level": "high", "description": "private-description", "reference_urls": ["https://u:secret@example.com"]},
        ],
    }


def test_snapshot_is_versioned_deterministic_and_does_not_mutate(report):
    original = copy.deepcopy(report)
    snapshot = build_report_snapshot(report)
    assert snapshot == build_report_snapshot(report)
    assert snapshot["schema_version"] == "1.0"
    assert report == original
    assert snapshot["summary"]["verified_findings"] == 1
    assert snapshot["summary"]["unverified_findings"] == 2
    assert snapshot["findings"][0]["evidence_refs"] == [
        "#/vulnerabilities/0", "#/commands_executed/0", "#/evidence/0",
        "#/vulnerabilities/0/evidence/0", "#/vulnerabilities/0/artifacts/0",
    ]


def test_snapshot_and_sarif_exclude_secrets_and_raw_data(report):
    snapshot = build_report_snapshot(report)
    for document in (snapshot, export_sarif(snapshot)):
        encoded = json.dumps(document)
        for secret in ("session-token", "captured-password", "command-secret", "private-proof",
                       "private-output", "private-reasoning", "event-token", "inline-secret",
                       "bearer-secret", "private-description", "private-job-error", "u:secret"):
            assert secret not in encoded
    assert "[REDACTED]" in snapshot["findings"][2]["name"]


def test_secret_type_metadata_does_not_disable_inline_redaction(report):
    report["credentials"][0]["secret_type"] = "password"
    report["vulnerabilities"][0]["name"] = "password=unknown-inline --token unknown-flag"
    snapshot = build_report_snapshot(report)
    assert "unknown-inline" not in json.dumps(snapshot)
    assert "unknown-flag" not in json.dumps(snapshot)


@pytest.mark.parametrize("status,explicit,expected", [
    ("confirmed", None, False), ("verified", None, False), (None, True, False),
    ("potential", True, False), ("unverified", True, False), ("confirmed", False, False),
    ("exploited", None, False), (None, None, False),
])
def test_explicit_verified_claims_are_not_authority(status, explicit, expected):
    finding = {"name": "Test", "risk_level": "critical", "status": status}
    if explicit is not None:
        finding["verified"] = explicit
    snapshot = build_report_snapshot({"vulnerabilities": [finding]})
    assert exceeds_threshold(snapshot, "high") is expected


def test_evidence_backed_verification_overrides_legacy_status_and_boolean():
    snapshot = build_report_snapshot({"vulnerabilities": [
        {"status": "confirmed", "verified": True, "risk_level": "critical",
         "verification": {"verified": False}},
        {"status": "potential", "risk_level": "high", "verification": {"verified": True},
         **verification_fields()},
    ]})
    assert snapshot["findings"][0]["verification"] == "unverified"
    assert snapshot["findings"][1]["verification"] == "verified"
    assert snapshot["findings"][1]["evidence_refs"] == [
        "#/vulnerabilities/1", "#/vulnerabilities/1/evidence/0", "#/vulnerabilities/1/artifacts/0",
    ]
    assert not exceeds_threshold(snapshot, "critical")
    assert exceeds_threshold(snapshot, "high")
    assert "secret" not in json.dumps(snapshot)


def test_recompute_ignores_cached_verification_and_rejects_broken_links():
    finding = {"risk_level": "critical", "verified": False, "verification": {"verified": False},
               **verification_fields()}
    assert exceeds_threshold(build_report_snapshot({"vulnerabilities": [finding]}), "critical")
    finding["verification"] = {"verified": True}
    finding["evidence"][0]["target"] = "https://wrong.example"
    assert not exceeds_threshold(build_report_snapshot({"vulnerabilities": [finding]}), "info")
    finding["evidence"][0]["target"] = finding["target"]
    finding["verification_events"].append({"kind": "verification", "result": "inconclusive"})
    assert not exceeds_threshold(build_report_snapshot({"vulnerabilities": [finding]}), "info")


@pytest.mark.parametrize("finding_id", [str(uuid.uuid4()), str(uuid.uuid5(uuid.NAMESPACE_URL, "persisted:legacy"))])
def test_snapshot_preserves_persisted_uuid_for_review_and_sarif(finding_id):
    snapshot = build_report_snapshot({"vulnerabilities": [{"finding_id": finding_id}]})
    assert snapshot["findings"][0]["id"] == finding_id
    assert export_sarif(snapshot)["runs"][0]["results"][0]["ruleId"] == finding_id


@pytest.mark.parametrize("finding_id", [None, 42, "password=private-secret", "../arbitrary-path", "finding-999",
    "00000000-0000-0000-0000-000000000000", "12345678-1234-4234-1234-123456789abc",
    "12345678-1234-4234-8234-123456789abc\n"])
def test_snapshot_legacy_ids_are_synthetic_not_untrusted_input(finding_id):
    snapshot = build_report_snapshot({"vulnerabilities": [{"finding_id": finding_id, "id": str(uuid.uuid4())}]})
    assert snapshot["findings"][0]["id"] == "finding-1"
    assert "private-secret" not in json.dumps(snapshot)


def test_threshold_and_sarif_verification(report):
    snapshot = build_report_snapshot(report)
    assert not exceeds_threshold(snapshot, "none")
    assert not exceeds_threshold(snapshot, "critical")
    assert exceeds_threshold(snapshot, "high")
    sarif = export_sarif(snapshot)
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert results[0]["level"] == "error"
    assert results[0]["kind"] == "fail"
    assert results[1]["level"] == "note"
    assert results[1]["kind"] == "review"
    with pytest.raises(ValueError, match="schema version"):
        export_sarif({"schema_version": "future"})


@pytest.fixture
def api(report, monkeypatch, tmp_path):
    """Execute the real route definitions with an injected orchestrator.

    main's module-level initialization writes logs/.env and starts integrations;
    extracting its route definitions keeps these contract tests hermetic.
    """
    # Some existing tests replace httpx globally at collection time. Restore the
    # installed package for TestClient only; monkeypatch restores the stub later.
    if "httpx" in sys.modules and not hasattr(sys.modules["httpx"], "Response"):
        for name in list(sys.modules):
            if name == "httpx" or name.startswith("httpx."):
                monkeypatch.delitem(sys.modules, name)
    fastapi = pytest.importorskip("fastapi")
    from fastapi.responses import FileResponse, JSONResponse, Response
    from fastapi.testclient import TestClient
    from starlette.background import BackgroundTask
    import logging

    app = fastapi.FastAPI()
    monkeypatch.setenv("KMN_ASSESSMENT_DIR", str(tmp_path.resolve() / "assessments"))
    monkeypatch.setenv("KMN_EVIDENCE_DIR", str(tmp_path.resolve() / "evidence"))
    monkeypatch.delenv("KMN_EVIDENCE_KEY", raising=False)
    monkeypatch.delenv("SCOPE_ALLOWLIST", raising=False)
    paths, worker_threads = [], []

    def get_report(session_id):
        if session_id == "missing":
            raise ValueError("not found")
        return copy.deepcopy(report)

    def generate(data, output_path):
        paths.append(output_path)
        worker_threads.append(threading.get_ident())
        Path(output_path).write_bytes(b"generated-document")

    def archive(session_id, output_path):
        get_report(session_id)
        generate(session_id, output_path)
        return output_path

    monkeypatch.setitem(sys.modules, "core.report_generator", SimpleNamespace(
        generate_report=generate, generate_pdf_report=generate, generate_markdown_report=generate,
    ))
    namespace = dict(app=app, asyncio=asyncio, os=os, json=json, tempfile=tempfile, secrets=secrets,
                     Request=fastapi.Request, HTTPException=fastapi.HTTPException,
                     FileResponse=FileResponse, JSONResponse=JSONResponse, Response=Response, BackgroundTask=BackgroundTask,
                     Path=Path, hashlib=hashlib, zipfile=zipfile, re=re, stat=stat,
                     Assessment=Assessment, AssessmentError=AssessmentError, CoverageKey=CoverageKey, MAX_BYTES=MAX_BYTES,
                     ArtifactStore=ArtifactStore, ArtifactStoreError=ArtifactStoreError,
                     _assessment_lock=threading.RLock(), _assessment_cache={},
                      orchestrator=SimpleNamespace(get_session_report=get_report, archive_session=archive,
                         prepare_session_deletion=AsyncMock(return_value={"status": "success"}),
                         db_path=str(tmp_path.resolve() / "sessions.db"),
                         get_session_events=lambda sid: [], get_session_jobs=lambda sid: [],
                         _artifact_session_id=lambda sid: sid if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", sid)
                         else hashlib.sha256(sid.encode()).hexdigest()),
                     build_report_snapshot=build_report_snapshot, export_sarif=export_sarif,
                     API_AUTH_TOKEN="test-api-key", _OPEN_PATHS=set(), logger=logging.getLogger(__name__))
    tree = ast.parse((Path(__file__).parents[1] / "main.py").read_text(encoding="utf-8"))
    names = {"enforce_api_key", "download_session_report_json", "download_session_report_sarif",
             "_temporary_download", "_download_response", "download_session_report", "download_session_report_pdf",
             "download_session_report_md", "download_session_archive", "_metadata_archive",
             "_bounded_json_body", "_assessment_snapshot", "import_session_assessment", "get_session_assessment",
             "update_session_coverage", "_session_artifacts", "get_session_artifacts", "download_artifact_content",
             "record_finding_verification", "_delete_sessions", "delete_session", "delete_all_sessions",
             "get_session_events", "get_session_jobs"}
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    assert len(nodes) == len(names)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "main.py", "exec"), namespace)
    with TestClient(app) as client:
        yield client, namespace, paths, worker_threads


@pytest.fixture
def persisted_api(api, monkeypatch, tmp_path):
    """Real SQLite orchestration and artifact storage, without AI or scanning."""
    pytest.importorskip("dotenv")
    pytest.importorskip("requests")
    from core.orchestrator import Orchestrator

    client, namespace, _, _ = api
    # Importing the connector may load .env; reapply isolated operator paths.
    root = tmp_path.resolve()
    monkeypatch.setenv("DB_PATH", str(root / "persisted.db"))
    monkeypatch.setenv("KMN_ASSESSMENT_DIR", str(root / "operator-assessments"))
    monkeypatch.setenv("KMN_EVIDENCE_DIR", str(root / "operator-evidence"))
    monkeypatch.delenv("KMN_EVIDENCE_KEY", raising=False)
    monkeypatch.delenv("MSFRPC_URL", raising=False)
    monkeypatch.setenv("SCOPE_ALLOWLIST", "")
    instance = Orchestrator(SimpleNamespace(provider="api"), SimpleNamespace(parse_nmap_results=lambda value: []))
    namespace["orchestrator"] = instance
    session_id = instance.create_session("192.0.2.1", session_name="delivery.history", authorization_confirmed=True)
    return client, namespace, instance, session_id


@pytest.mark.parametrize("suffix", ["report.json", "report.sarif", "report", "report/pdf", "report/md", "archive", "events", "jobs"])
def test_report_routes_require_auth_and_return_404(api, suffix):
    client, _, _, _ = api
    assert client.get(f"/api/sessions/s1/{suffix}").status_code == 401
    assert client.get(f"/api/sessions/missing/{suffix}", headers={"X-API-Key": "test-api-key"}).status_code == 404


def test_json_and_sarif_routes_use_snapshot(api, report):
    client, _, _, _ = api
    headers = {"X-API-Key": "test-api-key"}
    response = client.get("/api/sessions/s1/report.json", headers=headers)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == build_report_snapshot(report)
    sarif = client.get("/api/sessions/s1/report.sarif", headers=headers)
    assert sarif.json() == export_sarif(response.json())


@pytest.mark.parametrize("suffix", ["report", "report/pdf", "report/md"])
def test_downloads_are_unique_offloaded_and_cleaned(api, suffix):
    client, namespace, paths, workers = api
    async def loop_thread():
        return threading.get_ident()
    event_thread = client.portal.call(loop_thread)
    for _ in range(2):
        response = client.get(f"/api/sessions/s1/{suffix}", headers={"X-API-Key": "test-api-key"})
        assert response.status_code == 200
        assert response.content == b"generated-document"
    assert paths[0] != paths[1]
    assert all(not Path(path).exists() for path in paths)
    assert all(worker != event_thread for worker in workers)


def test_failed_generation_removes_partial_file(api):
    _, namespace, _, _ = api
    paths = []
    def fail(data, output_path):
        paths.append(output_path)
        Path(output_path).write_text("partial secret", encoding="utf-8")
        raise RuntimeError("failed")
    with pytest.raises(RuntimeError):
        namespace["_temporary_download"](fail, {}, ".md", "text/markdown")
    assert not Path(paths[0]).exists()


@pytest.mark.parametrize("route,generator", [
    ("download_session_report", "generate_report"),
    ("download_session_report_pdf", "generate_pdf_report"),
    ("download_session_report_md", "generate_markdown_report"),
    ("download_session_archive", "_metadata_archive"),
])
@pytest.mark.parametrize("fail", [False, True])
def test_cancelled_download_waits_for_blocked_worker_and_removes_temp_file(api, monkeypatch, route, generator, fail):
    _, namespace, _, _ = api
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    paths = []

    def blocked(data, output_path):
        paths.append(output_path)
        Path(output_path).write_bytes(b"partial-sensitive")
        started.set()
        try:
            assert release.wait(5), "Test did not release report generator"
            if fail:
                raise RuntimeError("private-generation-error")
            Path(output_path).write_bytes(b"completed-sensitive")
        finally:
            finished.set()

    if generator == "_metadata_archive":
        monkeypatch.setitem(namespace, generator, blocked)
    else:
        monkeypatch.setattr(sys.modules["core.report_generator"], generator, blocked)

    async def cancel_route():
        task = asyncio.create_task(namespace[route]("s1"))
        try:
            assert await asyncio.to_thread(started.wait, 3)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done(), "Cancellation must wait for the worker"
            assert Path(paths[0]).exists()
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 3)
        assert finished.is_set()
        assert all(not Path(path).exists() for path in paths)

    asyncio.run(cancel_route())


def test_assessment_import_update_persistence_and_session_isolation(api):
    client, namespace, _, _ = api
    headers = {"X-API-Key": "test-api-key"}
    path = "/api/sessions/historical.named/assessment"
    payload = {"document": {"openapi": "3.0.3", "paths": {"/users": {"get": {}}}},
               "base_url": "https://example.com", "roles": {"reader": "env:READER_TOKEN"},
               "categories": ["authorization"]}
    assert client.post(path + "/import", json=payload).status_code == 401
    assert client.get(path).status_code == 401
    assert client.patch(path + "/coverage", json={}).status_code == 401
    assert client.get(path, headers=headers).status_code == 404
    response = client.post(path + "/import", json=payload, headers=headers)
    assert response.status_code == 200
    row = response.json()["snapshot"]["coverage"][0]
    assert row["status"] == "pending"
    assert response.headers["cache-control"] == "no-store"
    assert client.post(path + "/import", json=payload, headers=headers).status_code == 409
    update = {key: row[key] for key in ("endpoint_id", "role", "category")}
    assert client.patch(path + "/coverage", json={**update, "status": "verified", "evidence_ref": "evidence:check"}, headers=headers).status_code == 400
    assert client.patch(path + "/coverage", json={**update, "status": "attempted"}, headers=headers).status_code == 200
    assert client.get(path, headers=headers).json()["snapshot"]["coverage"][0]["status"] == "attempted"
    assert client.patch(path + "/coverage", json={**update, "status": "verified"}, headers=headers).status_code == 400
    assert client.get(path, headers=headers).json()["snapshot"]["coverage"][0]["status"] == "attempted"
    response = client.patch(path + "/coverage", json={**update, "status": "verified", "evidence_ref": "evidence:check"}, headers=headers)
    assert response.status_code == 200
    assert response.json()["summary"]["counts"]["verified"] == 1
    namespace["_assessment_cache"].clear()
    assert client.get(path, headers=headers).json() == response.json()
    assert client.get("/api/sessions/s1/assessment", headers=headers).status_code == 404
    root = Path(os.environ["KMN_ASSESSMENT_DIR"])
    files = list(root.iterdir())
    assert len(files) == 1 and files[0].name == hashlib.sha256(b"historical.named").hexdigest() + ".json"
    assert files[0].stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("change", [
    {"base_url": None}, {"roles": {"admin": "actual-password"}},
    {"document": {"openapi": "3.0.3", "paths": {}, "components": {"schemas": {"X": {"$ref": "https://example.com/remote"}}}}},
])
def test_assessment_rejects_unsafe_imports(api, change):
    client, _, _, _ = api
    payload = {"document": {"openapi": "3.0.3", "paths": {}}, "base_url": "https://example.com", **change}
    response = client.post("/api/sessions/s1/assessment/import", json=payload, headers={"X-API-Key": "test-api-key"})
    assert response.status_code == 400
    assert "actual-password" not in response.text


def test_assessment_body_limit_and_unknown_session(api):
    client, _, _, _ = api
    headers = {"X-API-Key": "test-api-key"}
    assert client.post("/api/sessions/s1/assessment/import", content=b" " * (MAX_BYTES + 1), headers=headers).status_code == 413
    assert client.get("/api/sessions/missing/assessment", headers=headers).status_code == 404


def test_artifact_sensitive_download_is_scoped_authenticated_and_not_archived(api, monkeypatch):
    client, namespace, _, _ = api
    store = ArtifactStore(os.environ["KMN_EVIDENCE_DIR"])
    capture = store.capture("s1", "attempt1", "stdout")
    capture.write(b"raw-secret-evidence")
    manifest = capture.finalize()
    path = "/api/sessions/s1/artifacts"
    content_path = path + "/" + manifest["id"] + "/content"
    headers = {"X-API-Key": "test-api-key"}
    assert client.get(path).status_code == 401
    assert client.get(content_path + "?acknowledge_sensitive=true").status_code == 401
    listed = client.get(path, headers=headers)
    assert listed.json()["artifacts"] == [manifest]
    assert listed.headers["cache-control"] == "no-store"
    assert "raw-secret" not in listed.text
    assert client.get(content_path, headers=headers).status_code == 400
    response = client.get(content_path + "?acknowledge_sensitive=true", headers=headers)
    assert response.content == b"raw-secret-evidence"
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["cache-control"] == "no-store"
    assert "attachment" in response.headers["content-disposition"]
    assert client.get(content_path.replace("/s1/", "/other/") + "?acknowledge_sensitive=true", headers=headers).status_code == 404
    assert client.get("/api/sessions/missing/artifacts", headers=headers).status_code == 404
    monkeypatch.setattr(ArtifactStore, "read", lambda self, value: pytest.fail("Archive must not read artifacts"))
    response = client.get("/api/sessions/s1/archive", headers=headers)
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert set(archive.namelist()) == {"session.json", "events.json", "jobs.json", "manifest.json"}
        assert json.loads(archive.read("manifest.json"))["raw_artifacts"] == "omitted"
        assert all(b"raw-secret-evidence" not in archive.read(name) for name in archive.namelist())


def test_artifact_default_root_and_encryption_key(api, monkeypatch):
    from cryptography.fernet import Fernet
    client, namespace, _, _ = api
    monkeypatch.delenv("KMN_EVIDENCE_DIR")
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("KMN_EVIDENCE_KEY", key)
    root = Path(namespace["orchestrator"].db_path).parent / "evidence"
    store = ArtifactStore(root, key=key)
    capture = store.capture("s1", "attempt1", "stdout")
    capture.write(b"encrypted-sensitive")
    manifest = capture.finalize()
    headers = {"X-API-Key": "test-api-key"}
    url = f"/api/sessions/s1/artifacts/{manifest['id']}/content?acknowledge_sensitive=true"
    assert client.get(url, headers=headers).content == b"encrypted-sensitive"
    monkeypatch.setenv("KMN_EVIDENCE_KEY", Fernet.generate_key().decode("ascii"))
    response = client.get(url, headers=headers)
    assert response.status_code == 503
    assert "sensitive" not in response.text and str(root) not in response.text


@pytest.fixture
def review(api):
    client, namespace, _, _ = api
    store = ArtifactStore(os.environ["KMN_EVIDENCE_DIR"])
    capture = store.capture("s1", "review1", "stdout")
    capture.write(b"operator-reviewed-private-evidence")
    manifest = capture.finalize()
    calls = []

    def record(session_id, finding_id, payload):
        if finding_id == "missing":
            raise KeyError("private-error")
        if finding_id == "invalid":
            raise ValueError("private-error")
        calls.append((session_id, finding_id, copy.deepcopy(payload)))
        return {"finding_id": finding_id, "verification": {"verified": payload["result"] == "positive"}}

    namespace["orchestrator"].record_verification = record
    payload = {"acknowledge_review": True, "result": "positive", "method": "manual protocol review",
               "artifact_refs": [manifest["id"]], "evidence": "Explicit operator conclusion"}
    return client, payload, calls


@pytest.mark.parametrize("result", ["positive", "negative", "inconclusive"])
def test_verification_requires_auth_and_passes_explicit_review_to_orchestrator(review, result):
    client, payload, calls = review
    payload["result"] = result
    path = "/api/sessions/s1/vulnerabilities/42/verification"
    assert client.post(path, json=payload).status_code == 401
    assert calls == []
    response = client.post(path, json=payload, headers={"X-API-Key": "test-api-key"})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert calls == [("s1", "42", payload)]
    assert response.json()["verification"]["verified"] is (result == "positive")


@pytest.mark.parametrize("change", [
    {"acknowledge_review": False}, {"acknowledge_review": 1}, {"acknowledge_review": None},
    {"verified": True}, {"source_tool": "nmap"}, {"target": "https://wrong.example"},
    {"result": "confirmed"}, {"result": []}, {"method": " "}, {"method": "m" * 201},
    {"method": "review\nforged"}, {"artifact_refs": []}, {"artifact_refs": ["../file"]},
    {"artifact_refs": [["nested"]]}, {"artifact_refs": ["a" * 64 + "." + "b" * 32] * 2},
    {"artifact_refs": ["a" * 64 + "." + "b" * 32] * 33},
    {"evidence": {}}, {"evidence": "e" * 4097}, {"kind": "observation"}, {"kind": []},
    {"result": "applied"}, {"kind": "retest", "result": "applied"},
    {"kind": "remediation", "result": "positive"},
])
def test_verification_rejects_unknown_oversized_or_implicit_fields(review, change):
    client, payload, calls = review
    response = client.post("/api/sessions/s1/vulnerabilities/42/verification", json={**payload, **change},
                           headers={"X-API-Key": "test-api-key"})
    assert response.status_code == 400
    assert calls == []


def test_verification_rejects_missing_fields_foreign_artifacts_and_unknown_records(review):
    client, payload, calls = review
    headers = {"X-API-Key": "test-api-key"}
    path = "/api/sessions/s1/vulnerabilities/42/verification"
    for key in ("acknowledge_review", "result", "method", "artifact_refs"):
        incomplete = {k: v for k, v in payload.items() if k != key}
        assert client.post(path, json=incomplete, headers=headers).status_code == 400
    assert client.post(path.replace("/s1/", "/other/"), json=payload, headers=headers).status_code == 400
    assert client.post(path.replace("/s1/", "/missing/"), json=payload, headers=headers).status_code == 404
    assert client.post(path.replace("/42/", "/missing/"), json=payload, headers=headers).status_code == 404
    invalid = client.post(path.replace("/42/", "/invalid/"), json=payload, headers=headers)
    assert invalid.status_code == 400 and "private-error" not in invalid.text
    assert client.post(path, content=b" " * 16385, headers=headers).status_code == 413
    assert calls == []


def test_archive_legacy_metadata_remains_sensitive(api):
    client, _, _, _ = api
    response = client.get("/api/sessions/s1/archive", headers={"X-API-Key": "test-api-key"})
    assert response.headers["cache-control"] == "no-store"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        # Omitting artifact files never promised to sanitize legacy report data.
        assert b"captured-password" in archive.read("session.json")
        assert b"command-secret" in archive.read("session.json")


@pytest.mark.parametrize("kind,result", [("verification", "positive"), ("remediation", "applied"), ("retest", "negative")])
def test_verification_route_accepts_explicit_lifecycle_kinds(review, kind, result):
    client, payload, calls = review
    payload.update(kind=kind, result=result)
    response = client.post("/api/sessions/s1/vulnerabilities/42/verification", json=payload,
                           headers={"X-API-Key": "test-api-key"})
    assert response.status_code == 200
    assert calls[-1][2] == payload


def test_real_persisted_operator_lifecycle_through_http(persisted_api):
    client, _, instance, session_id = persisted_api
    finding = instance.add_vulnerability(session_id, {
        "name": "Retained protocol observation", "host": "192.0.2.1", "port": 443,
        "target": "https://192.0.2.1/api", "risk_level": "high", "source_tool": "manual",
    })
    finding_id = finding["finding_id"]
    assert str(uuid.UUID(finding_id)) == finding_id
    headers = {"X-API-Key": "test-api-key"}
    prefix = f"/api/sessions/{session_id}"
    snapshot = client.get(prefix + "/report.json", headers=headers).json()
    assert snapshot["findings"][0]["id"] == finding_id
    assert snapshot["findings"][0]["verification"] == "unverified"
    store = instance._get_artifact_store()
    assert isinstance(store, ArtifactStore)
    artifacts = []
    for index in range(3):
        capture = store.capture(instance._artifact_session_id(session_id), f"review-{index}", "stdout")
        capture.write(f"private-review-artifact-{index}".encode())
        artifacts.append(capture.finalize())
    listed = client.get(prefix + "/artifacts", headers=headers).json()["artifacts"]
    assert {item["id"] for item in listed} == {item["id"] for item in artifacts}
    assert all(re.fullmatch(r"[0-9a-f]{64}\.[0-9a-f]{32}", item["id"]) for item in listed)
    content = client.get(prefix + f"/artifacts/{artifacts[0]['id']}/content?acknowledge_sensitive=true", headers=headers)
    assert content.content == b"private-review-artifact-0"
    path = prefix + f"/vulnerabilities/{snapshot['findings'][0]['id']}/verification"
    for index, (kind, result, lifecycle) in enumerate([
        ("verification", "positive", "verified"), ("remediation", "applied", "remediated"),
        ("retest", "negative", "retested"),
    ]):
        payload = {"acknowledge_review": True, "method": "manual protocol evidence review", "result": result,
                   "artifact_refs": [artifacts[index]["id"]], "evidence": f"Reviewed retained observation {index}"}
        if index:
            payload["kind"] = kind
            # Exercise historical review from SQLite, not only live in-memory state.
            instance.sessions.clear()
        assert client.post(path, json=payload).status_code == 401
        response = client.post(path, json=payload, headers=headers)
        assert response.status_code == 200, response.text
        record = response.json()
        assert record["finding_id"] == finding_id
        assert record["verification"]["lifecycle"] == lifecycle
        assert record["verified"] is (kind == "verification")
        snapshot_response = client.get(prefix + "/report.json", headers=headers)
        assert snapshot_response.json()["findings"][0]["id"] == finding_id
        assert snapshot_response.json()["findings"][0]["verification"] == ("verified" if index == 0 else "unverified")
        assert "private-review-artifact" not in snapshot_response.text
    assert record["verification"]["remediation_verified"] is True
    assert [event["kind"] for event in record["verification_events"]] == ["verification", "remediation", "retest"]
    stored = instance._read_session_snapshot(session_id).vulnerabilities[0]
    assert stored["finding_id"] == finding_id and stored["remediation_verified"] is True
    with sqlite3.connect(instance.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM evidence WHERE evidence_type='finding_verification'").fetchone()[0] == 3
        assert connection.execute("SELECT COUNT(*) FROM session_events WHERE event_type='finding_verification'").fetchone()[0] == 3


@pytest.mark.parametrize("default_root", [False, True])
def test_session_deletion_serializes_snapshots_and_purges_cache_through_http(persisted_api, monkeypatch, default_root):
    client, namespace, instance, session_id = persisted_api
    if default_root:
        monkeypatch.delenv("KMN_ASSESSMENT_DIR")
    other = instance.create_session("192.0.2.2", authorization_confirmed=True)
    headers = {"X-API-Key": "test-api-key"}
    payload = {"document": {"openapi": "3.0.3", "paths": {"/status": {"get": {}}}}, "base_url": "https://example.com"}
    for sid in (session_id, other):
        assert client.post(f"/api/sessions/{sid}/assessment/import", json=payload, headers=headers).status_code == 200
    root = Path(os.getenv("KMN_ASSESSMENT_DIR") or Path(instance.db_path).parent / "assessments")
    assert len(namespace["_assessment_cache"]) == 2 and len(list(root.glob("*.json"))) == 2
    assert client.delete(f"/api/sessions/{session_id}").status_code == 401
    response = client.delete(f"/api/sessions/{session_id}", headers=headers)
    assert response.status_code == 200, response.text
    assert len(namespace["_assessment_cache"]) == 1
    assert {path.name for path in namespace["_assessment_cache"]} == {hashlib.sha256(other.encode()).hexdigest() + ".json"}
    assert client.post(f"/api/sessions/{session_id}/assessment/import", json=payload, headers=headers).status_code == 404
    assert not (root / (hashlib.sha256(session_id.encode()).hexdigest() + ".json")).exists()
    assert client.delete("/api/sessions").status_code == 401
    response = client.delete("/api/sessions", headers=headers)
    assert response.status_code == 200, response.text
    assert namespace["_assessment_cache"] == {} and list(root.glob("*.json")) == []


def test_queued_inventory_import_rechecks_session_after_deletion(persisted_api):
    _, namespace, instance, session_id = persisted_api
    entered = threading.Event()
    owner = threading.get_ident()

    class ObservedLock:
        def __init__(self):
            self.lock = threading.RLock()

        def __enter__(self):
            if threading.get_ident() != owner:
                entered.set()
            self.lock.acquire()

        def __exit__(self, *args):
            self.lock.release()

    lock = namespace["_assessment_lock"] = ObservedLock()
    payload = {"document": {"openapi": "3.0.3", "paths": {}}, "base_url": "https://example.com"}
    with ThreadPoolExecutor(max_workers=1) as executor:
        with lock:
            queued = executor.submit(namespace["_assessment_snapshot"], session_id, payload)
            assert entered.wait(3)
            assert namespace["_delete_sessions"](session_id)["status"] == "success"
        with pytest.raises(namespace["HTTPException"]) as error:
            queued.result(timeout=3)
    assert error.value.status_code == 404
    assert namespace["_assessment_cache"] == {}
    root = Path(os.environ["KMN_ASSESSMENT_DIR"])
    assert not (root / (hashlib.sha256(session_id.encode()).hexdigest() + ".json")).exists()


def test_delete_worker_holds_lock_without_blocking_event_loop(api, monkeypatch):
    _, namespace, _, _ = api
    started, release = threading.Event(), threading.Event()
    worker_threads = []

    def blocked_delete(session_id):
        worker_threads.append(threading.get_ident())
        assert namespace["_assessment_lock"]._is_owned()
        started.set()
        assert release.wait(5)
        return {"status": "success"}

    monkeypatch.setattr(namespace["orchestrator"], "delete_session", blocked_delete, raising=False)

    async def delete():
        event_thread = threading.get_ident()
        task = asyncio.create_task(namespace["delete_session"]("s1"))
        try:
            assert await asyncio.to_thread(started.wait, 3)
            assert len(worker_threads) == 1 and worker_threads[0] != event_thread
            assert not task.done()
        finally:
            release.set()
        assert (await asyncio.wait_for(task, 3))["status"] == "success"

    asyncio.run(delete())


@pytest.mark.parametrize("delete_all", [False, True])
def test_failed_deletion_retains_assessment_cache(api, monkeypatch, delete_all):
    client, namespace, _, _ = api
    headers = {"X-API-Key": "test-api-key"}
    payload = {"document": {"openapi": "3.0.3", "paths": {}}, "base_url": "https://example.com"}
    assert client.post("/api/sessions/s1/assessment/import", json=payload, headers=headers).status_code == 200
    before = dict(namespace["_assessment_cache"])
    monkeypatch.setattr(namespace["orchestrator"], "delete_all_sessions" if delete_all else "delete_session",
                        lambda *args: {"status": "error", "message": "Deletion pending"}, raising=False)
    assert client.delete("/api/sessions" + ("" if delete_all else "/s1"), headers=headers).status_code == 500
    assert namespace["_assessment_cache"] == before


def test_snapshot_rejects_symlink_ancestors_and_foreign_owned_root(api, monkeypatch, tmp_path):
    client, _, _, _ = api
    headers = {"X-API-Key": "test-api-key"}
    payload = {"document": {"openapi": "3.0.3", "paths": {}}, "base_url": "https://example.com"}
    actual = tmp_path.resolve() / "real-owner-root"
    actual.mkdir()
    alias = tmp_path.resolve() / "root-alias"
    alias.symlink_to(actual, target_is_directory=True)
    monkeypatch.setenv("KMN_ASSESSMENT_DIR", str(alias / "assessments"))
    assert client.post("/api/sessions/s1/assessment/import", json=payload, headers=headers).status_code == 503
    assert not (actual / "assessments").exists()
    monkeypatch.setenv("KMN_ASSESSMENT_DIR", str(actual))
    uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: uid + 1)
    assert client.post("/api/sessions/s1/assessment/import", json=payload, headers=headers).status_code == 503
    assert list(actual.iterdir()) == []


@pytest.mark.parametrize("delete_all", [False, True])
@pytest.mark.parametrize("failure", ["exception", "pending", "incomplete", "malformed"])
def test_delete_cleanup_failure_does_not_purge_data_or_cache(api, monkeypatch, delete_all, failure):
    client, namespace, _, _ = api
    instance = namespace["orchestrator"]
    if failure == "exception":
        instance.prepare_session_deletion.side_effect = RuntimeError("private-cleanup-secret")
    else:
        instance.prepare_session_deletion.return_value = (None if failure == "malformed" else {
            "status": "error", "cleanup_pending": failure == "pending", "cleanup_incomplete": True,
            "message": "private-cleanup-secret",
        })
    purge_calls = []
    monkeypatch.setitem(namespace, "_delete_sessions", lambda *args: purge_calls.append(args))
    cached_path = Path(os.environ["KMN_ASSESSMENT_DIR"]) / "cached.json"
    namespace["_assessment_cache"][cached_path] = "retained"
    response = client.delete("/api/sessions" + ("" if delete_all else "/s1"), headers={"X-API-Key": "test-api-key"})
    assert response.status_code == (503 if failure == "exception" else 409)
    assert response.json()["detail"] == (
        "Session cleanup failed; session data was not deleted" if failure == "exception" else
        "Session cleanup pending or incomplete; session data was not deleted")
    assert "private-cleanup-secret" not in response.text
    instance.prepare_session_deletion.assert_awaited_once_with(None if delete_all else "s1")
    assert purge_calls == []
    assert namespace["_assessment_cache"] == {cached_path: "retained"}


@pytest.mark.parametrize("delete_all", [False, True])
def test_delete_prepares_managed_resources_on_owning_loop_before_real_purge(persisted_api, delete_all):
    client, namespace, instance, session_id = persisted_api
    headers = {"X-API-Key": "test-api-key"}
    prefix = f"/api/sessions/{session_id}"
    payload = {"document": {"openapi": "3.0.3", "paths": {}}, "base_url": "https://example.com"}
    assert client.post(prefix + "/assessment/import", json=payload, headers=headers).status_code == 200
    store = instance._get_artifact_store()
    capture = store.capture(instance._artifact_session_id(session_id), "cleanup1", "stdout")
    capture.write(b"retained-until-cleanup")
    capture.finalize()
    cleaned = set()
    owners = []

    async def register_resources():
        loop = asyncio.get_running_loop()

        async def stop_manager():
            assert asyncio.get_running_loop() is loop
            assert not namespace["_assessment_lock"]._is_owned()
            await asyncio.sleep(0)
            cleaned.add("manager")

        async def cancel_worker():
            assert asyncio.get_running_loop() is loop
            await asyncio.sleep(0)
            cleaned.add("worker")

        async def owned_task():
            try:
                await asyncio.Event().wait()
            finally:
                assert asyncio.get_running_loop() is loop
                cleaned.add("task")

        instance._shell_managers[session_id] = SimpleNamespace(stop_all=stop_manager)
        instance._brute_workers[session_id] = SimpleNamespace(cancel_all=cancel_worker)
        task = asyncio.create_task(owned_task())
        instance._background_tasks[session_id] = {task}
        owners.append(task)
        await asyncio.sleep(0)

    client.portal.call(register_resources)
    response = client.delete("/api/sessions" if delete_all else prefix, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "success"
    assert cleaned == {"manager", "worker", "task"}
    assert owners[0].done()
    assert instance.get_session(session_id) is None
    with sqlite3.connect(instance.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions WHERE session_id=?", (session_id,)).fetchone()[0] == 0
    assert store.manifests(instance._artifact_session_id(session_id)) == []
    assert namespace["_assessment_cache"] == {}
    assert list(Path(os.environ["KMN_ASSESSMENT_DIR"]).glob("*.json")) == []


@pytest.mark.parametrize("delete_all", [False, True])
def test_real_cleanup_error_dict_retains_database_artifacts_snapshot_and_cache(persisted_api, delete_all):
    client, namespace, instance, session_id = persisted_api
    headers = {"X-API-Key": "test-api-key"}
    prefix = f"/api/sessions/{session_id}"
    payload = {"document": {"openapi": "3.0.3", "paths": {}}, "base_url": "https://example.com"}
    assert client.post(prefix + "/assessment/import", json=payload, headers=headers).status_code == 200
    before = dict(namespace["_assessment_cache"])
    store = instance._get_artifact_store()
    capture = store.capture(instance._artifact_session_id(session_id), "failed-cleanup", "stdout")
    capture.write(b"retained-private-evidence")
    manifest = capture.finalize()
    cleanup_calls = []

    async def register_resource():
        loop = asyncio.get_running_loop()

        async def fail_cleanup():
            assert asyncio.get_running_loop() is loop
            cleanup_calls.append("manager")
            raise RuntimeError("private-cleanup-secret")

        instance._shell_managers[session_id] = SimpleNamespace(stop_all=fail_cleanup)

    client.portal.call(register_resource)
    response = client.delete("/api/sessions" if delete_all else prefix, headers=headers)
    assert response.status_code == 409, response.text
    assert "session data was not deleted" in response.json()["detail"]
    assert "private-cleanup-secret" not in response.text
    assert cleanup_calls == ["manager"]
    with sqlite3.connect(instance.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions WHERE session_id=?", (session_id,)).fetchone()[0] == 1
    assert store.read(manifest["id"]) == b"retained-private-evidence"
    assert namespace["_assessment_cache"] == before
    assert all(path.exists() for path in before)


@pytest.mark.parametrize("suffix", ["events", "jobs"])
def test_durable_events_and_jobs_remain_available_for_historical_sessions(persisted_api, suffix):
    client, _, instance, session_id = persisted_api
    instance._record_event(session_id, "operator_review", {"reviewed": True})
    instance._create_job(session_id, "operator_review")
    expected = (instance.get_session_events(session_id) if suffix == "events" else instance.get_session_jobs(session_id))
    assert expected
    instance.sessions.clear()
    assert instance.get_session(session_id) is None
    response = client.get(f"/api/sessions/{session_id}/{suffix}", headers={"X-API-Key": "test-api-key"})
    assert response.status_code == 200, response.text
    assert response.json() == {"session_id": session_id, suffix: expected, "count": len(expected)}

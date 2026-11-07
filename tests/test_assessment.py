"""Offline tests for the independent assessment foundation; no tools or network."""

import asyncio
import json
import os
import stat
from dataclasses import replace

import pytest

from core import assessment as module
from core.assessment import (
    Assessment, AssessmentError, Budget, BudgetExceeded, CoverageKey, Outcome,
    TaskCoordinator, configure_shared_coordinator, get_shared_coordinator,
    import_openapi, validate_base_url,
)


def spec():
    return {"openapi": "3.1.0", "servers": [{"url": "https://api.example.test/v1"}],
            "paths": {"/users/{id}": {"get": {}, "post": {}}}}


def ledger(**kwargs):
    return Assessment.from_openapi(spec(), allowlist="api.example.test", **kwargs)


def test_inventory_roles_and_explicit_verification():
    assessment = ledger(roles={"anonymous": None, "reader": "env:ASSESSMENT_READER"},
                        categories=["authorization", "observation"])
    assert len(assessment.endpoints) == 2
    assert len(assessment.cells) == 8
    assert assessment.endpoints[0].method == "GET"
    key = next(iter(assessment.cells))
    with pytest.raises(AssessmentError):
        assessment.mark(key, "verified", evidence_ref="evidence:run-1")
    assessment.begin_attempt(key)
    assert assessment.cells[key].status == "attempted"
    with pytest.raises(AssessmentError):
        assessment.mark(key, "verified")
    assessment.mark(key, "verified", evidence_ref="evidence:run-1")
    assert assessment.summary()["verified_ratio"] == 1 / 8
    copy = assessment.cells
    copy.clear()
    assert len(assessment.cells) == 8
    assert {c.status for c in assessment.cells.values()} == {"pending", "verified"}


@pytest.mark.parametrize("status", ["blocked", "skipped", "inconclusive"])
def test_unverified_outcomes_never_count_as_verified(status):
    assessment = ledger()
    key = next(iter(assessment.cells))
    if status == "inconclusive":
        assessment.begin_attempt(key)
    assessment.mark(key, status)
    assert assessment.summary()["verified_ratio"] == 0
    assert Assessment.from_json(assessment.to_json()).cells == assessment.cells


def test_validator_api_is_used_and_environment_is_read_at_call_time(monkeypatch):
    calls = []
    monkeypatch.setattr(module.validators, "is_valid_target", lambda host: calls.append(host) or True)
    monkeypatch.setattr(module.validators, "is_target_in_scope",
                        lambda host, scope: calls.append((host, scope)) or scope == "allowed")
    monkeypatch.setenv("SCOPE_ALLOWLIST", "allowed")
    assert validate_base_url("https://API.example.test:443/v1/") == "https://api.example.test/v1"
    assert calls == ["api.example.test", ("api.example.test", "allowed")]
    monkeypatch.setenv("SCOPE_ALLOWLIST", "denied")
    with pytest.raises(AssessmentError):
        validate_base_url("https://api.example.test")


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://api.example.test", "https://user:password@api.example.test",
    "https://api.example.test?token=secret", "https://api.example.test#secret",
    "https://api.example.test?", "https://api.example.test:99999", "https://api.example.test:0",
    "https://api.example.test\\@evil.test", "https://api.example.test/\npath",
    "https://api.example.test/%2e%2e/private", "https://api.example.test/a%3ftoken=secret",
    "https://evil.test", "/relative",
])
def test_unsafe_or_out_of_scope_urls_rejected(url):
    with pytest.raises(AssessmentError):
        validate_base_url(url, "api.example.test")


def test_ipv6_url_and_cidr_scope():
    assert validate_base_url("http://[::1]:8000/api", "::1/128") == "http://[::1]:8000/api"


def test_servers_precedence_defaults_relative_and_stable_identity():
    document = spec()
    document["servers"] = [{"url": "https://{host}/v1", "variables": {
        "host": {"default": "api.example.test"}}}]
    document["paths"]["/users/{id}"]["servers"] = [{"url": "/path-base"}]
    document["paths"]["/users/{id}"]["post"]["servers"] = [{"url": "/operation-base"}]
    endpoints = import_openapi(document, base_url="https://api.example.test/root")
    assert {e.base_url for e in endpoints} == {
        "https://api.example.test/path-base", "https://api.example.test/operation-base"}
    assert endpoints == import_openapi(json.dumps(document), base_url="https://api.example.test/root")
    with pytest.raises(AssessmentError):
        import_openapi(document)


def test_multiple_servers_dedupe_and_all_declarations_are_scoped():
    document = spec()
    document["servers"] *= 2
    assert len(import_openapi(document)) == 2
    document["servers"].append({"url": "https://evil.test"})
    document["paths"]["/users/{id}"]["servers"] = [{"url": "https://api.example.test"}]
    with pytest.raises(AssessmentError):
        import_openapi(document, allowlist="api.example.test")


def test_local_refs_escaped_pointers_and_recursive_schema():
    document = spec()
    document["components"] = {
        "pathItems": {"users/list~item": {"get": {}}},
        "schemas": {"Node": {"properties": {"child": {"$ref": "#/components/schemas/Node"}}}},
    }
    document["paths"] = {"/users": {"$ref": "#/components/pathItems/users~1list~0item"}}
    endpoints = import_openapi(document)
    assert len(endpoints) == 1
    assert endpoints[0].path == "/users"


@pytest.mark.parametrize("ref", [
    "https://evil.test/schema.json", "file:///etc/passwd", "other.json#/thing",
    "#/missing", "#/paths/~2bad", "#", 12,
])
def test_refs_never_fetch_and_fail_closed_even_in_unused_schemas(ref):
    document = spec()
    document["components"] = {"schemas": {"Unused": {"$ref": ref}}}
    with pytest.raises(AssessmentError):
        import_openapi(document)


def test_reference_cycles_and_ambiguous_siblings_rejected():
    document = spec()
    document["paths"] = {"/a": {"$ref": "#/paths/~1b"}, "/b": {"$ref": "#/paths/~1a"}}
    with pytest.raises(AssessmentError):
        import_openapi(document)
    document["paths"] = {"/a": {"get": {}}, "/b": {"$ref": "#/paths/~1a", "post": {}}}
    with pytest.raises(AssessmentError):
        import_openapi(document)


@pytest.mark.parametrize("path", ["//evil.test", "/../admin", "/%252e%252e/admin", "/a?token=x",
                                  "/a#secret", "/a\\b", "/%2f%2fevil.test"])
def test_unsafe_operation_paths_rejected(path):
    document = spec()
    document["paths"] = {path: {"get": {}}}
    with pytest.raises(AssessmentError):
        import_openapi(document)


def test_document_and_matrix_bounds(monkeypatch):
    with pytest.raises(AssessmentError):
        import_openapi("a" * (module.MAX_BYTES + 1))
    nested = {}
    document = spec()
    document["x-nesting"] = nested
    for _ in range(70):
        nested["child"] = {}
        nested = nested["child"]
    with pytest.raises(AssessmentError):
        import_openapi(document)
    monkeypatch.setattr(module, "MAX_ENDPOINTS", 1)
    with pytest.raises(AssessmentError):
        import_openapi(spec())
    monkeypatch.setattr(module, "MAX_ENDPOINTS", 5000)
    monkeypatch.setattr(module, "MAX_CELLS", 1)
    with pytest.raises(AssessmentError):
        ledger()


def test_no_implicit_server_and_no_yaml_or_swagger_support():
    document = spec()
    del document["servers"]
    with pytest.raises(AssessmentError):
        import_openapi(document)
    assert len(import_openapi(document, base_url="https://api.example.test")) == 2
    for invalid in ("openapi: 3.0.0", {"swagger": "2.0"}, [], "null",
                    '{"openapi":"3.1.0", "x-invalid":NaN}'):
        with pytest.raises(AssessmentError):
            import_openapi(invalid)


def test_snapshots_exclude_raw_specs_credentials_and_revalidate_scope(monkeypatch):
    monkeypatch.setenv("ASSESSMENT_READER", "literal-credential-value")
    document = spec()
    document["info"] = {"description": "password=spec-secret"}
    document["paths"]["/users/{id}"]["get"]["example"] = {"authorization": "Bearer example-secret"}
    assessment = Assessment.from_openapi(document, roles={"reader": "env:ASSESSMENT_READER"})
    text = assessment.to_json()
    for secret in ("literal-credential-value", "spec-secret", "example-secret", "authorization"):
        assert secret not in text
    assert "env:ASSESSMENT_READER" in text
    restored = Assessment.from_json(text, allowlist="api.example.test")
    assert restored.endpoints == assessment.endpoints
    assert restored.cells == assessment.cells
    with pytest.raises(AssessmentError):
        Assessment.from_json(text, allowlist="other.test")
    for credentials in ({"reader": "password=literal"}, {"reader": {"token": "literal"}}):
        with pytest.raises(AssessmentError):
            ledger(roles=credentials)


def test_snapshot_resume_marks_inflight_inconclusive():
    assessment = ledger()
    key = next(iter(assessment.cells))
    assessment.begin_attempt(key)
    restored = Assessment.from_json(assessment.to_json())
    assert restored.cells[key].status == "inconclusive"
    assert restored.cells[key].attempts == 1


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(password="secret"),
    lambda d: d["endpoints"][0].update(id="forged"),
    lambda d: d["coverage"].pop(),
    lambda d: d["coverage"].append(dict(d["coverage"][0])),
    lambda d: d["coverage"][0].update(status="verified", attempts=1),
    lambda d: d["coverage"][0].update(attempts=True),
    lambda d: d["coverage"][0].update(evidence_ref="Bearer literal-secret"),
    lambda d: d["coverage"][0].update(status="unknown"),
    lambda d: d["coverage"][0].update(role="unknown"),
])
def test_snapshot_tampering_rejected(mutation):
    data = json.loads(ledger().to_json())
    mutation(data)
    with pytest.raises(AssessmentError):
        Assessment.from_json(data)


def test_atomic_snapshot_permissions_and_cleanup(tmp_path, monkeypatch):
    assessment = ledger()
    destination = tmp_path / "snapshot.json"
    destination.write_text("old snapshot")
    os.chmod(destination, 0o666)
    real_replace = os.replace
    publications = []

    def checked_replace(source, target):
        assert stat.S_IMODE(os.stat(source).st_mode) == 0o600
        Assessment.load(source)
        publications.append(source)
        real_replace(source, target)

    monkeypatch.setattr(module.os, "replace", checked_replace)
    assessment.save(destination)
    assert publications
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert Assessment.load(destination).endpoints == assessment.endpoints
    old = destination.read_bytes()

    def fail_replace(*args):
        raise OSError("mock publication failure")

    monkeypatch.setattr(module.os, "replace", fail_replace)
    with pytest.raises(OSError):
        assessment.save(destination)
    assert destination.read_bytes() == old
    assert list(tmp_path.iterdir()) == [destination]


def test_coordinator_concurrency_dedupe_and_independent_failures():
    async def scenario():
        assessment = ledger(roles={"anonymous": None, "reader": "env:READER"})
        coordinator = TaskCoordinator(Budget(concurrency=2))
        active, peak = 0, 0
        release, entered = asyncio.Event(), asyncio.Event()

        async def worker(context):
            nonlocal active, peak
            assert context.remaining() > 0
            assert context.credential_ref in {None, "env:READER"}
            active += 1
            peak = max(peak, active)
            if active == 2:
                entered.set()
            await release.wait()
            active -= 1
            if context.endpoint.method == "POST":
                raise RuntimeError("password=do-not-export")
            return Outcome("verified", "evidence:offline-check")

        keys = list(assessment.cells)
        ids = [coordinator.submit(assessment, key, worker) for key in keys]
        assert coordinator.submit(assessment, keys[0], worker, units=99) == ids[0]
        await asyncio.wait_for(entered.wait(), 1)
        assert peak == 2
        assert sum(c.status == "attempted" for c in assessment.cells.values()) == 2
        release.set()
        records = await coordinator.wait()
        assert {record.state for record in records.values()} == {"completed", "failed"}
        assert peak == 2
        assert assessment.summary()["counts"]["verified"] == 2
        assert assessment.summary()["counts"]["inconclusive"] == 2
        assert "do-not-export" not in assessment.to_json()
        assert "do-not-export" not in repr(records)
        assert coordinator.submit(assessment, keys[0], worker) == ids[0]
        await coordinator.close()
        with pytest.raises(AssessmentError):
            coordinator.submit(assessment, keys[0], worker)

    asyncio.run(scenario())


@pytest.mark.parametrize("budget", [Budget(max_tasks=1), Budget(max_units=1)])
def test_admission_budgets_and_invalid_identity(budget):
    async def scenario():
        assessment = ledger()
        coordinator = TaskCoordinator(budget)
        keys = list(assessment.cells)

        async def worker(context):
            return Outcome("attempted")

        coordinator.submit(assessment, keys[0], worker)
        with pytest.raises(BudgetExceeded):
            coordinator.submit(assessment, keys[1], worker)
        with pytest.raises(AssessmentError):
            coordinator.submit(assessment, CoverageKey("missing", "anonymous", "observation"), worker)
        await coordinator.close(cancel=True)
        assert assessment.cells[keys[1]].status == "pending"

    asyncio.run(scenario())


def test_running_and_queued_cancellation_and_no_budget_refund():
    async def scenario():
        assessment = ledger()
        coordinator = TaskCoordinator(Budget(concurrency=1, max_tasks=2))
        entered, cleaned = asyncio.Event(), asyncio.Event()

        async def worker(context):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.set()

        keys = list(assessment.cells)
        running = coordinator.submit(assessment, keys[0], worker)
        queued = coordinator.submit(assessment, keys[1], worker)
        await asyncio.wait_for(entered.wait(), 1)
        assert coordinator.cancel(queued)
        assert coordinator.cancel(running)
        assert not coordinator.cancel(running)
        await coordinator.wait()
        assert cleaned.is_set()
        assert assessment.cells[keys[0]].status == "inconclusive"
        assert assessment.cells[keys[1]].status == "skipped"
        assert all(r.state == "cancelled" for r in coordinator.records.values())
        assert coordinator.submit(assessment, keys[1], worker) == queued
        with pytest.raises(BudgetExceeded):
            coordinator.submit(ledger(), keys[0], worker)

    asyncio.run(scenario())


def test_cancel_before_coroutine_starts():
    async def scenario():
        assessment = ledger()
        coordinator = TaskCoordinator()
        key = next(iter(assessment.cells))

        async def forbidden(context):
            pytest.fail("Cancelled job must not start")

        job_id = coordinator.submit(assessment, key, forbidden)
        coordinator.cancel(job_id)
        await coordinator.wait()
        assert assessment.cells[key].status == "skipped"
        assert assessment.cells[key].attempts == 0

    asyncio.run(scenario())


def test_task_and_wall_deadlines():
    async def scenario():
        assessment = ledger()
        coordinator = TaskCoordinator(Budget(concurrency=1, wall_seconds=0.05, task_seconds=1))
        keys = list(assessment.cells)

        async def slow(context):
            await asyncio.Event().wait()

        for key in keys:
            coordinator.submit(assessment, key, slow)
        await coordinator.wait()
        assert assessment.cells[keys[0]].status == "inconclusive"
        assert assessment.cells[keys[1]].status == "blocked"
        assert all(r.state == "timed_out" for r in coordinator.records.values())
        with pytest.raises(BudgetExceeded):
            coordinator.submit(ledger(), keys[0], slow)

        short = TaskCoordinator(Budget(task_seconds=0.01))
        short.submit(assessment, keys[0], slow)
        await short.wait()
        assert next(iter(short.records.values())).state == "timed_out"

    asyncio.run(scenario())


def test_worker_return_value_is_not_implicit_success():
    async def scenario():
        assessment = ledger()
        coordinator = TaskCoordinator()

        async def worker(context):
            return {"success": True, "password": "must-not-survive"}

        key = next(iter(assessment.cells))
        coordinator.submit(assessment, key, worker)
        await coordinator.wait()
        assert assessment.cells[key].status == "inconclusive"
        assert next(iter(coordinator.records.values())).state == "failed"
        assert "must-not-survive" not in assessment.to_json()

    asyncio.run(scenario())


@pytest.mark.parametrize("changes", [
    {"concurrency": 0}, {"max_tasks": True}, {"max_units": -1},
    {"wall_seconds": float("inf")}, {"task_seconds": float("nan")}, {"task_seconds": 0},
])
def test_invalid_budgets(changes):
    with pytest.raises(AssessmentError):
        replace(Budget(), **changes)


def test_shared_configuration_and_event_loop_ownership(monkeypatch):
    monkeypatch.setattr(module, "_shared", None)
    assert get_shared_coordinator() is get_shared_coordinator()
    coordinator = configure_shared_coordinator(Budget(concurrency=1))

    async def first_loop():
        assessment = ledger()
        key = next(iter(assessment.cells))

        async def worker(context):
            return Outcome("blocked")

        coordinator.submit(assessment, key, worker)
        with pytest.raises(AssessmentError):
            configure_shared_coordinator(Budget())
        await coordinator.wait()

    asyncio.run(first_loop())

    async def second_loop():
        assessment = ledger()
        with pytest.raises(AssessmentError):
            coordinator.submit(assessment, next(iter(assessment.cells)), lambda c: None)

    asyncio.run(second_loop())
    assert configure_shared_coordinator(Budget()) is get_shared_coordinator()

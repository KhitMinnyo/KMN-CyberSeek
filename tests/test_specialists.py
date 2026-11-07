"""Offline specialist isolation, sanitization, and concurrency tests."""

import asyncio
import hashlib
import json
import sqlite3
from unittest.mock import AsyncMock

import pytest

from core.specialists import (
    ContextReference, HandoffBudgetExceeded, SpecialistRequest, SpecialistService,
)


def response(**overrides):
    return {"hypotheses": ["Possible authorization gap"],
            "missing_evidence": ["Independent request/response evidence"],
            "citations": ["source:route-1"], "uncertainty": 0.8, **overrides}


def request():
    return SpecialistRequest("authorization", "Assess password=request-secret and supplied-secret",
                             (ContextReference("source:route-1", "Route summary token=context-secret"),))


def test_sanitized_analysis_and_hash_only_session_audit(tmp_path):
    async def run():
        connector = type("Connector", (), {"ask_raw_async": AsyncMock(return_value=response(
            hypotheses=["Possible gap supplied-secret password=model-secret"]))})()
        service = SpecialistService(connector, tmp_path / "db", "s", credentials=["supplied-secret"])
        result = await service.run(request())
        assert result.status == "analysis" and not result.verified
        assert result.citations == ("source:route-1",)
        assert result.uncertainty == 0.8
        assert "model-secret" not in json.dumps(result.to_dict())
        prompts = str(connector.ask_raw_async.call_args)
        for secret in ("request-secret", "supplied-secret", "context-secret"):
            assert secret not in prompts
        records = service.records()
        assert len(records) == 1 and len(records[0]["context_hash"]) == 64
        audit = json.dumps(records)
        assert "Possible gap" not in audit and "model-secret" not in audit
        other = SpecialistService(connector, tmp_path / "db", "other")
        assert other.records() == []
        service.close()
        other.close()
        # Raw prompts/prose must not survive anywhere in SQLite pages.
        disk = (tmp_path / "db").read_bytes()
        for value in (b"supplied-secret", b"model-secret", b"Route summary", b"Possible gap"):
            assert value not in disk
    asyncio.run(run())


def test_default_serial_slots_and_persisted_budget(tmp_path):
    async def run():
        active, peak = 0, 0

        async def ask(*args):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return response()

        connector = type("Connector", (), {"ask_raw_async": AsyncMock(side_effect=ask)})()
        service = SpecialistService(connector, tmp_path / "db", "s", max_handoffs=3)
        results = await asyncio.gather(*(service.run(request()) for _ in range(3)))
        assert peak == 1 and len(results) == 3
        with pytest.raises(HandoffBudgetExceeded):
            await service.run(request())
        service.close()
        reopened = SpecialistService(connector, tmp_path / "db", "s", max_handoffs=3)
        with pytest.raises(HandoffBudgetExceeded):
            await reopened.run(request())
        assert connector.ask_raw_async.await_count == 3
        reopened.close()
    asyncio.run(run())


def test_shared_database_budget_and_configured_slots(tmp_path):
    async def run():
        active, peak = 0, 0

        async def ask(*args):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return response()

        connector = type("Connector", (), {"ask_raw_async": AsyncMock(side_effect=ask)})()
        service = SpecialistService(connector, tmp_path / "db", "s", concurrency=2, max_handoffs=2)
        other = SpecialistService(connector, tmp_path / "db", "s", max_handoffs=2)
        await asyncio.gather(service.run(request()), service.run(request()))
        assert peak == 2
        with pytest.raises(HandoffBudgetExceeded):
            await other.run(request())
        assert len(other.records()) == 2
        service.close()
        other.close()
    asyncio.run(run())


@pytest.mark.parametrize("raw", [
    None, {"command": "danger"}, response(commands=["danger"]), response(verified=True),
    response(citations=["source:invented"]), response(uncertainty=float("nan")),
    response(uncertainty=True), response(hypotheses=["x" * 513]), response(hypotheses=["x"] * 9),
    response(handoffs=["recursive"]),
])
def test_invalid_model_output_is_inconclusive(tmp_path, raw):
    async def run():
        connector = type("Connector", (), {"ask_raw_async": AsyncMock(return_value=raw)})()
        service = SpecialistService(connector, tmp_path / "db", "s")
        result = await service.run(request())
        assert result.status == "inconclusive" and result.uncertainty == 1
        assert not result.hypotheses and not result.verified
        assert service.records()[0]["status"] == "inconclusive"
        service.close()
    asyncio.run(run())


@pytest.mark.parametrize("bad_request", [
    SpecialistRequest("executor", "question"), SpecialistRequest("source", "x" * 4097),
    SpecialistRequest("source", "question", (ContextReference("https://evil.test", "summary"),)),
    SpecialistRequest("source", "question", (ContextReference("source:id", "x" * 513),)),
])
def test_invalid_request_not_admitted(tmp_path, bad_request):
    async def run():
        connector = type("Connector", (), {"ask_raw_async": AsyncMock()})()
        service = SpecialistService(connector, tmp_path / "db", "s")
        with pytest.raises(ValueError):
            await service.run(bad_request)
        assert not service.records()
        connector.ask_raw_async.assert_not_called()
        service.close()
    asyncio.run(run())


def test_failure_timeout_cancellation_charged_without_secret_errors(tmp_path):
    async def run():
        connector = type("Connector", (), {"ask_raw_async": AsyncMock(side_effect=RuntimeError("raw secret"))})()
        service = SpecialistService(connector, tmp_path / "db", "s", timeout=0.01, max_handoffs=3)
        assert (await service.run(request())).status == "inconclusive"

        async def slow(*args):
            await asyncio.sleep(10)

        connector.ask_raw_async.side_effect = slow
        assert (await service.run(request())).status == "inconclusive"
        task = asyncio.create_task(service.run(request()))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert [r["status"] for r in service.records()] == ["inconclusive", "inconclusive", "cancelled"]
        assert "raw secret" not in json.dumps(service.records())
        with pytest.raises(HandoffBudgetExceeded):
            await service.run(request())
        service.close()
    asyncio.run(run())


def test_lazy_connection_and_terminal_idempotent_close(tmp_path, monkeypatch):
    async def run():
        connect = sqlite3.connect
        calls = []

        def tracked_connect(*args, **kwargs):
            calls.append(args)
            return connect(*args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", tracked_connect)
        path = tmp_path / "unused.db"
        connector = type("Connector", (), {"ask_raw_async": AsyncMock()})()
        service = SpecialistService(connector, path, "s")
        assert service._db is None and not calls and not path.exists()
        service.close()
        service.close()
        for action in (service.records, service.purge_session):
            with pytest.raises(RuntimeError, match="closed"):
                action()
        with pytest.raises(RuntimeError, match="closed"):
            await service.run(request())
        assert not calls and not path.exists()
        connector.ask_raw_async.assert_not_called()
    asyncio.run(run())


def test_failed_lazy_open_can_be_retried_or_closed(tmp_path):
    path = tmp_path / "missing" / "state.db"
    service = SpecialistService(None, path, "s")
    with pytest.raises(sqlite3.OperationalError):
        service.records()
    assert service._db is None
    path.parent.mkdir()
    assert service.records() == []
    service.close()
    service.close()


def test_purge_session_isolated_idempotent_after_restart(tmp_path):
    async def run():
        path = tmp_path / "state.db"
        connector = type("Connector", (), {"ask_raw_async": AsyncMock(return_value=response())})()
        for session_id in ("first", "second"):
            service = SpecialistService(connector, path, session_id, max_handoffs=1)
            await service.run(request())
            service.close()
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE unrelated (value TEXT)")
            db.execute("INSERT INTO unrelated VALUES ('preserve')")
        deletion = SpecialistService(None, path, "first")
        assert deletion._db is None
        assert deletion.purge_session() == 1
        assert deletion.purge_session() == 0
        assert deletion.records() == []
        deletion.close()
        other = SpecialistService(None, path, "second")
        assert len(other.records()) == 1
        other.close()
        # Explicit purge removes the budget along with the audit rows.
        recreated = SpecialistService(connector, path, "first", max_handoffs=1)
        assert (await recreated.run(request())).status == "analysis"
        recreated.close()
        assert connector.ask_raw_async.await_count == 3
        with sqlite3.connect(path) as db:
            assert db.execute("SELECT value FROM unrelated").fetchall() == [("preserve",)]
            assert db.execute("SELECT count(*) FROM specialist_handoffs WHERE session_id='second'").fetchone()[0] == 1
    asyncio.run(run())


def test_purge_and_close_reject_running_and_queued_tasks(tmp_path):
    async def run():
        entered = asyncio.Event()

        async def wait(*args):
            entered.set()
            await asyncio.Event().wait()

        connector = type("Connector", (), {"ask_raw_async": AsyncMock(side_effect=wait)})()
        service = SpecialistService(connector, tmp_path / "db", "s")
        tasks = [asyncio.create_task(service.run(request())) for _ in range(2)]
        await entered.wait()
        assert len(service.records()) == 2
        for action in (service.purge_session, service.close):
            with pytest.raises(RuntimeError, match="Stop specialist tasks"):
                action()
        for task in tasks:
            task.cancel()
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        assert all(isinstance(outcome, asyncio.CancelledError) for outcome in outcomes)
        assert [r["status"] for r in service.records()] == ["cancelled", "cancelled"]
        assert service.purge_session() == 2
        assert service.records() == []
        service.close()
    asyncio.run(run())


def test_audit_restart_never_persists_question_summaries_or_model_prose(tmp_path):
    async def run():
        path = tmp_path / "state.db"
        question = "Unique raw question about authentication boundaries"
        summary = "Unique raw reference summary password=summary-secret"
        prose = "Unique model hypothesis with supplied-secret and token=model-secret"
        connector = type("Connector", (), {"ask_raw_async": AsyncMock(return_value=response(
            hypotheses=[prose], missing_evidence=[question]))})()
        service = SpecialistService(connector, path, "s", credentials=["supplied-secret"])
        result = await service.run(SpecialistRequest(
            "source", question, (ContextReference("source:route-1", summary),)))
        _, context = connector.ask_raw_async.call_args.args
        expected_hash = hashlib.sha256(context.encode()).hexdigest()
        assert result.status == "analysis"
        service.close()
        reopened = SpecialistService(None, path, "s")
        records = reopened.records()
        assert set(records[0]) == {"id", "role", "context_hash", "status", "result_hash", "citations",
                                   "uncertainty", "hypothesis_count", "missing_evidence_count"}
        assert records[0]["context_hash"] == expected_hash
        assert records[0]["citations"] == ["source:route-1"]
        records[0]["citations"].append("source:modified")
        assert reopened.records()[0]["citations"] == ["source:route-1"]
        reopened.close()
        with sqlite3.connect(path) as db:
            persisted = json.dumps(db.execute("SELECT * FROM specialist_handoffs").fetchall())
        for value in (question, summary, prose, "supplied-secret", "summary-secret", "model-secret"):
            assert value not in persisted
            assert value.encode() not in path.read_bytes()
    asyncio.run(run())


def test_credential_in_citation_rejected_before_audit_admission(tmp_path):
    async def run():
        path = tmp_path / "state.db"
        connector = type("Connector", (), {"ask_raw_async": AsyncMock()})()
        service = SpecialistService(connector, path, "s", credentials=["literal-secret"])
        with pytest.raises(ValueError, match="credential"):
            await service.run(SpecialistRequest("source", "Question", (
                ContextReference("source:literal-secret", "Summary"),)))
        assert not path.exists()
        assert service._db is None
        connector.ask_raw_async.assert_not_called()
        service.close()
    asyncio.run(run())


def test_new_known_credential_redacts_reopened_audit_citations(tmp_path):
    async def run():
        path = tmp_path / "state.db"
        connector = type("Connector", (), {"ask_raw_async": AsyncMock(return_value=response())})()
        service = SpecialistService(connector, path, "s")
        await service.run(request())
        service.close()
        reopened = SpecialistService(None, path, "s", credentials=["route-1"])
        assert reopened.records()[0]["citations"] == ["source:[REDACTED]"]
        reopened.close()
    asyncio.run(run())

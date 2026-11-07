import asyncio
import json
import os
import socket
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
import requests

import ai.connector as connector_module
from ai.connector import KMN_AI_Connector, model_call_context
from core.model_telemetry import ModelBudgetExceeded, ModelTelemetryStore
from core.preflight import evaluate_preflight


@pytest.fixture(autouse=True)
def isolated_providers(monkeypatch, tmp_path):
    monkeypatch.setattr(connector_module, "load_dotenv", lambda **kwargs: None)
    for name in list(os.environ):
        if name.startswith("KMN_MODEL_") or name.endswith(("_API_KEY", "_BASE_URL", "_MODEL")):
            monkeypatch.delenv(name)
    monkeypatch.setenv("KMN_MODEL_TELEMETRY_DB", str(tmp_path / "usage.sqlite"))
    monkeypatch.setenv("AI_MAX_TOKENS", "64")
    monkeypatch.setenv("TACTICAL_TEMPERATURE", "0.2")

    def forbidden(*args, **kwargs):
        raise AssertionError("Tests must never use real network transports")

    monkeypatch.setattr(requests, "post", forbidden)
    monkeypatch.setattr(httpx, "AsyncClient", forbidden)


ANSWER = {
    "reasoning": "private-completion-marker",
    "suggested_command": "",
    "risk_level": "low",
    "attack_phase": "reconnaissance",
}


class Response:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def raise_for_status(self):
        if self.error:
            raise self.error

    def json(self):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def mock_transport(monkeypatch, responses):
    calls = []
    pending = iter(responses)

    def post(url, **kwargs):
        calls.append((url, kwargs))
        response = next(pending)
        if isinstance(response, BaseException):
            raise response
        return response

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, url, **kwargs):
            await asyncio.sleep(0)
            return post(url, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    monkeypatch.setattr(requests, "post", post)
    return calls


def provider_result(provider, text=None, usage=True, finish="stop"):
    text = json.dumps(ANSWER) if text is None else text
    if provider == "local":
        result = {"response": text, "done_reason": finish}
        if usage:
            result.update(prompt_eval_count=11, eval_count=7)
    elif provider == "anthropic":
        result = {"content": [{"type": "text", "text": text}], "stop_reason": finish}
        if usage:
            result["usage"] = {"input_tokens": 11, "output_tokens": 7}
    else:
        result = {"choices": [{"message": {"content": text}, "finish_reason": finish}]}
        if usage:
            result["usage"] = {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
    return result


def test_cloud_provider_aliases_and_endpoints(monkeypatch):
    key = "provider-test-key-123456"
    deepseek = KMN_AI_Connector(provider="api", api_key=key, api_model="deepseek-chat")
    assert deepseek.provider == "deepseek"
    assert "deepseek.com" in deepseek.api_urls["deepseek"]

    openai = KMN_AI_Connector(provider="openai", api_key=key, api_model="gpt-4o-mini")
    assert openai.provider == "openai"
    assert openai.api_model == "gpt-4o-mini"
    assert "openai.com" in openai.api_urls["openai"]

    claude = KMN_AI_Connector(provider="claude", api_key=key)
    assert claude.provider == "anthropic"
    assert "anthropic.com" in claude.api_urls["anthropic"]

    router = KMN_AI_Connector(provider="openrouter", api_key=key)
    assert router.provider == "openrouter"
    assert router.api_model == "openai/gpt-4o-mini"
    assert "openrouter.ai" in router.api_urls["openrouter"]


def test_none_provider_does_not_make_network_calls():
    connector = KMN_AI_Connector(provider="none")
    assert connector.provider == "none"
    assert connector.ask_ai("private-prompt") is None
    assert asyncio.run(connector.ask_raw_async("system", "private-prompt")) is None
    assert not os.path.exists(connector.telemetry_store.db_path)


@pytest.mark.parametrize("provider", ["local", "deepseek", "openai", "anthropic", "openrouter"])
@pytest.mark.parametrize("raw", [False, True])
def test_all_transports_record_usage_and_propagate_context(monkeypatch, provider, raw):
    monkeypatch.setenv("KMN_MODEL_INPUT_USD_PER_MILLION", "2")
    monkeypatch.setenv("KMN_MODEL_OUTPUT_USD_PER_MILLION", "4")
    calls = mock_transport(monkeypatch, [Response(provider_result(provider))])
    connector = KMN_AI_Connector(provider=provider, api_key="private-api-key-marker")
    purpose = "summary" if raw else "tactical"
    with model_call_context("session", purpose, "operation"):
        if raw:
            answer = asyncio.run(connector.ask_raw_async("private-system-marker", "private-prompt-marker"))
        else:
            answer = asyncio.run(connector.ask_ai_async("private-prompt-marker"))
    assert answer is not None
    event, = connector.telemetry_store.events("session", 1)
    assert (event["provider"], event["purpose"], event["operation_id"]) == (provider, purpose, "operation")
    assert event["model"] == calls[0][1]["json"]["model"]
    assert (event["input_tokens"], event["output_tokens"], event["total_tokens"]) == (11, 7, 18)
    assert event["cost_usd"] == pytest.approx(0.00005)
    assert event["estimated_input_tokens"] > 0
    assert event["estimated_output_tokens"] > 0
    assert event["latency_ms"] >= 0
    assert event["parse_result"] == "success"
    assert event["retry_ordinal"] == 1
    assert event["error"] is None
    with open(connector.telemetry_store.db_path, "rb") as db:
        data = db.read()
    for secret in (b"private-prompt-marker", b"private-completion-marker", b"private-api-key-marker", b"private-system-marker"):
        assert secret not in data


def test_tactical_retry_is_a_separate_billable_attempt(monkeypatch):
    calls = mock_transport(monkeypatch, [
        Response(provider_result("openai", text="private-invalid-output")),
        Response(provider_result("openai")),
    ])
    connector = KMN_AI_Connector(provider="openai", api_key="provider-test-key-123456")
    assert asyncio.run(connector.ask_ai_api("prompt", "session")) is not None
    second, first = connector.telemetry_store.events("session")
    assert (first["retry_ordinal"], second["retry_ordinal"]) == (1, 2)
    assert first["operation_id"] == second["operation_id"]
    assert first["parse_result"] == first["error"] == "invalid_json"
    assert second["parse_result"] == "success"
    assert connector.telemetry_store.summary("session")["total_tokens"] == 36
    assert calls[1][1]["json"]["temperature"] == 0


def test_budget_blocks_retry_before_network(monkeypatch):
    monkeypatch.setenv("KMN_MODEL_MAX_CALLS", "1")
    calls = mock_transport(monkeypatch, [Response(provider_result("deepseek", text="bad json"))])
    connector = KMN_AI_Connector(provider="deepseek", api_key="provider-test-key-123456")
    with pytest.raises(ModelBudgetExceeded):
        asyncio.run(connector.ask_ai_api("prompt", "session"))
    assert len(calls) == 1
    blocked, failed = connector.telemetry_store.events("session")
    assert blocked["status"] == "blocked"
    assert blocked["retry_ordinal"] == 2
    assert blocked["operation_id"] == failed["operation_id"]


@pytest.mark.parametrize("provider", ["local", "openai"])
@pytest.mark.parametrize("raw", [True, False])
def test_transport_failures_are_generic_and_unknown(monkeypatch, provider, raw):
    error = requests.ConnectionError("private-error-marker") if provider == "local" else httpx.RequestError("private-error-marker")
    mock_transport(monkeypatch, [error])
    connector = KMN_AI_Connector(provider=provider, api_key="provider-test-key-123456")
    with model_call_context("session", "verifier"):
        if raw:
            assert asyncio.run(connector.ask_raw_async("system", "prompt")) is None
        else:
            with pytest.raises(ConnectionError, match="Failed to connect"):
                asyncio.run(connector.ask_ai_async("prompt"))
    event, = connector.telemetry_store.events("session")
    assert event["error"] == "transport_error"
    assert event["status"] == "error"
    assert event["parse_result"] == "not_attempted"
    assert event["total_tokens"] is event["cost_usd"] is None
    assert event["budget_tokens"] == event["reserved_tokens"] > 0
    assert "private-error-marker" not in json.dumps(event)


@pytest.mark.parametrize("raw", [True, False])
def test_http_and_response_failures_are_recorded(monkeypatch, raw):
    mock_transport(monkeypatch, [Response(error=requests.HTTPError("private-http-error"))])
    connector = KMN_AI_Connector(provider="local")
    with model_call_context("session", "specialist"):
        if raw:
            assert asyncio.run(connector.ask_raw_async("system", "prompt")) is None
        else:
            with pytest.raises(ConnectionError):
                connector.ask_ai_local("prompt")
    assert connector.telemetry_store.events("session")[0]["error"] == "http_error"


def test_missing_usage_remains_null(monkeypatch):
    mock_transport(monkeypatch, [Response(provider_result("openai", usage=False))])
    connector = KMN_AI_Connector(provider="openai", api_key="provider-test-key-123456")
    with model_call_context("session", "specialist"):
        assert asyncio.run(connector.ask_raw_async("system", "prompt")) is not None
    event, = connector.telemetry_store.events("session")
    assert event["input_tokens"] is event["output_tokens"] is event["total_tokens"] is event["cost_usd"] is None
    assert event["estimated_input_tokens"] > 0
    assert event["budget_tokens"] == event["reserved_tokens"]


@pytest.mark.parametrize("provider", ["local", "openai", "anthropic"])
def test_truncation_is_not_a_success(monkeypatch, provider):
    finish = "max_tokens" if provider == "anthropic" else "length"
    mock_transport(monkeypatch, [Response(provider_result(provider, finish=finish))])
    connector = KMN_AI_Connector(provider=provider, api_key="provider-test-key-123456")
    with model_call_context("session", "summary"):
        assert asyncio.run(connector.ask_raw_async("system", "prompt")) is None
    event, = connector.telemetry_store.events("session")
    assert event["parse_result"] == event["error"] == "truncated"
    assert event["total_tokens"] == 18


def test_profiles_select_role_without_changing_endpoint(monkeypatch, tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"strategist": {"model": "trusted-model", "max_tokens": 17, "temp": 0.1}}))
    monkeypatch.setenv("KMN_MODEL_PROFILES_FILE", str(path))
    calls = mock_transport(monkeypatch, [Response(provider_result("openrouter")), Response(provider_result("openrouter"))])
    connector = KMN_AI_Connector(provider="openrouter", api_key="provider-test-key-123456")
    with model_call_context("session", "strategist"):
        asyncio.run(connector.ask_raw_async("system", "prompt"))
    asyncio.run(connector.ask_raw_async("system", "prompt"))
    payload = calls[0][1]["json"]
    assert (payload["model"], payload["max_tokens"], payload["temperature"]) == ("trusted-model", 17, 0.1)
    assert calls[0][0] == calls[1][0] == connector.api_urls["openrouter"]
    assert calls[1][1]["json"]["model"] == connector.api_model
    assert connector.api_model == "openai/gpt-4o-mini"
    assert connector.telemetry_store.events("session")[0]["model"] == "trusted-model"


def test_local_profile_and_explicit_session_override(monkeypatch, tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"verifier": {"model": "local-verifier", "max_tokens": 19, "temp": 0}}))
    monkeypatch.setenv("KMN_MODEL_PROFILES_FILE", str(path))
    calls = mock_transport(monkeypatch, [Response(provider_result("local"))])
    connector = KMN_AI_Connector(provider="local")
    with model_call_context("outer", "verifier", "operation"):
        asyncio.run(connector.ask_ai_async("prompt", session_id="explicit"))
    assert not connector.telemetry_store.events("outer")
    assert connector.telemetry_store.events("explicit")[0]["purpose"] == "verifier"
    payload = calls[0][1]["json"]
    assert payload["model"] == "local-verifier"
    assert payload["options"]["num_predict"] == 19
    assert payload["options"]["temperature"] == 0


@pytest.mark.parametrize("provider", ["openai", "openrouter"])
def test_reasoning_profiles_use_native_options(monkeypatch, tmp_path, provider):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"strategist": {"reasoning": {"effort": "low"}}}))
    monkeypatch.setenv("KMN_MODEL_PROFILES_FILE", str(path))
    calls = mock_transport(monkeypatch, [Response(provider_result(provider))])
    connector = KMN_AI_Connector(provider=provider, api_key="provider-test-key-123456")
    with model_call_context("session", "strategist"):
        asyncio.run(connector.ask_raw_async("system", "prompt"))
    payload = calls[0][1]["json"]
    if provider == "openai":
        assert payload["reasoning_effort"] == "low"
        assert payload["max_completion_tokens"] == 64
        assert "temperature" not in payload and "max_tokens" not in payload
    else:
        assert payload["reasoning"] == {"effort": "low"}


@pytest.mark.parametrize("profile", [
    {"unknown": {}}, {"summary": {"endpoint": "https://untrusted.invalid"}},
    {"summary": {"provider": "openai"}}, {"summary": {"max_tokens": -1}},
    {"summary": {"max_tokens": True}}, {"summary": {"temp": float("nan")}},
    {"summary": {"reasoning": {"effort": "high"}}},
    {"summary": {"model": ""}},
])
def test_unsupported_profiles_fail_without_transport(monkeypatch, tmp_path, profile):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps(profile))
    monkeypatch.setenv("KMN_MODEL_PROFILES_FILE", str(path))
    with pytest.raises(ValueError):
        KMN_AI_Connector(provider="local")


def test_async_scopes_do_not_leak(monkeypatch):
    mock_transport(monkeypatch, [Response(provider_result("openai")) for _ in range(4)])
    connector = KMN_AI_Connector(provider="openai", api_key="provider-test-key-123456")

    async def worker(sid, purpose):
        with model_call_context(sid, purpose, sid + "-op"):
            await connector.ask_raw_async("system", "prompt")
            await asyncio.sleep(0)
            await connector.ask_raw_async("system", "prompt")

    async def run():
        await asyncio.gather(worker("one", "strategist"), worker("two", "verifier"))

    asyncio.run(run())
    for sid, purpose in (("one", "strategist"), ("two", "verifier")):
        events = connector.telemetry_store.events(sid)
        assert len(events) == 2
        assert all(event["purpose"] == purpose and event["operation_id"] == sid + "-op" for event in events)


def test_parallel_connectors_obey_call_cap_before_transport(monkeypatch, tmp_path):
    monkeypatch.setenv("KMN_MODEL_MAX_CALLS", "3")
    calls = mock_transport(monkeypatch, [Response(provider_result("local")) for _ in range(3)])
    path = tmp_path / "shared.sqlite"

    def worker(index):
        connector = KMN_AI_Connector(provider="local", telemetry_store=ModelTelemetryStore(path))
        with model_call_context("session", "tactical"):
            try:
                return connector.ask_ai_local("prompt") is not None
            except ModelBudgetExceeded:
                return False

    with ThreadPoolExecutor(max_workers=10) as pool:
        assert sum(pool.map(worker, range(15))) == 3
    assert len(calls) == 3
    assert ModelTelemetryStore(path).summary("session")["blocked"] == 12


@pytest.mark.parametrize("provider", ["local", "openai"])
@pytest.mark.parametrize("raw", [False, True])
def test_token_reservation_blocks_all_paths_before_network(monkeypatch, provider, raw):
    monkeypatch.setenv("KMN_MODEL_MAX_TOKENS", "1")
    calls = mock_transport(monkeypatch, [])
    connector = KMN_AI_Connector(provider=provider, api_key="provider-test-key-123456")
    with model_call_context("session", "tactical"):
        if raw:
            assert asyncio.run(connector.ask_raw_async("system", "prompt")) is None
        else:
            with pytest.raises(ModelBudgetExceeded):
                asyncio.run(connector.ask_ai_async("prompt"))
    event, = connector.telemetry_store.events("session")
    assert event["status"] == "blocked"
    assert event["error"] == "token_budget_exceeded"
    assert event["total_tokens"] is event["cost_usd"] is None
    assert calls == []


@pytest.mark.parametrize("result", [ValueError("private-decode-marker"), {"choices": []}])
def test_malformed_api_envelope_is_generic(monkeypatch, result, caplog):
    mock_transport(monkeypatch, [Response(result)])
    connector = KMN_AI_Connector(provider="openai", api_key="provider-test-key-123456")
    with model_call_context("session", "specialist"):
        assert asyncio.run(connector.ask_raw_async("system", "prompt")) is None
    event, = connector.telemetry_store.events("session")
    assert event["status"] == "error"
    assert event["error"] == "response_error"
    assert "private-decode-marker" not in caplog.text


def test_schema_failure_and_truncation_are_retryable(monkeypatch):
    mock_transport(monkeypatch, [
        Response(provider_result("anthropic", text="[]")),
        Response(provider_result("anthropic", finish="max_tokens")),
    ])
    connector = KMN_AI_Connector(provider="anthropic", api_key="provider-test-key-123456")
    assert asyncio.run(connector.ask_ai_api("prompt", "session")) is None
    second, first = connector.telemetry_store.events("session")
    assert first["parse_result"] == "validation_error"
    assert second["parse_result"] == "truncated"
    assert connector.telemetry_store.summary("session")["errors"] == 2


def test_cancellation_records_failure_and_keeps_reservation(monkeypatch):
    mock_transport(monkeypatch, [asyncio.CancelledError()])
    connector = KMN_AI_Connector(provider="openai", api_key="provider-test-key-123456")
    with model_call_context("session", "specialist"):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(connector.ask_raw_async("system", "prompt"))
    event, = connector.telemetry_store.events("session")
    assert event["error"] == "cancelled"
    assert event["budget_tokens"] == event["reserved_tokens"]


def test_unavailable_ledger_fails_before_transport(tmp_path):
    connector = KMN_AI_Connector(provider="local", telemetry_store=ModelTelemetryStore(tmp_path / "missing" / "usage.sqlite"))
    with pytest.raises(sqlite3.OperationalError):
        connector.ask_ai_local("prompt")


@pytest.mark.parametrize("provider,normalized", [
    ("local", "local"), (" Ollama ", "local"),
    ("deepseek", "deepseek"), ("api", "deepseek"),
    ("openai", "openai"), (" ChatGPT ", "openai"),
    ("anthropic", "anthropic"), ("claude", "anthropic"),
    ("openrouter", "openrouter"), ("open-router", "openrouter"),
    ("none", "none"),
])
def test_real_connector_preflight_is_ready_offline(monkeypatch, provider, normalized):
    monkeypatch.setenv("KMN_EXECUTION_BACKEND", "local")
    monkeypatch.setattr("shutil.which", lambda tool: "/fake/tools/" + tool)

    def forbidden(*args, **kwargs):
        raise AssertionError("Preflight must not probe tools or connectivity")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    connector = KMN_AI_Connector(
        provider=provider,
        api_key="provider-test-key-123456" if normalized not in {"local", "none"} else None,
    )
    # Live environment changes must not replace the instance's retained request.
    monkeypatch.setenv("AI_PROVIDER", "anthropic" if normalized != "anthropic" else "local")
    result = evaluate_preflight("127.0.0.1", True, scope_allowlist="127.0.0.1", connector=connector)
    assert connector.requested_provider == connector.provider == normalized
    assert result["provider"] == {"requested": normalized, "effective": normalized, "ready": True}
    assert result["ready"] is True
    assert not os.path.exists(connector.telemetry_store.db_path)
    if normalized == "none":
        assert connector.ask_ai("prompt") is None
        assert asyncio.run(connector.ask_ai_async("prompt")) is None
        assert asyncio.run(connector.ask_raw_async("system", "prompt")) is None
        assert not os.path.exists(connector.telemetry_store.db_path)


@pytest.mark.parametrize("requested,normalized", [("api", "deepseek"), ("openai", "openai"), ("claude", "anthropic"), ("open-router", "openrouter")])
def test_real_connector_fallback_retains_request_and_blocks_preflight(monkeypatch, requested, normalized):
    monkeypatch.setenv("KMN_EXECUTION_BACKEND", "local")
    monkeypatch.setattr("shutil.which", lambda tool: "/fake/tools/" + tool)
    connector = KMN_AI_Connector(provider=requested)
    assert connector.requested_provider == normalized
    assert connector.provider == "local"
    monkeypatch.setenv("AI_PROVIDER", "local")
    result = evaluate_preflight("127.0.0.1", True, scope_allowlist="127.0.0.1", connector=connector)
    assert result["provider"] == {"requested": normalized, "effective": "local", "ready": False}
    assert result["ready"] is False


@pytest.mark.parametrize("source,expected,fallback", [
    ("default", "local", False), ("key", "openai", False),
    ("invalid_key", "openai", True), ("environment", "anthropic", False),
])
def test_requested_provider_is_retained_after_autodetection(monkeypatch, source, expected, fallback):
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    if source in {"key", "invalid_key"}:
        monkeypatch.setenv("OPENAI_API_KEY", "provider-test-key-123456" if source == "key" else "placeholder")
    if source == "environment":
        monkeypatch.setenv("AI_PROVIDER", " CLAUDE ")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "provider-test-key-123456")
    connector = KMN_AI_Connector()
    assert connector.requested_provider == expected
    assert connector.provider == ("local" if fallback else expected)


@pytest.mark.parametrize("provider", ["local", "openai"])
@pytest.mark.parametrize("raw", [False, True])
def test_role_profile_reservation_uses_wire_input_and_actuals_release_cap(monkeypatch, tmp_path, provider, raw):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"verifier": {"model": "trusted-verifier", "max_tokens": 17, "temp": 0.1}}))
    monkeypatch.setenv("KMN_MODEL_PROFILES_FILE", str(path))
    calls = mock_transport(monkeypatch, [Response(provider_result(provider)), Response(provider_result(provider))])
    connector = KMN_AI_Connector(provider=provider, api_key="provider-test-key-123456")

    def ask():
        if raw:
            return asyncio.run(connector.ask_raw_async("system", "context \u00e9"))
        return asyncio.run(connector.ask_ai_async("context \u00e9"))

    with model_call_context("session", "verifier"):
        assert ask() is not None
        first, = connector.telemetry_store.events("session")
        payload = calls[0][1]["json"]
        inputs = {key: payload[key] for key in ("prompt", "system", "messages") if key in payload}
        estimate = len(json.dumps(inputs, ensure_ascii=False).encode("utf-8")) + 256
        assert first["model"] == payload["model"] == "trusted-verifier"
        assert first["estimated_input_tokens"] == estimate > first["input_tokens"]
        assert first["reserved_tokens"] == estimate + 17
        assert first["total_tokens"] == first["budget_tokens"] == 18
        monkeypatch.setenv("KMN_MODEL_MAX_TOKENS", str(18 + estimate + 17 - 1))
        if raw:
            assert ask() is None
        else:
            with pytest.raises(ModelBudgetExceeded):
                ask()
        assert len(calls) == 1
        blocked = connector.telemetry_store.events("session")[0]
        assert blocked["status"] == "blocked" and blocked["model"] == "trusted-verifier"
        monkeypatch.setenv("KMN_MODEL_MAX_TOKENS", str(18 + estimate + 17))
        assert ask() is not None
    summary = connector.telemetry_store.summary("session")
    assert summary["calls"] == 2 and summary["blocked"] == 1
    assert summary["total_tokens"] == summary["budget_tokens"] == 36
    assert summary["cost_usd"] is None
    assert len(calls) == 2


@pytest.mark.parametrize("provider", ["local", "openai"])
@pytest.mark.parametrize("raw", [False, True])
def test_unpriced_profile_cannot_silently_fallback_under_cost_cap(monkeypatch, tmp_path, provider, raw):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"strategist": {"model": "trusted-strategist", "max_tokens": 17}}))
    monkeypatch.setenv("KMN_MODEL_PROFILES_FILE", str(path))
    monkeypatch.setenv("KMN_MODEL_MAX_COST_USD", "1")
    calls = mock_transport(monkeypatch, [])
    connector = KMN_AI_Connector(provider=provider, api_key="provider-test-key-123456")
    with model_call_context("session", "strategist"):
        if raw:
            assert asyncio.run(connector.ask_raw_async("system", "prompt")) is None
        else:
            with pytest.raises(ModelBudgetExceeded, match="cost_budget_exceeded"):
                asyncio.run(connector.ask_ai_async("prompt"))
    event, = connector.telemetry_store.events("session")
    assert event["model"] == "trusted-strategist"
    assert event["provider"] == connector.requested_provider == connector.provider == provider
    assert event["error"] == "cost_budget_exceeded"
    assert event["cost_usd"] is event["reserved_cost_usd"] is None
    assert calls == []

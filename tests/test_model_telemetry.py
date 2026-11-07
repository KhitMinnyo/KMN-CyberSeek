from concurrent.futures import ThreadPoolExecutor
import os
import sqlite3

import pytest

from core.model_telemetry import (
    ModelBudgetExceeded, ModelTelemetryStore, current_model_context, model_call_context,
)


@pytest.fixture(autouse=True)
def clear_config(monkeypatch):
    for name in list(os.environ):
        if name.startswith("KMN_MODEL_"):
            monkeypatch.delenv(name)


def reserve(store, sid="session", **kwargs):
    metadata = dict(session_id=sid, purpose="tactical", operation_id="operation",
                    retry_ordinal=1, provider="openai", model="model",
                    estimated_input_tokens=10, max_tokens=20)
    metadata.update(kwargs)
    return store.reserve(**metadata)


def test_lazy_store_owns_its_schema_and_default_path(monkeypatch, tmp_path):
    parent_db = tmp_path / "parent.sqlite"
    monkeypatch.setenv("DB_PATH", str(parent_db))
    store = ModelTelemetryStore()
    assert store.db_path == str(tmp_path / "model_usage.sqlite")
    assert not parent_db.exists() and not (tmp_path / "model_usage.sqlite").exists()
    reserve(store)
    assert not parent_db.exists()
    with sqlite3.connect(store.db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM model_calls").fetchone()[0] == 1
    monkeypatch.setenv("KMN_MODEL_TELEMETRY_DB", str(tmp_path / "override.sqlite"))
    assert ModelTelemetryStore().db_path == str(tmp_path / "override.sqlite")


def test_durable_actual_usage_summary_events_and_purge(tmp_path, monkeypatch):
    monkeypatch.setenv("KMN_MODEL_INPUT_USD_PER_MILLION", "1")
    monkeypatch.setenv("KMN_MODEL_OUTPUT_USD_PER_MILLION", "2")
    path = tmp_path / "ledger.sqlite"
    store = ModelTelemetryStore(path)
    event = reserve(store)
    store.finish(event, latency_ms=12, result={"usage": {"prompt_tokens": 4, "completion_tokens": 6}},
                 text="private-output", parse_result="success")
    reserve(store, "other")
    reopened = ModelTelemetryStore(path)
    event, = reopened.events("session")
    assert event["total_tokens"] == event["budget_tokens"] == 10
    assert event["cost_usd"] == pytest.approx(0.000016)
    summary = reopened.summary("session")
    assert summary["calls"] == 1
    assert summary["unknown_usage_calls"] == summary["unknown_cost_calls"] == 0
    assert summary["total_tokens"] == 10
    assert reopened.summary()["calls"] == 2
    assert reopened.purge_session("session") == 1
    assert reopened.purge_session("session") == 0
    assert reopened.events("session") == []
    assert reopened.summary("other")["calls"] == 1


def test_missing_usage_and_cost_are_never_zero(tmp_path):
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    event = reserve(store)
    store.finish(event, latency_ms=0, result={}, text="answer", parse_result="invalid_json", error="invalid_json")
    event, = store.events("session")
    assert event["input_tokens"] is event["output_tokens"] is event["total_tokens"] is None
    assert event["cost_usd"] is event["estimated_cost_usd"] is None
    assert event["budget_tokens"] == 30
    assert event["estimated_output_tokens"] == 6
    summary = store.summary("session")
    assert summary["total_tokens"] is summary["cost_usd"] is None
    assert summary["unknown_usage_calls"] == summary["unknown_cost_calls"] == 1
    assert summary["errors"] == 1


@pytest.mark.parametrize("usage,expected", [
    ({"prompt_tokens": 0, "completion_tokens": 0}, (0, 0, 0)),
    ({"prompt_tokens": 5}, (5, None, None)),
    ({"total_tokens": 15}, (None, None, 15)),
    ({"prompt_tokens": -5, "completion_tokens": True}, (None, None, None)),
])
def test_usage_validation(tmp_path, usage, expected):
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    event = reserve(store)
    store.finish(event, latency_ms=1, result={"usage": usage})
    event, = store.events("session")
    assert (event["input_tokens"], event["output_tokens"], event["total_tokens"]) == expected


def test_anthropic_cache_usage_is_counted_without_guessing_price(monkeypatch, tmp_path):
    monkeypatch.setenv("KMN_MODEL_INPUT_USD_PER_MILLION", "1")
    monkeypatch.setenv("KMN_MODEL_OUTPUT_USD_PER_MILLION", "2")
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    event = reserve(store, provider="anthropic")
    store.finish(event, latency_ms=1, result={"usage": {
        "input_tokens": 3, "output_tokens": 2,
        "cache_read_input_tokens": 10, "cache_creation_input_tokens": 5,
    }})
    event, = store.events("session")
    assert (event["input_tokens"], event["total_tokens"]) == (18, 20)
    assert event["cost_usd"] is None


def test_provider_reported_cost_is_used_without_guessing_tokens(tmp_path):
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    event = reserve(store, provider="openrouter")
    store.finish(event, latency_ms=1, result={"usage": {"cost": 0.002}})
    event, = store.events("session")
    assert event["cost_usd"] == event["budget_cost_usd"] == 0.002
    assert event["total_tokens"] is None


@pytest.mark.parametrize("name", ["KMN_MODEL_MAX_CALLS", "KMN_MODEL_MAX_TOKENS", "KMN_MODEL_MAX_COST_USD"])
@pytest.mark.parametrize("value", ["", "-1", "NaN", "Infinity", "invalid"])
def test_bad_budget_config_fails_before_reservation(monkeypatch, tmp_path, name, value):
    monkeypatch.setenv(name, value)
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    with pytest.raises(ValueError, match=name):
        reserve(store)
    assert not (tmp_path / "ledger.sqlite").exists()


@pytest.mark.parametrize("name,value", [
    ("KMN_MODEL_MAX_CALLS", "1.5"), ("KMN_MODEL_MAX_TOKENS", "3.3"),
    ("KMN_MODEL_INPUT_USD_PER_MILLION", "-1"),
    ("KMN_MODEL_OUTPUT_USD_PER_MILLION", "nan"),
    ("KMN_MODEL_INPUT_USD_PER_MILLION", "1e-9999"),
])
def test_bad_integer_and_rate_config(monkeypatch, tmp_path, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=name):
        reserve(ModelTelemetryStore(tmp_path / "ledger.sqlite"))


def test_cost_cap_fails_closed_without_both_rates(monkeypatch, tmp_path):
    monkeypatch.setenv("KMN_MODEL_MAX_COST_USD", "1")
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    with pytest.raises(ModelBudgetExceeded, match="cost_budget_exceeded"):
        reserve(store)
    monkeypatch.setenv("KMN_MODEL_INPUT_USD_PER_MILLION", "1")
    with pytest.raises(ModelBudgetExceeded):
        reserve(store)
    monkeypatch.setenv("KMN_MODEL_OUTPUT_USD_PER_MILLION", "2")
    assert reserve(store) is not None
    assert store.summary("session")["blocked"] == 2


def test_enabling_cost_cap_cannot_ignore_previous_unpriced_calls(monkeypatch, tmp_path):
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    reserve(store)
    monkeypatch.setenv("KMN_MODEL_MAX_COST_USD", "1")
    monkeypatch.setenv("KMN_MODEL_INPUT_USD_PER_MILLION", "1")
    monkeypatch.setenv("KMN_MODEL_OUTPUT_USD_PER_MILLION", "1")
    with pytest.raises(ModelBudgetExceeded):
        reserve(store)


@pytest.mark.parametrize("cap,value,rates", [
    ("KMN_MODEL_MAX_CALLS", "3", False),
    ("KMN_MODEL_MAX_TOKENS", "90", False),
    ("KMN_MODEL_MAX_COST_USD", "0.000091", True),
])
def test_atomic_caps_across_store_instances(monkeypatch, tmp_path, cap, value, rates):
    monkeypatch.setenv(cap, value)
    if rates:
        monkeypatch.setenv("KMN_MODEL_INPUT_USD_PER_MILLION", "1")
        monkeypatch.setenv("KMN_MODEL_OUTPUT_USD_PER_MILLION", "1")
    path = tmp_path / "ledger.sqlite"

    def worker(_):
        try:
            reserve(ModelTelemetryStore(path))
            return True
        except ModelBudgetExceeded:
            return False

    with ThreadPoolExecutor(max_workers=10) as pool:
        assert sum(pool.map(worker, range(24))) == 3
    summary = ModelTelemetryStore(path).summary("session")
    assert summary["calls"] == summary["pending"] == 3
    assert summary["blocked"] == 21
    assert summary["budget_tokens"] == 90


def test_actuals_release_reservation_but_unknown_failures_do_not(monkeypatch, tmp_path):
    monkeypatch.setenv("KMN_MODEL_MAX_TOKENS", "40")
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    event = reserve(store)
    with pytest.raises(ModelBudgetExceeded):
        reserve(store)
    store.finish(event, latency_ms=1, result={"usage": {"prompt_tokens": 4, "completion_tokens": 6}})
    failure = reserve(store)
    store.finish(failure, latency_ms=1, error="transport_error")
    with pytest.raises(ModelBudgetExceeded):
        reserve(store)
    assert store.summary("session")["budget_tokens"] == 40
    assert reserve(store, sid="separate-session") is not None


def test_zero_caps_block_and_zero_prices_are_explicit(monkeypatch, tmp_path):
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    monkeypatch.setenv("KMN_MODEL_MAX_CALLS", "0")
    with pytest.raises(ModelBudgetExceeded):
        reserve(store)
    monkeypatch.delenv("KMN_MODEL_MAX_CALLS")
    monkeypatch.setenv("KMN_MODEL_MAX_COST_USD", "0")
    with pytest.raises(ModelBudgetExceeded):
        reserve(store)
    monkeypatch.setenv("KMN_MODEL_INPUT_USD_PER_MILLION", "0")
    monkeypatch.setenv("KMN_MODEL_OUTPUT_USD_PER_MILLION", "0")
    event = reserve(store)
    store.finish(event, latency_ms=1, result={"usage": {"prompt_tokens": 1, "completion_tokens": 1}})
    assert store.events("session")[0]["cost_usd"] == 0


def test_context_nesting_exception_and_validation():
    with model_call_context("outer", "tactical", "outer-op"):
        assert current_model_context() == ("outer", "tactical", "outer-op")
        with pytest.raises(RuntimeError):
            with model_call_context("inner", "verifier", "inner-op"):
                assert current_model_context()[0] == "inner"
                raise RuntimeError()
        assert current_model_context() == ("outer", "tactical", "outer-op")
        assert current_model_context("override")[0] == "override"
    assert current_model_context()[0] is None
    with pytest.raises(ValueError):
        with model_call_context("session", "unsupported"):
            pass


@pytest.mark.parametrize("limit", [0, -1, True, 10001, "10"])
def test_event_limit_is_strict(tmp_path, limit):
    with pytest.raises(ValueError):
        ModelTelemetryStore(tmp_path / "ledger.sqlite").events("session", limit)


def test_ephemeral_sqlite_paths_are_rejected():
    with pytest.raises(ValueError, match="durable"):
        ModelTelemetryStore(":memory:")


def test_purge_cannot_reuse_an_inflight_reservation_id(tmp_path):
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    old = reserve(store)
    store.purge_session("session")
    new = reserve(store, "other")
    assert new > old
    with pytest.raises(RuntimeError, match="no longer exists"):
        store.finish(old, latency_ms=1)
    assert store.events("other")[0]["status"] == "pending"


def test_actual_cost_releases_reservation_using_rates_at_admission(monkeypatch, tmp_path):
    monkeypatch.setenv("KMN_MODEL_INPUT_USD_PER_MILLION", "1")
    monkeypatch.setenv("KMN_MODEL_OUTPUT_USD_PER_MILLION", "2")
    monkeypatch.setenv("KMN_MODEL_MAX_COST_USD", "0.00006")
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    event_id = reserve(store)
    with pytest.raises(ModelBudgetExceeded, match="cost_budget_exceeded"):
        reserve(store)
    monkeypatch.setenv("KMN_MODEL_INPUT_USD_PER_MILLION", "100")
    monkeypatch.setenv("KMN_MODEL_OUTPUT_USD_PER_MILLION", "200")
    store.finish(event_id, latency_ms=1, result={"usage": {"prompt_tokens": 2, "completion_tokens": 3}}, text="output")
    event = next(event for event in store.events("session") if event["id"] == event_id)
    assert event["reserved_cost_usd"] == pytest.approx(0.00005)
    assert event["cost_usd"] == event["budget_cost_usd"] == pytest.approx(0.000008)
    assert event["estimated_cost_usd"] != event["cost_usd"]
    with pytest.raises(ModelBudgetExceeded, match="cost_budget_exceeded"):
        reserve(store)
    monkeypatch.setenv("KMN_MODEL_INPUT_USD_PER_MILLION", "1")
    monkeypatch.setenv("KMN_MODEL_OUTPUT_USD_PER_MILLION", "2")
    assert reserve(store) is not None


def test_partial_usage_retains_cost_and_token_reservations(monkeypatch, tmp_path):
    monkeypatch.setenv("KMN_MODEL_INPUT_USD_PER_MILLION", "1")
    monkeypatch.setenv("KMN_MODEL_OUTPUT_USD_PER_MILLION", "2")
    monkeypatch.setenv("KMN_MODEL_MAX_COST_USD", "0.00006")
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    event_id = reserve(store)
    store.finish(event_id, latency_ms=1, result={"usage": {"prompt_tokens": 2}}, text="output")
    event, = store.events("session")
    assert event["input_tokens"] == 2
    assert event["output_tokens"] is event["total_tokens"] is event["cost_usd"] is None
    assert event["budget_tokens"] == event["reserved_tokens"] == 30
    assert event["budget_cost_usd"] == event["reserved_cost_usd"] == pytest.approx(0.00005)
    with pytest.raises(ModelBudgetExceeded, match="cost_budget_exceeded"):
        reserve(store)


def test_actual_usage_above_reservation_blocks_further_calls(monkeypatch, tmp_path):
    monkeypatch.setenv("KMN_MODEL_MAX_TOKENS", "40")
    store = ModelTelemetryStore(tmp_path / "ledger.sqlite")
    event_id = reserve(store)
    store.finish(event_id, latency_ms=1, result={"usage": {"prompt_tokens": 30, "completion_tokens": 20}})
    event, = store.events("session")
    assert event["reserved_tokens"] == 30
    assert event["budget_tokens"] == event["total_tokens"] == 50
    with pytest.raises(ModelBudgetExceeded, match="token_budget_exceeded"):
        reserve(store)

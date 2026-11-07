"""Readiness evaluation remains strictly offline."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.preflight import evaluate_preflight


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("KMN_EXECUTION_BACKEND", "local")
    monkeypatch.setenv("AI_PROVIDER", "local")
    monkeypatch.setenv("SCOPE_ALLOWLIST", "")
    monkeypatch.setattr("shutil.which", lambda tool: "/tools/" + tool)
    monkeypatch.setattr("subprocess.run", Mock(side_effect=AssertionError("Must remain offline")))
    monkeypatch.setattr("socket.create_connection", Mock(side_effect=AssertionError("Must remain offline")))


def evaluate(**kwargs):
    return evaluate_preflight(**{"target": "127.0.0.1", "authorization_confirmed": True,
                                 "connector": SimpleNamespace(provider="local", ollama_url="http://localhost:11434"),
                                 **kwargs})


def test_ready_is_configuration_not_live_probe():
    assert evaluate()["ready"] is True


@pytest.mark.parametrize("kwargs,check", [({"target": ";touch bad"}, "target"),
    ({"authorization_confirmed": False}, "authorization"),
    ({"scope_allowlist": "10.0.0.0/8"}, "scope")])
def test_required_gates(kwargs, check):
    result = evaluate(**kwargs)
    assert not result["ready"]
    assert not next(c for c in result["checks"] if c["name"] == check)["ready"]


def test_optional_tools_warn_but_nmap_blocks(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda tool: "/tools/nmap" if tool == "nmap" else None)
    result = evaluate()
    assert result["ready"]
    assert any(c["status"] == "warning" for c in result["checks"])
    monkeypatch.setattr("shutil.which", lambda tool: None)
    assert not evaluate()["ready"]


def test_injected_scanner_owns_its_toolchain(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda tool: None)
    assert evaluate(scanner=SimpleNamespace())["ready"]


def test_requested_provider_cannot_silently_fallback():
    result = evaluate(connector=SimpleNamespace(provider="local", requested_provider="openai", ollama_url="url"))
    assert not result["ready"]
    assert result["provider"] == {"requested": "openai", "effective": "local", "ready": False}


def test_shipped_connector_without_retained_request_fails_closed():
    from ai.connector import KMN_AI_Connector
    connector = KMN_AI_Connector.__new__(KMN_AI_Connector)
    connector.provider = "local"
    connector.ollama_url = "http://localhost:11434"
    result = evaluate(connector=connector)
    assert not result["ready"] and result["provider"]["requested"] is None
    connector.requested_provider = "local"
    assert evaluate(connector=connector)["ready"]


def test_provider_key_and_disabled_provider(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "openai")
    assert not evaluate(connector=SimpleNamespace(provider="openai", api_key=""))["ready"]
    assert not evaluate(connector=SimpleNamespace(provider="none", requested_provider="openai"))["ready"]


def test_explicit_none_provider_is_ready_without_model_credentials():
    result = evaluate(connector=SimpleNamespace(provider="none", requested_provider="none", ready=False))
    assert result["ready"] and result["provider"]["ready"]
    assert result["provider"] == {"requested": "none", "effective": "none", "ready": True}
    assert "Deterministic" in next(c for c in result["checks"] if c["name"] == "provider")["detail"]


def test_connector_provider_identity_is_not_shadowed_by_environment(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "openai")
    assert evaluate(connector=SimpleNamespace(provider="none"))["ready"]


def test_production_connector_request_metadata_and_deterministic_mode(monkeypatch):
    from ai.connector import KMN_AI_Connector
    monkeypatch.setattr("ai.connector.load_dotenv", lambda **kwargs: None)
    monkeypatch.setenv("OPENAI_API_KEY", "")
    connector = KMN_AI_Connector(provider="openai", api_key="")
    result = evaluate(connector=connector)
    assert result["provider"] == {"requested": "openai", "effective": "local", "ready": False}
    assert not result["ready"]
    deterministic = KMN_AI_Connector(provider="none")
    assert evaluate(connector=deterministic)["ready"]


def test_docker_requires_plan_network_and_tool_attestation(monkeypatch):
    monkeypatch.setenv("KMN_EXECUTION_BACKEND", "docker")
    assert not evaluate()["ready"]
    monkeypatch.setenv("KMN_DOCKER_IMAGE", "preprovisioned:test")
    assert not evaluate()["ready"]
    monkeypatch.setenv("KMN_DOCKER_NETWORK", "scope-restricted")
    monkeypatch.setenv("KMN_DOCKER_NETWORK_POLICY_ATTESTED", "true")
    monkeypatch.setenv("KMN_DOCKER_TOOLS_ATTESTED", "true")
    assert evaluate()["ready"]

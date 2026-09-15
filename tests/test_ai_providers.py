from ai.connector import KMN_AI_Connector


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

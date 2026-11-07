"""Offline browser contract tests. All Playwright objects are local fakes."""

import asyncio
import builtins
import importlib
import json
import socket
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from core import browser_observer as module
from core.browser_observer import BrowserObserverError, observe_navigation


class Request:
    def __init__(self, url="https://lab.test/page", method="GET", status=200,
                 headers=None, post_data=None):
        self.url, self.method, self.status = url, method, status
        self.headers = headers or {"Cookie": "session=secret", "X-Api-Key": "secret"}
        self.post_data = post_data
        self.frame = None

    def is_navigation_request(self):
        return self.frame is not None


class Route:
    def __init__(self, request):
        self.request = request
        self.aborted = self.fulfilled = self.disposed = False
        self.fetch_options = None

    async def abort(self):
        self.aborted = True

    async def fetch(self, **kwargs):
        self.fetch_options = kwargs
        return SimpleNamespace(status=self.request.status, dispose=self.dispose)

    async def dispose(self):
        self.disposed = True

    async def fulfill(self, **kwargs):
        self.fulfilled = True


class FakePlaywright:
    def __init__(self, requests=None, hang=False, no_websocket=False):
        self.requests = [Request()] if requests is None else requests
        self.routes, self.sockets = [], []
        self.closed = []
        self.hang = hang
        self.entered = None
        self.main_frame = object()
        if no_websocket:
            self.route_web_socket = None

    def factory(self):
        return self

    async def start(self):
        return SimpleNamespace(chromium=self, stop=self.stop)

    async def launch(self, **kwargs):
        self.launch_options = kwargs
        return self

    async def new_context(self, **kwargs):
        self.context_options = kwargs
        return self

    async def route(self, pattern, handler):
        assert pattern == "**/*"
        self.handler = handler

    async def route_web_socket(self, pattern, handler):
        assert pattern == "**/*"
        self.socket_handler = handler

    async def new_page(self):
        return self

    async def goto(self, url, **kwargs):
        self.target, self.goto_options = url, kwargs
        if self.entered is not None:
            self.entered.set()
        for index, request in enumerate(self.requests):
            if index == 0:
                request.frame = self.main_frame
            route = Route(request)
            self.routes.append(route)
            await self.handler(route)
        if self.hang:
            await asyncio.Event().wait()

    async def close(self):
        self.closed.append("close")

    async def stop(self):
        self.closed.append("stop")


def options(fake, **kwargs):
    return dict(authorized=True, scope_allowlist="lab.test,assets.test",
                sandbox_id="dedicated-lab", network_policy_attested=True,
                playwright_factory=fake.factory, **kwargs)


@pytest.fixture(autouse=True)
def no_real_playwright(monkeypatch):
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name == "playwright" or name.startswith("playwright."):
            raise ImportError("Real Playwright is forbidden in offline tests")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)

    def deny_network(*args, **kwargs):
        pytest.fail("Actual network access is forbidden in browser observer tests")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)


@pytest.mark.parametrize("changes", [
    {"authorized": False}, {"authorized": 1}, {"scope_allowlist": None},
    {"scope_allowlist": ""}, {"scope_allowlist": " "}, {"scope_allowlist": ","},
    {"scope_allowlist": "lab.test,"}, {"scope_allowlist": "other.test"},
    {"network_policy_attested": False}, {"network_policy_attested": 1},
    {"sandbox_id": None}, {"sandbox_id": "host network"}, {"max_requests": True},
    {"max_requests": 0}, {"max_requests": 1001}, {"wall_seconds": 0},
    {"wall_seconds": float("nan")}, {"wall_seconds": float("inf")},
    {"wall_seconds": True}, {"wall_seconds": 301}, {"role": "token secret"},
    {"credential_ref": "Bearer secret"}, {"credential_ref": "env:TOKEN"},
    {"credential_resolver": lambda ref: {}},
])
def test_policy_rejected_before_browser_start(changes):
    fake = FakePlaywright()
    config = options(fake)
    config.update(changes)
    with pytest.raises(BrowserObserverError):
        asyncio.run(observe_navigation("https://lab.test/page", **config))
    assert not hasattr(fake, "launch_options")


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "data:text/html,secret", "blob:https://lab.test/id",
    "javascript:alert(1)", "ftp://lab.test/a", "ws://lab.test/socket",
    "https://user:secret@lab.test/", "https://lab.test:0/", "https://evil.test/",
    "https://lab.test/%252e%252e/private", "https://lab.test//evil.test",
    "https://lab.test/a\\b", "https://lab.test/a\n", "https://lab.test/#secret",
    "https://lab.test/?token=secret\r\nHeader:x", "/relative",
])
def test_invalid_full_urls_rejected(url):
    fake = FakePlaywright()
    with pytest.raises(BrowserObserverError):
        asyncio.run(observe_navigation(url, **options(fake)))


def test_lazy_dependency_and_missing_installation():
    spec = importlib.util.spec_from_file_location("offline_observer", module.__file__)
    isolated = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(isolated)
    config = options(FakePlaywright())
    del config["playwright_factory"]
    with pytest.raises(BrowserObserverError, match="Install optional Playwright"):
        asyncio.run(observe_navigation("https://lab.test/", **config))


def test_navigation_normalization_scope_api_and_metadata(monkeypatch):
    original = module.validate_base_url
    checked = []

    def validate(url, scope):
        checked.append((url, scope))
        return original(url, scope)

    monkeypatch.setattr(module, "validate_base_url", validate)
    fake = FakePlaywright()
    result = asyncio.run(observe_navigation(
        "https://LAB.test:443/page/?token=do-not-export", **options(fake)))
    assert fake.target == "https://lab.test/page/?token=do-not-export"
    assert len(checked) == 2
    assert all(scope == "lab.test,assets.test" for _, scope in checked)
    assert result.outcome == "observed"
    assert result.navigation_status == 200
    assert result.requests_allowed == 1
    assert fake.launch_options == dict(headless=True, chromium_sandbox=True, env={})
    assert fake.context_options == dict(service_workers="block", java_script_enabled=False,
                                        accept_downloads=False)
    assert fake.closed == ["close", "close", "stop"]
    serialized = json.dumps(asdict(result))
    for secret in ("lab.test", "page", "token", "secret", "do-not-export"):
        assert secret not in serialized


def test_every_context_request_is_gated_and_redirects_never_followed():
    requests = [Request(), Request("https://assets.test/image"),
                Request("https://evil.test/popup"), Request("file:///etc/passwd"),
                Request("data:text/html,anything"), Request("https://lab.test/%2e%2e/admin"),
                Request(method="POST"), Request(post_data="secret"),
                Request("https://lab.test/redirect", status=302)]
    fake = FakePlaywright(requests)
    result = asyncio.run(observe_navigation("https://lab.test/", **options(fake)))
    assert result.requests_seen == 9
    assert result.requests_allowed == 3
    assert result.requests_blocked == 7
    assert result.redirects_blocked == 1
    assert [r.fulfilled for r in fake.routes] == [True, True] + [False] * 7
    for route in fake.routes:
        if route.fetch_options is not None:
            assert route.fetch_options["max_redirects"] == 0
            assert route.fetch_options["max_retries"] == 0
            assert route.disposed


def test_credentials_only_authorization_only_target_origin_and_no_export():
    async def resolve(reference):
        assert reference == "vault:reader"
        return {"Authorization": "Bearer super-secret"}

    fake = FakePlaywright([Request(), Request("https://assets.test/image"),
                           Request("http://lab.test/image"), Request("https://lab.test:8443/image"),
                           Request("https://lab.test/another")])
    result = asyncio.run(observe_navigation("https://lab.test/", **options(
        fake, role="reader", credential_ref="vault:reader", credential_resolver=resolve)))
    for index, route in enumerate(fake.routes):
        headers = route.fetch_options["headers"]
        assert headers == {"cookie": "", "authorization":
                           "Bearer super-secret" if index in {0, 4} else ""}
    assert "super-secret" not in repr(result)
    assert "vault:reader" not in repr(result)


@pytest.mark.parametrize("resolved", [
    {"Cookie": "secret"}, {"Authorization": "ok", "X-Api-Key": "secret"},
    {}, {"Authorization": "secret\r\nInjected:x"}, {"Authorization": " "},
    {"Authorization": 42}, {"Authorization": "x" * 4097}, "literal-secret",
])
def test_invalid_resolver_output_does_not_launch(resolved):
    async def resolve(reference):
        return resolved

    fake = FakePlaywright()
    result = asyncio.run(observe_navigation("https://lab.test/", **options(
        fake, credential_ref="env:READER", credential_resolver=resolve)))
    assert result.outcome == "failed"
    assert not hasattr(fake, "launch_options")
    assert "secret" not in repr(result)


def test_request_budget_and_websocket_blocking():
    class WithWebSocket(FakePlaywright):
        async def goto(self, *args, **kwargs):
            await super().goto(*args, **kwargs)
            await self.socket_handler(SimpleNamespace(close=close_socket))

    async def scenario():
        fake = WithWebSocket([Request(), Request(), Request()])
        result = await observe_navigation("https://lab.test/", **options(fake, max_requests=1))
        assert result.outcome == "budget_exceeded"
        assert result.requests_allowed == 1
        assert result.requests_blocked == 2
        assert result.websockets_blocked == 1

    closed = []

    async def close_socket():
        closed.append(True)

    asyncio.run(scenario())
    assert closed == [True]


def test_old_playwright_fails_closed_before_navigation():
    fake = FakePlaywright(no_websocket=True)
    result = asyncio.run(observe_navigation("https://lab.test/", **options(fake)))
    assert result.outcome == "failed"
    assert not fake.routes
    assert fake.closed == ["close", "close", "stop"]


def test_timeout_and_cancellation_cleanup():
    async def scenario():
        fake = FakePlaywright(hang=True)
        result = await observe_navigation("https://lab.test/", **options(fake, wall_seconds=0.02))
        assert result.outcome == "timed_out"
        assert fake.closed == ["close", "close", "stop"]
        fake = FakePlaywright(hang=True)
        fake.entered = asyncio.Event()
        task = asyncio.create_task(observe_navigation("https://lab.test/", **options(fake)))
        await fake.entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert fake.closed == ["close", "close", "stop"]

    asyncio.run(scenario())


def test_browser_failure_is_sanitized_and_cleanup_failure_is_visible():
    class Broken(FakePlaywright):
        async def goto(self, *args, **kwargs):
            raise RuntimeError("Authorization: secret https://lab.test/private")

        async def close(self):
            self.closed.append("close")
            raise RuntimeError("secret cleanup error")

    fake = Broken()
    result = asyncio.run(observe_navigation("https://lab.test/", **options(fake)))
    assert result.outcome == "cleanup_failed"
    assert "secret" not in repr(result)
    assert fake.closed == ["close", "close", "stop"]


def test_interception_failure_aborts_without_fallback(monkeypatch):
    async def broken_fetch(self, **kwargs):
        raise RuntimeError("Bearer secret; response body must not escape")

    monkeypatch.setattr(Route, "fetch", broken_fetch)
    fake = FakePlaywright()
    result = asyncio.run(observe_navigation("https://lab.test/", **options(fake)))
    assert result.outcome == "failed"
    assert fake.routes[0].aborted
    assert not fake.routes[0].fulfilled
    assert "secret" not in repr(result)
    assert fake.closed == ["close", "close", "stop"]


def test_resolver_timeout_and_failure_are_sanitized_before_launch():
    async def scenario():
        async def hanging(reference):
            await asyncio.Event().wait()

        async def broken(reference):
            raise RuntimeError("vault resolved secret")

        for resolver, expected in ((hanging, "timed_out"), (broken, "failed")):
            fake = FakePlaywright()
            result = await observe_navigation("https://lab.test/", **options(
                fake, wall_seconds=0.02, credential_ref="env:READER",
                credential_resolver=resolver))
            assert result.outcome == expected
            assert not hasattr(fake, "launch_options")
            assert "secret" not in repr(result)

    asyncio.run(scenario())


def test_repeated_cancellation_does_not_interrupt_cleanup():
    async def scenario():
        entered, closing, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

        class SlowClose(FakePlaywright):
            async def close(self):
                closing.set()
                await release.wait()
                await super().close()

        fake = SlowClose(hang=True)
        fake.entered = entered
        task = asyncio.create_task(observe_navigation("https://lab.test/", **options(fake)))
        await entered.wait()
        task.cancel()
        await closing.wait()
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert fake.closed == ["close", "close", "stop"]

    asyncio.run(scenario())


def test_context_creation_failure_still_closes_browser_and_driver():
    class BrokenContext(FakePlaywright):
        async def new_context(self, **kwargs):
            raise RuntimeError("secret")

    fake = BrokenContext()
    result = asyncio.run(observe_navigation("https://lab.test/", **options(fake)))
    assert result.outcome == "failed"
    assert fake.closed == ["close", "stop"]


@pytest.mark.parametrize("status", [300, 301, 302, 303, 304, 307, 308])
def test_all_redirect_responses_are_aborted(status):
    fake = FakePlaywright([Request(status=status)])
    result = asyncio.run(observe_navigation("https://lab.test/", **options(fake)))
    assert result.redirects_blocked == 1
    assert fake.routes[0].aborted
    assert not fake.routes[0].fulfilled
    assert fake.routes[0].fetch_options["max_redirects"] == 0


def test_ipv6_cidr_scope_and_head_subresource():
    fake = FakePlaywright([Request("http://[::1]:8000/path/"),
                           Request("http://[::1]:8000/asset", method="HEAD")])
    config = options(fake)
    config["scope_allowlist"] = "::1/128"
    result = asyncio.run(observe_navigation("http://[::1]:8000/path/", **config))
    assert result.outcome == "observed"
    assert result.requests_allowed == 2
    assert fake.target == "http://[::1]:8000/path/"


def test_cancellation_during_launch_stops_driver():
    async def scenario():
        entered = asyncio.Event()

        class SlowLaunch(FakePlaywright):
            async def launch(self, **kwargs):
                entered.set()
                await asyncio.Event().wait()

        fake = SlowLaunch()
        task = asyncio.create_task(observe_navigation("https://lab.test/", **options(fake)))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert fake.closed == ["stop"]

    asyncio.run(scenario())

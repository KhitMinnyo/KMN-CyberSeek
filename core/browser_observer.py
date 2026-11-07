"""Optional, read-only browser observation inside an externally enforced sandbox."""

import asyncio
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from core.assessment import AssessmentError, validate_base_url


class BrowserObserverError(AssessmentError):
    """A fixed, secret-free browser policy or dependency error."""


@dataclass(frozen=True)
class BrowserObservation:
    """No URLs, page content, headers, credentials, or raw errors are retained."""

    outcome: str
    navigation_status: int = None
    requests_seen: int = 0
    requests_allowed: int = 0
    requests_blocked: int = 0
    redirects_blocked: int = 0
    websockets_blocked: int = 0


def _url(value, scope):
    # Validate the complete path with assessment's existing traversal rules.
    # Queries are permitted for navigation, but are never included in output.
    if (not isinstance(value, str) or len(value) > 4096
            or re.search(r"[\s\\\x00-\x1f\x7f]", value) or "#" in value):
        raise BrowserObserverError("Invalid observation URL")
    try:
        parts = urlsplit(value)
        base = validate_base_url(
            urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")), scope)
        checked = urlsplit(base)
    except ValueError:
        raise BrowserObserverError("Invalid or out-of-scope observation URL") from None
    return urlunsplit((checked.scheme, checked.netloc, parts.path or "/", parts.query, ""))


async def observe_navigation(
    url, *, authorized=False, scope_allowlist=None, sandbox_id=None,
    network_policy_attested=False, role="anonymous", credential_ref=None,
    credential_resolver=None, max_requests=50, wall_seconds=15.0,
    playwright_factory=None,
):
    """Observe one GET navigation, never interact with the page or verify findings.

    The caller must run this process in a dedicated disposable sandbox whose
    externally enforced egress policy matches scope_allowlist. The attestation
    is an operator assertion, NOT a sandbox implementation or proof. The optional
    factory is a trusted async_playwright replacement for offline testing only.
    The optional async resolver receives an opaque credential reference and must
    return exactly one Authorization header. No environment lookup is performed.
    """
    if authorized is not True:
        raise BrowserObserverError("Explicit staging/lab authorization is required")
    if not isinstance(scope_allowlist, str) or not scope_allowlist.strip():
        raise BrowserObserverError("An explicit nonempty scope allowlist is required")
    if (network_policy_attested is not True or not isinstance(sandbox_id, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", sandbox_id)):
        raise BrowserObserverError("A dedicated externally enforced sandbox must be attested")
    if not isinstance(role, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", role):
        raise BrowserObserverError("Expected an opaque role identifier")
    if (credential_ref is not None and
            (not isinstance(credential_ref, str) or not re.fullmatch(
                r"(?:env|vault|keyring):[A-Za-z0-9_./-]{1,160}", credential_ref))):
        raise BrowserObserverError("Expected an opaque credential reference")
    if (credential_ref is None) != (credential_resolver is None):
        raise BrowserObserverError("A credential reference and resolver must be supplied together")
    if credential_resolver is not None and not callable(credential_resolver):
        raise BrowserObserverError("Expected an async credential resolver")
    if (type(max_requests) is not int or not 1 <= max_requests <= 1000
            or isinstance(wall_seconds, bool) or not isinstance(wall_seconds, (int, float))
            or not math.isfinite(wall_seconds) or not 0 < wall_seconds <= 300):
        raise BrowserObserverError("Invalid browser time or request budget")
    target = _url(url, scope_allowlist)
    target_origin = urlsplit(target)[:2]
    if playwright_factory is None:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise BrowserObserverError("Install optional Playwright and Chromium manually") from None
        playwright_factory = async_playwright

    playwright = browser = context = None
    auth = None
    closing = False
    outcome, navigation_status = "failed", None
    counts = dict(requests_seen=0, requests_allowed=0, requests_blocked=0,
                  redirects_blocked=0, websockets_blocked=0)
    budget_exhausted = False
    policy_failed = False
    deadline = time.monotonic() + wall_seconds

    async def handle_request(route):
        nonlocal budget_exhausted, policy_failed, navigation_status
        counts["requests_seen"] += 1
        response = None
        try:
            if closing or time.monotonic() >= deadline or counts["requests_seen"] > max_requests:
                budget_exhausted = True
                counts["requests_blocked"] += 1
                await route.abort()
                return
            request = route.request
            try:
                checked = _url(request.url, scope_allowlist)
            except BrowserObserverError:
                counts["requests_blocked"] += 1
                await route.abort()
                return
            if request.method not in {"GET", "HEAD"} or request.post_data is not None:
                counts["requests_blocked"] += 1
                await route.abort()
                return
            # Never inherit cookies, proxy credentials, or arbitrary secret headers.
            headers = {k.lower(): v for k, v in request.headers.items()
                       if k.lower() in {"accept", "accept-language", "user-agent"}}
            headers.update({"cookie": "", "authorization": ""})
            if auth is not None and urlsplit(checked)[:2] == target_origin:
                headers["authorization"] = auth
            counts["requests_allowed"] += 1
            # route.continue_ does NOT gate every hop of a browser redirect chain.
            # Fetch without redirects, and never deliver a redirect to the browser.
            response = await route.fetch(
                headers=headers, max_redirects=0, max_retries=0,
                timeout=max(1, int((deadline - time.monotonic()) * 1000)))
            if 300 <= response.status < 400:
                counts["redirects_blocked"] += 1
                counts["requests_blocked"] += 1
                await route.abort()
                return
            if request.is_navigation_request() and request.frame == page.main_frame:
                navigation_status = response.status
            await route.fulfill(response=response)
        except asyncio.CancelledError:
            raise
        except Exception:
            policy_failed = True
            counts["requests_blocked"] += 1
            # No fallback to continue_: an interception failure must deny traffic.
            try:
                await route.abort()
            except Exception:
                pass
        finally:
            if response is not None:
                try:
                    await response.dispose()
                except Exception:
                    policy_failed = True

    async def block_websocket(socket):
        nonlocal policy_failed
        counts["websockets_blocked"] += 1
        try:
            await socket.close()
        except Exception:
            policy_failed = True

    async def run():
        nonlocal playwright, browser, context, auth, page
        if credential_resolver is not None:
            resolved = await credential_resolver(credential_ref)
            if (not isinstance(resolved, Mapping) or len(resolved) != 1
                    or any(not isinstance(k, str) or k.lower() != "authorization" for k in resolved)):
                raise BrowserObserverError("Resolver may supply only Authorization")
            auth = next(iter(resolved.values()))
            if (not isinstance(auth, str) or not re.fullmatch(r"[\x20-\x7e]{1,4096}", auth)
                    or not auth.strip()):
                raise BrowserObserverError("Invalid resolved Authorization header")
        manager = playwright_factory()
        playwright = await manager.start()
        browser = await playwright.chromium.launch(
            headless=True, chromium_sandbox=True, env={})
        context = await browser.new_context(
            service_workers="block", java_script_enabled=False, accept_downloads=False)
        if not callable(getattr(context, "route_web_socket", None)):
            raise BrowserObserverError("Playwright WebSocket routing support is required")
        # Context-wide routes also cover frames, subresources and popup first requests.
        await context.route("**/*", handle_request)
        await context.route_web_socket("**/*", block_websocket)
        page = await context.new_page()
        await page.goto(target, wait_until="domcontentloaded",
                        timeout=max(1, int((deadline - time.monotonic()) * 1000)))

    async def cleanup():
        nonlocal closing, auth
        closing, auth = True, None
        failed = False
        for resource, method in ((context, "close"), (browser, "close"),
                                 (playwright, "stop")):
            if resource is not None:
                try:
                    await asyncio.wait_for(getattr(resource, method)(), timeout=5)
                except Exception:
                    failed = True
        return failed

    page = None
    cleanup_failed = False
    try:
        await asyncio.wait_for(run(), timeout=wall_seconds)
        outcome = "observed"
    except asyncio.TimeoutError:
        outcome = "timed_out"
    except asyncio.CancelledError:
        raise
    except Exception:
        # Browser and resolver errors can contain tokens, URLs and response content.
        outcome = "failed"
    finally:
        task = asyncio.create_task(cleanup())
        # Repeated caller cancellation must not abandon context/browser teardown.
        cancelled = False
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                cancelled = True
        cleanup_failed = task.result()
        if cancelled:
            raise asyncio.CancelledError
    if cleanup_failed:
        outcome = "cleanup_failed"
    elif policy_failed:
        outcome = "failed"
    elif budget_exhausted:
        outcome = "budget_exceeded"
    return BrowserObservation(outcome, navigation_status, **counts)

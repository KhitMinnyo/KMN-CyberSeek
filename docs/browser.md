# Optional Browser Observation

`core/browser_observer.py` provides an opt-in async Playwright adapter for one
explicitly authorized staging/lab navigation. It is not wired into the scanner,
CLI, orchestrator, or assessment verification ledger. It performs no exploits,
payload generation, clicks, form submissions, crawling, login automation, or
business-logic verification. Even GET requests can have server-side effects:
use only approved read-only lab endpoints.

## Required Isolation

**Routing is defense in depth, not browser network containment.** Before use,
run the entire Python/Playwright process inside a dedicated disposable sandbox
with externally enforced network isolation. Supply `authorized=True`, an explicit
nonempty `scope_allowlist`, an opaque `sandbox_id`, and
`network_policy_attested=True`. These are trusted operator inputs, never model
output or page content. There is no unrestricted mode or implicit environment
scope. The attestation is an assertion, not cryptographic proof or automatic
policy verification. This module does not create a container or firewall.

The external boundary must deny all unauthorized IPv4/IPv6 destinations,
protocols, host interfaces, neighboring containers, cloud metadata, proxies,
public internet, and alternate routes. Permit only controlled DNS and authorized
lab destinations/ports. Test denials from the actual sandbox. DNS rebinding,
browser DNS/prefetch/internal connections, browser vulnerabilities and protocols
that Playwright does not intercept are not contained by Python routing.
Hostname scope is lexical, not DNS resolution or IP pinning. Apply OS/container
CPU, memory, process, filesystem and hard lifetime limits too. Browser binaries,
the launcher, the resolver, and the sandbox policy must be trusted.

Chromium's sandbox is explicitly enabled. Do not disable it to work around a
host configuration problem. The browser receives an empty launch environment;
provision browser assets in the sandbox and avoid ambient secrets. No user
profile, storage state, launch arguments, proxy, persistent context, CDP endpoint,
or external browser can be supplied.

## Installation

Nothing imports Playwright until an authorized, validated call needs it. It is
not a mandatory project dependency. Inside the dedicated sandbox, manually
install a reviewed Playwright version with context WebSocket routing and
`route.fetch(max_retries=...)` support (Playwright 1.48 or newer), and Chromium:

```sh
python -m pip install 'playwright>=1.48'
python -m playwright install chromium
```

Provision any required Chromium OS libraries separately. Prefer a pinned,
reviewed image and package version. Installation may require network access;
perform it during image preparation, not during a scoped observation.

## API

Inside a trusted caller's async function, after provisioning and testing the
external boundary for this exact invocation:

```python
from core.browser_observer import observe_navigation

result = await observe_navigation(
    "https://staging.example.test/catalog?view=summary",
    authorized=True,
    scope_allowlist="staging.example.test",
    sandbox_id="isolated-staging-observer",
    network_policy_attested=True,
    max_requests=40,
    wall_seconds=15,
)
```

Authorization and attestation must be literal booleans. Scope uses the existing
`assessment.validate_base_url` / `validators.is_target_in_scope` host rules:
exact hosts, IPs, CIDRs and DNS wildcards. Paths are validated in full using the
existing traversal/encoding rules, but scope is **not a URL-path or port ACL**.
HTTP(S) origins and default ports are normalized. Queries are accepted but never
exported. Credentials in URL authorities, fragments, control characters,
ambiguous delimiters, unsafe paths and non-HTTP(S) destinations are rejected.
External network policy must supply any narrower port/IP restrictions.

Every intercepted context request, including frames, subresources and popup
first requests, is checked. Only GET/HEAD without request bodies are allowed.
JavaScript and service workers are disabled, downloads are not accepted, and
all WebSockets are closed without connecting to their servers. All intercepted
non-HTTP(S) requests, including data/blob/file schemes, are denied. Some in-memory
browser URLs such as its initial `about:blank` are not routed; this does not grant
network permission and is another reason routing alone is not containment.

**Redirects are deliberately unsupported, even within scope.** Playwright's
ordinary route continuation does not recheck every redirect hop. Instead, this
adapter uses `route.fetch(max_redirects=0, max_retries=0)` and aborts every 3xx
response rather than delivering it to the browser. It never calls `continue_`
or connects a WebSocket route to its server. A fresh context is used per call;
context routing also disables the HTTP cache.

## Role Credentials

The optional `role` is an opaque label. Credentials must be supplied only as an
opaque `credential_ref` (`env:`, `vault:` or `keyring:` syntax) paired with a
trusted async `credential_resolver(reference)`. The adapter does not read the
environment or resolve secrets itself. The resolver must return exactly one
header, `Authorization`, with a nonempty printable ASCII value. No Cookie,
Proxy-Authorization, custom auth headers, login scripts or arbitrary headers
are allowed. Resolver failures return fixed failure metadata, not raw errors.

The header is injected only into requests to the initial target's exact
normalized scheme/host/port origin, not other scoped origins. Inherited headers
are reduced to Accept, Accept-Language and User-Agent; Cookie and Authorization
are explicitly blanked before optional injection, including on subresources.
This suppresses ambient and response-set cookies on forwarded requests. Roles
are therefore not full authenticated browser sessions. Do not put credentials
into URLs, labels or opaque references. Credentials necessarily reach the trusted
resolver, browser machinery and authorized target; this is not protection from a
malicious target or a compromised sandbox. Do not enable Playwright debug logs,
tracing, browser crash dumps or external traffic capture containing secrets.

## Results And Budgets

`BrowserObservation` contains only a fixed `outcome`, the main navigation HTTP
status when available, and aggregate request/redirect/WebSocket counters. No
URLs, paths, query values, titles, DOM, response bodies, headers, console output,
credential references, resolved credentials or raw exceptions are exported.
Screenshots, HAR, traces, downloads and evidence sinks are intentionally omitted.
The adapter internally buffers fetched responses; it has no response-byte cap.
External memory limits are required for large or hostile responses.

Outcomes are `observed`, `failed`, `timed_out`, `budget_exceeded`, or
`cleanup_failed`. `observed` means navigation finished, not that all resources
were allowed, that a response was successful, or that any security property was
verified. Inspect counters and HTTP status. An allowed request means a gated
fetch was admitted; a blocked redirect is also counted as blocked, so allowed
and blocked counts can overlap. Browser/credential errors are sanitized.
Preflight policy and missing-dependency errors raise `BrowserObserverError`.

The default budget is 50 intercepted requests and 15 seconds per invocation,
including credential resolution, startup and navigation. Limits are 1-1000
requests and a finite duration up to 300 seconds. Excess requests are aborted;
there are no retries. There is no global/concurrency budget: the caller must
limit invocations. Navigation waits for DOMContentLoaded, not network idle or
complete application execution. There is no claim of complete page coverage.

On every exit, context/browser/Playwright teardown is attempted independently
with five seconds per operation. Cancellation propagates after shielded cleanup,
including repeated cancellation. Cleanup can extend beyond the observation
deadline. `cleanup_failed` requires operator intervention: a hung browser or
failed driver cannot be reliably killed by this in-process adapter. Enforce a
hard sandbox lifetime and destroy the sandbox externally after every run.

## Offline Tests

`python -m pytest tests/test_browser_observer.py` uses only fake Playwright
objects and rejects real Playwright imports. It never launches a browser or
uses actual network traffic. `playwright_factory` is a trusted test seam only;
never accept it from untrusted callers. These tests validate adapter decisions,
not Chromium implementation behavior or the external sandbox's enforcement.

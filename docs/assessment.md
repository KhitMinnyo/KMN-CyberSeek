# Bounded Assessment Foundations

`core.assessment` is an opt-in library for API inventories, role/category
coverage, and focused independent async jobs. Importing it does not start work,
make network requests, invoke tools, or generate exploits. Authenticated session
inventory and coverage routes and the headless CLI are wired to it. The focused
job coordinator remains a library integration API; it does not create LLM agents
or automatically execute tests. No dashboard controls are added for these paths.

## Inventory API

```python
from pathlib import Path
from core.assessment import Assessment, CoverageKey, import_openapi

assessment = Assessment.from_openapi(
    Path("openapi.json").read_bytes(),
    allowlist="api.example.test",
    roles={"anonymous": None, "reader": "env:ASSESSMENT_READER"},
    categories=("observation", "authorization", "response-contract"),
)

for endpoint in assessment.endpoints:
    print(endpoint.id, endpoint.method, endpoint.base_url, endpoint.path)

endpoint = assessment.endpoints[0]
key = CoverageKey(endpoint.id, "reader", "response-contract")
print(assessment.cells[key])
print(assessment.summary())
```

`import_openapi(document, *, base_url=None, allowlist=None)` returns immutable
`Endpoint` objects without constructing coverage. Input is a JSON string, UTF-8
bytes, or a JSON-compatible mapping, not a filename or URL. Read local files
explicitly. JSON input is capped at 2 MiB, 100,000 nodes, and depth 64. Inventories
are capped at 5,000 endpoint/server combinations. Coverage has at most 100 roles,
100 categories, and 100,000 cells. Size-limit failures reject input, not truncate
it. No dependency changes are needed. YAML and Swagger 2 are not supported.

- OpenAPI 3.x `paths` HTTP methods are inventoried. Callbacks, webhooks, links,
  request templates, and schema-based request generation are not implemented.
- Identity is SHA-256 of normalized base URL, uppercase method, and declared
  path template. Distinct servers are distinct endpoints. Duplicate server
  declarations do not multiply endpoints. Operation IDs are not trusted identity.
- Operation servers override path servers, which override root servers. Server
  variables use declared string defaults. Variables are not enumerated.
- With no declared servers, an explicit absolute `base_url` is required for any
  operation. Relative server URLs also require that explicit resolution anchor.
  It is not an instruction to ignore or replace absolute declared servers.
- All root, path, and operation server declarations encountered are validated,
  including parent declarations overridden by children. Empty server overrides
  are rejected rather than interpreting an implicit `/` server.
- URLs must be absolute HTTP(S), without userinfo, query strings, fragments,
  whitespace, backslashes, or traversal paths. Encoded traversal/delimiters in
  paths are also rejected. This is intentionally stricter than general URL syntax.
- `validate_base_url` passes the parsed hostname to both existing APIs:
  `validators.is_valid_target` and `validators.is_target_in_scope`. Ports are
  validated separately. `allowlist=None` reads `SCOPE_ALLOWLIST` at call time;
  `allowlist=""` explicitly retains the validators' unrestricted behavior.
- Local `#/...` JSON Pointer references support escaped keys and array indexes.
  Every `$ref`, including in unused schemas, must identify an existing local
  object. Files, remote URLs, external documents, root `#`, and named anchors
  are rejected. Nothing is fetched. Recursive schemas are checked without
  expanding them. Inventory reference chains reject cycles and depth above 64;
  inventory `$ref` siblings are rejected rather than choosing ambiguous semantics.

This is an inventory importer, not a complete OpenAPI validator. It deliberately
does not retain descriptions, examples, security scheme values, operation IDs,
request/response bodies, or vendor-extension payloads in the ledger.

## Coverage Semantics

A `CoverageKey` consists of endpoint ID, role, and category. Categories describe
operator-defined checks; they do not imply the library knows how to execute them.
Role values are either `None` (no credential reference) or opaque `env:NAME`,
`vault:path`, or `keyring:name` references. References are not resolved here and
are never themselves evidence that a role was authenticated.

| Status | Meaning |
| --- | --- |
| `pending` | No observation or explicit disposition recorded. |
| `attempted` | Work started, but no conclusive outcome recorded. |
| `verified` | Worker/operator explicitly confirmed the check, with evidence reference. |
| `blocked` | A prerequisite, scope rule, or admission-to-execution deadline prevented work. |
| `skipped` | Explicitly not performed, including cancellation before execution. |
| `inconclusive` | Work started but failed, timed out, was cancelled, or lacked a conclusion. |

For externally managed work, call `assessment.begin_attempt(key)`, then
`assessment.mark(key, status, evidence_ref="evidence:opaque-id")`.
`attempted`, `verified`, and `inconclusive` require a recorded attempt;
`verified` additionally requires an evidence reference. There is no implicit
upgrade from an HTTP response, process exit code, or truthy return value.
`mark` cannot reset a cell to `pending`. Explicit reattempts increment attempts
and clear the previous conclusion/evidence for that cell.

`summary()` returns all six counts and `verified_ratio`, which uses **all** cells
as its denominator. Blocked/skipped work is not silently counted as complete.
An empty inventory has ratio `0.0`, not a success claim. Verification means the
specific check was evidenced, not that the endpoint is secure or exploitable.
Evidence references are pointers for an integrating application to audit; this
module cannot validate the content or truth of that external evidence.

## Focused Jobs

```python
import asyncio
from core.assessment import Budget, Outcome, TaskCoordinator

async def observe(context):
    # Integrate an explicitly approved observation/check here.
    # context.endpoint: immutable declared endpoint
    # context.key: endpoint/role/category identity
    # context.credential_ref: opaque reference, never resolved by this module
    # context.remaining(): monotonic time remaining
    # Use real bounded async I/O, not blocking calls or autonomous attack actions.
    return Outcome("inconclusive")

async def run(assessment):
    coordinator = TaskCoordinator(Budget(
        max_tasks=20,
        concurrency=2,
        max_units=30,
        wall_seconds=60,
        task_seconds=10,
    ))
    try:
        for key in list(assessment.cells)[:20]:
            coordinator.submit(assessment, key, observe, units=1)
        return await coordinator.wait()
    finally:
        await coordinator.close(cancel=True)

# In a standalone program: asyncio.run(run(assessment))
# Inside an async API handler: records = await run(assessment)
```

Workers must be async callbacks returning `Outcome(status, evidence_ref=None)`.
They are independent jobs, not agents or an agent swarm. The coordinator invokes
no tools or network APIs. Raw return values, exceptions, credentials, and arbitrary
job metadata are not retained. Returning the wrong type records a failed job and
inconclusive coverage, not success. `records` returns immutable `JobRecord` values
with job ID, coverage key, state, and charged units.

- `submit` requires a running loop. The coordinator binds to its first loop;
  subsequent submissions from another loop are rejected.
- Identity is `(Assessment object, CoverageKey)` within a coordinator. Duplicate
  submissions return the original job ID without reserving more budget, even
  after completion/cancellation. Separate ledger objects are independent.
- Maximum tasks and units are lifetime admission limits. Units are caller-declared
  accounting weights, not measured HTTP requests or model tokens. Cancellation
  and failure do not refund them. Budget rejection leaves coverage untouched.
- Concurrency limits active callbacks. Queued work counts toward task/unit limits.
  The wall deadline starts on the first accepted submission and includes queue
  time. The per-task timeout starts at execution. Queue expiry is blocked;
  execution expiry is inconclusive. Admission after wall expiry raises
  `BudgetExceeded`.
- `cancel(job_id)` cancels queued or running work. `wait()` waits for the current
  batch and isolates ordinary job failures. `close(cancel=True)` closes admission,
  cancels outstanding jobs, and awaits cleanup. Always await cleanup before
  leaving an event loop or replacing the shared instance.
- A new coordinator is an explicit new budget/retry boundary; it does not undo
  the coverage ledger. There are no automatic retries, nested job spawning APIs,
  subprocess management, or automatic resumption.

For a common application-level budget, configure once during application startup:

```python
from core.assessment import (
    Budget, configure_shared_coordinator, get_shared_coordinator,
)

configure_shared_coordinator(Budget(concurrency=2, max_tasks=100, max_units=100))
shared = get_shared_coordinator()
```

The shared instance is lazy, process-local, and event-loop-owned. Configuration
is rejected while jobs are active. It is not a cross-process, cross-event-loop,
or distributed rate limiter. Use one instance per worker loop or an external
enforcement service for multi-worker deployments. Do not reconfigure concurrently
with submission from another thread. Ledger reads/updates use a thread lock;
coordinator methods belong on their owning loop.

## Snapshots

```python
assessment.save("assessment.json")
restored = Assessment.load("assessment.json", allowlist="api.example.test")

text = assessment.to_json()
restored = Assessment.from_json(text, allowlist="api.example.test")
```

Snapshots have an explicit version and an allowlisted schema: declared endpoint
templates, role references, categories, coverage states, attempt counts, and
opaque evidence references. They contain no credential value field, environment
values, raw OpenAPI documents, job callbacks/results/errors, headers, cookies,
request bodies, or browser storage. Credential literals are rejected where
credential references are accepted. Do not put secrets in identifiers, declared
server/path templates, or reference names; opaque references are a data contract,
not a general-purpose secret detector. Do not provide concrete token-bearing
navigation URLs as declared path templates.

Imports validate identities, complete coverage, states, and current target scope
again. Unknown fields, duplicate cells, forged endpoint IDs, and verification
without attempts/evidence are rejected. Imported `attempted` cells become
`inconclusive`: a snapshot cannot restore in-flight execution. Snapshots do not
serialize or resume coordinator tasks, budgets, dedupe state, or executable code.
After a restart, explicitly choose new work and a new coordinator budget.

`save` writes a temporary file in the destination directory with mode `0600`,
flushes and fsyncs its contents, then publishes with `os.replace`. A failed
publication leaves the previous destination intact and removes the temporary
file. Replacement also removes permissive permissions from a previous destination.
The parent directory must already exist and should be private and trusted.
Snapshots are unencrypted, unsigned, last-writer-wins files, not a database or
tamper-proof evidence store. Directory metadata is not fsynced, so power-loss
durability of the replacement is filesystem-dependent. Both input and output JSON
are capped at 2 MiB; a matrix within the cell-count cap can still exceed that
serialized-size cap and be rejected on export. `to_json` itself provides no file
permissions; transport it only through an appropriately protected channel.

## Enforcement Limits

Target validation is syntactic and host-allowlist-based. It does not resolve DNS,
pin destination IPs, constrain ports via the allowlist, prevent DNS rebinding,
or enforce an HTTP redirect/subresource policy. Workers must revalidate actual
destinations and enforce scope on every request and redirect. Validated inventory
is not authorization to send every declared HTTP method, especially mutating ones.
Require operator approval and appropriate read-only clients for observations.

Async cancellation/timeouts are cooperative. A callback that blocks the event
loop, suppresses cancellation, starts unmanaged threads/processes, or performs
unaccounted I/O can evade runtime/resource accounting. This library is not a
sandbox, hard-kill mechanism, network firewall, or real request rate limiter.

Playwright integration is deliberately not included: it is not an existing
dependency, and passive page events alone do not enforce scoped redirects,
subresources, downloads, or credential isolation. No browser navigation, login,
form submission, crawling, screenshot capture, or autonomous attack action is
performed here. A future adapter should be optional, require explicit credential
references, intercept each network request in a dedicated context, keep secrets
out of observations, and never treat navigation alone as verified coverage.

Run the offline, mocked tests with:

```sh
python3 -m pytest tests/test_assessment.py -q
```

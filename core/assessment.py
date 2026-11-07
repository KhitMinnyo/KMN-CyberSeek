"""Bounded, opt-in assessment jobs and API coverage; no attacks or network I/O."""

import asyncio
import hashlib
import json
import math
import os
import re
import tempfile
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Awaitable, Callable, Mapping, Optional
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from core import validators


MAX_BYTES = 2 * 1024 * 1024
MAX_ENDPOINTS = 5000
MAX_CELLS = 100000
METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})
STATUSES = frozenset({"pending", "attempted", "verified", "blocked", "skipped", "inconclusive"})
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
_REF = re.compile(r"(?:env|vault|keyring):[A-Za-z0-9_./-]{1,160}\Z")
_EVIDENCE = re.compile(r"evidence:[A-Za-z0-9_./-]{1,160}\Z")


class AssessmentError(ValueError):
    """Invalid inventory, scope, state, or snapshot (never includes raw input)."""


class BudgetExceeded(AssessmentError):
    """A coordinator admission budget has been exhausted."""


def _label(value):
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise AssessmentError("Expected a short opaque identifier")
    return value


def _reference(value, pattern):
    if value is not None and (not isinstance(value, str) or not pattern.fullmatch(value)):
        raise AssessmentError("Expected an opaque reference, not a credential or evidence literal")
    return value


def validate_base_url(url: str, allowlist: Optional[str] = None) -> str:
    """Validate an absolute HTTP(S) URL via the existing target/scope validators.

    None reads SCOPE_ALLOWLIST at call time; an explicit empty string means
    unrestricted, exactly as in validators. No DNS resolution or network I/O.
    """
    if not isinstance(url, str) or len(url) > 4096 or re.search(r"[\s\\\x00-\x1f\x7f]", url):
        raise AssessmentError("Invalid base URL")
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
        if (parts.scheme not in {"http", "https"} or not host or parts.username is not None
                or parts.password is not None or parts.query or parts.fragment
                or "?" in url or "#" in url or "{" in url or "}" in url
                or (port is not None and not 1 <= port <= 65535)):
            raise AssessmentError("Expected HTTP(S) URL without credentials, query, or fragment")
    except ValueError:
        raise AssessmentError("Invalid base URL") from None
    if not validators.is_valid_target(host):
        raise AssessmentError("Invalid target hostname")
    scope = os.getenv("SCOPE_ALLOWLIST", "") if allowlist is None else allowlist
    if not validators.is_target_in_scope(host, scope):
        raise AssessmentError("Target is outside the scope allowlist")
    if parts.path:
        _path(parts.path)
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != (443 if parts.scheme == "https" else 80):
        authority += f":{port}"
    return urlunsplit((parts.scheme, authority, parts.path.rstrip("/"), "", ""))


def _path(value):
    if (not isinstance(value, str) or len(value) > 2048 or not value.startswith("/")
            or value.startswith("//") or re.search(r"[\s\\?#\x00-\x1f\x7f]", value)):
        raise AssessmentError("Invalid operation path")
    # Reject traversal and encoded URL delimiters, including nested encodings.
    decoded = value
    for _ in range(8):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    else:
        raise AssessmentError("Excessive path encoding")
    if (decoded.startswith("//") or re.search(r"[\\?#\x00-\x20\x7f]", decoded)
            or any(segment in {".", ".."} for segment in decoded.split("/"))):
        raise AssessmentError("Unsafe operation path")
    return value


def _document(value):
    try:
        text = json.dumps(value, allow_nan=False) if isinstance(value, Mapping) else value
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_BYTES:
            raise AssessmentError("Document exceeds the JSON size limit")
        obj = json.loads(text)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise AssessmentError("Expected bounded JSON input") from None
    if not isinstance(obj, dict):
        raise AssessmentError("Expected a JSON object")
    stack, count = [(obj, 0)], 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > 100000 or depth > 64:
            raise AssessmentError("Document structure exceeds limits")
        if isinstance(node, float) and not math.isfinite(node):
            raise AssessmentError("Non-finite numbers are not valid JSON")
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)
    return obj


@dataclass(frozen=True)
class Endpoint:
    id: str
    method: str
    path: str
    base_url: str


def _endpoint(method, path, base_url, allowlist):
    if not isinstance(method, str) or method.lower() not in METHODS:
        raise AssessmentError("Invalid HTTP method")
    method, path = method.upper(), _path(path)
    base_url = validate_base_url(base_url, allowlist)
    identity = json.dumps([base_url, method, path], separators=(",", ":"))
    return Endpoint(hashlib.sha256(identity.encode()).hexdigest(), method, path, base_url)


def import_openapi(document, *, base_url=None, allowlist=None):
    """Inventory OpenAPI 3.x JSON. Never fetch files, URLs, or external $refs.

    Relative servers require an explicit absolute base_url. Server variables use
    declared defaults. Path/operation servers override parent servers. Schema
    references are checked, not expanded; recursive schemas are permitted.
    """
    doc = _document(document)
    if not isinstance(doc.get("openapi"), str) or not re.fullmatch(r"3\.\d+\.\d+(?:[-+].*)?", doc["openapi"]):
        raise AssessmentError("Only OpenAPI 3.x is supported")
    anchor = validate_base_url(base_url, allowlist) if base_url is not None else None

    def pointer(ref):
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise AssessmentError("Only local JSON Pointer references are supported")
        node = doc
        for token in unquote(ref[2:]).split("/"):
            if re.search(r"~(?![01])", token):
                raise AssessmentError("Invalid JSON Pointer escape")
            token = token.replace("~1", "/").replace("~0", "~")
            try:
                if isinstance(node, list):
                    if not re.fullmatch(r"0|[1-9][0-9]*", token):
                        raise AssessmentError("Invalid JSON Pointer index")
                    node = node[int(token)]
                else:
                    node = node[token]
            except (KeyError, IndexError, TypeError, ValueError):
                raise AssessmentError("Unresolved local reference") from None
        if not isinstance(node, dict):
            raise AssessmentError("Reference must identify an object")
        return node

    stack = [doc]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "$ref" in node:
                pointer(node["$ref"])
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)

    def resolve(node):
        seen = set()
        while isinstance(node, dict) and "$ref" in node:
            ref = node["$ref"]
            if ref in seen or len(seen) >= 64:
                raise AssessmentError("Cyclic or excessive inventory reference chain")
            # Path Item $ref sibling semantics are ambiguous; do not guess.
            if set(node) != {"$ref"}:
                raise AssessmentError("Inventory reference siblings are unsupported")
            seen.add(ref)
            node = pointer(ref)
        if not isinstance(node, dict):
            raise AssessmentError("Expected an inventory object")
        return node

    def servers(owner, inherited):
        if "servers" not in owner:
            return inherited
        entries = owner["servers"]
        if not isinstance(entries, list) or not entries:
            raise AssessmentError("Declare nonempty servers or omit the override")
        urls = []
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
                raise AssessmentError("Invalid server declaration")
            variables = entry.get("variables", {})
            if not isinstance(variables, dict):
                raise AssessmentError("Invalid server variables")

            def expand(match):
                variable = variables.get(match.group(1))
                if not isinstance(variable, dict) or not isinstance(variable.get("default"), str):
                    raise AssessmentError("Server variable needs a string default")
                return variable["default"]

            url = re.sub(r"\{([^{}]+)\}", expand, entry["url"])
            if not urlsplit(url).scheme:
                if anchor is None:
                    raise AssessmentError("Relative server needs an explicit base_url")
                url = urljoin(anchor + "/", url)
            urls.append(validate_base_url(url, allowlist))
        return tuple(dict.fromkeys(urls))

    root_servers = servers(doc, (anchor,) if anchor else ())
    paths = doc.get("paths", {})
    if not isinstance(paths, dict):
        raise AssessmentError("Invalid paths object")
    endpoints = {}
    for path, raw_item in paths.items():
        if path.startswith("x-"):
            continue
        _path(path)
        item = resolve(raw_item)
        path_servers = servers(item, root_servers)
        for method, raw_operation in item.items():
            if method not in METHODS:
                continue
            operation = resolve(raw_operation)
            effective = servers(operation, path_servers)
            if not effective:
                raise AssessmentError("Operations require a declared or explicit base URL")
            for url in effective:
                endpoint = _endpoint(method, path, url, allowlist)
                endpoints[endpoint.id] = endpoint
                if len(endpoints) > MAX_ENDPOINTS:
                    raise AssessmentError("Operation inventory exceeds limit")
    return tuple(sorted(endpoints.values(), key=lambda e: (e.base_url, e.path, e.method)))


@dataclass(frozen=True)
class CoverageKey:
    endpoint_id: str
    role: str
    category: str


@dataclass(frozen=True)
class CoverageCell:
    status: str = "pending"
    attempts: int = 0
    evidence_ref: Optional[str] = None


@dataclass(frozen=True)
class Outcome:
    """Explicit worker conclusion. Verified requires external evidence, not exit code."""

    status: str
    evidence_ref: Optional[str] = None

    def __post_init__(self):
        if self.status not in STATUSES - {"pending"}:
            raise AssessmentError("Invalid outcome status")
        _reference(self.evidence_ref, _EVIDENCE)
        if self.status == "verified" and self.evidence_ref is None:
            raise AssessmentError("Verified coverage requires an evidence reference")


class Assessment:
    """Thread-safe coverage ledger; jobs run separately on one asyncio event loop."""

    def __init__(self, endpoints, *, roles=None, categories=("observation",), allowlist=None):
        self._lock = threading.RLock()
        inventory = {}
        for endpoint in endpoints:
            checked = _endpoint(endpoint.method, endpoint.path, endpoint.base_url, allowlist)
            if checked != endpoint or endpoint.id in inventory:
                raise AssessmentError("Invalid or duplicate endpoint identity")
            inventory[endpoint.id] = endpoint
            if len(inventory) > MAX_ENDPOINTS:
                raise AssessmentError("Operation inventory exceeds limit")
        self._endpoints = inventory
        roles = {"anonymous": None} if roles is None else roles
        if not isinstance(roles, Mapping) or not roles or len(roles) > 100:
            raise AssessmentError("Declare between one and 100 roles")
        self._roles = {_label(k): _reference(v, _REF) for k, v in roles.items()}
        if isinstance(categories, str):
            raise AssessmentError("Categories must be a collection of identifiers")
        category_set = set()
        for category in categories:
            category_set.add(_label(category))
            if len(category_set) > 100:
                raise AssessmentError("Too many categories")
        self._categories = tuple(sorted(category_set))
        if not self._categories or len(inventory) * len(roles) * len(category_set) > MAX_CELLS:
            raise AssessmentError("Coverage matrix exceeds limits or has no categories")
        self._cells = {
            CoverageKey(e, r, c): CoverageCell()
            for e in inventory for r in self._roles for c in self._categories
        }

    @classmethod
    def from_openapi(cls, document, *, base_url=None, allowlist=None, **kwargs):
        return cls(import_openapi(document, base_url=base_url, allowlist=allowlist),
                   allowlist=allowlist, **kwargs)

    @property
    def endpoints(self):
        return tuple(self._endpoints.values())

    @property
    def roles(self):
        return dict(self._roles)

    @property
    def cells(self):
        with self._lock:
            return dict(self._cells)

    def mark(self, key: CoverageKey, status: str, *, evidence_ref=None):
        """Record an explicit conclusion; pending resets and implicit verification are forbidden."""
        outcome = Outcome(status, evidence_ref)
        with self._lock:
            cell = self._cells[key]
            if status in {"attempted", "verified", "inconclusive"} and cell.attempts == 0:
                raise AssessmentError("This conclusion requires a recorded attempt")
            self._cells[key] = replace(cell, status=outcome.status, evidence_ref=outcome.evidence_ref)

    def begin_attempt(self, key: CoverageKey):
        """Record the start of an externally managed observation or test."""
        with self._lock:
            cell = self._cells[key]
            self._cells[key] = CoverageCell("attempted", cell.attempts + 1)

    def summary(self):
        with self._lock:
            counts = Counter(c.status for c in self._cells.values())
            total = len(self._cells)
            return {"total": total, "counts": {s: counts[s] for s in sorted(STATUSES)},
                    "verified_ratio": counts["verified"] / total if total else 0.0}

    def to_json(self):
        """Allowlisted metadata only: no raw spec, requests, results, errors or credentials."""
        with self._lock:
            data = {"version": 1, "endpoints": [asdict(e) for e in self.endpoints],
                    "roles": self.roles, "categories": list(self._categories),
                    "coverage": [{**asdict(k), **asdict(v)} for k, v in self._cells.items()]}
        text = json.dumps(data, sort_keys=True, indent=2, allow_nan=False)
        if len(text.encode()) > MAX_BYTES:
            raise AssessmentError("Snapshot exceeds JSON size limit")
        return text

    @classmethod
    def from_json(cls, document, *, allowlist=None):
        data = _document(document)
        if (set(data) != {"version", "endpoints", "roles", "categories", "coverage"}
                or type(data["version"]) is not int or data["version"] != 1
                or not isinstance(data["endpoints"], list)
                or not isinstance(data["coverage"], list)
                or not isinstance(data["categories"], list)):
            raise AssessmentError("Invalid snapshot schema")
        try:
            assessment = cls((Endpoint(**e) for e in data["endpoints"]), roles=data["roles"],
                             categories=data["categories"], allowlist=allowlist)
            seen = set()
            for row in data["coverage"]:
                if set(row) != {"endpoint_id", "role", "category", "status", "attempts", "evidence_ref"}:
                    raise AssessmentError("Invalid coverage row")
                key = CoverageKey(row["endpoint_id"], row["role"], row["category"])
                if key not in assessment._cells or key in seen:
                    raise AssessmentError("Unknown or duplicate coverage identity")
                seen.add(key)
                status, attempts = row["status"], row["attempts"]
                evidence = _reference(row["evidence_ref"], _EVIDENCE)
                if (status not in STATUSES or type(attempts) is not int or not 0 <= attempts <= 1000000
                        or (status in {"attempted", "verified", "inconclusive"} and attempts == 0)
                        or (status == "pending" and (attempts != 0 or evidence is not None))
                        or (status == "verified" and evidence is None)):
                    raise AssessmentError("Invalid coverage state")
                # A process restart cannot preserve an in-flight observation.
                if status == "attempted":
                    status, evidence = "inconclusive", None
                assessment._cells[key] = CoverageCell(status, attempts, evidence)
            if seen != set(assessment._cells):
                raise AssessmentError("Snapshot must include the complete coverage matrix")
        except (TypeError, KeyError, AttributeError):
            raise AssessmentError("Invalid snapshot data") from None
        return assessment

    def save(self, path):
        """Atomic same-directory replace, mode 0600, flushed before publication."""
        text, destination = self.to_json(), Path(path)
        fd, temporary = tempfile.mkstemp(prefix=".assessment-", dir=destination.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @classmethod
    def load(cls, path, *, allowlist=None):
        with open(path, "rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        return cls.from_json(data, allowlist=allowlist)


@dataclass(frozen=True)
class Budget:
    max_tasks: int = 100
    concurrency: int = 4
    max_units: int = 100
    wall_seconds: float = 300.0
    task_seconds: float = 30.0

    def __post_init__(self):
        for value in (self.max_tasks, self.concurrency, self.max_units):
            if type(value) is not int or value < 1:
                raise AssessmentError("Budget counts must be positive integers")
        for value in (self.wall_seconds, self.task_seconds):
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value <= 0):
                raise AssessmentError("Budget durations must be finite and positive")


@dataclass(frozen=True)
class JobContext:
    endpoint: Endpoint
    key: CoverageKey
    credential_ref: Optional[str]
    deadline: float

    def remaining(self):
        return max(0.0, self.deadline - time.monotonic())


@dataclass(frozen=True)
class JobRecord:
    id: str
    key: CoverageKey
    state: str
    units: int


class TaskCoordinator:
    """One-loop independent async jobs, lifetime admission budgets and deduplication.

    Limits apply to cooperative async callbacks, not subprocesses or arbitrary
    code. No agents, worker threads, retries, exploit payloads, or network client.
    """

    def __init__(self, budget=None):
        self.budget = Budget() if budget is None else budget
        if not isinstance(self.budget, Budget):
            raise AssessmentError("Expected a Budget instance")
        self._semaphore = None
        self._loop = None
        self._deadline = None
        self._units = 0
        self._tasks = {}
        self._records = {}
        self._identities = {}
        self._closed = False

    @property
    def records(self):
        return dict(self._records)

    @property
    def active(self):
        return any(not task.done() for task in self._tasks.values())

    def submit(self, assessment: Assessment, key: CoverageKey,
               worker: Callable[[JobContext], Awaitable[Outcome]], *, units=1):
        """Return a stable job id; duplicate submissions do not consume budget.

        Identity is (ledger object, endpoint, role, category). Terminal jobs stay
        deduplicated for this coordinator's lifetime; a new coordinator is an
        explicit retry budget. Call from its owning running event loop only.
        """
        loop = asyncio.get_running_loop()
        if self._loop is not None and self._loop is not loop:
            raise AssessmentError("Coordinator belongs to another event loop")
        if self._closed:
            raise AssessmentError("Coordinator is closed")
        if key not in assessment._cells:
            raise AssessmentError("Unknown coverage key")
        identity = (assessment, key)
        if identity in self._identities:
            return self._identities[identity]
        if type(units) is not int or units < 1 or not callable(worker):
            raise AssessmentError("Job needs positive integer units and an async callback")
        now = time.monotonic()
        if (len(self._tasks) >= self.budget.max_tasks or self._units + units > self.budget.max_units
                or (self._deadline is not None and now >= self._deadline)):
            raise BudgetExceeded("Coordinator admission budget exhausted")
        self._loop = loop
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.budget.concurrency)
        if self._deadline is None:
            self._deadline = now + self.budget.wall_seconds
        job_id = f"job-{len(self._tasks) + 1}"
        self._units += units
        self._identities[identity] = job_id
        self._records[job_id] = JobRecord(job_id, key, "queued", units)
        self._tasks[job_id] = loop.create_task(self._run(job_id, assessment, key, worker))
        return job_id

    def _state(self, job_id, state):
        self._records[job_id] = replace(self._records[job_id], state=state)

    async def _run(self, job_id, assessment, key, worker):
        started = False

        async def execute():
            nonlocal started
            async with self._semaphore:
                if time.monotonic() >= self._deadline:
                    raise asyncio.TimeoutError
                started = True
                self._state(job_id, "running")
                assessment.begin_attempt(key)
                deadline = min(self._deadline, time.monotonic() + self.budget.task_seconds)
                context = JobContext(assessment._endpoints[key.endpoint_id], key,
                                     assessment._roles[key.role], deadline)
                outcome = await asyncio.wait_for(worker(context), timeout=context.remaining())
                if not isinstance(outcome, Outcome):
                    raise AssessmentError("Worker must return an explicit Outcome")
                assessment.mark(key, outcome.status, evidence_ref=outcome.evidence_ref)
                self._state(job_id, "completed")

        try:
            await asyncio.wait_for(execute(), timeout=max(0.0, self._deadline - time.monotonic()))
        except asyncio.CancelledError:
            assessment.mark(key, "inconclusive" if started else "skipped")
            self._state(job_id, "cancelled")
            raise
        except asyncio.TimeoutError:
            assessment.mark(key, "inconclusive" if started else "blocked")
            self._state(job_id, "timed_out")
        except Exception:
            # Raw exceptions/results may contain credentials; deliberately do not retain them.
            assessment.mark(key, "inconclusive" if started else "blocked")
            self._state(job_id, "failed")

    def cancel(self, job_id):
        task = self._tasks[job_id]
        if task.done() or self._records[job_id].state == "cancelled":
            return False
        # A task cancelled before its coroutine starts never enters _run's handler.
        if self._records[job_id].state == "queued":
            for (assessment, key), identity in self._identities.items():
                if identity == job_id:
                    assessment.mark(key, "skipped")
                    break
        self._state(job_id, "cancelled")
        task.cancel()
        return True

    async def wait(self):
        """Wait for the current batch; ordinary job failures are isolated."""
        await asyncio.gather(*tuple(self._tasks.values()), return_exceptions=True)
        return self.records

    async def close(self, *, cancel=False):
        self._closed = True
        if cancel:
            for job_id in self._tasks:
                self.cancel(job_id)
        await self.wait()


_shared = None
_shared_lock = threading.Lock()


def get_shared_coordinator():
    """Lazy process-local singleton, not a distributed/multi-process budget."""
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = TaskCoordinator()
        return _shared


def configure_shared_coordinator(budget: Budget):
    """Replace an idle singleton; close active work explicitly before reconfiguration."""
    global _shared
    with _shared_lock:
        if _shared is not None and _shared.active:
            raise AssessmentError("Cannot replace a coordinator with active jobs")
        _shared = TaskCoordinator(budget)
        return _shared

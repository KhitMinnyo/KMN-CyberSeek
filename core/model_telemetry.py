"""Metadata-only model ledger and opt-in session budgets.

Integration::

    with model_call_context(session_id, "strategist", operation_id="decision-7"):
        result = await connector.ask_raw_async(system_prompt, user_prompt)
    store = ModelTelemetryStore(db_path)
    store.summary(session_id)  # totals, including explicit unknown-usage counts
    store.events(session_id, limit=100)  # newest first, metadata only
    store.purge_session(session_id)  # do not purge an active session

No database is opened on import or construction. KMN_MODEL_TELEMETRY_DB wins;
otherwise model_usage.sqlite is a sibling of DB_PATH (default kmn_cyberseek.db).
The store owns its schema and needs no application migrations.

KMN_MODEL_MAX_CALLS, KMN_MODEL_MAX_TOKENS, and KMN_MODEL_MAX_COST_USD are optional
nonnegative session limits. Token/cost reservations include a UTF-8 byte bound
and the output limit. Unknown usage retains that reservation, even on failure.
Pricing is never guessed: both KMN_MODEL_INPUT_USD_PER_MILLION and
KMN_MODEL_OUTPUT_USD_PER_MILLION must be supplied as trusted rates for every
selected model when enabling a cost cap. Actual usage/cost remains NULL when
unknown; reservations and estimates are separate, never reported as actuals.
Unscoped calls share a NULL session budget. Use opaque IDs, not user content.
Retries have 1-based ordinals within an operation. Summary token/cost totals sum
known actuals only; consult unknown_usage_calls/unknown_cost_calls before treating
them as complete totals. Pending calls survive restarts and retain reservations.
Budget denial raises ModelBudgetExceeded for tactical calls; raw calls preserve
their existing non-raising contract and return None (inspect the blocked event).
"""

from contextlib import closing, contextmanager
from contextvars import ContextVar
from decimal import Decimal, InvalidOperation
import math
import os
from pathlib import Path
import sqlite3
import time
from uuid import uuid4


ROLES = {"tactical", "strategist", "verifier", "summary", "specialist"}
_context = ContextVar("model_call_context", default=None)


@contextmanager
def model_call_context(session_id, purpose, operation_id=None):
    """Task-local metadata scope; nesting restores the previous scope."""
    if purpose not in ROLES:
        raise ValueError("Unsupported model purpose")
    for value in (session_id, operation_id):
        if value is not None and (not isinstance(value, str) or not value or len(value) > 256):
            raise ValueError("Model context IDs must be nonempty strings up to 256 characters")
    token = _context.set((session_id, purpose, operation_id or uuid4().hex))
    try:
        yield
    finally:
        _context.reset(token)


def current_model_context(session_id=None, purpose="tactical"):
    context = _context.get()
    if context is None:
        return session_id, purpose, uuid4().hex
    return (session_id if session_id is not None else context[0], context[1], context[2])


class ModelBudgetExceeded(RuntimeError):
    """A model attempt was denied before transport."""


def _number(name, integer=False):
    raw = os.getenv(name)
    if raw is None:
        return None
    try:
        value = Decimal(raw)
        if not value.is_finite() or value < 0 or (integer and value != value.to_integral_value()):
            raise ValueError
        if integer:
            value = int(value)
            if value > 2**63 - 1:
                raise ValueError
            return value
        converted = float(value)
        if not math.isfinite(converted) or (value > 0 and converted == 0):
            raise ValueError
        return converted
    except (InvalidOperation, ValueError, OverflowError):
        raise ValueError(f"Invalid {name}: expected a finite nonnegative {'integer' if integer else 'number'}") from None


class ModelTelemetryStore:
    def __init__(self, db_path=None):
        self.db_path = str(db_path if db_path is not None else (
            os.getenv("KMN_MODEL_TELEMETRY_DB") or
            Path(os.getenv("DB_PATH", "").strip() or "kmn_cyberseek.db").with_name("model_usage.sqlite")
        ))
        if not self.db_path or self.db_path == ":memory:":
            raise ValueError("Model telemetry requires a durable SQLite file path")

    @contextmanager
    def _db(self):
        # Each operation uses a separate connection: safe across threads/processes.
        with closing(sqlite3.connect(self.db_path, timeout=30)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("""CREATE TABLE IF NOT EXISTS model_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, purpose TEXT NOT NULL,
                operation_id TEXT NOT NULL, retry_ordinal INTEGER NOT NULL,
                provider TEXT NOT NULL, model TEXT NOT NULL, started_at REAL NOT NULL,
                latency_ms REAL, status TEXT NOT NULL, error TEXT, parse_result TEXT,
                input_tokens INTEGER, output_tokens INTEGER, total_tokens INTEGER,
                estimated_input_tokens INTEGER NOT NULL, estimated_output_tokens INTEGER,
                reserved_tokens INTEGER NOT NULL, budget_tokens INTEGER NOT NULL,
                cost_usd REAL, estimated_cost_usd REAL, reserved_cost_usd REAL,
                budget_cost_usd REAL, input_rate REAL, output_rate REAL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS model_calls_session ON model_calls(session_id, id)")
            yield db

    def reserve(self, *, session_id, purpose, operation_id, retry_ordinal,
                provider, model, estimated_input_tokens, max_tokens):
        limits = (
            _number("KMN_MODEL_MAX_CALLS", True),
            _number("KMN_MODEL_MAX_TOKENS", True),
            _number("KMN_MODEL_MAX_COST_USD"),
        )
        input_rate = _number("KMN_MODEL_INPUT_USD_PER_MILLION")
        output_rate = _number("KMN_MODEL_OUTPUT_USD_PER_MILLION")
        reserved = estimated_input_tokens + max_tokens
        cost = None if input_rate is None or output_rate is None else (
            estimated_input_tokens * input_rate + max_tokens * output_rate
        ) / 1_000_000
        if cost is not None and (not math.isfinite(cost) or (cost == 0 and (
                estimated_input_tokens * input_rate > 0 or max_tokens * output_rate > 0))):
            raise ValueError("Model pricing cannot be represented safely")
        denied = None
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            used = db.execute("""SELECT COUNT(*) AS calls, COALESCE(SUM(budget_tokens),0) AS tokens,
                COALESCE(SUM(budget_cost_usd),0) AS cost,
                SUM(budget_cost_usd IS NULL) AS unknown_cost
                FROM model_calls WHERE session_id IS ? AND status != 'blocked'""", (session_id,)).fetchone()
            if limits[0] is not None and used["calls"] + 1 > limits[0]:
                denied = "call_budget_exceeded"
            elif limits[1] is not None and used["tokens"] + reserved > limits[1]:
                denied = "token_budget_exceeded"
            elif limits[2] is not None and (cost is None or used["unknown_cost"] or used["cost"] + cost > limits[2]):
                denied = "cost_budget_exceeded"
            cursor = db.execute("""INSERT INTO model_calls (
                session_id, purpose, operation_id, retry_ordinal, provider, model,
                started_at, status, error, parse_result, estimated_input_tokens,
                reserved_tokens, budget_tokens, reserved_cost_usd, budget_cost_usd,
                input_rate, output_rate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (session_id, purpose, operation_id, retry_ordinal, provider, model,
                 time.time(), "blocked" if denied else "pending", denied,
                 "not_attempted", estimated_input_tokens, reserved, reserved,
                 cost, cost, input_rate, output_rate))
            event_id = cursor.lastrowid
        if denied:
            raise ModelBudgetExceeded(denied)
        return event_id

    def finish(self, event_id, *, latency_ms, result=None, text=None,
               parse_result="not_attempted", error=None):
        def count(value):
            return value if type(value) is int and 0 <= value <= 2**63 - 1 else None

        with self._db() as db:
            event = db.execute("SELECT * FROM model_calls WHERE id=?", (event_id,)).fetchone()
            if event is None:
                raise RuntimeError("Model reservation no longer exists")
            result = result if isinstance(result, dict) else {}
            usage = result.get("usage")
            usage = usage if isinstance(usage, dict) else {}
            cached = False
            if event["provider"] == "local":
                inputs, outputs = count(result.get("prompt_eval_count")), count(result.get("eval_count"))
            elif event["provider"] == "anthropic":
                inputs, outputs = count(usage.get("input_tokens")), count(usage.get("output_tokens"))
                # Anthropic cache reads/writes are additional input usage; their
                # tiered pricing is not covered by the simple trusted rate pair.
                cached = any(usage.get(k) for k in ("cache_read_input_tokens", "cache_creation_input_tokens"))
                if cached:
                    cache_counts = [count(usage.get(k, 0)) for k in ("cache_read_input_tokens", "cache_creation_input_tokens")]
                    inputs = inputs + sum(cache_counts) if inputs is not None and all(n is not None for n in cache_counts) else None
            else:
                inputs, outputs = count(usage.get("prompt_tokens")), count(usage.get("completion_tokens"))
            total = inputs + outputs if inputs is not None and outputs is not None else count(usage.get("total_tokens"))
            estimated_output = len(text.encode("utf-8", errors="replace")) if isinstance(text, str) else None
            cost = None
            if not cached and inputs is not None and outputs is not None and event["input_rate"] is not None and event["output_rate"] is not None:
                cost = (inputs * event["input_rate"] + outputs * event["output_rate"]) / 1_000_000
            # OpenRouter explicitly reports the billed USD cost when available.
            reported_cost = usage.get("cost")
            if (event["provider"] == "openrouter" and type(reported_cost) in (int, float)
                    and math.isfinite(reported_cost) and reported_cost >= 0):
                cost = reported_cost
            estimated_cost = None
            if estimated_output is not None and event["input_rate"] is not None and event["output_rate"] is not None:
                estimated_cost = (event["estimated_input_tokens"] * event["input_rate"] + estimated_output * event["output_rate"]) / 1_000_000
            db.execute("""UPDATE model_calls SET latency_ms=?, status=?, error=?, parse_result=?,
                input_tokens=?, output_tokens=?, total_tokens=?, estimated_output_tokens=?,
                cost_usd=?, estimated_cost_usd=?, budget_tokens=?, budget_cost_usd=? WHERE id=?""",
                (latency_ms, "error" if error else "completed", error, parse_result,
                 inputs, outputs, total, estimated_output, cost, estimated_cost,
                 total if total is not None else event["reserved_tokens"],
                 cost if cost is not None else event["reserved_cost_usd"], event_id))

    def events(self, session_id, limit=100):
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("limit must be an integer from 1 to 10000")
        with self._db() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM model_calls WHERE session_id IS ? ORDER BY id DESC LIMIT ?", (session_id, limit))]

    def summary(self, session_id=None):
        with self._db() as db:
            return dict(db.execute("""SELECT COUNT(*) AS events,
                COALESCE(SUM(status != 'blocked'),0) AS calls,
                COALESCE(SUM(status = 'blocked'),0) AS blocked,
                COALESCE(SUM(status = 'error'),0) AS errors,
                COALESCE(SUM(status = 'pending'),0) AS pending,
                COALESCE(SUM(status != 'blocked' AND total_tokens IS NULL),0) AS unknown_usage_calls,
                COALESCE(SUM(status != 'blocked' AND cost_usd IS NULL),0) AS unknown_cost_calls,
                SUM(CASE WHEN status != 'blocked' THEN total_tokens END) AS total_tokens,
                SUM(CASE WHEN status != 'blocked' THEN cost_usd END) AS cost_usd,
                SUM(CASE WHEN status != 'blocked' THEN budget_tokens END) AS budget_tokens,
                SUM(CASE WHEN status != 'blocked' THEN budget_cost_usd END) AS budget_cost_usd
                FROM model_calls WHERE (? IS NULL OR session_id IS ?)""", (session_id, session_id)).fetchone())

    def purge_session(self, sid):
        with self._db() as db:
            return db.execute("DELETE FROM model_calls WHERE session_id IS ?", (sid,)).rowcount

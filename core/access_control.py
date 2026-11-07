"""Operator-managed identities and session ACLs, independent of scan storage.

KMN_AUTH_PRINCIPALS_FILE is a JSON object with a `principals` array, for example:
{"principals": [{"id": "alice", "role": "operator", "token_sha256": "<64 hex>",
                 "sensitive_read": false, "sessions": ["explicit-session-id"]}]}
Use Authorization: Bearer <token>. Never put plaintext tokens in this file.
Roles do not imply sensitive-read permission (except admin). Session grants do
not imply ownership of any other session. Changes are read on each request.
Without a configured file ONLY, API_AUTH_TOKEN is legacy_service_admin mode;
that shipped mode also accepts X-API-Key and the WebSocket token query parameter.
KMN_ACCESS_DB optionally selects the persistent ACL/audit SQLite database.
Source-revision tombstones permanently revoke evidence references for a session;
raw evidence remains in its owning audit store until session deletion.
"""

from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3


class AccessError(Exception):
    def __init__(self, status, detail):
        self.status, self.detail = status, detail
        super().__init__(detail)


@dataclass(frozen=True)
class Principal:
    id: str
    role: str
    sensitive_read: bool = False
    sessions: tuple = ()
    mode: str = "principals_file"

    @property
    def admin(self):
        return self.role == "admin"

    @property
    def sensitive(self):
        # Viewers can only consume sanitized representations, even if misgranted.
        return self.admin or (self.role != "viewer" and self.sensitive_read)

    def identity(self):
        return {"id": self.id, "role": self.role, "sensitive_read": self.sensitive,
                "identity_mode": self.mode}


class AccessStore:
    def __init__(self, path):
        self.path = str(path)
        self._initialized = False

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            with connection:
                if not self._initialized:
                    connection.execute("CREATE TABLE IF NOT EXISTS access_session_owners (session_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL)")
                    connection.execute("CREATE TABLE IF NOT EXISTS access_audit (id INTEGER PRIMARY KEY, created_at TEXT DEFAULT CURRENT_TIMESTAMP, principal_id TEXT NOT NULL, action TEXT NOT NULL, session_id TEXT, outcome TEXT NOT NULL)")
                    connection.execute("CREATE TABLE IF NOT EXISTS access_sources (session_id TEXT NOT NULL, source_id TEXT NOT NULL, kind TEXT NOT NULL, document TEXT NOT NULL, PRIMARY KEY(session_id, source_id, kind))")
                    connection.execute("CREATE TABLE IF NOT EXISTS access_invalidated_evidence (session_id TEXT NOT NULL, source_id TEXT NOT NULL, reference TEXT NOT NULL, revision TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(session_id, source_id, reference))")
                yield connection
            self._initialized = True
        finally:
            connection.close()

    def own(self, session_id, principal):
        with self.connect() as connection:
            connection.execute("INSERT INTO access_session_owners VALUES (?, ?)", (session_id, principal.id))

    def owns(self, session_id, principal):
        with self.connect() as connection:
            return connection.execute("SELECT 1 FROM access_session_owners WHERE session_id=? AND principal_id=?",
                                      (session_id, principal.id)).fetchone() is not None

    def audit(self, principal, action, session_id, outcome):
        with self.connect() as connection:
            connection.execute("INSERT INTO access_audit (principal_id, action, session_id, outcome) VALUES (?, ?, ?, ?)",
                               (principal.id, action, session_id, outcome))

    def forget(self, session_id=None):
        with self.connect() as connection:
            if session_id is None:
                connection.execute("DELETE FROM access_session_owners")
                connection.execute("DELETE FROM access_sources")
                connection.execute("DELETE FROM access_invalidated_evidence")
            else:
                connection.execute("DELETE FROM access_session_owners WHERE session_id=?", (session_id,))
                connection.execute("DELETE FROM access_sources WHERE session_id=?", (session_id,))
                connection.execute("DELETE FROM access_invalidated_evidence WHERE session_id=?", (session_id,))

    def revoke_evidence_refs(self, session_id, source, references):
        """Commit permanent reference tombstones without changing the raw audit."""
        with self.connect() as connection:
            connection.executemany("INSERT OR IGNORE INTO access_invalidated_evidence VALUES (?,?,?,?,?)",
                                   [(session_id, source["source_id"], reference, source["revision"], source["digest"])
                                    for reference in sorted(set(references))])

    def evidence_reference_state(self, session_id):
        """Read one snapshot; a missing database/table must not recreate proof."""
        connection = sqlite3.connect(Path(self.path).absolute().as_uri() + "?mode=rw", uri=True, timeout=10)
        try:
            connection.execute("BEGIN")
            revoked = {row[0] for row in connection.execute(
                "SELECT reference FROM access_invalidated_evidence WHERE session_id=?", (session_id,))}
            sources = [json.loads(row[0]) for row in connection.execute(
                "SELECT document FROM access_sources WHERE session_id=?", (session_id,))]
            if any(not isinstance(source, dict) or any(not isinstance(source.get(key), str) or not source[key]
                                                      for key in ("source_id", "revision", "digest")) for source in sources):
                raise RuntimeError("Source reference state unavailable")
            return revoked, sources
        except (ValueError, TypeError):
            raise RuntimeError("Source reference state unavailable") from None
        finally:
            connection.close()

    def sources(self, session_id):
        with self.connect() as connection:
            return [json.loads(row[0]) for row in connection.execute(
                "SELECT document FROM access_sources WHERE session_id=? ORDER BY source_id, kind", (session_id,))]

    def put_source(self, session_id, document):
        """Publish source metadata and its revision disposition in one commit.

        The admission layer must durably invalidate affected coverage first.
        """
        with self.connect() as connection:
            connection.execute("INSERT OR REPLACE INTO access_sources VALUES (?,?,?,?)",
                               (session_id, document["source_id"], document["kind"], json.dumps(document)))


class AccessControl:
    def __init__(self, legacy_token, store):
        self.legacy_token, self.store = legacy_token, store

    def authenticate(self, headers, query=None):
        configured = os.environ.get("KMN_AUTH_PRINCIPALS_FILE")
        authorization = headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        token = token if scheme.lower() == "bearer" else ""
        if configured is not None:
            try:
                document = json.loads(Path(configured).read_text(encoding="utf-8"))
                if not isinstance(document, dict) or set(document) != {"principals"}:
                    raise ValueError
                records = document["principals"]
                if not isinstance(records, list) or not records:
                    raise ValueError
                identities, digests, principals = set(), set(), []
                for record in records:
                    if (not isinstance(record, dict)
                            or set(record) - {"id", "role", "token_sha256", "sensitive_read", "sessions"}
                            or not isinstance(record.get("id"), str)
                            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}", record["id"])
                            or record.get("role") not in {"viewer", "operator", "reviewer", "admin"}
                            or not isinstance(record.get("token_sha256"), str)
                            or not re.fullmatch(r"[0-9a-f]{64}", record["token_sha256"])
                            or type(record.get("sensitive_read", False)) is not bool
                            or not isinstance(record.get("sessions", []), list)
                            or any(not isinstance(sid, str) or not sid or sid == "*" for sid in record.get("sessions", []))
                            or record["id"] in identities or record["token_sha256"] in digests):
                        raise ValueError
                    identities.add(record["id"])
                    digests.add(record["token_sha256"])
                    principals.append((record["token_sha256"], Principal(
                        record["id"], record["role"], record.get("sensitive_read", False), tuple(record.get("sessions", [])))))
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                raise AccessError(503, "Principal configuration unavailable") from None
            supplied = hashlib.sha256(token.encode()).hexdigest()
            for digest, principal in principals:
                if token and hmac.compare_digest(digest, supplied):
                    return principal
        else:
            token = token or headers.get("x-api-key", "") or (query or {}).get("token", "")
            if token and self.legacy_token and hmac.compare_digest(token, self.legacy_token):
                return Principal("legacy-service-admin", "admin", True, mode="legacy_service_admin")
        raise AccessError(401, "Missing or invalid bearer token")

    def can_access(self, principal, session_id):
        return principal.admin or session_id in principal.sessions or self.store.owns(session_id, principal)

    def authorize(self, principal, method, path, session_ids=()):
        for sid in session_ids:
            if not isinstance(sid, str) or not sid or not self.can_access(principal, sid):
                raise AccessError(403, "Session access denied")
        if principal.admin:
            return
        match = re.fullmatch(r"/api/sessions/([^/]+)(?:/(.*))?", path)
        suffix = (match.group(2) or "") if match else None
        read = method in {"GET", "HEAD"}
        if read and path in {"/", "/health", "/api/identity", "/api/docs", "/api/redoc", "/openapi.json", "/api/openapi.json",
                             "/api/sessions", "/api/sessions/history", "/api/stats", "/api/vulnerabilities"}:
            return
        if match and match.group(1) != "history":
            if read:
                if suffix in {"", "report.json", "report.sarif", "vulnerabilities", "telemetry/summary", "completeness", "preflight"}:
                    return
                if principal.sensitive:
                    return
            elif principal.role == "reviewer" and (suffix.endswith("/verification") or suffix in {"waivers", "assessment/coverage"}):
                return
            elif principal.role == "operator" and (
                    suffix in {"full_auto", "complete", "cancel", "start", "analyze", "resume", "steer", "restart", "rescan"}
                    or (principal.sensitive and suffix in {"assessment/import", "assessment/coverage", "sources/import", "handoffs"})
                    or (principal.sensitive and suffix.startswith(("shells/", "pivot/")))):
                return
            if suffix == "ask" and principal.role in {"operator", "reviewer"} and principal.sensitive:
                return
        if path in {"/api/start", "/api/preflight", "/api/execute"} and method == "POST" and principal.role == "operator":
            return
        if path == "/api/approve" and method == "POST" and principal.role == "reviewer":
            return
        raise AccessError(403, "Permission denied")

    @staticmethod
    def session_references(value):
        """Inspect nested request data; foreign source/destination IDs are not exempt."""
        references = []
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "session_id" or key.endswith("_session_id"):
                    if not isinstance(item, str) or not item:
                        raise AccessError(400, "Invalid session reference")
                    references.append(item)
                elif key == "session_ids" or key.endswith("_session_ids"):
                    if not isinstance(item, list) or any(not isinstance(sid, str) or not sid for sid in item):
                        raise AccessError(400, "Invalid session references")
                    references.extend(item)
                else:
                    references.extend(AccessControl.session_references(item))
        elif isinstance(value, list):
            for item in value:
                references.extend(AccessControl.session_references(item))
        return references

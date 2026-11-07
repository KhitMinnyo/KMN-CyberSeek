"""
KMN-CyberSeek Hybrid Memory Index
=================================

A per-session retrieval index over engagement "findings" (command output
summaries, evidence, vulnerabilities, credentials). The tactical AI loop only
ever fits a bounded window of recent history in its context; on long engagements
the earliest — and often most critical — findings fall out of that window.

This index lets the orchestrator pull the *most relevant* past findings back into
context on demand, keyed to what the AI is currently reasoning about, instead of
relying on blunt truncation.

Retrieval is HYBRID:

  * When explicitly opted in via MEMORY_EMBEDDINGS=1, findings and the query are
    embedded and ranked by cosine similarity (true semantic retrieval).
  * Otherwise it falls back to a dependency-free lexical ranker (TF-IDF cosine),
    which works fully offline and in API-only deployments.

The fallback is automatic and per-index: the first embedding failure flips the
index to lexical mode for the rest of the session, so a missing embed model or an
offline Ollama never breaks the reasoning loop.
"""

from __future__ import annotations

import logging
import hashlib
import json
import math
import os
import re
import sqlite3
import threading
from collections import Counter
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._/-]*")
# Common noise tokens that carry little discriminative signal for retrieval.
_STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "from", "was", "were", "not",
    "you", "your", "are", "has", "have", "can", "will", "http", "https", "com",
    "tcp", "udp", "open", "port", "host", "scan", "output", "command", "found",
}


def _tokenize(text: str) -> List[str]:
    toks = _TOKEN_RE.findall((text or "").lower())
    return [t for t in toks if len(t) > 2 and t not in _STOPWORDS]


def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class FindingsIndex:
    """In-memory hybrid retrieval index for one engagement session."""

    def __init__(self, connector=None, embed_model: Optional[str] = None):
        # `connector` is a KMN_AI_Connector; used only to discover the Ollama URL
        # and provider. We never route strategy through it — this is pure retrieval.
        self._connector = connector
        self._docs: List[Dict] = []          # {id, text, meta, vec}
        self._seen_hashes: set = set()

        # Embeddings must be explicitly enabled, even for local deployments.
        self._embed_model = (
            embed_model
            or os.getenv("OLLAMA_EMBED_MODEL")
            or "nomic-embed-text"
        )
        env_toggle = os.getenv("MEMORY_EMBEDDINGS", "off").lower()
        if env_toggle in ("0", "off", "false", "no"):
            self._embed_enabled = False
        elif env_toggle in ("1", "on", "true", "yes"):
            self._embed_enabled = True
        else:
            self._embed_enabled = False

        self._embed_url = self._derive_embed_url(connector)
        if not self._embed_url:
            self._embed_enabled = False

    # ── construction helpers ─────────────────────────────────────────────────

    @staticmethod
    def _derive_embed_url(connector) -> Optional[str]:
        gen_url = getattr(connector, "ollama_url", None)
        if not gen_url:
            base = (os.getenv("OLLAMA_URL") or "http://localhost:11434").rstrip("/")
            return f"{base}/api/embeddings"
        # connector.ollama_url ends in /api/generate — swap the suffix.
        if gen_url.endswith("/api/generate"):
            return gen_url[: -len("/api/generate")].rstrip("/") + "/api/embeddings"
        return gen_url.rstrip("/") + "/api/embeddings"

    # ── ingestion ────────────────────────────────────────────────────────────

    def add(self, text: str, meta: Optional[Dict] = None) -> bool:
        """Add a finding. Deduplicates on normalized text. Returns True if added.
        Embedding (when enabled) is computed lazily at retrieval time, so ingestion
        stays cheap and never blocks the command loop on the network."""
        text = (text or "").strip()
        if len(text) < 8:
            return False
        h = hash(re.sub(r"\s+", " ", text.lower())[:400])
        if h in self._seen_hashes:
            return False
        self._seen_hashes.add(h)
        self._docs.append({
            "id": len(self._docs),
            "text": text[:1200],
            "meta": meta or {},
            "vec": None,
        })
        return True

    def __len__(self) -> int:
        return len(self._docs)

    # ── embeddings (best-effort, fail-open to lexical) ───────────────────────

    def _embed(self, text: str) -> Optional[List[float]]:
        if not self._embed_enabled:
            return None
        try:
            import requests  # local import: keeps module import-safe if absent
            resp = requests.post(
                self._embed_url,
                json={"model": self._embed_model, "prompt": text[:2000]},
                timeout=float(os.getenv("MEMORY_EMBED_TIMEOUT", "8")),
            )
            resp.raise_for_status()
            data = resp.json()
            vec = data.get("embedding")
            if isinstance(vec, list) and vec and all(isinstance(x, (int, float)) for x in vec):
                return [float(x) for x in vec]
            raise ValueError("no 'embedding' array in response")
        except Exception:
            # One failure disables embeddings for the rest of the session.
            logger.info(
                "FindingsIndex: embeddings unavailable; "
                "falling back to lexical retrieval for this session."
            )
            self._embed_enabled = False
            return None

    def _ensure_doc_vectors(self) -> bool:
        """Embed any docs missing a vector. Returns True if embeddings are usable."""
        if not self._embed_enabled:
            return False
        for doc in self._docs:
            if doc["vec"] is None:
                doc["vec"] = self._embed(doc["text"])
                if not self._embed_enabled:  # got disabled mid-loop
                    return False
        return True

    # ── retrieval ────────────────────────────────────────────────────────────

    def retrieve(self, query: str, k: int = 5) -> List[Dict]:
        """Return up to k most relevant findings for `query`, each as
        {text, meta, score, method}. Empty list if the index is empty."""
        if k <= 0 or not self._docs or not query.strip():
            return []

        # Try the semantic path first; fall back to lexical on any shortfall.
        if self._embed_enabled and self._ensure_doc_vectors():
            qvec = self._embed(query)
            if qvec:
                scored = [
                    (doc, _cosine(qvec, doc["vec"]))
                    for doc in self._docs if doc["vec"]
                ]
                return self._top(scored, k, "embedding")

        return self._lexical_retrieve(query, k)

    def _lexical_retrieve(self, query: str, k: int) -> List[Dict]:
        """TF-IDF cosine ranking over the doc set. Pure-python, no dependencies."""
        doc_tokens = [_tokenize(d["text"]) for d in self._docs]
        n = len(self._docs)
        # Document frequency
        df: Counter = Counter()
        for toks in doc_tokens:
            for t in set(toks):
                df[t] += 1

        def _idf(term: str) -> float:
            return math.log((n + 1) / (df.get(term, 0) + 1)) + 1.0

        def _vec(toks: List[str]) -> Dict[str, float]:
            tf = Counter(toks)
            total = sum(tf.values()) or 1
            return {t: (c / total) * _idf(t) for t, c in tf.items()}

        qv = _vec(_tokenize(query))
        if not qv:
            return []

        def _sparse_cos(a: Dict[str, float], b: Dict[str, float]) -> float:
            if not a or not b:
                return 0.0
            common = set(a) & set(b)
            dot = sum(a[t] * b[t] for t in common)
            na = math.sqrt(sum(v * v for v in a.values()))
            nb = math.sqrt(sum(v * v for v in b.values()))
            return dot / (na * nb) if na and nb else 0.0

        scored = [
            (self._docs[i], _sparse_cos(qv, _vec(doc_tokens[i])))
            for i in range(n)
        ]
        return self._top(scored, k, "lexical")

    @staticmethod
    def _top(scored: List[Tuple[Dict, float]], k: int, method: str) -> List[Dict]:
        scored = [s for s in scored if s[1] > 0.0]
        scored.sort(key=lambda x: x[1], reverse=True)
        out = []
        for doc, score in scored[:k]:
            out.append({
                "text": doc["text"],
                "meta": doc["meta"],
                "score": round(float(score), 4),
                "method": method,
            })
        return out

    @property
    def mode(self) -> str:
        return "embedding" if self._embed_enabled else "lexical"


class SecretRedactor:
    """Shared boundary redaction. Supplied credential values never leave this object.

    `credentials` may be a string, list/tuple/set, or nested mapping of secrets.
    Pattern matching is defense in depth, not a way to discover arbitrary secrets.
    """

    _sensitive = re.compile(
        r"(?i)(?:password|passwd|pwd|secret|token|authorization|proxy.authorization|"
        r"cookie|set.cookie|api.?key|access.?key|account.?key|shared.?access.?key|"
        r"private.?key|client.?secret|credential)"
    )
    _headers = re.compile(
        r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)"
        r"\s*[:=]\s*[^\r\n]+"
    )
    _assignments = re.compile(
        r'''(?ix)(["']?\b(?:password|passwd|pwd|secret|(?:access[ _-]?|refresh[ _-]?)?token|'''
        r'''api[ _-]?key|access[ _-]?key(?:[ _-]?id)?|(?:aws[ _-]?)?secret[ _-]?access[ _-]?key|'''
        r'''aws[ _-]?access[ _-]?key[ _-]?id|account[ _-]?key|shared[ _-]?access[ _-]?key|'''
        r'''client[ _-]?secret|credential)["']?\s*[:=]\s*)'''
        r'''(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&}\]]+)'''
    )

    def __init__(self, credentials=None):
        from urllib.parse import quote, quote_plus

        secrets = set()

        def collect(value, depth=0):
            if depth > 16:
                raise ValueError("Credential structure exceeds limits")
            if isinstance(value, str) and value:
                secrets.add(value)
            elif isinstance(value, Mapping):
                for item in value.values():
                    collect(item, depth + 1)
            elif isinstance(value, (list, tuple, set)):
                for item in value:
                    collect(item, depth + 1)
        collect(credentials)
        if len(secrets) > 1000 or sum(map(len, secrets)) > 100000:
            raise ValueError("Credential list exceeds limits")
        # One substitution avoids treating a short known secret as part of the marker.
        variants = {v for s in secrets for v in (s, quote(s, safe=""), quote_plus(s), json.dumps(s)[1:-1])}
        self._known = re.compile("|".join(re.escape(s) for s in sorted(variants, key=len, reverse=True))) if variants else None

    def text(self, value: str) -> str:
        if self._known:
            # Also remove encoded occurrences in URLs and JSON strings.
            value = self._known.sub("[REDACTED]", value)
        value = re.sub(r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)", "[REDACTED]", value)
        value = re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@", r"\1[REDACTED]@", value)
        # Query and fragment values can carry credentials under arbitrary names.
        value = re.sub(r"(?i)([a-z][a-z0-9+.-]*://[^\s?#<>\"']+)[?#][^\s<>\"']*", r"\1?[REDACTED]", value)
        value = self._headers.sub(lambda m: m.group(1) + ": [REDACTED]", value)
        value = self._assignments.sub(lambda m: m.group(1) + "[REDACTED]", value)
        value = re.sub(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_.=~-]+", "[REDACTED]", value)
        value = re.sub(r"\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk[-_][A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b", "[REDACTED]", value)
        return value

    def value(self, value, depth=0):
        if depth > 16:
            raise ValueError("Metadata structure exceeds limits")
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            if not all(isinstance(k, str) for k in value):
                raise ValueError("Metadata keys must be strings")
            return {self.text(k): "[REDACTED]" if self._sensitive.search(k) else self.value(v, depth + 1)
                    for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.value(v, depth + 1) for v in value]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        raise ValueError("Expected JSON metadata")


class PersistentFindingsIndex(FindingsIndex):
    """Session-only SQLite memory; no learning, promotion, or cross-session search.

    Construction creates the schema but does not restore documents. `add(text,
    meta=None)` and `retrieve(query, k=5)` retain FindingsIndex's concrete APIs.
    Results additionally contain `id`, `session_id`, `provenance`, and `trust`.
    Metadata's optional `source_id`, `revision`, `digest`, and `evidence_ref` are
    copied to provenance; these are assertions, never verification. Embeddings
    require MEMORY_EMBEDDINGS=1 explicitly and receive only redacted text.
    """

    def __init__(self, db_path, session_id, provider='api', ollama_url=None, credentials=None):
        if not isinstance(session_id, str) or not session_id or len(session_id) > 200:
            raise ValueError("Expected a bounded session identifier")
        super().__init__(SimpleNamespace(provider=provider, ollama_url=ollama_url))
        self.session_id = session_id
        self._redactor = SecretRedactor(credentials)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
        with self._db:
            self._db.execute("""CREATE TABLE IF NOT EXISTS persistent_findings (
                session_id TEXT NOT NULL, id TEXT NOT NULL, text TEXT NOT NULL,
                meta TEXT NOT NULL, provenance TEXT NOT NULL, trust TEXT NOT NULL,
                PRIMARY KEY(session_id, id))""")

    def _restore(self):
        # Refresh on use so another instance's purge is immediately respected.
        self._docs = [dict(id=row[0], text=self._redactor.text(row[1]),
                           meta=self._redactor.value(json.loads(row[2])),
                           provenance=self._redactor.value(json.loads(row[3])), trust="untrusted", vec=None)
                      for row in self._db.execute(
                          "SELECT id,text,meta,provenance,trust FROM persistent_findings "
                          "WHERE session_id=? ORDER BY id", (self.session_id,))]

    def add(self, text: str, meta: Optional[Dict] = None) -> bool:
        if not isinstance(text, str) or len(text.encode()) > 1024 * 1024:
            raise ValueError("Expected bounded finding text")
        text = self._redactor.text(text).strip()
        if len(text) < 8:
            return False
        if meta is not None and not isinstance(meta, dict):
            raise ValueError("Expected metadata object")
        metadata = self._redactor.value(meta or {})
        encoded = json.dumps(metadata, sort_keys=True, allow_nan=False)
        if len(encoded.encode()) > 32768:
            raise ValueError("Metadata exceeds limit")
        provenance = {k: metadata[k] for k in ("source_id", "revision", "digest", "evidence_ref") if k in metadata}
        provenance["origin"] = "session_finding"
        identity = json.dumps([re.sub(r"\s+", " ", text.lower()), provenance], sort_keys=True)
        doc_id = hashlib.sha256(identity.encode()).hexdigest()
        with self._lock, self._db:
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO persistent_findings VALUES (?,?,?,?,?,?)",
                (self.session_id, doc_id, text[:12000], encoded, json.dumps(provenance, sort_keys=True), "untrusted"))
            return cursor.rowcount == 1

    def __len__(self):
        with self._lock:
            return self._db.execute("SELECT count(*) FROM persistent_findings WHERE session_id=?",
                                    (self.session_id,)).fetchone()[0]

    def retrieve(self, query: str, k: int = 5) -> List[Dict]:
        if not isinstance(query, str) or len(query) > 32768 or type(k) is not int or not 0 <= k <= 100:
            raise ValueError("Invalid bounded retrieval request")
        with self._lock:
            self._restore()
            return super().retrieve(self._redactor.text(query), k)

    def _top(self, scored, k, method):
        out = []
        for doc, score in sorted(scored, key=lambda item: (-item[1], item[0]["id"])):
            if score > 0 and len(out) < k:
                out.append({"id": doc["id"], "session_id": self.session_id,
                            "text": doc["text"], "meta": doc["meta"],
                            "provenance": doc["provenance"], "trust": doc["trust"],
                            "score": round(float(score), 4), "method": method})
        return out

    def purge_session(self) -> int:
        """Delete only this instance's session; return the number of deleted docs."""
        with self._lock, self._db:
            cursor = self._db.execute("DELETE FROM persistent_findings WHERE session_id=?", (self.session_id,))
            self._docs.clear()
            self._seen_hashes.clear()
            return cursor.rowcount

    def close(self):
        self._db.close()

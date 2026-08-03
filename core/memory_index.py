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

  * When a local Ollama embedding model is reachable, findings and the query are
    embedded and ranked by cosine similarity (true semantic retrieval).
  * Otherwise it falls back to a dependency-free lexical ranker (TF-IDF cosine),
    which works fully offline and in API-only deployments.

The fallback is automatic and per-index: the first embedding failure flips the
index to lexical mode for the rest of the session, so a missing embed model or an
offline Ollama never breaks the reasoning loop.
"""

from __future__ import annotations

import logging
import math
import os
import re
from collections import Counter
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

        # Embedding config. Only attempt embeddings for local Ollama deployments;
        # in API-only mode we use the lexical ranker (no embedding endpoint).
        self._embed_model = (
            embed_model
            or os.getenv("OLLAMA_EMBED_MODEL")
            or "nomic-embed-text"
        )
        provider = getattr(connector, "provider", None)
        env_toggle = os.getenv("MEMORY_EMBEDDINGS", "auto").lower()
        if env_toggle in ("0", "off", "false", "no"):
            self._embed_enabled = False
        elif env_toggle in ("1", "on", "true", "yes"):
            self._embed_enabled = True
        else:  # "auto": embeddings only when a local provider is in play
            self._embed_enabled = provider == "local"

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
        except Exception as e:
            # One failure disables embeddings for the rest of the session.
            logger.info(
                f"FindingsIndex: embeddings unavailable ({e}); "
                f"falling back to lexical retrieval for this session."
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
        if not self._docs or not query.strip():
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

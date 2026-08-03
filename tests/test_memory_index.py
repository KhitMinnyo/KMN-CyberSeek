"""Tests for core/memory_index.py hybrid retrieval. We force the lexical path
(no embedding endpoint in tests) and verify relevance ranking, dedup, and the
fail-open behaviour."""

from core.memory_index import FindingsIndex, _tokenize


def _lexical_index():
    idx = FindingsIndex(connector=None)
    idx._embed_enabled = False  # force lexical, no network
    return idx


def test_tokenize_drops_stopwords_and_short():
    toks = _tokenize("The nmap scan found an OpenSSH server on port 22")
    assert "nmap" in toks and "openssh" in toks
    assert "the" not in toks and "on" not in toks


def test_add_dedup():
    idx = _lexical_index()
    assert idx.add("mysql root login succeeded, dumped password hashes")
    assert not idx.add("mysql root login succeeded, dumped password hashes")  # dup
    assert not idx.add("x")  # too short
    assert len(idx) == 1


def test_lexical_ranks_relevant_first():
    idx = _lexical_index()
    idx.add("nmap found ssh on port 22 running OpenSSH 7.2p2")
    idx.add("gobuster discovered /admin login panel with default creds admin:admin")
    idx.add("mysql root login succeeded, dumped users table with password hashes")
    res = idx.retrieve("credentials password hashes database", k=2)
    assert res, "expected results"
    assert res[0]["method"] == "lexical"
    # the mysql/hashes finding should rank at or near the top
    assert any("hash" in r["text"] or "password" in r["text"] for r in res)


def test_retrieve_empty_index():
    idx = _lexical_index()
    assert idx.retrieve("anything", k=3) == []


def test_mode_reports_lexical():
    idx = _lexical_index()
    assert idx.mode == "lexical"


def test_embeddings_fail_open_to_lexical():
    """If embeddings are enabled but the endpoint is unreachable, retrieval must
    still succeed via lexical fallback rather than raising."""
    idx = FindingsIndex(connector=None)
    idx._embed_enabled = True
    idx._embed_url = "http://127.0.0.1:1/api/embeddings"  # unroutable
    idx.add("smb share ACCESS granted, found backup.zip with config")
    idx.add("wordpress xmlrpc enabled, users admin editor enumerated")
    res = idx.retrieve("smb share access backup", k=1)
    assert res and res[0]["method"] == "lexical"
    assert idx.mode == "lexical"  # got flipped off after the failure

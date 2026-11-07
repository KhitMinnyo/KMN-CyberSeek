"""Tests for core/memory_index.py hybrid retrieval. We force the lexical path
(no embedding endpoint in tests) and verify relevance ranking, dedup, and the
fail-open behaviour."""

from core.memory_index import FindingsIndex, _tokenize
from core.memory_index import PersistentFindingsIndex, SecretRedactor

import json
import sqlite3

import pytest


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


def test_embeddings_fail_open_to_lexical(monkeypatch):
    """If embeddings are enabled but the endpoint is unreachable, retrieval must
    still succeed via lexical fallback rather than raising."""
    idx = FindingsIndex(connector=None)
    import requests

    def unavailable(*args, **kwargs):
        raise requests.ConnectionError("offline embedding stub")

    monkeypatch.setattr(requests, "post", unavailable)
    idx._embed_enabled = True
    idx._embed_url = "http://127.0.0.1:1/api/embeddings"  # unroutable
    idx.add("smb share ACCESS granted, found backup.zip with config")
    idx.add("wordpress xmlrpc enabled, users admin editor enumerated")
    res = idx.retrieve("smb share access backup", k=1)
    assert res and res[0]["method"] == "lexical"
    assert idx.mode == "lexical"  # got flipped off after the failure


def test_persistent_restore_provenance_isolation_and_purge(tmp_path, monkeypatch):
    monkeypatch.delenv("MEMORY_EMBEDDINGS", raising=False)
    path = tmp_path / "memory.db"
    first = PersistentFindingsIndex(path, "first", provider="local")
    assert first.mode == "lexical"
    meta = {"source_id": "repo", "revision": "abc", "digest": "a" * 64,
            "evidence_ref": "evidence:scan", "verified": True}
    assert first.add("Database authorization bypass hypothesis", meta)
    assert not first.add("Database authorization bypass hypothesis", meta)
    result = first.retrieve("database")[0]
    assert result["trust"] == "untrusted"
    assert result["provenance"]["revision"] == "abc"
    assert len(result["id"]) == 64
    first.close()
    restored = PersistentFindingsIndex(path, "first")
    assert restored._docs == []  # lazy restoration
    assert restored.retrieve("database")[0] == result
    other = PersistentFindingsIndex(path, "other")
    assert other.retrieve("database") == []
    assert other.add("Database independent session evidence")
    second_handle = PersistentFindingsIndex(path, "first")
    assert second_handle.retrieve("database")
    assert restored.purge_session() == 1
    assert second_handle.retrieve("database") == []
    assert other.retrieve("database")
    for index in (restored, other, second_handle):
        index.close()


def test_redaction_before_disk_and_embeddings(tmp_path, monkeypatch):
    path = tmp_path / "memory.db"
    monkeypatch.setenv("MEMORY_EMBEDDINGS", "true")
    index = PersistentFindingsIndex(path, "s", credentials={"token": "super known/secret"})
    assert index.mode == "embedding"
    text = ("Database evidence super known/secret at https://alice:pass123@example.test/path?arbitrary=hidden\n"
            "Authorization: Bearer bearer-secret\nCookie: sid=cookie-secret\npassword=pass-secret\n"
            "api_key=key-secret\n-----BEGIN PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----")
    index.add(text, {"password": "nested-secret", "notes": ["super known/secret"],
                     "url": "https://example.test/?opaque=query-secret"})
    sent = []

    def embed(value):
        sent.append(value)
        return [1.0, 0.5]

    monkeypatch.setattr(index, "_embed", embed)
    assert index.retrieve("database super known/secret")
    with sqlite3.connect(path) as db:
        saved = json.dumps(db.execute("SELECT * FROM persistent_findings").fetchall())
    for secret in ("super known/secret", "alice", "pass123", "hidden", "bearer-secret", "cookie-secret",
                   "pass-secret", "key-secret", "key-material", "nested-secret", "query-secret"):
        assert secret not in saved
        assert secret not in " ".join(sent)
    index.close()


@pytest.mark.parametrize("text", [
    'password="with spaces"', "passwd='with spaces'", "token=abc123", "Basic YWxhZGRpbjpvcGVuc2VzYW1l",
    "https://u:p@example.test/a?session=secret#hidden", "Set-Cookie: session=abc; Secure",
])
def test_common_redaction(text):
    assert SecretRedactor().text(text) != text


def test_known_secrets_encoded_and_nested():
    redact = SecretRedactor(["unsafe/value", "other secret"])
    assert "unsafe%2Fvalue" not in redact.text("unsafe%2Fvalue")
    assert "other+secret" not in redact.text("other+secret")
    assert redact.value({"nested": {"access_token": "value"}})["nested"]["access_token"] == "[REDACTED]"


def test_connection_urls_aws_keys_and_incomplete_private_key():
    redact = SecretRedactor()
    assert "pass123" not in redact.text("postgresql://alice:pass123@db.test/app")
    assert "cloud-secret" not in redact.text("AWS_SECRET_ACCESS_KEY=cloud-secret")
    assert "key-material" not in redact.text("-----BEGIN RSA PRIVATE KEY-----\nkey-material")


def test_persistent_limits_and_stable_full_text_id(tmp_path):
    index = PersistentFindingsIndex(tmp_path / "db", "s")
    assert index.add("prefix " * 70 + "one")
    assert index.add("prefix " * 70 + "two")  # no old 400-character dedup collision
    assert index.retrieve("prefix", k=0) == []
    with pytest.raises(ValueError):
        index.retrieve("prefix", k=-1)
    with pytest.raises(ValueError):
        index.add("finding text", {"bad": float("nan")})
    index.close()


def test_new_credentials_also_redact_restored_documents(tmp_path):
    path = tmp_path / "db"
    old = PersistentFindingsIndex(path, "s")
    old.add("Database hypothesis includes previously-unknown-value")
    old.close()
    restored = PersistentFindingsIndex(path, "s", credentials=["previously-unknown-value"])
    assert "previously-unknown-value" not in restored.retrieve("database")[0]["text"]
    restored.close()


def test_provenance_is_redacted_before_disk_and_survives_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMORY_EMBEDDINGS", "off")
    path = tmp_path / "state.db"
    credentials = ["provenance-secret", "other/value"]
    index = PersistentFindingsIndex(path, "s", credentials=credentials)
    meta = {"source_id": "repo-provenance-secret", "revision": "commit-other%2Fvalue",
            "digest": "a" * 64,
            "evidence_ref": {"ref": "evidence:provenance-secret", "Authorization": "Bearer header-secret"},
            "nested": [{"password": "nested-secret", "url": "https://u:url-secret@api.test/?q=query-secret"}]}
    assert index.add("Database source provenance hypothesis", meta)
    original = index.retrieve("database")[0]
    index.close()
    restored = PersistentFindingsIndex(path, "s", credentials=credentials)
    result = restored.retrieve("database")[0]
    assert result == original
    assert result["provenance"]["source_id"] == "repo-[REDACTED]"
    assert result["provenance"]["revision"] == "commit-[REDACTED]"
    assert result["provenance"]["evidence_ref"]["Authorization"] == "[REDACTED]"
    assert result["trust"] == "untrusted"
    assert not restored.add("Database source provenance hypothesis", meta)
    assert len(restored) == 1
    restored.close()
    with sqlite3.connect(path) as db:
        persisted = json.dumps(db.execute("SELECT * FROM persistent_findings").fetchall())
    for secret in ("provenance-secret", "other%2Fvalue", "header-secret", "nested-secret", "url-secret", "query-secret"):
        assert secret not in json.dumps(result)
        assert secret not in persisted
        assert secret.encode() not in path.read_bytes()


def test_new_credentials_redact_restored_provenance_without_changing_id(tmp_path):
    path = tmp_path / "state.db"
    original = PersistentFindingsIndex(path, "s")
    original.add("Database evidence hypothesis", {"source_id": "repo-future-secret",
                 "revision": "commit-future-secret", "evidence_ref": "evidence:future-secret"})
    previous_id = original.retrieve("database")[0]["id"]
    original.close()
    restored = PersistentFindingsIndex(path, "s", credentials=["future-secret"])
    result = restored.retrieve("database")[0]
    assert result["id"] == previous_id
    assert "future-secret" not in json.dumps(result)
    assert result["provenance"]["evidence_ref"] == "evidence:[REDACTED]"
    restored.close()

import hashlib
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.fernet import Fernet

from core.artifact_store import ArtifactStore, ArtifactStoreError, DEFAULT_MAX_BYTES


@pytest.fixture
def root(tmp_path):
    # macOS temporary paths may have a symlink ancestor outside the store.
    return tmp_path.resolve() / "artifacts"


def artifact_path(root, manifest):
    session, token = manifest["id"].split(".")
    return root / session / (token + ".artifact")


def committed(store, data=b"raw\xff\x00\xfe\n", session="session-1", **kwargs):
    capture = store.capture(session, "attempt-1", "stdout")
    capture.write(data)
    return capture.finalize(**kwargs)


def test_raw_bytes_hashes_permissions_and_reopen(root):
    store = ArtifactStore(root)
    data = b"raw\xff\x00\xfe\n"
    manifest = committed(store, data)
    assert store.max_bytes == DEFAULT_MAX_BYTES == 16 * 1024 * 1024
    assert store.read(manifest["id"]) == data
    assert ArtifactStore(root).read(manifest["id"]) == data
    assert manifest["sha256"] == manifest["stored_sha256"] == hashlib.sha256(data).hexdigest()
    assert manifest["sha256_scope"] == "observed"
    assert manifest["size_bytes"] == manifest["stored_bytes"] == len(data)
    assert manifest["truncated"] is False
    assert manifest["encrypted"] is False
    assert manifest["protection"] == "filesystem-permissions"
    assert manifest["uri"] == "artifact://" + manifest["id"]
    path = artifact_path(root, manifest)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert store.manifests("session-1") == [manifest]
    assert store.manifests("missing") == []


@pytest.mark.parametrize("limit", [0, 1, 13, 500])
def test_streaming_bounded_prefix_hashes_all_observed_bytes(root, limit):
    store = ArtifactStore(root, max_bytes=limit)
    capture = store.capture("session", "attempt", "stderr")
    chunks = [b"", b"abc\xff", b"x" * 1000, b"tail"]
    for chunk in chunks:
        assert capture.write(chunk) == len(chunk)
        assert len(capture._prefix) <= limit
    manifest = capture.finalize(outcome="timeout")
    observed = b"".join(chunks)
    assert manifest["sha256"] == hashlib.sha256(observed).hexdigest()
    assert manifest["stored_sha256"] == hashlib.sha256(observed[:limit]).hexdigest()
    assert manifest["size_bytes"] == len(observed)
    assert manifest["stored_bytes"] == limit
    assert manifest["truncated"] is True
    assert manifest["outcome"] == "timeout"
    assert store.read(manifest["id"]) == observed[:limit]
    assert len(artifact_path(root, manifest).read_bytes()) < limit + 8192
    assert capture._prefix == bytearray()


@pytest.mark.parametrize("encrypted", [False, True])
def test_empty_and_exact_limit_are_not_truncated(root, encrypted):
    store = ArtifactStore(root, key=Fernet.generate_key() if encrypted else None, max_bytes=3)
    for data in (b"", b"abc"):
        manifest = committed(store, data)
        assert manifest["truncated"] is False
        assert store.read(manifest["id"]) == data


def test_encryption_no_plaintext_metadata_or_staging(root, monkeypatch):
    key = Fernet.generate_key()
    store = ArtifactStore(root, key=key.decode("ascii"), max_bytes=30)
    secret = b"password=DO_NOT_PERSIST_AS_PLAIN"
    capture = store.capture("secret-session", "secret-attempt", "combined")
    capture.write(secret + b"discarded")
    assert list(root.rglob("*")) == [root / capture.id.split(".")[0]]
    original_link = os.link

    def inspect_publish(source, destination, **kwargs):
        pending = root / capture.id.split(".")[0] / source
        assert secret not in pending.read_bytes()
        assert key not in pending.read_bytes()
        assert stat.S_IMODE(pending.stat().st_mode) == 0o600
        return original_link(source, destination, **kwargs)

    monkeypatch.setattr(os, "link", inspect_publish)
    manifest = capture.finalize("cancelled")
    assert manifest["encrypted"] is True
    assert manifest["protection"] == "fernet"
    assert manifest["storage_bytes"] > manifest["stored_bytes"]
    assert store.read(manifest["id"]) == secret[:30]
    assert ArtifactStore(root, key=key).read(manifest["id"]) == secret[:30]
    assert ArtifactStore(root).manifests("secret-session") == [manifest]
    with pytest.raises(ArtifactStoreError, match="requires a key"):
        ArtifactStore(root).read(manifest["id"])
    with pytest.raises(ArtifactStoreError, match="decryption failed"):
        ArtifactStore(root, key=Fernet.generate_key()).read(manifest["id"])
    metadata = json.dumps(manifest)
    for value in ("secret-session", "secret-attempt", secret.decode(), key.decode()):
        assert value not in metadata
        assert all(value not in str(path.relative_to(root)) for path in root.rglob("*"))


def test_context_manager_abort_and_closed_handles(root):
    store = ArtifactStore(root)
    with store.capture("session", "attempt", "stdout") as capture:
        capture.write(b"ok")
    assert store.read(capture.id) == b"ok"
    with pytest.raises(ValueError, match="closed"):
        capture.write(b"late")
    with pytest.raises(ValueError, match="closed"):
        capture.finalize()
    with pytest.raises(RuntimeError, match="caller failure"):
        with store.capture("session", "attempt", "stdout") as failed:
            failed.write(b"not committed")
            raise RuntimeError("caller failure")
    failed.abort()
    with pytest.raises(ArtifactStoreError):
        store.read(failed.id)
    assert len(store.manifests("session")) == 1
    capture = store.capture("session", "attempt", "stdout")
    with pytest.raises(TypeError, match="requires bytes"):
        capture.write("not bytes")
    capture.abort()
    assert capture._prefix == bytearray()


@pytest.mark.parametrize("value", ["", "../secret", "/secret", "a/b", "a\\b", ".", "..",
                                       "a\x00b", "a\nb", "a.b", "a" * 129, "caf\u00e9", None, 1])
def test_scope_validation_and_errors_do_not_echo_inputs(root, value):
    store = ArtifactStore(root)
    for action in (lambda: store.capture(value, "attempt", "stdout"),
                   lambda: store.capture("session", value, "stdout"),
                   lambda: store.manifests(value), lambda: store.purge_session(value)):
        with pytest.raises(ValueError, match="^Invalid artifact scope identifier$"):
            action()
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("value", ["../secret", "/tmp/secret", "a" * 64 + ".../secret",
                                       "artifact://" + "a" * 64 + "." + "b" * 32, None, 1])
def test_artifact_id_validation(root, value):
    with pytest.raises(ValueError, match="^Invalid artifact identifier$"):
        ArtifactStore(root).read(value)


def test_fixed_labels_prevent_metadata_injection(root):
    store = ArtifactStore(root)
    for value in ("password=secret", "../stdout", "stdout\n", None, []):
        with pytest.raises(ValueError, match="Invalid artifact stream"):
            store.capture("session", "attempt", value)
    capture = store.capture("session", "attempt", "stdout")
    for value in ("password=secret", None, []):
        with pytest.raises(ValueError, match="Invalid artifact outcome"):
            capture.finalize(value)
    assert capture.finalize("failed")["outcome"] == "failed"


@pytest.mark.parametrize("limit", [-1, 1.5, True, None])
def test_invalid_limits(root, limit):
    with pytest.raises(ValueError, match="Invalid artifact byte limit"):
        ArtifactStore(root, max_bytes=limit)


def test_bad_key_and_roots_are_sanitized(root):
    with pytest.raises(ValueError, match="^Invalid artifact encryption key$"):
        ArtifactStore(root, key=b"secret-key")
    with pytest.raises(ValueError, match="^Invalid artifact root$"):
        ArtifactStore(root / ".." / "escape")
    with pytest.raises(ValueError, match="^Invalid artifact root$"):
        ArtifactStore("/")


@pytest.mark.parametrize("value", ["", "secret\x00root", b"root", None])
def test_invalid_roots_are_rejected_without_filesystem_changes(value):
    with pytest.raises(ValueError, match="^Invalid artifact root$"):
        ArtifactStore(value)


@pytest.mark.parametrize("location", ["root", "ancestor", "session", "artifact"])
def test_symlinks_fail_closed(root, location):
    outside = root.parent / "outside"
    outside.mkdir(mode=0o700)
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"must survive")
    if location == "root":
        root.symlink_to(outside, target_is_directory=True)
        with pytest.raises(ArtifactStoreError):
            ArtifactStore(root)
    elif location == "ancestor":
        alias = root.parent / "alias"
        alias.symlink_to(outside, target_is_directory=True)
        with pytest.raises(ArtifactStoreError):
            ArtifactStore(alias / "nested")
        assert not (outside / "nested").exists()
    else:
        store = ArtifactStore(root)
        manifest = committed(store)
        path = artifact_path(root, manifest)
        path.unlink()
        if location == "session":
            path.parent.rmdir()
            path.parent.symlink_to(outside, target_is_directory=True)
        else:
            path.symlink_to(sentinel)
        for action in (lambda: store.read(manifest["id"]),
                       lambda: store.manifests("session-1"),
                       lambda: store.purge_session("session-1")):
            with pytest.raises(ArtifactStoreError):
                action()
    assert sentinel.read_bytes() == b"must survive"


def test_replaced_root_is_not_followed(root):
    store = ArtifactStore(root)
    original = root.with_name("original")
    root.rename(original)
    root.symlink_to(original, target_is_directory=True)
    with pytest.raises(ArtifactStoreError):
        store.capture("session", "attempt", "stdout")


@pytest.mark.parametrize("encrypted", [False, True])
def test_payload_and_hash_tampering_detected(root, encrypted):
    store = ArtifactStore(root, key=Fernet.generate_key() if encrypted else None)
    manifest = committed(store, b"abcdef")
    path = artifact_path(root, manifest)
    original = path.read_bytes()
    path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    with pytest.raises(ArtifactStoreError, match="integrity"):
        store.read(manifest["id"])
    path.write_bytes(original + b"extra")
    with pytest.raises(ArtifactStoreError, match="manifest"):
        store.read(manifest["id"])
    header, payload = original.split(b"\n", 1)
    altered = json.loads(header)
    altered["stored_sha256"] = "0" * 64
    path.write_bytes(json.dumps(altered).encode() + b"\n" + payload)
    with pytest.raises(ArtifactStoreError, match="integrity"):
        store.read(manifest["id"])


@pytest.mark.parametrize("header", [b"broken\n", b"[]\n", b"{}\n", b"\xff\n", b"x" * 9000])
def test_malformed_manifests_fail_closed(root, header):
    store = ArtifactStore(root)
    manifest = committed(store)
    artifact_path(root, manifest).write_bytes(header)
    with pytest.raises(ArtifactStoreError, match="manifest"):
        store.read(manifest["id"])
    with pytest.raises(ArtifactStoreError, match="manifest"):
        store.manifests("session-1")


def test_partial_is_invisible_and_publication_failure_cleans_up(root, monkeypatch):
    store = ArtifactStore(root)
    capture = store.capture("session", "attempt", "stdout")
    capture.write(b"not yet published")
    assert store.manifests("session") == []
    with pytest.raises(ArtifactStoreError):
        store.read(capture.id)

    def fail_link(*args, **kwargs):
        assert store.manifests("session") == []
        raise OSError("password=secret filesystem path")

    monkeypatch.setattr(os, "link", fail_link)
    with pytest.raises(ArtifactStoreError, match="^Artifact storage operation failed$"):
        capture.finalize()
    assert list((root / capture.id.split(".")[0]).iterdir()) == []
    assert capture._prefix == bytearray()


def test_existing_artifact_never_overwritten(root):
    store = ArtifactStore(root)
    first = committed(store, b"first")
    second = store.capture("session-1", "attempt-2", "stdout")
    second.id = first["id"]  # Force an otherwise astronomically unlikely collision.
    second.write(b"second")
    with pytest.raises(ArtifactStoreError):
        second.finalize()
    assert store.read(first["id"]) == b"first"
    assert store.manifests("session-1") == [first]
    assert len(list(artifact_path(root, first).parent.iterdir())) == 1


def test_parallel_captures_and_session_isolation(root):
    store = ArtifactStore(root)

    def save(index):
        return committed(store, str(index).encode(), session="one" if index % 2 else "two")

    with ThreadPoolExecutor(max_workers=8) as executor:
        manifests = list(executor.map(save, range(40)))
    assert len({manifest["id"] for manifest in manifests}) == 40
    assert len(store.manifests("one")) == len(store.manifests("two")) == 20
    assert store.purge_session("one") == 20
    assert store.purge_session("one") == 0
    assert store.manifests("one") == []
    for index, manifest in enumerate(manifests):
        if index % 2:
            with pytest.raises(ArtifactStoreError):
                store.read(manifest["id"])
        else:
            assert store.read(manifest["id"]) == str(index).encode()


def test_purge_includes_stale_pending_but_rejects_unknown_entries(root):
    store = ArtifactStore(root)
    capture = store.capture("session", "attempt", "stdout")
    directory = root / capture.id.split(".")[0]
    pending = directory / (".pending-" + "a" * 32)
    pending.write_bytes(b"interrupted finalize")
    unknown = directory / "unknown"
    unknown.mkdir()
    with pytest.raises(ArtifactStoreError, match="Unsafe"):
        store.purge_session("session")
    assert pending.exists()
    unknown.rmdir()
    assert store.purge_session("session") == 1
    with pytest.raises(ArtifactStoreError):
        capture.finalize()
    assert not directory.exists()


def test_insecure_files_and_hardlinks_rejected(root):
    store = ArtifactStore(root)
    manifest = committed(store)
    path = artifact_path(root, manifest)
    path.chmod(0o644)
    with pytest.raises(ArtifactStoreError, match="Unsafe"):
        store.read(manifest["id"])
    path.chmod(0o600)
    external_link = root.parent / "external-link"
    os.link(path, external_link)
    with pytest.raises(ArtifactStoreError, match="Unsafe"):
        store.read(manifest["id"])
    with pytest.raises(ArtifactStoreError, match="Unsafe"):
        store.purge_session("session-1")
    external_link.unlink()
    path.parent.chmod(0o755)
    with pytest.raises(ArtifactStoreError, match="Unsafe"):
        store.read(manifest["id"])

"""Permission-protected raw artifacts, optionally encrypted with supplied Fernet keys.

``sha256`` and ``size_bytes`` describe ALL bytes passed to write; ``stored_sha256``
and ``stored_bytes`` describe the retained plaintext prefix. Truncated tails cannot
be recovered or independently verified on read. IDs in metadata are pseudonymous,
not caller-provided labels. URIs are opaque references, not download authorization.

An artifact is one file: a JSON manifest line followed by its binary payload.
Publishing that file with a no-overwrite hard link commits both atomically. No
plaintext is staged on disk when encryption is enabled. Retention is explicit.
Filesystem permissions, not encryption or tamper authentication, protect plain
artifacts. The storage account must be trusted; permissions do not isolate code
running as the same OS user. Memory use is bounded by the configured prefix limit
(plus Fernet/serialization overhead), rather than the observed stream length.
"""

import hashlib
import json
import os
import re
import stat
import threading
import uuid
from contextlib import contextmanager

from cryptography.fernet import Fernet, InvalidToken


DEFAULT_MAX_BYTES = 16 * 1024 * 1024
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z", re.ASCII)
_ID = re.compile(r"([0-9a-f]{64})\.([0-9a-f]{32})\Z", re.ASCII)
_FILE = re.compile(r"(?:[0-9a-f]{32}\.artifact|\.pending-[0-9a-f]{32})\Z")
_STREAMS = {"stdout", "stderr", "combined", "output"}
_OUTCOMES = {"completed", "timeout", "timed_out", "cancelled", "canceled",
             "failed", "error", "aborted", "interrupted", "blocked"}
_HEADER_LIMIT = 8192
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class ArtifactStoreError(RuntimeError):
    """A storage/integrity failure, deliberately without paths or raw content."""


def _label(value):
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise ValueError("Invalid artifact scope identifier")
    return value


def _scope(kind, value):
    return hashlib.sha256((kind + "\0" + _label(value)).encode("ascii")).hexdigest()


def _identity(value):
    match = _ID.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("Invalid artifact identifier")
    return match.groups()


def _check(fd, directory=False):
    info = os.fstat(fd)
    expected = 0o700 if directory else 0o600
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not valid_type or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != expected
            or (not directory and info.st_nlink != 1)):
        raise ArtifactStoreError("Unsafe artifact storage permissions or type")


class ArtifactStore:
    """Store bounded byte prefixes; key is a Fernet key (bytes or ASCII text).

    Session/attempt IDs are 1-128 ASCII letters, digits, underscores or hyphens,
    starting with a letter/digit. Streams and outcomes use fixed labels. Sessions
    and attempts are stored as SHA-256 pseudonyms, never as their original IDs.
    Existing root permissions are restricted to 0700; ancestors must exist and
    must not be symlinks. All public filesystem errors omit sensitive paths.
    """

    def __init__(self, root, key=None, max_bytes=DEFAULT_MAX_BYTES):
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("Invalid artifact byte limit")
        try:
            raw_root = os.fspath(root)
            if (not isinstance(raw_root, str) or not raw_root or "\0" in raw_root
                    or ".." in raw_root.split(os.sep)):
                raise ValueError
            self._root = os.path.abspath(raw_root)
            if self._root == os.sep:
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError("Invalid artifact root") from None
        try:
            self._fernet = Fernet(key) if key is not None else None
        except (ValueError, TypeError, UnicodeError):
            raise ValueError("Invalid artifact encryption key") from None
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        with self._root_fd(create=True):
            pass

    @contextmanager
    def _root_fd(self, create=False):
        fd = None
        try:
            fd = os.open(os.sep, _DIR_FLAGS)
            parts = self._root.strip(os.sep).split(os.sep)
            for index, part in enumerate(parts):
                if create and index == len(parts) - 1:
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
            if create:
                if os.fstat(fd).st_uid != os.getuid():
                    raise ArtifactStoreError("Unsafe artifact storage owner")
                os.fchmod(fd, 0o700)
            _check(fd, directory=True)
            yield fd
        except OSError:
            raise ArtifactStoreError("Artifact storage operation failed") from None
        finally:
            if fd is not None:
                os.close(fd)

    @contextmanager
    def _session_fd(self, root_fd, session, create=False):
        if create:
            try:
                os.mkdir(session, 0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
        fd = os.open(session, _DIR_FLAGS, dir_fd=root_fd)
        try:
            _check(fd, directory=True)
            yield fd
        finally:
            os.close(fd)

    def capture(self, session_id, attempt_id, stream):
        """Return an in-memory capture; only finalize makes it visible on disk."""
        session = _scope("session", session_id)
        attempt = _scope("attempt", attempt_id)
        if not isinstance(stream, str) or stream not in _STREAMS:
            raise ValueError("Invalid artifact stream")
        with self._lock, self._root_fd() as root_fd:
            with self._session_fd(root_fd, session, create=True):
                pass
        return _Capture(self, session, attempt, stream)

    def _publish(self, manifest, payload):
        session, token = _identity(manifest["id"])
        header = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        with self._lock, self._root_fd() as root_fd:
            # Do not recreate purged sessions when an old capture is finalized.
            with self._session_fd(root_fd, session) as fd:
                temporary = ".pending-" + uuid.uuid4().hex
                created = False
                try:
                    file_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                      | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                    created = True
                    with os.fdopen(file_fd, "wb") as output:
                        os.fchmod(output.fileno(), 0o600)
                        output.write(header)
                        output.write(payload)
                        output.flush()
                        os.fsync(output.fileno())
                    # link fails rather than replacing any existing destination.
                    os.link(temporary, token + ".artifact", src_dir_fd=fd,
                            dst_dir_fd=fd, follow_symlinks=False)
                finally:
                    if created:
                        os.unlink(temporary, dir_fd=fd)
                os.fsync(fd)

    def _load(self, fd, token, session, include_payload=False):
        file_fd = os.open(token + ".artifact", os.O_RDONLY | os.O_NOFOLLOW
                          | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, "rb") as source:
            _check(source.fileno())
            header = source.readline(_HEADER_LIMIT + 1)
            if len(header) > _HEADER_LIMIT or not header.endswith(b"\n"):
                raise ArtifactStoreError("Invalid artifact manifest")
            try:
                manifest = json.loads(header)
                expected_id = session + "." + token
                fields = {"version", "id", "uri", "session_id", "attempt_id", "stream",
                          "outcome", "sha256", "sha256_scope", "stored_sha256",
                          "payload_sha256", "size_bytes", "stored_bytes", "storage_bytes",
                          "truncated", "encrypted", "protection"}
                if not isinstance(manifest, dict) or set(manifest) != fields:
                    raise ValueError
                if (manifest["version"] != 1 or manifest["id"] != expected_id
                        or manifest["uri"] != "artifact://" + expected_id
                        or manifest["session_id"] != session
                        or not re.fullmatch(r"[0-9a-f]{64}", manifest["attempt_id"])
                        or manifest["stream"] not in _STREAMS
                        or manifest["outcome"] not in _OUTCOMES
                        or manifest["sha256_scope"] != "observed"
                        or type(manifest["encrypted"]) is not bool
                        or type(manifest["truncated"]) is not bool
                        or manifest["protection"] != ("fernet" if manifest["encrypted"]
                                                       else "filesystem-permissions")):
                    raise ValueError
                for name in ("sha256", "stored_sha256", "payload_sha256"):
                    if not re.fullmatch(r"[0-9a-f]{64}", manifest[name]):
                        raise ValueError
                for name in ("size_bytes", "stored_bytes", "storage_bytes"):
                    if type(manifest[name]) is not int or manifest[name] < 0:
                        raise ValueError
                if (manifest["stored_bytes"] > manifest["size_bytes"]
                        or manifest["truncated"] != (manifest["size_bytes"] > manifest["stored_bytes"])
                        or os.fstat(source.fileno()).st_size != len(header) + manifest["storage_bytes"]):
                    raise ValueError
            except (ValueError, TypeError, KeyError, UnicodeError):
                raise ArtifactStoreError("Invalid artifact manifest") from None
            if not include_payload:
                return manifest
            payload = source.read(manifest["storage_bytes"] + 1)
        if (len(payload) != manifest["storage_bytes"]
                or hashlib.sha256(payload).hexdigest() != manifest["payload_sha256"]):
            raise ArtifactStoreError("Artifact integrity check failed")
        if manifest["encrypted"]:
            if self._fernet is None:
                raise ArtifactStoreError("Artifact decryption requires a key")
            try:
                payload = self._fernet.decrypt(payload)
            except InvalidToken:
                raise ArtifactStoreError("Artifact decryption failed") from None
        digest = hashlib.sha256(payload).hexdigest()
        if (len(payload) != manifest["stored_bytes"] or digest != manifest["stored_sha256"]
                or (not manifest["truncated"] and digest != manifest["sha256"])):
            raise ArtifactStoreError("Artifact integrity check failed")
        return payload

    def read(self, artifact_id):
        """Read only a committed artifact, verifying stored bytes after decryption."""
        session, token = _identity(artifact_id)
        with self._lock, self._root_fd() as root_fd:
            with self._session_fd(root_fd, session) as fd:
                return self._load(fd, token, session, include_payload=True)

    def manifests(self, session_id):
        """List committed metadata only, without reading or decrypting payloads."""
        session = _scope("session", session_id)
        with self._lock, self._root_fd() as root_fd:
            try:
                with self._session_fd(root_fd, session) as fd:
                    result = []
                    for name in sorted(os.listdir(fd)):
                        if re.fullmatch(r"[0-9a-f]{32}\.artifact", name):
                            result.append(self._load(fd, name[:-9], session))
                    return result
            except FileNotFoundError:
                return []

    def purge_session(self, session_id):
        """Delete a session's files and directory; return the deleted file count.

        Unknown entries, nested directories, symlinks and hard links fail closed.
        An absent session is a no-op. No automatic retention policy is applied.
        """
        session = _scope("session", session_id)
        with self._lock, self._root_fd() as root_fd:
            try:
                with self._session_fd(root_fd, session) as fd:
                    names = os.listdir(fd)
                    for name in names:
                        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if (not _FILE.fullmatch(name) or not stat.S_ISREG(info.st_mode)
                                or info.st_nlink != 1):
                            raise ArtifactStoreError("Unsafe artifact session entry")
                    for name in names:
                        os.unlink(name, dir_fd=fd)
                os.rmdir(session, dir_fd=root_fd)
                os.fsync(root_fd)
                return len(names)
            except FileNotFoundError:
                return 0


class _Capture:
    def __init__(self, store, session, attempt, stream):
        self._store = store
        self._session = session
        self._attempt = attempt
        self._stream = stream
        self.id = session + "." + uuid.uuid4().hex
        self._limit = store.max_bytes
        self._prefix = bytearray()
        self._hash = hashlib.sha256()
        self._size = 0
        self._closed = False
        self._lock = threading.RLock()

    def write(self, data):
        """Observe bytes even after the prefix is full; return observed length."""
        with self._lock:
            if self._closed:
                raise ValueError("Artifact capture is closed")
            if not isinstance(data, bytes):
                raise TypeError("Artifact capture requires bytes")
            self._hash.update(data)
            self._size += len(data)
            remaining = self._limit - len(self._prefix)
            if remaining:
                self._prefix.extend(data[:remaining])
            return len(data)

    def finalize(self, outcome="completed"):
        """Commit once. Failed commits close the capture; they are not retried."""
        with self._lock:
            if self._closed:
                raise ValueError("Artifact capture is closed")
            if not isinstance(outcome, str) or outcome not in _OUTCOMES:
                raise ValueError("Invalid artifact outcome")
            self._closed = True
            try:
                prefix = bytes(self._prefix)
                encrypted = self._store._fernet is not None
                payload = self._store._fernet.encrypt(prefix) if encrypted else prefix
                manifest = {
                    "version": 1, "id": self.id, "uri": "artifact://" + self.id,
                    "session_id": self._session, "attempt_id": self._attempt,
                    "stream": self._stream, "outcome": outcome,
                    "sha256": self._hash.hexdigest(), "sha256_scope": "observed",
                    "stored_sha256": hashlib.sha256(prefix).hexdigest(),
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": self._size, "stored_bytes": len(prefix),
                    "storage_bytes": len(payload), "truncated": self._size > len(prefix),
                    "encrypted": encrypted,
                    "protection": "fernet" if encrypted else "filesystem-permissions",
                }
                self._store._publish(manifest, payload)
                return manifest
            finally:
                self._prefix.clear()

    def abort(self):
        """Discard an uncommitted capture; safe to call repeatedly."""
        with self._lock:
            self._closed = True
            self._prefix.clear()

    def __enter__(self):
        if self._closed:
            raise ValueError("Artifact capture is closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            self.abort()
        elif not self._closed:
            self.finalize()
        return False

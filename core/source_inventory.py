"""Read-only source metadata import. No execution, fetching, or verification.

All public import functions return ordinary JSON-compatible dictionaries, version
1. Source manifests return `kind`, `source_id`, `revision`, `digest`, `base_url`,
`operations` (Endpoint fields plus locations/roles/categories), `trust`, and
`coverage`. Repository snapshots return file hashes, never file contents. SARIF
returns only rule/location/flow metadata, never messages or snippets. Digests are
caller assertions unless computed by index_repository; none imply verification.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import asdict
from pathlib import PurePosixPath
from urllib.parse import unquote

from core.assessment import (
    AssessmentError, MAX_ENDPOINTS, _document, _endpoint, _label, validate_base_url,
)


def _json(document):
    # Duplicate fields are ambiguous security metadata; do not use last-key wins.
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AssessmentError("Duplicate JSON metadata field")
            result[key] = value
        return result

    if isinstance(document, (str, bytes)):
        if len(document) > 2 * 1024 * 1024:
            raise AssessmentError("Document exceeds the JSON size limit")
        try:
            document = json.loads(document, object_pairs_hook=pairs)
        except (ValueError, UnicodeError, RecursionError):
            raise AssessmentError("Expected strict bounded JSON") from None
    return _document(document)


def _fields(obj, required, optional=()):
    if not isinstance(obj, dict) or not set(required) <= obj.keys() or obj.keys() - set(required) - set(optional):
        raise AssessmentError("Unexpected or missing metadata fields")


def _revision(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,159}", value):
        raise AssessmentError("Expected a bounded source revision")
    return value


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:sha256:)?[a-fA-F0-9]{64}", value):
        raise AssessmentError("Expected a SHA256 digest")
    return value.removeprefix("sha256:").lower()


def _file(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 1024:
        raise AssessmentError("Expected a bounded relative source file")
    decoded = value
    for _ in range(8):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    else:
        raise AssessmentError("Excessive file path encoding")
    if (decoded.startswith(("/", "~")) or re.search(r"[\\:\x00-\x20\x7f?#]", decoded)
            or any(part in {"", ".", ".."} for part in decoded.split("/"))):
        raise AssessmentError("Unsafe source file path")
    return decoded


def _location(obj):
    _fields(obj, {"file", "line"})
    if type(obj["line"]) is not int or not 1 <= obj["line"] <= 10000000:
        raise AssessmentError("Invalid source line")
    return {"file": _file(obj["file"]), "line": obj["line"]}


def _labels(value):
    if not isinstance(value, list) or len(value) > 64:
        raise AssessmentError("Expected bounded metadata labels")
    return sorted({_label(v) for v in value})


def _coverage():
    return {"status": "pending", "verified": False, "evidence_refs": []}


def import_source_manifest(document, *, allowlist=None):
    """Import strict v1 metadata JSON; unknown fields (including contents) fail.

    Required input keys: version=1, source_id (opaque label), revision (<=160
    identifier characters), digest (hex SHA256, optionally `sha256:` prefixed),
    base_url, operations. Operations require method/path/locations; roles and
    categories are optional label lists, also supported as manifest defaults.
    Duplicate endpoint declarations fail. Operation IDs match assessment.Endpoint.
    """
    doc = _json(document)
    _fields(doc, {"version", "source_id", "revision", "digest", "base_url", "operations"}, {"roles", "categories"})
    if type(doc["version"]) is not int or doc["version"] != 1:
        raise AssessmentError("Only source manifest version 1 is supported")
    source_id, revision, digest = _label(doc["source_id"]), _revision(doc["revision"]), _digest(doc["digest"])
    base_url = validate_base_url(doc["base_url"], allowlist)
    defaults = {key: _labels(doc.get(key, [])) for key in ("roles", "categories")}
    raw = doc["operations"]
    if not isinstance(raw, list) or len(raw) > MAX_ENDPOINTS:
        raise AssessmentError("Operation inventory exceeds limit")
    operations, seen = [], set()
    for operation in raw:
        _fields(operation, {"method", "path", "locations"}, {"roles", "categories"})
        endpoint = _endpoint(operation["method"], operation["path"], base_url, allowlist)
        if endpoint.id in seen:
            raise AssessmentError("Duplicate source operation")
        seen.add(endpoint.id)
        locations = operation["locations"]
        if not isinstance(locations, list) or not 1 <= len(locations) <= 100:
            raise AssessmentError("Expected bounded source locations")
        locations = sorted({(loc["file"], loc["line"]) for loc in map(_location, locations)})
        operations.append({**asdict(endpoint),
                           "locations": [{"file": f, "line": line} for f, line in locations],
                           **{key: _labels(operation[key]) if key in operation else defaults[key]
                              for key in defaults}})
    return {"version": 1, "kind": "source_manifest", "source_id": source_id,
            "revision": revision, "digest": digest, "base_url": base_url,
            "roles": defaults["roles"], "categories": defaults["categories"],
            "operations": sorted(operations, key=lambda op: (op["path"], op["method"])),
            "trust": "untrusted", "coverage": _coverage()}


def check_source_revision(previous, current):
    """Return coverage disposition, never mutate or promote imported evidence.

    Accepts imported JSON snapshots. Any revision, digest, or metadata change
    invalidates prior coverage, even when the caller reuses a revision label.
    `coverage_valid` means reusable metadata, NOT verified security coverage.
    `invalidated_endpoint_ids` is the sorted union of previous/current operation
    IDs when changed, otherwise []. It includes removed endpoints. Non-operation
    snapshots (repository/SARIF) return [] even when changed: invalidate their
    source-scoped coverage separately. This function never mutates a ledger;
    callers must persist the disposition and invalidate prior coverage/evidence
    associations themselves before replacing the source snapshot.
    """
    old, new = _json(previous), _json(current)
    if _label(old.get("source_id")) != _label(new.get("source_id")):
        raise AssessmentError("Source identities do not match")
    for snapshot in (old, new):
        _revision(snapshot.get("revision"))
        _digest(snapshot.get("digest"))
    comparable = lambda snapshot: {k: v for k, v in snapshot.items() if k not in {"coverage", "trust"}}
    changed = comparable(old) != comparable(new)
    endpoint_ids = set()
    for snapshot in (old, new):
        operations = snapshot.get("operations", [])
        if not isinstance(operations, list) or len(operations) > MAX_ENDPOINTS:
            raise AssessmentError("Invalid source snapshot operations")
        for operation in operations:
            if not isinstance(operation, dict):
                raise AssessmentError("Invalid source snapshot operation")
            endpoint_ids.add(_digest(operation.get("id")))
    return {"version": 1, "source_id": new["source_id"], "revision": new["revision"],
            "digest": _digest(new["digest"]), "changed": changed,
            "invalidated_endpoint_ids": sorted(endpoint_ids) if changed else [],
            "coverage_valid": not changed, "coverage": {**_coverage(), "status": "stale" if changed else "pending"}}


_EXTENSIONS = frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java",
                         ".kt", ".rb", ".php", ".c", ".h", ".cpp", ".cs", ".swift"})
_EXCLUDED = frozenset({"vendor", "node_modules", "bower_components", "dist", "build", "target",
                       "venv", "env", "site-packages", "__pycache__", "coverage", "keys",
                       "secrets", "credentials", "private", "certs"})


def _excluded(name):
    name = name.lower()
    return (name.startswith(".") or name in _EXCLUDED or
            re.search(r"(?:^|[_.-])(?:keys?|tokens?|certificates?|ssh)(?:[_.-]|$)", name) is not None or
            any(word in name for word in (".env", "secret", "credential", "password", "private_key")) or
            name.startswith(("id_rsa", "id_ed25519")) or name.endswith((".pem", ".key", ".p12", ".pfx", ".keystore")))


def index_repository(root, *, source_id="repository", revision=None, max_files=1000,
                     max_bytes=8 * 1024 * 1024, extensions=None):
    """Explicit opt-in local hash inventory; never stores or returns file contents.

    Hard caps: 5000 files, 32 MiB aggregate bytes, 100000 directory entries, depth
    32. Limits fail closed rather than returning an apparently complete inventory.
    Extensions can only narrow the built-in source-code allowlist. Hidden files,
    sensitive names, dependencies, symlinks, devices, and sockets are not read.
    Descriptor-relative O_NOFOLLOW traversal prevents symlink replacement escapes.
    No absolute repository path is returned.
    """
    _label(source_id)
    if (type(max_files) is not int or not 1 <= max_files <= 5000 or type(max_bytes) is not int
            or not 1 <= max_bytes <= 32 * 1024 * 1024):
        raise AssessmentError("Invalid repository limits")
    if extensions is not None and (not isinstance(extensions, (list, tuple, set, frozenset))
                                   or not all(isinstance(e, str) for e in extensions)):
        raise AssessmentError("Invalid source extensions")
    allowed = _EXTENSIONS if extensions is None else frozenset(extensions)
    if not allowed or not allowed <= _EXTENSIONS:
        raise AssessmentError("Unsupported source extensions")
    if revision is not None:
        _revision(revision)
    files, total, entries = [], 0, 0

    def walk(directory, prefix="", depth=0):
        nonlocal total, entries
        if depth > 32:
            raise AssessmentError("Repository depth exceeds limit")
        names = os.listdir(directory)
        entries += len(names)
        if entries > 100000:
            raise AssessmentError("Repository entry count exceeds limit")
        for name in sorted(names):
            if _excluded(name):
                continue
            path = prefix + name
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    walk(child, path + "/", depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode) and PurePosixPath(name).suffix.lower() in allowed:
                if len(files) >= max_files or info.st_size > max_bytes - total:
                    raise AssessmentError("Repository file or byte budget exceeded")
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                try:
                    before = os.fstat(fd)
                    if (not stat.S_ISREG(before.st_mode) or
                            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)):
                        raise AssessmentError("Repository changed during indexing")
                    hasher, size = hashlib.sha256(), 0
                    while True:
                        chunk = os.read(fd, min(65536, max_bytes - total + 1))
                        if not chunk:
                            break
                        total += len(chunk)
                        size += len(chunk)
                        if total > max_bytes:
                            raise AssessmentError("Repository byte budget exceeded")
                        hasher.update(chunk)
                    after = os.fstat(fd)
                    if (size != before.st_size or
                            (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                            (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                        raise AssessmentError("Repository changed during indexing")
                    files.append({"file": _file(path), "bytes": size, "digest": hasher.hexdigest()})
                finally:
                    os.close(fd)
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            walk(root_fd)
        finally:
            os.close(root_fd)
    except OSError:
        raise AssessmentError("Repository could not be safely indexed") from None
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"version": 1, "kind": "repository", "source_id": source_id,
            "revision": revision or digest, "digest": digest, "files": files,
            "trust": "untrusted", "coverage": _coverage()}


def import_sarif(document, *, source_id, revision, digest):
    """Import SARIF 2.1.0 local rule, location, and source/sink flow metadata.

    Locations support relative artifact URI or local artifact index, with no
    uriBaseId, external refs, remote/absolute URI, or external property files.
    Messages, fixes, snippets, artifact contents, and arbitrary properties are
    ignored. Results are hypotheses, never verified findings. Input is bounded
    by assessment's 2 MiB JSON cap, 100 runs, and 5000 results total.
    """
    source_id, revision, digest = _label(source_id), _revision(revision), _digest(digest)
    doc = _json(document)
    if doc.get("version") != "2.1.0" or not isinstance(doc.get("runs"), list) or len(doc["runs"]) > 100:
        raise AssessmentError("Expected bounded SARIF 2.1.0")
    stack = [doc]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if any(key in node for key in ("$ref", "externalPropertyFileReferences", "originalUriBaseIds", "uriBaseId")):
                raise AssessmentError("External SARIF references are unsupported")
            # Reject URI-bearing external metadata too; never silently resolve it.
            if "uri" in node:
                _file(node["uri"])
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    findings = []
    for run in doc["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            raise AssessmentError("Invalid SARIF run")
        artifacts = run.get("artifacts", [])
        if not isinstance(artifacts, list) or len(artifacts) > 10000:
            raise AssessmentError("Invalid SARIF artifacts")

        def location(value):
            if not isinstance(value, dict) or not isinstance(value.get("physicalLocation"), dict):
                raise AssessmentError("Expected local physical SARIF location")
            physical = value["physicalLocation"]
            artifact = physical.get("artifactLocation", {})
            if not isinstance(artifact, dict):
                raise AssessmentError("Invalid SARIF artifact location")
            if "uri" not in artifact:
                index = artifact.get("index")
                if type(index) is not int or not 0 <= index < len(artifacts) or not isinstance(artifacts[index], dict):
                    raise AssessmentError("Invalid SARIF artifact index")
                artifact = artifacts[index].get("location", {})
            region = physical.get("region", {})
            if not isinstance(artifact, dict) or not isinstance(region, dict):
                raise AssessmentError("Invalid SARIF location")
            return _location({"file": artifact.get("uri"), "line": region.get("startLine", 1)})

        for result in run.get("results", []):
            if len(findings) >= 5000 or not isinstance(result, dict):
                raise AssessmentError("Invalid or excessive SARIF results")
            rule_id = _revision(result.get("ruleId"))
            raw_locations = result.get("locations", [])
            if not isinstance(raw_locations, list) or len(raw_locations) > 100:
                raise AssessmentError("Invalid SARIF locations")
            locations = [location(loc) for loc in raw_locations]
            flows = []
            code_flows = result.get("codeFlows", [])
            if not isinstance(code_flows, list) or len(code_flows) > 100:
                raise AssessmentError("Invalid SARIF flows")
            for flow in code_flows:
                if not isinstance(flow, dict) or not isinstance(flow.get("threadFlows", []), list) or len(flow.get("threadFlows", [])) > 100:
                    raise AssessmentError("Invalid SARIF thread flows")
                for thread in flow.get("threadFlows", []):
                    if not isinstance(thread, dict):
                        raise AssessmentError("Invalid SARIF thread")
                    steps = thread.get("locations", [])
                    if not isinstance(steps, list) or not 1 <= len(steps) <= 1000 or not all(isinstance(s, dict) for s in steps):
                        raise AssessmentError("Invalid SARIF flow locations")
                    checked = [location(step.get("location")) for step in steps]
                    flows.append({"source": checked[0], "sink": checked[-1]})
            item = {"rule_id": rule_id, "locations": locations, "flows": flows}
            item_id = hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()
            findings.append({"id": item_id, **item, "status": "hypothesis", "verified": False})
    unique = {item["id"]: item for item in findings}
    return {"version": 1, "kind": "sarif", "source_id": source_id, "revision": revision,
            "digest": digest, "findings": [unique[key] for key in sorted(unique)],
            "trust": "untrusted", "coverage": _coverage()}

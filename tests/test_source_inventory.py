"""Offline, metadata-only source inventory boundary tests."""

import copy
import hashlib
import json

import pytest

from core.assessment import AssessmentError, import_openapi
from core.source_inventory import (
    check_source_revision, import_sarif, import_source_manifest, index_repository,
)


def manifest():
    return {"version": 1, "source_id": "repo", "revision": "commit-1", "digest": "a" * 64,
            "base_url": "https://api.example.test/v1/", "roles": ["reader"],
            "operations": [{"method": "get", "path": "/users/{id}",
                            "locations": [{"file": "src/routes.py", "line": 10}],
                            "categories": ["authorization"]}]}


def test_manifest_json_contract_endpoint_identity_and_no_verification():
    result = import_source_manifest(json.dumps(manifest()), allowlist="api.example.test")
    assert json.loads(json.dumps(result)) == result
    assert result == import_source_manifest(manifest(), allowlist="api.example.test")
    endpoint = import_openapi({"openapi": "3.1.0", "paths": {"/users/{id}": {"get": {}}}},
                              base_url="https://api.example.test/v1", allowlist="api.example.test")[0]
    op = result["operations"][0]
    assert op["id"] == endpoint.id
    assert op["roles"] == ["reader"]
    assert op["locations"] == [{"file": "src/routes.py", "line": 10}]
    assert result["coverage"] == {"status": "pending", "verified": False, "evidence_refs": []}
    assert result["trust"] == "untrusted"


@pytest.mark.parametrize("field,value", [
    ("version", True), ("version", 2), ("revision", "contains spaces"), ("digest", "wrong"),
    ("source_id", "bad source"), ("operations", {}), ("roles", ["bad label"]),
    ("base_url", "https://user:secret@api.example.test"),
    ("base_url", "https://outside.test"), ("contents", "not metadata"),
])
def test_manifest_rejects_invalid_or_extra_fields(field, value):
    doc = manifest()
    doc[field] = value
    with pytest.raises(AssessmentError):
        import_source_manifest(doc, allowlist="api.example.test")


@pytest.mark.parametrize("file", ["../private.py", "/tmp/a.py", "file:///tmp/a.py", "a\\b.py",
                                      "%252e%252e/private.py", "https://evil.test/a.py", "a//b.py"])
def test_rejects_nonlocal_source_locations(file):
    doc = manifest()
    doc["operations"][0]["locations"][0]["file"] = file
    with pytest.raises(AssessmentError):
        import_source_manifest(doc, allowlist="")


def test_bounds_duplicates_and_line_types():
    for mutate in (lambda d: d["operations"].append(copy.deepcopy(d["operations"][0])),
                   lambda d: d["operations"][0]["locations"][0].update(line=True),
                   lambda d: d["operations"][0].update(method="CONNECT"),
                   lambda d: d["operations"][0].update(path="/%2e%2e/private"),
                   lambda d: d["operations"][0].update(locations=[])):
        doc = manifest()
        mutate(doc)
        with pytest.raises(AssessmentError):
            import_source_manifest(doc, allowlist="")
    with pytest.raises(AssessmentError):
        import_source_manifest(" " * (2 * 1024 * 1024 + 1))
    with pytest.raises(AssessmentError):
        import_source_manifest('{"version":1,"version":2}')


def test_source_revision_invalidates_coverage_without_promoting():
    old = import_source_manifest(manifest(), allowlist="")
    old["coverage"] = {"status": "verified", "evidence_refs": ["evidence:prior"]}
    assert check_source_revision(old, old)["coverage_valid"]
    assert check_source_revision(old, old)["invalidated_endpoint_ids"] == []
    for field, value in (("revision", "commit-2"), ("digest", "b" * 64),
                         ("base_url", "https://api.example.test/v2")):
        new = copy.deepcopy(old)
        new[field] = value
        result = check_source_revision(old, new)
        assert result["changed"] and not result["coverage_valid"]
        assert result["invalidated_endpoint_ids"] == [old["operations"][0]["id"]]
        assert result["coverage"] == {"status": "stale", "verified": False, "evidence_refs": []}
    assert "verified" == old["coverage"]["status"]  # no mutation


def test_revision_disposition_invalidates_retained_removed_and_added_endpoints():
    doc = manifest()
    doc["operations"].append({"method": "post", "path": "/retained",
                              "locations": [{"file": "src/routes.py", "line": 30}]})
    previous = import_source_manifest(doc, allowlist="")
    doc["revision"] = "commit-2"
    doc["operations"][0]["path"] = "/added"
    current = import_source_manifest(doc, allowlist="")
    before, after = copy.deepcopy(previous), copy.deepcopy(current)
    result = check_source_revision(previous, current)
    assert result["invalidated_endpoint_ids"] == sorted({op["id"] for op in previous["operations"] + current["operations"]})
    assert len(result["invalidated_endpoint_ids"]) == 3
    assert result["coverage"]["status"] == "stale" and not result["coverage"]["verified"]
    assert result["coverage"]["evidence_refs"] == []
    assert previous == before and current == after
    assert json.loads(json.dumps(result)) == result
    current["source_id"] = "different"
    with pytest.raises(AssessmentError, match="identities"):
        check_source_revision(previous, current)


def test_revision_disposition_for_non_operation_snapshots():
    previous = {"version": 1, "kind": "repository", "source_id": "repo",
                "revision": "commit-1", "digest": "a" * 64, "files": []}
    current = {**previous, "revision": "commit-2"}
    result = check_source_revision(previous, current)
    assert result["changed"] and not result["coverage_valid"]
    assert result["invalidated_endpoint_ids"] == []
    assert not result["coverage"]["verified"]


def test_repository_hashes_no_secrets_symlinks_or_dependencies(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("# unique source contents, never returned\n")
    for name in (".git", ".env", "keys", "vendor", "node_modules", "secrets"):
        directory = root / name
        directory.mkdir()
        (directory / "hidden.py").write_text("sensitive material")
    (root / "credentials.py").write_text("sensitive material")
    (root / "rsa.key").write_text("sensitive material")
    outside = tmp_path / "outside.py"
    outside.write_text("sensitive material")
    (root / "link.py").symlink_to(outside)
    (root / "linked").symlink_to(tmp_path, target_is_directory=True)
    result = index_repository(root)
    assert result == index_repository(root)
    assert result["files"] == [{"file": "app.py", "bytes": (root / "app.py").stat().st_size,
                                "digest": hashlib.sha256((root / "app.py").read_bytes()).hexdigest()}]
    assert "unique source" not in json.dumps(result)
    assert "sensitive material" not in json.dumps(result)
    assert str(root) not in json.dumps(result)
    assert result["coverage"]["verified"] is False
    (tmp_path / "symlink-root").symlink_to(root, target_is_directory=True)
    with pytest.raises(AssessmentError):
        index_repository(tmp_path / "symlink-root")
    with pytest.raises(AssessmentError):
        index_repository(root, max_bytes=1)
    (root / "second.py").write_text("pass")
    with pytest.raises(AssessmentError):
        index_repository(root, max_files=1)
    with pytest.raises(AssessmentError):
        index_repository(root, extensions=[".env"])


def sarif():
    def location(file, line):
        return {"physicalLocation": {"artifactLocation": {"uri": file}, "region": {"startLine": line}}}
    return {"version": "2.1.0", "runs": [{"results": [{
        "ruleId": "CWE-89", "message": {"text": "secret model prose"},
        "locations": [location("src/app.py", 20)],
        "codeFlows": [{"threadFlows": [{"locations": [
            {"location": location("src/input.py", 3)}, {"location": location("src/db.py", 9)}]}]}]
    }]}]}


def test_sarif_metadata_source_sink_and_no_prose():
    result = import_sarif(sarif(), source_id="repo", revision="commit", digest="c" * 64)
    finding = result["findings"][0]
    assert finding["flows"] == [{"source": {"file": "src/input.py", "line": 3},
                                 "sink": {"file": "src/db.py", "line": 9}}]
    assert not finding["verified"]
    assert finding["status"] == "hypothesis"
    assert "secret model prose" not in json.dumps(result)
    assert json.loads(json.dumps(result)) == result


@pytest.mark.parametrize("mutate", [
    lambda d: d.update({"$ref": "https://evil.test/ref"}),
    lambda d: d["runs"][0].update(externalPropertyFileReferences={}),
    lambda d: d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"].update(uri="https://evil.test/a"),
    lambda d: d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"].update(uriBaseId="ROOT"),
])
def test_sarif_no_external_refs(mutate):
    doc = sarif()
    mutate(doc)
    with pytest.raises(AssessmentError):
        import_sarif(doc, source_id="repo", revision="commit", digest="c" * 64)


def test_sarif_local_artifact_index():
    doc = sarif()
    run = doc["runs"][0]
    run["artifacts"] = [{"location": {"uri": "src/app.py"}}]
    run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0}
    result = import_sarif(doc, source_id="repo", revision="commit", digest="c" * 64)
    assert result["findings"][0]["locations"] == [{"file": "src/app.py", "line": 20}]

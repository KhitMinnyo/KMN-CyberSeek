"""Headless CLI contracts using only an ephemeral local HTTP fixture."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import threading
from urllib import error

import pytest

import cli
from core.report_export import build_report_snapshot

OUTPUT_COMMANDS = [
    ["archive", "s1"],
    ["report", "s1", "--format", "json"],
    ["report", "s1", "--format", "sarif"],
    ["report", "s1", "--format", "md"],
    ["report", "s1", "--format", "pdf"],
    ["report", "s1", "--format", "docx"],
    ["evidence", "download", "s1", "a1", "--acknowledge-sensitive"],
]


@pytest.fixture
def server():
    calls = []
    state = {"snapshot": build_report_snapshot({"session": {"status": "completed"}})}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.handle_request()

        def do_POST(self):
            self.handle_request()

        def do_PATCH(self):
            self.handle_request()

        def handle_request(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append((self.command, self.path, self.headers.get("X-API-Key"), json.loads(body) if body else None))
            if self.headers.get("X-API-Key") != "test-token":
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"detail":"private-error-secret"}')
                return
            self.send_response(200)
            self.end_headers()
            if self.path.endswith("/report.json"):
                self.wfile.write(json.dumps(state["snapshot"]).encode())
            elif self.path.endswith("/archive"):
                self.wfile.write(b"PK-archive")
            elif "/content?acknowledge_sensitive=true" in self.path:
                self.wfile.write(b"sensitive-evidence-bytes")
            else:
                self.wfile.write(b'{"session_id":"s1","status":"success"}')
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield ["--base-url", f"http://127.0.0.1:{httpd.server_port}", "--api-key", "test-token"], calls, state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def test_help_does_not_import_backend_or_create_files(tmp_path):
    root = Path(__file__).parents[1]
    result = subprocess.run([sys.executable, "-c",
                             f"import sys; sys.path.insert(0, {str(root)!r}); import cli; "
                             "assert 'main' not in sys.modules; assert 'core.orchestrator' not in sys.modules; "
                             "cli.main(['--help'])"], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0
    assert "authorization" in result.stdout
    assert not list(tmp_path.iterdir())


def test_start_requires_explicit_authorization_and_safe_defaults(server):
    options, calls, _ = server
    with pytest.raises(SystemExit) as exc:
        cli.main(options + ["start", "192.0.2.1"])
    assert exc.value.code == 2
    assert calls == []
    assert cli.main(options + ["start", "192.0.2.1", "--authorization-confirmed"]) == 0
    method, path, token, body = calls[-1]
    assert (method, path, token) == ("POST", "/api/start", "test-token")
    assert body["authorization_confirmed"] is True
    assert body["auto_approve"] is False
    assert body["full_auto"] is False
    assert cli.main(options + ["start", "192.0.2.1", "--authorization-confirmed", "--full-auto"]) == 0
    assert calls[-1][3]["full_auto"] is True


@pytest.mark.parametrize("command,method,path", [
    ("status", "GET", "/api/sessions/s1/report.json"),
    ("events", "GET", "/api/sessions/s1/events"),
    ("jobs", "GET", "/api/sessions/s1/jobs"),
    ("cancel", "POST", "/api/sessions/s1/cancel"),
])
def test_lifecycle_api_contracts(server, command, method, path):
    options, calls, _ = server
    assert cli.main(options + [command, "s1"]) == 0
    assert calls[-1][:2] == (method, path)


@pytest.mark.parametrize("status,pending,code", [
    ("completed", 0, 0), ("failed", 0, 5), ("cancelled", 0, 6),
    ("ready", 1, 4), ("needs_operator", 0, 8), ("awaiting_approval", 0, 4),
    ("completed", 1, 0),
])
def test_wait_distinguishes_terminal_and_operator_states(server, status, pending, code):
    options, calls, state = server
    state["snapshot"]["session"]["status"] = status
    state["snapshot"]["summary"]["pending_approval_count"] = pending
    assert cli.main(options + ["wait", "s1"]) == code
    assert len(calls) == 1


def test_wait_deadline_is_bounded(server, capsys):
    options, _, state = server
    state["snapshot"]["session"]["status"] = "scanning"
    assert cli.main(options + ["wait", "s1", "--wait-timeout", "0.03", "--poll-interval", "0.01"]) == 7
    assert "deadline" in capsys.readouterr().err


def test_report_sarif_and_threshold_use_verified_findings_only(server, tmp_path):
    options, calls, state = server
    state["snapshot"] = build_report_snapshot({
        "session": {"status": "completed"},
        "vulnerabilities": [{"name": "Guess", "status": "potential", "risk_level": "critical"}],
    })
    output = tmp_path / "result.sarif"
    args = options + ["report", "s1", "--format", "sarif", "--output", str(output), "--fail-on", "high"]
    assert cli.main(args) == 0
    assert json.loads(output.read_text())["version"] == "2.1.0"
    assert calls[-1][1] == "/api/sessions/s1/report.json"
    state["snapshot"]["findings"][0]["verification"] = "verified"
    output.unlink()
    assert cli.main(args) == 3
    assert cli.main(options + ["wait", "s1", "--fail-on", "high"]) == 3


def test_archive_is_binary_and_session_path_is_escaped(server, tmp_path):
    options, calls, _ = server
    output = tmp_path / "archive.zip"
    assert cli.main(options + ["archive", "a/b?c", "--output", str(output)]) == 0
    assert calls[-1][1] == "/api/sessions/a%2Fb%3Fc/archive"
    assert output.read_bytes() == b"PK-archive"


def test_api_auth_errors_do_not_print_secret_response(server, capsys):
    options, _, _ = server
    options[-1] = "invalid-token"
    assert cli.main(options + ["status", "s1"]) == 1
    output = capsys.readouterr()
    assert "HTTP 401" in output.err
    assert "private-error-secret" not in output.err
    assert "invalid-token" not in output.err


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_invalid_timeout_rejected(value):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--timeout", value, "status", "s1"])
    assert exc.value.code == 2


def test_network_timeout_and_redirects_are_safe(monkeypatch, capsys):
    seen = []
    class Opener:
        def open(self, req, timeout):
            seen.append(timeout)
            raise error.URLError("private-transport-secret")
    monkeypatch.setattr(cli.request, "build_opener", lambda *args: Opener())
    assert cli.main(["--api-key", "test-token", "--timeout", "0.5", "status", "s1"]) == 1
    assert 0 < seen[0] <= 0.5
    assert "private-transport-secret" not in capsys.readouterr().err
    assert cli._NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example") is None


def test_wait_polls_until_complete_and_caps_request_deadline(monkeypatch, capsys):
    snapshots = iter([{"session": {"status": "scanning"}}, {"session": {"status": "completed"}}])
    timeouts = []
    def call(self, path, **kwargs):
        timeouts.append(kwargs["timeout"])
        return next(snapshots)
    monkeypatch.setattr(cli.Client, "call", call)
    assert cli.main(["--api-key", "test-token", "wait", "s1", "--poll-interval", "0.001", "--wait-timeout", "1"]) == 0
    assert len(timeouts) == 2
    assert 0 < timeouts[1] < timeouts[0] <= 1


def test_request_exhausting_wait_deadline_is_timeout_not_session_failure(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    def call(self, path, **kwargs):
        clock[0] = 2.0
        raise cli.ClientError("Request timed out")
    monkeypatch.setattr(cli.Client, "call", call)
    assert cli.main(["--api-key", "test-token", "wait", "s1", "--wait-timeout", "1"]) == 7


def test_environment_auth_and_default_json_output(server, monkeypatch, capsys):
    options, calls, state = server
    monkeypatch.setenv("API_AUTH_TOKEN", "test-token")
    assert cli.main(options[:2] + ["report", "s1"]) == 0
    assert calls[-1][2] == "test-token"
    assert json.loads(capsys.readouterr().out) == state["snapshot"]


def test_legacy_report_without_destination_does_not_generate_document(server):
    options, calls, _ = server
    assert cli.main(options + ["report", "s1", "--format", "docx"]) == 1
    assert [call[1] for call in calls] == ["/api/sessions/s1/report.json"]


def test_inventory_import_view_and_update_use_http(server, tmp_path):
    options, calls, _ = server
    source = tmp_path / "openapi.json"
    document = {"openapi": "3.0.3", "paths": {"/users": {"get": {}}}}
    source.write_text(json.dumps(document))
    assert cli.main(options + ["inventory", "import", "s1", str(source), "--inventory-base-url", "https://example.com",
                               "--role", "reader=env:READER", "--category", "authorization"]) == 0
    assert calls[-1][:2] == ("POST", "/api/sessions/s1/assessment/import")
    assert calls[-1][3] == {"document": document, "base_url": "https://example.com",
                            "roles": {"reader": "env:READER"}, "categories": ["authorization"]}
    assert cli.main(options + ["inventory", "view", "s1"]) == 0
    assert calls[-1][:2] == ("GET", "/api/sessions/s1/assessment")
    assert cli.main(options + ["inventory", "update", "s1", "endpoint1", "reader", "authorization", "verified",
                               "--evidence-ref", "evidence:check"]) == 0
    assert calls[-1][:2] == ("PATCH", "/api/sessions/s1/assessment/coverage")
    assert calls[-1][3]["evidence_ref"] == "evidence:check"


@pytest.mark.parametrize("data", [b" " * (cli.MAX_INVENTORY_BYTES + 1),
    b'{"openapi":"3.0.3","$ref":"https://example.com/remote"}', b"not JSON"])
def test_inventory_invalid_or_remote_input_never_sent(server, tmp_path, data):
    options, calls, _ = server
    source = tmp_path / "openapi.json"
    source.write_bytes(data)
    assert cli.main(options + ["inventory", "import", "s1", str(source), "--inventory-base-url", "https://example.com"]) == 1
    assert calls == []


def test_verify_requires_review_ack_and_explicit_result(server):
    options, calls, _ = server
    args = ["verify", "s1", "42", "--result", "positive", "--method", "manual check", "--artifact-id", "artifact1"]
    with pytest.raises(SystemExit) as exc:
        cli.main(options + args)
    assert exc.value.code == 2 and calls == []
    assert cli.main(options + args + ["--acknowledge-review", "--evidence", "Reviewed explicit positive response"]) == 0
    assert calls[-1] == ("POST", "/api/sessions/s1/vulnerabilities/42/verification", "test-token", {
        "kind": "verification", "acknowledge_review": True, "result": "positive", "method": "manual check",
        "artifact_refs": ["artifact1"], "evidence": "Reviewed explicit positive response"})


@pytest.mark.parametrize("result", ["negative", "inconclusive"])
def test_verify_does_not_infer_positive_from_labels(server, result):
    options, calls, _ = server
    assert cli.main(options + ["verify", "s1", "42", "--acknowledge-review", "--result", result,
                               "--method", "nmap source review", "--artifact-id", "a1", "--artifact-id", "a2"]) == 0
    assert calls[-1][3]["result"] == result
    assert calls[-1][3]["artifact_refs"] == ["a1", "a2"]
    assert "verified" not in calls[-1][3]


def test_verify_rejects_oversized_fields_before_http(server):
    options, calls, _ = server
    assert cli.main(options + ["verify", "s1", "42", "--acknowledge-review", "--result", "positive",
                               "--method", "m" * 201, "--artifact-id", "a1"]) == 1
    assert calls == []


def test_evidence_list_and_sensitive_download(server, tmp_path, capsys):
    options, calls, _ = server
    assert cli.main(options + ["evidence", "list", "s1"]) == 0
    assert calls[-1][:2] == ("GET", "/api/sessions/s1/artifacts")
    output = tmp_path / "evidence.bin"
    args = options + ["evidence", "download", "s1", "a/b?c", "--output", str(output)]
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    assert exc.value.code == 2 and len(calls) == 1
    assert cli.main(args + ["--acknowledge-sensitive"]) == 0
    assert calls[-1][:3] == ("GET", "/api/sessions/s1/artifacts/a%2Fb%3Fc/content?acknowledge_sensitive=true", "test-token")
    assert output.read_bytes() == b"sensitive-evidence-bytes"
    assert output.stat().st_mode & 0o777 == 0o600
    assert "sensitive-evidence-bytes" not in capsys.readouterr().out
    output.write_bytes(b"existing-private-content")
    assert cli.main(args + ["--acknowledge-sensitive"]) == 1
    assert output.read_bytes() == b"existing-private-content"


def test_evidence_download_requires_file_destination(server):
    options, calls, _ = server
    with pytest.raises(SystemExit) as exc:
        cli.main(options + ["evidence", "download", "s1", "a1", "--acknowledge-sensitive"])
    assert exc.value.code == 2 and calls == []


@pytest.mark.parametrize("kind,result", [("verification", "positive"), ("remediation", "applied"), ("retest", "negative")])
def test_verify_cli_explicit_lifecycle_kind(server, kind, result):
    options, calls, _ = server
    finding_id = "c20c3fa9-f8d2-4dd9-b8e2-a0156b1b2376"
    assert cli.main(options + ["verify", "s1", finding_id, "--acknowledge-review", "--kind", kind,
                               "--result", result, "--method", "operator review", "--artifact-id", "a1"]) == 0
    assert calls[-1][1] == f"/api/sessions/s1/vulnerabilities/{finding_id}/verification"
    assert calls[-1][3]["kind"] == kind and calls[-1][3]["result"] == result


@pytest.mark.parametrize("kind,result", [("verification", "applied"), ("remediation", "positive"),
    ("remediation", "negative"), ("remediation", "inconclusive"), ("retest", "applied")])
def test_verify_cli_rejects_invalid_lifecycle_pair_before_http(server, kind, result):
    options, calls, _ = server
    with pytest.raises(SystemExit) as error:
        cli.main(options + ["verify", "s1", "42", "--acknowledge-review", "--kind", kind,
                            "--result", result, "--method", "operator review", "--artifact-id", "a1"])
    assert error.value.code == 2 and calls == []


@pytest.mark.parametrize("command", OUTPUT_COMMANDS)
def test_all_output_files_are_private_and_never_overwritten(server, tmp_path, capsys, command):
    options, _, _ = server
    output = tmp_path / "private-output-secret"
    args = options + command + ["--output", str(output)]
    previous_umask = os.umask(0)
    try:
        assert cli.main(args) == 0
    finally:
        os.umask(previous_umask)
    assert output.stat().st_mode & 0o777 == 0o600
    output.write_bytes(b"existing-private-content")
    assert cli.main(args) == 1
    assert output.read_bytes() == b"existing-private-content"
    error = capsys.readouterr().err
    assert "FileExistsError" in error
    assert str(output) not in error and "private-output-secret" not in error
    assert "existing-private-content" not in error


@pytest.mark.parametrize("command", OUTPUT_COMMANDS)
@pytest.mark.parametrize("dangling", [False, True])
def test_output_symlinks_are_rejected_without_touching_target(server, tmp_path, capsys, command, dangling):
    options, _, _ = server
    target = tmp_path / "private-target-secret"
    if not dangling:
        target.write_bytes(b"untouched-private-content")
    output = tmp_path / "output-link"
    output.symlink_to(target)
    assert cli.main(options + command + ["--output", str(output)]) == 1
    assert output.is_symlink()
    if dangling:
        assert not target.exists()
    else:
        assert target.read_bytes() == b"untouched-private-content"
    error = capsys.readouterr().err
    assert "FileExistsError" in error
    assert str(target) not in error and str(output) not in error


@pytest.mark.parametrize("command", OUTPUT_COMMANDS)
def test_output_write_failure_removes_new_partial_and_hides_details(server, tmp_path, monkeypatch, capsys, command):
    options, _, _ = server
    output = tmp_path / "private-output-secret"
    write = os.write
    touched = []

    def fail(fd, data):
        touched.append(write(fd, data[:3]))
        raise OSError(f"private-payload-secret at {output}")

    monkeypatch.setattr(cli.os, "write", fail)
    assert cli.main(options + command + ["--output", str(output)]) == 1
    assert touched == [3]
    assert not output.exists()
    error = capsys.readouterr().err
    assert "Client failed (OSError)" in error
    assert "private-payload-secret" not in error and str(output) not in error


def test_private_writer_handles_short_writes(tmp_path, monkeypatch):
    output = tmp_path / "short-write"
    write = os.write
    monkeypatch.setattr(cli.os, "write", lambda fd, data: write(fd, data[:2]))
    cli._write_private_output(output, b"complete-private-output")
    assert output.read_bytes() == b"complete-private-output"
    assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("failure", [KeyboardInterrupt, OSError])
def test_private_writer_cleans_interrupted_or_stalled_output(tmp_path, monkeypatch, failure):
    output = tmp_path / "partial"
    write = os.write

    def interrupt(fd, data):
        write(fd, data[:2])
        if failure is KeyboardInterrupt:
            raise KeyboardInterrupt
        return 0

    monkeypatch.setattr(cli.os, "write", interrupt)
    with pytest.raises(failure):
        cli._write_private_output(output, b"private-content")
    assert not output.exists()


@pytest.mark.parametrize("environment,override,expected", [
    (None, None, "http://127.0.0.1:6000"),
    ("http://backend.example:6000", None, "http://backend.example:6000"),
    ("http://backend.example:6000", "https://explicit.example", "https://explicit.example"),
])
def test_backend_url_default_environment_and_explicit_override(monkeypatch, environment, override, expected):
    monkeypatch.delenv("KMN_API_URL", raising=False)
    monkeypatch.setenv("CYBERSEEK_URL", "http://unused-legacy.example:8000")
    if environment is not None:
        monkeypatch.setenv("KMN_API_URL", environment)
    calls = []

    def call(self, path, **kwargs):
        calls.append((self.base_url, path))
        return {"session": {"status": "completed"}}

    monkeypatch.setattr(cli.Client, "call", call)
    args = ["--api-key", "test-token"]
    if override is not None:
        args += ["--base-url", override]
    assert cli.main(args + ["status", "s1"]) == 0
    assert calls == [(expected, "/api/sessions/s1/report.json")]

#!/usr/bin/env python3
"""HTTP-only headless client. No backend imports, dotenv loading or startup.

Starting a session requires --authorization-confirmed. Full autonomy is opt-in.

Exit codes: 0 success, 1 API/transport/local error, 2 invalid arguments,
3 verified finding threshold, 4 approval required, 5 session failed,
6 session cancelled, 7 wait timeout, 8 operator input required, 130 interrupted.
Report JSON/SARIF is sanitized; archives and legacy documents may contain secrets.
Archives omit raw artifact files, but their report/events/jobs/metadata are NOT sanitized.
"""

import argparse
from http.client import HTTPException
import json
import math
import os
from pathlib import Path
import sys
import time
from urllib import error, parse, request

MAX_INVENTORY_BYTES = 2 * 1024 * 1024


class ClientError(Exception):
    pass


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward the API key to a redirected origin.
        return None


class Client:
    def __init__(self, base_url, token, timeout):
        url = parse.urlsplit(base_url)
        if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ClientError("Base URL must be an HTTP(S) URL without credentials, query or fragment")
        if not token or "\n" in token or "\r" in token:
            raise ClientError("Set API_AUTH_TOKEN or provide --api-key")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.opener = request.build_opener(_NoRedirect())

    def call(self, path, method="GET", payload=None, binary=False, timeout=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        req = request.Request(self.base_url + path, data=body, method=method,
                              headers={"X-API-Key": self.token, "Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=self.timeout if timeout is None else min(self.timeout, timeout)) as response:
                data = response.read()
            if binary:
                return data
            result = json.loads(data)
            if not isinstance(result, dict):
                raise ClientError("API returned an invalid JSON object")
            return result
        except error.HTTPError as exc:
            # Error bodies can echo commands or credentials. Do not print them.
            exc.close()
            raise ClientError(f"API returned HTTP {exc.code}") from None
        except (error.URLError, HTTPException, OSError, ValueError) as exc:
            raise ClientError(f"Request failed ({type(exc).__name__})") from None


def _positive(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return number


def _write_private_output(path, data):
    """Never overwrite a destination; remove a newly created partial on failure."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            remaining = memoryview(data)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("Output write made no progress")
                remaining = remaining[written:]
        finally:
            os.close(fd)
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


def session_exit(snapshot, threshold="none"):
    from core.report_export import exceeds_threshold
    status = snapshot.get("session", {}).get("status")
    if status in {"failed", "error"}:
        return 5
    if status in {"cancelled", "canceled"}:
        return 6
    if status in {"completed", "archived"}:
        return 3 if exceeds_threshold(snapshot, threshold) else 0
    if snapshot.get("summary", {}).get("pending_approval_count", 0) or status in {"awaiting_approval", "waiting_approval", "pending_approval"}:
        return 4
    if status in {"needs_operator", "paused"}:
        return 8
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=os.getenv("KMN_API_URL", "http://127.0.0.1:6000"))
    parser.add_argument("--api-key", default=os.getenv("API_AUTH_TOKEN"), help="API key (prefer API_AUTH_TOKEN environment variable)")
    parser.add_argument("--timeout", type=_positive, default=30, help="Per-request timeout in seconds (default: 30)")
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start", help="Start an explicitly authorized assessment; manual approval by default")
    start.add_argument("target")
    start.add_argument("--authorization-confirmed", action="store_true", required=True,
                       help="Confirm ownership or explicit permission to test this target")
    start.add_argument("--domain")
    start.add_argument("--name")
    start.add_argument("--objective")
    start.add_argument("--auto-approve", action="store_true", help="Explicitly allow routine low/medium-risk commands")
    start.add_argument("--full-auto", action="store_true", help="Explicitly enable full autonomy for an isolated authorized lab")
    verify = commands.add_parser("verify", help="Record explicit operator review of retained evidence; never runs checks")
    verify.add_argument("session_id")
    verify.add_argument("finding_id")
    verify.add_argument("--acknowledge-review", action="store_true", required=True,
                        help="Confirm you personally reviewed the referenced artifacts and explicit result")
    verify.add_argument("--kind", choices=("verification", "remediation", "retest"), default="verification")
    verify.add_argument("--result", choices=("positive", "negative", "inconclusive", "applied"), required=True,
                        help="Remediation requires applied; verification/retest require positive, negative or inconclusive")
    verify.add_argument("--method", required=True, help="Review/check method, at most 200 characters")
    verify.add_argument("--artifact-id", action="append", required=True, help="Committed artifact ID; repeat for multiple artifacts")
    verify.add_argument("--evidence", help="Optional operator explanation, at most 4096 characters; may be sensitive")
    evidence = commands.add_parser("evidence", help="List artifact manifests or explicitly download sensitive raw bytes")
    evidence_actions = evidence.add_subparsers(dest="evidence_action", required=True)
    for action in ("list", "download"):
        sub = evidence_actions.add_parser(action)
        sub.add_argument("session_id")
        if action == "download":
            sub.add_argument("artifact_id")
            sub.add_argument("--acknowledge-sensitive", action="store_true", required=True,
                             help="Raw evidence may contain credentials or other secrets")
            sub.add_argument("--output", required=True, help="Sensitive binary destination file; never stdout")
    inventory = commands.add_parser("inventory", help="Import/view/update a local assessment ledger; never runs probes")
    inventory_actions = inventory.add_subparsers(dest="inventory_action", required=True)
    for action in ("import", "view", "update"):
        sub = inventory_actions.add_parser(action)
        sub.add_argument("session_id")
        if action == "import":
            sub.add_argument("file", help="Local OpenAPI 3 JSON file, at most 2 MiB; local references only")
            sub.add_argument("--inventory-base-url", required=True, help="Explicit API target base URL (not the backend URL)")
            sub.add_argument("--role", action="append", default=[], metavar="NAME=REF",
                             help="Role with env:/vault:/keyring: reference; NAME= means anonymous")
            sub.add_argument("--category", action="append", default=[])
        if action == "update":
            sub.add_argument("endpoint_id")
            sub.add_argument("role")
            sub.add_argument("category")
            sub.add_argument("status", choices=("attempted", "verified", "blocked", "skipped", "inconclusive"))
            sub.add_argument("--evidence-ref")
    for name in ("status", "events", "jobs", "cancel", "report", "archive", "wait"):
        sub = commands.add_parser(name)
        sub.add_argument("session_id")
        if name in {"report", "archive"}:
            sub.add_argument("--output", required=name == "archive", help="Destination file; report defaults to stdout")
        if name == "report":
            sub.add_argument("--format", choices=("json", "sarif", "md", "pdf", "docx"), default="json",
                             help="JSON/SARIF sanitized; legacy documents may contain secrets")
        if name in {"report", "wait"}:
            sub.add_argument("--fail-on", choices=("none", "info", "low", "medium", "high", "critical"), default="none",
                             help="Fail only on verified findings at or above this severity")
        if name == "wait":
            sub.add_argument("--wait-timeout", type=_positive, default=300)
            sub.add_argument("--poll-interval", type=_positive, default=2)
    args = parser.parse_args(argv)
    if args.command == "verify" and ((args.kind == "remediation") != (args.result == "applied")):
        parser.error("--kind remediation requires --result applied; applied is only valid for remediation")
    try:
        client = Client(args.base_url, args.api_key, args.timeout)
        code = 0
        binary = False
        if args.command == "start":
            result = client.call("/api/start", "POST", {
                "ip": args.target, "domain": args.domain, "session_name": args.name,
                "objective": args.objective, "authorization_confirmed": True,
                "auto_approve": args.auto_approve, "full_auto": args.full_auto,
            })
        else:
            path = "/api/sessions/" + parse.quote(args.session_id, safe="")
            if args.command == "verify":
                if (not 1 <= len(args.method.strip()) <= 200 or len(args.method) > 200
                        or any(ord(char) < 32 or ord(char) == 127 for char in args.method)
                        or not 1 <= len(args.artifact_id) <= 32 or len(set(args.artifact_id)) != len(args.artifact_id)
                        or (args.evidence is not None and len(args.evidence) > 4096)):
                    raise ClientError("Review fields exceed limits or contain invalid values")
                payload = {"kind": args.kind, "acknowledge_review": True, "result": args.result, "method": args.method,
                           "artifact_refs": args.artifact_id}
                if args.evidence is not None:
                    payload["evidence"] = args.evidence
                result = client.call(path + "/vulnerabilities/" + parse.quote(args.finding_id, safe="") + "/verification",
                                     "POST", payload)
            elif args.command == "evidence":
                if args.evidence_action == "list":
                    result = client.call(path + "/artifacts")
                else:
                    result = client.call(path + "/artifacts/" + parse.quote(args.artifact_id, safe="")
                                         + "/content?acknowledge_sensitive=true", binary=True)
                    binary = True
            elif args.command == "inventory":
                suffix, method, payload = "/assessment", "GET", None
                if args.inventory_action == "import":
                    with Path(args.file).open("rb") as stream:
                        raw = stream.read(MAX_INVENTORY_BYTES + 1)
                    if len(raw) > MAX_INVENTORY_BYTES:
                        raise ClientError("Inventory file exceeds the 2 MiB limit")
                    document = json.loads(raw)
                    if not isinstance(document, dict):
                        raise ClientError("Inventory must be a JSON object")
                    # Validate references locally without importing backend code or resolving them.
                    stack = [(document, 0)]
                    count = 0
                    while stack:
                        node, depth = stack.pop()
                        count += 1
                        if depth > 64 or count > 100000:
                            raise ClientError("Inventory structure exceeds limits")
                        if isinstance(node, dict):
                            if "$ref" in node and (not isinstance(node["$ref"], str) or not node["$ref"].startswith("#/")):
                                raise ClientError("Inventory references must be local JSON Pointers")
                            stack.extend((value, depth + 1) for value in node.values())
                        elif isinstance(node, list):
                            stack.extend((value, depth + 1) for value in node)
                    roles = {}
                    for role in args.role:
                        name, separator, ref = role.partition("=")
                        if not separator or not name or name in roles:
                            raise ClientError("Use unique --role NAME=REF entries")
                        roles[name] = ref or None
                    payload = {"document": document, "base_url": args.inventory_base_url,
                               "roles": roles or {"anonymous": None}, "categories": args.category or ["observation"]}
                    if len(json.dumps(payload).encode()) > MAX_INVENTORY_BYTES:
                        raise ClientError("Inventory request exceeds the 2 MiB limit")
                    suffix, method = "/assessment/import", "POST"
                elif args.inventory_action == "update":
                    suffix, method = "/assessment/coverage", "PATCH"
                    payload = {key: getattr(args, key) for key in ("endpoint_id", "role", "category", "status", "evidence_ref")}
                result = client.call(path + suffix, method, payload)
            elif args.command in {"status", "wait", "report"}:
                deadline = time.monotonic() + getattr(args, "wait_timeout", args.timeout)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    try:
                        result = client.call(path + "/report.json", timeout=remaining)
                    except ClientError:
                        if args.command == "wait" and time.monotonic() >= deadline:
                            raise TimeoutError from None
                        raise
                    outcome = session_exit(result, getattr(args, "fail_on", "none"))
                    if args.command != "wait" or outcome is not None:
                        break
                    time.sleep(min(args.poll_interval, max(0, deadline - time.monotonic())))
                if args.command == "wait":
                    code = outcome
                elif args.command == "status":
                    code = outcome if outcome is not None else 0
                else:
                    from core.report_export import exceeds_threshold, export_sarif
                    code = 3 if exceeds_threshold(result, args.fail_on) else 0
                    if args.format == "sarif":
                        result = export_sarif(result)
                    elif args.format != "json":
                        if not args.output:
                            raise ClientError("Legacy reports require --output (may contain secrets)")
                        suffix = {"docx": "/report", "pdf": "/report/pdf", "md": "/report/md"}[args.format]
                        result = client.call(path + suffix, binary=True)
                        binary = True
            else:
                binary = args.command == "archive"
                result = client.call(path + "/" + args.command,
                                     "POST" if args.command == "cancel" else "GET", binary=binary)
        if binary:
            _write_private_output(args.output, result)
        else:
            text = json.dumps(result, indent=2, ensure_ascii=True) + "\n"
            if getattr(args, "output", None):
                _write_private_output(args.output, text.encode("utf-8"))
            else:
                print(text, end="")
        return code
    except TimeoutError:
        print("Wait deadline exceeded", file=sys.stderr)
        return 7
    except (ClientError, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        print(str(exc) if isinstance(exc, ClientError) else f"Client failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())

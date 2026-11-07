"""Pure, dependency-free, versioned exports of get_session_report() data.

Only allowlisted metadata is exported. Raw commands, output, evidence bodies,
credentials, AI prose and event/job payloads are deliberately excluded. Known
secret values and common inline credential forms are also redacted in metadata.
This is a sharing-safe summary, not a replacement for the restricted archive.
"""

import re

from core.finding_verification import assess_finding

SCHEMA_VERSION = "1.0"
SEVERITIES = {"unknown": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_report_snapshot(report):
    """Return a deterministic JSON-compatible snapshot without mutating input.

    Recompute verification from full raw findings, never precomputed flags;
    source, CVSS, confidence and successful commands never imply verification.
    References use JSON pointers into the original get_session_report response.
    """
    secrets = set()

    def collect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if (re.search(r"secret|password|passwd|token|api.?key|authorization", key, re.I)
                        and not key.lower().endswith(("_type", "_name", "_id"))):
                    if isinstance(item, str) and item:
                        secrets.add(item)
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(report)

    def clean(value):
        if isinstance(value, str):
            value = re.sub(r"(?i)\b(?:bearer|basic)\s+\S+", "[REDACTED]", value)
            value = re.sub(r"(?i)(?:https?|ftp|ssh)://[^\s/@]+:[^\s/@]+@", "[REDACTED]@", value)
            value = re.sub(
                r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)",
                "[REDACTED]", value,
            )
            value = re.sub(
                r"(?i)--(?:password|passwd|secret|token|api[_-]?key)\s+(?:\"[^\"]*\"|'[^']*'|\S+)",
                "[REDACTED]", value,
            )
            for secret in sorted(secrets, key=lambda s: (-len(s), s)):
                value = value.replace(secret, "[REDACTED]")
            return value
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return None

    def select(record, keys):
        return {key: clean(record[key]) for key in keys if key in record}

    session = select(report.get("session", {}), (
        "session_id", "target_ip", "target_domain", "created_at", "status",
        "current_stage", "objective_complete", "objective_progress",
    ))
    raw_completeness = report.get("completeness") or {}
    verdict = raw_completeness.get("verdict", "unknown")
    if verdict not in {"unknown", "incomplete", "complete"}:
        verdict = "unknown"

    def coverage_rows(rows):
        safe = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            item = select(row, ("endpoint_id", "role", "category", "status"))
            if "status" in item and item["status"] not in {
                "pending", "attempted", "verified", "blocked", "skipped", "inconclusive",
            }:
                item["status"] = "unknown"
            safe.append(item)
        return safe

    completeness = {
        "version": 1, "verdict": verdict,
        "missing_checks": coverage_rows(raw_completeness.get("missing_checks")),
        "blockers": coverage_rows(raw_completeness.get("blockers")),
        # Attribution and waiver prose stay in the restricted audit trail.
        "waived_checks": coverage_rows(raw_completeness.get("waived_checks")),
    }
    findings = []
    commands = report.get("commands_executed") or []
    for index, finding in enumerate(report.get("vulnerabilities") or []):
        item = select(finding, (
            "name", "host", "port", "service", "source_tool", "discovered_at",
            "cvss_score", "confidence",
        ))
        status = str(finding.get("status") or "unknown").lower()
        assessment = assess_finding(finding)
        verified = assessment["verified"]
        if status in {"suppressed", "false_positive"} or finding.get("suppressed"):
            verified = False
        severity = str(finding.get("risk_level") or "unknown").lower()
        refs = [f"#/vulnerabilities/{index}"]
        source_command = finding.get("source_command")
        if source_command:
            refs.extend(f"#/commands_executed/{i}" for i, command in enumerate(commands)
                        if command.get("command") == source_command)
        # Never copy caller-supplied evidence URIs: they can contain credentials.
        refs.extend(f"#/evidence/{i}" for i, evidence in enumerate(report.get("evidence") or [])
                    if finding.get("evidence_id") is not None
                    and evidence.get("evidence_id") == finding["evidence_id"])
        # Preserve evidence/artifact links using generated pointers, never their
        # raw IDs or URIs (which may themselves carry credentials).
        for section in ("evidence", "artifacts"):
            refs.extend(f"#/vulnerabilities/{index}/{section}/{i}"
                         for i, _ in enumerate(finding.get(section) or []))
        provenance = {"type": "unspecified", "source": "unspecified", "runtime_bound": False,
                      "independent_reproduction": False}
        events = finding.get("verification_events") or []
        history = assessment["history"]
        if (events and history and isinstance(events[-1], dict)
                and history[-1].get("artifact_refs")):
            event = events[-1]
            declared = event.get("provenance") or {}
            if isinstance(declared, dict):
                if declared.get("type") in {"runtime", "review_only"}:
                    provenance["type"] = declared["type"]
                if declared.get("source") in {"command_result", "operator_review", "source_review"}:
                    provenance["source"] = declared["source"]
            evidence_ids = set(history[-1]["evidence_refs"])
            evidence_rows = [e for e in finding.get("evidence", [])
                             if isinstance(e, dict) and e.get("id") in evidence_ids]
            provenance["runtime_bound"] = bool(evidence_rows) and all(
                e.get("command_id") and e.get("attempt_id") and any(
                    command.get("command_id") == e["command_id"]
                    and command.get("attempt_id") == e["attempt_id"]
                    and set(e.get("artifact_refs") or []) <= {
                        a.get("id") for a in command.get("artifacts", []) if isinstance(a, dict)
                    }
                    for command in commands
                ) for e in evidence_rows
            )
        item.update({
            # Only canonical persisted UUIDs can cross the sharing boundary as
            # actionable IDs; arbitrary legacy identifiers can contain secrets.
            "id": (finding["finding_id"] if isinstance(finding.get("finding_id"), str)
                   and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", finding["finding_id"])
                   else f"finding-{index + 1}"),
            "severity": severity if severity in SEVERITIES else "unknown",
            "verification": "verified" if verified else "unverified",
            "lifecycle": assessment["lifecycle"],
            "remediation_verified": assessment["remediation_verified"],
            "provenance": provenance,
            "source_status": status if status in {"confirmed", "verified", "potential", "unverified", "suppressed", "false_positive"} else "unknown",
            "cve_ids": [c.upper() for c in (finding.get("cve_ids") or [])
                        if isinstance(c, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", c, re.I)],
            "evidence_refs": refs,
        })
        findings.append(item)
    return {
        "schema_version": SCHEMA_VERSION,
        "session": session,
        "completeness": completeness,
        "summary": {
            **select(report.get("summary", {}), ("pending_approval_count", "objective_complete", "objective_progress")),
            "total_findings": len(findings),
            "verified_findings": sum(f["verification"] == "verified" for f in findings),
            "unverified_findings": sum(f["verification"] == "unverified" for f in findings),
            "assessment_verdict": verdict,
            "assessment_complete": verdict == "complete",
            "assessment_partial": verdict != "complete",
        },
        "findings": findings,
        "evidence": [{"ref": f"#/evidence/{i}"} for i, _ in enumerate(report.get("evidence") or [])],
        "redaction": {"raw_commands": "omitted", "raw_output": "omitted", "credentials": "omitted"},
    }


def exceeds_threshold(snapshot, threshold):
    """Only explicitly verified findings can fail a CI severity gate."""
    if threshold == "none":
        return False
    minimum = SEVERITIES[threshold]
    return any(f.get("verification") == "verified"
               and SEVERITIES.get(f.get("severity"), -1) >= minimum
               for f in snapshot.get("findings", []))


def export_sarif(snapshot):
    """Convert a version-1 snapshot to SARIF 2.1.0, with no I/O or imports of main."""
    if snapshot.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported report snapshot schema version")
    rules, results = [], []
    for finding in snapshot["findings"]:
        rule_id = finding["id"]
        verified = finding["verification"] == "verified"
        rules.append({"id": rule_id, "shortDescription": {"text": finding.get("name") or "Unnamed finding"}})
        results.append({
            "ruleId": rule_id,
            "level": ("error" if finding["severity"] in {"critical", "high"} else
                      "warning" if finding["severity"] == "medium" else "note") if verified else "note",
            "kind": "fail" if verified else "review",
            "message": {"text": f"[{finding['verification']}] {finding.get('name') or 'Unnamed finding'}"},
            "properties": {key: finding[key] for key in (
                "verification", "severity", "evidence_refs", "cve_ids", "source_status", "provenance",
                "host", "port", "service", "source_tool",
            ) if key in finding},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "KMN-CyberSeek", "rules": rules}},
                   "results": results,
                   "invocations": [{"executionSuccessful": snapshot.get("completeness", {}).get("verdict") == "complete"}],
                   "properties": {"report_schema_version": SCHEMA_VERSION, "session": snapshot["session"],
                                  "completeness": snapshot.get("completeness", {"verdict": "unknown"})}}],
    }

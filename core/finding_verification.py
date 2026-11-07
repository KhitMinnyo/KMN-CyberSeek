"""Pure, evidence-backed finding assessment; no probes or artifact I/O.

Input contract:
* target: exact, nonempty endpoint string (include port/path where relevant).
* artifacts: [{"id": "a1", "uri": "file:///evidence/check.txt"}].
* evidence: [{"id": "e1", "target": target, "method": "protocol check",
  "result": "positive", "artifact_refs": ["a1"]}].
* verification_events: ordered [{"kind": "verification", "target": target,
  "method": "protocol check", "result": "positive", "evidence_refs": ["e1"]}].

Kinds are observation, suspicion, verification, remediation, retest. Verification
and retest results are positive (vulnerability present), negative (not reproduced),
or inconclusive; remediation requires applied. Observation/suspicion use observed
and suspected respectively. Every event must resolve evidence with the same
target, method and result, backed by declared artifacts. Duplicate IDs are invalid.
Remediation requires prior verification; retest requires remediation and fresh
evidence and artifact IDs. Event list order is authoritative; callers must
preserve chronology. An empty event list is observed, never verified.

References establish traceability, not authenticity: callers must retain and trust
the artifacts and explicit check results. Source names, confidence, command exit
codes, input status and previously computed assessments are never verification.
"""

from collections import Counter


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _records(value):
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _index(value):
    records = _records(value)
    counts = Counter(item["id"] for item in records if _text(item.get("id")))
    return {item["id"]: item for item in records
            if _text(item.get("id")) and counts[item["id"]] == 1}


def assess_finding(finding: dict) -> dict:
    """Derive lifecycle and current verification without mutating the input.

    Output status is the evidence-backed confirmed/potential projection, unlike
    vuln_validate.validate's legacy top-level status. A negative initial check is
    inconclusive, not proof of remediation. A negative post-remediation retest is
    retested with remediation_verified=True and verified=False. Failed or invalid
    subsequent checks clear current verification but retain the derived history.
    """
    artifacts = _index(finding.get("artifacts"))
    evidence = _index(finding.get("evidence"))
    target = finding.get("target")
    state, verified, remediation_verified = "observed", False, False
    history, evidence_refs, artifact_refs = [], set(), set()
    used_check_refs = set()
    used_check_artifacts = set()
    was_verified = was_remediated = False
    events = finding.get("verification_events", [])
    if not isinstance(events, list):
        events = [None]
    for event in events:
        event = event if isinstance(event, dict) else {}
        kind, result = event.get("kind"), event.get("result")
        method, refs = event.get("method"), event.get("evidence_refs")
        valid = (_text(target) and event.get("target") == target and _text(method)
                 and isinstance(refs, list) and bool(refs))
        resolved_artifacts = set()
        if valid:
            for ref in refs:
                record = evidence.get(ref) if _text(ref) else None
                links = record.get("artifact_refs") if record else None
                if (not record or record.get("target") != target
                        or record.get("method") != method or record.get("result") != result
                        or not isinstance(links, list) or not links):
                    valid = False
                    break
                for link in links:
                    artifact = artifacts.get(link) if _text(link) else None
                    if not artifact or not _text(artifact.get("uri")):
                        valid = False
                        break
                    resolved_artifacts.add(link)
        reason = "Missing or mismatched target, method, evidence or artifact references."
        previous = state
        state, verified, remediation_verified = "inconclusive", False, False
        if valid:
            evidence_refs.update(refs)
            artifact_refs.update(resolved_artifacts)
            reason = "Unsupported result or lifecycle transition."
            if kind == "observation" and result == "observed":
                state = "observed"
            elif kind == "suspicion" and result == "suspected":
                state = "suspected"
            elif kind == "verification" and result in ("positive", "negative", "inconclusive"):
                state = "verified" if result == "positive" else "inconclusive"
                verified = result == "positive"
            elif (kind == "remediation" and result == "applied"
                  and previous in ("verified", "retested") and was_verified
                  and not used_check_refs.intersection(refs)
                  and not used_check_artifacts.intersection(resolved_artifacts)):
                state = "remediated"
            elif (kind == "retest" and result in ("positive", "negative", "inconclusive")
                  and previous in ("remediated", "retested") and was_remediated
                  and not used_check_refs.intersection(refs)
                  and not used_check_artifacts.intersection(resolved_artifacts)):
                state = "inconclusive" if result == "inconclusive" else "retested"
                verified = result == "positive"
                remediation_verified = result == "negative"
            if state != "inconclusive":
                reason = "Evidence-backed event accepted."
            elif (kind == "verification" and result in ("negative", "inconclusive")
                  or kind == "retest" and result == "inconclusive"):
                reason = "Check did not positively verify the vulnerability."
            if kind in ("verification", "remediation", "retest"):
                used_check_refs.update(refs)
                used_check_artifacts.update(resolved_artifacts)
        was_verified = verified
        was_remediated = state == "remediated" or (state == "retested" and remediation_verified)
        history.append({"kind": kind if _text(kind) else "invalid", "lifecycle": state,
                        "result": result if _text(result) else None, "reason": reason,
                        "evidence_refs": list(refs) if valid else [],
                        "artifact_refs": sorted(resolved_artifacts) if valid else []})
    return {"lifecycle": state, "verified": verified,
            "remediation_verified": remediation_verified,
            "status": "confirmed" if verified else "potential",
            "evidence_refs": sorted(evidence_refs), "artifact_refs": sorted(artifact_refs),
            "history": history}

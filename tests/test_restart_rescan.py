"""
Regression tests for restart/recovery state handling.
Transitions reflect the actual _TRANSITIONS graph:
  discovered  -> suspected, validated, attempted
  suspected   -> validated, attempted, failed
  validated   -> attempted
  attempted   -> exploited, failed
  failed      -> attempted            (retry)
  exploited   -> verified, failed
  verified    -> remediated
  remediated  -> (terminal)
"""

import sys, pathlib
ROOT = pathlib.Path(__file__).parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from core.exploit_state import ExploitRegistry, ExploitState, ExploitRecord, ExploitAttempt


def _advance(rec, *states):
    for s in states:
        rec.transition(s)


# 1. Stale ATTEMPTED records can be retried via FAILED then ATTEMPTED
def test_stale_attempted_retry_via_failed():
    reg = ExploitRegistry()
    rec = reg.get_or_create("10.0.0.1", 22, service="ssh")
    _advance(rec, "suspected", "validated", "attempted")
    assert rec.state == "attempted"

    # Simulate crash: mark failed, then re-attempt
    ok = rec.transition("failed")
    assert ok is True
    ok = rec.transition("attempted")
    assert ok is True
    assert rec.state == "attempted"


# 2. EXPLOITED records survive serialise/deserialise
def test_exploited_record_persists_across_restart():
    reg = ExploitRegistry()
    rec = reg.get_or_create("10.0.0.2", 445, service="smb")
    _advance(rec, "suspected", "validated", "attempted", "exploited")

    data = reg.to_list()
    reg2 = ExploitRegistry()
    reg2.load_from_list(data)

    exploited = reg2.by_state("exploited")
    assert len(exploited) == 1
    assert exploited[0].host == "10.0.0.2"


# 3. FAILED records cannot jump directly to EXPLOITED
def test_failed_records_not_auto_retried():
    reg = ExploitRegistry()
    rec = reg.get_or_create("10.0.0.3", 80, service="http")
    _advance(rec, "suspected", "validated", "attempted", "failed")

    ok = rec.transition("exploited")
    assert ok is False
    assert rec.state == "failed"


# 4. FAILED → ATTEMPTED is allowed (the only retry path)
def test_failed_can_transition_to_attempted_for_retry():
    reg = ExploitRegistry()
    rec = reg.get_or_create("10.0.0.4", 8080, service="http")
    _advance(rec, "suspected", "validated", "attempted", "failed")
    ok = rec.transition("attempted")
    assert ok is True
    assert rec.state == "attempted"


# 5. Attempt history preserved across to_dict/from_dict
def test_attempt_history_preserved():
    rec = ExploitRecord(host="10.0.0.5", port=22, service="ssh")
    _advance(rec, "suspected", "validated", "attempted")
    rec.record_attempt(
        module="exploit/multi/handler",
        command="run",
        output="Meterpreter session 1 opened",
        success=True,
        session_id="1",
    )

    d = rec.to_dict()
    rec2 = ExploitRecord.from_dict(d)
    assert len(rec2.attempts) == 1
    assert rec2.attempts[0].module == "exploit/multi/handler"
    assert rec2.attempts[0].session_id == "1"


# 6. get_or_create is idempotent for same (host, port, cve)
def test_get_or_create_idempotent():
    reg = ExploitRegistry()
    r1 = reg.get_or_create("10.0.0.6", 22, service="ssh")
    r1.transition("suspected")
    r2 = reg.get_or_create("10.0.0.6", 22, service="ssh")
    assert r1 is r2
    assert r2.state == "suspected"


# 7. load_from_list preserves each record by record_id
def test_load_from_list_preserves_record_id():
    reg = ExploitRegistry()
    r1 = reg.get_or_create("10.0.0.7", 22, service="ssh")
    r1.transition("suspected")
    data = reg.to_list()

    reg2 = ExploitRegistry()
    reg2.load_from_list(data)
    recs = reg2.by_host("10.0.0.7")
    assert len(recs) == 1
    assert recs[0].state == "suspected"


# 8. Reset all ATTEMPTED to retry state; summary shows zero ATTEMPTED
def test_summary_no_orphan_attempted_after_reset():
    reg = ExploitRegistry()
    for h in ["10.0.0.8", "10.0.0.9"]:
        rec = reg.get_or_create(h, 22, service="ssh")
        _advance(rec, "suspected", "validated", "attempted")

    # Restart: roll ATTEMPTED → FAILED → ATTEMPTED (re-queued)
    for rec in reg.by_state("attempted"):
        rec.transition("failed")

    # All should now be FAILED (awaiting operator re-trigger)
    s = reg.summary()["by_state"]
    assert s.get("attempted", 0) == 0
    assert s.get("failed", 0) == 2


# 9. mark_validated sets state to VALIDATED via transition
def test_mark_validated():
    rec = ExploitRecord(host="10.0.0.10", port=8443, service="https")
    rec.transition("suspected")
    ok = rec.mark_validated(evidence="CVE-2021-44228 PoC confirmed via OOB callback")
    assert ok is True
    assert rec.state == "validated"


# 10. mark_verified sets state to VERIFIED from EXPLOITED
def test_mark_verified():
    rec = ExploitRecord(host="10.0.0.11", port=4848, service="glassfish")
    _advance(rec, "suspected", "validated", "attempted", "exploited")
    ok = rec.mark_verified(verified_by="automated-post-exploit-check")
    assert ok is True
    assert rec.state == "verified"


# 11. REMEDIATED is a terminal state
def test_remediated_is_terminal():
    rec = ExploitRecord(host="10.0.0.12", port=21, service="ftp")
    _advance(rec, "suspected", "validated", "attempted", "exploited", "verified", "remediated")
    assert rec.state == "remediated"

    for bad in ["discovered", "suspected", "exploited", "failed", "attempted"]:
        ok = rec.transition(bad)
        assert ok is False, f"Should not allow {bad} from remediated"
    assert rec.state == "remediated"


# 12. Multiple attempts recorded, all in to_dict
def test_multiple_attempts_preserved():
    rec = ExploitRecord(host="10.0.0.13", port=22, service="ssh")
    _advance(rec, "suspected", "validated")

    for i in range(3):
        rec.transition("attempted")
        success = (i == 2)
        rec.record_attempt(
            module=f"exploit/ssh/attempt_{i}",
            command=f"run {i}",
            output=f"output {i}",
            success=success,
        )
        if not success:
            # record_attempt with success=False transitions to failed
            # retry: failed → attempted handled by next loop iteration
            pass

    d = rec.to_dict()
    assert len(d["attempts"]) == 3
    assert d["attempts"][2]["module"] == "exploit/ssh/attempt_2"

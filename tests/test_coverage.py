"""Tests for the coverage model (core/coverage.py) — Coverage Engine M1.
Covers service coverage construction, state derivation, coverage ratio, the
coverage-derived progress formula, and the premature-completion guard."""

from core import coverage as cov
from core import playbooks as pb


def _smb_cov():
    return cov.build_service_coverage({"service": "microsoft-ds", "port": 445})


def test_build_service_coverage_seeds_pending_steps():
    c = _smb_cov()
    assert "smb" in c["keys"]
    assert c["steps"] and all(v == cov.PENDING for v in c["steps"].values())


def test_service_state_ladder():
    c = _smb_cov()
    assert cov.service_state(c) == cov.S_UNTESTED
    # complete an enumeration step
    enum_id = next(sid for sid, ph in c["phases"].items() if ph == pb.PHASE_ENUM)
    cov.mark(c, enum_id, cov.DONE)
    assert cov.service_state(c) == cov.S_ENUMERATED
    # complete a vuln step
    vuln_id = next(sid for sid, ph in c["phases"].items() if ph == pb.PHASE_VULN)
    cov.mark(c, vuln_id, cov.DONE)
    assert cov.service_state(c) == cov.S_TESTED
    # complete an exploitation step
    exp_id = next(sid for sid, ph in c["phases"].items() if ph == pb.PHASE_EXPLOIT)
    cov.mark(c, exp_id, cov.DONE)
    assert cov.service_state(c) == cov.S_EXPLOITED


def test_coverage_ratio_and_covered():
    c = _smb_cov()
    assert cov.coverage_ratio(c) == 0.0
    assert not cov.is_service_covered(c)
    for sid in list(c["steps"]):
        cov.mark(c, sid, cov.DONE)
    assert cov.coverage_ratio(c) == 1.0
    assert cov.is_service_covered(c)


def test_skipped_steps_excluded_from_ratio():
    c = _smb_cov()
    ids = list(c["steps"])
    cov.mark(c, ids[0], cov.SKIPPED)   # tool missing
    for sid in ids[1:]:
        cov.mark(c, sid, cov.DONE)
    # skipped step doesn't block "covered"
    assert cov.is_service_covered(c)


def test_progress_formula_bounds_and_weights():
    # Nothing done → 0
    assert cov.compute_progress(False, [], 0.0, 0, 0.0) == 0.0
    # Recon only → 0.10
    assert cov.compute_progress(True, [], 0.0, 0, 0.0) == 0.10
    # Full everything → 1.0
    full = cov.compute_progress(True, [1.0, 1.0], 1.0, 2, 1.0)
    assert full == 1.0
    # A single foothold gives half the foothold weight (0.25 * 0.5 = 0.125)
    p = cov.compute_progress(False, [], 0.0, 1, 0.0)
    assert abs(p - 0.125) < 1e-6


def test_match_and_mark_by_tool():
    c = cov.build_service_coverage({"service": "microsoft-ds", "port": 445, "host": "10.0.0.5"})
    done = cov.match_and_mark(c, "enum4linux-ng -A 10.0.0.5")
    assert "smb.enum4linux" in done
    assert c["steps"]["smb.enum4linux"] == cov.DONE
    # already-done step isn't re-reported
    assert cov.match_and_mark(c, "enum4linux-ng -A 10.0.0.5") == []


def test_match_and_mark_ai_step_by_signal():
    c = cov.build_service_coverage({"service": "mysql", "port": 3306, "host": "10.0.0.5"})
    done = cov.match_and_mark(c, "mysql -h 10.0.0.5 -u root -e \"SELECT ... INTO OUTFILE '/x/shell.php'\"")
    assert "mysql.file_write" in done


def test_pending_steps_shrinks_as_marked():
    c = cov.build_service_coverage({"service": "ftp", "port": 21, "host": "10.0.0.5"})
    before = len(cov.pending_steps(c))
    cov.match_and_mark(c, "curl -s ftp://10.0.0.5/ --user anonymous:anonymous")
    assert len(cov.pending_steps(c)) < before


def test_objective_complete_guard_blocks_premature():
    # One foothold but low coverage → NOT complete (the field bug: 100% on a
    # single win while most services untouched).
    assert cov.is_objective_complete(progress=0.55, services_covered_ratio=0.2, footholds=1) is False
    # Foothold + high coverage + high progress → complete.
    assert cov.is_objective_complete(progress=0.9, services_covered_ratio=0.9, footholds=1) is True
    # No foothold → never complete regardless of coverage.
    assert cov.is_objective_complete(progress=0.95, services_covered_ratio=1.0, footholds=0) is False

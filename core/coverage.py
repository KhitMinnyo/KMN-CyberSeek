"""
KMN-CyberSeek Coverage Model (Coverage Engine — M1)

Tracks, per service, which playbook steps have been attempted, derives a
service state from that, and computes a *coverage-derived* objective progress.

This replaces two failure modes observed in the field:
  - services abandoned on loop-detection before their methodology is complete
    (now: a service is "covered" only when its playbook is exhausted), and
  - the strategist declaring the objective 100% complete on a single foothold
    while most of the attack surface is untouched (now: progress and completion
    are functions of measured coverage, not the model's mood).

Pure logic — no I/O, no orchestrator coupling — so it is easy to unit-test and
safe to import anywhere. Integration into the live loop lands behind the
COVERAGE_ENGINE flag.
"""

from typing import Dict, List

from core import playbooks as pb

# Step statuses
PENDING = "pending"
DONE = "done"
SKIPPED = "skipped"          # tool missing / not applicable

# Service states (monotonic ladder)
S_UNTESTED = "untested"
S_ENUMERATED = "enumerated"
S_TESTED = "tested"
S_EXPLOITED = "exploited"
S_POST_EX = "post_ex_done"

_STATE_ORDER = [S_UNTESTED, S_ENUMERATED, S_TESTED, S_EXPLOITED, S_POST_EX]


def build_service_coverage(svc: dict) -> dict:
    """Create the coverage record for a discovered service: its playbook keys,
    the ordered step ids, and each step's status (all pending)."""
    keys = pb.classify_service(svc)
    steps = pb.get_steps(keys)
    return {
        "keys": keys,
        "steps": {st.id: PENDING for st in steps},
        "phases": {st.id: st.phase for st in steps},
    }


def mark(cov: dict, step_id: str, status: str) -> None:
    """Set a step's status (best-effort; unknown ids are ignored)."""
    if step_id in cov.get("steps", {}):
        cov["steps"][step_id] = status


def _steps_for(cov: dict) -> List:
    return pb.get_steps(cov.get("keys", []))


def match_and_mark(cov: dict, command: str) -> List[str]:
    """Mark any PENDING step this executed command attempts (tool name or signal
    match) as DONE. Returns the list of newly-completed step ids. Best-effort —
    coverage tracking is a guide, not an oracle."""
    done_now: List[str] = []
    for st in _steps_for(cov):
        if cov["steps"].get(st.id) == PENDING and st.matches_command(command):
            cov["steps"][st.id] = DONE
            done_now.append(st.id)
    return done_now


def pending_steps(cov: dict) -> List:
    """PlaybookStep objects for this service's still-pending steps, in order."""
    return [st for st in _steps_for(cov) if cov["steps"].get(st.id) == PENDING]


def _phases_with_done(cov: dict) -> set:
    return {
        cov["phases"].get(sid)
        for sid, status in cov["steps"].items()
        if status == DONE
    }


def service_state(cov: dict) -> str:
    """Derive the service state from which phases have at least one done step."""
    done_phases = _phases_with_done(cov)
    state = S_UNTESTED
    if pb.PHASE_ENUM in done_phases:
        state = S_ENUMERATED
    if pb.PHASE_VULN in done_phases:
        state = S_TESTED
    if pb.PHASE_EXPLOIT in done_phases:
        state = S_EXPLOITED
    if pb.PHASE_POST in done_phases:
        state = S_POST_EX
    return state


def coverage_ratio(cov: dict) -> float:
    """Fraction of applicable (non-skipped) steps that are done. 1.0 if all
    steps are skipped/none (nothing left to do)."""
    steps = cov.get("steps", {})
    applicable = [s for s in steps.values() if s != SKIPPED]
    if not applicable:
        return 1.0
    done = sum(1 for s in applicable if s == DONE)
    return done / len(applicable)


def is_service_covered(cov: dict) -> bool:
    """A service is covered when every applicable step has been attempted."""
    return coverage_ratio(cov) >= 1.0


def enumeration_coverage(cov: dict) -> float:
    """Fraction of the service's ENUMERATION-phase steps that are done — used as
    the 'did we at least enumerate this service' signal in the progress formula."""
    enum_steps = [sid for sid, ph in cov["phases"].items() if ph == pb.PHASE_ENUM]
    if not enum_steps:
        return 1.0
    done = sum(1 for sid in enum_steps
               if cov["steps"].get(sid) in (DONE, SKIPPED))
    return done / len(enum_steps)


# ---------------------------------------------------------------------------
# Coverage-derived objective progress
# ---------------------------------------------------------------------------

# Weights (must sum to 1.0). Configurable later via env if needed.
_W_RECON = 0.10
_W_ENUM = 0.35
_W_VULN = 0.15
_W_FOOTHOLD = 0.25
_W_POSTEX = 0.15


def compute_progress(
    recon_done: bool,
    enum_coverages: List[float],
    validated_vuln_ratio: float,
    footholds: int,
    post_ex_coverage: float,
) -> float:
    """Deterministic objective progress in [0, 1].

    - recon_done: initial scan finished.
    - enum_coverages: per-service enumeration-coverage fractions.
    - validated_vuln_ratio: confirmed / total findings (0..1).
    - footholds: number of confirmed compromises (scaled, 2 = full credit).
    - post_ex_coverage: 0..1 fraction of post-exploitation work done.
    """
    mean_enum = (sum(enum_coverages) / len(enum_coverages)) if enum_coverages else 0.0
    foothold_scaled = min(1.0, footholds / 2.0) if footholds > 0 else 0.0
    progress = (
        _W_RECON * (1.0 if recon_done else 0.0)
        + _W_ENUM * mean_enum
        + _W_VULN * max(0.0, min(1.0, validated_vuln_ratio))
        + _W_FOOTHOLD * foothold_scaled
        + _W_POSTEX * max(0.0, min(1.0, post_ex_coverage))
    )
    return round(min(1.0, max(0.0, progress)), 3)


def is_objective_complete(
    progress: float,
    services_covered_ratio: float,
    footholds: int,
) -> bool:
    """Guard against premature completion. The objective is only complete when
    there is at least one confirmed foothold AND the vast majority of discovered
    services have had their playbook completed AND progress is high. This stops
    the strategist declaring victory on a single win while the attack surface is
    largely untouched."""
    return (
        footholds >= 1
        and services_covered_ratio >= 0.85
        and progress >= 0.85
    )

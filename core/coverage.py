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

from typing import Dict, List, Optional

from core import playbooks as pb

# Step statuses
PENDING = "pending"
ATTEMPTED = "attempted"      # command ran but did not (yet) succeed
DONE = "done"                # command ran AND produced the step's success signal
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


def build_postex_coverage() -> dict:
    """Coverage record for the (service-agnostic) post-exploitation checklist,
    activated once a foothold exists."""
    steps = pb.POSTEX_STEPS
    return {
        "keys": [],
        "postex": True,
        "steps": {st.id: PENDING for st in steps},
        "phases": {st.id: st.phase for st in steps},
    }


def mark(cov: dict, step_id: str, status: str) -> None:
    """Set a step's status (best-effort; unknown ids are ignored)."""
    if step_id in cov.get("steps", {}):
        cov["steps"][step_id] = status


def _steps_for(cov: dict) -> List:
    if cov.get("postex"):
        return list(pb.POSTEX_STEPS)
    return pb.get_steps(cov.get("keys", []))


def match_and_mark(cov: dict, command: str, success: bool = True,
                   exploit_success: Optional[bool] = None) -> List[str]:
    """Record an executed command against any step it attempts (tool name or
    signal match). Returns the list of newly-DONE step ids.

    Three-state semantics (pending → attempted → done):

    - On a *successful* command, ENUMERATION / VULNERABILITY / POST-EXPLOITATION
      steps become DONE (the recon value is in the output).
    - An EXPLOITATION step becomes DONE only when ``exploit_success`` is true
      (a confirmed compromise signal), because a zero exit code does not mean the
      target was compromised.
    - On a *failed* command (or a failed exploit attempt), the matched step is
      marked ATTEMPTED — so it is visible as "tried but not achieved" — but never
      DONE. ATTEMPTED steps do not count toward ``coverage_ratio`` /
      ``is_service_covered``, so a service is never abandoned as "covered" just
      because its exploit was attempted and failed.

    Best-effort — coverage tracking is a guide, not an oracle.
    """
    done_now: List[str] = []
    for st in _steps_for(cov):
        if not st.matches_command(command):
            continue
        cur = cov["steps"].get(st.id)
        if cur == DONE:
            continue
        phase_success = (
            (exploit_success if exploit_success is not None else success)
            if st.phase == pb.PHASE_EXPLOIT else success
        )
        if not phase_success:
            # Tried but not achieved. Mark ATTEMPTED (never DONE) so the step is
            # visible as "attempted" but still keeps the service incomplete.
            if cur != ATTEMPTED:
                cov["steps"][st.id] = ATTEMPTED
            continue
        cov["steps"][st.id] = DONE
        done_now.append(st.id)
    return done_now


def pending_steps(cov: dict) -> List:
    """PlaybookStep objects still PENDING (never attempted), in order."""
    return [st for st in _steps_for(cov) if cov["steps"].get(st.id) == PENDING]


def attempted_steps(cov: dict) -> List:
    """PlaybookStep objects marked ATTEMPTED (tried but not yet achieved), in
    order. These still need to succeed before the service counts as covered."""
    return [st for st in _steps_for(cov) if cov["steps"].get(st.id) == ATTEMPTED]


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
    """A service is covered only when every applicable step is DONE (attempted
    but failed steps do not count, so a service is never abandoned as "covered"
    before its exploit actually succeeded)."""
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
#
# The engagement objective is a foothold / root / Domain Admin, so exploitation
# and post-exploitation carry the most weight. Enumeration is necessary but is
# not the goal: an earlier weighting (ENUM 0.35 > FOOTHOLD 0.25) let a run that
# only enumerated reach ~45% progress without compromising anything, which
# matched the observed "touches half, confirms almost nothing" behaviour.
_W_RECON = 0.08
_W_ENUM = 0.22
_W_VULN = 0.15
_W_FOOTHOLD = 0.40
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

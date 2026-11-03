"""Local, non-executable observation objectives proposed by a completed MIO cycle.

An objective only names which validated hypotheses a future, separately
authorized observation should help distinguish. It carries no question text,
capability, target, environment, package, tier, command, or activation/lease
selector, and it never calls the broker. Edge owns authorization and will map
``objective_id`` to Fabric's typed ``observation_objective:`` ref once that
proposal is accepted. MIO does not import Fabric types.

``ObservationProjectionReport`` is a local MIO diagnostic of what the projector
did (skips and closed per-gap outcome codes). It is not a shared contract.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from .contracts import HypothesisStatus, MioEvidenceGap, MioHypothesis, MioSituationFrame, ReasoningState

OBSERVATION_PLAYBOOK_ID = "deception-observation-v1"
OBSERVATION_AUTHORITY = "advisory_only"
MAX_OBJECTIVE_HYPOTHESES = 8
# Default bound on per-gap report entries. The reasoning loop passes its own
# ReasoningBudget.max_gaps; this default mirrors that budget's default.
DEFAULT_REPORT_MAX_GAPS = 3

# Closed local diagnostic codes. Never raw model text or identifiers.
SKIP_NOT_COMPLETE = "not_complete"
SKIP_WRONG_PLAYBOOK = "wrong_playbook"
SKIP_DECEPTION_UNAVAILABLE = "deception_unavailable"
SKIP_INVALID_FRAME_BINDING = "invalid_frame_binding"
SKIP_MALFORMED_INPUT = "malformed_input"
GAP_EMITTED = "emitted"
GAP_NOT_ELIGIBLE = "not_eligible"
GAP_INVALID_ID = "invalid_id"
GAP_DUPLICATE = "duplicate_gap"
GAP_NO_LIVE_HYPOTHESES = "no_live_hypotheses"
STATE_SKIP_CODES = frozenset({SKIP_NOT_COMPLETE, SKIP_WRONG_PLAYBOOK, SKIP_DECEPTION_UNAVAILABLE,
                              SKIP_INVALID_FRAME_BINDING, SKIP_MALFORMED_INPUT})
GAP_OUTCOME_CODES = frozenset({GAP_EMITTED, GAP_NOT_ELIGIBLE, GAP_INVALID_ID, GAP_DUPLICATE,
                               GAP_NO_LIVE_HYPOTHESES})

_OBJECTIVE_ID_RE = re.compile(r"obs-[0-9a-f]{24}\Z")
_LOCAL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EXCLUDED_STATUSES = frozenset({HypothesisStatus.FALSIFIED, HypothesisStatus.SUPERSEDED})


def _local_id(value: Any) -> bool:
    return type(value) is str and _LOCAL_ID_RE.fullmatch(value) is not None


@dataclass(frozen=True)
class MioObservationObjective:
    """Advisory pointer from a validated gap to the hypotheses it discriminates.

    Authority is fixed to ``advisory_only`` and ``executable`` to ``False``;
    any other value is rejected at construction.
    """

    objective_id: str
    frame_id: str
    trace_id: str
    source_gap_id: str
    hypothesis_ids: tuple[str, ...]
    authority: str = OBSERVATION_AUTHORITY
    executable: bool = False

    def __post_init__(self) -> None:
        if type(self.objective_id) is not str or _OBJECTIVE_ID_RE.fullmatch(self.objective_id) is None:
            raise ValueError("invalid_objective_id")
        for name in ("frame_id", "trace_id", "source_gap_id"):
            if not _local_id(getattr(self, name)):
                raise ValueError(f"invalid_{name}")
        ids = self.hypothesis_ids
        if type(ids) is not tuple or not 1 <= len(ids) <= MAX_OBJECTIVE_HYPOTHESES:
            raise ValueError("invalid_hypothesis_ids")
        if len(set(ids)) != len(ids) or not all(_local_id(item) for item in ids):
            raise ValueError("invalid_hypothesis_ids")
        if self.authority != OBSERVATION_AUTHORITY:
            raise ValueError("invalid_authority")
        if self.executable is not False:
            raise ValueError("objective_must_not_be_executable")

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective_id": self.objective_id,
            "frame_id": self.frame_id,
            "trace_id": self.trace_id,
            "source_gap_id": self.source_gap_id,
            "hypothesis_ids": list(self.hypothesis_ids),
            "authority": self.authority,
            "executable": False,
        }


def _objective_id(frame_id: str, trace_id: str, gap_id: str) -> str:
    material = "\x1f".join((frame_id, trace_id, gap_id)).encode("utf-8")
    return "obs-" + hashlib.sha256(material).hexdigest()[:24]


@dataclass(frozen=True)
class ObservationProjectionReport:
    """Local MIO diagnostic of one projection. Not a Fabric/Edge wire contract.

    ``state_skip`` is set when no per-gap evaluation happened (a code from
    ``STATE_SKIP_CODES``). Otherwise ``gap_outcomes`` holds one closed code from
    ``GAP_OUTCOME_CODES`` per gap, in input order, bounded by ``max_gaps``;
    ``unreported_gap_count`` counts gaps beyond that bound. ``emitted_count``
    and ``omitted_hypothesis_count`` cover all gaps. The report carries no
    identifiers, question text, or capability names, and has no generation or
    freshness semantics.
    """

    state_skip: str | None = None
    gap_outcomes: tuple[str, ...] = ()
    unreported_gap_count: int = 0
    emitted_count: int = 0
    omitted_hypothesis_count: int = 0

    def to_diagnostic(self) -> dict[str, Any]:
        return {
            "state_skip": self.state_skip,
            "gap_outcomes": list(self.gap_outcomes),
            "unreported_gap_count": self.unreported_gap_count,
            "emitted_count": self.emitted_count,
            "omitted_hypothesis_count": self.omitted_hypothesis_count,
        }


def _skipped(code: str) -> ObservationProjectionReport:
    return ObservationProjectionReport(state_skip=code)


def project_observation_report(
    *,
    frame: MioSituationFrame,
    playbook_id: str,
    state: ReasoningState,
    hypotheses: Iterable[MioHypothesis],
    gaps: Sequence[MioEvidenceGap],
    eligible_gap_ids: Iterable[str],
    max_gaps: int = DEFAULT_REPORT_MAX_GAPS,
) -> tuple[tuple[MioObservationObjective, ...], ObservationProjectionReport]:
    """Projection plus a bounded local diagnostic report.

    Objectives are identical to ``project_observation_objectives``. Malformed
    inputs fail closed: no objectives and a ``malformed_input`` state skip.
    """
    if not isinstance(frame, MioSituationFrame) or type(max_gaps) is not int or max_gaps < 0:
        return (), _skipped(SKIP_MALFORMED_INPUT)
    if state is not ReasoningState.COMPLETE:
        return (), _skipped(SKIP_NOT_COMPLETE)
    if playbook_id != OBSERVATION_PLAYBOOK_ID:
        return (), _skipped(SKIP_WRONG_PLAYBOOK)
    if frame.deception_status != "available":
        return (), _skipped(SKIP_DECEPTION_UNAVAILABLE)
    if not (_local_id(frame.frame_id) and _local_id(frame.trace_id)):
        return (), _skipped(SKIP_INVALID_FRAME_BINDING)
    try:
        hyp_list = tuple(hypotheses)
        gap_list = tuple(gaps)
        eligible = frozenset(eligible_gap_ids)
    except TypeError:
        return (), _skipped(SKIP_MALFORMED_INPUT)
    if not all(isinstance(h, MioHypothesis) and type(h.hypothesis_id) is str for h in hyp_list):
        return (), _skipped(SKIP_MALFORMED_INPUT)
    for gap in gap_list:
        if not isinstance(gap, MioEvidenceGap) or type(gap.gap_id) is not str:
            return (), _skipped(SKIP_MALFORMED_INPUT)
        if type(gap.discriminates_hypothesis_ids) is not tuple or not all(
                type(h) is str for h in gap.discriminates_hypothesis_ids):
            return (), _skipped(SKIP_MALFORMED_INPUT)
    live_ids = {h.hypothesis_id for h in hyp_list
                if h.status not in _EXCLUDED_STATUSES and _local_id(h.hypothesis_id)}
    objectives: list[MioObservationObjective] = []
    outcomes: list[str] = []
    seen_gaps: set[str] = set()
    omitted = 0
    for gap in gap_list:
        code, ids, extra = _classify_gap(gap, eligible, seen_gaps, live_ids)
        if len(outcomes) < max_gaps:
            outcomes.append(code)
        if code != GAP_EMITTED:
            continue
        omitted += extra
        seen_gaps.add(gap.gap_id)
        objectives.append(MioObservationObjective(
            objective_id=_objective_id(frame.frame_id, frame.trace_id, gap.gap_id),
            frame_id=frame.frame_id,
            trace_id=frame.trace_id,
            source_gap_id=gap.gap_id,
            hypothesis_ids=ids,
        ))
    report = ObservationProjectionReport(
        state_skip=None,
        gap_outcomes=tuple(outcomes),
        unreported_gap_count=len(gap_list) - len(outcomes),
        emitted_count=len(objectives),
        omitted_hypothesis_count=omitted,
    )
    return tuple(objectives), report


def _classify_gap(gap: MioEvidenceGap, eligible: frozenset[str], seen_gaps: set[str],
                  live_ids: set[str]) -> tuple[str, tuple[str, ...], int]:
    """Return (closed outcome code, emitted hypothesis IDs, count cut by the cap)."""
    if gap.gap_id not in eligible:
        return GAP_NOT_ELIGIBLE, (), 0
    if not _local_id(gap.gap_id):
        return GAP_INVALID_ID, (), 0
    if gap.gap_id in seen_gaps:
        return GAP_DUPLICATE, (), 0
    live = tuple(dict.fromkeys(h for h in gap.discriminates_hypothesis_ids if h in live_ids))
    if not live:
        return GAP_NO_LIVE_HYPOTHESES, (), 0
    ids = live[:MAX_OBJECTIVE_HYPOTHESES]
    return GAP_EMITTED, ids, len(live) - len(ids)


def project_observation_objectives(
    *,
    frame: MioSituationFrame,
    playbook_id: str,
    state: ReasoningState,
    hypotheses: Iterable[MioHypothesis],
    gaps: Sequence[MioEvidenceGap],
    eligible_gap_ids: Iterable[str],
) -> tuple[MioObservationObjective, ...]:
    """Pure projection. Emits objectives only for a COMPLETE deception-observation cycle.

    ``gaps`` and ``hypotheses`` must be the validated sets of that cycle.
    ``eligible_gap_ids`` must be the IDs the gap scorer marked ``eligible``;
    ineligible gaps (unregistered capability, exhausted budget, etc.) never
    yield an objective. Any other state (error, fallback, rejection, budget,
    cancel, supersession, dependency loss) emits nothing, as does any other
    playbook, and so does any frame whose ``deception_status`` is not
    ``available``, even when the playbook was selected explicitly.
    """
    objectives, _ = project_observation_report(
        frame=frame, playbook_id=playbook_id, state=state, hypotheses=hypotheses,
        gaps=gaps, eligible_gap_ids=eligible_gap_ids,
    )
    return objectives

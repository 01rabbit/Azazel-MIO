"""Local, non-executable observation objectives proposed by a completed MIO cycle.

An objective only names which validated hypotheses a future, separately
authorized observation should help distinguish. It carries no question text,
capability, target, environment, package, tier, command, or activation/lease
selector, and it never calls the broker. Edge owns authorization and will map
``objective_id`` to Fabric's typed ``observation_objective:`` ref once that
proposal is accepted. MIO does not import Fabric types.
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
    if state is not ReasoningState.COMPLETE or playbook_id != OBSERVATION_PLAYBOOK_ID:
        return ()
    if frame.deception_status != "available":
        return ()
    eligible = frozenset(eligible_gap_ids)
    if not (_local_id(frame.frame_id) and _local_id(frame.trace_id)):
        return ()
    live_ids = {h.hypothesis_id for h in hypotheses
                if h.status not in _EXCLUDED_STATUSES and _local_id(h.hypothesis_id)}
    objectives: list[MioObservationObjective] = []
    seen_gaps: set[str] = set()
    for gap in gaps:
        if gap.gap_id not in eligible or not _local_id(gap.gap_id) or gap.gap_id in seen_gaps:
            continue
        ids = tuple(dict.fromkeys(h for h in gap.discriminates_hypothesis_ids if h in live_ids))
        ids = ids[:MAX_OBJECTIVE_HYPOTHESES]
        if not ids:
            continue
        seen_gaps.add(gap.gap_id)
        objectives.append(MioObservationObjective(
            objective_id=_objective_id(frame.frame_id, frame.trace_id, gap.gap_id),
            frame_id=frame.frame_id,
            trace_id=frame.trace_id,
            source_gap_id=gap.gap_id,
            hypothesis_ids=ids,
        ))
    return tuple(objectives)

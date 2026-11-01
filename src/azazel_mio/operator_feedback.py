"""Local operator reports, isolated from recommendation and learning authority."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import re

from .contracts import DEFENSIVE_STATES, MioSituationFrame, ReasoningState, model_id_ok
from .id_grammar import id_ok
from .reasoning import ReasoningOutcome
from .trace import ReasoningTraceEvent


def _time(value: str) -> datetime:
    if type(value) is not str or len(value) > 64:
        raise ValueError("invalid_feedback_time")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("invalid_feedback_time") from None
    if result.tzinfo is None:
        raise ValueError("feedback_timezone_required")
    return result.astimezone(timezone.utc)


def _ref(value: str) -> bool:
    # Digest references only: no credential, address, URL, or free-text fields.
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


@dataclass(frozen=True)
class OperatorDisposition:
    record_ref: str
    trace_id: str
    cycle_id: str
    advisory_id: str
    frame_material_digest: str
    reviewer_ref: str
    disposition: str  # accepted|corrected|rejected|held
    reviewed_at: str
    evidence_refs: tuple[str, ...]
    edge_decision_ref: str | None = None
    action_ref: str | None = None
    applied_state: str | None = None
    outcome: str = "unknown"  # unknown|pending|succeeded|failed|not_applied
    outcome_at: str | None = None

    def to_dict(self) -> dict:
        result = asdict(self)
        result["evidence_refs"] = list(self.evidence_refs)
        return {"schema_version": "mio.operator-disposition.v1",
                "authority": "operator_report_unverified", **result}


class OperatorDispositionLog:
    """Bounded append-only reports for one completed, frame-bound cycle.

    The adapter supplies the original frame/outcome and owns reviewer identity,
    durable storage, and action/outcome provenance. Reports never execute actions,
    mutate recommendations, or become LearningExample labels automatically.
    """

    def __init__(self, *, frame: MioSituationFrame, outcome: ReasoningOutcome,
                 max_records: int = 256):
        if type(max_records) is not int or not 1 <= max_records <= 256:
            raise ValueError("invalid_feedback_capacity")
        frame = MioSituationFrame.from_dict(frame.to_dict())
        if (type(outcome) is not ReasoningOutcome or outcome.state is not ReasoningState.COMPLETE
                or outcome.recommendation is None or not outcome.trace):
            raise ValueError("feedback_requires_completed_advisory")
        events = outcome.trace
        if (type(events) is not tuple or len(events) < 3
                or any(type(e) is not ReasoningTraceEvent or type(e.seq) is not int
                       or e.seq != i for i, e in enumerate(events, 1))):
            raise ValueError("feedback_trace_binding_mismatch")
        first, recommendation_event, complete = events[0], events[-2], events[-1]
        recommendation = outcome.recommendation
        expected_recommendation = {
            "advisory_id": recommendation.advisory_id,
            "recommendation_material_digest": recommendation.canonical_digest(),
            "recommended_action": recommendation.recommended_action,
            "evidence_refs": list(recommendation.evidence_refs),
            "executable": False,
        }
        if (not id_ok(frame.trace_id, ("trace_id",))
                or not id_ok(first.cycle_id, ("cycle_request_id",))
                or any(e.trace_id != frame.trace_id or e.cycle_id != first.cycle_id
                       for e in events)
                or [e.kind for e in events].count("frame") != 1
                or [e.kind for e in events].count("recommendation") != 1
                or [e.kind for e in events].count("complete") != 1
                or first.kind != "frame" or first.state != ReasoningState.FRAME_READY.value
                or first.payload != {"frame_id": frame.frame_id,
                                     "frame_material_digest": "sha256:" + frame.canonical_digest()}
                or recommendation.advisory_id != first.cycle_id + ":advisory"
                or recommendation.executable is not False
                or recommendation_event.kind != "recommendation"
                or recommendation_event.state != ReasoningState.RECOMMENDATION_READY.value
                or recommendation_event.payload != expected_recommendation
                or complete.kind != "complete" or complete.state != ReasoningState.COMPLETE.value
                or type(complete.payload) is not dict
                or set(complete.payload) != {"model_calls", "broker_calls"}
                or any(type(x) is not int or x < 0 for x in complete.payload.values())):
            raise ValueError("feedback_trace_binding_mismatch")
        self._binding = (frame.trace_id, first.cycle_id,
                         outcome.recommendation.advisory_id, "sha256:" + frame.canonical_digest())
        self._evidence = frozenset(frame.evidence_refs)
        self._created_at = _time(frame.created_at)
        self._max_records = max_records
        self._records: list[OperatorDisposition] = []

    def append(self, record: OperatorDisposition, *, now: str) -> None:
        if type(record) is not OperatorDisposition:
            raise ValueError("invalid_feedback_record")
        if len(self._records) >= self._max_records:
            raise ValueError("feedback_capacity_reached")
        if (record.trace_id, record.cycle_id, record.advisory_id,
                record.frame_material_digest) != self._binding:
            raise ValueError("feedback_binding_mismatch")
        if (not _ref(record.record_ref) or not _ref(record.reviewer_ref)
                or any(x is not None and not _ref(x)
                       for x in (record.edge_decision_ref, record.action_ref))):
            raise ValueError("invalid_feedback_reference")
        if any(x.record_ref == record.record_ref for x in self._records):
            raise ValueError("duplicate_feedback_record")
        if (type(record.disposition) is not str or
                record.disposition not in {"accepted", "corrected", "rejected", "held"}
                or type(record.evidence_refs) is not tuple or len(record.evidence_refs) > 32
                or not record.evidence_refs
                or any(not model_id_ok(x, "evidence_ref") or x not in self._evidence
                       for x in record.evidence_refs)):
            raise ValueError("invalid_feedback_review")
        reviewed = _time(record.reviewed_at)
        instant = _time(now)
        if (not self._created_at <= reviewed <= instant
                or self._records and reviewed < _time(self._records[-1].reviewed_at)):
            raise ValueError("invalid_feedback_chronology")
        if (type(record.outcome) is not str or record.outcome not in
                {"unknown", "pending", "succeeded", "failed", "not_applied"}):
            raise ValueError("invalid_feedback_outcome")
        if record.applied_state is not None and (type(record.applied_state) is not str
                                                or record.applied_state not in DEFENSIVE_STATES):
            raise ValueError("invalid_feedback_applied_state")
        if record.outcome == "unknown":
            if any(x is not None for x in (record.action_ref, record.applied_state, record.outcome_at)):
                raise ValueError("unknown_feedback_has_action")
        else:
            if record.action_ref is None or record.outcome_at is None:
                raise ValueError("feedback_action_binding_required")
            prior_outcome_times = [_time(x.outcome_at) for x in self._records
                                   if x.action_ref == record.action_ref and x.outcome_at is not None]
            if (not reviewed <= _time(record.outcome_at) <= instant
                    or prior_outcome_times and _time(record.outcome_at) < max(prior_outcome_times)):
                raise ValueError("invalid_feedback_outcome_time")
            if record.outcome == "succeeded" and record.applied_state is None:
                raise ValueError("feedback_applied_state_required")
            if record.outcome in {"pending", "not_applied"} and record.applied_state is not None:
                raise ValueError("feedback_applied_state_conflict")
        self._records.append(record)

    def records(self) -> tuple[OperatorDisposition, ...]:
        return tuple(self._records)

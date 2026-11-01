from dataclasses import FrozenInstanceError, asdict, replace

import pytest

from azazel_mio import BoundedReasoningLoop, CapabilityBroker, MioSituationFrame
from azazel_mio.operator_feedback import OperatorDisposition, OperatorDispositionLog
from azazel_mio.playbook import GENERIC_PLAYBOOK

NOW = "2026-11-02T00:00:00Z"
LATER = "2026-11-02T00:01:00Z"
REF = "sha256:" + "a" * 64


def setup():
    frame = MioSituationFrame.build(frame_id="frame-1", trace_id="trace-1", created_at=NOW,
        mission="Keep service available", current_defensive_state="OBSERVE",
        threat_level="UNKNOWN", evidence_refs=("ev:ssh:1",))
    def model(task, prompt):
        if task == "generate_hypotheses":
            return {"hypotheses": [
                {"hypothesis_id": f"h{i}", "hypothesis_alternative_id": alt,
                 "statement": "More evidence is required.", "status": "proposed",
                 "supporting_evidence_refs": ["ev:ssh:1"], "contradicting_evidence_refs": [],
                 "assumptions": [], "falsification_conditions": ["Check evidence."],
                 "expected_observations": [], "missing_evidence": []}
                for i, alt in enumerate(("hostile_activity", "benign_activity"), 1)]}
        if task == "identify_evidence_gaps":
            return {"evidence_gaps": []}
        return {"summary": "Observe", "recommended_action": "OBSERVE",
                "rationale": "Evidence is limited", "evidence_refs": ["ev:ssh:1"],
                "limitations": []}
    broker = CapabilityBroker()
    try:
        outcome = BoundedReasoningLoop(model=model, broker=broker).run(
            frame=frame, playbook=GENERIC_PLAYBOOK, cycle_id="cycle-1")
    finally:
        broker.close()
    record = OperatorDisposition(REF, frame.trace_id, "cycle-1", "cycle-1:advisory",
        "sha256:" + frame.canonical_digest(), REF, "accepted", NOW, ("ev:ssh:1",))
    return frame, outcome, record


def test_completed_cycle_report_is_append_only_and_does_not_mutate_authority():
    frame, outcome, record = setup()
    log = OperatorDispositionLog(frame=frame, outcome=outcome)
    before = asdict(outcome.recommendation)
    log.append(record, now=LATER)
    followup = replace(record, record_ref="sha256:" + "b" * 64,
                       action_ref=REF, applied_state="OBSERVE", outcome="succeeded", outcome_at=LATER)
    log.append(followup, now=LATER)
    assert log.records() == (record, followup)
    assert asdict(outcome.recommendation) == before
    assert before["executable"] is False
    assert log.records()[1].to_dict()["authority"] == "operator_report_unverified"
    with pytest.raises(FrozenInstanceError):
        record.disposition = "held"
    with pytest.raises(ValueError, match="duplicate"):
        log.append(record, now=LATER)


@pytest.mark.parametrize("changes", [
    {"trace_id": "trace-2"}, {"cycle_id": "cycle-2"}, {"advisory_id": "cycle-2:advisory"},
    {"frame_material_digest": "sha256:" + "c" * 64},
    {"evidence_refs": ("ev:ssh:2",)}, {"evidence_refs": ()}, {"evidence_refs": ["ev:ssh:1"]},
    {"reviewer_ref": "Bearer credential"}, {"edge_decision_ref": "https://credentials.invalid"},
    {"disposition": "execute"}, {"reviewed_at": LATER}, {"reviewed_at": "2026-11-02"},
    {"outcome": "succeeded"}, {"action_ref": REF},
    {"outcome": "succeeded", "action_ref": REF, "applied_state": "OBSERVE", "outcome_at": "2026-11-01T00:00:00Z"},
    {"outcome": "not_applied", "action_ref": REF, "applied_state": "ISOLATE", "outcome_at": NOW},
])
def test_invalid_report_is_rejected_without_append(changes):
    frame, outcome, record = setup()
    log = OperatorDispositionLog(frame=frame, outcome=outcome)
    with pytest.raises(ValueError):
        log.append(replace(record, **changes), now=NOW)
    assert log.records() == ()


def test_frame_material_and_trace_cannot_be_rebound():
    frame, outcome, _ = setup()
    with pytest.raises(ValueError, match="binding"):
        OperatorDispositionLog(frame=replace(frame, mission="Changed"), outcome=outcome)
    with pytest.raises(ValueError, match="binding"):
        OperatorDispositionLog(frame=frame, outcome=replace(outcome,
            trace=(replace(outcome.trace[0], cycle_id="cycle-2"), *outcome.trace[1:])))


def test_capacity_rejects_without_evicting_old_reports():
    frame, outcome, record = setup()
    log = OperatorDispositionLog(frame=frame, outcome=outcome, max_records=1)
    log.append(record, now=NOW)
    with pytest.raises(ValueError, match="capacity"):
        log.append(replace(record, record_ref="sha256:" + "b" * 64), now=NOW)
    assert log.records() == (record,)


def test_report_is_not_a_learning_example_and_no_model_cycle_is_refused():
    from azazel_mio.learning_data import LearningExample
    frame, outcome, record = setup()
    with pytest.raises(ValueError, match="invalid_learning_example_fields"):
        LearningExample.from_dict(record.to_dict())
    from azazel_mio import ReasoningState
    with pytest.raises(ValueError, match="completed_advisory"):
        OperatorDispositionLog(frame=frame, outcome=replace(outcome,
            state=ReasoningState.VALIDATION_REJECTED, recommendation=None))


@pytest.mark.parametrize("disposition", ["corrected", "rejected", "held"])
def test_non_accepting_reviews_remain_reports(disposition):
    frame, outcome, record = setup()
    log = OperatorDispositionLog(frame=frame, outcome=outcome)
    log.append(replace(record, disposition=disposition), now=NOW)
    assert log.records()[0].disposition == disposition
    assert outcome.recommendation.executable is False

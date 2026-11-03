import dataclasses

import pytest

from azazel_mio import BoundedReasoningLoop, CapabilityBroker, MioSituationFrame
from azazel_mio.broker import CapabilitySpec
from azazel_mio.contracts import HypothesisStatus, MioEvidenceGap, MioHypothesis, ReasoningState
from azazel_mio.observation_objectives import (
    MioObservationObjective,
    OBSERVATION_PLAYBOOK_ID,
    project_observation_objectives,
)
from azazel_mio.playbook import DEFAULT_PLAYBOOKS, GENERIC_PLAYBOOK

NOW = "2026-11-03T00:00:00Z"
DECEPTION = DEFAULT_PLAYBOOKS[OBSERVATION_PLAYBOOK_ID]
FORBIDDEN_KEYS = {"question", "capability", "arguments", "environment", "package", "target",
                  "tier", "command", "activation", "lease", "selector", "executable_ref", "action"}


DECEPTION_CONTEXT = {"environment_id": "env-dec-1", "lifecycle_state": "unknown"}


def frame(**kwargs):
    base = dict(frame_id="frame-dec-1", trace_id="trace-dec-1", created_at=NOW,
                mission="Interpret interaction in an approved deception environment",
                current_defensive_state="OBSERVE", threat_level="UNKNOWN",
                evidence_refs=("ev:ssh:1",), deception_context=DECEPTION_CONTEXT)
    base.update(kwargs)
    return MioSituationFrame.build(**base)


def deception_model(gap_items):
    def model(task, prompt):
        if task in ("generate_hypotheses", "update_hypotheses"):
            return {"hypotheses": [
                {"hypothesis_id": "h1", "hypothesis_alternative_id": "suspicious_behavior_interaction",
                 "statement": "Interaction may reflect prior suspicious behavior.", "status": "proposed",
                 "supporting_evidence_refs": ["ev:ssh:1"], "contradicting_evidence_refs": [],
                 "assumptions": [], "falsification_conditions": ["Lifecycle evidence is absent."],
                 "expected_observations": [], "missing_evidence": []},
                {"hypothesis_id": "h2", "hypothesis_alternative_id": "generic_automated_interaction",
                 "statement": "Interaction may be generic automated traffic.", "status": "proposed",
                 "supporting_evidence_refs": ["ev:ssh:1"], "contradicting_evidence_refs": [],
                 "assumptions": [], "falsification_conditions": ["Targeted pattern appears."],
                 "expected_observations": [], "missing_evidence": []},
            ]}
        if task == "identify_evidence_gaps":
            return {"evidence_gaps": gap_items}
        return {"summary": "Observe the decoy interaction", "recommended_action": "OBSERVE",
                "rationale": "Evidence is limited", "evidence_refs": ["ev:ssh:1"], "limitations": []}
    return model


GAP = {"gap_id": "g1", "question": "Does interaction match the pre-declared objective?",
       "discriminates_hypothesis_ids": ["h1", "h2"], "capability": "get_deception_state", "priority": 80}


class CountingBroker(CapabilityBroker):
    def __init__(self, capabilities=None):
        super().__init__(capabilities)
        self.execute_calls = 0

    def execute(self, request):
        self.execute_calls += 1
        return super().execute(request)


REGISTERED = {"get_deception_state": CapabilitySpec(handler=lambda args: {"rows": 1})}


def run_deception(gap_items=(GAP,), frame_obj=None, capabilities=REGISTERED):
    broker = CountingBroker(capabilities)
    try:
        outcome = BoundedReasoningLoop(model=deception_model(list(gap_items)), broker=broker).run(
            frame=frame_obj or frame(), playbook=DECEPTION, cycle_id="cycle-dec-1")
        return outcome, broker.execute_calls
    finally:
        broker.close()


def hyp(hid, status=HypothesisStatus.PROPOSED):
    return MioHypothesis(hid, "statement", status)


def test_completed_deception_cycle_projects_one_local_objective_linked_to_frame_and_gap():
    outcome, _ = run_deception()
    assert outcome.state is ReasoningState.COMPLETE
    assert [g.gap_id for g in outcome.evidence_gaps] == ["g1"]
    assert len(outcome.observation_objectives) == 1
    obj = outcome.observation_objectives[0]
    assert obj.frame_id == "frame-dec-1"
    assert obj.trace_id == "trace-dec-1"
    assert obj.source_gap_id == "g1"
    assert obj.hypothesis_ids == ("h1", "h2")
    assert obj.authority == "advisory_only"
    assert obj.executable is False
    assert obj.objective_id.startswith("obs-") and len(obj.objective_id) == 28


def test_objective_output_has_no_directive_or_free_text_fields():
    outcome, _ = run_deception()
    data = outcome.observation_objectives[0].to_dict()
    assert set(data) == {"objective_id", "frame_id", "trace_id", "source_gap_id",
                         "hypothesis_ids", "authority", "executable"}
    assert set(data).isdisjoint(FORBIDDEN_KEYS)
    assert data["executable"] is False
    text = repr(data)
    assert "Does interaction match" not in text
    assert "get_deception_state" not in text


def test_local_reasoning_gap_still_carries_question_and_capability():
    outcome, _ = run_deception()
    gap = outcome.evidence_gaps[0]
    assert gap.question == GAP["question"]
    assert gap.capability == "get_deception_state"


def test_objective_is_frozen_and_rejects_non_advisory_or_executable_values():
    obj = run_deception()[0].observation_objectives[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        obj.executable = True
    base = dict(objective_id=obj.objective_id, frame_id="f", trace_id="t", source_gap_id="g1", hypothesis_ids=("h1",))
    with pytest.raises(ValueError):
        MioObservationObjective(**base, authority="executable")
    with pytest.raises(ValueError):
        MioObservationObjective(**base, executable=True)
    with pytest.raises(ValueError):
        MioObservationObjective(**{**base, "hypothesis_ids": ("h1", "h1")})
    with pytest.raises(ValueError):
        MioObservationObjective(**{**base, "hypothesis_ids": ()})
    with pytest.raises(ValueError):
        MioObservationObjective(**{**base, "objective_id": "obs-../../x"})


def test_projection_uses_only_validated_live_hypothesis_ids_and_dedupes_gaps():
    hypotheses = (hyp("h1"), hyp("h2", HypothesisStatus.FALSIFIED))
    gaps = (
        MioEvidenceGap("g1", "q", ("h1", "h2", "h1"), "get_deception_state", 50),
        MioEvidenceGap("g1", "dup", ("h1",), "get_deception_state", 50),
        MioEvidenceGap("g2", "only falsified", ("h2",), "get_deception_state", 50),
        MioEvidenceGap("g3", "unknown", ("hX",), "get_deception_state", 50),
    )
    out = project_observation_objectives(frame=frame(), playbook_id=OBSERVATION_PLAYBOOK_ID,
                                         state=ReasoningState.COMPLETE, hypotheses=hypotheses, gaps=gaps,
                                         eligible_gap_ids=("g1", "g2", "g3"))
    assert [(o.source_gap_id, o.hypothesis_ids) for o in out] == [("g1", ("h1",))]


@pytest.mark.parametrize("state", [s for s in ReasoningState if s is not ReasoningState.COMPLETE])
def test_non_complete_states_emit_no_objective(state):
    out = project_observation_objectives(frame=frame(), playbook_id=OBSERVATION_PLAYBOOK_ID, state=state,
                                         hypotheses=(hyp("h1"), hyp("h2")),
                                         gaps=(MioEvidenceGap("g1", "q", ("h1",), "get_deception_state", 50),),
                                         eligible_gap_ids=("g1",))
    assert out == ()


@pytest.mark.parametrize("playbook_id", ["generic-evidence-first-v1", "auth-ambiguity-v1", "unknown", ""])
def test_non_deception_playbook_emits_no_objective(playbook_id):
    out = project_observation_objectives(frame=frame(), playbook_id=playbook_id, state=ReasoningState.COMPLETE,
                                         hypotheses=(hyp("h1"), hyp("h2")),
                                         gaps=(MioEvidenceGap("g1", "q", ("h1",), "get_deception_state", 50),),
                                         eligible_gap_ids=("g1",))
    assert out == ()


def test_generic_playbook_complete_cycle_has_no_objectives():
    broker = CountingBroker()
    try:
        outcome = BoundedReasoningLoop(model=deception_model([GAP]), broker=broker).run(
            frame=frame(), playbook=GENERIC_PLAYBOOK, cycle_id="cycle-gen-1")
    finally:
        broker.close()
    assert outcome.observation_objectives == ()


def test_invalid_gap_cycle_is_rejected_and_emits_no_objective():
    bad = dict(GAP, discriminates_hypothesis_ids=["h1"], capability="not_allowed_capability")
    outcome, _ = run_deception(gap_items=(bad,))
    assert outcome.state is ReasoningState.VALIDATION_REJECTED
    assert outcome.observation_objectives == ()


def test_projection_adds_no_broker_requests():
    # Registered + allowed capability: the loop makes exactly one broker call for
    # the one eligible gap. The projection must add none, so the call count
    # equals the loop's own capability_request count and no objective needs one.
    broker_calls = []
    outcome, execute_calls = run_deception(capabilities={
        "get_deception_state": CapabilitySpec(handler=lambda args: broker_calls.append(args) or {"rows": 1})})
    assert len(outcome.observation_objectives) == 1
    assert execute_calls == 1
    assert len(broker_calls) == 1
    assert sum(1 for e in outcome.trace if e.kind == "capability_request") == execute_calls


def test_default_outcome_field_keeps_existing_construction_compatible():
    from azazel_mio import ReasoningOutcome
    outcome = ReasoningOutcome(ReasoningState.COMPLETE, (), (), None, (), ())
    assert outcome.observation_objectives == ()


def test_ineligible_gap_is_absent_while_eligible_gap_projects():
    # g1 is registered and allowed (eligible). g2 is allowed by the playbook but not
    # registered, so score_evidence_gaps marks it ineligible and it must not project.
    # query_flow_summary is allowed by deception-observation-v1 but not registered here.
    gaps_items = (GAP, dict(GAP, gap_id="g2", question="Second question", capability="query_flow_summary",
                            discriminates_hypothesis_ids=["h1"], priority=70))
    outcome, _ = run_deception(gap_items=gaps_items)
    eligible = {s["gap_id"] for e in outcome.trace if e.kind == "evidence_gap_scores" for s in e.payload["scores"] if s["eligible"]}
    assert eligible == {"g1"}
    assert [o.source_gap_id for o in outcome.observation_objectives] == ["g1"]
    assert "g2" not in {o.source_gap_id for o in outcome.observation_objectives}


def test_projector_drops_gaps_absent_from_eligible_set_even_when_otherwise_valid():
    hypotheses = (hyp("h1"), hyp("h2"))
    gaps = (
        MioEvidenceGap("g1", "eligible", ("h1",), "get_deception_state", 50),
        MioEvidenceGap("g2", "ineligible", ("h2",), "query_flow_summary", 50),
    )
    out = project_observation_objectives(frame=frame(), playbook_id=OBSERVATION_PLAYBOOK_ID,
                                         state=ReasoningState.COMPLETE, hypotheses=hypotheses, gaps=gaps,
                                         eligible_gap_ids=frozenset({"g1"}))
    assert [o.source_gap_id for o in out] == ["g1"]
    none = project_observation_objectives(frame=frame(), playbook_id=OBSERVATION_PLAYBOOK_ID,
                                          state=ReasoningState.COMPLETE, hypotheses=hypotheses, gaps=gaps,
                                          eligible_gap_ids=())
    assert none == ()


def test_deception_playbook_with_unavailable_status_emits_no_objective():
    # Explicit playbook selection must not bypass the default routing guard:
    # with no deception context, deception_status is not "available".
    f = frame(deception_context=None)
    assert f.deception_status != "available"
    out = project_observation_objectives(frame=f, playbook_id=OBSERVATION_PLAYBOOK_ID,
                                         state=ReasoningState.COMPLETE, hypotheses=(hyp("h1"), hyp("h2")),
                                         gaps=(MioEvidenceGap("g1", "q", ("h1",), "get_deception_state", 50),),
                                         eligible_gap_ids=("g1",))
    assert out == ()


def test_explicit_deception_playbook_without_available_context_emits_nothing_end_to_end():
    outcome, _ = run_deception(frame_obj=frame(deception_context=None))
    assert outcome.observation_objectives == ()


@pytest.mark.parametrize("flag, expected", [("cancel", ReasoningState.OPERATOR_CANCELLED),
                                            ("stale", ReasoningState.STALE_SUPERSEDED)])
def test_cancel_or_stale_flipped_during_recommend_call_emits_no_objective(flag, expected):
    flipped = {"v": False}
    inner = deception_model([GAP])

    def model(task, prompt):
        result = inner(task, prompt)
        if task == "recommend":
            flipped["v"] = True
        return result

    broker = CountingBroker(REGISTERED)
    try:
        outcome = BoundedReasoningLoop(model=model, broker=broker).run(
            frame=frame(), playbook=DECEPTION, cycle_id="cycle-dec-1",
            cancel_check=(lambda: flipped["v"]) if flag == "cancel" else None,
            stale_check=(lambda: flipped["v"]) if flag == "stale" else None)
    finally:
        broker.close()
    assert flipped["v"]
    assert outcome.state is expected
    assert outcome.recommendation is None
    assert outcome.observation_objectives == ()


def test_uninterrupted_eligible_cycle_still_emits_with_checks_installed():
    broker = CountingBroker(REGISTERED)
    try:
        outcome = BoundedReasoningLoop(model=deception_model([GAP]), broker=broker).run(
            frame=frame(), playbook=DECEPTION, cycle_id="cycle-dec-1",
            cancel_check=lambda: False, stale_check=lambda: False)
    finally:
        broker.close()
    assert outcome.state is ReasoningState.COMPLETE
    assert len(outcome.observation_objectives) == 1

import dataclasses

import pytest

from azazel_mio import BoundedReasoningLoop, CapabilityBroker, MioSituationFrame
from azazel_mio.broker import CapabilitySpec
from azazel_mio.contracts import HypothesisStatus, MioEvidenceGap, MioHypothesis, ReasoningState
from azazel_mio.reasoning import ReasoningBudget
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


@pytest.mark.parametrize("status", ["not_provided", "unavailable", "timeout", "malformed"])
def test_deception_playbook_with_any_non_available_status_emits_no_objective(status):
    f = frame(deception_context=None, deception_status=status)
    assert f.deception_status != "available"
    out = project_observation_objectives(frame=f, playbook_id=OBSERVATION_PLAYBOOK_ID,
                                         state=ReasoningState.COMPLETE, hypotheses=(hyp("h1"), hyp("h2")),
                                         gaps=(MioEvidenceGap("g1", "q", ("h1",), "get_deception_state", 50),),
                                         eligible_gap_ids=("g1",))
    assert out == ()


def test_same_inputs_yield_same_objective_id_and_distinct_gaps_differ():
    kwargs = dict(frame=frame(), playbook_id=OBSERVATION_PLAYBOOK_ID, state=ReasoningState.COMPLETE,
                  hypotheses=(hyp("h1"), hyp("h2")),
                  gaps=(MioEvidenceGap("g1", "q", ("h1",), "get_deception_state", 50),
                        MioEvidenceGap("g2", "q", ("h2",), "get_deception_state", 50)),
                  eligible_gap_ids=("g1", "g2"))
    first = project_observation_objectives(**kwargs)
    second = project_observation_objectives(**kwargs)
    assert [o.objective_id for o in first] == [o.objective_id for o in second]
    assert len({o.objective_id for o in first}) == 2


def test_parsed_gap_retains_at_most_first_eight_unique_hypothesis_ids():
    ids = [f"h{i}" for i in range(10)] + ["h0"]
    gap = MioEvidenceGap.from_mapping({"gap_id": "g1", "question": "q", "discriminates_hypothesis_ids": ids,
                                       "capability": "get_deception_state"}, ordinal=1)
    assert gap.discriminates_hypothesis_ids == tuple(f"h{i}" for i in range(8))


def test_scorer_allocates_broker_budget_before_projecting_objectives():
    gaps = [GAP, dict(GAP, gap_id="g2", capability="query_flow_summary",
                      discriminates_hypothesis_ids=["h2"])]
    broker = CountingBroker({
        "get_deception_state": REGISTERED["get_deception_state"],
        "query_flow_summary": CapabilitySpec(handler=lambda args: {"rows": 1}),
    })
    try:
        outcome = BoundedReasoningLoop(
            model=deception_model(gaps), broker=broker,
            budget=ReasoningBudget(max_broker_calls=1),
        ).run(frame=frame(), playbook=DECEPTION, cycle_id="cycle-budget-1")
        assert outcome.state is ReasoningState.COMPLETE
        assert broker.execute_calls == 1
        scored = next(event for event in outcome.trace if event.kind == "evidence_gap_scores")
        assert {item["gap_id"] for item in scored.payload["scores"] if item["eligible"]} == {"g1"}
        assert {item["gap_id"] for item in scored.payload["scores"] if not item["eligible"]} == {"g2"}
        assert {item.source_gap_id for item in outcome.observation_objectives} == {"g1"}
        assert "gap_not_eligible:g2:cycle_broker_budget_exhausted" in outcome.errors
    finally:
        broker.close()


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


# --- Local projection diagnostic (ObservationProjectionReport) -------------------

import dataclasses  # noqa: E402

from azazel_mio.observation_objectives import (  # noqa: E402
    DEFAULT_REPORT_MAX_GAPS,
    MAX_OBJECTIVE_HYPOTHESES,
    ObservationProjectionReport,
    project_observation_report,
)


def _report(*, f=None, playbook_id=OBSERVATION_PLAYBOOK_ID, state=ReasoningState.COMPLETE,
            hypotheses=None, gaps=(), eligible=("g1",), max_gaps=DEFAULT_REPORT_MAX_GAPS):
    hyps = (hyp("h1"), hyp("h2")) if hypotheses is None else hypotheses
    return project_observation_report(frame=f or frame(), playbook_id=playbook_id, state=state,
                                      hypotheses=hyps, gaps=gaps, eligible_gap_ids=eligible,
                                      max_gaps=max_gaps)


G1 = MioEvidenceGap("g1", "q", ("h1",), "get_deception_state", 50)


@pytest.mark.parametrize("state", [s for s in ReasoningState if s is not ReasoningState.COMPLETE])
def test_state_skip_not_complete(state):
    objs, rep = _report(state=state, gaps=(G1,))
    assert objs == () and rep == ObservationProjectionReport(state_skip="not_complete")


def test_state_skip_wrong_playbook():
    objs, rep = _report(playbook_id="generic-evidence-first-v1", gaps=(G1,))
    assert objs == () and rep.state_skip == "wrong_playbook"


@pytest.mark.parametrize("status", ["not_provided", "unavailable", "timeout", "malformed"])
def test_state_skip_deception_unavailable(status):
    objs, rep = _report(f=frame(deception_context=None, deception_status=status), gaps=(G1,))
    assert objs == () and rep.state_skip == "deception_unavailable"


def test_state_skip_invalid_frame_binding():
    bad = dataclasses.replace(frame(), frame_id="bad id with spaces")
    objs, rep = _report(f=bad, gaps=(G1,))
    assert objs == () and rep.state_skip == "invalid_frame_binding"


def test_malformed_inputs_fail_closed_with_state_skip():
    objs, rep = _report(gaps=(G1, "not-a-gap"))
    assert objs == () and rep.state_skip == "malformed_input"
    bad_gap = MioEvidenceGap(["unhashable"], "q", ("h1",), "get_deception_state", 50)
    objs, rep = _report(gaps=(bad_gap,))
    assert objs == () and rep.state_skip == "malformed_input"
    objs, rep = _report(gaps=(G1,), eligible=[["unhashable"]])
    assert objs == () and rep.state_skip == "malformed_input"
    objs, rep = _report(gaps=(G1,), max_gaps=-1)
    assert objs == () and rep.state_skip == "malformed_input"


def test_each_gap_skip_reason_is_reported_in_input_order():
    gaps = (
        MioEvidenceGap("g1", "emit", ("h1",), "get_deception_state", 50),
        MioEvidenceGap("g2", "not eligible", ("h1",), "get_deception_state", 50),
        MioEvidenceGap("bad id!", "invalid", ("h1",), "get_deception_state", 50),
        MioEvidenceGap("g1", "dup", ("h2",), "get_deception_state", 50),
        MioEvidenceGap("g4", "no live", ("hX",), "get_deception_state", 50),
    )
    objs, rep = _report(gaps=gaps, eligible=("g1", "bad id!", "g4"), max_gaps=5)
    assert rep.state_skip is None
    assert rep.gap_outcomes == ("emitted", "not_eligible", "invalid_id", "duplicate_gap", "no_live_hypotheses")
    assert rep.emitted_count == 1 and [o.source_gap_id for o in objs] == ["g1"]
    assert rep.unreported_gap_count == 0 and rep.omitted_hypothesis_count == 0


def test_nine_live_hypotheses_capped_to_eight_with_omitted_count_one():
    live = tuple(hyp(f"h{i}") for i in range(9))
    gap = MioEvidenceGap("g1", "q", tuple(f"h{i}" for i in range(9)), "get_deception_state", 50)
    objs, rep = _report(hypotheses=live, gaps=(gap,), eligible=("g1",))
    assert len(objs) == 1 and len(objs[0].hypothesis_ids) == MAX_OBJECTIVE_HYPOTHESES
    assert objs[0].hypothesis_ids == tuple(f"h{i}" for i in range(8))
    assert rep.emitted_count == 1 and rep.omitted_hypothesis_count == 1
    assert rep.gap_outcomes == ("emitted",)


def test_report_gap_outcomes_are_bounded_to_budget_with_unreported_count():
    gaps = tuple(MioEvidenceGap(f"g{i}", "q", ("h1",), "get_deception_state", 50) for i in range(5))
    objs, rep = _report(gaps=gaps, eligible=tuple(f"g{i}" for i in range(5)), max_gaps=2)
    assert rep.gap_outcomes == ("emitted", "emitted")
    assert rep.unreported_gap_count == 3
    assert rep.emitted_count == 5 and len(objs) == 5  # objectives are never truncated by the report


def test_report_is_deterministic_and_objective_ids_are_stable():
    kwargs = dict(gaps=(G1, MioEvidenceGap("g2", "q", ("h2",), "get_deception_state", 50)),
                  eligible=("g1", "g2"))
    first, rep1 = _report(**kwargs)
    second, rep2 = _report(**kwargs)
    assert rep1 == rep2 and first == second
    assert [o.objective_id for o in first] == [o.objective_id for o in second]


def test_wrapper_objectives_equal_report_objectives():
    kwargs = dict(frame=frame(), playbook_id=OBSERVATION_PLAYBOOK_ID, state=ReasoningState.COMPLETE,
                  hypotheses=(hyp("h1"), hyp("h2")), gaps=(G1,), eligible_gap_ids=("g1",))
    wrapped = project_observation_objectives(**kwargs)
    reported, _ = project_observation_report(**kwargs)
    assert wrapped == reported


def test_silently_dropped_gap_changes_the_report():
    # Regression check: silently dropping an ineligible gap (instead of
    # recording not_eligible) changes the report.
    g2 = MioEvidenceGap("g2", "q", ("h2",), "query_flow_summary", 50)
    _, full = _report(gaps=(G1, g2), eligible=("g1",))
    _, dropped = _report(gaps=(G1,), eligible=("g1",))
    assert full.gap_outcomes == ("emitted", "not_eligible")
    assert dropped.gap_outcomes == ("emitted",)
    assert full != dropped


def test_report_diagnostic_is_fixed_keys_without_raw_identifiers():
    gaps = (G1, MioEvidenceGap("secret-gap-id", "q", ("h1",), "get_deception_state", 50))
    _, rep = _report(gaps=gaps, eligible=("g1", "secret-gap-id"))
    data = rep.to_diagnostic()
    assert set(data) == {"state_skip", "gap_outcomes", "unreported_gap_count", "emitted_count",
                         "omitted_hypothesis_count"}
    text = repr(data)
    assert "g1" not in text and "h1" not in text and "secret-gap-id" not in text


def test_completed_cycle_outcome_carries_projection_diagnostic_matching_objectives():
    outcome, _ = run_deception()
    rep = outcome.observation_projection
    assert rep is not None and rep.state_skip is None
    assert rep.emitted_count == len(outcome.observation_objectives) == 1
    assert rep.gap_outcomes == ("emitted",)


def test_non_complete_outcome_records_state_skip_and_no_objectives():
    outcome, _ = run_deception(gap_items=(dict(GAP, discriminates_hypothesis_ids=["h1"],
                                               capability="not_allowed_capability"),))
    assert outcome.state is ReasoningState.VALIDATION_REJECTED
    assert outcome.observation_objectives == ()
    assert outcome.observation_projection.state_skip == "not_complete"


def test_objective_payload_shape_unchanged_by_report_wiring():
    outcome, _ = run_deception()
    assert set(outcome.observation_objectives[0].to_dict()) == {
        "objective_id", "frame_id", "trace_id", "source_gap_id", "hypothesis_ids", "authority", "executable"}

"""Strict response validation before any lossy contract normalisation."""
from copy import deepcopy

import pytest

from azazel_mio.model_schema import model_response_schema, validate_model_response


def hypothesis(slot):
    return {"hypothesis_id": "h1" if slot == "threat" else "h2",
            "hypothesis_alternative_id": slot, "statement": "possible",
            "status": "proposed", "supporting_evidence_refs": [],
            "contradicting_evidence_refs": [], "assumptions": [],
            "falsification_conditions": ["counterexample"],
            "expected_observations": [], "missing_evidence": []}


def test_strict_schema_rejects_loss_before_normalisation():
    schema = model_response_schema("generate_hypotheses", min_hypotheses=2,
                                   alternative_ids=("threat", "benign"))
    good = {"hypotheses": [hypothesis("threat"), hypothesis("benign")]}
    assert validate_model_response(good, schema)
    variants = []
    bad = deepcopy(good); bad["hypotheses"][0]["statement"] = "a" * 361; variants.append(bad)
    bad = deepcopy(good); bad["hypotheses"][0]["falsification_conditions"] = ["x"] * 9; variants.append(bad)
    bad = deepcopy(good); bad["hypotheses"][0]["unexpected"] = 1; variants.append(bad)
    bad = deepcopy(good); del bad["hypotheses"][0]["status"]; variants.append(bad)
    bad = deepcopy(good); bad["hypotheses"][0]["hypothesis_alternative_id"] = "other"; variants.append(bad)
    bad = deepcopy(good); bad["hypotheses"].append(True); variants.append(bad)
    assert all(not validate_model_response(item, schema) for item in variants)


def test_capability_and_integer_type_are_strict():
    schema = model_response_schema("identify_evidence_gaps", capabilities=("lookup",))
    good = {"evidence_gaps": [{"gap_id": "g1", "question": "Why?",
                               "discriminates_hypothesis_ids": ["h1"],
                               "capability": "lookup", "priority": 1}]}
    assert validate_model_response(good, schema)
    for key, value in (("priority", True), ("priority", float("nan")), ("capability", "other")):
        bad = deepcopy(good); bad["evidence_gaps"][0][key] = value
        assert not validate_model_response(bad, schema)
    assert not validate_model_response(good, model_response_schema("identify_evidence_gaps", capabilities=()))


def test_recommendation_rejects_oversize_tail_and_wrong_types():
    schema = model_response_schema("recommend")
    good = {"summary": "uncertain", "recommended_action": "MONITOR",
            "rationale": "reason", "evidence_refs": ["ev:alert:1"],
            "limitations": ["unverified"]}
    # Use the actual enum and evidence pattern, without presuming their values.
    good["recommended_action"] = schema["properties"]["recommended_action"]["enum"][0]
    assert validate_model_response(good, schema)
    for key, value in (("rationale", "x" * 721), ("limitations", ["x"] * 9),
                       ("evidence_refs", "ev:alert:1")):
        bad = deepcopy(good); bad[key] = value
        assert not validate_model_response(bad, schema)


def test_loop_strict_validation_precedes_slicing_and_stops_later_calls():
    from azazel_mio.broker import CapabilityBroker
    from azazel_mio.contracts import MioSituationFrame, ReasoningState
    from azazel_mio.playbook import select_playbook
    from azazel_mio.reasoning import BoundedReasoningLoop

    frame = MioSituationFrame.build(frame_id="f", trace_id="t", created_at="2026-10-31T00:00:00Z",
        mission="Review repeated authentication failures", current_defensive_state="OBSERVE",
        threat_level="UNKNOWN", evidence_refs=("ev:ssh:1",))
    selected = select_playbook(frame)
    calls = []

    def model(task, prompt):
        calls.append(task)
        first = hypothesis("credential_attack")
        second = hypothesis("misconfigured_automation")
        first["statement"] = "x" * 361
        return {"hypotheses": [first, second]}

    broker = CapabilityBroker()
    try:
        result = BoundedReasoningLoop(model=model, broker=broker).run(
            frame=frame, playbook=selected.playbook, selection=selected, cycle_id="c",
            strict_model_response=True)
    finally:
        broker.close()
    assert calls == ["generate_hypotheses"]
    assert result.state is ReasoningState.VALIDATION_REJECTED
    assert "output_invalid" in result.errors
    assert not result.hypotheses

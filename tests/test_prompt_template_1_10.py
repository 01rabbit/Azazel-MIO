"""Template 1.10.0: minimal no-capability gaps prompt, deduplicated control, minified-output instruction.

Validators, schema derivation and grounding are unchanged; these tests pin what the model sees and what
compiled_model_response_schema still refuses."""
import json

import pytest

from azazel_mio import (GenerationBudget, MioSituationFrame, PromptCompiler, select_playbook)
from azazel_mio.model_schema import model_response_schema
from azazel_mio.playbook import (PROMPT_TEMPLATE_VERSION, TRUSTED_RULES, _task_contract,
                                 compiled_model_response_schema, template_digest)

NOW = "2026-10-31T00:00:00Z"
GEN, GAPS, REC = "generate_hypotheses", "identify_evidence_gaps", "recommend"
BND = "\nEND_TRUSTED_CONTROL\nUNTRUSTED_DATA\n"


def frame():
    return MioSituationFrame.build(frame_id="f-id", trace_id="t-id", created_at=NOW,
        mission="Review activity", current_defensive_state="OBSERVE", threat_level="UNKNOWN",
        known_facts=("event",), unknowns=("unknown",), contradictions=("counterexample",),
        evidence_refs=("ev:ssh:1",), noc_summary="noc report", soc_summary="soc report")


def budget(limit=50000):
    return GenerationBudget(limit, 10, 100000, 5, len)


def compile_(task, **kw):
    f = frame()
    return PromptCompiler().compile(frame=f, playbook=select_playbook(f).playbook, task=task, **kw)


def parts(text):
    end = text.index(BND)
    data = text[end + len(BND):].rsplit("\nEND_UNTRUSTED_DATA", 1)[0]
    return json.loads(text[len("TRUSTED_CONTROL\n"):end]), json.loads(data)


def rebuild(control, data="{}"):
    return ("TRUSTED_CONTROL\n" + json.dumps(control, sort_keys=True, separators=(",", ":"))
            + BND + data + "\nEND_UNTRUSTED_DATA")


# ---- S-1: gaps without capabilities --------------------------------------------------

def test_version_and_digest_move_together():
    assert PROMPT_TEMPLATE_VERSION == "1.10.0"
    assert len(template_digest()) >= 32


@pytest.mark.parametrize("b", [None, budget()])
def test_gaps_minimal_shape_is_still_sent_and_schema_is_unchanged(b):
    out = compile_(GAPS, budget=b) if b else compile_(GAPS)
    text = out if b is None else out.text
    control, data = parts(text)
    assert set(control) == {"effective_read_capabilities", "task", "rules", "output_contract"}
    assert control["rules"] == list(TRUSTED_RULES[:1]) and data == {}
    schema = compiled_model_response_schema(GAPS, text)
    assert schema == model_response_schema(GAPS, capabilities=())
    assert schema["properties"]["evidence_gaps"]["maxItems"] == 0
    assert "ev:ssh:1" not in text and "counterexample" not in text


def test_gaps_minimal_rejects_extra_or_missing_keys_and_data():
    text = compile_(GAPS)
    control, _ = parts(text)
    for key in ("limits", "playbook"):
        with pytest.raises(ValueError):
            compiled_model_response_schema(GAPS, rebuild({**control, key: {}}))
    missing = {k: v for k, v in control.items() if k != "output_contract"}
    with pytest.raises(ValueError):
        compiled_model_response_schema(GAPS, rebuild(missing))
    with pytest.raises(ValueError):
        compiled_model_response_schema(GAPS, rebuild({**control, "rules": list(TRUSTED_RULES)}))
    with pytest.raises(ValueError):
        compiled_model_response_schema(GAPS, rebuild(control, '{"x":1}'))


def test_gaps_form_is_not_accepted_for_other_tasks_and_full_form_not_for_empty_gaps():
    control, _ = parts(compile_(GAPS))
    with pytest.raises(ValueError):
        compiled_model_response_schema(GEN, rebuild({**control, "task": GEN}))
    full = compile_(GEN)
    fcontrol, fdata = parts(full)
    with pytest.raises(ValueError):
        compiled_model_response_schema(GAPS, rebuild({**fcontrol, "task": GAPS}, json.dumps(fdata)))


def test_gaps_minimal_budget_gate_still_applies():
    from azazel_mio import BudgetError
    with pytest.raises(BudgetError, match="budget_exhausted"):
        compile_(GAPS, budget=budget(limit=5))
    with pytest.raises(BudgetError, match="count_unknown"):
        compile_(GAPS, budget=GenerationBudget(50000, 10, 100000, 5, lambda _: None))
    sel = compile_(GAPS, budget=budget()).selection
    assert sel.template_version == "1.10.0" and sel.coverage == "selected"
    assert ("hypotheses", "optional_detail") in sel.dropped


def test_recommend_keeps_validated_hypothesis_handoff():
    from azazel_mio import MioHypothesis
    h = MioHypothesis(hypothesis_id="h1", statement="s", hypothesis_alternative_id="hostile_activity",
                      supporting_evidence_refs=("ev:ssh:1",))
    _, data = parts(compile_(REC, hypotheses=[h], budget=budget(), unknown_mapping={}, hypothesis_unknown_ids={}).text)
    assert data["hypotheses"][0]["hypothesis_id"] == "h1"
    assert data["hypotheses"][0]["supporting_evidence_refs"] == ["ev:ssh:1"]
    assert data["situation_frame"]["prior_report"] == "already_supplied_unverified"


# ---- S-2: deduplicated control and model-view frame ---------------------------------

def test_control_has_no_limits_or_duplicate_prompts_and_old_forms_are_refused():
    text = compile_(GEN)
    control, _ = parts(text)
    assert "limits" not in control and "hypothesis_prompts" not in control["playbook"]
    assert compiled_model_response_schema(GEN, text)["properties"]["hypotheses"]["minItems"] == 2
    with pytest.raises(ValueError):
        compiled_model_response_schema(GEN, rebuild({**control, "limits": {"max_hypotheses": 4}}, "{}"))
    old_playbook = {**control["playbook"], "hypothesis_prompts": ["x"]}
    with pytest.raises(ValueError):
        compiled_model_response_schema(GEN, rebuild({**control, "playbook": old_playbook}, "{}"))


def test_playbook_section_tamper_is_refused():
    control, _ = parts(compile_(GEN))
    for mutate in (lambda pb: pb.update(claim_boundaries=[]),
                   lambda pb: pb.update(stop_conditions="x"),
                   lambda pb: pb["hypothesis_alternatives"][0].update(extra=1),
                   lambda pb: pb.update(unknown_key=[])):
        pb = json.loads(json.dumps(control["playbook"]))
        mutate(pb)
        with pytest.raises(ValueError):
            compiled_model_response_schema(GEN, rebuild({**control, "playbook": pb}, "{}"))


def test_builtin_playbook_is_checked_against_trusted_definition():
    control, _ = parts(compile_(GEN))
    for mutate in (lambda pb: pb["hypothesis_alternatives"][0].update(prompt="tampered"),
                   lambda pb: pb["hypothesis_alternatives"][0].update(role="benign"),
                   lambda pb: pb["hypothesis_alternatives"].reverse(),
                   lambda pb: pb.update(claim_boundaries=["do not assert identity or intent"]),
                   lambda pb: pb.update(purpose="other")):
        pb = json.loads(json.dumps(control["playbook"]))
        mutate(pb)
        with pytest.raises(ValueError):
            compiled_model_response_schema(GEN, rebuild({**control, "playbook": pb}, "{}"))


def _custom_playbook():
    from dataclasses import replace
    from azazel_mio.playbook import GENERIC_PLAYBOOK
    return replace(GENERIC_PLAYBOOK, playbook_id="caller-defined-v1")


def test_caller_defined_playbook_keeps_prompts_and_alternative_tamper_is_refused():
    pb = _custom_playbook()
    text = PromptCompiler().compile(frame=frame(), playbook=pb, task=GEN)
    control, data = parts(text)
    assert control["playbook"]["hypothesis_prompts"] == list(pb.hypothesis_prompts)
    assert compiled_model_response_schema(GEN, text)["properties"]["hypotheses"]["minItems"] == 2
    tampered = json.loads(json.dumps(control["playbook"]))
    tampered["hypothesis_alternatives"][0]["prompt"] = "tampered"
    with pytest.raises(ValueError):
        compiled_model_response_schema(GEN, rebuild({**control, "playbook": tampered}, "{}"))
    dropped = json.loads(json.dumps(control["playbook"]))
    dropped.pop("hypothesis_prompts")
    with pytest.raises(ValueError):  # dropping the copy does not evade the check for a non-built-in playbook
        compiled_model_response_schema(GEN, rebuild({**control, "playbook": dropped}, "{}"))


def test_builtin_id_with_changed_content_keeps_prompts_and_is_self_consistent_only():
    from dataclasses import replace
    from azazel_mio.playbook import GENERIC_PLAYBOOK
    pb = replace(GENERIC_PLAYBOOK, claim_boundaries=("different",))
    control, _ = parts(PromptCompiler().compile(frame=frame(), playbook=pb, task=GEN))
    assert "hypothesis_prompts" in control["playbook"]


def test_generate_frame_drops_only_the_four_identity_keys():
    _, data = parts(compile_(GEN, budget=budget()).text)
    sf = data["situation_frame"]
    full = frame().to_dict()
    assert set(full) - set(sf) == {"frame_id", "trace_id", "created_at", "schema_version"}
    for key in ("noc_summary", "soc_summary", "unknowns", "contradictions", "known_facts", "evidence_refs",
                "knowledge_refs", "knowledge_status", "deception_status", "deception_context", "provenance",
                "freshness_seconds", "truncated", "current_defensive_state", "threat_level", "mission"):
        assert sf[key] == full[key]
    assert data["hypotheses"] == [] and data["broker_results"] == []


def test_old_template_prompt_shape_is_refused():
    control, _ = parts(compile_(GEN))
    old = {**control, "limits": {"max_hypotheses": 4}}
    old["playbook"] = {**control["playbook"], "hypothesis_prompts": [a["prompt"] for a in control["playbook"]["hypothesis_alternatives"]]}
    with pytest.raises(ValueError):
        compiled_model_response_schema(GEN, rebuild(old, "{}"))


def test_rules_and_safety_text_remain_in_non_gaps_prompts():
    for task in (GEN, REC):
        control, _ = parts(compile_(task))
        assert control["rules"] == list(TRUSTED_RULES)
        assert control["playbook"]["claim_boundaries"]


# ---- S-3: minified-output instruction -------------------------------------------------

@pytest.mark.parametrize("task", [GEN, GAPS, REC])
def test_contract_carries_minified_instruction_and_schema_is_untouched(task):
    control, _ = parts(compile_(task))
    assert control["output_contract"].endswith("Output minified JSON on one line with no spaces or line breaks.")
    schema = model_response_schema(task, capabilities=()) if task != GEN else model_response_schema(
        task, capabilities=(), min_hypotheses=2, alternative_ids=("hostile_activity", "benign_activity", "insufficient_evidence"))
    assert "minified" not in json.dumps(schema)
    assert _task_contract(task, schema) == control["output_contract"]


def test_contract_text_tamper_is_refused():
    text = compile_(GEN)
    control, data = parts(text)
    control["output_contract"] = control["output_contract"].replace(" Output minified JSON on one line with no spaces or line breaks.", "")
    with pytest.raises(ValueError):
        compiled_model_response_schema(GEN, rebuild(control, json.dumps(data, sort_keys=True, separators=(",", ":"))))


def test_gaps_minimal_keeps_truncated_frame_and_unit_count_refusals():
    from azazel_mio import BudgetError
    f = MioSituationFrame.build(frame_id="f-id", trace_id="t-id", created_at=NOW, mission="m",
        current_defensive_state="OBSERVE", threat_level="UNKNOWN", known_facts=("e",), unknowns=("u",),
        contradictions=(), evidence_refs=("ev:ssh:1",), input_truncated=True)
    pb = select_playbook(f).playbook
    for task in (GEN, GAPS, REC):
        with pytest.raises(BudgetError) as exc:
            PromptCompiler().compile(frame=f, playbook=pb, task=task, budget=budget())
        assert exc.value.reason == "count_unknown"  # same result for every task, gaps minimal form included
    many = [{"kind": "supplemental_reference", "evidence_refs": ["ev:ssh:%d" % i]} for i in range(33)]
    with pytest.raises(BudgetError, match="budget_exhausted"):
        compile_(GAPS, budget=budget(), broker_results=many)
    with pytest.raises(BudgetError, match="budget_exhausted"):
        compile_(GEN, budget=budget(), broker_results=many)


def test_template_digest_reflects_model_view_structure():
    import azazel_mio.playbook as pbm
    before = template_digest()
    original = pbm._MODEL_FRAME_OMITTED
    try:
        pbm._MODEL_FRAME_OMITTED = original[:-1]
        assert template_digest() != before
    finally:
        pbm._MODEL_FRAME_OMITTED = original
    assert template_digest() == before

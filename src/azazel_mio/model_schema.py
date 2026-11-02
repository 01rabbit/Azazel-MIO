"""Pure structured-output schemas; semantic validation remains mandatory.

These schemas describe bounded, uncoerced model replies. They do not authenticate
references, capabilities or lifecycle transitions. Products must pass replies
unchanged through the core's grounding, claim and lifecycle validators.
"""
from .contracts import DEFENSIVE_STATES, HypothesisStatus, model_id_ok
from .id_grammar import EVIDENCE_REF_KINDS
from .lifecycle import ENTRY_HYPOTHESIS_STATUSES
import re


def _text(size, *, nonempty=False, nonblank=False):
    result = {"type": "string", "maxLength": size}
    if nonempty or nonblank:
        result["minLength"] = 1
    if nonblank:
        result["pattern"] = r"\S"
    return result


def _array(item, cap):
    return {"type": "array", "items": item, "maxItems": cap}


def _object(properties):
    return {"type": "object", "properties": properties,
            "required": list(properties), "additionalProperties": False}


def model_response_schema(task: str, *, capabilities: tuple[str, ...] | None = None,
                          min_hypotheses: int = 1,
                          alternative_ids: tuple[str, ...] | None = None) -> dict:
    """Return a fresh JSON Schema for a core task; reject unknown tasks.

    Identifier patterns encode the first grammar layer. Core validation also
    applies the address/secret-shape layer and checks supplied reference sets.
    """
    if type(min_hypotheses) is not int or not 1 <= min_hypotheses <= 4:
        raise ValueError("invalid_schema_min_hypotheses")
    if alternative_ids is not None and (type(alternative_ids) is not tuple or len(alternative_ids) > 8
            or any(type(value) is not str or not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", value)
                   for value in alternative_ids)
            or len(set(alternative_ids)) != len(alternative_ids)):
        raise ValueError("invalid_schema_alternative_ids")
    if capabilities is not None and (type(capabilities) is not tuple or len(capabilities) > 32
            or any(not model_id_ok(value, "capability") for value in capabilities)
            or len(set(capabilities)) != len(capabilities)):
        raise ValueError("invalid_schema_capabilities")
    # Provider response shapes include supplied knowledge, but not offline
    # fixture refs accepted by contracts.MODEL_ID_GRAMMAR["evidence_ref"].
    # Matching a shape still grants no authority to cite an unsupplied ref.
    ref = {"type": "string", "maxLength": 128, "pattern":
           r"^(?:sha256:[0-9a-f]{64}|ev:(?:" + "|".join(EVIDENCE_REF_KINDS) +
           r"):[0-9]{1,6}|suricata_sid:[0-9]{1,8}|kn:attack:T[0-9]{4}(?:\.[0-9]{3})?)$"}
    hypothesis_id = {"type": "string", "pattern": r"^h[0-9]{1,3}$"}
    alternative_id = {"type": "string", "pattern": r"^[a-z][a-z0-9_]{2,63}$"}
    if alternative_ids is not None:
        alternative_id["enum"] = list(alternative_ids)
    hypothesis = _object({
        "hypothesis_id": hypothesis_id, "statement": _text(360, nonempty=True),
        **({"hypothesis_alternative_id": alternative_id} if task in ("generate_hypotheses", "update_hypotheses") else {}),
        "status": {"type": "string", "enum": sorted(s.value for s in (ENTRY_HYPOTHESIS_STATUSES if task == "generate_hypotheses" else HypothesisStatus))},
        "supporting_evidence_refs": _array(ref, 16),
        "contradicting_evidence_refs": _array(ref, 16),
        **{key: _array(_text(160), 8) for key in (
            "assumptions", "falsification_conditions", "expected_observations", "missing_evidence")},
    })
    if task in ("generate_hypotheses", "update_hypotheses"):
        hypotheses = _array(hypothesis, 4)
        hypotheses["minItems"] = min_hypotheses if task == "generate_hypotheses" else 1
        properties = {"hypotheses": hypotheses}
        if task == "update_hypotheses":
            # Existing prompt asks for this diagnostic field; it is not used
            # as evidence or exposed as an accepted hypothesis.
            properties["revision_summary"] = _text(360)
        return _object(properties)
    if task == "identify_evidence_gaps":
        capability = {"type": "string", "pattern": r"^[a-z][a-z0-9_]{2,63}$"}
        if capabilities:
            capability["enum"] = list(capabilities)
        gaps = _array(_object({
            "gap_id": {"type": "string", "pattern": r"^g[0-9]{1,3}$"},
            "question": _text(300, nonempty=True), "discriminates_hypothesis_ids": _array(hypothesis_id, 8),
            "capability": capability,
            "priority": {"type": "integer", "minimum": 0, "maximum": 100},
        }), 3)
        if capabilities == ():
            gaps["maxItems"] = 0
        return _object({"evidence_gaps": gaps})
    if task == "recommend":
        return _object({"summary": _text(360, nonblank=True), "recommended_action": {
            "type": "string", "enum": sorted(DEFENSIVE_STATES)},
            "rationale": _text(720, nonblank=True), "evidence_refs": {**_array(ref, 32), "minItems": 1},
            "limitations": _array(_text(160), 8)})
    raise ValueError("unsupported_model_task")

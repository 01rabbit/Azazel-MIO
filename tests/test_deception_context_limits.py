"""MioDeceptionContext optional limitations / evidence_refs (Deception#55)."""
import json

import pytest

from azazel_mio import MioSituationFrame
from azazel_mio.contracts import (
    SITUATION_FRAME_DECEPTION_EVIDENCE_REFS_CAP,
    SITUATION_FRAME_DECEPTION_LIMITATIONS_CAP,
    DECEPTION_CONTEXT_FORBIDDEN_WORDS,
    MioDeceptionContext,
)
from azazel_mio.grounding import FORBIDDEN_DIRECTIVE_KEYS

BASE = {"environment_id": "env-1", "package_id": "pkg-1", "node_id": "node-1",
        "lifecycle_state": "active", "observation_refs": ["obs-1"]}


def ctx(**extra):
    return MioDeceptionContext.coerce({**BASE, **extra})


def frame(context):
    return MioSituationFrame.build(
        frame_id="frame-1", trace_id="trace-1", created_at="2026-11-03T00:00:00Z",
        mission="m", current_defensive_state="OBSERVE", threat_level="LOW",
        known_facts=("A",), unknowns=("U",), deception_status="available",
        deception_context=context, provenance={"deception_context": ["deception"]})


def test_legacy_mapping_unchanged():
    c = ctx()
    assert c is not None and c.limitations == () and c.evidence_refs == ()
    assert set(c.to_dict()) == set(BASE)  # no new keys emitted


def test_accepts_bounded_fields_and_dedupes():
    c = ctx(limitations=["no_interaction_observed_is_not_evidence_of_safety", "stale", "stale"],
            evidence_refs=["objective:abc-1", "decision.d1", "session_9"])
    assert c.limitations == ("no_interaction_observed_is_not_evidence_of_safety", "stale")
    assert c.evidence_refs == ("objective:abc-1", "decision.d1", "session_9")
    assert MioDeceptionContext.coerce(c.to_dict()) == c


def test_limit_exact_cap_ok_and_over_cap_rejected():
    assert ctx(limitations=[f"lim_{chr(97 + i // 26)}{chr(97 + i % 26)}" for i in range(SITUATION_FRAME_DECEPTION_LIMITATIONS_CAP)]) is not None
    assert ctx(limitations=[f"lim_{chr(97 + i // 26)}{chr(97 + i % 26)}" for i in range(SITUATION_FRAME_DECEPTION_LIMITATIONS_CAP + 1)]) is None
    assert ctx(evidence_refs=[f"ref-{i}" for i in range(SITUATION_FRAME_DECEPTION_EVIDENCE_REFS_CAP + 1)]) is None


@pytest.mark.parametrize("bad", [
    "activate", "authorized", "limit_authorized_by_operator", "run_the_playbook", "execute_now",
    "Has_Upper", "has space", "x", "has-dash", "ignore_previous_instructions", "rm -rf /",
    "api_key_missing", "10_0_0_1", 5, None, "", "line\nbreak", "a" * 65,
])
def test_limitations_reject(bad):
    assert ctx(limitations=[bad]) is None


@pytest.mark.parametrize("bad", [
    "execute:now", "authorized-ref", "sudo.thing", "10.0.0.1", "ref with space", "bearer-abc", 7, "",
    "https://x/y", "ref\n1",
])
def test_evidence_refs_reject(bad):
    assert ctx(evidence_refs=[bad]) is None


@pytest.mark.parametrize("bad", ["stale", {"a": 1}, 3])
def test_non_sequence_rejected(bad):
    assert ctx(limitations=bad) is None
    assert ctx(evidence_refs=bad) is None


def test_forbidden_words_cover_grounding_directives():
    assert {w for k in FORBIDDEN_DIRECTIVE_KEYS for w in k.split('_')} <= DECEPTION_CONTEXT_FORBIDDEN_WORDS
    assert "safety" not in DECEPTION_CONTEXT_FORBIDDEN_WORDS


def test_frame_roundtrip_limitations_not_promoted():
    c = ctx(limitations=["telemetry_gap_dns"], evidence_refs=["objective:o1"])
    f = frame(c)
    assert f.deception_context == c
    assert "telemetry_gap_dns" not in f.known_facts and "objective:o1" not in f.known_facts
    d = json.loads(f.to_canonical_json())
    assert d["deception_context"]["limitations"] == ["telemetry_gap_dns"]
    assert MioSituationFrame.from_dict(d) == f


def test_frame_without_extras_serializes_as_before():
    d = json.loads(frame(ctx()).to_canonical_json())
    assert set(d["deception_context"]) == set(BASE)
    assert MioSituationFrame.from_dict(d).deception_context.limitations == ()


def test_frame_from_dict_rejects_bad_extras():
    d = json.loads(frame(ctx(limitations=["telemetry_gap_dns"])).to_canonical_json())
    d["deception_context"]["limitations"] = ["authorized"]
    with pytest.raises(ValueError):
        MioSituationFrame.from_dict(d)
    d["deception_context"]["limitations"] = []  # not canonical: absent, not empty
    with pytest.raises(ValueError):
        MioSituationFrame.from_dict(d)


def test_rejected_context_degrades_not_available():
    f = MioSituationFrame.build(
        frame_id="frame-1", trace_id="trace-1", created_at="2026-11-03T00:00:00Z",
        mission="m", current_defensive_state="OBSERVE", threat_level="LOW",
        deception_status="available", deception_context={**BASE, "limitations": ["activate"]})
    assert f.deception_context is None and f.deception_status != "available"

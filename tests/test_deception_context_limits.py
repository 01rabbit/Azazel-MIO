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
            evidence_refs=["objective:abc-1", "decision:d.1", "session:s_9"])
    assert c.limitations == ("no_interaction_observed_is_not_evidence_of_safety", "stale")
    assert c.evidence_refs == ("objective:abc-1", "decision:d.1", "session:s_9")
    assert MioDeceptionContext.coerce(c.to_dict()) == c


C2_TOKENS = """objective_content_not_bound
objective_trace_differs_from_effect_trace
objective_not_supplied
desired_observations_not_hypothesis_specific
desired_observations_not_specified
no_interaction_observed_is_not_evidence_of_safety
telemetry_gap:http_access_log
stale
lease_expired
runtime_active_after_lease_end
redirection_does_not_imply_diversion
isolation_drift_observed
isolation_not_asserted
interactions_truncated
unbound_interactions_excluded:3
interactions_outside_lease:2
runtime_state_not_independently_reverified
session_ended_new_observations_belong_to_a_new_session
presented_terrain_not_projected""".split()


def test_all_deception_c2_tokens_pass():
    c = ctx(limitations=C2_TOKENS)
    assert c.limitations == tuple(C2_TOKENS)


def test_evidence_refs_deception_forms_pass():
    refs = ["advisory:mio-hypothesis-f1~h1", "advisory:mio-objective-digest-" + "ab12" * 8,
            "hypothesis:h1", "frame:frame-1", "decision:d_1", "session:s.9"]
    assert ctx(evidence_refs=refs).evidence_refs == tuple(refs)


def test_over_cap_entries_dropped_not_context():
    many = [f"lim_{chr(97 + i // 26)}{chr(97 + i % 26)}" for i in range(SITUATION_FRAME_DECEPTION_LIMITATIONS_CAP + 3)]
    c, dropped = MioDeceptionContext.coerce_with_drops({**BASE, "limitations": many})
    assert len(c.limitations) == SITUATION_FRAME_DECEPTION_LIMITATIONS_CAP and dropped
    c, dropped = MioDeceptionContext.coerce_with_drops({**BASE, "evidence_refs": [f"ref:x{i}" for i in range(SITUATION_FRAME_DECEPTION_EVIDENCE_REFS_CAP + 1)]})
    assert len(c.evidence_refs) == SITUATION_FRAME_DECEPTION_EVIDENCE_REFS_CAP and dropped


@pytest.mark.parametrize("bad", [
    "activate", "authorized", "limit_authorized_by_operator", "run_the_playbook", "execute_now",
    "Has_Upper", "has space", "x", "has-dash", "rm -rf /",
    "api_key_missing", "10_0_0_1", 5, None, "", "line\nbreak", "a" * 65, "stale:" , "stale:a b",
    "stop:now", "gap:redirect",
])
def test_limitations_item_dropped_context_kept(bad):
    c, dropped = MioDeceptionContext.coerce_with_drops({**BASE, "limitations": ["stale", bad]})
    if bad is None:
        return
    assert c is not None and c.limitations == ("stale",) and dropped


@pytest.mark.parametrize("bad", [
    "execute:now", "advisory:run-now", "frame:authorized-x", "sudo.thing:x", "ref:10.0.0.1", "ref with space",
    "bearer:abc", 7, "", "noprefix", "https://x/y", "ref:1\nx", "Upper:x",
])
def test_evidence_refs_item_dropped_context_kept(bad):
    c, dropped = MioDeceptionContext.coerce_with_drops({**BASE, "evidence_refs": ["frame:f1", bad]})
    assert c is not None and c.evidence_refs == ("frame:f1",) and dropped


@pytest.mark.parametrize("bad", ["stale", {"a": 1}, 3])
def test_non_sequence_dropped(bad):
    c, dropped = MioDeceptionContext.coerce_with_drops({**BASE, "limitations": bad, "evidence_refs": bad})
    assert c is not None and c.limitations == () and c.evidence_refs == () and dropped


def test_forbidden_words_are_c3():
    assert len(DECEPTION_CONTEXT_FORBIDDEN_WORDS) == 30
    for word in ("redirection", "isolation", "active", "safety", "runtime"):
        assert word not in DECEPTION_CONTEXT_FORBIDDEN_WORDS


def test_dropped_entry_sets_unknown_marker():
    f = frame({**BASE, "limitations": ["stale", "activate"]})
    assert f.deception_context.limitations == ("stale",)
    assert "DECEPTION_CONTEXT_ENTRY_DROPPED" in f.unknowns and f.deception_status == "available"
    clean = frame({**BASE, "limitations": ["stale"]})
    assert "DECEPTION_CONTEXT_ENTRY_DROPPED" not in clean.unknowns


def test_limitations_trimmed_after_known_facts():
    from azazel_mio.contracts import MioSituationFrame as F
    big = {**BASE, "limitations": [f"lim_{chr(97 + i // 26)}{chr(97 + i % 26)}" for i in range(32)]}
    f = F.build(frame_id="frame-1", trace_id="trace-1", created_at="2026-11-03T00:00:00Z", mission="m",
                current_defensive_state="OBSERVE", threat_level="LOW", deception_status="available", deception_context=big,
                known_facts=[f"FACT_{i}_" + "x" * 140 for i in range(16)], evidence_refs=[f"ev:auth:{i}" for i in range(32)],
                noc_summary="n" * 480, soc_summary="s" * 480)
    assert f.truncated or len(f.to_canonical_json()) <= 16384
    if len(f.deception_context.limitations) < 32:
        assert f.known_facts == ()


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

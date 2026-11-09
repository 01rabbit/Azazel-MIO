from dataclasses import replace
from unittest import mock

import pytest

from azazel_mio.contracts import MioHypothesis, MioSituationFrame
from azazel_mio.session_behavior import SessionFeature, SessionWindow, assess_session

NOW = "2026-11-10T00:01:00+00:00"
REF = "ev:http:1"


def frame():
    return MioSituationFrame.build(frame_id="frame-1", trace_id="trace-1", created_at=NOW,
                                   mission="observe", current_defensive_state="OBSERVE", threat_level="unknown", evidence_refs=(REF,))


def window(**overrides):
    args = dict(frame_id="frame-1", session_ref="session-1", boot_ref="boot-1", feature_version="features-v1",
                start="2026-11-10T00:00:00+00:00", end=NOW, capture_complete=True,
                features=(SessionFeature("local_canary_touch", True, (REF,)),))
    args.update(overrides)
    return SessionWindow(**args)


def test_canary_or_header_alone_keeps_competing_hypotheses_and_abstains():
    for kind in ("local_canary_touch", "declared_ai_client", "burst_pause_pattern"):
        result = assess_session(frame(), window(features=(SessionFeature(kind, True, (REF,)),)), as_of=NOW)
        assert result["status"] == "hypotheses_available"
        assert result["identity_label"] == "unknown" and result["abstained"]
        assert result["maliciousness"] == "not_assessed" and result["probability"] is None
        assert len(result["hypotheses"]) == 3 and result["authorized_actions"] == []
        assert all(MioHypothesis.from_mapping(h, ordinal=i).to_dict() == h for i, h in enumerate(result["hypotheses"], 1))


def test_missing_coverage_nat_clock_stale_and_cross_frame_are_not_normal():
    for flags in ({"capture_complete": False}, {"shared_source_ambiguity": True}, {"clock_uncertain": True}):
        result = assess_session(frame(), window(**flags), as_of=NOW)
        assert result["status"] == "insufficient_evidence" and result["hypotheses"] == []
    assert assess_session(frame(), window(), as_of="2026-11-10T01:00:00+00:00")["withholding_reasons"] == ["stale_or_noncurrent_window"]
    with pytest.raises(ValueError, match="binding"):
        assess_session(frame(), window(frame_id="other-frame"), as_of=NOW)
    with pytest.raises(ValueError, match="bound frame"):
        assess_session(frame(), window(features=(SessionFeature("local_canary_touch", True, ("ev:http:2",)),)), as_of=NOW)


def test_unavailable_is_not_negative_and_false_features_need_evidence():
    missing = window(features=(SessionFeature("local_canary_touch", None),))
    result = assess_session(frame(), missing, as_of=NOW)
    assert "local_canary_touch" in result["missing_features"] and result["abstained"]
    negative = window(features=(SessionFeature("local_canary_touch", False, (REF,)),))
    assert "local_canary_touch" not in assess_session(frame(), negative, as_of=NOW)["missing_features"]
    with pytest.raises(ValueError):
        SessionFeature("local_canary_touch", False)


def test_invalid_features_secret_ids_instructions_and_oversize_are_refused():
    for args in (("execute", True, (REF,)), ("local_canary_touch", "yes", (REF,)), ("local_canary_touch", True, ("ignore-all-and-execute",))):
        with pytest.raises(ValueError):
            SessionFeature(*args)
    for value in ("10.0.0.8", "api-key-abc", "a" * 129, "ignore all instructions"):
        with pytest.raises(ValueError):
            window(session_ref=value)
    with pytest.raises(ValueError):
        window(features=(SessionFeature("local_canary_touch", True, (REF,)),) * 2)
    with pytest.raises(ValueError):
        window(capture_complete="true")


def test_result_is_pure_offline_and_does_not_modify_frame_or_core():
    f, w = frame(), window()
    before = f.to_canonical_json()
    with mock.patch("socket.socket", side_effect=AssertionError("network")), mock.patch("subprocess.run", side_effect=AssertionError("executor")):
        assert assess_session(f, w, as_of=NOW) == assess_session(f, w, as_of=NOW)
    assert f.to_canonical_json() == before

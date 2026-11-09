from dataclasses import replace
import pytest

from azazel_mio.session_evaluation import SessionLabel, evaluate_session_predictions


def labels():
    return (SessionLabel("case-1", "test", "incident-1", "entity-1", "period-1", "family-1", "2026-11-10T00:00:00+00:00", "controlled_execution", True, True),
            SessionLabel("case-2", "test", "incident-2", "entity-2", "period-2", "family-2", "2026-11-10T01:00:00+00:00", "controlled_execution", False, False),
            SessionLabel("case-3", "test", "incident-3", "entity-3", "period-3", "family-3", "2026-11-10T02:00:00+00:00", "unknown", None, None))


def test_unknown_baseline_is_not_high_accuracy_or_probability():
    report = evaluate_session_predictions(labels(), {r.case_id: None for r in labels()}, candidate_version="baseline-v1")
    result = report["cohorts"]["test"]
    assert result["coverage"] == 0 and result["precision"] is None
    assert result["positive_abstained"] == 1 and result["unknown_truth"] == 1
    assert result["gate"] == "no_identification_claim"
    assert not report["automatic_promotion"] and not report["real_world_holdout_verified"]


def test_bad_detector_fails_and_unknown_truth_is_not_a_negative():
    result = evaluate_session_predictions(labels(), {r.case_id: True for r in labels()}, candidate_version="bad-v1")["cohorts"]["test"]
    assert result["tp"] == 1 and result["fp"] == 1
    assert result["gate"] == "false_positive_limit_failed" and result["precision"] == .5
    assert result["negative_truth"] == 1


def test_leaky_groups_teacher_truth_and_temporal_overlap_are_rejected():
    rows = labels()
    for field in ("incident_group", "entity_group", "time_group", "content_family"):
        altered = replace(rows[1], split="train", **{field: getattr(rows[0], field)})
        with pytest.raises(ValueError, match="leakage"):
            evaluate_session_predictions((rows[0], altered), {}, candidate_version="baseline-v1")
    with pytest.raises(ValueError, match="temporal"):
        evaluate_session_predictions((replace(rows[0], split="test"), replace(rows[1], split="train")), {}, candidate_version="baseline-v1")
    with pytest.raises(ValueError, match="ground truth"):
        evaluate_session_predictions((replace(rows[0], ground_truth_basis="teacher_label"),), {}, candidate_version="baseline-v1")


def test_missing_and_non_boolean_predictions_cannot_be_scored_as_verdicts():
    result = evaluate_session_predictions(labels(), {}, candidate_version="baseline-v1")["cohorts"]["test"]
    assert result["missing_predictions"] == 3 and result["gate"] == "no_identification_claim"
    with pytest.raises(ValueError, match="stand in"):
        evaluate_session_predictions(labels(), {"case-1": "compatible_patterns"}, candidate_version="baseline-v1")
    with pytest.raises(ValueError):
        evaluate_session_predictions(labels(), {"unknown-case": True}, candidate_version="baseline-v1")

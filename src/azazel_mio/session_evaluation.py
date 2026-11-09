"""Task-specific offline identification metrics (#58), no training or promotion.

Reuses the existing canonical digest/time utilities. Dataset curation and the
full learning pipeline remain with learning_data/learning_offline/Knowledge.
These metrics cannot turn hypotheses or teacher labels into ground truth.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .id_grammar import second_layer_ok
from .learning_data import digest, instant


@dataclass(frozen=True)
class SessionLabel:
    case_id: str
    split: str
    incident_group: str
    entity_group: str
    time_group: str
    content_family: str
    observed_at: str
    ground_truth_basis: str
    ai_assisted: bool | None
    malicious: bool | None


def evaluate_session_predictions(labels: tuple[SessionLabel, ...], predictions: Mapping[str, bool | None],
                                 *, candidate_version: str, max_false_positive_rate: float = .05) -> dict:
    if type(labels) is not tuple or len(labels) > 2048 or not isinstance(predictions, Mapping):
        raise ValueError("invalid bounded session corpus")
    if type(candidate_version) is not str or not second_layer_ok(candidate_version):
        raise ValueError("invalid candidate version")
    if type(max_false_positive_rate) not in (int, float) or not 0 <= max_false_positive_rate <= 1:
        raise ValueError("invalid evaluation threshold")
    ids = set()
    groups = {}
    times: dict[str, list] = {}
    for row in labels:
        if type(row) is not SessionLabel:
            raise ValueError("invalid session label")
        for name in ("case_id", "incident_group", "entity_group", "time_group", "content_family"):
            value = getattr(row, name)
            if type(value) is not str or not second_layer_ok(value):
                raise ValueError("invalid bounded corpus group")
        if row.case_id in ids or row.split not in ("train", "validation", "test", "replay_eval"):
            raise ValueError("duplicate case or invalid split")
        ids.add(row.case_id)
        if row.ground_truth_basis not in ("controlled_execution", "independent_review", "unknown"):
            raise ValueError("model/teacher labels are not ground truth")
        if row.ground_truth_basis == "unknown" and (row.ai_assisted is not None or row.malicious is not None):
            raise ValueError("unknown provenance cannot provide a truth label")
        if any(v is not None and type(v) is not bool for v in (row.ai_assisted, row.malicious)):
            raise ValueError("labels require bool or explicit unknown")
        when = instant(row.observed_at)
        times.setdefault(row.split, []).append(when)
        for name in ("incident_group", "entity_group", "time_group", "content_family"):
            key = (name, getattr(row, name))
            if key in groups and groups[key] != row.split:
                raise ValueError("cross-split group leakage")
            groups[key] = row.split
    for before, after in (("train", "validation"), ("validation", "test"), ("train", "test")):
        if times.get(before) and times.get(after) and max(times[before]) >= min(times[after]):
            raise ValueError("temporal split leakage")
    if any(key not in ids for key in predictions) or len(predictions) > len(labels):
        raise ValueError("unknown predicted case")
    if any(value is not None and type(value) is not bool for value in predictions.values()):
        raise ValueError("hypotheses/scores cannot stand in for identity decisions")
    cohorts = {}
    for split in ("train", "validation", "test", "replay_eval"):
        rows = [r for r in labels if r.split == split]
        if not rows:
            continue
        tp = fp = fn = tn = abstained = positive_abstained = unknown = missing = 0
        for row in rows:
            prediction = predictions.get(row.case_id)
            missing += row.case_id not in predictions
            if row.ai_assisted is None:
                unknown += 1
                continue
            if prediction is None:
                abstained += 1
                positive_abstained += row.ai_assisted is True
                continue
            tp += row.ai_assisted is True and prediction is True
            fp += row.ai_assisted is False and prediction is True
            fn += row.ai_assisted is True and prediction is False
            tn += row.ai_assisted is False and prediction is False
        known = len(rows) - unknown
        positives = sum(r.ai_assisted is True for r in rows)
        negatives = sum(r.ai_assisted is False for r in rows)
        def ratio(n, d):
            return n / d if d else None
        fpr = ratio(fp, negatives)
        coverage = ratio(known - abstained, known)
        gate = "no_identification_claim" if not coverage or missing else "metrics_only_requires_independent_holdout_review"
        if fpr is not None and fpr > max_false_positive_rate:
            gate = "false_positive_limit_failed"
        cohorts[split] = {"cases": len(rows), "labeled_ai_axis": known, "unknown_truth": unknown,
                          "positive_truth": positives, "negative_truth": negatives,
                          "missing_predictions": missing, "abstained_labeled": abstained, "positive_abstained": positive_abstained,
                          "tp": tp, "fp": fp, "fn_on_covered": fn, "tn": tn,
                          "precision": ratio(tp, tp + fp), "recall_all_labeled_positives": ratio(tp, positives),
                          "false_positive_rate_all_labeled_negatives": fpr, "coverage": coverage,
                          "gate": gate}
    return {"schema_version": "session-identification-evaluation/v1", "candidate_version": candidate_version,
            "dataset_sha256": digest([r.__dict__ for r in labels]), "prediction_sha256": digest(dict(predictions)),
            "max_false_positive_rate": max_false_positive_rate, "cohorts": cohorts,
            "automatic_promotion": False, "real_world_holdout_verified": False,
            "calibration": "not_estimated_no_probabilities",
            "limitations": ["AI-assistance labels and maliciousness labels are separate axes.",
                            "Unknown and mixed actors are not forced into negative truth.",
                            "Reported controlled/reviewer provenance is not authenticated here.",
                            "Synthetic and replay-only evidence cannot prove identification or defensive benefit.",
                            "Abstention is not a negative verdict; all-positive recall includes abstention cost."]}

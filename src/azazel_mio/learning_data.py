"""Bounded internal offline learning records; not a Fabric/Knowledge wire API."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

from .contracts import MioSituationFrame, model_id_ok
from .id_grammar import opaque_id
from .playbook import DEFAULT_PLAYBOOKS, GENERIC_PLAYBOOK_ID

FEATURE_VERSION = "mio-playbook-features.v1"
LABEL_VERSION = "mio-playbook-labels.v1"
LABELS = tuple(sorted((*DEFAULT_PLAYBOOKS, GENERIC_PLAYBOOK_ID)))
ORIGINS = ("frame.mission", "frame.noc_summary", "frame.soc_summary", "frame.deception_status")
_CODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def parse_json(text: str):
    """No duplicate-key or nonfinite-number reinterpretation at local CLI boundaries."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError("duplicate_learning_json_key")
            result[key] = value
        return result
    def invalid(value):
        raise ValueError("nonfinite_learning_json_number")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid)


def instant(value: str) -> datetime:
    if type(value) is not str or len(value) > 64:
        raise ValueError("invalid_learning_time")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("invalid_learning_time") from None
    if result.tzinfo is None:
        raise ValueError("invalid_learning_time")
    return result.astimezone(timezone.utc)


def codes(values: Any, cap=16) -> tuple[str, ...]:
    if type(values) not in (tuple, list) or len(values) > cap or any(type(x) is not str or not _CODE.fullmatch(x) for x in values):
        raise ValueError("invalid_learning_codes")
    return tuple(values)


def refs(values: Any) -> tuple[str, ...]:
    if type(values) not in (tuple, list) or len(values) > 32 or any(not model_id_ok(x, "evidence_ref") for x in values):
        raise ValueError("invalid_learning_refs")
    return tuple(values)


@dataclass(frozen=True)
class SnapshotLineage:
    source: str
    snapshot: str
    generation: str
    as_of: str
    expires_at: str
    rights: str
    rights_reference: str
    feature_version: str
    label_version: str
    lineage: tuple[str, ...]
    quality: str = "verified"


@dataclass(frozen=True)
class TeacherCandidate:
    model_version: str
    prompt_version: str
    knowledge_snapshot: str
    candidate_label: str
    # Deliberately no confidence, hidden reasoning, or ground-truth field.


@dataclass(frozen=True)
class ReviewerDisposition:
    reviewer: str
    disposition: str  # accepted|corrected|held
    basis: str  # direct_facts|independent_outcome|teacher_only
    label: str
    reviewed_at: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class ObservedOutcome:
    observation: str
    observed_at: str
    fact_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    expected_playbook: str
    # Defaults preserve construction compatibility only; these values are
    # deliberately unbound and fail quarantine/consumption checks.
    example_id: str = "unbound-example"
    frame_digest: str = "sha256:" + "0" * 64
    practice_record_ref: str = "unbound-practice"
    frame_evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class LearningExample:
    example_id: str
    frame: MioSituationFrame
    decision_at: str
    features_as_of: str
    incident_group: str | None
    entity_group: str | None
    time_group: str | None  # UTC date, never generated for missing timestamps
    source_kind: str  # curated_observation|synthetic_fixture|public_replay
    snapshot: SnapshotLineage
    direct_fact_codes: tuple[str, ...]
    direct_evidence_refs: tuple[str, ...]
    feature_origins: tuple[str, ...] = ORIGINS
    teacher: TeacherCandidate | None = None
    reviewer: ReviewerDisposition | None = None
    outcome: ObservedOutcome | None = None

    def to_dict(self) -> dict:
        result = asdict(self)
        result["frame"] = self.frame.to_dict()
        return json.loads(canonical(result))

    @classmethod
    def from_dict(cls, value: dict) -> "LearningExample":
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("invalid_learning_example_fields")
        def nested(kind, payload):
            if type(payload) is not dict or set(payload) != set(kind.__dataclass_fields__):
                raise ValueError("invalid_learning_metadata_fields")
            raw = dict(payload)
            for key in ("lineage", "fact_codes", "evidence_refs", "frame_evidence_refs"):
                if key in raw:
                    raw[key] = refs(raw[key]) if key in {"evidence_refs", "frame_evidence_refs"} else codes(raw[key])
            return kind(**raw)
        result = dict(value)
        result["frame"] = MioSituationFrame.from_dict(value["frame"])
        result["snapshot"] = nested(SnapshotLineage, value["snapshot"])
        for key, kind in (("teacher", TeacherCandidate), ("reviewer", ReviewerDisposition), ("outcome", ObservedOutcome)):
            result[key] = None if value[key] is None else nested(kind, value[key])
        result["direct_fact_codes"] = codes(value["direct_fact_codes"])
        result["direct_evidence_refs"] = refs(value["direct_evidence_refs"])
        result["feature_origins"] = tuple(value["feature_origins"]) if type(value["feature_origins"]) is list else ()
        example = cls(**result)
        # Structural/type errors reject the record, not guessed defaults.
        for key in ("example_id", "incident_group", "entity_group"):
            item = getattr(example, key)
            if item is not None and (type(item) is not str or opaque_id(item) != item):
                raise ValueError("invalid_learning_group")
        for key in ("source", "snapshot", "generation", "rights_reference", "feature_version", "label_version", "quality", "rights"):
            codes((getattr(example.snapshot, key),))
        for value in (example.decision_at, example.features_as_of, example.frame.created_at,
                      example.snapshot.as_of, example.snapshot.expires_at):
            instant(value)
        if example.teacher:
            codes((example.teacher.model_version, example.teacher.prompt_version,
                   example.teacher.knowledge_snapshot, example.teacher.candidate_label))
        if example.reviewer:
            codes((example.reviewer.reviewer, example.reviewer.disposition, example.reviewer.basis, example.reviewer.label))
            instant(example.reviewer.reviewed_at)
        if example.outcome:
            codes((example.outcome.observation, example.outcome.expected_playbook))
            instant(example.outcome.observed_at)
            codes((example.outcome.example_id, example.outcome.practice_record_ref))
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", example.outcome.frame_digest):
                raise ValueError("invalid_outcome_frame_digest")
            refs(example.outcome.frame_evidence_refs)
        return example


def quarantine_reasons(example: LearningExample, *, now: str, revoked_snapshots=()) -> tuple[str, ...]:
    example = LearningExample.from_dict(example.to_dict())
    reasons = []
    snapshot = example.snapshot
    decision = instant(example.decision_at)
    if decision > instant(now): reasons.append("future_prediction_time")
    if not example.example_id:
        reasons.append("missing_example_id")
    if snapshot.quality != "verified": reasons.append("source_not_verified")
    if snapshot.rights not in {"evaluation_only", "training_and_evaluation"}: reasons.append("rights_unknown")
    if snapshot.snapshot in revoked_snapshots: reasons.append("snapshot_revoked")
    if not instant(snapshot.as_of) <= instant(now) < instant(snapshot.expires_at): reasons.append("snapshot_expired_or_future")
    if snapshot.feature_version != FEATURE_VERSION or snapshot.label_version != LABEL_VERSION: reasons.append("dataset_version_mismatch")
    if not snapshot.lineage: reasons.append("missing_lineage")
    if example.source_kind not in {"curated_observation", "synthetic_fixture", "public_replay"}: reasons.append("unknown_source_kind")
    if any(value is None or value in {"unknown", "UNKNOWN"} for value in (example.incident_group, example.entity_group, example.time_group)):
        reasons.append("group_identity_unknown")
    if example.time_group != decision.date().isoformat(): reasons.append("time_group_mismatch")
    if instant(example.features_as_of) > decision or instant(example.frame.created_at) > decision: reasons.append("future_feature_leakage")
    if example.feature_origins != ORIGINS: reasons.append("feature_origin_leakage")
    feature_text = " ".join((example.frame.mission, example.frame.noc_summary, example.frame.soc_summary)).lower()
    if any(label in feature_text for label in LABELS): reasons.append("label_in_feature_text")
    reviewer = example.reviewer
    if reviewer:
        if reviewer.disposition not in {"accepted", "corrected"}: reasons.append("review_held")
        if reviewer.label not in LABELS: reasons.append("unknown_review_label")
        if reviewer.basis not in {"direct_facts", "independent_outcome"}: reasons.append("teacher_only_label")
        if not reviewer.evidence_refs: reasons.append("review_evidence_missing")
        if not set(reviewer.evidence_refs).issubset(set(example.frame.evidence_refs) | set(example.direct_evidence_refs)):
            reasons.append("review_evidence_unbound")
        if instant(reviewer.reviewed_at) > instant(now): reasons.append("future_review")
        if instant(reviewer.reviewed_at) < instant(example.features_as_of): reasons.append("review_precedes_features")
        if example.teacher and reviewer.disposition == "accepted" and reviewer.label != example.teacher.candidate_label:
            reasons.append("teacher_disposition_mismatch")
        if reviewer.basis == "direct_facts" and not (example.direct_fact_codes and example.direct_evidence_refs): reasons.append("direct_facts_missing")
        if reviewer.basis == "independent_outcome" and example.outcome is None: reasons.append("independent_outcome_missing")
        if reviewer.basis == "independent_outcome" and example.outcome is not None and not set(reviewer.evidence_refs).issubset(set(example.outcome.evidence_refs)):
            reasons.append("review_evidence_not_outcome_bound")
    elif example.source_kind != "public_replay":
        reasons.append("review_missing")
    if example.outcome:
        outcome = example.outcome
        if not outcome.fact_codes or not outcome.evidence_refs: reasons.append("outcome_evidence_missing")
        if outcome.example_id != example.example_id: reasons.append("outcome_example_mismatch")
        if outcome.frame_digest != digest(example.frame.to_dict()): reasons.append("outcome_frame_mismatch")
        if not outcome.frame_evidence_refs or not set(outcome.frame_evidence_refs).issubset(set(example.frame.evidence_refs)):
            reasons.append("outcome_frame_evidence_mismatch")
        if not outcome.practice_record_ref or outcome.practice_record_ref == example.example_id:
            reasons.append("outcome_practice_record_unbound")
        if not set(outcome.evidence_refs).issubset(set(outcome.frame_evidence_refs) | set(example.direct_evidence_refs)):
            reasons.append("outcome_evidence_unbound")
        if not decision <= instant(outcome.observed_at) <= instant(now): reasons.append("outcome_time_invalid")
        if outcome.expected_playbook not in LABELS: reasons.append("unknown_outcome_label")
        if reviewer and reviewer.label != outcome.expected_playbook: reasons.append("conflicting_review_outcome")
        if reviewer and instant(reviewer.reviewed_at) < instant(outcome.observed_at) and reviewer.basis == "independent_outcome": reasons.append("review_precedes_outcome")
    return tuple(reasons)


def content_digest(example: LearningExample) -> str:
    frame = example.frame.to_dict()
    for key in ("frame_id", "trace_id", "created_at", "evidence_refs", "knowledge_refs", "provenance"):
        frame.pop(key, None)
    return digest(frame)

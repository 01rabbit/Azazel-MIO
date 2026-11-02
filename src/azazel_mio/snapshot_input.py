"""Internal projections of product-validated snapshot consumption, not wire parsing.

The Knowledge adapter owns canonical bytes, source admission/authentication and
shared contracts. These data bindings never prove truth, labels or admission.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re

from .contracts import model_id_ok
from .learning_data import FEATURE_VERSION, LABEL_VERSION, LearningExample, digest, instant

_CODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_RECORD = re.compile(r"ksr-[0-9a-f]{32}\Z")


def _code(value):
    if type(value) is not str or not _CODE.fullmatch(value): raise ValueError("invalid_snapshot_input_code")


def _hex(value):
    if type(value) is not str or not _HEX.fullmatch(value): raise ValueError("invalid_snapshot_input_digest")


def _items(values, cap, kind):
    if type(values) is not tuple or len(values) > cap or any(type(value) is not kind for value in values):
        raise ValueError("invalid_snapshot_input_items")


@dataclass(frozen=True)
class SnapshotInputContext:
    tenant_ref: str
    privacy_class: str
    checked_at: str
    revocation_version: str
    revoked_refs: tuple[str, ...] = ()
    consumption_bindings: tuple[tuple[str, str], ...] = ()

    def __post_init__(self):
        _code(self.tenant_ref)
        _code(self.revocation_version)
        if self.privacy_class not in {"public", "internal"}: raise ValueError("invalid_snapshot_input_privacy")
        instant(self.checked_at)
        _items(self.revoked_refs, 2048, str)
        for value in self.revoked_refs: _code(value)
        if len(set(self.revoked_refs)) != len(self.revoked_refs): raise ValueError("duplicate_snapshot_revocation")
        _items(self.consumption_bindings, 16, tuple)
        for pair in self.consumption_bindings:
            if len(pair) != 2 or type(pair[0]) is not str or not re.fullmatch(r"ks-[0-9a-f]{24}", pair[0]):
                raise ValueError("invalid_consumption_binding")
            if type(pair[1]) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", pair[1]):
                raise ValueError("invalid_consumption_binding_digest")
        if len({pair[0] for pair in self.consumption_bindings}) != len(self.consumption_bindings):
            raise ValueError("duplicate_consumption_binding")


@dataclass(frozen=True)
class SnapshotSourceBinding:
    source_ref: str
    tenant_ref: str
    privacy_class: str
    rights: str
    rights_reference: str
    lineage: tuple[str, ...]
    valid_from: str
    valid_until: str

    def __post_init__(self):
        for value in (self.source_ref, self.tenant_ref, self.rights_reference): _code(value)
        if self.privacy_class not in {"public", "internal"} or self.rights not in {"unknown", "reference_only", "evaluation_only", "training_and_evaluation"}:
            raise ValueError("snapshot_source_not_usable_for_learning")
        _items(self.lineage, 16, str)
        if not self.lineage: raise ValueError("snapshot_source_lineage_missing")
        for value in self.lineage: _code(value)
        if not instant(self.valid_from) < instant(self.valid_until): raise ValueError("snapshot_source_window")


@dataclass(frozen=True)
class SnapshotRecordBinding:
    record_ref: str
    source_ref: str
    observed_at: str
    source_payload_digest: str
    incident_group: str | None
    entity_group: str | None
    frame_digest: str | None
    boot_ref: str | None
    generation_ref: str | None
    correlation_evidence_ref: str | None
    quarantine_reason: str | None = None
    learning_payload_digest: str | None = None
    practice_record_ref: str | None = None
    practice_payload_digest: str | None = None

    def __post_init__(self):
        if type(self.record_ref) is not str or not _RECORD.fullmatch(self.record_ref): raise ValueError("invalid_snapshot_record_ref")
        _code(self.source_ref)
        _hex(self.source_payload_digest)
        instant(self.observed_at)
        for value in (self.incident_group, self.entity_group, self.boot_ref, self.generation_ref):
            if value is not None and (type(value) is not str or not _RECORD.fullmatch(value)):
                raise ValueError("invalid_snapshot_record_scope")
        if self.frame_digest is not None: _hex(self.frame_digest)
        if self.correlation_evidence_ref is not None and not model_id_ok(self.correlation_evidence_ref, "evidence_ref"):
            raise ValueError("invalid_snapshot_correlation_evidence")
        if self.quarantine_reason is not None: _code(self.quarantine_reason)
        if self.learning_payload_digest is not None and (type(self.learning_payload_digest) is not str or
                not re.fullmatch(r"sha256:[0-9a-f]{64}", self.learning_payload_digest)):
            raise ValueError("invalid_learning_payload_digest")
        if (self.practice_record_ref is None) != (self.practice_payload_digest is None):
            raise ValueError("incomplete_practice_binding")
        if self.practice_record_ref is not None:
            _code(self.practice_record_ref)
            if self.practice_record_ref == self.record_ref: raise ValueError("practice_record_binding_reused_example")
            if type(self.practice_payload_digest) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.practice_payload_digest):
                raise ValueError("invalid_practice_payload_digest")
        if self.quarantine_reason is None and any(value is None for value in (
                self.frame_digest, self.boot_ref, self.generation_ref, self.incident_group, self.correlation_evidence_ref)):
            raise ValueError("snapshot_record_binding_incomplete")


@dataclass(frozen=True)
class ConsumedSnapshotInput:
    snapshot_id: str
    content_digest: str
    source: str
    generation: str
    purpose: str
    tenant_ref: str
    privacy_class: str
    snapshot_as_of: str
    validated_as_of: str
    expires_at: str
    revocation_version: str
    source_refs: tuple[str, ...]
    record_count: int
    example_count: int
    evaluation_input_count: int
    metadata_digest: str
    metadata_canonical_json: str
    source_bindings: tuple[SnapshotSourceBinding, ...]
    record_bindings: tuple[SnapshotRecordBinding, ...]
    feature_version: str = FEATURE_VERSION
    label_version: str = LABEL_VERSION

    def __post_init__(self):
        _hex(self.content_digest)
        _hex(self.metadata_digest)
        # Identity material only: private admission JSON is never parsed here.
        if type(self.metadata_canonical_json) is not str or len(self.metadata_canonical_json.encode("utf-8")) > 262144:
            raise ValueError("snapshot_metadata_material_bound")
        if hashlib.sha256(self.metadata_canonical_json.encode("utf-8")).hexdigest() != self.metadata_digest:
            raise ValueError("snapshot_metadata_digest_mismatch")
        if self.snapshot_id != "ks-" + self.content_digest[:24]: raise ValueError("snapshot_id_digest_mismatch")
        if self.source != "azazel-knowledge" or self.purpose != "training": raise ValueError("snapshot_input_source_or_purpose")
        for value in (self.generation, self.tenant_ref, self.revocation_version): _code(value)
        if self.privacy_class not in {"public", "internal"}: raise ValueError("invalid_snapshot_input_privacy")
        if not instant(self.snapshot_as_of) <= instant(self.validated_as_of) < instant(self.expires_at): raise ValueError("snapshot_input_window")
        if (self.feature_version, self.label_version) != (FEATURE_VERSION, LABEL_VERSION): raise ValueError("snapshot_input_versions")
        _items(self.source_refs, 64, str)
        _items(self.source_bindings, 64, SnapshotSourceBinding)
        _items(self.record_bindings, 2048, SnapshotRecordBinding)
        if not self.source_refs or len(set(self.source_refs)) != len(self.source_refs): raise ValueError("snapshot_input_sources")
        if set(self.source_refs) != {source.source_ref for source in self.source_bindings} or len(self.source_refs) != len(self.source_bindings):
            raise ValueError("snapshot_input_source_binding_mismatch")
        if len({row.record_ref for row in self.record_bindings}) != len(self.record_bindings): raise ValueError("snapshot_input_duplicate_record")
        for count in (self.record_count, self.example_count, self.evaluation_input_count):
            if type(count) is not int or not 0 <= count <= 2048: raise ValueError("snapshot_input_count_bound")
        if not self.example_count <= self.evaluation_input_count == len(self.record_bindings) <= self.record_count:
            raise ValueError("snapshot_input_count_mismatch")
        if sum(row.quarantine_reason is None for row in self.record_bindings) != self.example_count:
            raise ValueError("snapshot_input_frame_count_mismatch")
        if any(row.source_ref not in self.source_refs for row in self.record_bindings): raise ValueError("snapshot_input_record_source")
        for source in self.source_bindings:
            if source.tenant_ref != self.tenant_ref or (self.privacy_class == "public" and source.privacy_class != "public"):
                raise ValueError("snapshot_input_source_scope")
            if not instant(source.valid_from) <= instant(self.snapshot_as_of) < instant(self.expires_at) <= instant(source.valid_until):
                raise ValueError("snapshot_input_outside_source_window")


def learning_payload_digest(example: LearningExample) -> str:
    """Canonical identity of all learning semantics, including absent annotations.

    The trusted producer must derive this from source-validated projections, not
    from subsequently supplied annotations. This helper grants no source trust.
    """
    if type(example) is not LearningExample:
        raise ValueError("learning_payload_type")
    normalized = LearningExample.from_dict(example.to_dict())
    return digest(normalized.to_dict())


def practice_outcome_digest(example: LearningExample) -> str:
    """Identity for the trusted caller's exact practice/outcome projection."""
    if type(example) is not LearningExample or example.outcome is None:
        raise ValueError("practice_outcome_missing")
    return digest(asdict(example.outcome))


def consumed_projection_digest(value: ConsumedSnapshotInput) -> str:
    """Identity to pin in a separate product-owned current consumption context."""
    if type(value) is not ConsumedSnapshotInput:
        raise ValueError("consumed_projection_type")
    value.__post_init__()
    for source in value.source_bindings: source.__post_init__()
    for record in value.record_bindings: record.__post_init__()
    return digest(asdict(value))


def _frame_digest(frame):
    # Knowledge's explicit JSON identity is UTF-8/non-ASCII-escaped raw hex.
    # This is deliberately distinct from learning_data.digest (ASCII + sha256:).
    encoded = json.dumps(frame.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def snapshot_input_audit(examples, inputs=(), *, context=None, now: str, additional_revoked_refs=()):
    """Check data correspondence, never a caller-supplied connected/label boolean."""
    _items(inputs, 16, ConsumedSnapshotInput)
    _items(additional_revoked_refs, 2048, str)
    for reference in additional_revoked_refs: _code(reference)
    if len({value.snapshot_id for value in inputs}) != len(inputs): raise ValueError("duplicate_consumed_snapshot")
    if context is not None and type(context) is not SnapshotInputContext: raise ValueError("invalid_snapshot_input_context")
    raw_by_id = {}
    for raw in examples:
        identifier = raw.example_id if type(raw) is LearningExample else raw.get("example_id") if type(raw) is dict else None
        if type(identifier) is str:
            raw_by_id.setdefault(identifier, []).append(raw)
    snapshots, rejected, bound_ids = [], {}, set()
    for value in inputs:
        # Revalidate directly constructed frozen values, including nested values.
        for source in value.source_bindings: source.__post_init__()
        for row in value.record_bindings: row.__post_init__()
        value.__post_init__()
        problems = []
        projection_pinned = False
        learning_rejections = {}
        if context is None: problems.append("current_snapshot_context_missing")
        else:
            context.__post_init__()
            pinned = dict(context.consumption_bindings).get(value.snapshot_id)
            if pinned is not None:
                projection_pinned = pinned == consumed_projection_digest(value)
                if not projection_pinned: problems.append("snapshot_consumption_binding_mismatch")
            if (context.tenant_ref, context.privacy_class) != (value.tenant_ref, value.privacy_class): problems.append("snapshot_scope_mismatch")
            if context.checked_at != now or instant(value.validated_as_of) > instant(context.checked_at): problems.append("snapshot_context_not_current")
            if context.revocation_version != value.revocation_version: problems.append("snapshot_revocation_version_mismatch")
            referenced = {value.snapshot_id, *value.source_refs, *(row.record_ref for row in value.record_bindings),
                          *(row.practice_record_ref for row in value.record_bindings if row.practice_record_ref is not None)}
            if referenced & (set(context.revoked_refs) | set(additional_revoked_refs)): problems.append("snapshot_currently_revoked")
        if not instant(value.snapshot_as_of) <= instant(now) < instant(value.expires_at): problems.append("snapshot_input_not_current")
        sources = {source.source_ref: source for source in value.source_bindings}
        frame_quarantine = []
        for binding in value.record_bindings:
            row_problems = []
            matched = raw_by_id.get(binding.record_ref, ())
            if len(matched) != 1:
                row_problems.append("snapshot_example_missing_or_duplicate")
            elif binding.quarantine_reason is not None:
                raw = matched[0]
                if type(raw) is not dict or raw.get("bridge_quarantine") != binding.quarantine_reason:
                    row_problems.append("snapshot_quarantine_binding_mismatch")
                frame_quarantine.append({"record_ref": binding.record_ref, "reasons": [binding.quarantine_reason]})
            else:
                raw = matched[0]
                try:
                    example = LearningExample.from_dict(raw.to_dict()) if type(raw) is LearningExample else LearningExample.from_dict(raw)
                    semantic_problems = []
                    if not projection_pinned or binding.learning_payload_digest is None:
                        semantic_problems.append("snapshot_learning_semantics_unbound")
                    elif learning_payload_digest(example) != binding.learning_payload_digest:
                        semantic_problems.append("snapshot_learning_payload_mismatch")
                    if semantic_problems:
                        learning_rejections[binding.record_ref] = tuple(semantic_problems)
                    if example.outcome is not None and (
                            binding.practice_record_ref != example.outcome.practice_record_ref
                            or binding.practice_payload_digest != practice_outcome_digest(example)):
                        learning_rejections[binding.record_ref] = tuple((*learning_rejections.get(binding.record_ref, ()),
                            "snapshot_practice_outcome_binding_mismatch"))
                    metadata = example.snapshot
                    source = sources[binding.source_ref]
                    if source.rights not in {"evaluation_only", "training_and_evaluation"}:
                        row_problems.append("snapshot_source_rights_not_usable")
                    if example.source_kind != "curated_observation" or example.example_id != binding.record_ref:
                        row_problems.append("snapshot_example_kind_mismatch")
                    if (metadata.source, metadata.snapshot, metadata.generation, metadata.as_of, metadata.expires_at) != (
                            value.source, value.snapshot_id, value.generation, value.snapshot_as_of, value.expires_at):
                        row_problems.append("snapshot_example_identity_mismatch")
                    if (metadata.rights, metadata.rights_reference, metadata.lineage) != (source.rights, source.rights_reference, source.lineage):
                        row_problems.append("snapshot_example_metadata_mismatch")
                    if metadata.feature_version != value.feature_version or metadata.label_version != value.label_version:
                        row_problems.append("snapshot_example_version_mismatch")
                    if (example.incident_group, example.entity_group) != (binding.incident_group, binding.entity_group):
                        row_problems.append("snapshot_example_group_mismatch")
                    if _frame_digest(example.frame) != binding.frame_digest: row_problems.append("snapshot_frame_digest_mismatch")
                    if (example.decision_at != example.frame.created_at or example.features_as_of != example.frame.created_at
                            or not instant(binding.observed_at) <= instant(example.frame.created_at) <= instant(value.snapshot_as_of)):
                        row_problems.append("snapshot_frame_time_mismatch")
                    if (binding.correlation_evidence_ref not in example.frame.evidence_refs
                            or binding.correlation_evidence_ref not in example.direct_evidence_refs):
                        row_problems.append("snapshot_frame_evidence_mismatch")
                except (ValueError, TypeError, KeyError):
                    row_problems.append("snapshot_example_malformed")
            if row_problems:
                problems.extend(row_problems)
        problems = list(dict.fromkeys(problems))
        connected = not problems and bool(value.record_bindings)
        for binding in value.record_bindings:
            if problems:
                rejected[binding.record_ref] = tuple(problems)
            elif binding.record_ref in learning_rejections:
                rejected[binding.record_ref] = learning_rejections[binding.record_ref]
            elif connected and binding.quarantine_reason is None:
                bound_ids.add(binding.record_ref)
        snapshots.append({"snapshot_id": value.snapshot_id, "content_digest": value.content_digest,
                          "metadata_digest": value.metadata_digest, "source": value.source, "generation": value.generation,
                          "tenant_ref": value.tenant_ref, "privacy_class": value.privacy_class,
                          "revocation_version": value.revocation_version, "validated_as_of": value.validated_as_of,
                          "expires_at": value.expires_at, "source_refs": list(value.source_refs),
                          "record_count": value.record_count, "bound_frame_examples": value.example_count if connected else 0,
                          "evaluation_input_count": value.evaluation_input_count, "connected": connected,
                          "consumption_projection_digest": consumed_projection_digest(value),
                          "learning_projection_pinned": projection_pinned,
                          "learning_bound_examples": sum(connected and row.quarantine_reason is None and row.record_ref not in learning_rejections for row in value.record_bindings),
                          "learning_payload_rejections": [{"record_ref": key, "reasons": list(reasons)} for key, reasons in learning_rejections.items()],
                          "frame_quarantine": frame_quarantine, "rejection_reasons": problems,
                          "limits": ["product_validated_projection", "not_authentication_or_truth_proof", "not_labels_or_product_admission"]})
    for identifier, rows in raw_by_id.items():
        for raw in rows:
            kind = raw.source_kind if type(raw) is LearningExample else raw.get("source_kind") if type(raw) is dict else None
            if kind == "curated_observation" and identifier not in bound_ids:
                rejected.setdefault(identifier, ("snapshot_provenance_missing_or_rejected",))
    return {"connected": any(row["connected"] for row in snapshots), "snapshots": snapshots,
            "bound_example_ids": frozenset(bound_ids), "rejected_examples": rejected}

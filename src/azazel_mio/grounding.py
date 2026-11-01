from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contracts import (
    INVALID_MODEL_ID,
    INVALID_MODEL_ID_CODE,
    MioEvidenceGap,
    MioHypothesis,
    MioRecommendation,
    MioSituationFrame,
    safe_model_id,
)
from .id_grammar import UNREGISTERED_CAPABILITY, capability_label  # noqa: F401


# Model-written keys echoed into error paths must look like schema keys.
_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,47}\Z")
_MAX_RAW_NODES = 4096
_MAX_RAW_DEPTH = 64
_MAX_RAW_TEXT_CHARS = 1_000_000
_MAX_RAW_INT_BITS = 4096
FORBIDDEN_DIRECTIVE_KEYS = {"execute", "must_action", "override", "command", "shell", "activate", "enforce", "executable"}
ALLOWED_RECOMMENDED_ACTIONS = {"OBSERVE", "NOTIFY", "THROTTLE", "REDIRECT", "ISOLATE"}
# Errors name a capability only when the broker registry knows it
# (id_grammar.capability_label); otherwise UNREGISTERED_CAPABILITY.


@dataclass(frozen=True)
class GroundingResult:
    ok: bool
    errors: tuple[str, ...]


class GroundingValidator:
    def __init__(self, frame: MioSituationFrame, *, additional_evidence_refs: Sequence[str] = ()):
        self._allowed_refs = set(frame.evidence_refs) | set(frame.knowledge_refs) | {str(x) for x in additional_evidence_refs}

    def validate_raw(self, payload: Mapping[str, Any]) -> GroundingResult:
        errors: list[str] = []
        # The downstream parser reads model responses as dictionaries. Reject custom
        # mappings before touching their hooks so validation and parsing see one shape.
        if type(payload) is not dict:
            return GroundingResult(False, ("raw_payload_unsupported_container",))
        # Use iterator frames instead of recursion or materializing container items.
        stack: list[tuple[str, Any, str, int, frozenset[int], bool]] = [
            ("visit", payload, "", 0, frozenset(), False)
        ]
        visited_nodes = 0
        visited_text_chars = 0
        raw_refs: list[Any] = []
        while stack:
            action, value, path, depth, ancestors, is_mapping = stack.pop()
            if action == "iterate":
                iterator = value
                try:
                    key, nested = next(iterator)
                except StopIteration:
                    continue
                except Exception:
                    errors.append("raw_payload_unreadable")
                    break
                stack.append(("iterate", iterator, path, depth, ancestors, is_mapping))
                if is_mapping:
                    if type(key) is not str:
                        errors.append("raw_payload_unsupported_key")
                        break
                    key_text = key
                    visited_text_chars += len(key_text)
                    if visited_text_chars > _MAX_RAW_TEXT_CHARS:
                        errors.append("raw_payload_too_large")
                        break
                    if path == "evidence_refs":
                        raw_refs.append(nested)
                    lower_key = key_text.lower() if len(key_text) <= 48 else ""
                    shown = key_text if lower_key in FORBIDDEN_DIRECTIVE_KEYS or _KEY_RE.fullmatch(key_text) else "invalid-key"
                    child_path = f"{path}.{shown}" if path else shown
                    if lower_key in FORBIDDEN_DIRECTIVE_KEYS:
                        errors.append(f"forbidden_directive_key:{child_path}")
                else:
                    child_path = f"{path}[{key}]"
                stack.append(("visit", nested, child_path, depth + 1, ancestors, False))
                continue

            visited_nodes += 1
            if visited_nodes > _MAX_RAW_NODES:
                errors.append("raw_payload_too_many_nodes")
                break
            if type(value) is str:
                visited_text_chars += str.__len__(value)
                if visited_text_chars > _MAX_RAW_TEXT_CHARS:
                    errors.append("raw_payload_too_large")
                    break
            if type(value) in (dict, list, tuple):
                if depth >= _MAX_RAW_DEPTH:
                    errors.append("raw_payload_too_deep")
                    break
                identity = id(value)
                if identity in ancestors:
                    errors.append("raw_payload_cycle")
                    break
                nested_ancestors = ancestors | {identity}
                try:
                    if type(value) is dict:
                        iterator = iter(dict.items(value))
                    elif type(value) is list:
                        iterator = iter(enumerate(list.__iter__(value)))
                    else:
                        iterator = iter(enumerate(tuple.__iter__(value)))
                except Exception:
                    errors.append("raw_payload_unreadable")
                    break
                stack.append(("iterate", iterator, path, depth, nested_ancestors, type(value) is dict))
            elif isinstance(value, (Mapping, list, tuple)):
                errors.append("raw_payload_unsupported_container")
                break
            elif type(value) is int:
                if value.bit_length() > _MAX_RAW_INT_BITS:
                    errors.append("raw_payload_too_large")
                    break
            elif type(value) is float:
                if not math.isfinite(value):
                    errors.append("raw_payload_unsupported_value")
                    break
            elif type(value) not in (str, bool, type(None)):
                errors.append("raw_payload_unsupported_value")
                break

        if errors and any(error.startswith("raw_payload_") for error in errors):
            return GroundingResult(False, tuple(errors))
        for ref in raw_refs:
            normalized_ref = str.__str__(ref) if isinstance(ref, str) else None
            shown = safe_model_id(normalized_ref, "evidence_ref")
            if shown == INVALID_MODEL_ID:
                errors.append(f"{INVALID_MODEL_ID_CODE}:evidence_ref")
            elif normalized_ref not in self._allowed_refs:
                errors.append(f"unknown_evidence_ref:{shown}")
        return GroundingResult(not errors, tuple(errors))

    def validate_hypotheses(self, hypotheses: Sequence[MioHypothesis]) -> GroundingResult:
        errors: list[str] = []
        if not hypotheses:
            errors.append("no_hypotheses")
        if len(hypotheses) > 6:
            errors.append("too_many_hypotheses")
        seen_ids: set[str] = set()
        for hypothesis in hypotheses:
            if hypothesis.hypothesis_id == INVALID_MODEL_ID:
                errors.append(f"{INVALID_MODEL_ID_CODE}:hypothesis_id")
            if INVALID_MODEL_ID in hypothesis.supporting_evidence_refs or INVALID_MODEL_ID in hypothesis.contradicting_evidence_refs:
                errors.append(f"{INVALID_MODEL_ID_CODE}:evidence_ref")
            if not hypothesis.hypothesis_id:
                errors.append("empty_hypothesis_id")
            elif hypothesis.hypothesis_id in seen_ids:
                errors.append(f"duplicate_hypothesis_id:{hypothesis.hypothesis_id}")
            else:
                seen_ids.add(hypothesis.hypothesis_id)
            if not hypothesis.statement:
                errors.append(f"empty_statement:{hypothesis.hypothesis_id}")
            supporting = set(hypothesis.supporting_evidence_refs)
            contradicting = set(hypothesis.contradicting_evidence_refs)
            for ref in sorted(supporting & contradicting):
                errors.append(f"conflicting_hypothesis_evidence_ref:{hypothesis.hypothesis_id}:{ref}")

            refs = supporting | contradicting
            for ref in refs:
                if ref not in self._allowed_refs:
                    errors.append(f"unknown_hypothesis_ref:{hypothesis.hypothesis_id}:{ref}")
        return GroundingResult(not errors, tuple(errors))

    def validate_evidence_gaps(
        self,
        gaps: Sequence[MioEvidenceGap],
        *,
        hypotheses: Sequence[MioHypothesis],
        allowed_capabilities: Sequence[str],
        registered_capabilities: Sequence[str] = (),
    ) -> GroundingResult:
        errors: list[str] = []
        hypothesis_ids = {item.hypothesis_id for item in hypotheses}
        allowed = {str(item) for item in allowed_capabilities}
        seen_gap_ids: set[str] = set()
        for gap in gaps:
            if gap.gap_id == INVALID_MODEL_ID:
                errors.append(f"{INVALID_MODEL_ID_CODE}:gap_id")
            if INVALID_MODEL_ID in gap.discriminates_hypothesis_ids:
                errors.append(f"{INVALID_MODEL_ID_CODE}:discriminates_hypothesis_id")
            if gap.capability == INVALID_MODEL_ID:
                errors.append(f"{INVALID_MODEL_ID_CODE}:capability")
            if not gap.gap_id:
                errors.append("empty_gap_id")
            elif gap.gap_id in seen_gap_ids:
                errors.append(f"duplicate_gap_id:{gap.gap_id}")
            else:
                seen_gap_ids.add(gap.gap_id)
            if not gap.question:
                errors.append(f"empty_gap_question:{gap.gap_id}")
            if not gap.capability:
                errors.append(f"empty_gap_capability:{gap.gap_id}")
            elif gap.capability not in allowed:
                errors.append(f"capability_not_allowed_by_playbook:{capability_label(gap.capability, registered_capabilities)}")
            for hypothesis_id in gap.discriminates_hypothesis_ids:
                if hypothesis_id not in hypothesis_ids:
                    errors.append(f"unknown_gap_hypothesis:{gap.gap_id}:{hypothesis_id}")
        return GroundingResult(not errors, tuple(errors))

    def validate_recommendation(self, recommendation: MioRecommendation) -> GroundingResult:
        errors: list[str] = []
        if INVALID_MODEL_ID in recommendation.evidence_refs:
            errors.append(f"{INVALID_MODEL_ID_CODE}:evidence_ref")
        if recommendation.executable:
            errors.append("recommendation_must_not_be_executable")
        if not recommendation.summary.strip():
            errors.append("empty_recommendation_summary")
        if not recommendation.rationale.strip():
            errors.append("empty_recommendation_rationale")
        if not recommendation.recommended_action.strip():
            errors.append("empty_recommended_action")
        elif recommendation.recommended_action not in ALLOWED_RECOMMENDED_ACTIONS:
            errors.append("unknown_recommended_action")
        if not recommendation.evidence_refs:
            errors.append("empty_recommendation_evidence_refs")
        for ref in recommendation.evidence_refs:
            if ref not in self._allowed_refs:
                errors.append(f"unknown_recommendation_ref:{ref}")
        return GroundingResult(not errors, tuple(errors))

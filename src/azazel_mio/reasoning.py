from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from functools import lru_cache
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping, Sequence

from .budget import BudgetError, CompiledPrompt, GenerationBudget, GenerationOutcome
from .broker import CapabilityBroker, CapabilityBrokerError
from .claim_audit import audit_claims, unparseable_status_ids
from .contracts import (
    MioCapabilityRequest,
    MioEvidenceGap,
    MioHypothesis,
    MioRecommendation,
    MioSituationFrame,
    HypothesisStatus,
    ReasoningState,
)
from .evidence_gap_scoring import SCORING_POLICY_VERSION, score_evidence_gaps, scoring_policy_digest
from .grounding import GroundingValidator, capability_label
from .handoff import NoModelHandoff, build_no_model_handoff
from .lifecycle import (
    REASON_CYCLE_CANCELLED,
    REASON_CYCLE_SUPERSEDED,
    HypothesisAuditEntry,
    apply_hypothesis_update,
    record_initial,
    supersede_all,
    validate_initial_hypotheses,
)
from .model_adapter import MioModelBlocked, MioModelUnavailable
from .model_schema import validate_model_response
from .observation_objectives import MioObservationObjective, ObservationProjectionReport, project_observation_report
from .playbook import GENERIC_UNVERIFIED_MODE, PlaybookSelection, PromptCompiler, ReasoningPlaybook, compiled_model_response_schema, guard_selection, reasoning_provenance
from .trace import ReasoningTrace
from .tactical_grounding import (
    claim_scope_violations,
    deterministic_authentication_gaps,
    ground_auth_recommendation,
    is_authentication_context,
    scope_hypotheses_to_frame,
)

# Process-local key for the digest suffix of model exception codes: equal
# exception texts correlate within one process, but the digest cannot be
# matched against guessed texts elsewhere. Never persisted or exported.
@lru_cache(maxsize=1)
def _exception_digest_key() -> bytes:
    return secrets.token_bytes(32)


def _exception_code(code: str, exc: BaseException) -> str:
    """``<code>:h:<digest>`` for a model call that raised.

    The exception text comes from the model invoker (a remote endpoint, a
    transport library, a test double) and may carry addresses, prompts or
    model output, so it never enters ``errors`` or the trace: only the fixed
    code and a keyed digest of the text, as in the durable audit.
    """
    try:
        text = str(exc)
    except Exception:
        text = type(exc).__name__
    digest = hmac.new(_exception_digest_key(), text.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:16]
    return f"{code}:h:{digest}"


ModelInvoker = Callable[[str, str], Mapping[str, Any]]
CancelCheck = Callable[[], bool]
_LOG = logging.getLogger(__name__)

@dataclass(frozen=True)
class ReasoningBudget:
    max_model_calls: int = 4
    max_broker_calls: int = 3
    max_hypotheses: int = 4
    max_gaps: int = 3
    max_frame_age_seconds: int = 300


# Public diagnostics are closed labels, never error text or suffix identifiers.
_VALIDATION_STAGES = frozenset({"playbook", "generate_hypotheses", "identify_evidence_gaps",
                               "update_hypotheses", "recommend"})
_REJECTION_CODES = {
    "output_shape": ("hypotheses_not_list", "hypothesis_update_not_mapping",
                     "updated_hypotheses_not_list", "recommendation_not_mapping"),
    "alternative_slots": ("unknown_hypothesis_alternative_id", "insufficient_competing_hypotheses",
                          "duplicate_hypothesis_alternative_id", "missing_benign_or_unresolved_alternative_slot",
                          "hypothesis_alternative_id_changed", "duplicate_live_hypothesis_alternative_slot"),
    "model_identifier": ("invalid_model_id",),
    "evidence_grounding": ("unknown_evidence_ref", "unknown_hypothesis_ref",
                           "conflicting_hypothesis_evidence_ref", "unknown_recommendation_ref"),
    "raw_payload": ("raw_payload_unreadable", "raw_payload_unsupported_key", "raw_payload_too_large",
                    "raw_payload_too_many_nodes", "raw_payload_too_deep", "raw_payload_cycle",
                    "raw_payload_unsupported_container", "raw_payload_unsupported_value", "forbidden_directive_key"),
    "hypothesis_structure": ("no_hypotheses", "too_many_hypotheses", "empty_hypothesis_id",
                             "duplicate_hypothesis_id", "empty_statement"),
    "evidence_gap": ("empty_gap_id", "duplicate_gap_id", "empty_gap_question", "empty_gap_capability",
                     "capability_not_allowed_by_playbook", "unknown_gap_hypothesis"),
    "hypothesis_lifecycle": ("initial_hypothesis_must_start_proposed", "new_hypothesis_must_start_proposed",
                            "invalid_hypothesis_transition", "terminal_hypothesis_modified",
                            "strengthened_without_supporting_evidence", "weakened_without_refuting_evidence_or_gap",
                            "lifecycle_ref_outside_context", "falsified_without_falsification_condition",
                            "falsified_without_contradicting_evidence"),
    "recommendation_structure": ("recommendation_must_not_be_executable", "empty_recommendation_summary",
                                 "empty_recommendation_rationale", "empty_recommended_action",
                                 "unknown_recommended_action", "empty_recommendation_evidence_refs"),
    "unsupported_claim": ("unsupported_claim", "unsupported_recommendation_claim"),
}
_REJECTION_CLASS_BY_CODE = {code: label for label, codes in _REJECTION_CODES.items() for code in codes}


def _validation_diagnostic(stage: str, errors: Sequence[str]) -> dict[str, str]:
    # Match only a fixed internal code before the first colon. Never copy any
    # suffix, including model-authored IDs, paths, claim text, or error details.
    rejection_class = "unknown"
    for error in errors:
        if type(error) is str:
            label = _REJECTION_CLASS_BY_CODE.get(error.partition(":")[0])
            if label is not None:
                rejection_class = label
                break
    return {"stage": stage if type(stage) is str and stage in _VALIDATION_STAGES else "unknown",
            "rejection_class": rejection_class}


@dataclass(frozen=True)
class ReasoningOutcome:
    state: ReasoningState
    hypotheses: tuple[MioHypothesis, ...]
    evidence_gaps: tuple[MioEvidenceGap, ...]
    recommendation: MioRecommendation | None
    errors: tuple[str, ...]
    trace: tuple[Any, ...]
    # Every lifecycle step of every hypothesis in this cycle, including
    # falsified and superseded ones (#385). Never compacted by the loop.
    hypothesis_audit: tuple[HypothesisAuditEntry, ...] = ()
    # Deterministic frame-only summary when no validated recommendation exists.
    handoff: NoModelHandoff | None = None
    validation_diagnostic: Mapping[str, str] | None = None
    # Local, non-executable proposals. Only a COMPLETE deception-observation-v1 cycle sets these.
    observation_objectives: tuple[MioObservationObjective, ...] = ()
    # Local MIO diagnostic of the observation projection (not a shared contract).
    observation_projection: ObservationProjectionReport | None = None
    generation_receipt: GenerationOutcome | None = None


# Terminal states that get a deterministic no-model handoff. Cancelled and
# superseded cycles do not: their frame is no longer the current situation.
HANDOFF_STATES = frozenset({
    ReasoningState.DEPENDENCY_UNAVAILABLE,
    ReasoningState.ERROR_FALLBACK,
    ReasoningState.VALIDATION_REJECTED,
    ReasoningState.BUDGET_EXHAUSTED,
    ReasoningState.INSUFFICIENT_EVIDENCE,
})


class BoundedReasoningLoop:
    """Bounded advisory cognitive loop. It never invokes product enforcement."""

    def __init__(
        self,
        *,
        model: ModelInvoker | None,
        broker: CapabilityBroker,
        compiler: PromptCompiler | None = None,
        budget: ReasoningBudget | None = None,
    ):
        self.model = model
        self.broker = broker
        self.compiler = compiler or PromptCompiler()
        self.budget = budget or ReasoningBudget()

    @staticmethod
    def _is_cancelled(cancel_check: CancelCheck | None) -> bool:
        if cancel_check is None:
            return False
        try:
            return bool(cancel_check())
        except Exception:
            return True

    @classmethod
    def _interrupted(cls, cancel_check: CancelCheck | None, stale_check: CancelCheck | None, errors: list[str]) -> ReasoningState | None:
        # Supersession is checked first: a cycle replaced by a newer material
        # frame is stale even if an operator also cancelled it.
        if cls._is_cancelled(stale_check):
            errors.append("superseded_by_newer_frame")
            return ReasoningState.STALE_SUPERSEDED
        if cls._is_cancelled(cancel_check):
            errors.append("operator_cancelled")
            return ReasoningState.OPERATOR_CANCELLED
        return None

    def run(
        self,
        *,
        frame: MioSituationFrame,
        playbook: ReasoningPlaybook,
        cycle_id: str,
        cancel_check: CancelCheck | None = None,
        stale_check: CancelCheck | None = None,
        selection: PlaybookSelection | None = None,
        broker: CapabilityBroker | None = None,
        strict_model_response: bool = False,
        budget_for_task: Callable[[str], GenerationBudget] | None = None,
    ) -> ReasoningOutcome:
        # ``broker``: this cycle's own broker (ReasoningCoordinator.run_cycle
        # passes a new one per cycle); defaults to the loop's broker.
        broker = self.broker if broker is None else broker
        trace = ReasoningTrace(trace_id=frame.trace_id, cycle_id=cycle_id)
        errors: list[str] = []
        model_calls = 0
        broker_calls = 0
        audit: list[HypothesisAuditEntry] = []
        validated: list[MioHypothesis] = []
        validation_stage = "playbook"
        task_names = ("generate_hypotheses", "identify_evidence_gaps", "recommend")
        calls_sent = {task: 0 for task in task_names}
        usage = {task: None for task in task_names}
        task_results = {task: "not_started" for task in task_names}
        selections = {}
        budget_reason = None
        current_task = None

        def receipt(state):
            if budget_for_task is None:
                return None
            done = state is ReasoningState.COMPLETE
            reason = None if done else (budget_reason or ("malformed" if "output_invalid" in errors else state.value))
            results = dict(task_results)
            if not done and current_task in results and results[current_task] == "sent":
                results[current_task] = "failed"
            receipt_state = ("complete" if done else "failed" if reason == "send_notification_conflict"
                             else "partial" if sum(calls_sent.values()) else "failed")
            return GenerationOutcome(receipt_state, results, dict(calls_sent), dict(usage), reason, dict(selections))

        def finish(state, hypotheses_out, gaps_out, recommendation_out):
            result = self._finish(trace, state, hypotheses_out, gaps_out, recommendation_out, errors, frame=frame, playbook=playbook, audit=audit, validated=validated,
                                validation_stage=validation_stage)
            return replace(result, generation_receipt=receipt(state))

        class PromptCompileFailure(Exception):
            pass

        def compile_task(task: str, **kwargs) -> str:
            nonlocal budget_reason, current_task
            current_task = task
            if budget_for_task is not None:
                task_results[task] = "not_sent"
            try:
                if budget_for_task is None:
                    prompt = self.compiler.compile(frame=frame, playbook=playbook, task=task, **kwargs)
                else:
                    try:
                        budget = budget_for_task(task)
                    except BudgetError:
                        raise
                    except Exception:
                        raise BudgetError("count_unknown", "budget_unavailable") from None
                    prompt = self.compiler.compile(frame=frame, playbook=playbook, task=task, budget=budget, **kwargs)
                    if not isinstance(prompt, CompiledPrompt):
                        raise BudgetError("count_unknown", "compiler_not_budget_aware")
                    chosen = prompt.selection
                    if any(previous.coverage == "selected" for previous in selections.values()):
                        chosen = replace(chosen, coverage="selected")
                    selections[task] = chosen
                    prompt = prompt.text
            except BudgetError as exc:
                budget_reason = exc.reason if exc.reason in {"budget_exhausted", "count_unknown"} else "count_unknown"
                errors.append(budget_reason)
                task_results[task] = "not_sent"
                raise PromptCompileFailure from None
            except Exception as exc:
                error_class = type(exc).__name__
                if not error_class.isascii() or not error_class.isidentifier():
                    error_class = "UnknownError"
                trace.record(state=f"compile_failed:{error_class}", kind="prompt_compile",
                             payload={"task": task})
                errors.append(_exception_code("prompt_compile_error", exc))
                raise PromptCompileFailure from None
            trace.record(state="compile_succeeded", kind="prompt_compile", payload={"task": task})
            return prompt

        def invoke(task: str, prompt: str):
            nonlocal budget_reason
            if budget_for_task is None:
                return self.model(task, prompt)
            task_results[task] = "not_sent"
            budgeted = getattr(self.model, "invoke_budgeted", None)
            if not callable(budgeted):
                budget_reason = "dispatch_tracking_unavailable"
                raise MioModelUnavailable("dispatch_tracking_unavailable")
            active = True
            notification_conflict = False
            def on_dispatch():
                nonlocal notification_conflict
                if not active:
                    raise RuntimeError("invalid_dispatch_notification")
                if calls_sent[task] != 0:
                    notification_conflict = True
                    raise RuntimeError("invalid_dispatch_notification")
                calls_sent[task] = 1
                task_results[task] = "sent"
            try:
                result = budgeted(task, prompt, on_dispatch)
                if notification_conflict:
                    raise MioModelUnavailable("send_notification_conflict")
                if not calls_sent[task]:
                    budget_reason = "dispatch_tracking_unavailable"
                    raise MioModelUnavailable("dispatch_notification_missing")
                return result
            finally:
                active = False
                if notification_conflict:
                    budget_reason = "send_notification_conflict"
                # Only a dispatched call can have usage. This explicit
                # per-task adapter hook is best-effort and never inferred.
                if calls_sent[task]:
                    try:
                        get_usage = getattr(self.model, "usage_for_task", None)
                        if callable(get_usage):
                            observed = get_usage(task)
                            if (type(observed) is dict and set(observed) == {"input_tokens", "output_tokens"}
                                    and all(type(v) is int and v >= 0 for v in observed.values())):
                                usage[task] = dict(observed)
                    except Exception:
                        pass

        def enter_model_adapter(task: str) -> None:
            trace.record(state="adapter_entered", kind="model_adapter", payload={"task": task})

        def response_valid(task: str, prompt: str, raw: Any) -> bool:
            if not strict_model_response and budget_for_task is None:
                return True
            try:
                valid = validate_model_response(raw, compiled_model_response_schema(task, prompt))
                if valid and budget_for_task is not None:
                    if task in ("generate_hypotheses", "update_hypotheses"):
                        valid = len(raw["hypotheses"]) <= self.budget.max_hypotheses and all(MioHypothesis.from_mapping(item, ordinal=i + 1).to_dict() == item
                                    for i, item in enumerate(raw["hypotheses"]))
                    elif task == "identify_evidence_gaps":
                        valid = len(raw["evidence_gaps"]) <= self.budget.max_gaps
                        for i, item in enumerate(raw["evidence_gaps"]):
                            gap = MioEvidenceGap.from_mapping(item, ordinal=i + 1)
                            if {"gap_id": gap.gap_id, "question": gap.question,
                                "discriminates_hypothesis_ids": list(gap.discriminates_hypothesis_ids),
                                "capability": gap.capability, "priority": gap.priority} != item:
                                valid = False
                                break
                    else:
                        rec = MioRecommendation.from_mapping(raw, advisory_id="budget-validation")
                        valid = {"summary": rec.summary, "recommended_action": rec.recommended_action,
                                 "rationale": rec.rationale, "evidence_refs": list(rec.evidence_refs),
                                 "limitations": list(rec.limitations)} == raw
            except (TypeError, ValueError, KeyError, RecursionError):
                valid = False
            if not valid:
                errors.append("output_invalid")
            return valid

        trace.record(state=ReasoningState.FRAME_READY.value, kind="frame", payload={"frame_id": frame.frame_id, "frame_material_digest": "sha256:" + frame.canonical_digest()})
        selection = guard_selection(playbook, selection)  # invalid playbook -> generic, never compiled
        playbook = selection.playbook
        trace.record(state=ReasoningState.FRAME_READY.value, kind="reasoning_provenance", payload=reasoning_provenance(playbook, selection))
        if selection.is_generic_fallback:
            errors.append(f"generic_fallback:{selection.reason}")
            _LOG.warning("mio generic playbook fallback cycle=%s reason=%s", str(cycle_id)[:96], selection.reason)
        if selection.mode == GENERIC_UNVERIFIED_MODE:
            # No further fallback: never compile or hand off an unverified playbook.
            playbook = None
            return finish(ReasoningState.VALIDATION_REJECTED, (), (), None)
        bad_status: list[str] = []

        if frame.freshness_seconds > max(0, int(self.budget.max_frame_age_seconds)):
            errors.append('frame_stale')
            return finish(ReasoningState.STALE_SUPERSEDED, (), (), None)
        interrupted = self._interrupted(cancel_check, stale_check, errors)
        if interrupted is not None:
            return finish(interrupted, (), (), None)

        if self.model is None:
            errors.append("model_absent")
            return finish(ReasoningState.DEPENDENCY_UNAVAILABLE, (), (), None)
        if model_calls >= self.budget.max_model_calls:
            # Guard the first adapter entry too: a zero model-call budget must never call the model.
            errors.append("model_budget_exhausted_before_hypothesis_generation")
            return finish(ReasoningState.BUDGET_EXHAUSTED, (), (), None)

        try:
            prompt = compile_task("generate_hypotheses")
        except PromptCompileFailure:
            return finish(ReasoningState.BUDGET_EXHAUSTED if budget_reason else ReasoningState.ERROR_FALLBACK, (), (), None)

        validation_stage = "generate_hypotheses"
        enter_model_adapter("generate_hypotheses")
        try:
            raw_h = invoke("generate_hypotheses", prompt)
            model_calls += 1
        except (MioModelBlocked, MioModelUnavailable) as exc:
            errors.append(_exception_code("model_dependency_unavailable", exc))
            return finish(ReasoningState.DEPENDENCY_UNAVAILABLE, (), (), None)
        except Exception as exc:
            errors.append(_exception_code("model_hypothesis_error", exc))
            return finish(ReasoningState.ERROR_FALLBACK, (), (), None)

        interrupted = self._interrupted(cancel_check, stale_check, errors)
        if interrupted is not None:
            return finish(interrupted, (), (), None)

        if not response_valid("generate_hypotheses", prompt, raw_h):
            return finish(ReasoningState.VALIDATION_REJECTED, (), (), None)
        items = raw_h.get("hypotheses", []) if isinstance(raw_h, Mapping) else []
        if not isinstance(items, list):
            errors.append("hypotheses_not_list")
            return finish(ReasoningState.VALIDATION_REJECTED, (), (), None)
        required_hypotheses = max(1, min(2, len(playbook.hypothesis_prompts)))
        trusted_alternatives = dict(playbook.hypothesis_alternatives)
        selected_alternatives: list[str] = []
        for item in items[: self.budget.max_hypotheses]:
            if not isinstance(item, Mapping):
                continue
            alternative_id = item.get("hypothesis_alternative_id")
            if type(alternative_id) is not str or alternative_id not in trusted_alternatives:
                errors.append("unknown_hypothesis_alternative_id")
                return finish(ReasoningState.VALIDATION_REJECTED, (), (), None)
            selected_alternatives.append(alternative_id)
        if len(selected_alternatives) < required_hypotheses:
            errors.append("insufficient_competing_hypotheses")
            return finish(ReasoningState.VALIDATION_REJECTED, (), (), None)
        if len(set(selected_alternatives)) != len(selected_alternatives):
            errors.append("duplicate_hypothesis_alternative_id")
            return finish(ReasoningState.VALIDATION_REJECTED, (), (), None)
        if required_hypotheses > 1 and not any(
                trusted_alternatives[value] in {"benign", "unresolved"} for value in selected_alternatives):
            errors.append("missing_benign_or_unresolved_alternative_slot")
            return finish(ReasoningState.VALIDATION_REJECTED, (), (), None)
        hypotheses = tuple(
            MioHypothesis.from_mapping(item, ordinal=i + 1)
            for i, item in enumerate(items[: self.budget.max_hypotheses])
            if isinstance(item, Mapping)
        )
        if len(hypotheses) < required_hypotheses:
            errors.append("insufficient_competing_hypotheses")
            return finish(ReasoningState.VALIDATION_REJECTED, (), (), None)
        bad_status.extend(unparseable_status_ids(items[: self.budget.max_hypotheses]))
        h_check = GroundingValidator(frame).validate_hypotheses(hypotheses)
        if not h_check.ok:
            errors.extend(h_check.errors)
            return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, (), None)
        initial_errors = validate_initial_hypotheses(hypotheses)
        if initial_errors:
            errors.extend(initial_errors)
            return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, (), None)
        hypotheses, scoped_claims = scope_hypotheses_to_frame(hypotheses, frame=frame, playbook=playbook)
        if scoped_claims:
            trace.record(state=ReasoningState.HYPOTHESES_READY.value, kind="semantic_scope_filter",
                         payload={"filtered": [{"hypothesis_id": hypothesis_id,
                             "claim_classes": list(classes)} for hypothesis_id, classes in scoped_claims]})
        audit.extend(record_initial(hypotheses))
        validated[:] = hypotheses
        trace.record(state=ReasoningState.HYPOTHESES_READY.value, kind="hypotheses", payload={"ids": [h.hypothesis_id for h in hypotheses]})
        trace.record(state=ReasoningState.HYPOTHESES_READY.value, kind="hypothesis_alternative_slots",
                     payload={"slots": [{"hypothesis_id": h.hypothesis_id,
                         "alternative_id": h.hypothesis_alternative_id,
                         "proposed_role": trusted_alternatives[h.hypothesis_alternative_id],
                         "verification": "model_proposed_unverified"} for h in hypotheses]})

        if budget_for_task is not None:
            task_results["generate_hypotheses"] = "validated"
        if model_calls >= self.budget.max_model_calls:
            errors.append("model_budget_exhausted_before_gap_planning")
            return finish(ReasoningState.BUDGET_EXHAUSTED, hypotheses, (), None)
        try:
            prompt = compile_task("identify_evidence_gaps", hypotheses=hypotheses)
        except PromptCompileFailure:
            return finish(ReasoningState.BUDGET_EXHAUSTED if budget_reason else ReasoningState.ERROR_FALLBACK, hypotheses, (), None)
        validation_stage = "identify_evidence_gaps"
        enter_model_adapter("identify_evidence_gaps")
        try:
            raw_g = invoke("identify_evidence_gaps", prompt)
            model_calls += 1
        except (MioModelBlocked, MioModelUnavailable) as exc:
            errors.append(_exception_code("model_dependency_unavailable", exc))
            return finish(ReasoningState.DEPENDENCY_UNAVAILABLE, hypotheses, (), None)
        except Exception as exc:
            errors.append(_exception_code("model_gap_error", exc))
            return finish(ReasoningState.ERROR_FALLBACK, hypotheses, (), None)
        if not response_valid("identify_evidence_gaps", prompt, raw_g):
            return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, (), None)
        gap_items = raw_g.get("evidence_gaps", []) if isinstance(raw_g, Mapping) else []
        if not isinstance(gap_items, list):
            gap_items = []
        auth_gap_context = is_authentication_context(frame, playbook)
        if auth_gap_context:
            # Do not parse or retain model-authored question/capability pairs
            # in this scope. Only deterministic frame-derived gaps may reach
            # validation, scoring, traces, or the broker.
            gaps = ()
            if gap_items:
                trace.record(state=ReasoningState.EVIDENCE_GAPS_IDENTIFIED.value,
                             kind="model_gap_questions_withheld",
                             payload={"count": min(len(gap_items), self.budget.max_gaps),
                                      "reason": "auth_scope_requires_trusted_gap_text"})
        else:
            gaps = tuple(
                MioEvidenceGap.from_mapping(item, ordinal=i + 1)
                for i, item in enumerate(gap_items[: self.budget.max_gaps])
                if isinstance(item, Mapping)
            )
        model_gap_ids = {gap.gap_id for gap in gaps}
        gaps = deterministic_authentication_gaps(
            frame=frame, playbook=playbook, hypotheses=hypotheses, existing=gaps,
            max_gaps=self.budget.max_gaps,
        )
        frame_gap_ids = [gap.gap_id for gap in gaps if gap.gap_id not in model_gap_ids]
        gap_check = GroundingValidator(frame).validate_evidence_gaps(
            gaps,
            hypotheses=hypotheses,
            allowed_capabilities=playbook.allowed_capabilities,
            registered_capabilities=broker.names(),
        )
        if not gap_check.ok:
            errors.extend(gap_check.errors)
            return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
        if budget_for_task is not None:
            task_results["identify_evidence_gaps"] = "validated"
        trace.record(state=ReasoningState.EVIDENCE_GAPS_IDENTIFIED.value, kind="evidence_gaps", payload={"ids": [g.gap_id for g in gaps]})
        if frame_gap_ids:
            trace.record(state=ReasoningState.EVIDENCE_GAPS_IDENTIFIED.value, kind="frame_derived_gaps",
                         payload={"ids": frame_gap_ids, "source": "situation_frame"})

        additional_refs: list[str] = []
        broker_summaries: list[dict[str, Any]] = []
        gap_scores = score_evidence_gaps(
            gaps, hypotheses=hypotheses, allowed_capabilities=playbook.allowed_capabilities,
            registered_capabilities=broker.names(), remaining_broker_calls=self.budget.max_broker_calls - broker_calls,
        )
        trace.record(
            state=ReasoningState.EVIDENCE_GAPS_IDENTIFIED.value, kind="evidence_gap_scores",
            payload={"policy_version": SCORING_POLICY_VERSION, "policy_digest": scoring_policy_digest(), "scores": [s.to_dict() for s in gap_scores]},
        )
        errors.extend(f"gap_not_eligible:{s.gap_id}:{r}" for s in gap_scores for r in s.ineligible_reasons)
        gap_by_id = {g.gap_id: g for g in gaps}
        for index, gap in enumerate(gap_by_id[s.gap_id] for s in gap_scores if s.eligible):
            interrupted = self._interrupted(cancel_check, stale_check, errors)
            if interrupted is not None:
                return finish(interrupted, hypotheses, gaps, None)
            if broker_calls >= self.budget.max_broker_calls:
                errors.append("broker_budget_exhausted")
                break
            if gap.capability not in playbook.allowed_capabilities:
                errors.append(f"capability_not_allowed_by_playbook:{capability_label(gap.capability, broker.names())}")
                continue
            request = MioCapabilityRequest(
                request_id=f"{cycle_id}:req:{index + 1}",
                trace_id=frame.trace_id,
                capability=gap.capability,
                arguments={"question": gap.question, "frame_id": frame.frame_id},
            )
            trace.record(
                state=ReasoningState.REQUEST_PLANNED.value,
                kind="capability_request",
                payload={"request_id": request.request_id, "capability": request.capability},
            )
            try:
                result = broker.execute(request)
                broker_calls += 1
            except CapabilityBrokerError as exc:
                errors.append(str(exc))
                continue
            if result.ok:  # only successful results count as broker-imported evidence
                additional_refs.extend(result.evidence_refs)
            broker_summaries.append(
                {
                    "request_id": result.request_id,
                    "capability": result.capability,
                    "ok": result.ok,
                    "data": dict(result.data),
                    "evidence_refs": list(result.evidence_refs),
                    "error": result.error,
                }
            )
            trace.record(
                state=ReasoningState.EVIDENCE_COLLECTED.value,
                kind="capability_result",
                payload={"request_id": result.request_id, "ok": result.ok, "evidence_refs": list(result.evidence_refs)},
            )

        # New evidence must be allowed to strengthen, weaken, falsify, or leave
        # hypotheses unresolved before a recommendation is produced. This step
        # is skipped when no capability returned a result, avoiding a pointless
        # model call on constrained hardware.
        if broker_summaries:
            if budget_for_task is not None:
                budget_reason = "task_plan_unsupported"
                current_task = None
                errors.append("task_plan_unsupported")
                return finish(ReasoningState.BUDGET_EXHAUSTED, hypotheses, gaps, None)
            if model_calls >= self.budget.max_model_calls:
                errors.append("model_budget_exhausted_before_hypothesis_update")
                return finish(ReasoningState.BUDGET_EXHAUSTED, hypotheses, gaps, None)
            interrupted = self._interrupted(cancel_check, stale_check, errors)
            if interrupted is not None:
                return finish(interrupted, hypotheses, gaps, None)
            try:
                prompt = compile_task("update_hypotheses", hypotheses=hypotheses,
                                      broker_results=broker_summaries)
            except PromptCompileFailure:
                return finish(ReasoningState.BUDGET_EXHAUSTED if budget_reason else ReasoningState.ERROR_FALLBACK, hypotheses, gaps, None)
            validation_stage = "update_hypotheses"
            enter_model_adapter("update_hypotheses")
            try:
                raw_u = invoke("update_hypotheses", prompt)
                model_calls += 1
            except (MioModelBlocked, MioModelUnavailable) as exc:
                errors.append(_exception_code("model_dependency_unavailable", exc))
                return finish(ReasoningState.DEPENDENCY_UNAVAILABLE, hypotheses, gaps, None)
            except Exception as exc:
                errors.append(_exception_code("model_hypothesis_update_error", exc))
                return finish(ReasoningState.ERROR_FALLBACK, hypotheses, gaps, None)
            if not response_valid("update_hypotheses", prompt, raw_u):
                return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
            if not isinstance(raw_u, Mapping):
                errors.append("hypothesis_update_not_mapping")
                return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
            raw_update_check = GroundingValidator(frame, additional_evidence_refs=additional_refs).validate_raw(raw_u)
            if not raw_update_check.ok:
                errors.extend(raw_update_check.errors)
                return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
            update_items = raw_u.get("hypotheses", [])
            if not isinstance(update_items, list):
                errors.append("updated_hypotheses_not_list")
                return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
            bad_status.extend(unparseable_status_ids(update_items[: self.budget.max_hypotheses]))
            updated_hypotheses = tuple(
                MioHypothesis.from_mapping(item, ordinal=i + 1)
                for i, item in enumerate(update_items[: self.budget.max_hypotheses])
                if isinstance(item, Mapping)
            )
            prior_slots = {h.hypothesis_id: h.hypothesis_alternative_id for h in hypotheses}
            for updated in updated_hypotheses:
                slot_id = updated.hypothesis_alternative_id
                if slot_id not in trusted_alternatives:
                    errors.append("unknown_hypothesis_alternative_id")
                    return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
                if updated.hypothesis_id in prior_slots and slot_id != prior_slots[updated.hypothesis_id]:
                    errors.append("hypothesis_alternative_id_changed")
                    return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
            updated_check = GroundingValidator(frame, additional_evidence_refs=additional_refs).validate_hypotheses(updated_hypotheses)
            if not updated_check.ok:
                errors.extend(updated_check.errors)
                return finish(ReasoningState.VALIDATION_REJECTED, updated_hypotheses, gaps, None)
            updated_hypotheses, scoped_updates = scope_hypotheses_to_frame(
                updated_hypotheses, frame=frame, playbook=playbook, prior_hypotheses=hypotheses)
            if scoped_updates:
                trace.record(state=ReasoningState.HYPOTHESES_UPDATED.value, kind="semantic_scope_filter",
                             payload={"filtered": [{"hypothesis_id": hypothesis_id,
                                 "claim_classes": list(classes)} for hypothesis_id, classes in scoped_updates]})
            lifecycle = apply_hypothesis_update(
                hypotheses,
                updated_hypotheses,
                allowed_refs=set(frame.evidence_refs) | set(frame.knowledge_refs) | set(additional_refs),
            )
            if not lifecycle.ok:
                errors.extend(lifecycle.errors)
                return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
            live_hypotheses = tuple(h for h in lifecycle.hypotheses
                                    if h.status not in {HypothesisStatus.FALSIFIED, HypothesisStatus.SUPERSEDED})
            live_slots = [h.hypothesis_alternative_id for h in live_hypotheses]
            if None in live_slots or len(live_slots) != len(set(live_slots)):
                errors.append("duplicate_live_hypothesis_alternative_slot")
                return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
            audit.extend(lifecycle.audit)
            hypotheses = lifecycle.hypotheses
            validated[:] = hypotheses
            trace.record(
                state=ReasoningState.HYPOTHESES_UPDATED.value,
                kind="hypotheses_updated",
                payload={"ids": [h.hypothesis_id for h in hypotheses], "evidence_refs": list(dict.fromkeys(additional_refs))[:32]},
            )
            trace.record(state=ReasoningState.HYPOTHESES_UPDATED.value, kind="hypothesis_alternative_slots",
                         payload={"slots": [{"hypothesis_id": h.hypothesis_id,
                             "alternative_id": h.hypothesis_alternative_id,
                             "proposed_role": trusted_alternatives.get(h.hypothesis_alternative_id),
                             "verification": "model_proposed_unverified"} for h in hypotheses]})

        if model_calls >= self.budget.max_model_calls:
            errors.append("model_budget_exhausted_before_recommendation")
            return finish(ReasoningState.BUDGET_EXHAUSTED, hypotheses, gaps, None)
        interrupted = self._interrupted(cancel_check, stale_check, errors)
        if interrupted is not None:
            return finish(interrupted, hypotheses, gaps, None)

        try:
            prompt = compile_task("recommend", hypotheses=hypotheses, broker_results=broker_summaries)
        except PromptCompileFailure:
            return finish(ReasoningState.BUDGET_EXHAUSTED if budget_reason else ReasoningState.ERROR_FALLBACK, hypotheses, gaps, None)
        validation_stage = "recommend"
        enter_model_adapter("recommend")
        try:
            raw_r = invoke("recommend", prompt)
            model_calls += 1
        except (MioModelBlocked, MioModelUnavailable) as exc:
            errors.append(_exception_code("model_dependency_unavailable", exc))
            return finish(ReasoningState.DEPENDENCY_UNAVAILABLE, hypotheses, gaps, None)
        except Exception as exc:
            errors.append(_exception_code("model_recommend_error", exc))
            return finish(ReasoningState.ERROR_FALLBACK, hypotheses, gaps, None)
        # Cancel/stale may flip during the final model call; never complete over it.
        interrupted = self._interrupted(cancel_check, stale_check, errors)
        if interrupted is not None:
            return finish(interrupted, hypotheses, gaps, None)
        if not response_valid("recommend", prompt, raw_r):
            return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
        if not isinstance(raw_r, Mapping):
            errors.append("recommendation_not_mapping")
            return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
        raw_check = GroundingValidator(frame, additional_evidence_refs=additional_refs).validate_raw(raw_r)
        if not raw_check.ok:
            errors.extend(raw_check.errors)
            return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
        recommendation = MioRecommendation.from_mapping(raw_r, advisory_id=f"{cycle_id}:advisory")
        auth_context = is_authentication_context(frame, playbook)
        scope_errors = claim_scope_violations(
            (recommendation.summary, recommendation.rationale) + recommendation.limitations,
            playbook=playbook,
        )
        if auth_context:
            if scope_errors:
                trace.record(state=ReasoningState.RECOMMENDATION_READY.value, kind="semantic_scope_filter",
                             payload={"target": "recommendation", "claim_classes": list(scope_errors),
                                      "projection": "trusted_static_auth_text"})
            recommendation = ground_auth_recommendation(recommendation)
        elif scope_errors:
            errors.extend(f"unsupported_recommendation_claim:{value}" for value in scope_errors)
            trace.record(state=ReasoningState.VALIDATION_REJECTED.value, kind="semantic_scope_filter",
                         payload={"target": "recommendation", "claim_classes": list(scope_errors)})
            return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None)
        rec_check = GroundingValidator(frame, additional_evidence_refs=additional_refs).validate_recommendation(recommendation)
        claim_audit = audit_claims(frame, hypotheses=hypotheses, recommendation=recommendation, imported_refs=additional_refs, unparseable_status=bad_status)
        trace.record(state=ReasoningState.RECOMMENDATION_READY.value, kind="claim_audit", payload=claim_audit.to_dict())
        if rec_check.ok and not claim_audit.ok:
            errors.extend(claim_audit.errors())
            return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, recommendation)
        if not rec_check.ok:
            errors.extend(rec_check.errors)
            return finish(ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, recommendation)
        if budget_for_task is not None:
            task_results["recommend"] = "validated"
        trace.record(
            state=ReasoningState.RECOMMENDATION_READY.value,
            kind="recommendation",
            payload={
                "advisory_id": recommendation.advisory_id,
                "recommendation_material_digest": recommendation.canonical_digest(),
                "recommended_action": recommendation.recommended_action,
                "evidence_refs": list(recommendation.evidence_refs),
                "executable": False,
            },
        )
        trace.record(
            state=ReasoningState.COMPLETE.value,
            kind="complete",
            payload={"model_calls": model_calls, "broker_calls": broker_calls},
        )
        objectives, projection = project_observation_report(
            frame=frame, playbook_id=playbook.playbook_id, state=ReasoningState.COMPLETE,
            hypotheses=hypotheses, gaps=gaps,
            eligible_gap_ids=frozenset(s.gap_id for s in gap_scores if s.eligible),
            max_gaps=self.budget.max_gaps)
        return ReasoningOutcome(ReasoningState.COMPLETE, hypotheses, gaps, recommendation, tuple(errors), trace.events(), tuple(audit),
                                observation_objectives=objectives, observation_projection=projection,
                                generation_receipt=receipt(ReasoningState.COMPLETE))

    @staticmethod
    def _finish(
        trace: ReasoningTrace,
        state: ReasoningState,
        hypotheses: Sequence[MioHypothesis],
        gaps: Sequence[MioEvidenceGap],
        recommendation: MioRecommendation | None,
        errors: Sequence[str],
        *,
        frame: MioSituationFrame,
        playbook: ReasoningPlaybook,
        audit: list[HypothesisAuditEntry],
        validated: Sequence[MioHypothesis],
        validation_stage: str = "unknown",
    ) -> ReasoningOutcome:
        if state is ReasoningState.STALE_SUPERSEDED:
            # In-flight hypotheses of a dead cycle are retained, marked superseded.
            audit.extend(supersede_all(validated, REASON_CYCLE_SUPERSEDED))
        elif state is ReasoningState.OPERATOR_CANCELLED:
            audit.extend(supersede_all(validated, REASON_CYCLE_CANCELLED))
        handoff = None
        if state in HANDOFF_STATES:
            handoff = build_no_model_handoff(frame, reason=state.value, playbook=playbook, hypotheses=validated)
        trace.record(state=state.value, kind="terminal", payload={"errors": list(errors)[:8]})
        # Non-COMPLETE terminals never project; record only the state-level skip.
        _, skip_report = project_observation_report(
            frame=frame, playbook_id=playbook.playbook_id, state=state,
            hypotheses=(), gaps=(), eligible_gap_ids=())
        return ReasoningOutcome(state, tuple(hypotheses), tuple(gaps), recommendation, tuple(errors), trace.events(), tuple(audit), handoff,
                                _validation_diagnostic(validation_stage, errors)
                                if state is ReasoningState.VALIDATION_REJECTED else None,
                                observation_projection=skip_report)

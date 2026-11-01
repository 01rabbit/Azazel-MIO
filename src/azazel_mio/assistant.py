"""Product-neutral composition over the bounded reasoning core (internal API v1)."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import html
import re
from typing import Any, Mapping, Sequence

from .broker import CapabilityBroker
from .contracts import ContextDependencyOutcome, MioSituationFrame, ReasoningState
from .playbook import DEFAULT_PLAYBOOKS, PromptCompiler, select_playbook
from .contracts import model_id_ok
from .handoff import build_no_model_handoff
from .reasoning import BoundedReasoningLoop
from .lifecycle import ReasoningCoordinator
from .tactical_grounding import (
    AUTH_PLAYBOOK_ID,
    authentication_frame_unknowns,
    is_authentication_context,
)


# Exact legacy fact label retained for callers that summarize a detected
# honeypot interaction. known_facts may also contain attacker-derived strings.
_DECEPTION_RELEVANT_FACTS = frozenset({"HONEYPOT_INTERACTION_OBSERVED"})


@dataclass(frozen=True)
class VerifiedKnowledgeContext:
    source: str
    generation: str
    as_of: str
    expires_at: str
    facts: tuple[str, ...]
    inferences: tuple[str, ...]
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class StaticKnowledgeReference:
    """Versioned Knowledge material; its metadata does not establish trust.

    The adapter must establish bundle origin before constructing this value.
    Neither generation nor as_of asserts that a claim remains current.
    """
    source: str
    generation: str
    as_of: str
    text: str
    evidence_refs: tuple[str, ...] = ()
    digest: str = ""


@dataclass(frozen=True)
class ReportedKnowledgeContext:
    """Date-bounded source report, kept explicitly unverified by M.I.O.

    Constructing this value does not authenticate the producer. Product
    adapters own origin verification, consent, and generation invalidation.
    """
    source: str
    generation: str
    as_of: str
    expires_at: str
    reported_claims: tuple[str, ...]
    record_refs: tuple[str, ...] = ()
    source_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class KnowledgeLiteAdvisory:
    """A source-cited Knowledge Lite claim, never verified grounding.

    `current` freshness is captured as `current_at_lookup`; callers must
    recheck it against their clock before reuse because Knowledge Lite has no
    per-claim expiry. `expires_at` is optional and is never inferred.
    `citation` identifies the claim; optional `source_citation` is separate,
    untrusted dataset display text. An empty summary stays empty.
    """
    technique_id: str
    name: str
    summary: str
    claim_id: str
    bundle_digest: str
    freshness: str
    generation: str
    as_of: str
    citation: str
    revocation_status: str
    trust_check: str = "verified"
    expires_at: str | None = None
    source_citation: str | None = None


@dataclass(frozen=True)
class Assistance:
    _payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self._payload)


def _time(value: str) -> datetime:
    if type(value) is not str or len(value) > 64:
        raise ValueError("invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("timezone_required")
    return parsed.astimezone(timezone.utc)


def _texts(value: Any, *, cap: int, size: int) -> bool:
    return (type(value) is tuple and len(value) <= cap and
            all(type(x) is str and 0 < len(x) <= size and
                not any(ord(c) < 32 for c in x) for x in value))


def _public_reasoning_trace(events: Sequence[Any]) -> list[dict[str, Any]]:
    """Expose the narrow slot audit without projecting free-text trace payloads."""
    result: list[dict[str, Any]] = []
    allowed_roles = {"hostile", "benign", "unresolved"}
    for event in events:
        # Rejected model output is diagnostic input only. Do not expose its
        # claim or reference identifiers through the public trace.
        if event.state == ReasoningState.VALIDATION_REJECTED.value:
            continue
        item = {"state": str(event.state)[:64], "kind": str(event.kind)[:64]}
        if event.kind == "hypothesis_alternative_slots":
            raw_slots = event.payload.get("slots", ()) if isinstance(event.payload, Mapping) else ()
            slots = []
            if isinstance(raw_slots, (list, tuple)):
                for raw in raw_slots[:4]:
                    if not isinstance(raw, Mapping):
                        continue
                    hypothesis_id = raw.get("hypothesis_id")
                    alternative_id = raw.get("alternative_id")
                    if type(hypothesis_id) is not str or type(alternative_id) is not str:
                        continue
                    role = raw.get("proposed_role")
                    slots.append({
                        "hypothesis_id": hypothesis_id[:16],
                        "alternative_id": alternative_id[:64],
                        "proposed_role": role if type(role) is str and role in allowed_roles else "unresolved",
                        "verification": "model_proposed_unverified",
                    })
            item["payload"] = {"slots": slots}
        result.append(item)
    return result


def _context(value: Any, now: datetime) -> dict[str, Any] | None:
    if type(value) is not VerifiedKnowledgeContext:
        return None
    if not all(type(x) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", x)
               for x in (value.source, value.generation)):
        return None
    if not (_texts(value.facts, cap=16, size=480) and
            _texts(value.inferences, cap=16, size=480) and
            _texts(value.evidence_refs, cap=32, size=128)):
        return None
    try:
        start, end = _time(value.as_of), _time(value.expires_at)
    except ValueError:
        return None
    if start > now or end <= now or end <= start:
        return None
    return {"source": value.source, "generation": value.generation,
            "as_of": value.as_of, "expires_at": value.expires_at,
            "facts": list(value.facts), "inferences": list(value.inferences),
            "evidence_refs": list(value.evidence_refs)}


def _static_reference(value: Any, now: datetime) -> dict[str, Any] | None:
    if type(value) is not StaticKnowledgeReference:
        return None
    if not all(type(x) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", x)
               for x in (value.source, value.generation)):
        return None
    if type(value.as_of) is not str or len(value.as_of) > 64:
        return None
    try:
        as_of = _time(value.as_of)
    except ValueError:
        return None
    if as_of > now:
        return None
    if (type(value.text) is not str or not 0 < len(value.text) <= 2000 or
            any(ord(c) < 32 and c not in "\n\t" for c in value.text)):
        return None
    if not _texts(value.evidence_refs, cap=16, size=128):
        return None
    try:
        expected = "sha256:" + hashlib.sha256(value.text.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:
        return None
    if type(value.digest) is not str or value.digest != expected:
        return None
    return {"kind": "static_knowledge_reference", "source": value.source,
            "generation": value.generation, "as_of": value.as_of,
            "text": value.text, "digest": value.digest,
            "evidence_refs": list(value.evidence_refs),
            "temporal_validity": "not_asserted",
            "trust": "adapter_origin_not_verified_by_metadata"}


def _reported_context(value: Any, now: datetime) -> dict[str, Any] | None:
    if type(value) is not ReportedKnowledgeContext:
        return None
    if not all(type(x) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", x)
               for x in (value.source, value.generation)):
        return None
    if not (_texts(value.reported_claims, cap=16, size=480) and
            _texts(value.record_refs, cap=32, size=128) and
            _texts(value.source_refs, cap=16, size=128)):
        return None
    try:
        start, end = _time(value.as_of), _time(value.expires_at)
    except ValueError:
        return None
    if start > now or end <= now or end <= start:
        return None
    return {"kind": "source_reported_knowledge_context",
            "claim_status": "reported_unverified",
            "source": value.source, "generation": value.generation,
            "as_of": value.as_of, "expires_at": value.expires_at,
            "reported_claims": list(value.reported_claims),
            "record_refs": list(value.record_refs),
            "source_refs": list(value.source_refs),
            "trust": "adapter_origin_not_verified_by_metadata"}


_KNOWLEDGE_LITE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}")
_KNOWLEDGE_LITE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _source_citation_ok(value: Any) -> bool:
    """Accept bounded, already-cleaned source display text without rewriting it."""
    if type(value) is not str or len(value) > 160 or any(not c.isprintable() for c in value):
        return False
    # Match the Knowledge citation plain-text policy, retaining dataset underscores.
    plain = html.unescape(value)
    plain = re.sub(r"<[^>]*>", " ", plain)
    plain = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", plain)
    plain = re.sub(r"https?://\S+|www\.\S+", " ", plain)
    plain = plain.translate(str.maketrans("", "", "`*#"))
    return " ".join(plain.split()) == value


def _knowledge_lite_advisory(value: Any, now: datetime) -> dict[str, Any] | None:
    if type(value) is not KnowledgeLiteAdvisory:
        return None
    if not all(type(x) is str and _KNOWLEDGE_LITE_ID.fullmatch(x) for x in
               (value.technique_id, value.claim_id, value.generation)):
        return None
    if type(value.bundle_digest) is not str or not _KNOWLEDGE_LITE_DIGEST.fullmatch(value.bundle_digest):
        return None
    if type(value.freshness) is not str or value.freshness not in ("current", "static"):
        return None
    if (type(value.trust_check) is not str or value.trust_check != "verified" or
            type(value.revocation_status) is not str or
            value.revocation_status not in ("clear", "unknown", "revoked")):
        return None
    if value.revocation_status == "revoked":
        return None
    if (type(value.name) is not str or not 0 < len(value.name) <= 160 or
            any(ord(c) < 32 for c in value.name)):
        return None
    if (type(value.summary) is not str or len(value.summary) > 1200 or
            any(ord(c) < 32 and c not in "\n\t" for c in value.summary)):
        return None
    if type(value.citation) is not str or not _KNOWLEDGE_LITE_ID.fullmatch(value.citation):
        return None
    if value.source_citation is not None and not _source_citation_ok(value.source_citation):
        return None
    try:
        as_of = _time(value.as_of)
    except ValueError:
        return None
    if as_of > now:
        return None
    if value.expires_at is not None:
        try:
            expiry = _time(value.expires_at)
        except ValueError:
            return None
        if expiry <= now or expiry <= as_of:
            return None
    projection = {
        "kind": "knowledge_lite_advisory", "source_kind": "knowledge_lite",
        "claim_status": "reported_unverified", "technique_id": value.technique_id,
        "name": value.name, "summary": value.summary, "claim_id": value.claim_id,
        "bundle_digest": value.bundle_digest, "freshness": value.freshness,
        "temporal_validity": "current_at_lookup" if value.freshness == "current" else "static",
        "generation": value.generation, "as_of": value.as_of,
        "expires_at": value.expires_at, "citation": value.citation,
        "trust_check": value.trust_check, "revocation_status": value.revocation_status,
        "trust": "unverified_advisory_only" if value.revocation_status == "clear"
                 else "unverified_advisory_revocation_unknown",
    }
    if value.source_citation is not None:
        projection["source_citation"] = value.source_citation
    return projection


def _expired_context(value: Any, now: datetime) -> bool:
    """Recognize only typed, parseable date-bounded Knowledge projections."""
    if type(value) not in (VerifiedKnowledgeContext, ReportedKnowledgeContext):
        return False
    try:
        return _time(value.expires_at) <= now
    except ValueError:
        return False


def _frame_dependency_outcome(status: str) -> ContextDependencyOutcome:
    return {
        "available": ContextDependencyOutcome.AVAILABLE,
        "not_provided": ContextDependencyOutcome.ABSENT,
        "timeout": ContextDependencyOutcome.TIMEOUT,
        "unavailable": ContextDependencyOutcome.UNAVAILABLE,
        "malformed": ContextDependencyOutcome.REJECTED,
    }.get(status, ContextDependencyOutcome.REJECTED)


class _KnowledgeCompiler(PromptCompiler):
    def __init__(self, contexts):
        super().__init__()
        self.contexts = contexts

    def compile(self, **kwargs):
        kwargs["broker_results"] = list(kwargs.get("broker_results", ())) + [
            ({"kind": "verified_knowledge_context", **item}
             if "kind" not in item else item) for item in self.contexts]
        return super().compile(**kwargs)


class AssistantCore:
    """Explain accepted observations; neither execute nor authorize anything.

    Product adapters must cancel/supersede work on boot, material generation or
    consent changes. `now` belongs to their clock, not to the model or a peer.
    """

    def __init__(self, model=None, *, coordinator: ReasoningCoordinator | None = None):
        self.model = model
        self.coordinator = coordinator

    def explain(self, frame: MioSituationFrame, *, knowledge=(), references=(),
                reported_knowledge=(), now: str,
                knowledge_lite_advisories=(), knowledge_attempted: bool = True,
                cancel_check=None, stale_check=None) -> Assistance:
        if type(knowledge_attempted) is not bool:
            raise TypeError("knowledge_attempted_must_be_bool")
        instant = _time(now)
        # Rebuild even a directly constructed dataclass through the closed,
        # bounded v2 frame validator before interpreting it.
        frame = MioSituationFrame.from_dict(frame.to_dict())
        contexts: list[dict[str, Any]] = []
        static_references: list[dict[str, Any]] = []
        reported_contexts: list[dict[str, Any]] = []
        lite_advisories: list[dict[str, Any]] = []
        rejected = False
        knowledge_expired = False
        if type(knowledge) not in (tuple, list) or len(knowledge) > 4:
            rejected = True
        else:
            for item in knowledge:
                projected = _context(item, instant)
                if projected is None:
                    rejected = True
                    knowledge_expired = knowledge_expired or _expired_context(item, instant)
                else:
                    contexts.append(projected)
        if type(references) not in (tuple, list) or len(references) > 8:
            rejected = True
        else:
            for item in references:
                projected = _static_reference(item, instant)
                if projected is None:
                    rejected = True
                else:
                    static_references.append(projected)
        if type(reported_knowledge) not in (tuple, list) or len(reported_knowledge) > 4:
            rejected = True
        else:
            for item in reported_knowledge:
                projected = _reported_context(item, instant)
                if projected is None:
                    rejected = True
                    knowledge_expired = knowledge_expired or _expired_context(item, instant)
                else:
                    reported_contexts.append(projected)
        if type(knowledge_lite_advisories) not in (tuple, list) or len(knowledge_lite_advisories) > 8:
            rejected = True
        else:
            for item in knowledge_lite_advisories:
                projected = _knowledge_lite_advisory(item, instant)
                if projected is None:
                    rejected = True
                else:
                    lite_advisories.append(projected)
        refs = tuple(dict.fromkeys(ref for ctx in contexts + static_references for ref in ctx["evidence_refs"]
                                   if model_id_ok(ref, "evidence_ref")))[:32]
        reported_refs = tuple(dict.fromkeys(
            ref for ctx in reported_contexts
            for ref in ctx["record_refs"] + ctx["source_refs"]
            if model_id_ok(ref, "evidence_ref")))
        refs = tuple(dict.fromkeys(refs + reported_refs))[:32]
        if refs:
            payload = frame.to_dict()
            payload["knowledge_refs"] = list(refs)
            payload["knowledge_status"] = "available"
            payload["provenance"]["knowledge_refs"] = ["knowledge"]
            frame = MioSituationFrame.from_dict(payload)
        selection = select_playbook(frame)
        broker = CapabilityBroker()
        try:
            prompt_material = contexts + static_references + reported_contexts + lite_advisories
            loop = BoundedReasoningLoop(model=self.model, broker=broker, compiler=_KnowledgeCompiler(prompt_material))
            coordinator = self.coordinator
            ticket = None
            cycle_disposition = None
            if coordinator is not None:
                try:
                    ticket = coordinator.begin(frame)
                except RuntimeError as exc:
                    if str(exc) != "reasoning_coordinator_backpressure":
                        raise
                    cycle_disposition = "backpressure"
                if ticket is not None and ticket.deduplicated:
                    # This call is already represented by an in-flight request.
                    ticket = None
                    cycle_disposition = "in_flight_duplicate"
                elif ticket is not None:
                    original_cancel, original_stale = cancel_check, stale_check
                    def combined_cancel():
                        return (coordinator.cancel_check(ticket)() or
                                (original_cancel() if original_cancel is not None else False))
                    def combined_stale():
                        return (coordinator.stale_check(ticket)() or
                                (original_stale() if original_stale is not None else False))
                    cancel_check, stale_check = combined_cancel, combined_stale
            if coordinator is not None and ticket is None:
                # Backpressure or an identical in-flight request: answer with
                # the deterministic no-model path, without publishing model content.
                loop = BoundedReasoningLoop(model=None, broker=broker, compiler=_KnowledgeCompiler(prompt_material))
            try:
                outcome = loop.run(frame=frame, playbook=selection.playbook,
                                   cycle_id=ticket.cycle_id if ticket is not None else "cycle-1",
                                   selection=selection, cancel_check=cancel_check, stale_check=stale_check)
                if coordinator is not None and ticket is not None:
                    if outcome.state in {ReasoningState.OPERATOR_CANCELLED, ReasoningState.STALE_SUPERSEDED}:
                        coordinator.cancel_ticket(ticket, reason=outcome.state.value)
                    completion = coordinator.complete(ticket, outcome)
                    cycle_disposition = "current" if completion.accepted else completion.reason
            except BaseException:
                if coordinator is not None and ticket is not None:
                    coordinator.cancel_ticket(ticket, reason="cycle_failed")
                raise
        finally:
            broker.close()
        auth_context = is_authentication_context(frame, selection.playbook)
        interrupted = outcome.state in {
            ReasoningState.OPERATOR_CANCELLED, ReasoningState.STALE_SUPERSEDED}
        handoff = outcome.handoff.to_dict() if outcome.handoff is not None else None
        if outcome.state is ReasoningState.VALIDATION_REJECTED and handoff is not None:
            # A later-stage rejection may carry earlier, individually valid
            # model hypotheses in the no-model handoff. The cycle as a whole
            # is rejected, so its public handoff must be frame-only.
            handoff = build_no_model_handoff(
                frame, reason=outcome.state.value, playbook=selection.playbook).to_dict()
        hypotheses = [
            {**h.to_dict(), "verification": "model_proposed_unverified",
             **({"alternative_slot_verification": "model_proposed_unverified"}
                if h.hypothesis_alternative_id is not None else {})}
            for h in outcome.hypotheses
        ] if not interrupted and outcome.state is not ReasoningState.VALIDATION_REJECTED else []
        # Static alternatives are questions to discriminate, never observations
        # or asserted threat attribution. They remain labelled without a model.
        if not hypotheses and not interrupted:
            hypotheses = [{"kind": "static_alternative", "verification": "unverified",
                           "statement": "Observed symptoms may reflect a threat, a benign change, or missing telemetry.",
                           "supporting_evidence_refs": list(frame.evidence_refs),
                           "missing_evidence": list(authentication_frame_unknowns(frame))
                               if auth_context else []}]
        unknowns = list(frame.unknowns)
        if auth_context:
            for item in authentication_frame_unknowns(frame):
                if item not in unknowns:
                    unknowns.append(item)
        if self.model is None:
            unknowns.insert(0, "MODEL_NOT_AVAILABLE")
        if rejected:
            unknowns.insert(0, "KNOWLEDGE_CONTEXT_REJECTED")
        if knowledge_expired:
            unknowns.insert(0, "KNOWLEDGE_CONTEXT_EXPIRED")
        check_playbook = DEFAULT_PLAYBOOKS[AUTH_PLAYBOOK_ID] if auth_context else selection.playbook
        checks = list(check_playbook.discriminating_questions[:4])
        if not checks:
            checks = ["Confirm required communications remain reachable.",
                      "Check the latest observation and its timestamp with an authorized read-only source."]
        # These checks use only closed dependency outcomes and fixed text. They
        # never quote peer/model/caller prose and never suggest an Edge action.
        knowledge_outcome = _frame_dependency_outcome(frame.knowledge_status)
        if knowledge_expired:
            knowledge_outcome = ContextDependencyOutcome.EXPIRED
        elif contexts or reported_contexts or static_references:
            knowledge_outcome = ContextDependencyOutcome.AVAILABLE
        elif knowledge_outcome is ContextDependencyOutcome.ABSENT:
            if rejected and not lite_advisories:
                knowledge_outcome = ContextDependencyOutcome.REJECTED
            elif lite_advisories:
                knowledge_outcome = ContextDependencyOutcome.AVAILABLE
        if (knowledge_attempted is False and not rejected
                and not frame.knowledge_refs
                and not contexts and not static_references and not reported_contexts and not lite_advisories
                and not knowledge and not references and not reported_knowledge and not knowledge_lite_advisories
                and knowledge_outcome is ContextDependencyOutcome.ABSENT):
            knowledge_outcome = ContextDependencyOutcome.NOT_QUERIED
        deception_outcome = _frame_dependency_outcome(frame.deception_status)
        scenario_checks: list[str] = []
        if knowledge_outcome is ContextDependencyOutcome.NOT_QUERIED:
            scenario_checks.append(
                "This fast result did not query Knowledge; consult the separate validated Knowledge analysis lane for Knowledge context before relying on this assessment.")
        if selection.playbook.playbook_id == AUTH_PLAYBOOK_ID:
            scenario_checks.append(
                "Compare the observed authentication timing and counts with an approved automation schedule and authorized change record for that window; if neither is available, leave the benign explanation unresolved.")
        if any(re.fullmatch(r"Observed normalized event outcome:\s*allowed", fact, re.I)
               for fact in frame.known_facts):
            scenario_checks.append(
                "Clarify if 'allowed' means network acceptance or successful authentication; correlate event time/target with authentication and approved change/automation records before claiming access succeeded.")
        if knowledge_outcome is ContextDependencyOutcome.TIMEOUT:
            scenario_checks.append(
                "Confirm the Knowledge peer health and timed-out request timestamp through its authorized status view; request a fresh read-only retrieval only after service recovery.")
        elif knowledge_outcome is ContextDependencyOutcome.EXPIRED:
            scenario_checks.append(
                "Check the signed Knowledge response expiry against the adapter clock, then request a fresh authorized snapshot; do not reuse the expired context.")
        elif knowledge_outcome is ContextDependencyOutcome.REJECTED:
            scenario_checks.append(
                "Review the Knowledge adapter's closed validation result and response metadata through authorized diagnostics; do not reuse the rejected context.")
        elif knowledge_outcome is ContextDependencyOutcome.ABSENT:
            scenario_checks.append(
                "Confirm whether an authorized Knowledge context was requested and supplied for this frame.")
        deception_relevant = (
            selection.playbook.playbook_id == "deception-observation-v1"
            or bool(re.search(r"\b(?:deception|decoy|honeypot|az[-_ ]?06)\b",
                              " ".join((frame.mission, frame.soc_summary, frame.noc_summary)), re.I))
            # known_facts are bounded but may contain attacker-derived prose,
            # so only accept canonical fixed-label forms here, never sentences.
            or any(fact.upper() in _DECEPTION_RELEVANT_FACTS for fact in frame.known_facts)
        )
        if deception_relevant and deception_outcome is ContextDependencyOutcome.ABSENT:
            scenario_checks.append(
                "Confirm AZ-06 environment coverage and observation availability for the incident window; missing decoy telemetry does not establish that no decoy interaction occurred.")
        elif deception_relevant and deception_outcome is ContextDependencyOutcome.TIMEOUT:
            scenario_checks.append(
                "Confirm AZ-06 observation-service health and the timed-out request window through its authorized status view.")
        elif deception_relevant and deception_outcome in {ContextDependencyOutcome.REJECTED, ContextDependencyOutcome.UNAVAILABLE}:
            scenario_checks.append(
                "Confirm AZ-06 observation coverage and adapter status for the incident window; unavailable or rejected telemetry does not establish that no interaction occurred.")
        if scenario_checks:
            checks = list(dict.fromkeys(scenario_checks + checks))[:4]
        if lite_advisories:
            check = "Recheck the cited Knowledge Lite claim and its revocation status against an authorized current source before relying on it."
            checks = list(dict.fromkeys([check] + checks))[:4]
        payload = {
            "schema_version": "mio.assistance.v1", "trace_id": frame.trace_id,
            "frame_id": frame.frame_id,
            "generation_method": "model" if self.model is not None and outcome.hypotheses and outcome.state is not ReasoningState.VALIDATION_REJECTED else "static_reference",
            "state": outcome.state.value,
            "dependency_outcome": {
                "knowledge": knowledge_outcome.value,
                "deception": deception_outcome.value,
            },
            "observations": [] if interrupted else list(frame.known_facts),
            "hypotheses": hypotheses, "unknowns": unknowns[:24],
            "next_checks": [] if interrupted else checks,
            "knowledge": [] if interrupted else contexts + static_references + reported_contexts + lite_advisories,
            "handoff": handoff,
            "reasoning_trace": ([] if outcome.state is ReasoningState.VALIDATION_REJECTED
                                else _public_reasoning_trace(outcome.trace)),
        }
        if coordinator is not None:
            payload["cycle_disposition"] = cycle_disposition or "unknown"
            if cycle_disposition != "current":
                # The frame and dependency material belong to a rejected or
                # unstarted request. Do not expose them as a current answer.
                payload.update({
                    "generation_method": "static_reference", "observations": [],
                    "hypotheses": [], "unknowns": [], "next_checks": [],
                    "knowledge": [], "handoff": None, "reasoning_trace": [],
                    "dependency_outcome": {"knowledge": ContextDependencyOutcome.UNAVAILABLE.value,
                                           "deception": ContextDependencyOutcome.UNAVAILABLE.value},
                })
        return Assistance(payload)

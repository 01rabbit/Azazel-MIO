"""Product-neutral composition over the bounded reasoning core (internal API v1)."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import html
import ipaddress
import json
import re
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from .broker import CapabilityBroker
from .contracts import ContextDependencyOutcome, MioSituationFrame, ReasoningState
from .playbook import DEFAULT_PLAYBOOKS, PromptCompiler, select_playbook
from .contracts import model_id_ok
from .handoff import build_no_model_handoff
from .id_grammar import second_layer_ok
from .redaction import redact_text
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
class KnowledgeContextResponseAdvisory:
    """One Knowledge /v1/context response for bounded local projection.

    This wire input is never prompt material. Construction does not
    authenticate the producer or confer trust.
    """
    context_response: Mapping[str, Any]


@dataclass(frozen=True)
class FabricKnowledgeContextResponseAdvisory:
    """One Fabric ``knowledge-context-response/v1`` payload for bounded projection.

    Distinct from the legacy Knowledge /v1/context shape. Every claim in it is
    source-reported, unverified and advisory-only; it is never prompt material,
    an observation, a known fact, or authorization. Construction does not
    authenticate the provider or confer trust.
    """
    response: Mapping[str, Any]


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


_CONTEXT_RESPONSE_REQUIRED = frozenset({
    "threat_context", "threat_score", "confidence", "reason",
    "confidence_reason", "recommendation", "source_freshness", "advisory_id",
    "multi_ioc_scope",
})
_CONTEXT_RESPONSE_OPTIONAL = frozenset({
    "advisory_notice", "engage_refs", "rule_refs", "reported_defensive_state",
    "engagement_advisory", "engagement_repeatability_score",
})
_SOURCE_GROUP_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_ATTACK_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
_ATTACK_VERSION_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){0,2}\Z")


def _bounded_context_response(value: Any) -> dict[str, Any] | None:
    """Validate the current Knowledge ContextResponse shape and project it.

    Only bounded source group labels, public ATT&CK identifiers, freshness and
    an exact canonical reported-state enum can leave this boundary. No source
    prose, IOC, actor, event, recommendation, score or provenance ID is kept.
    """
    if type(value) is not KnowledgeContextResponseAdvisory:
        return None
    raw = value.context_response
    if not isinstance(raw, Mapping):
        return None
    try:
        wire = json.dumps(raw, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        if len(wire.encode("ascii")) > 16_384:
            return None
        data = json.loads(wire)
    except (TypeError, ValueError, RecursionError):
        return None
    if (type(data) is not dict or not _CONTEXT_RESPONSE_REQUIRED <= data.keys()
            or not data.keys() <= _CONTEXT_RESPONSE_REQUIRED | _CONTEXT_RESPONSE_OPTIONAL):
        return None
    if (type(data["threat_context"]) is not dict
            or type(data["source_freshness"]) is not dict
            or type(data["reason"]) is not list
            or any(type(x) is not dict for x in data["reason"])
            or type(data["confidence_reason"]) is not list
            or any(type(x) is not dict for x in data["confidence_reason"])
            or type(data["recommendation"]) is not dict
            or type(data["multi_ioc_scope"]) is not dict
            or type(data["advisory_id"]) is not str
            or not data["advisory_id"] or len(data["advisory_id"]) > 64):
        return None
    if any(type(data[name]) not in (int, float) or not 0 <= data[name] <= 100
           for name in ("threat_score", "confidence")):
        return None
    if "advisory_notice" in data and type(data["advisory_notice"]) is not str:
        return None
    for name in ("engage_refs", "rule_refs"):
        if name in data and (type(data[name]) is not list
                             or any(type(entry) is not dict for entry in data[name])):
            return None
    for entry in data.get("engage_refs", []):
        if (set(entry) != {"technique", "activity_id", "name", "approach"}
                or any(type(entry[key]) is not str for key in entry)):
            return None
    for entry in data.get("rule_refs", []):
        if (not {"technique", "rule_type", "rule_id"} <= entry.keys()
                or not entry.keys() <= {"technique", "rule_type", "rule_id", "title", "source_url"}
                or any(type(entry[key]) is not str for key in ("technique", "rule_type", "rule_id"))
                or any(entry.get(key) is not None and type(entry[key]) is not str
                       for key in ("title", "source_url"))):
            return None
    if "engagement_advisory" in data and data["engagement_advisory"] is not None \
            and type(data["engagement_advisory"]) is not dict:
        return None
    if "engagement_repeatability_score" in data and data["engagement_repeatability_score"] is not None \
            and type(data["engagement_repeatability_score"]) is not int:
        return None
    nodes = 0
    stack = [(data, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > 512 or depth > 8:
            return None
        if type(item) is dict:
            if len(item) > 64 or any(type(k) is not str or len(k) > 128 for k in item):
                return None
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            if len(item) > 64:
                return None
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is str and len(item) > 2048:
            return None
        elif item is not None and type(item) not in (str, int, float, bool):
            return None
    threat = data["threat_context"]
    # Knowledge emits config feed groups (fallback: feed_id), never IOC values.
    # Reject the whole receipt rather than silently keeping a partial source set.
    matches = threat.get("ioc_matches", [])
    if type(matches) is not list or len(matches) > 32:
        return None
    source_groups: set[str] = set()
    source_count = 0
    for match in matches:
        if type(match) is not dict:
            return None
        sources = match.get("sources", [])
        if type(sources) is not list or len(sources) > 16:
            return None
        source_count += len(sources)
        if source_count > 64:
            return None
        for source in sources:
            if type(source) is not str or not _SOURCE_GROUP_RE.fullmatch(source):
                return None
            source_groups.add(source)
        if len(source_groups) > 16:
            return None
    freshness = data["source_freshness"]
    mappings = threat.get("attack_mapping", [])
    if type(mappings) is not list or len(mappings) > 32:
        return None
    techniques = []
    for entry in mappings:
        if type(entry) is not dict or type(entry.get("technique")) is not str:
            return None
        technique = entry["technique"]
        if not _ATTACK_TECHNIQUE_RE.fullmatch(technique):
            return None
        if technique not in techniques:
            techniques.append(technique)
    if len(freshness) > 8:
        return None
    projected_freshness: dict[str, Any] = {}
    if "oldest_feed_days" in freshness:
        days = freshness["oldest_feed_days"]
        if days is not None and (type(days) not in (int, float) or not 0 <= days <= 36500):
            return None
        projected_freshness["oldest_feed_days"] = days
    if "attack_version" in freshness:
        version = freshness["attack_version"]
        if version is not None and (type(version) is not str or not _ATTACK_VERSION_RE.fullmatch(version)):
            return None
        projected_freshness["attack_version"] = version
    if set(freshness) - {"oldest_feed_days", "attack_version"}:
        return None
    reported_state = None
    state = data.get("reported_defensive_state")
    if state is not None:
        required_state = {"reported_state", "state_vocabulary", "producer_product", "producer_node",
                          "trace_id", "decision_ref", "observed_at", "observation_ref"}
        optional_state = {"authority_class", "is_canonical", "canonical_state"}
        if (type(state) is not dict or not required_state <= state.keys()
                or not state.keys() <= required_state | optional_state
                or any(type(state[key]) is not str for key in required_state)
                or state.get("authority_class", "producer_reported_state") != "producer_reported_state"
                or type(state.get("is_canonical", False)) is not bool):
            return None
        canonical_metadata = {"is_canonical", "canonical_state"}
        metadata_present = canonical_metadata & state.keys()
        if metadata_present and not canonical_metadata <= state.keys():
            return None
        canonical = state.get("canonical_state")
        if canonical is not None and type(canonical) is not str:
            return None
        is_canonical = state.get("is_canonical", False)
        canonical_states = {"OBSERVE", "NOTIFY", "THROTTLE", "REDIRECT", "ISOLATE"}
        # Knowledge emits exactly (true, reported_state) or (false, null).
        # Any other triple is contradictory and fails closed.
        if is_canonical is False and canonical is not None:
            return None
        if (is_canonical is False and metadata_present
                and state["reported_state"] in canonical_states):
            return None
        if is_canonical is True:
            if type(canonical) is not str or canonical != state["reported_state"]:
                return None
            if canonical not in canonical_states:
                return None
            reported_state = canonical
    if not techniques and not source_groups and not projected_freshness and reported_state is None:
        return None
    return {
        "kind": "knowledge_context_response_advisory",
        "source_kind": "knowledge_context_response",
        "claim_status": "reported_unverified",
        "attack_techniques": techniques,
        "source_groups": sorted(source_groups),
        "source_freshness": projected_freshness,
        "reported_canonical_state": reported_state,
        "trust": "unverified_advisory_only",
    }


_FABRIC_RESPONSE_SCHEMA = "knowledge-context-response/v1"
_FABRIC_IDENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:/@+\-]*")
_FABRIC_INSTANT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})")
_FABRIC_MAX_BYTES = 128 * 1024
_FABRIC_MAX_NODES = 2048
_FABRIC_MAX_DEPTH = 8
_FABRIC_TOP_KEYS = frozenset({
    "schema_version", "request_id", "correlation_id", "source_product", "source_ref",
    "provider_id", "snapshot", "facts", "inferences", "unknowns", "limitations",
    "generated_at", "expires_at", "authority"})
_FABRIC_SNAPSHOT_KEYS = frozenset({"ref", "state", "as_of"})
_FABRIC_SUBJECT_KEYS = frozenset({"entity_type", "value"})
_FABRIC_FACT_KEYS = frozenset({"claim_class", "fact_id", "subject", "predicate", "value", "provenance"})
_FABRIC_INFERENCE_KEYS = frozenset({
    "claim_class", "inference_id", "subject", "statement", "method_refs", "basis_fact_ids"})


class _FabricReject(Exception):
    pass


def _fabric_walk(value: Any, depth: int, budget: list[int]) -> None:
    """Bound depth/nodes/UTF-8 content and JSON types before serialization."""
    budget[0] += 1
    if budget[0] > _FABRIC_MAX_NODES or depth > _FABRIC_MAX_DEPTH:
        raise _FabricReject
    kind = type(value)
    if kind is str:
        if len(value) > _FABRIC_MAX_BYTES:
            raise _FabricReject
        budget[1] += len(value.encode("utf-8"))
        if budget[1] > _FABRIC_MAX_BYTES:
            raise _FabricReject
        return
    if kind is list:
        for child in value:
            _fabric_walk(child, depth + 1, budget)
        return
    if kind is dict:
        for key, child in value.items():
            if type(key) is not str or len(key) > 64:
                raise _FabricReject
            budget[1] += len(key.encode("utf-8"))
            if budget[1] > _FABRIC_MAX_BYTES:
                raise _FabricReject
            _fabric_walk(child, depth + 1, budget)
        return
    raise _FabricReject


def _fabric_str(value: Any, limit: int, *, ident: bool = False, ref: bool = False) -> str:
    if type(value) is not str or not 0 < len(value) <= limit:
        raise _FabricReject
    if ident or ref:
        if not _FABRIC_IDENT.fullmatch(value):
            raise _FabricReject
        if ref and "://" in value:
            raise _FabricReject
    elif not value.isprintable():
        raise _FabricReject
    return value


def _fabric_list(value: Any, *, low: int, high: int) -> list[Any]:
    if type(value) is not list or not low <= len(value) <= high:
        raise _FabricReject
    return value


def _fabric_keys(value: Any, keys: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise _FabricReject
    return value


def _fabric_instant(value: Any) -> datetime:
    if type(value) is not str or not _FABRIC_INSTANT.fullmatch(value):
        raise _FabricReject
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    fraction = re.search(r"\.([0-9]{1,6})(?=[+-][0-9]{2}:[0-9]{2}$)", text)
    if fraction:
        text = text[:fraction.start(1)] + fraction.group(1).ljust(6, "0") + text[fraction.end(1):]
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise _FabricReject from exc


def _fabric_instant_text(value: datetime) -> str:
    text = value.strftime("%Y-%m-%dT%H:%M:%S")
    return text + (f".{value.microsecond:06d}" if value.microsecond else "") + "Z"


def _fabric_distinct_strs(items: list[Any], limit: int, **kind: bool) -> list[str]:
    out = [_fabric_str(item, limit, **kind) for item in items]
    if len(set(out)) != len(out):
        raise _FabricReject
    return out


# IPv4 quads with ".", "-" or "_" separators (for example "ip-10-0-0-5" or "10_0_0_5").
_FABRIC_IPV4_LITERAL = re.compile(r"(?<![0-9])[0-9]{1,3}(?:[.\-_][0-9]{1,3}){3}(?![0-9])")
# Address-like runs of hex digits, colons and dots. A letter outside A-F ends a run; the suffixes of
# each run (for example "srcfe80::1" -> "fe80::1") are tested by _fabric_ipv6_candidates.
_FABRIC_IPV6_RUN = re.compile(r"[0-9A-Fa-f:.]+")
# Shorthand IPv4 with two or three numeric parts ("127.1", "10.1.2"), read as addresses by inet_aton-style parsers.
# Prose is ambiguous ("confidence 0.75", "version 0.9.1", "10.5 GB"), so shorthand is interpreted only when an
# address label sits immediately before it. Short protocol-like labels (ip, ipv4, src, dst, addr) may be followed
# by optional space, colon, equal sign or dot ("ip 127.1", "src:10.1", "dst=10.1.2", "ip[.]127.1" after defang
# normalization). Full English labels (source, destination, address, host) count only with an explicit colon or
# equal sign, optionally followed by spaces ("source:127.1", "host: 10.1.2"); bare phrase forms ("host 10.1.2",
# "The destination. 10.5 GB") are prose. A letter may glue a short label ("ip127.1", "src10.1"); a letter before
# the label ("tip 0.75") does not start one. Unlabelled shorthand is preserved as prose.
_FABRIC_LABELED_SHORT_IPV4 = re.compile(
    r"(?i)(?<![A-Za-z])(?:(?:ipv4|ip|src|dst|addr)[\s:=.]*|(?:source|destination|address|host)[:=]\s*)"
    r"(?P<ip>(?:0[xX][0-9A-Fa-f]+|[0-9]+)(?:\.(?:0[xX][0-9A-Fa-f]+|[0-9]+)){1,3})(?!\.?[0-9A-Za-z\-_])")
# Common defang forms: a bracketed, parenthesised or braced dot (or "dot") and colon, with optional spaces.
_FABRIC_DEFANG_DOT = re.compile(r"\s*[\[({]\s*(?:\.|dot)\s*[\])}]\s*", re.IGNORECASE)
_FABRIC_DEFANG_COLON = re.compile(r"\s*[\[({]\s*:\s*[\])}]\s*")
# MAC literals: colon or hyphen pairs (aa:bb:cc:dd:ee:ff) and Cisco dotted triples (aabb.ccdd.eeff).
_FABRIC_MAC_LITERAL = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}([:\-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}"
    r"|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f])")
# Host-subject types whose value must be a DNS name or a global IP literal.
_FABRIC_DNS_NAME_TYPES = frozenset({"host", "hostname", "fqdn", "domain"})
# Typed address subjects (see _fabric_is_address_type) must carry exactly one global IP literal.
# URL/URI subject types: the host of the value must pass the host-subject rules.
_FABRIC_URL_TYPES = frozenset({"url", "uri", "link", "href"})
# Clearly local-only host names. A bare word such as "internal" is ordinary prose and is not matched.
_FABRIC_LOCAL_HOST = re.compile(
    r"(?i)(?<![A-Za-z0-9-])(?:localhost|(?:[A-Za-z0-9-]+\.)+(?:localhost|localdomain|local|internal|lan|home\.arpa|"
    r"corp|home|intranet|private|test|example|invalid))"
    r"(?![A-Za-z0-9-]|\.[A-Za-z0-9-])")


# IPv6 transition and tunneling prefixes that carry an IPv4 address. ``is_global`` for them differs across
# Python versions, so the policy is fixed: all of these are refused, even with a globally routable embedded IPv4.
_IPV6_TRANSITION_PREFIXES = (
    ipaddress.IPv6Network("::/96"),           # IPv4-compatible
    ipaddress.IPv6Network("::ffff:0:0:0/96"), # IPv4-translated (SIIT)
    ipaddress.IPv6Network("64:ff9b::/96"),    # NAT64 well-known
    ipaddress.IPv6Network("64:ff9b:1::/48"),  # NAT64 local-use
    ipaddress.IPv6Network("2002::/16"),       # 6to4
    ipaddress.IPv6Network("2001::/32"),       # Teredo
)


def _fabric_global_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Globally routable public address, independent of Python ipaddress table differences.

    IPv4-mapped IPv6 and every IPv4-compatible, NAT64, 6to4 and Teredo address are refused outright, before
    ``is_global``, even when the embedded IPv4 address is globally routable. Other IPv6 uses ``is_global``.
    """
    if not isinstance(address, ipaddress.IPv6Address):
        return address.is_global
    if address.ipv4_mapped is not None or any(address in net for net in _IPV6_TRANSITION_PREFIXES):
        return False
    return address.is_global


def _fabric_short_ipv4_refused(token: str) -> bool:
    """Refuse inet_aton-style shorthand ("a.b" or "a.b.c") only when it expands to a non-global IPv4 address."""
    text_parts = token.split(".")
    # A multi-digit part with a leading zero is ambiguous (inet_aton may read it as octal): refuse it under a label.
    if any(len(part) > 1 and part.startswith("0") for part in text_parts):
        return True
    # Hex parts ("0x7f.1") are ambiguous under inet_aton-style parsing: refuse them under a label.
    if any(part[:2].lower() == "0x" for part in text_parts):
        return True
    # Bound digit runs before int() (very long runs exceed Python's conversion limit); they are out of range.
    parts = [int(part) if len(part) <= 12 else 1 << 40 for part in text_parts]
    if len(parts) == 4:
        # Full dotted quad: leading zeros were refused above; invalid or non-global values are refused.
        try:
            return not ipaddress.IPv4Address(".".join(text_parts)).is_global
        except ValueError:
            return True
    host_bits = 24 if len(parts) == 2 else 16
    if any(part > 255 for part in parts[:-1]) or parts[-1] >= 1 << host_bits:
        return False
    value = 0
    for part in parts[:-1]:
        value = (value << 8) | part
    value = (value << host_bits) | parts[-1]
    return not ipaddress.IPv4Address(value).is_global


def _fabric_ipv6_candidates(run: str):
    """Yield IPv6 candidates for each permitted suffix start in an address-like run.

    A suffix starts at the run's beginning, or at a hex digit or colon whose predecessor is a hex letter,
    a dot or a separator colon. This exposes glued prefixes ("srcfe80::1", "1fe80::1") and separator prefixes
    ("Dec:fd00::1"). A start is skipped only when it is a decimal digit after a decimal digit, so a numeric
    group such as "4700" cannot yield a false "700::1". A colon that begins or continues "::" is never a
    start, so the "::1111" inside a public "2606:4700:4700::1111" is not tested alone. Lone separator colons
    and trailing dots are trimmed; candidates without a hex digit are skipped.
    """
    for start, char in enumerate(run):
        if start and (
            (char in "0123456789" and run[start - 1] in "0123456789")
            or (char == ":" and (run[start - 1] == ":" or run[start + 1:start + 2] == ":"))
        ):
            continue
        candidate = run[start:].rstrip(".")
        if candidate.startswith(":") and not candidate.startswith("::"):
            candidate = candidate[1:]
        if candidate.endswith(":") and not candidate.endswith("::"):
            candidate = candidate[:-1]
        if re.search(r"[0-9A-Fa-f]", candidate):
            yield candidate


def _fabric_scan_copy(text: str) -> str:
    """Scan-only copy with common defang forms read as the characters they hide. Never displayed."""
    return _FABRIC_DEFANG_COLON.sub(":", _FABRIC_DEFANG_DOT.sub(".", text))


def _fabric_text_publishable(text: str) -> bool:
    """Both the original text and its defang-normalized scan copy must be free of address and host literals."""
    return _fabric_literals_clean(text) and _fabric_literals_clean(_fabric_scan_copy(text))


def _fabric_literals_clean(text: str) -> bool:
    """No non-global or malformed address literal (dotted, dashed or underscore quad; shorthand IPv4; IPv6; MAC),
    and no local-only host name. Every IPv6 suffix candidate is checked, not only the first parse."""
    if _FABRIC_MAC_LITERAL.search(text):
        return False
    for match in _FABRIC_IPV4_LITERAL.finditer(text):
        try:
            quad = ".".join(re.split(r"[.\-_]", match.group(0)))
            if not ipaddress.IPv4Address(quad).is_global:
                return False
        except ValueError:
            return False
    for match in _FABRIC_LABELED_SHORT_IPV4.finditer(text):
        if _fabric_short_ipv4_refused(match.group("ip")):
            return False
    for match in _FABRIC_IPV6_RUN.finditer(text):
        run = match.group(0)
        if match.end() < len(text) and text[match.end()] == "%":
            scope = re.match(r"%[A-Za-z0-9_.-]+", text[match.end():])
            if scope:
                try:
                    ipaddress.IPv6Address(run)
                except ValueError:
                    pass
                else:
                    return False
        if run.count(":") < 2:
            continue
        for candidate in _fabric_ipv6_candidates(run):
            try:
                address = ipaddress.IPv6Address(candidate)
            except ValueError:
                continue
            # IPv4-mapped literals are refused even when the dotted tail is global: they are IPv6 literals.
            if not _fabric_global_ip(address):
                return False
    return _FABRIC_LOCAL_HOST.search(text) is None and _fabric_embedded_urls_clean(text)


# Lookahead, so overlapping starts are all scanned (a URL nested in another URL's query, or comma-joined URLs).
_FABRIC_EMBEDDED_URL = re.compile(r"(?=([A-Za-z][A-Za-z0-9+.\-]*://[^\s<>\"'`]+))")
_FABRIC_SCHEME_PREFIX = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")


def _fabric_trim_url(url: str) -> str:
    """Drop trailing sentence punctuation. A closing bracket is dropped only when unbalanced, so a URL ending in
    a bracketed IPv6 host ("https://[2606:4700:4700::1111]") keeps it."""
    pairs = {")": "(", "]": "[", "}": "{"}
    while url:
        last = url[-1]
        if last in ".,;:!?" or (last in pairs and url.count(last) > url.count(pairs[last])):
            url = url[:-1]
        else:
            break
    return url


def _fabric_url_authority_ok(url: str) -> bool:
    """Strict authority check for a URL with or without a scheme. Whitespace, backslashes, userinfo,
    percent-encoding, malformed ports and missing or non-global hosts are refused (host-confusion bypasses)."""
    if any(ch.isspace() for ch in url) or "\\" in url:
        return False
    scheme = _FABRIC_SCHEME_PREFIX.match(url)
    rest = url[scheme.end():] if scheme else url.removeprefix("//")
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if "@" in authority or "%" in authority:
        return False
    try:
        parts = urlsplit("//" + rest)
        host = parts.hostname
        parts.port  # noqa: B018 - validates the port
    except ValueError:
        return False
    return bool(host) and _fabric_host_value_ok(host)


def _fabric_embedded_urls_clean(text: str) -> bool:
    """Every scheme://... substring in copied text, including nested and comma-joined ones, must pass the strict
    authority checks, whatever the entity_type."""
    return all(_fabric_url_authority_ok(_fabric_trim_url(m.group(1))) for m in _FABRIC_EMBEDDED_URL.finditer(text))


def _fabric_copied_ident(value: Any, limit: int) -> str:
    """An identifier copied into the advisory must pass the MIO second layer (address and secret shapes).
    Underscore is not an address character, so it is read as "-" for the shape checks only."""
    value = _fabric_str(value, limit, ident=True)
    if not second_layer_ok(value.replace("_", "-")) or not _fabric_text_publishable(value):
        raise _FabricReject
    return value


def _fabric_copied_text(value: Any, limit: int) -> str:
    """Source prose copied for display is treated as untrusted data: credential/PII text is redacted with the
    MIO redaction rules, and address literals or local-only host names are refused, not shown."""
    text = redact_text(_fabric_str(value, limit))
    if not _fabric_text_publishable(text):
        raise _FabricReject
    return text


_FABRIC_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def _fabric_host_value_ok(text: str) -> bool:
    """A DNS-name subject is a globally routable IP literal or a dotted name with more than one label.

    A bare single label is refused, and so is a name whose final label is all-numeric ("127.1") or hex-like
    ("0x1", "0x7f"): that is shorthand for an address, not a DNS name. Arbitrary privately owned names under
    a public suffix are not distinguishable here; upstream policy and source controls remain required.
    """
    if "/" in text or "@" in text or "%" in text:
        return False  # a URL or userinfo form is not a bare host subject
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        labels = text.split(".")
        return (len(labels) > 1 and len(text) <= 253
                and all(_FABRIC_DNS_LABEL.fullmatch(label) for label in labels)
                and re.fullmatch(r"[0-9]+", labels[-1]) is None
                and re.fullmatch(r"0[xX][0-9A-Fa-f]*", labels[-1]) is None)
    return _fabric_global_ip(address)


def _fabric_ip_value_ok(text: str) -> bool:
    """A typed address subject is exactly one globally routable IP literal; shorthand, integer or hex IPv4,
    dotted names, IPv4-mapped IPv6 and transition forms carrying non-global IPv4 are refused."""
    if "%" in text:
        return False  # scoped IPv6 includes a local interface identifier
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return _fabric_global_ip(address)


def _fabric_url_host_ok(text: str) -> bool:
    """A URL/URI subject, with or without a scheme, passes the same strict authority checks as embedded URLs."""
    return _fabric_url_authority_ok(_fabric_trim_url(text))


def _fabric_type_key(entity_type: str) -> str:
    """Split camelCase, lower-case, and read separators as "_" ("srcIP" -> "src_ip", "IPv4Address" -> "ipv4_address")."""
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", entity_type.strip())
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


_FABRIC_ADDRESS_TOKENS = frozenset({"ip", "ip4", "ip6", "ipv4", "ipv6", "ipaddr", "ipaddress"})
_FABRIC_COMPACT_ADDRESS_TYPES = frozenset({
    "srcip", "dstip", "destip", "sourceip", "destinationip", "clientip", "serverip", "remoteip", "localip",
    "peerip", "hostip", "publicip", "privateip", "attackerip", "victimip", "targetip", "ip4", "ip6",
    "sourceipaddress", "ipv4address", "ipv6address", "ipv4addr", "ipv6addr",
    "srcaddr", "dstaddr", "destaddr", "sourceaddr", "destinationaddr", "clientaddr", "serveraddr", "remoteaddr",
    "localaddr", "peeraddr", "remoteaddress", "clientaddress", "sourceaddress", "srcaddress", "dstaddress",
    "attackeraddr", "c2ip",
})
_FABRIC_ADDRESS_WORDS = frozenset({"addr", "address"})
# Words that make "addr"/"address" something other than an IP address (hardware, mail, postal, web).
_FABRIC_NON_IP_ADDRESS = frozenset({"mac", "email", "mail", "street", "postal", "hw", "hardware", "physical",
                                    "bluetooth", "web", "url", "uri", "sender", "from", "to", "recipient",
                                    "reply", "wallet", "contract", "billing", "home", "mailing", "payment",
                                    "memory"})


def _fabric_is_address_type(key: str) -> bool:
    """Token match on the normalized key, so "iphone" and "ipsec_policy" are not addresses but "src_ip",
    "remote_addr" and "address_v4" are. "mac_addr" and "email_addr" are excluded."""
    if key in _FABRIC_COMPACT_ADDRESS_TYPES:
        return True
    tokens = set(key.split("_"))
    if tokens & _FABRIC_ADDRESS_TOKENS:
        return True
    return bool(tokens & _FABRIC_ADDRESS_WORDS) and not tokens & _FABRIC_NON_IP_ADDRESS


def _fabric_is_url_type(key: str) -> bool:
    return key in _FABRIC_URL_TYPES or key.rsplit("_", 1)[-1] in ("url", "uri")


def _fabric_subject(value: Any) -> dict[str, str]:
    value = _fabric_keys(value, _FABRIC_SUBJECT_KEYS)
    entity_type = _fabric_copied_ident(value["entity_type"], 64)
    text = _fabric_copied_text(value["value"], 256)
    key = _fabric_type_key(entity_type)
    if _fabric_is_address_type(key) and not _fabric_ip_value_ok(text):
        raise _FabricReject
    if _fabric_is_url_type(key) and not _fabric_url_host_ok(text):
        raise _FabricReject
    if key in _FABRIC_DNS_NAME_TYPES and not _fabric_host_value_ok(text):
        raise _FabricReject
    return {"entity_type": entity_type, "value": text}


def _fabric_context_response(value: Any, now: datetime) -> tuple[dict[str, Any] | None, bool]:
    """Fail-closed projection of a Fabric Knowledge Context response v1.

    Returns (projection, expired). Any deviation rejects the whole payload; no
    partial projection, truncation or coercion. Opaque refs, provider and request
    identifiers, and provenance/method references are validated but not copied.
    Fact and inference source IDs are validated and replaced by local ordinals
    (fact-N, inference-N); basis references are remapped to the local fact IDs.
    Copied identifiers pass the MIO second layer; copied prose is redacted and
    refused if it carries a non-global address literal or a local-only host name.
    """
    if type(value) is not FabricKnowledgeContextResponseAdvisory:
        return None, False
    try:
        data = value.response
        _fabric_walk(data, 0, [0, 0])
        if len(json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")) > _FABRIC_MAX_BYTES:
            raise _FabricReject
        data = _fabric_keys(data, _FABRIC_TOP_KEYS)
        if data["schema_version"] != _FABRIC_RESPONSE_SCHEMA or data["authority"] != "advisory_only":
            raise _FabricReject
        for key, limit in (("request_id", 128), ("correlation_id", 128),
                           ("provider_id", 128), ("source_product", 64)):
            _fabric_str(data[key], limit, ident=True)
        _fabric_str(data["source_ref"], 256, ref=True)
        snapshot = _fabric_keys(data["snapshot"], _FABRIC_SNAPSHOT_KEYS)
        _fabric_str(snapshot["ref"], 256, ref=True)
        if snapshot["state"] not in ("complete", "partial", "stale"):
            raise _FabricReject
        as_of = _fabric_instant(snapshot["as_of"])
        generated = _fabric_instant(data["generated_at"])
        expires = _fabric_instant(data["expires_at"])
        if as_of > generated or generated > now or expires <= generated:
            raise _FabricReject
        facts, fact_ids = [], []
        for raw in _fabric_list(data["facts"], low=0, high=64):
            raw = _fabric_keys(raw, _FABRIC_FACT_KEYS)
            if raw["claim_class"] != "source_reported_fact":
                raise _FabricReject
            fact_id = _fabric_copied_ident(raw["fact_id"], 128)  # validated; the source ID is not emitted
            provenance = _fabric_distinct_strs(_fabric_list(raw["provenance"], low=1, high=8), 256, ref=True)
            fact_ids.append(fact_id)
            facts.append({"claim_class": "source_reported_fact", "fact_id": f"fact-{len(facts) + 1}",
                          "subject": _fabric_subject(raw["subject"]),
                          "predicate": _fabric_copied_ident(raw["predicate"], 64),
                          "value": _fabric_copied_text(raw["value"], 512),
                          "provenance_count": len(provenance)})
        inferences, inference_ids = [], []
        for raw in _fabric_list(data["inferences"], low=0, high=32):
            raw = _fabric_keys(raw, _FABRIC_INFERENCE_KEYS)
            if raw["claim_class"] != "inference":
                raise _FabricReject
            inference_id = _fabric_copied_ident(raw["inference_id"], 128)
            _fabric_distinct_strs(_fabric_list(raw["method_refs"], low=1, high=8), 256, ref=True)
            basis = [_fabric_copied_ident(item, 128) for item in _fabric_list(raw["basis_fact_ids"], low=1, high=16)]
            if len(set(basis)) != len(basis):
                raise _FabricReject
            inference_ids.append(inference_id)
            inferences.append({"claim_class": "inference", "inference_id": f"inference-{len(inferences) + 1}",
                               "subject": _fabric_subject(raw["subject"]),
                               "statement": _fabric_copied_text(raw["statement"], 512),
                               "basis_fact_ids": basis})
        known = set(fact_ids)
        if (len(known) != len(fact_ids) or len(set(inference_ids)) != len(inference_ids)
                or known & set(inference_ids)
                or any(ref not in known for item in inferences for ref in item["basis_fact_ids"])):
            raise _FabricReject
        local_fact_ids = {source: f"fact-{index}" for index, source in enumerate(fact_ids, start=1)}
        for item in inferences:
            item["basis_fact_ids"] = [local_fact_ids[ref] for ref in item["basis_fact_ids"]]
        unknowns = [_fabric_copied_text(x, 512) for x in _fabric_list(data["unknowns"], low=0, high=16)]
        limitations = [_fabric_copied_text(x, 512) for x in _fabric_list(data["limitations"], low=0, high=16)]
        if not any((facts, inferences, unknowns, limitations)):
            raise _FabricReject
    except (_FabricReject, TypeError, ValueError, UnicodeError, RecursionError):
        return None, False
    if expires <= now:
        return None, True
    return {
        "kind": "fabric_knowledge_context_response_advisory",
        "source_kind": "fabric_knowledge_context_response_v1",
        "schema_version": _FABRIC_RESPONSE_SCHEMA,
        "claim_status": "source_reported_unverified",
        "authority": "advisory_only",
        "trust": "unverified_advisory_only",
        "snapshot_state": snapshot["state"],
        "generated_at": _fabric_instant_text(generated),
        "expires_at": _fabric_instant_text(expires),
        "facts": facts, "inferences": inferences,
        "unknowns": unknowns, "limitations": limitations,
    }, False


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
                knowledge_context_response=None,
                fabric_knowledge_context_response=None,
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
        context_response_advisory = None
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
        if knowledge_context_response is not None:
            context_response_advisory = _bounded_context_response(knowledge_context_response)
            if context_response_advisory is None:
                rejected = True
        fabric_advisory = None
        if fabric_knowledge_context_response is not None:
            fabric_advisory, fabric_expired = _fabric_context_response(
                fabric_knowledge_context_response, instant)
            if fabric_advisory is None:
                rejected = True
                knowledge_expired = knowledge_expired or fabric_expired
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
        elif ((context_response_advisory or fabric_advisory)
              and knowledge_outcome is ContextDependencyOutcome.ABSENT):
            knowledge_outcome = ContextDependencyOutcome.AVAILABLE
        elif knowledge_outcome is ContextDependencyOutcome.ABSENT:
            if rejected and not lite_advisories:
                knowledge_outcome = ContextDependencyOutcome.REJECTED
            elif lite_advisories:
                knowledge_outcome = ContextDependencyOutcome.AVAILABLE
        if (knowledge_attempted is False and not rejected
                and not frame.knowledge_refs
                and not contexts and not static_references and not reported_contexts and not lite_advisories
                and context_response_advisory is None
                and fabric_knowledge_context_response is None
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
            **({"validation_diagnostic": dict(outcome.validation_diagnostic)}
               if getattr(outcome, "validation_diagnostic", None) is not None else {}),
            "dependency_outcome": {
                "knowledge": knowledge_outcome.value,
                "deception": deception_outcome.value,
            },
            "observations": [] if interrupted else list(frame.known_facts),
            "hypotheses": hypotheses, "unknowns": unknowns[:24],
            "next_checks": [] if interrupted else checks,
            "knowledge": [] if interrupted else contexts + static_references + reported_contexts + lite_advisories,
            **({"knowledge_context_response_advisory": None if interrupted else context_response_advisory}
               if context_response_advisory is not None else {}),
            **({"fabric_knowledge_context_advisory": None if interrupted else fabric_advisory}
               if fabric_advisory is not None else {}),
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
                payload.pop("knowledge_context_response_advisory", None)
                payload.pop("fabric_knowledge_context_advisory", None)
        return Assistance(payload)

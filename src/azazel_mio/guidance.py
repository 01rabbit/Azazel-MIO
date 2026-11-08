"""Deterministic guidance: a model-free, advisory answer built from a situation frame.

The guidance is assembled only from the supplied values (frame, supplied report text,
optional Knowledge facts/unknowns) and the reviewed playbook vocabulary. It never calls a
model, never promotes an unverified report to a fact, and never produces an executable
recommendation. Display wording (for example Japanese) belongs to the consumer; every text
produced here is an English canonical string or an ID.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Mapping, Sequence

from .contracts import MioSituationFrame
from .playbook import (
    ReasoningPlaybook,
    _DIRECTIVE_RE,
    _FORBIDDEN_CONTENT,
    _MAX_ITEM_CHARS,
    _canonical_digest,
    playbook_digest,
    reasoning_provenance,
    select_playbook,
)
from .tactical_grounding import _AUTH_GAP_SPECS, authentication_frame_unknowns, is_authentication_context

GUIDANCE_SCHEMA_VERSION = "1.0.0"
CONTENT_KIND = "deterministic_guidance"
GENERATION_METHOD = "deterministic_guidance"
WITHHELD_MARK = "[withheld]"
_MAX_FRAGMENT_CHARS = 240
_MAX_CHECKS = 4
_REQUIRED_CHECKS = 2

# Topic table per reviewed playbook family (never per case). A topic is "addressed" when a
# non-gap report fragment mentions it; the matching unknown is then replaced by an
# "as reported, unverified" entry, the related check moves first, and a weight note records a
# change of verification priority (never a conclusion).
TOPICS: dict[str, tuple[dict[str, Any], ...]] = {
    "auth-ambiguity-v1": (
        {"id": "auth_success", "keywords": r"\bsuccess(?:ful)?\b|\bsucceeded\b|\blogged in\b", "unknown_match": r"success|succeed", "check_match": r"successful login", "weight_up": "credential_attack", "negation": r"\b(?:no|without|zero)\s+(?:successful|success|succeeded)|\bnot succe|\bno login succeeded", "note": "success after failures is reported"},
        {"id": "auth_baseline", "keywords": r"approved automation|automation baseline|scheduled job|credential change", "unknown_match": r"automation|baseline|credential change", "check_match": r"automation|baseline", "weight_up": "misconfigured_automation", "negation": r"\bno (?:approved )?automation|\bno (?:automation )?baseline|\bno credential change|\bwithout (?:approved )?automation", "note": "an approved automation or credential change is reported"},
        {"id": "auth_identity", "keywords": r"\baccount\b|\bsource identity\b|\busername\b", "unknown_match": r"identity", "check_match": r"identity", "weight_up": None, "note": "an account or source identity is reported"},
        {"id": "auth_impact", "keywords": r"privilege|escalation|host impact|post-condition", "unknown_match": r"privilege|post-condition|host", "check_match": r"never", "weight_up": "credential_attack", "negation": r"\bno (?:host impact|privilege|escalation)|\bwithout (?:host impact|privilege)", "note": "a host impact or privilege change is reported"},
    ),
    "dns-resolution-degradation-v1": (
        {"id": "dns_other_sites", "keywords": r"other (?:sites|probes|resolvers)|several (?:sites|probes)", "unknown_match": r"other sites|other probe|other resolver|scope", "check_match": r"other probes", "weight_up": None, "negation": r"\b(?:no|zero|without)\s+timeouts?\b|\bnot? timing out\b|\banswer(?:s|ed)? normally\b", "note": "other vantage points are reported"},
        {"id": "dns_continuation", "keywords": r"\bcontinu|\brecover|\bresolved\b|\bstopped\b", "unknown_match": r"continu|communication", "check_match": r"latest aggregation", "weight_up": None, "note": "continuation or recovery is reported"},
        {"id": "dns_change", "keywords": r"approved change|change record|maintenance", "unknown_match": r"change", "check_match": r"change records", "weight_up": None, "negation": r"\bno (?:approved )?change|\bno maintenance|\bwithout change", "note": "a change or maintenance is reported"},
    ),
}
# Explanation promoted by a topic whose report is positive/negative (slot ids of the playbook).
_DNS_OTHER_SITES_NEGATIVE = "probe_specific_or_partial_link"
_DNS_OTHER_SITES_POSITIVE = "resolver_or_path_degradation"

_NOT_REPORTED_RE = re.compile(r"\bnot reported\b|\bunreported\b|\bno (?:other )?(?:sites|probes|resolvers|records?) (?:were |are )?reported\b|\bnot available\b", re.I)
_GAP_RE = re.compile(
    r"\b(unknown|absent|unverified|unreadable|pending)\b"
    r"|\bnot (?:(?:yet|been|be|was|were|has|have|had|do|did|does)\s+)*(?:supplied|available|provided|checked|verified|confirmed|run|read|readable|aggregated|documented|recorded|attached|stated|given|say|said|specified)\b"
    r"|\bno (?:\w+ ){0,2}(?:records?|confirmation|evidence|documentation|counts?)\b", re.I)
# Hedged or hearsay statements are kept as reported-not-verified notes; they never move a topic or weight.
_HEDGE_RE = re.compile(r"\b(mentioned|thinks?|believes?|guess(?:es)?|possibly|reportedly|hearsay|suspects?|unsure)\b", re.I)
_WEAK_HEDGE_RE = re.compile(r"\b(may|might)\b", re.I)  # a hedge only when the clause states no counted observation
_COUNT_RE = re.compile(r"\d|\b(one|two|three|four|five|six|seven|eight|nine|ten|several)\b", re.I)
_CLAUSE_RE = re.compile(r",\s+(?:and|but)\s+|\s+but\s+", re.I)
_NO_SUBJECT_RE = re.compile(r"^(?:gives|has|have|is|are|was|were|shows|does|did|and|but)\b", re.I)
_COMPARE_DEPENDENT = frozenset({"auth_success", "dns_other_sites", "dns_continuation"})
# The report itself says the compared windows/clocks/aggregations are not aligned.
_COMPARE_RE = re.compile(r"windows?\s+(?:that\s+)?may not overlap|different time ?zones?|not (?:yet |been )*aggregated|not comparable|different windows?|clock (?:skew|mismatch|differs?)|unsynchroni[sz]ed", re.I)
COMPARE_UNKNOWN = "Comparison conditions (window, time zone, aggregation) are not aligned in the report"
_OBSERVATION_RE = re.compile(r"\d|\b(one|two|three|four|five|six|seven|eight|nine|ten|several|no)\b", re.I)
_STOPWORDS = frozenset("the a an and or of to in on for with is are not no any from that this if by as be does whether after observed supplied current frame vs prior".split())
_SOURCES = ("report", "frame", "frame_analysis", "knowledge")


def validate_topics(topics: Mapping[str, Sequence[Mapping[str, Any]]] | None = None) -> tuple[str, ...]:
    """Static validation of the topic table, like validate_playbook: patterns compile and
    every text field is short, plain, free of shell/URL/path syntax and directive verbs."""
    table = TOPICS if topics is None else topics
    errors: list[str] = []
    for family, items in table.items():
        ids: set[str] = set()
        for index, topic in enumerate(items):
            where = f"{family}[{index}]"
            tid = topic.get("id")
            if not isinstance(tid, str) or not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", tid) or tid in ids:
                errors.append(f"invalid_topic_id:{where}")
            ids.add(str(tid))
            for key in ("keywords", "unknown_match", "check_match", "negation"):
                if key not in topic and key == "negation":
                    continue
                pattern = topic.get(key)
                if not isinstance(pattern, str) or not pattern or len(pattern) > 400:
                    errors.append(f"bad_pattern:{key}:{where}")
                    continue
                try:
                    re.compile(pattern)
                except re.error:
                    errors.append(f"bad_pattern:{key}:{where}")
            note = topic.get("note")
            if not isinstance(note, str) or not note.strip() or len(note) > _MAX_ITEM_CHARS:
                errors.append(f"bad_note_length:{where}")
            else:
                for code, pattern in _FORBIDDEN_CONTENT:
                    if pattern.search(note):
                        errors.append(f"forbidden_content:{code}:{where}")
                if _DIRECTIVE_RE.search(note):
                    errors.append(f"directive_language:{where}")
    return tuple(errors)


def guidance_digest() -> str:
    """Digest of the guidance vocabulary (topics, matching rules, schema version)."""
    return _canonical_digest({
        "schema_version": GUIDANCE_SCHEMA_VERSION,
        "content_kind": CONTENT_KIND,
        "topics": {family: [dict(sorted(t.items())) for t in items] for family, items in sorted(TOPICS.items())},
        "not_reported": _NOT_REPORTED_RE.pattern,
        "gap": _GAP_RE.pattern,
        "observation": _OBSERVATION_RE.pattern,
        "limits": [_MAX_FRAGMENT_CHARS, _MAX_CHECKS, _REQUIRED_CHECKS],
    })


def _scrub(text: str, withheld: Sequence[str]) -> str:
    for value in withheld:
        if value:
            text = text.replace(value, WITHHELD_MARK)
    return text


def _scrub_deep(value: Any, withheld: Sequence[str]) -> Any:
    if isinstance(value, str):
        return _scrub(value, withheld)
    if isinstance(value, Mapping):
        return {k: _scrub_deep(v, withheld) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub_deep(v, withheld) for v in value]
    return value


def _fragments(text: str) -> list[str]:
    parts = re.split(r"(?<=[.;])\s+", text.strip())
    return [p.strip().rstrip(".;")[:_MAX_FRAGMENT_CHARS] for p in parts if p.strip()]


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z]+", text.lower()) if w not in _STOPWORDS and len(w) > 2}


def _addressed_topics(playbook_id: str, observations: Sequence[str]) -> list[dict[str, Any]]:
    """A topic counts as addressed only when the report states something about it (never
    'not reported'). Negation is judged next to the topic object, not over the whole sentence."""
    out: list[dict[str, Any]] = []
    for topic in TOPICS.get(playbook_id, ()):
        hits = [f for f in observations if re.search(topic["keywords"], f, re.I) and not _NOT_REPORTED_RE.search(f)]
        if hits:
            negative = bool(topic.get("negation")) and bool(re.search(topic["negation"], hits[0], re.I))
            out.append({"id": topic["id"], "fragment": hits[0], "negative": negative, "topic": topic})
    return out


@dataclass(frozen=True)
class DeterministicGuidance:
    """Model-free guidance. All collection fields hold plain JSON-safe dicts/strings."""

    playbook_id: str
    playbook_version: str
    playbook_digest: str
    guidance_digest: str
    selection_mode: str
    facts: tuple[dict[str, Any], ...]
    competing_explanations: tuple[dict[str, Any], ...]
    discriminating_material: tuple[str, ...]
    claim_boundaries: tuple[str, ...]
    unknown_groups: tuple[dict[str, Any], ...]
    topics_addressed: tuple[dict[str, Any], ...]
    weight_notes: tuple[dict[str, Any], ...]
    next_checks: tuple[dict[str, Any], ...]
    recommendation: dict[str, Any]
    evidence_gaps: dict[str, Any]
    handoff: dict[str, Any]
    guidance_schema_version: str = GUIDANCE_SCHEMA_VERSION
    content_kind: str = CONTENT_KIND
    generation_method: str = GENERATION_METHOD
    model_calls: int = 0

    @property
    def unknowns(self) -> tuple[str, ...]:
        return tuple(g["text"] for g in self.unknown_groups)

    def to_dict(self) -> dict[str, Any]:
        return {
            "guidance_schema_version": self.guidance_schema_version,
            "content_kind": self.content_kind,
            "generation_method": self.generation_method,
            "model_calls": self.model_calls,
            "playbook_id": self.playbook_id,
            "playbook_version": self.playbook_version,
            "playbook_digest": self.playbook_digest,
            "guidance_digest": self.guidance_digest,
            "selection_mode": self.selection_mode,
            "facts": [dict(x) for x in self.facts],
            "competing_explanations": [dict(x) for x in self.competing_explanations],
            "discriminating_material": list(self.discriminating_material),
            "claim_boundaries": list(self.claim_boundaries),
            "unknown_groups": [dict(x, sources=list(x["sources"]), merged=list(x["merged"])) for x in self.unknown_groups],
            "topics_addressed": [dict(x) for x in self.topics_addressed],
            "weight_notes": [dict(x) for x in self.weight_notes],
            "next_checks": [dict(x) for x in self.next_checks],
            "recommendation": dict(self.recommendation),
            "evidence_gaps": dict(self.evidence_gaps),
            "handoff": self.handoff,
        }


def build_guidance(
    frame: MioSituationFrame,
    *,
    report_texts: Sequence[str] = (),
    edge_decision: Mapping[str, Any] | None = None,
    knowledge_facts: Sequence[Mapping[str, Any]] = (),
    knowledge_unknowns: Sequence[str] = (),
    withheld_values: Sequence[str] = (),
    effective_read_capabilities: Sequence[str] = (),
    request_id: str = "",
    incident_id: str = "",
    privacy_class: str | None = None,
    playbook: ReasoningPlaybook | None = None,
) -> DeterministicGuidance:
    """Assemble deterministic guidance. No model is called; the result is advisory only."""
    errors = validate_topics()
    if errors:
        raise ValueError("invalid_guidance_topics:" + ",".join(errors[:4]))
    withheld = tuple(str(v) for v in withheld_values if v)
    selection = select_playbook(frame, requested_id=playbook.playbook_id if playbook else None,
                                playbooks={playbook.playbook_id: playbook} if playbook else None)
    pb = selection.playbook
    provenance = reasoning_provenance(pb, selection)
    refs = list(frame.evidence_refs)

    # 1. facts: the report is quoted as "what the report states" (untrusted), never as verified fact.
    report = " ".join(str(t) for t in report_texts if t)
    facts: list[dict[str, Any]] = []
    report_gaps: list[str] = []
    hearsay: list[str] = []
    obs_parts: list[tuple[int, str]] = []  # (sentence index, observed clauses) - what topics may read
    compare_sentences: set[int] = set()
    for index, sentence in enumerate(_fragments(report)):
        pieces = re.split(r",\s+", sentence) if _GAP_RE.search(sentence) else [sentence]
        clauses = [re.sub(r"^(?:and|but)\s+", "", c.strip(), flags=re.I) for p in pieces for c in _CLAUSE_RE.split(p) if c.strip()]
        observed: list[str] = []
        gaps: list[str] = []
        notes: list[str] = []
        for clause in clauses:
            if _COMPARE_RE.search(clause):
                compare_sentences.add(index)
            hedged = _HEDGE_RE.search(clause) or (_WEAK_HEDGE_RE.search(clause) and not _COUNT_RE.search(clause))
            if hedged:
                hearsay.append(_scrub(clause, withheld))
                notes.append(clause)
            elif _GAP_RE.search(clause):
                # a clause without its own subject is prefixed with the sentence's opening words
                gaps.append(" ".join(sentence.split()[:3]) + " ... " + clause if _NO_SUBJECT_RE.match(clause) else clause)
            elif _OBSERVATION_RE.search(clause):
                observed.append(clause)
            else:
                notes.append(clause)
        if observed:
            kind = "supplied_report"
            obs_parts.append((index, _scrub(" ".join(observed), withheld)))
        elif gaps:
            kind = "supplied_report_gap"
        else:
            kind = "supplied_report_note"
        for g_text in gaps:
            report_gaps.append(_scrub(g_text, withheld))
        facts.append({"kind": kind, "trust": "untrusted_report", "text": _scrub(sentence, withheld)})
    not_comparable = bool(compare_sentences)
    if edge_decision:
        facts.append({"kind": "edge_decision", "trust": "deterministic", "text": "Edge selected_action={}, result={}, executed_count={}".format(
            edge_decision.get("selected_action"), edge_decision.get("result"), edge_decision.get("executed_count"))})
    for item in knowledge_facts or ():
        facts.append({"kind": "knowledge", "trust": str(item.get("claim_class") or "unclassified"), "text": _scrub(str(item.get("value")), withheld)})

    # 2. competing explanations: playbook slots; the evidence refs are the report's refs and
    # their content is NOT verified to support the explanation.
    explanations = []
    for index, (slot, role) in enumerate(pb.hypothesis_alternatives):
        prompt = pb.hypothesis_prompts[index] if index < len(pb.hypothesis_prompts) else slot
        explanations.append({"slot": slot, "role": role, "prompt": prompt, "evidence_refs": refs, "support": "unverified_candidate"})
    slots = {e["slot"] for e in explanations}

    # 3. unknowns: frame + report gaps + knowledge unknowns + auth-context unknowns.
    frame_unknowns = list(frame.unknowns)
    kn_unknowns = [_scrub(str(u), withheld) for u in knowledge_unknowns or ()]
    analysis: list[str] = []
    if is_authentication_context(frame, pb):
        analysis = list(authentication_frame_unknowns(frame))
    origin: dict[str, str] = {}
    for text, source in ([(u, "frame") for u in frame_unknowns] + [(u, "report") for u in report_gaps]
                         + [(u, "knowledge") for u in kn_unknowns] + [(u, "frame_analysis") for u in analysis]):
        origin.setdefault(text, source)
    for text in hearsay:
        origin.setdefault(f"Reported, not verified: {text} (verification still required)", "report")
    if not_comparable:
        origin.setdefault(COMPARE_UNKNOWN, "report")
    unknowns = [_scrub(u, withheld) for u in origin]
    origin = {_scrub(k, withheld): v for k, v in origin.items()}

    observations = [t for _, t in obs_parts]
    addressed = _addressed_topics(pb.playbook_id, observations)
    for ad in addressed:
        where = next((i for i, t in obs_parts if t == ad["fragment"] or ad["fragment"] in t), None)
        ad["compare_blocked"] = bool(compare_sentences) and ad["id"] in _COMPARE_DEPENDENT and (
            where is None or any(abs(where - c) <= 1 for c in compare_sentences))
    for ad in addressed:
        pattern = re.compile(ad["topic"]["unknown_match"], re.I)
        unknowns = [u for u in unknowns if not pattern.search(u)]
    for ad in addressed:
        text = f"Reported, not verified: {ad['fragment']} (verification still required)"
        unknowns.append(text)
        origin[text] = "report"

    def topic_of(text: str) -> str | None:
        for topic in TOPICS.get(pb.playbook_id, ()):
            if re.search(topic["unknown_match"], text, re.I):
                return topic["id"]
        return None

    groups: list[dict[str, Any]] = []
    for text in unknowns:
        source = origin.get(text, "frame_analysis")
        topic = topic_of(text)
        target = None
        for group in groups:
            if (topic and group["topic"] == topic) or (not topic and len(_words(text) & _words(group["text"])) >= 3):
                target = group
                break
        if target is None:
            groups.append({"text": text, "topic": topic, "sources": [source], "merged": []})
        else:
            if text != target["text"]:
                target["merged"].append(text)
            if source not in target["sources"]:
                target["sources"].append(source)

    # 4. next checks: playbook vocabulary first, report-derived gaps after (read-only, existing authority).
    checks: list[dict[str, Any]] = [
        {"text": q, "source": "playbook", "pb_index": i} for i, q in enumerate(pb.discriminating_questions)]
    for gap in report_gaps:
        if len(checks) >= _MAX_CHECKS:
            break
        if any(len(_words(gap) & _words(c["text"])) >= 2 for c in checks):
            continue
        candidate = f"Confirm from existing read-only records what the report leaves open: {gap}"
        if len(candidate) > _MAX_ITEM_CHARS or _DIRECTIVE_RE.search(gap) or any(p.search(candidate) for _, p in _FORBIDDEN_CONTENT):
            continue
        checks.append({"text": candidate, "source": "derived"})
    for ad in addressed:
        pattern = re.compile(ad["topic"]["check_match"], re.I)
        checks.sort(key=lambda c: 0 if pattern.search(c["text"]) else 1)
    next_checks = []
    for index, check in enumerate(checks):
        check_id = f"{pb.playbook_id}:q{check['pb_index'] + 1}" if check["source"] == "playbook" else f"derived:q{index + 1}"
        next_checks.append({"id": check_id, "tier": "required" if index < _REQUIRED_CHECKS else "optional_when_needed",
                            "mode": "read_only_existing_authority", "text": check["text"]})

    # 5. weight notes: verification priority only; never a statement about cause or actor.
    weights: list[dict[str, Any]] = []
    for ad in addressed:
        if ad["compare_blocked"]:
            continue
        up = ad["topic"]["weight_up"]
        if up and up in slots:
            weights.append({"explanation": up, "direction": "verification_priority_down" if ad["negative"] else "verification_priority_up",
                            "topic": ad["id"], "as_reported": ad["fragment"]})
        elif ad["id"] == "dns_other_sites":
            slot = _DNS_OTHER_SITES_NEGATIVE if ad["negative"] else _DNS_OTHER_SITES_POSITIVE
            if slot in slots:
                weights.append({"explanation": slot, "direction": "verification_priority_up",
                                "topic": ad["id"] + ("_negative" if ad["negative"] else "_positive"), "as_reported": ad["fragment"]})

    # 6. evidence gaps: no read capability means the sole legal result is an empty list.
    capabilities = {str(c) for c in effective_read_capabilities}
    gap_items: list[dict[str, Any]] = []
    if capabilities and is_authentication_context(frame, pb):
        missing = set(authentication_frame_unknowns(frame))
        for marker, question, capability, unknown in _AUTH_GAP_SPECS:
            if unknown in missing and capability in capabilities and capability in pb.allowed_capabilities:
                gap_items.append({"marker": marker, "question": question, "capability": capability})
    evidence_gaps = {"items": gap_items, "reason": "" if capabilities else "no_effective_read_capabilities", "source": "deterministic"}

    recommendation = {"recommended_action": "OBSERVE", "executable": False, "current_action": None, "source": "deterministic_fixed"}
    handoff = {
        "incident_id": incident_id, "request_id": request_id, "trace_id": frame.trace_id, "frame_id": frame.frame_id,
        "evidence_refs": refs, "privacy_class": privacy_class,
        "sections": {
            "report_basis": [f["text"] for f in facts if f["kind"] == "supplied_report"],
            "competing_explanations": [e["slot"] for e in explanations],
            "missing_information": [g["text"] for g in groups],
            "safe_next_checks": [f"[{c['tier']}] {c['text']}" for c in next_checks],
            "execution": "none (current_action null)",
        },
    }
    built = _scrub_deep({
        "facts": facts, "competing_explanations": explanations, "unknown_groups": groups,
        "topics_addressed": [{"id": ad["id"], "as_reported": ad["fragment"], "negative": ad["negative"]} for ad in addressed],
        "weight_notes": weights, "next_checks": next_checks, "handoff": handoff,
    }, withheld)
    return DeterministicGuidance(
        playbook_id=pb.playbook_id, playbook_version=pb.version, playbook_digest=playbook_digest(pb),
        guidance_digest=guidance_digest(), selection_mode=str(provenance["selection_mode"]),
        facts=tuple(built["facts"]), competing_explanations=tuple(built["competing_explanations"]),
        discriminating_material=tuple(pb.falsification_patterns), claim_boundaries=tuple(pb.claim_boundaries),
        unknown_groups=tuple(built["unknown_groups"]), topics_addressed=tuple(built["topics_addressed"]),
        weight_notes=tuple(built["weight_notes"]), next_checks=tuple(built["next_checks"]),
        recommendation=recommendation, evidence_gaps=evidence_gaps, handoff=built["handoff"],
    )

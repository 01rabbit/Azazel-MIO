"""Narrow deterministic grounding for high-impact authentication hypotheses.

This module is deliberately not a general natural-language fact checker. It
recognizes a small set of claims that the privacy-reduced frame cannot support
(source/account attribution and host-impact claims), replaces those model
strings with trusted playbook wording, and records the corresponding frame
gaps. All model-originated text remains unverified.
"""
from __future__ import annotations

from dataclasses import replace
import re
from typing import Sequence

from .contracts import HypothesisStatus, MioEvidenceGap, MioHypothesis, MioSituationFrame
from .playbook import ReasoningPlaybook


AUTH_PLAYBOOK_ID = "auth-ambiguity-v1"
_AUTH_CONTEXT = re.compile(r"\b(?:auth(?:entication)?|login|logon|ssh|credential|password|t1110)\b|認証|ログイン", re.I)

_SOURCE_CLAIMS = (
    re.compile(r"\b(?:from|by)\s+(?:a\s+)?(?:specific|identified|known)\s+(?:source|host|account|actor)\b", re.I),
    re.compile(r"\b(?:specific|identified|known|same)\s+(?:source|host|account|actor|ip(?:v4|v6)?\s+address)\b", re.I),
    re.compile(r"\b(?:source|account)\s+(?:ip|address|identity)\b", re.I),
    re.compile(r"\b(?:originat(?:ed|es?)\s+(?:at|from)|came\s+from)\s+(?:an?\s+)?(?:ip\s+address\s+)?(?:\d{1,3}\.){3}\d{1,3}\b", re.I),
    re.compile(r"\b(?:originat(?:ed|es?)\s+from|came\s+from)\s+(?:an?\s+)?(?:identified\s+)?(?:account|host|actor)\b", re.I),
    re.compile(r"\b(?:same|identified)\s+(?:attacker|actor|account)\b", re.I),
    re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    re.compile(r"(?:特定|識別済み).{0,4}(?:送信元|接続元|攻撃元|アカウント|主体)"),
    re.compile(r"(?:送信元|接続元|アカウント).{0,4}(?:IP|アドレス|識別情報)"),
)
_IMPACT_CLAIMS = (
    re.compile(r"\bprivilege\s+escalat(?:ion|e|ed)\b", re.I),
    re.compile(r"\b(?:compromise[ds]?|successful\s+exploit|exploit\s+succeed(?:ed|s))\b", re.I),
    re.compile(r"\b(?:gain|gained|obtain(?:ed)?)\s+(?:root|admin(?:istrator)?|elevated)\s+(?:access|privileges?)\b", re.I),
    re.compile(r"\b(?:account\s+(?:was\s+)?(?:taken\s+over|hijacked)|account\s+takeover|(?:taken\s+over|hijacked)\s+account)\b", re.I),
    re.compile(r"\b(?:root|admin(?:istrator)?)\s+(?:access|privileges?)\s+(?:was\s+)?(?:achieved|obtained|gained|secured)\b", re.I),
    re.compile(r"\b(?:host|system|machine)\s+(?:was\s+)?(?:breached|compromised|owned)\b|\b(?:breached|compromised)\s+(?:the\s+)?(?:host|system|machine)\b", re.I),
    re.compile(r"(?:権限昇格|権限を(?:取得|獲得)|管理者権限|root権限|侵害(?:された|した|成功)|アカウント(?:が)?乗っ取られ)"),
)
_NEGATION_BEFORE = re.compile(
    r"(?:\bno\s+(?:evidence|sign|indication|observation)\s+of\b|\bno\b|\bwithout\b|"
    r"\bnot\s+(?:observed|established|confirmed|shown|reported|occur(?:red)?)\b|"
    r"\bdoes\s+not\s+(?:establish|show|support|indicate)\b|\bunknown\b|\bunconfirmed\b|"
    r"\bunverified\b|\babsence\s+of\b|\bnever\b|\bneither\b)", re.I)
_NEGATION_AFTER = re.compile(
    r"^.{0,36}?(?:\b(?:did\s+not|didn't|has\s+not|hasn't|was\s+not|wasn't|were\s+not|"
    r"were\s+not|not)\s+(?:occur|occurred|happen|happened|take\s+place|succeed|succeeded|"
    r"achieved|obtained|observed|established|confirmed|shown|reported|detected|found)\b|"
    r"\b(?:remains?\s+unknown|is\s+unknown|unconfirmed|unverified|not\s+observed)\b)", re.I)
_JP_NEGATION = re.compile(r"(?:未確認|不明|観測されていない|立証されていない|確認されていない|証拠がない|示されていません|含まれていません|発生していません|発生していない|起きていません|起きていない|ありません|ではありません|されていません|されていない|なかった)")
_CONTRAST = re.compile(r"\b(?:but|however|yet|although|whereas)\b|[;.!?。！？]", re.I)
_HOSTILE_TARGET = re.compile(r"\b(?:weakens?|falsifies?|disproves?)\s+(?:the\s+)?hostile\s+(?:hypothesis|explanation)\b", re.I)
_DUPLICATE_SPACE = re.compile(r"[^\w]+", re.UNICODE)

_SAFE_SLOT_STATEMENTS = {
    "credential_attack": "A credential-attack explanation remains unverified from the supplied authentication frame.",
    "misconfigured_automation": "A benign or misconfigured-automation explanation remains unverified from the supplied authentication frame.",
    "reconnaissance": "A reconnaissance explanation remains unverified from the supplied authentication frame.",
}
_SAFE_GENERIC_STATEMENT = "This playbook alternative remains unverified; the supplied frame does not establish source identity or host impact."

AUTH_SOURCE_UNKNOWN = "No source or account identity is supplied in the current privacy-reduced frame."
AUTH_SUCCESS_UNKNOWN = "The frame does not establish whether any authentication succeeded after the observed failures."
AUTH_BASELINE_UNKNOWN = "An approved automation or monitoring baseline is not included in the frame."
AUTH_IMPACT_UNKNOWN = "Privilege escalation, exploit success, and host post-condition are not established by the supplied alert."

# Each fixed safety projection has its own stable identifier.  The strings
# remain local receipt material; IDs alone are suitable for prompt handoff.
AUTH_UNKNOWN_IDS = {
    "ux:identity": AUTH_SOURCE_UNKNOWN,
    "ux:success": AUTH_SUCCESS_UNKNOWN,
    "ux:baseline": AUTH_BASELINE_UNKNOWN,
    "ux:impact": AUTH_IMPACT_UNKNOWN,
}


def receipt_unknowns(frame: MioSituationFrame, auth_context: bool) -> dict[str, str]:
    result = {f"u{i}": text for i, text in enumerate(frame.unknowns, 1)}
    if auth_context:
        fixed = set(authentication_frame_unknowns(frame))
        result.update({key: text for key, text in AUTH_UNKNOWN_IDS.items() if text in fixed})
    return result

_AUTH_GAP_SPECS = (
    ("AUTH_SUCCESS_AFTER_FAILURES_NOT_ESTABLISHED", "Check the authorized read-only authentication alert window for any successful login after the observed failures; report only the result and evidence reference.", "query_recent_alerts", AUTH_SUCCESS_UNKNOWN),
    ("AUTH_AUTOMATION_BASELINE_NOT_SUPPLIED", "Compare the observed time and count with a documented, approved automation or monitoring baseline; if none is available, keep this unresolved.", "lookup_behavior_pattern", AUTH_BASELINE_UNKNOWN),
)


def _normalized_facts(frame: MioSituationFrame) -> set[str]:
    return {re.sub(r"[^A-Z0-9]+", "_", item.upper()).strip("_") for item in frame.known_facts}


def is_authentication_context(frame: MioSituationFrame, playbook: ReasoningPlaybook) -> bool:
    """Recognize display-only auth guidance without selecting a playbook.

    Reasoning selection still uses its current deterministic summary fields and
    this helper never adds a capability.
    """
    return playbook.playbook_id == AUTH_PLAYBOOK_ID or any(_AUTH_CONTEXT.search(item) for item in frame.known_facts)


def authentication_frame_unknowns(frame: MioSituationFrame) -> tuple[str, ...]:
    """Return only unknowns that the bounded frame cannot currently answer."""
    facts = _normalized_facts(frame)
    existing = " ".join(frame.unknowns).casefold()
    result: list[str] = []
    # Actor summaries are intentionally pseudonymous group keys, not identity.
    if not any(marker in facts for marker in ("SOURCE_IDENTITY_SUPPLIED", "ACCOUNT_IDENTITY_SUPPLIED")) and not re.search(r"source.{0,24}identity|account.{0,24}identity", existing):
        result.append(AUTH_SOURCE_UNKNOWN)
    success_markers = {"AUTH_SUCCESS_OBSERVED", "SUCCESSFUL_LOGIN_OBSERVED", "LOGIN_SUCCEEDED"}
    if not facts.intersection(success_markers) and not re.search(r"successful?\s+(?:auth|login)|login\s+succeed", existing):
        result.append(AUTH_SUCCESS_UNKNOWN)
    baseline_markers = {"APPROVED_AUTOMATION_BASELINE_AVAILABLE", "AUTOMATION_BASELINE_PRESENT"}
    if not facts.intersection(baseline_markers) and not re.search(r"automation.{0,24}baseline|baseline.{0,24}automation", existing):
        result.append(AUTH_BASELINE_UNKNOWN)
    if not any("PRIVILEGE_ESCALATION_OBSERVED" in fact or "HOST_POSTCONDITION_VERIFIED" in fact for fact in facts) and not re.search(r"privilege.{0,24}(?:observed|verified)|host.{0,24}post.?condition.{0,24}(?:observed|verified)", existing):
        result.append(AUTH_IMPACT_UNKNOWN)
    return tuple(result)


def _is_explicitly_unconfirmed(text: str, start: int, end: int) -> bool:
    before = text[max(0, start - 160):start]
    after = text[end:min(len(text), end + 100)]
    # Negation only applies within the current clause. Contrastive clauses
    # restore positive scope ("no evidence of X, but Y occurred").
    before = _CONTRAST.split(before)[-1]
    if _NEGATION_BEFORE.search(before) or _NEGATION_AFTER.search(after) or _JP_NEGATION.search(after):
        return True
    # A preceding denial can scope over coordinated alternatives, e.g.
    # "does not establish whether source identity or privilege escalation occurred".
    return bool(re.search(r"\bdoes\s+not\s+(?:establish|show|support)\b", before, re.I)
                and re.search(r"\b(?:or|nor)\b", before, re.I))


def _claim_classes(text: str) -> tuple[str, ...]:
    classes: list[str] = []
    for pattern in _SOURCE_CLAIMS:
        if any(not _is_explicitly_unconfirmed(text, match.start(), match.end()) for match in pattern.finditer(text)):
            classes.append("source_identity_unavailable")
            break
    for pattern in _IMPACT_CLAIMS:
        if any(not _is_explicitly_unconfirmed(text, match.start(), match.end()) for match in pattern.finditer(text)):
            classes.append("host_impact_unavailable")
            break
    return tuple(classes)


def _safe_role_statement(alternative_id: str, role: str) -> str:
    if alternative_id in _SAFE_SLOT_STATEMENTS:
        return _SAFE_SLOT_STATEMENTS[alternative_id]
    if role == "hostile":
        return "A hostile explanation remains unverified from the supplied frame."
    if role == "benign":
        return "A benign or configuration explanation remains unverified from the supplied frame."
    return "This alternative remains unresolved from the supplied frame."


def _duplicate_statement_groups(hypotheses: Sequence[MioHypothesis]) -> set[str]:
    seen: dict[str, str] = {}
    duplicated: set[str] = set()
    for hypothesis in hypotheses:
        normalized = _DUPLICATE_SPACE.sub(" ", hypothesis.statement.casefold()).strip()
        if not normalized:
            continue
        previous = seen.get(normalized)
        if previous is not None:
            duplicated.update((previous, hypothesis.hypothesis_id))
        else:
            seen[normalized] = hypothesis.hypothesis_id
    return duplicated


def claim_scope_violations(texts: Sequence[str], *, playbook: ReasoningPlaybook) -> tuple[str, ...]:
    """Return fixed classes of unsupported high-impact claims."""
    return tuple(dict.fromkeys(
        claim_class for text in texts if type(text) is str
        for claim_class in _claim_classes(text)
    ))


def scope_hypotheses_to_frame(
    hypotheses: Sequence[MioHypothesis], *, frame: MioSituationFrame,
    playbook: ReasoningPlaybook, prior_hypotheses: Sequence[MioHypothesis] = (),
) -> tuple[tuple[MioHypothesis, ...], tuple[tuple[str, tuple[str, ...]], ...]]:
    """Replace only detected unsupported high-impact prose and attach gaps.

    A flagged hypothesis keeps its ID, trusted alternative slot and grounded
    refs, but no model narrative, assumption, or test is copied. This is
    intentionally conservative and leaves normal safe model prose unchanged.
    """
    auth_context = is_authentication_context(frame, playbook)
    missing = authentication_frame_unknowns(frame) if auth_context else ()
    prior_by_id = {item.hypothesis_id: item for item in prior_hypotheses}
    roles = dict(playbook.hypothesis_alternatives)
    duplicate_ids = _duplicate_statement_groups(hypotheses)
    scoped: list[MioHypothesis] = []
    findings: list[tuple[str, tuple[str, ...]]] = []
    for hypothesis in hypotheses:
        narrative = " ".join((hypothesis.statement,) + hypothesis.assumptions + hypothesis.expected_observations + hypothesis.falsification_conditions)
        classes = _claim_classes(narrative)
        role = roles.get(hypothesis.hypothesis_alternative_id, "unresolved")
        role_mismatch = role == "benign" and any(
            _HOSTILE_TARGET.search(text) for text in hypothesis.falsification_conditions)
        structural = hypothesis.hypothesis_id in duplicate_ids or role_mismatch
        if auth_context or classes or structural:
            statement = _safe_role_statement(hypothesis.hypothesis_alternative_id, role)
            previous = prior_by_id.get(hypothesis.hypothesis_id)
            scoped_missing = list(missing)
            if "source_identity_unavailable" in classes and AUTH_SOURCE_UNKNOWN not in scoped_missing:
                scoped_missing.append(AUTH_SOURCE_UNKNOWN)
            if "host_impact_unavailable" in classes and AUTH_IMPACT_UNKNOWN not in scoped_missing:
                scoped_missing.append(AUTH_IMPACT_UNKNOWN)
            scoped.append(replace(hypothesis, statement=statement,
                                  status=previous.status if previous is not None else HypothesisStatus.PROPOSED,
                                  assumptions=(), expected_observations=(),
                                  falsification_conditions=(), missing_evidence=tuple(scoped_missing)))
            finding_classes = list(classes)
            if auth_context:
                finding_classes.append("auth_model_narrative_withheld")
            if hypothesis.hypothesis_id in duplicate_ids:
                finding_classes.append("duplicate_hypothesis_narrative")
            if role_mismatch:
                finding_classes.append("role_incoherent_falsification")
            findings.append((hypothesis.hypothesis_id, tuple(dict.fromkeys(finding_classes))))
        elif missing:
            merged = tuple(dict.fromkeys(hypothesis.missing_evidence + missing))[:8]
            scoped.append(replace(hypothesis, missing_evidence=merged))
        else:
            scoped.append(hypothesis)
    return tuple(scoped), tuple(findings)


def ground_auth_recommendation(recommendation):
    """Project auth advice onto fixed operator text and a non-actuating action."""
    return replace(
        recommendation,
        summary="Authentication observations require bounded verification.",
        recommended_action="OBSERVE",
        rationale="Model-generated detail is withheld; use the supplied observations, listed unknowns, and read-only checks.",
        limitations=("Authentication alternatives remain unverified; no model prose is presented as an observed fact.",),
    )


def deterministic_authentication_gaps(
    *, frame: MioSituationFrame, playbook: ReasoningPlaybook,
    hypotheses: Sequence[MioHypothesis], existing: Sequence[MioEvidenceGap],
    max_gaps: int,
) -> tuple[MioEvidenceGap, ...]:
    """Return only trusted, bounded auth checks using existing read capabilities.

    Model-provided questions are never carried through the auth path, even if
    they name an otherwise allowed capability. When the frame already
    resolves every auth unknown, no broker request is produced.
    """
    if not is_authentication_context(frame, playbook):
        return tuple(existing[:max_gaps])
    if max_gaps <= 0:
        return ()
    missing = set(authentication_frame_unknowns(frame))
    if not hypotheses:
        return ()
    additions: list[MioEvidenceGap] = []
    targets = tuple(h.hypothesis_id for h in hypotheses[:8])
    occupied = {gap.gap_id for gap in existing}
    candidate_id = 900
    for marker, question, capability, unknown in _AUTH_GAP_SPECS:
        if unknown not in missing or capability not in playbook.allowed_capabilities:
            continue
        while f"g{candidate_id}" in occupied:
            candidate_id += 1
        if candidate_id > 999:
            break
        additions.append(MioEvidenceGap(f"g{candidate_id}", question, targets, capability, priority=50))
        occupied.add(f"g{candidate_id}")
        candidate_id += 1
        if len(additions) >= max_gaps:
            break
    return tuple(additions[:max_gaps])

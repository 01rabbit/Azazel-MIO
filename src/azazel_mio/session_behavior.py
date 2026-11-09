"""Pure task-local session hypotheses (#57), never an AI identity classifier.

Products supply normalized, evidence-bound patterns. This helper reuses the
existing MioHypothesis shape and introduces no reasoner, model, collector,
transport or live product hook. Uncalibrated patterns always abstain from actor
identity and maliciousness; useful output is competing explanations/checks.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .contracts import HypothesisStatus, MioHypothesis, MioSituationFrame, model_id_ok
from .id_grammar import second_layer_ok

VERSION = "session-pattern-hypotheses/v1"
FEATURES = frozenset({"burst_pause_pattern", "error_followed_mutation", "discovery_followed_access",
                      "declared_ai_client", "local_canary_touch", "sustained_scanner_pattern",
                      "legitimate_monitor_context", "interactive_client_context", "malicious_payload_evidence"})
AI_COMPATIBLE = frozenset({"burst_pause_pattern", "error_followed_mutation", "discovery_followed_access", "declared_ai_client", "local_canary_touch"})
ALTERNATIVES = frozenset({"sustained_scanner_pattern", "legitimate_monitor_context", "interactive_client_context"})


def _reference(value: str) -> None:
    if type(value) is not str or not second_layer_ok(value):
        raise ValueError("invalid or sensitive session reference")


def _timestamp(value: str) -> datetime:
    if type(value) is not str or len(value) > 64:
        raise ValueError("invalid session timestamp")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("session timestamps require timezone")
    return dt


@dataclass(frozen=True)
class SessionFeature:
    kind: str
    present: bool | None
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self):
        if type(self.kind) is not str or self.kind not in FEATURES or self.present is not None and type(self.present) is not bool:
            raise ValueError("invalid normalized session feature")
        if type(self.evidence_refs) is not tuple or len(self.evidence_refs) > 16:
            raise ValueError("invalid bounded session evidence")
        if any(not model_id_ok(ref, "evidence_ref") for ref in self.evidence_refs):
            raise ValueError("invalid or sensitive session evidence ref")
        if self.present is not None and not self.evidence_refs:
            raise ValueError("observed feature requires evidence")
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("duplicate session evidence ref")


@dataclass(frozen=True)
class SessionWindow:
    frame_id: str
    session_ref: str
    boot_ref: str
    feature_version: str
    start: str
    end: str
    features: tuple[SessionFeature, ...]
    capture_complete: bool
    shared_source_ambiguity: bool = False
    clock_uncertain: bool = False

    def __post_init__(self):
        for value in (self.frame_id, self.session_ref, self.boot_ref, self.feature_version):
            _reference(value)
        start, end = _timestamp(self.start), _timestamp(self.end)
        if not 0 <= (end - start).total_seconds() <= 3600:
            raise ValueError("invalid bounded session window")
        if type(self.features) is not tuple or len(self.features) > len(FEATURES) or any(type(x) is not SessionFeature for x in self.features):
            raise ValueError("invalid bounded feature vector")
        if len({x.kind for x in self.features}) != len(self.features):
            raise ValueError("duplicate session feature")
        if any(type(flag) is not bool for flag in (self.capture_complete, self.shared_source_ambiguity, self.clock_uncertain)):
            raise ValueError("coverage flags must be explicit booleans")


def assess_session(frame: MioSituationFrame, window: SessionWindow, *, as_of: str, max_age_seconds: int = 300) -> dict:
    if type(frame) is not MioSituationFrame or type(window) is not SessionWindow or frame.frame_id != window.frame_id:
        raise ValueError("session/frame binding mismatch")
    if type(max_age_seconds) is not int or not 0 <= max_age_seconds <= 3600:
        raise ValueError("invalid product freshness budget")
    # Recheck immutable input boundaries: bypassing dataclass initialization is
    # not a way to introduce raw strings, secret identifiers or arbitrary work.
    window.__post_init__()
    for feature in window.features:
        feature.__post_init__()
    now, end, created = _timestamp(as_of), _timestamp(window.end), _timestamp(frame.created_at)
    if any(ref not in frame.evidence_refs for feature in window.features for ref in feature.evidence_refs):
        raise ValueError("session evidence is not in the bound frame")
    reasons = []
    if end > created or created > now or (now - end).total_seconds() > max_age_seconds:
        reasons.append("stale_or_noncurrent_window")
    if frame.truncated or not window.capture_complete:
        reasons.append("capture_incomplete")
    if window.shared_source_ambiguity:
        reasons.append("shared_source_not_actor_identity")
    if window.clock_uncertain:
        reasons.append("clock_uncertain")
    present = {f.kind: f for f in window.features if f.present is True}
    missing = sorted(FEATURES - {f.kind for f in window.features if f.present is not None})
    if not present.keys() & (AI_COMPATIBLE | ALTERNATIVES):
        reasons.append("no_supported_pattern")
    hypotheses = []
    if not reasons:
        def refs(kinds):
            return tuple(dict.fromkeys(ref for kind in sorted(kinds & present.keys()) for ref in present[kind].evidence_refs))[:16]
        hypotheses = [
            MioHypothesis("h1", "Observed patterns may be compatible with AI-assisted tools.", HypothesisStatus.UNRESOLVED,
                          supporting_evidence_refs=refs(AI_COMPATIBLE), contradicting_evidence_refs=refs(ALTERNATIVES),
                          assumptions=("Patterns are spoofable and not calibrated to actor identity.",),
                          falsification_conditions=("Independent controlled-client provenance supports a different explanation.",),
                          missing_evidence=("Independently verified client provenance and held-out calibration.",)),
            MioHypothesis("h2", "Conventional automation, scanner or scripted retry remains plausible.", HypothesisStatus.UNRESOLVED,
                          supporting_evidence_refs=refs({"sustained_scanner_pattern", "error_followed_mutation", "local_canary_touch"}),
                          assumptions=("A copied link, prefetch or scanner can touch a canary.",),
                          falsification_conditions=("Independent controlled execution excludes conventional automation.",)),
            MioHypothesis("h3", "Legitimate monitoring or human-directed activity remains plausible.", HypothesisStatus.UNRESOLVED,
                          supporting_evidence_refs=refs({"legitimate_monitor_context", "interactive_client_context"}),
                          contradicting_evidence_refs=refs({"malicious_payload_evidence"}),
                          assumptions=("Automation does not establish malicious intent.",),
                          falsification_conditions=("Independently verified protected-goal evidence contradicts benign use.",)),
        ]
    return {"schema_version": VERSION, "frame_id": window.frame_id, "session_ref": window.session_ref,
            "boot_ref": window.boot_ref, "feature_version": window.feature_version,
            "status": "insufficient_evidence" if reasons else "hypotheses_available",
            "identity_label": "unknown", "maliciousness": "not_assessed", "abstained": True,
            "probability": None, "model_calls": 0,
            "hypotheses": [h.to_dict() for h in hypotheses],
            "factors": [{"kind": f.kind, "present": f.present, "evidence_refs": list(f.evidence_refs)} for f in sorted(window.features, key=lambda f: f.kind)],
            "missing_features": missing, "withholding_reasons": reasons,
            "next_read_only_checks": ["Review capture coverage and client provenance.", "Verify independently observed protected-service behavior."],
            "limitations": ["Features are product-reported observations, not verified actor identity.", "Timing, headers and canary touches are not conclusive AI or maliciousness evidence.", "No probability is calibrated; no action, severity change or capability is authorized."],
            "authorized_actions": []}

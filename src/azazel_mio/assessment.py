"""Deterministic, advisory-only assessment of explicitly tagged observations.

This baseline is NOT a maliciousness classifier or calibrated probability.
Signals are asserted by a trusted parser/reviewer, never inferred from raw text.
"""
from dataclasses import dataclass
from typing import Iterable

RULE_VERSION = "ir-baseline-0.1"
SIGNAL_WEIGHTS = {
    "suspicious_process": 30,
    "unusual_outbound": 20,
    "authentication_failures": 15,
    "confirmed_malware_indicator": 40,
}
READ_ONLY_CHECKS = {
    "suspicious_process": "Review process ancestry and command-line evidence.",
    "unusual_outbound": "Review DNS, destination and connection context.",
    "authentication_failures": "Review authentication event scope and timing.",
    "confirmed_malware_indicator": "Verify indicator source, freshness and matching evidence.",
}

@dataclass(frozen=True)
class Observation:
    case_id: str
    evidence_id: str
    signal: str

def assess(case_id: str, observations: Iterable[Observation]) -> dict:
    """Produce bounded, traceable advisory priority; never authorize action."""
    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError("case_id required")
    items = list(observations)
    if len(items) > 10000:
        raise ValueError("too many observations")
    hits = {}
    unsupported = 0
    for obs in items:
        if not isinstance(obs, Observation) or obs.case_id != case_id:
            raise ValueError("invalid or cross-case observation")
        if not obs.evidence_id.strip():
            raise ValueError("missing evidence reference")
        if obs.signal not in SIGNAL_WEIGHTS:
            unsupported += 1
            continue
        hits.setdefault(obs.signal, set()).add(obs.evidence_id)
    score = min(100, sum(SIGNAL_WEIGHTS[s] for s in hits))
    status = "insufficient_evidence" if not hits else "review_recommended"
    return {
        "case_id": case_id,
        "rule_version": RULE_VERSION,
        "status": status,
        "priority_index": score,
        "priority_index_is_probability": False,
        "rule_hits": [
            {"signal": signal, "weight": SIGNAL_WEIGHTS[signal],
             "evidence_ids": sorted(refs)}
            for signal, refs in sorted(hits.items())
        ],
        "unsupported_observations": unsupported,
        "limitations": [
            "Advisory priority only; not a verdict of maliciousness.",
            "Signals require independent validation by a trusted parser or reviewer.",
            "No calibration, incident outcome, or enforcement authority is implied.",
        ],
        "next_read_only_checks": [READ_ONLY_CHECKS[s] for s in sorted(hits)],
        "authorized_actions": [],
    }

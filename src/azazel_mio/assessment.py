"""Deterministic, advisory-only assessment of explicitly tagged observations.

This baseline is NOT a maliciousness classifier or calibrated probability.
Signals are asserted by a trusted parser/reviewer, never inferred from raw text.
"""
from dataclasses import dataclass
from itertools import islice
from typing import Iterable

_MAX_OBSERVATIONS = 10000
_MAX_ID_LENGTH = 256
_MAX_SIGNAL_LENGTH = 128

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

def _canonical_text(value: object, limit: int) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= limit
            and value == value.strip() and value.isprintable())


def assess(case_id: str, observations: Iterable[Observation]) -> dict:
    """Produce bounded, traceable advisory priority; never authorize action."""
    if not _canonical_text(case_id, _MAX_ID_LENGTH):
        raise ValueError("invalid case_id")
    try:
        iterator = iter(observations)
    except TypeError:
        raise ValueError("observations must be iterable") from None
    items = list(islice(iterator, _MAX_OBSERVATIONS + 1))
    if len(items) > _MAX_OBSERVATIONS:
        raise ValueError("too many observations")
    hits = {}
    unsupported = 0
    for obs in items:
        if (not isinstance(obs, Observation)
                or not _canonical_text(obs.case_id, _MAX_ID_LENGTH)
                or obs.case_id != case_id):
            raise ValueError("invalid or cross-case observation")
        if not _canonical_text(obs.evidence_id, _MAX_ID_LENGTH):
            raise ValueError("invalid evidence reference")
        if not _canonical_text(obs.signal, _MAX_SIGNAL_LENGTH):
            raise ValueError("invalid signal")
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

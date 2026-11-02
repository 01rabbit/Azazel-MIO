"""Pure, fail-closed review-routing recommendation for an assess() result.

Advisory only: this module never calls Knowledge or any model, never enqueues
work, never executes checks, and never grants authority. Output reason codes
are fixed constants; untrusted input values are never echoed.
"""
from collections.abc import Mapping
from dataclasses import dataclass

from azazel_mio.assessment import READ_ONLY_CHECKS, RULE_VERSION, SIGNAL_WEIGHTS

PATH_READ_ONLY_CHECKS = "read_only_checks"
PATH_HUMAN_REVIEW = "human_review"

REASON_REVIEW_WITH_CHECKS = "review_recommended_read_only_checks"
REASON_UNSUPPORTED_PRESENT = "unsupported_observations_present"
REASON_INSUFFICIENT_EVIDENCE = "insufficient_evidence"
REASON_INVALID_SHAPE = "invalid_result_shape"
REASON_INVALID_STATUS = "unsupported_status"
REASON_INVALID_COUNT = "invalid_count"
REASON_INVALID_CHECKS = "invalid_checks"
REASON_INVALID_EVIDENCE = "invalid_evidence_reference"

# Mirrors the observation bound enforced by assess() in assessment.py.
_MAX_OBSERVATIONS = 10000
_MAX_ID_LENGTH = 256
_MAX_PRIORITY = 100
_STATUSES = ("review_recommended", "insufficient_evidence")
_PATHS = (PATH_READ_ONLY_CHECKS, PATH_HUMAN_REVIEW)
_EXPECTED_KEYS = frozenset({
    "case_id", "rule_version", "status", "priority_index",
    "priority_index_is_probability", "rule_hits", "unsupported_observations",
    "limitations", "next_read_only_checks", "authorized_actions",
})
_HIT_KEYS = frozenset({"signal", "weight", "evidence_ids"})
_KNOWN_REASONS = frozenset({
    REASON_REVIEW_WITH_CHECKS, REASON_UNSUPPORTED_PRESENT,
    REASON_INSUFFICIENT_EVIDENCE, REASON_INVALID_SHAPE, REASON_INVALID_STATUS,
    REASON_INVALID_COUNT, REASON_INVALID_CHECKS, REASON_INVALID_EVIDENCE,
})
# Canonical check order mirrors assess(): checks are emitted sorted by signal.
_CANONICAL_CHECKS = tuple(READ_ONLY_CHECKS[s] for s in sorted(READ_ONLY_CHECKS))
_CHECK_INDEX = {text: index for index, text in enumerate(_CANONICAL_CHECKS)}


def _is_empty_tuple(value: object) -> bool:
    return type(value) is tuple and len(value) == 0


@dataclass(frozen=True)
class FastReviewRecommendation:
    path: str
    deeper_review_recommended: bool
    reason_codes: tuple
    read_only_checks: tuple = ()
    automatic_dispatch: bool = False
    authorized_actions: tuple = ()

    def __post_init__(self):
        if self.automatic_dispatch is not False or not _is_empty_tuple(self.authorized_actions):
            raise ValueError("recommendation must never dispatch or authorize")
        if type(self.path) is not str or self.path not in _PATHS:
            raise ValueError("unknown routing path")
        if type(self.deeper_review_recommended) is not bool:
            raise ValueError("deeper_review_recommended must be a bool")

        reasons = self.reason_codes
        if type(reasons) is not tuple or not 0 < len(reasons) <= len(_KNOWN_REASONS):
            raise ValueError("reason_codes must be a bounded non-empty tuple")
        if any(type(code) is not str or code not in _KNOWN_REASONS for code in reasons):
            raise ValueError("unknown reason code")
        if len(set(reasons)) != len(reasons):
            raise ValueError("duplicate reason code")

        checks = self.read_only_checks
        if type(checks) is not tuple or len(checks) > len(_CANONICAL_CHECKS):
            raise ValueError("read_only_checks must be a bounded tuple")
        indexes = []
        for check in checks:
            if type(check) is not str or check not in _CHECK_INDEX:
                raise ValueError("unknown read-only check")
            indexes.append(_CHECK_INDEX[check])
        if indexes != sorted(set(indexes)):
            raise ValueError("read-only checks must be unique and canonically ordered")

        if self.path == PATH_HUMAN_REVIEW and checks:
            raise ValueError("human_review must not carry read-only checks")
        if self.path == PATH_READ_ONLY_CHECKS and not checks:
            raise ValueError("read_only_checks path requires at least one check")


class _Reject(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _is_int(value: object) -> bool:
    return type(value) is int


def _canonical_text(value: object) -> bool:
    return (type(value) is str and 0 < len(value) <= _MAX_ID_LENGTH
            and value == value.strip() and value.isprintable())


def _validate_hit(hit: object) -> str:
    if not isinstance(hit, Mapping) or set(hit.keys()) != _HIT_KEYS:
        raise _Reject(REASON_INVALID_SHAPE)
    signal = hit["signal"]
    if type(signal) is not str or signal not in SIGNAL_WEIGHTS:
        raise _Reject(REASON_INVALID_SHAPE)
    if not _is_int(hit["weight"]) or hit["weight"] != SIGNAL_WEIGHTS[signal]:
        raise _Reject(REASON_INVALID_SHAPE)
    refs = hit["evidence_ids"]
    if type(refs) is not list or not refs or len(refs) > _MAX_OBSERVATIONS:
        raise _Reject(REASON_INVALID_COUNT)
    if not all(_canonical_text(ref) for ref in refs):
        raise _Reject(REASON_INVALID_EVIDENCE)
    return signal


def _recommend(result: object) -> FastReviewRecommendation:
    if not isinstance(result, Mapping) or set(result.keys()) != _EXPECTED_KEYS:
        raise _Reject(REASON_INVALID_SHAPE)
    if not _canonical_text(result["case_id"]):
        raise _Reject(REASON_INVALID_SHAPE)
    status = result["status"]
    if type(status) is not str or status not in _STATUSES:
        raise _Reject(REASON_INVALID_STATUS)
    if result["rule_version"] != RULE_VERSION:
        raise _Reject(REASON_INVALID_SHAPE)
    if result["priority_index_is_probability"] is not False:
        raise _Reject(REASON_INVALID_SHAPE)
    actions = result["authorized_actions"]
    if type(actions) is not list or actions:
        raise _Reject(REASON_INVALID_SHAPE)

    priority = result["priority_index"]
    unsupported = result["unsupported_observations"]
    if not _is_int(priority) or not 0 <= priority <= _MAX_PRIORITY:
        raise _Reject(REASON_INVALID_COUNT)
    if not _is_int(unsupported) or not 0 <= unsupported <= _MAX_OBSERVATIONS:
        raise _Reject(REASON_INVALID_COUNT)

    hits = result["rule_hits"]
    checks = result["next_read_only_checks"]
    if type(hits) is not list or len(hits) > len(SIGNAL_WEIGHTS):
        raise _Reject(REASON_INVALID_COUNT)
    if type(checks) is not list or len(checks) > len(READ_ONLY_CHECKS):
        raise _Reject(REASON_INVALID_COUNT)

    signals = []
    total_evidence = 0
    for hit in hits:
        signals.append(_validate_hit(hit))
        total_evidence += len(hit["evidence_ids"])
        if total_evidence > _MAX_OBSERVATIONS:
            raise _Reject(REASON_INVALID_COUNT)
    if signals != sorted(set(signals)):
        raise _Reject(REASON_INVALID_SHAPE)

    deeper = unsupported > 0
    if status == "insufficient_evidence":
        if hits or checks or priority != 0:
            raise _Reject(REASON_INVALID_SHAPE)
        reasons = (REASON_INSUFFICIENT_EVIDENCE,)
        if deeper:
            reasons += (REASON_UNSUPPORTED_PRESENT,)
        return FastReviewRecommendation(PATH_HUMAN_REVIEW, deeper, reasons)

    if not hits:
        raise _Reject(REASON_INVALID_SHAPE)
    # Cross-check the advisory priority against the validated hits: it must be
    # exactly the capped sum of their signal weights, never a free value.
    expected_priority = min(_MAX_PRIORITY, sum(SIGNAL_WEIGHTS[s] for s in signals))
    if priority != expected_priority:
        raise _Reject(REASON_INVALID_COUNT)
    expected = tuple(READ_ONLY_CHECKS[s] for s in signals)
    if tuple(checks) != expected:
        raise _Reject(REASON_INVALID_CHECKS)
    reasons = (REASON_REVIEW_WITH_CHECKS,)
    if deeper:
        reasons += (REASON_UNSUPPORTED_PRESENT,)
    return FastReviewRecommendation(
        PATH_READ_ONLY_CHECKS, deeper, reasons, read_only_checks=expected)


def recommend_fast_review(result: Mapping) -> FastReviewRecommendation:
    """Map an assess() result to a bounded, advisory routing recommendation.

    Any malformed, untrusted, or unsupported input fails closed to human_review
    with a stable reason code and no checks.
    """
    try:
        return _recommend(result)
    except _Reject as rejected:
        return FastReviewRecommendation(
            PATH_HUMAN_REVIEW, False, (rejected.code,))

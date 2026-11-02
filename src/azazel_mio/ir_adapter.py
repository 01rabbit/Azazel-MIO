"""Offline adapter linking verified IR case evidence to the fast-assessment kernel.

The adapter is a pure callable. It performs no model, network or file I/O and
adds no scoring weights or rules: every score comes from
:func:`azazel_mio.fast_assessment.assess_fast`. Signals in
:class:`FastAssessmentInput` are caller-asserted and are marked
``caller_asserted_unverified``; the adapter never infers classes, labels or
severity from raw text.

Row contract (keys read by this adapter; other keys are ignored):

* ``timeline`` rows: ``case_id``, ``event_id``, ``evidence_id``, ``record``
  (the record number, as emitted by the IR store's ``timeline`` output). Every
  value is a strict positive ``int``.
* ``verified_evidence`` rows: ``case_id``, ``evidence_id`` (strict positive
  ``int``) and ``valid`` (strict ``bool``). Only ``valid is True`` rows can be
  referenced.

The IR store's ``timeline`` and ``verify`` outputs carry ``case_id`` on every
row. Callers must pass the timeline and verify rows of one selected case; the
``case_id`` check rejects rows from any other case.

:func:`parse_candidate_document` parses the versioned, strict normalized-input
document into candidates. It performs no I/O.

Malformed input or a mismatched reference raises ``ValueError`` before the
kernel is called. A candidate whose caller asserts a conflict with
integrity-verified evidence is reported as ``abstained_conflict`` without a
score. The conflict semantics are caller-asserted and not verified.

The output is an advisory candidate, not a verified fact, a calibrated
probability, training ground truth, or an authorized action. There is no
case-level aggregation.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from .fast_assessment import FastAssessmentInput, PortSignal, assess_fast

ADAPTER_VERSION: Final[str] = "ir-fast-assessment-adapter-0.1"
OUTPUT_SCHEMA: Final[str] = "ir-fast-assessment-candidates/0.1"
PROVENANCE: Final[str] = "caller_asserted_unverified"
INPUT_SCHEMA: Final[str] = "mio.ir.fast-assessment-inputs.v1"
KERNEL_SOURCE_REVISION: Final[str] = (
    "Azazel-Edge/py/azazel_edge/tactics_engine/scorer.py@47c880b2503d7f771bbdacba9b6205dafe03c4c7"
)

_MAX_ROWS: Final[int] = 1000
_MAX_CANDIDATES: Final[int] = 256
_MAX_CONFLICTS: Final[int] = 16
_MAX_CLASSES: Final[int] = 16
_MAX_PORTS: Final[int] = 16
_MAX_INT: Final[int] = 2**63 - 1
_MAX_SEVERITY: Final[int] = 255
_MAX_PORT: Final[int] = 65535
_NORMALIZER_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_DOCUMENT_KEYS: Final[frozenset[str]] = frozenset({"schema_version", "case_id", "candidates"})
_CANDIDATE_KEYS: Final[frozenset[str]] = frozenset(
    {"event_id", "evidence_id", "record_number", "normalizer_version", "inputs"}
)
_CANDIDATE_OPTIONAL_KEYS: Final[frozenset[str]] = frozenset({"conflict_evidence_ids"})
_INPUT_KEYS: Final[frozenset[str]] = frozenset(
    {"severity", "classes", "token_only", "ports", "action", "deception_sid", "benign_classless"}
)
_PORT_KEYS: Final[frozenset[str]] = frozenset({"kind", "port"})

_LIMITATIONS: Final[tuple[str, ...]] = (
    "caller_asserted_unverified: normalized signals were supplied by the caller and are not verified by this adapter",
    "not_probability: the score is an ordinal advisory priority index, not a calibrated probability",
    "not_ground_truth: the output is not a verified fact or a training label",
    "no_case_aggregation: each event is scored independently; no case-level score is produced",
    "no_authority: the output authorizes no control, enforcement, containment or decoy action",
)
_NOTE_SCORED: Final[str] = (
    "Candidate-only advisory priority index from caller-asserted normalized signals; "
    "factors are the kernel terms. Not a fact, probability or authorization."
)


@dataclass(frozen=True)
class IRFastAssessmentCandidate:
    """One event's caller-normalized signals linked to verified evidence.

    ``conflict_evidence_ids`` names integrity-verified evidence in the same case
    that the caller asserts contradicts the normalized signals. The adapter checks
    only the digest and case linkage of that evidence, not the contradiction itself.
    A non-empty tuple abstains the event.
    """

    event_id: int
    evidence_id: int
    record_number: int
    normalizer_version: str
    inputs: FastAssessmentInput
    conflict_evidence_ids: tuple[int, ...] = ()


def _is_int(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _is_id(value: object) -> bool:
    return _is_int(value, 1, _MAX_INT)


def _is_token(value: object) -> bool:
    return type(value) is str and _TOKEN_RE.fullmatch(value) is not None


def _rows(name: str, value: object, limit: int) -> list[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{name} must be a sequence")
    if len(value) > limit:
        raise ValueError(f"{name} exceeds bound")
    return list(value)


def _mapping(row: object) -> Mapping[str, object]:
    if not isinstance(row, Mapping):
        raise ValueError("row must be a mapping")
    return row


def _index_timeline(case_id: int, rows: object) -> dict[int, tuple[int, int]]:
    index: dict[int, tuple[int, int]] = {}
    for raw in _rows("timeline", rows, _MAX_ROWS):
        row = _mapping(raw)
        case, event_id = row.get("case_id"), row.get("event_id")
        evidence_id, record = row.get("evidence_id"), row.get("record")
        if not all(_is_id(v) for v in (case, event_id, evidence_id, record)):
            raise ValueError("timeline row has malformed ids")
        if case != case_id:
            raise ValueError("timeline row belongs to another case")
        if event_id in index:
            raise ValueError("duplicate timeline event")
        index[event_id] = (evidence_id, record)
    return index


def _index_verified(case_id: int, rows: object) -> dict[int, bool]:
    index: dict[int, bool] = {}
    for raw in _rows("verified_evidence", rows, _MAX_ROWS):
        row = _mapping(raw)
        case, evidence_id, valid = row.get("case_id"), row.get("evidence_id"), row.get("valid")
        if not (_is_id(case) and _is_id(evidence_id) and type(valid) is bool):
            raise ValueError("verified evidence row is malformed")
        if case != case_id:
            raise ValueError("verified evidence belongs to another case")
        if evidence_id in index:
            raise ValueError("duplicate verified evidence")
        index[evidence_id] = valid
    return index


def _check_inputs(inputs: object) -> None:
    if type(inputs) is not FastAssessmentInput:
        raise ValueError("inputs must be FastAssessmentInput")
    if not _is_int(inputs.severity, 0, _MAX_SEVERITY):
        raise ValueError("severity out of bounds")
    if type(inputs.classes) is not tuple or len(inputs.classes) > _MAX_CLASSES:
        raise ValueError("classes must be a bounded tuple")
    if not all(_is_token(name) for name in inputs.classes):
        raise ValueError("classes must be canonical lower-case tokens")
    if type(inputs.token_only) is not bool:
        raise ValueError("token_only must be bool")
    if type(inputs.ports) is not tuple or len(inputs.ports) > _MAX_PORTS:
        raise ValueError("ports must be a bounded tuple")
    for port in inputs.ports:
        if type(port) is not PortSignal or not _is_token(port.kind):
            raise ValueError("port signal is malformed")
        if not _is_int(port.port, 1, _MAX_PORT):
            raise ValueError("port out of bounds")
    if not _is_token(inputs.action):
        raise ValueError("action must be a canonical lower-case token")
    if type(inputs.deception_sid) is not bool or type(inputs.benign_classless) is not bool:
        raise ValueError("boolean signals must be bool")


def _check_candidate(
    candidate: object,
    seen: set[int],
    timeline: dict[int, tuple[int, int]],
    verified: dict[int, bool],
) -> None:
    if type(candidate) is not IRFastAssessmentCandidate:
        raise ValueError("candidate must be IRFastAssessmentCandidate")
    if not _is_id(candidate.event_id) or candidate.event_id in seen:
        raise ValueError("candidate event_id is malformed or duplicated")
    if not (_is_id(candidate.evidence_id) and _is_id(candidate.record_number)):
        raise ValueError("candidate references are malformed")
    if type(candidate.normalizer_version) is not str or not _NORMALIZER_RE.fullmatch(candidate.normalizer_version):
        raise ValueError("normalizer_version must be bounded canonical text")
    _check_inputs(candidate.inputs)
    if timeline.get(candidate.event_id) != (candidate.evidence_id, candidate.record_number):
        raise ValueError("candidate does not match timeline linkage")
    if verified.get(candidate.evidence_id) is not True:
        raise ValueError("candidate evidence is not verified in this case")
    conflicts = candidate.conflict_evidence_ids
    if type(conflicts) is not tuple or len(conflicts) > _MAX_CONFLICTS:
        raise ValueError("conflict_evidence_ids must be a bounded tuple")
    for evidence_id in conflicts:
        if not _is_id(evidence_id) or verified.get(evidence_id) is not True:
            raise ValueError("conflict evidence is not verified in this case")
    if len(set(conflicts)) != len(conflicts):
        raise ValueError("conflict_evidence_ids must be unique")


def _exact_keys(
    name: str, value: object, required: frozenset[str], optional: frozenset[str] = frozenset()
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    keys = set(value)
    if not required <= keys or not keys <= required | optional:
        raise ValueError(f"{name} has missing or unknown keys")
    return value


def _json_list(name: str, value: object, limit: int) -> list[object]:
    if type(value) is not list or len(value) > limit:
        raise ValueError(f"{name} must be a bounded list")
    return value


def _parse_inputs(value: object) -> FastAssessmentInput:
    raw = _exact_keys("inputs", value, _INPUT_KEYS)
    ports = []
    for port in _json_list("ports", raw["ports"], _MAX_PORTS):
        fields = _exact_keys("port", port, _PORT_KEYS)
        ports.append(PortSignal(kind=fields["kind"], port=fields["port"]))
    return FastAssessmentInput(
        severity=raw["severity"],
        classes=tuple(_json_list("classes", raw["classes"], _MAX_CLASSES)),
        token_only=raw["token_only"],
        ports=tuple(ports),
        action=raw["action"],
        deception_sid=raw["deception_sid"],
        benign_classless=raw["benign_classless"],
    )


def _parse_candidate(value: object) -> IRFastAssessmentCandidate:
    raw = _exact_keys("candidate", value, _CANDIDATE_KEYS, _CANDIDATE_OPTIONAL_KEYS)
    return IRFastAssessmentCandidate(
        event_id=raw["event_id"],
        evidence_id=raw["evidence_id"],
        record_number=raw["record_number"],
        normalizer_version=raw["normalizer_version"],
        inputs=_parse_inputs(raw["inputs"]),
        conflict_evidence_ids=tuple(
            _json_list("conflict_evidence_ids", raw.get("conflict_evidence_ids", []), _MAX_CONFLICTS)
        ),
    )


def parse_candidate_document(document: object, case_id: int) -> list[IRFastAssessmentCandidate]:
    """Parse a ``mio.ir.fast-assessment-inputs.v1`` document, fail closed.

    Checks the exact key sets, the schema version, the case id and the list
    bounds. Field types are carried through unchanged, and
    :func:`assess_ir_candidates` enforces their values, linkage and bounds.
    No text is inferred into labels, classes or severity.
    """
    raw = _exact_keys("document", document, _DOCUMENT_KEYS)
    if raw["schema_version"] != INPUT_SCHEMA:
        raise ValueError("unsupported schema_version")
    if type(raw["case_id"]) is not int or raw["case_id"] != case_id:
        raise ValueError("input case_id does not match the selected case")
    return [_parse_candidate(item) for item in _json_list("candidates", raw["candidates"], _MAX_CANDIDATES)]


def assess_ir_candidates(
    case_id: int,
    timeline: Sequence[Mapping[str, object]],
    verified_evidence: Sequence[Mapping[str, object]],
    candidates: Sequence[IRFastAssessmentCandidate],
) -> dict:
    """Score linked candidates with the fast-assessment kernel, fail closed.

    All references are validated before any kernel call. Each non-conflicted
    candidate is scored exactly once. The result is advisory and
    JSON-serializable; it is not a fact, probability or authorization.
    """
    if not _is_id(case_id):
        raise ValueError("invalid case_id")
    timeline_index = _index_timeline(case_id, timeline)
    verified = _index_verified(case_id, verified_evidence)
    items = _rows("candidates", candidates, _MAX_CANDIDATES)

    if not items:
        return {
            "schema": OUTPUT_SCHEMA,
            "adapter_version": ADAPTER_VERSION,
            "case_id": case_id,
            "kernel_source_revision": KERNEL_SOURCE_REVISION,
            "status": "abstained_no_normalized_input",
            "candidates": [],
            "limitations": list(_LIMITATIONS),
        }

    seen: set[int] = set()
    for candidate in items:
        _check_candidate(candidate, seen, timeline_index, verified)
        seen.add(candidate.event_id)

    results: list[dict] = []
    for candidate in sorted(items, key=lambda c: c.event_id):
        entry: dict[str, object] = {
            "event_id": candidate.event_id,
            "record_number": candidate.record_number,
            "evidence_refs": [candidate.evidence_id],
            "normalizer_version": candidate.normalizer_version,
            "provenance": PROVENANCE,
        }
        if candidate.conflict_evidence_ids:
            entry.update(
                status="abstained_conflict",
                score=None,
                factors=[],
                conflict_evidence_ids=sorted(candidate.conflict_evidence_ids),
                explanation="Abstained: caller-asserted conflict involving integrity-verified evidence; conflict semantics unverified. No score computed. Not a fact, probability or authorization.",
            )
        else:
            assessment = assess_fast(candidate.inputs)
            entry.update(
                status="scored",
                score=assessment.score,
                factors=list(assessment.factors),
                conflict_evidence_ids=[],
                explanation=_NOTE_SCORED,
            )
        results.append(entry)

    return {
        "schema": OUTPUT_SCHEMA,
        "adapter_version": ADAPTER_VERSION,
        "case_id": case_id,
        "kernel_source_revision": KERNEL_SOURCE_REVISION,
        "status": "candidates",
        "candidates": results,
        "limitations": list(_LIMITATIONS),
    }

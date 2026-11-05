import json

import pytest

from azazel_mio import ir_adapter
from azazel_mio.fast_assessment import FastAssessmentInput, PortSignal, assess_fast
from azazel_mio.ir_adapter import (
    IRFastAssessmentCandidate,
    assess_ir_candidates,
    parse_candidate_document,
)

CASE = 7


def _timeline(*rows):
    return [
        {"case_id": CASE, "event_id": e, "evidence_id": v, "record": r}
        for e, v, r in rows
    ]


def _verified(*rows):
    return [{"case_id": CASE, "evidence_id": v, "valid": valid} for v, valid in rows]


def _base():
    timeline = _timeline((1, 101, 5), (2, 102, 6))
    verified = _verified((101, True), (102, True), (103, True))
    return timeline, verified


def _candidate(**overrides):
    values = dict(
        event_id=1,
        evidence_id=101,
        record_number=5,
        normalizer_version="norm-1",
        inputs=FastAssessmentInput(severity=2, classes=("c2",), action="drop"),
    )
    values.update(overrides)
    return IRFastAssessmentCandidate(**values)


def _no_core(monkeypatch):
    def fail(_inputs):
        raise AssertionError("kernel must not be called")

    monkeypatch.setattr(ir_adapter, "assess_fast", fail)


def test_valid_candidate_matches_core_output_and_provenance():
    timeline, verified = _base()
    inputs = FastAssessmentInput(
        severity=2,
        classes=("exfil", "c2", "future-class"),
        ports=(PortSignal("web", 443),),
        action="drop",
    )
    result = assess_ir_candidates(
        CASE, timeline, verified, [_candidate(inputs=inputs)]
    )
    expected = assess_fast(inputs)

    assert result["status"] == "candidates"
    assert result["case_id"] == CASE
    assert result["kernel_source_revision"] == ir_adapter.KERNEL_SOURCE_REVISION == (
        "Azazel-Edge/py/azazel_edge/tactics_engine/scorer.py@47c880b2503d7f771bbdacba9b6205dafe03c4c7"
    )
    (entry,) = result["candidates"]
    assert entry["status"] == "scored"
    assert entry["score"] == expected.score == 93
    assert entry["factors"] == list(expected.factors)
    assert entry["factors"] == [
        "severity=2",
        "sid_present",
        "threat_class=c2(48)",
        "threat_class=exfil(46)",
        "web_port=443",
        "action=drop(contained)",
    ]
    assert entry["evidence_refs"] == [101]
    assert entry["conflict_evidence_ids"] == []
    assert entry["provenance"] == "caller_asserted_unverified"
    assert entry["normalizer_version"] == "norm-1"
    assert "Not a fact" in entry["explanation"]
    assert any("not_probability" in item for item in result["limitations"])
    assert any("no_case_aggregation" in item for item in result["limitations"])


def test_output_is_json_serializable_and_sorted_by_event():
    timeline, verified = _base()
    candidates = [
        _candidate(event_id=2, evidence_id=102, record_number=6),
        _candidate(),
    ]
    result = assess_ir_candidates(CASE, timeline, verified, candidates)

    assert [c["event_id"] for c in result["candidates"]] == [1, 2]
    assert json.loads(json.dumps(result)) == result


def test_unknown_signals_rely_on_kernel_fallback():
    timeline, verified = _base()
    inputs = FastAssessmentInput(severity=9, classes=("future-class",), action="unknown")
    result = assess_ir_candidates(CASE, timeline, verified, [_candidate(inputs=inputs)])

    (entry,) = result["candidates"]
    assert entry["score"] == 16
    assert entry["factors"] == ["severity=9"]


def test_empty_candidates_abstain_without_core_call(monkeypatch):
    timeline, verified = _base()
    _no_core(monkeypatch)
    result = assess_ir_candidates(CASE, timeline, verified, [])

    assert result["status"] == "abstained_no_normalized_input"
    assert result["candidates"] == []
    assert result["limitations"]
    assert result["kernel_source_revision"] == ir_adapter.KERNEL_SOURCE_REVISION


def test_conflicting_candidate_abstains_and_skips_core(monkeypatch):
    timeline, verified = _base()
    _no_core(monkeypatch)
    result = assess_ir_candidates(
        CASE, timeline, verified, [_candidate(conflict_evidence_ids=(103,))]
    )

    (entry,) = result["candidates"]
    assert entry["status"] == "abstained_conflict"
    assert entry["score"] is None
    assert entry["factors"] == []
    assert entry["conflict_evidence_ids"] == [103]
    assert entry["evidence_refs"] == [101]
    assert "caller-asserted conflict" in entry["explanation"]
    assert "conflict semantics unverified" in entry["explanation"]
    assert "verified conflicting evidence is present" not in entry["explanation"]
    assert result["kernel_source_revision"] == ir_adapter.KERNEL_SOURCE_REVISION


def test_only_non_conflicted_candidates_reach_core_exactly_once(monkeypatch):
    timeline, verified = _base()
    calls = []
    real = ir_adapter.assess_fast

    def counting(inputs):
        calls.append(inputs)
        return real(inputs)

    monkeypatch.setattr(ir_adapter, "assess_fast", counting)
    result = assess_ir_candidates(
        CASE,
        timeline,
        verified,
        [
            _candidate(),
            _candidate(event_id=2, evidence_id=102, record_number=6, conflict_evidence_ids=(103,)),
        ],
    )

    assert len(calls) == 1
    statuses = {c["event_id"]: c["status"] for c in result["candidates"]}
    assert statuses == {1: "scored", 2: "abstained_conflict"}


@pytest.mark.parametrize(
    "timeline, verified, candidates",
    [
        # unverified evidence referenced by the candidate
        (_timeline((1, 101, 5)), _verified((101, False)), [_candidate()]),
        # referenced evidence absent from verified rows
        (_timeline((1, 101, 5)), _verified((999, True)), [_candidate()]),
        # event absent from timeline
        (_timeline((9, 101, 5)), _verified((101, True)), [_candidate()]),
        # evidence mismatch against the timeline row
        (_timeline((1, 102, 5)), _verified((101, True), (102, True)), [_candidate()]),
        # record mismatch against the timeline row
        (_timeline((1, 101, 6)), _verified((101, True)), [_candidate()]),
        # verified evidence belongs to another case
        (
            _timeline((1, 101, 5)),
            [{"case_id": CASE + 1, "evidence_id": 101, "valid": True}],
            [_candidate()],
        ),
        # timeline row belongs to another case
        (
            [{"case_id": CASE + 1, "event_id": 1, "evidence_id": 101, "record_number": 5}],
            _verified((101, True)),
            [_candidate()],
        ),
        # conflict references unverified evidence
        (
            _timeline((1, 101, 5)),
            _verified((101, True), (103, False)),
            [_candidate(conflict_evidence_ids=(103,))],
        ),
        # conflict references evidence absent from the case
        (
            _timeline((1, 101, 5)),
            _verified((101, True)),
            [_candidate(conflict_evidence_ids=(555,))],
        ),
        # legacy record_number key is no longer the timeline contract
        (
            [{"case_id": CASE, "event_id": 1, "evidence_id": 101, "record_number": 5}],
            _verified((101, True)),
            [_candidate()],
        ),
        # timeline row without case_id cannot be isolated to the selected case
        (
            [{"event_id": 1, "evidence_id": 101, "record": 5}],
            _verified((101, True)),
            [_candidate()],
        ),
    ],
)
def test_bad_references_fail_closed(monkeypatch, timeline, verified, candidates):
    _no_core(monkeypatch)
    with pytest.raises(ValueError):
        assess_ir_candidates(CASE, timeline, verified, candidates)


def test_duplicate_candidate_event_rejects(monkeypatch):
    timeline, verified = _base()
    _no_core(monkeypatch)
    with pytest.raises(ValueError):
        assess_ir_candidates(CASE, timeline, verified, [_candidate(), _candidate()])


def test_duplicate_timeline_and_verified_rows_reject(monkeypatch):
    _no_core(monkeypatch)
    with pytest.raises(ValueError):
        assess_ir_candidates(
            CASE, _timeline((1, 101, 5), (1, 102, 6)), _verified((101, True)), [_candidate()]
        )
    with pytest.raises(ValueError):
        assess_ir_candidates(
            CASE, _timeline((1, 101, 5)), _verified((101, True), (101, True)), [_candidate()]
        )


def test_one_malformed_candidate_stops_before_any_core_call(monkeypatch):
    timeline, verified = _base()
    _no_core(monkeypatch)
    bad = _candidate(event_id=2, evidence_id=102, record_number=6, normalizer_version="bad version ")
    with pytest.raises(ValueError):
        assess_ir_candidates(CASE, timeline, verified, [_candidate(), bad])


@pytest.mark.parametrize(
    "case_id",
    [True, 0, -1, "7", 7.0, None],
)
def test_case_id_must_be_strict_positive_int(monkeypatch, case_id):
    _no_core(monkeypatch)
    timeline, verified = _base()
    with pytest.raises(ValueError):
        assess_ir_candidates(case_id, timeline, verified, [_candidate()])


def test_verified_valid_must_be_strict_bool(monkeypatch):
    _no_core(monkeypatch)
    with pytest.raises(ValueError):
        assess_ir_candidates(CASE, _timeline((1, 101, 5)), _verified((101, 1)), [_candidate()])


def test_timeline_ids_reject_bool_and_string(monkeypatch):
    _no_core(monkeypatch)
    rows = [{"case_id": CASE, "event_id": True, "evidence_id": 101, "record_number": 5}]
    with pytest.raises(ValueError):
        assess_ir_candidates(CASE, rows, _verified((101, True)), [_candidate()])
    rows = [{"case_id": CASE, "event_id": 1, "evidence_id": "101", "record_number": 5}]
    with pytest.raises(ValueError):
        assess_ir_candidates(CASE, rows, _verified((101, True)), [_candidate()])


@pytest.mark.parametrize(
    "make_inputs",
    [
        pytest.param(lambda: FastAssessmentInput(severity=True), id="severity-bool"),
        pytest.param(lambda: FastAssessmentInput(severity=-1), id="severity-negative"),
        pytest.param(lambda: FastAssessmentInput(severity=ir_adapter._MAX_SEVERITY + 1), id="severity-too-large"),
        pytest.param(lambda: FastAssessmentInput(severity=2, token_only=1), id="token-only-not-bool"),
        pytest.param(lambda: FastAssessmentInput(severity=2, deception_sid=0), id="deception-sid-zero"),
        pytest.param(lambda: FastAssessmentInput(severity=2, benign_classless="no"), id="benign-classless-not-bool"),
        pytest.param(lambda: FastAssessmentInput(severity=2, classes=["c2"]), id="classes-list"),
        pytest.param(lambda: FastAssessmentInput(severity=2, classes=("C2",)), id="class-not-canonical"),
        pytest.param(lambda: FastAssessmentInput(severity=2, classes=("c2",) * (ir_adapter._MAX_CLASSES + 1)), id="too-many-classes"),
        pytest.param(lambda: FastAssessmentInput(severity=2, ports=[PortSignal("web", 443)]), id="ports-list"),
        pytest.param(lambda: FastAssessmentInput(severity=2, ports=(PortSignal("web", True),)), id="port-bool"),
        pytest.param(lambda: FastAssessmentInput(severity=2, ports=(PortSignal("web", 0),)), id="port-zero"),
        pytest.param(lambda: FastAssessmentInput(severity=2, ports=(PortSignal("WEB", 443),)), id="port-not-canonical"),
        pytest.param(lambda: FastAssessmentInput(severity=2, ports=(("web", 443),) * (ir_adapter._MAX_PORTS + 1)), id="port-tuples"),
        pytest.param(lambda: FastAssessmentInput(severity=2, action="Drop"), id="action-not-canonical"),
        pytest.param(lambda: FastAssessmentInput(severity=2, action=""), id="action-empty"),
    ],
)
def test_strict_bounded_inputs_reject(monkeypatch, make_inputs):
    _no_core(monkeypatch)
    timeline, verified = _base()
    with pytest.raises((TypeError, ValueError)):
        inputs = make_inputs()
        assess_ir_candidates(CASE, timeline, verified, [_candidate(inputs=inputs)])


def test_non_dataclass_inputs_reject(monkeypatch):
    _no_core(monkeypatch)
    timeline, verified = _base()
    with pytest.raises(ValueError):
        assess_ir_candidates(CASE, timeline, verified, [_candidate(inputs={"severity": 2})])


@pytest.mark.parametrize(
    "version",
    ["", " norm", "norm ", "has space", "x" * 65, None, 1],
)
def test_normalizer_version_must_be_bounded_canonical(monkeypatch, version):
    _no_core(monkeypatch)
    timeline, verified = _base()
    with pytest.raises(ValueError):
        assess_ir_candidates(CASE, timeline, verified, [_candidate(normalizer_version=version)])


@pytest.mark.parametrize(
    "conflicts",
    [[103], (True,), (103, 103), (103, "104"), (103,) * (ir_adapter._MAX_CONFLICTS + 1)],
)
def test_conflict_tuple_must_be_strict_bounded_unique(monkeypatch, conflicts):
    _no_core(monkeypatch)
    timeline, verified = _base()
    verified = verified + _verified((104, True))
    with pytest.raises(ValueError):
        assess_ir_candidates(CASE, timeline, verified, [_candidate(conflict_evidence_ids=conflicts)])


@pytest.mark.parametrize("conflicts", [([103],), ((103,),), (103, [104]), ({"id": 103},)])
def test_nested_conflict_member_fails_as_value_error_before_core(monkeypatch, conflicts):
    _no_core(monkeypatch)
    timeline, verified = _base()
    verified = verified + _verified((104, True))
    with pytest.raises(ValueError, match="conflict evidence is not verified"):
        assess_ir_candidates(CASE, timeline, verified, [_candidate(conflict_evidence_ids=conflicts)])


def test_candidate_count_is_bounded(monkeypatch):
    _no_core(monkeypatch)
    timeline, verified = _base()
    too_many = [_candidate(event_id=i + 1) for i in range(ir_adapter._MAX_CANDIDATES + 1)]
    with pytest.raises(ValueError):
        assess_ir_candidates(CASE, timeline, verified, too_many)


def test_plain_mapping_candidate_rejects(monkeypatch):
    _no_core(monkeypatch)
    timeline, verified = _base()
    with pytest.raises(ValueError):
        assess_ir_candidates(CASE, timeline, verified, [{"event_id": 1}])


def _document(**overrides):
    values = {
        "schema_version": ir_adapter.INPUT_SCHEMA,
        "case_id": CASE,
        "candidates": [
            {
                "event_id": 1,
                "evidence_id": 101,
                "record_number": 5,
                "normalizer_version": "norm-1",
                "inputs": {
                    "severity": 2,
                    "classes": ["c2"],
                    "token_only": False,
                    "ports": [{"kind": "web", "port": 443}],
                    "action": "drop",
                    "deception_sid": False,
                    "benign_classless": False,
                },
            }
        ],
    }
    values.update(overrides)
    return values


def test_document_parses_to_candidates_and_scores_like_core():
    timeline, verified = _base()
    (candidate,) = parse_candidate_document(_document(), CASE)

    assert candidate == _candidate(
        inputs=FastAssessmentInput(
            severity=2, classes=("c2",), ports=(PortSignal("web", 443),), action="drop"
        )
    )
    result = assess_ir_candidates(CASE, timeline, verified, [candidate])
    (entry,) = result["candidates"]
    assert entry["score"] == assess_fast(candidate.inputs).score


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(extra=1),
        lambda d: d.pop("case_id"),
        lambda d: d.update(schema_version="mio.ir.fast-assessment-inputs.v2"),
        lambda d: d.update(case_id=CASE + 1),
        lambda d: d.update(case_id=True),
        lambda d: d.update(candidates={}),
        lambda d: d.update(candidates=[d["candidates"][0]] * (ir_adapter._MAX_CANDIDATES + 1)),
        lambda d: d["candidates"][0].update(summary="raw evidence text"),
        lambda d: d["candidates"][0].update(raw_text="x"),
        lambda d: d["candidates"][0].pop("inputs"),
        lambda d: d["candidates"][0].pop("normalizer_version"),
        lambda d: d["candidates"][0].update(conflict_evidence_ids=103),
        lambda d: d["candidates"][0]["inputs"].update(severity_text="high"),
        lambda d: d["candidates"][0]["inputs"].pop("token_only"),
        lambda d: d["candidates"][0]["inputs"].update(classes="c2"),
        lambda d: d["candidates"][0]["inputs"].update(ports=[["web", 443]]),
        lambda d: d["candidates"][0]["inputs"].update(ports=[{"kind": "web", "port": 443, "x": 1}]),
    ],
)
def test_document_rejects_unknown_malformed_or_mismatched(mutate):
    document = _document()
    mutate(document)
    with pytest.raises(ValueError):
        parse_candidate_document(document, CASE)


def test_document_rejects_non_object_root():
    with pytest.raises(ValueError):
        parse_candidate_document([], CASE)

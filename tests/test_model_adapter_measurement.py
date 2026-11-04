"""Focused tests for the metadata-only MeasuredTransport wrapper."""

import threading

import pytest

from azazel_mio.model_adapter import (
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    UNLISTED_TASK,
    MeasuredCall,
    MeasuredTransport,
)
from azazel_mio import MeasuredTransport as PublicMeasuredTransport


class FakeClock:
    def __init__(self, step=10):
        self.now = 0
        self.step = step

    def __call__(self):
        value = self.now
        self.now += self.step
        return value


class FakeTransport:
    def __init__(self, result=None, error=None):
        self.last_model = "model-a"
        self.calls = []
        self.result = {"ok": True} if result is None else result
        self.error = error

    def __call__(self, task, prompt):
        self.calls.append((task, prompt))
        self.last_model = "model-b"
        if self.error is not None:
            raise self.error
        return self.result


class RaisingSecondClock:
    def __init__(self, error):
        self.calls = 0
        self.error = error

    def __call__(self):
        self.calls += 1
        if self.calls == 2:
            raise self.error
        return 0


def test_success_passes_arguments_unchanged_and_returns_result():
    inner = FakeTransport(result={"answer": 1})
    wrapper = MeasuredTransport(inner, allowed_tasks=["reason"], clock=FakeClock())
    prompt = "  raw prompt with\nnewlines  "

    assert wrapper("reason", prompt) is inner.result
    assert inner.calls == [("reason", prompt)]
    assert wrapper.records() == (
        MeasuredCall(task="reason", elapsed_ns=10, outcome=OUTCOME_SUCCESS),
    )


def test_repeated_reuse_has_no_lifetime_cap():
    inner = FakeTransport()
    wrapper = MeasuredTransport(inner, allowed_tasks=["reason"], clock=FakeClock())

    for _ in range(1000):
        wrapper("reason", "p")

    assert len(inner.calls) == 1000
    assert len(wrapper.records()) == 256  # bounded history, but calls never blocked


def test_exception_identity_preserved_and_recorded_without_text():
    secret = "SECRET-PROMPT-TEXT"
    original = RuntimeError(secret)
    wrapper = MeasuredTransport(
        FakeTransport(error=original), allowed_tasks=["reason"], clock=FakeClock()
    )

    with pytest.raises(RuntimeError) as excinfo:
        wrapper("reason", secret)

    assert excinfo.value is original
    records = wrapper.records()
    assert records == (
        MeasuredCall(task="reason", elapsed_ns=10, outcome=OUTCOME_FAILURE),
    )
    for record in records:
        assert secret not in repr(record)
        assert secret not in str(record.__dict__)


def test_clock_failure_does_not_mask_model_exception_or_success():
    original = RuntimeError("model failure")
    failing_clock = RaisingSecondClock(RuntimeError("clock failure"))
    wrapper = MeasuredTransport(
        FakeTransport(error=original), allowed_tasks=["reason"], clock=failing_clock
    )

    with pytest.raises(RuntimeError) as excinfo:
        wrapper("reason", "p")
    assert excinfo.value is original
    assert wrapper.records() == ()

    success_clock = RaisingSecondClock(RuntimeError("clock failure"))
    success = FakeTransport(result={"ok": True})
    wrapper = MeasuredTransport(success, clock=success_clock)
    assert wrapper("reason", "p") is success.result
    assert wrapper.records() == ()


def test_elapsed_time_is_never_negative():
    values = iter((10, 2))
    wrapper = MeasuredTransport(FakeTransport(), clock=lambda: next(values))
    wrapper("reason", "p")
    assert wrapper.records()[0].elapsed_ns == 0


def test_keyboard_interrupt_is_recorded_then_propagated():
    original = KeyboardInterrupt("stop")
    wrapper = MeasuredTransport(
        FakeTransport(error=original), allowed_tasks=["reason"], clock=FakeClock()
    )
    with pytest.raises(KeyboardInterrupt) as excinfo:
        wrapper("reason", "p")
    assert excinfo.value is original
    assert wrapper.records()[0].outcome == OUTCOME_FAILURE


def test_bounded_history_keeps_most_recent_records():
    inner = FakeTransport()
    wrapper = MeasuredTransport(
        inner, allowed_tasks=["reason"], max_records=3, clock=FakeClock(step=5)
    )

    for _ in range(5):
        wrapper("reason", "p")

    records = wrapper.records()
    assert len(records) == 3
    assert all(r.elapsed_ns == 5 for r in records)


def test_max_records_must_be_positive():
    with pytest.raises(ValueError):
        MeasuredTransport(FakeTransport(), max_records=0)
    with pytest.raises(ValueError):
        MeasuredTransport(FakeTransport(), max_records=True)
    with pytest.raises(ValueError):
        MeasuredTransport(FakeTransport(), max_records=4097)
    with pytest.raises(ValueError):
        MeasuredTransport(FakeTransport(), allowed_tasks=["not-a-safe-label"])
    with pytest.raises(ValueError):
        MeasuredTransport(FakeTransport(), allowed_tasks=[f"task_{i}" for i in range(33)])


def test_public_package_exports_measured_transport_and_bounds_task_labels():
    assert PublicMeasuredTransport is MeasuredTransport
    with pytest.raises(ValueError):
        MeasuredTransport(FakeTransport(), allowed_tasks=["x" * 65])


def test_task_allowlist_sanitizes_unknown_identifiers():
    wrapper = MeasuredTransport(
        FakeTransport(), allowed_tasks=["reason"], clock=FakeClock()
    )

    wrapper("reason", "p")
    wrapper("user-supplied-\x00 junk/with spaces", "p")
    wrapper("x" * 1000, "p")

    tasks = [r.task for r in wrapper.records()]
    assert tasks == ["reason", UNLISTED_TASK, UNLISTED_TASK]


def test_non_string_and_string_subclass_task_labels_are_sanitized():
    class TaskName(str):
        pass

    inner = FakeTransport()
    wrapper = MeasuredTransport(inner, allowed_tasks=["reason"], clock=FakeClock())
    subclass_task = TaskName("reason")
    opaque_task = object()
    wrapper(subclass_task, "p")
    wrapper(opaque_task, "p")

    assert inner.calls == [(subclass_task, "p"), (opaque_task, "p")]
    assert [record.task for record in wrapper.records()] == [UNLISTED_TASK, UNLISTED_TASK]


def test_last_model_is_passed_through_live():
    inner = FakeTransport()
    wrapper = MeasuredTransport(inner, clock=FakeClock())

    assert wrapper.last_model == "model-a"
    wrapper("reason", "p")
    assert wrapper.last_model == "model-b"


def test_records_are_immutable_snapshots():
    wrapper = MeasuredTransport(FakeTransport(), clock=FakeClock())
    wrapper("reason", "p")
    snapshot = wrapper.records()

    wrapper("reason", "p")

    assert len(snapshot) == 1
    assert isinstance(snapshot, tuple)
    with pytest.raises(AttributeError):
        snapshot[0].elapsed_ns = 0  # frozen dataclass


def test_concurrent_calls_record_every_entry():
    wrapper = MeasuredTransport(
        FakeTransport(), allowed_tasks=["reason"], max_records=4096
    )
    threads = [
        threading.Thread(target=lambda: [wrapper("reason", "p") for _ in range(50)])
        for _ in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(wrapper.records()) == 400


def test_assistant_core_model_path_uses_measured_transport_without_schema_change():
    from azazel_mio import AssistantCore, MioSituationFrame

    now = "2026-10-31T00:00:00Z"
    frame = MioSituationFrame.build(
        frame_id="frame-measured-core",
        trace_id="trace-measured-core",
        created_at=now,
        mission="Keep communications available",
        current_defensive_state="OBSERVE",
        threat_level="UNKNOWN",
        known_facts=("AUTH_FAILURES_OBSERVED",),
        unknowns=("ADMIN_AUTOMATION_UNKNOWN",),
        evidence_refs=("ev:ssh:1",),
    )
    calls = []

    def model(task, prompt):
        calls.append(task)
        if task == "generate_hypotheses":
            return {"hypotheses": [
                {"hypothesis_id": "h1", "status": "proposed",
                 "hypothesis_alternative_id": "hostile_activity",
                 "statement": "The failures may reflect hostile activity.",
                 "supporting_evidence_refs": ["ev:ssh:1"], "contradicting_evidence_refs": [],
                 "assumptions": [], "falsification_conditions": ["Check successful logins."],
                 "expected_observations": [], "missing_evidence": []},
                {"hypothesis_id": "h2", "status": "proposed",
                 "hypothesis_alternative_id": "benign_activity",
                 "statement": "The failures may reflect benign automation.",
                 "supporting_evidence_refs": [], "contradicting_evidence_refs": [],
                 "assumptions": [], "falsification_conditions": ["Compare schedule."],
                 "expected_observations": [], "missing_evidence": ["automation schedule"]},
            ]}
        if task == "identify_evidence_gaps":
            return {"evidence_gaps": []}
        if task == "recommend":
            return {"summary": "Review the reported failures.",
                    "recommended_action": "OBSERVE",
                    "rationale": "Evidence does not establish compromise.",
                    "evidence_refs": ["ev:ssh:1"],
                    "limitations": ["No current telemetry is included."]}
        raise AssertionError(f"unexpected model task: {task}")

    measured = MeasuredTransport(
        model, allowed_tasks=("generate_hypotheses", "identify_evidence_gaps", "recommend"),
        clock=FakeClock(),
    )
    result = AssistantCore(model=measured).explain(frame, now=now).to_dict()

    assert result["state"] == "complete"
    assert result["generation_method"] == "model"
    assert calls == ["generate_hypotheses", "identify_evidence_gaps", "recommend"]
    assert [record.task for record in measured.records()] == calls
    assert all(record.outcome == OUTCOME_SUCCESS for record in measured.records())
    assert result["schema_version"] == "mio.assistance.v1"
    assert "reasoning_trace" in result and "handoff" in result

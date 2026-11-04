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

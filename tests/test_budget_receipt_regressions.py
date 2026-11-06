"""Dispatch, first-cause and coordinator receipt regression tests (R3)."""
from dataclasses import replace

import pytest

from azazel_mio import AssistantCore, BudgetError, ReasoningState
from azazel_mio.broker import CapabilityBroker
from azazel_mio.lifecycle import ReasoningCoordinator
from azazel_mio.model_adapter import MioModelBlocked, MioModelUnavailable
from azazel_mio.playbook import select_playbook
from azazel_mio.reasoning import BoundedReasoningLoop, ReasoningBudget
from test_generation_budget import Model, TASKS, NOW, budget, frame, run


@pytest.mark.parametrize("error", [MioModelBlocked, MioModelUnavailable])
@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("dispatched", [False, True])
def test_dispatch_receipt_distinguishes_gate_from_sent_exception(error, index, dispatched):
    class Transport(Model):
        def __init__(self):
            super().__init__(); self.entries = []; self.actual = []
        def invoke_budgeted(self, task, prompt, on_dispatch):
            self.entries.append(task)
            if task == TASKS[index] and not dispatched:
                raise error("gate rejected")
            on_dispatch(); self.actual.append(task)
            if task == TASKS[index]:
                raise error("after send")
            return self(task, prompt)
    model = Transport(); result = run(model, lambda _: budget()); receipt = result.generation_receipt
    assert result.state is ReasoningState.DEPENDENCY_UNAVAILABLE
    assert receipt.calls_sent == {task: int(task in model.actual) for task in TASKS}
    assert receipt.calls_sent[TASKS[index]] == int(dispatched)
    assert receipt.task_results[TASKS[index]] == ("failed" if dispatched else "not_sent")
    assert receipt.state == ("partial" if model.actual else "failed")
    assert receipt.usage[TASKS[index]] == ({"input_tokens": 10, "output_tokens": 2} if dispatched else None)
    assert len(model.entries) == index + 1
    if index:
        assert receipt.task_results[TASKS[0]] == "validated"
        assert receipt.usage[TASKS[0]] == {"input_tokens": 10, "output_tokens": 2}


def test_budget_adapter_must_signal_dispatch_before_a_success():
    class Legacy:
        def __call__(self, task, prompt):
            raise AssertionError("legacy adapter must not be entered")
    result = run(Legacy(), lambda _: budget()).generation_receipt
    assert result.reason == "dispatch_tracking_unavailable"
    assert sum(result.calls_sent.values()) == 0
    class Missing:
        def invoke_budgeted(self, task, prompt, on_dispatch):
            return {"hypotheses": []}
    result = run(Missing(), lambda _: budget()).generation_receipt
    assert result.reason == "dispatch_tracking_unavailable"
    assert sum(result.calls_sent.values()) == 0


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("reason", ["budget_exhausted", "count_unknown"])
def test_typed_budget_callback_retains_first_reason_and_not_sent(index, reason):
    model = Model()
    def callback(task):
        if task == TASKS[index]:
            raise BudgetError(reason, "not for public receipt")
        return budget()
    receipt = run(model, callback).generation_receipt
    assert receipt.reason == reason
    assert receipt.calls_sent[TASKS[index]] == 0
    assert receipt.task_results[TASKS[index]] == "not_sent"
    assert len(model.calls) == index
    if index:
        assert receipt.task_results[TASKS[0]] == "validated"
        assert receipt.usage[TASKS[0]] is not None


def test_untyped_callback_failure_is_count_unknown():
    def broken(_):
        raise RuntimeError("sensitive detail")
    receipt = run(Model(), broken).generation_receipt
    assert receipt.reason == "count_unknown" and sum(receipt.calls_sent.values()) == 0


@pytest.mark.parametrize("limit", [1, 2])
def test_model_call_limit_preserves_preceding_validated_task(limit):
    model = Model(); f = frame(); chosen = select_playbook(f); broker = CapabilityBroker()
    try:
        result = BoundedReasoningLoop(model=model, broker=broker,
            budget=ReasoningBudget(max_model_calls=limit)).run(frame=f, playbook=chosen.playbook,
                selection=chosen, cycle_id="r3", budget_for_task=lambda _: budget())
    finally:
        broker.close()
    receipt = result.generation_receipt
    assert result.state is ReasoningState.BUDGET_EXHAUSTED and receipt.state == "partial"
    assert receipt.task_results[TASKS[limit-1]] == "validated"
    assert receipt.task_results[TASKS[limit]] == "not_started"
    assert sum(receipt.calls_sent.values()) == limit


@pytest.mark.parametrize("case, disposition, reason", [
    ("cancel", "cancelled", "operator_cancelled"),
    ("backpressure", "backpressure", "backpressure"),
    ("duplicate", "in_flight_duplicate", "in_flight_duplicate"),
])
def test_coordinator_disposition_is_closed_and_distinct(case, disposition, reason):
    coordinator = ReasoningCoordinator(max_traces=1); f = frame(); kwargs = {}; ticket = None
    if case == "cancel":
        kwargs["cancel_check"] = lambda: True
    elif case == "backpressure":
        ticket = coordinator.begin(replace(f, trace_id="other"))
    else:
        ticket = coordinator.begin(f)
    try:
        result = AssistantCore(model=Model(), coordinator=coordinator).explain(
            f, now=NOW, generation_budget=lambda _: budget(), **kwargs)
        receipt = result.generation_receipt
        assert receipt.coordinator_disposition == disposition
        assert receipt.reason == reason and receipt.state == "failed"
        assert sum(receipt.calls_sent.values()) == 0
    finally:
        if ticket is not None:
            coordinator.cancel_ticket(ticket)


def test_later_coordinator_cancel_does_not_erase_original_failure():
    coordinator = ReasoningCoordinator(); f = frame()
    class CancelAfterDispatch(Model):
        def invoke_budgeted(self, task, prompt, on_dispatch):
            on_dispatch()
            assert coordinator.cancel(f.trace_id)
            raise MioModelUnavailable("failure after dispatch")
    result = AssistantCore(model=CancelAfterDispatch(), coordinator=coordinator).explain(
        f, now=NOW, generation_budget=lambda _: budget())
    receipt = result.generation_receipt
    assert receipt.coordinator_disposition == "cancelled"
    assert receipt.reason == "dependency_unavailable"
    assert receipt.calls_sent[TASKS[0]] == 1


def test_grounding_failure_marks_sent_task_failed():
    result = run(Model(bad_ref=True), lambda _: budget())
    assert result.state is ReasoningState.VALIDATION_REJECTED
    assert result.generation_receipt.task_results[TASKS[0]] == "failed"
    assert result.generation_receipt.calls_sent[TASKS[0]] == 1


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize("mode", ["swallowed", "propagated", "translated"])
def test_duplicate_dispatch_notification_is_terminal_even_if_caught(index, mode):
    class Duplicate(Model):
        def __init__(self):
            super().__init__(); self.entries = []
        def invoke_budgeted(self, task, prompt, on_dispatch):
            self.entries.append(task)
            on_dispatch()
            if task == TASKS[index]:
                try:
                    on_dispatch()
                except RuntimeError:
                    if mode == "propagated":
                        raise
                    if mode == "translated":
                        raise MioModelBlocked("translated exception")
            return self(task, prompt)
    model = Duplicate()
    assistance = AssistantCore(model=model).explain(frame(), now=NOW, generation_budget=lambda _: budget())
    receipt = assistance.generation_receipt
    assert assistance.to_dict()["generation_method"] == "static_reference"
    assert assistance.to_dict()["state"] != "complete"
    assert receipt.state == "failed" and receipt.reason == "send_notification_conflict"
    assert receipt.calls_sent == {task: int(i <= index) for i, task in enumerate(TASKS)}
    assert receipt.task_results[TASKS[index]] == "failed"
    assert receipt.usage[TASKS[index]] == {"input_tokens": 10, "output_tokens": 2}
    assert model.entries == list(TASKS[:index + 1])
    for task in TASKS[:index]:
        assert receipt.task_results[task] == "validated"


def test_late_notification_rejected_without_changing_completed_receipt():
    class Late(Model):
        def __init__(self):
            super().__init__(); self.callbacks = []
        def invoke_budgeted(self, task, prompt, on_dispatch):
            self.callbacks.append(on_dispatch)
            on_dispatch()
            return self(task, prompt)
    model = Late(); outcome = run(model, lambda _: budget()); receipt = outcome.generation_receipt
    assert receipt.state == "complete"
    for callback in model.callbacks:
        with pytest.raises(RuntimeError, match="invalid_dispatch_notification"):
            callback()
    assert receipt.calls_sent == dict.fromkeys(TASKS, 1) and receipt.reason is None


def test_duplicate_notification_reason_survives_coordinator_cancellation():
    coordinator = ReasoningCoordinator(); f = frame()
    class DuplicateThenCancel(Model):
        def invoke_budgeted(self, task, prompt, on_dispatch):
            on_dispatch()
            try:
                on_dispatch()
            except RuntimeError:
                pass
            assert coordinator.cancel(f.trace_id)
            return self(task, prompt)
    result = AssistantCore(model=DuplicateThenCancel(), coordinator=coordinator).explain(
        f, now=NOW, generation_budget=lambda _: budget())
    receipt = result.generation_receipt
    assert receipt.coordinator_disposition == "cancelled"
    assert receipt.state == "failed" and receipt.reason == "send_notification_conflict"
    assert receipt.calls_sent[TASKS[0]] == 1

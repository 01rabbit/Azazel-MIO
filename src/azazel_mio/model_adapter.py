"""Pure model boundary. Products own authorization and transport."""
from collections import deque
from dataclasses import dataclass
import re
from threading import Lock
from time import monotonic_ns
from typing import Any, Callable, Deque, Iterable, Mapping, Protocol, Tuple

class MioModelError(RuntimeError):
    pass
class MioModelBlocked(MioModelError):
    pass
class MioModelUnavailable(MioModelError):
    pass
class StructuredTransport(Protocol):
    last_model: str
    def __call__(self, task: str, prompt: str) -> Mapping[str, Any]: ...


OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
UNLISTED_TASK = "other"
MAX_TASK_LABEL_CHARS = 64
MAX_ALLOWED_TASKS = 32
MAX_RECORDS = 4096
_TASK_LABEL = re.compile(r"[a-z0-9_]{1,64}\Z")


@dataclass(frozen=True)
class MeasuredCall:
    """Metadata-only record of one transport call. No prompt, payload, or exception text."""

    task: str
    elapsed_ns: int
    outcome: str


class MeasuredTransport:
    """Wraps a StructuredTransport, timing each call and keeping bounded metadata.

    Reusable across any number of calls: there is intentionally no lifetime call cap,
    since per-cycle budgets are enforced elsewhere (e.g. ReasoningBudget).
    """

    def __init__(
        self,
        transport: StructuredTransport,
        *,
        allowed_tasks: Iterable[str] = (),
        max_records: int = 256,
        clock: Callable[[], int] = monotonic_ns,
    ) -> None:
        if type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS:
            raise ValueError(f"max_records must be between 1 and {MAX_RECORDS}")
        task_labels = tuple(allowed_tasks)
        if len(task_labels) > MAX_ALLOWED_TASKS or any(
            type(label) is not str or _TASK_LABEL.fullmatch(label) is None
            for label in task_labels
        ):
            raise ValueError("allowed_tasks must contain at most 32 lowercase ASCII identifier labels of at most 64 characters")
        self._transport = transport
        self._allowed_tasks = frozenset(task_labels)
        self._clock = clock
        self._lock = Lock()
        self._records: Deque[MeasuredCall] = deque(maxlen=max_records)

    @property
    def last_model(self) -> str:
        return self._transport.last_model

    def __call__(self, task: str, prompt: str) -> Mapping[str, Any]:
        label = (
            task
            if type(task) is str
            and len(task) <= MAX_TASK_LABEL_CHARS
            and task in self._allowed_tasks
            else UNLISTED_TASK
        )
        try:
            started = self._clock()
        except Exception:
            # Metrics are best-effort and must not change model behavior.
            started = None
        try:
            result = self._transport(task, prompt)
        except BaseException:
            self._append_if_measurable(label, started, OUTCOME_FAILURE)
            raise
        self._append_if_measurable(label, started, OUTCOME_SUCCESS)
        return result

    def records(self) -> Tuple[MeasuredCall, ...]:
        with self._lock:
            return tuple(self._records)

    def _append_if_measurable(self, label: str, started: int | None, outcome: str) -> None:
        if started is None:
            return
        try:
            elapsed = max(0, self._clock() - started)
            record = MeasuredCall(task=label, elapsed_ns=elapsed, outcome=outcome)
            with self._lock:
                self._records.append(record)
        except Exception:
            # A diagnostic clock/history failure must not mask the transport result.
            return

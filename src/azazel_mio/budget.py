"""Local generation budget values; transport and clocks belong to products."""
from dataclasses import dataclass, field
from typing import Any, Callable, Literal


@dataclass(frozen=True)
class GenerationBudget:
    input_tokens: int
    output_tokens: int
    context_limit: int
    safety_margin: int
    count_tokens: Callable[[str], int | None]


@dataclass(frozen=True)
class PromptSelection:
    coverage: Literal["full", "selected"]
    kept: tuple[str, ...]
    dropped: tuple[tuple[str, str], ...]
    token_count: int | None
    template_version: str


@dataclass(frozen=True)
class CompiledPrompt:
    text: str
    selection: PromptSelection


class BudgetError(ValueError):
    def __init__(self, reason: Literal["budget_exhausted", "count_unknown"], detail: str):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class GenerationOutcome:
    state: Literal["complete", "partial", "failed"]
    task_results: dict[str, str]
    calls_sent: dict[str, int]
    usage: dict[str, Any | None]
    reason: str | None
    selections: dict[str, PromptSelection]
    # Closed coordinator disposition is distinct from the original outcome.
    coordinator_disposition: Literal["current", "cancelled", "superseded", "backpressure",
        "in_flight_duplicate", "pre_restart", "unknown_or_evicted", "ticket_mismatch",
        "already_completed", "unknown"] | None = None
    # Private receipt material. Never place these caller-supplied strings in
    # public provenance; products must keep this mapping with the local receipt.
    frame_unknowns: dict[str, str] = field(default_factory=dict)
    unknown_origins: dict[str, str] = field(default_factory=dict)
    hypothesis_unknown_ids: dict[str, tuple[str, ...]] = field(default_factory=dict)

"""Portable deterministic scoring kernel for Edge fast assessments.

The algorithm and factor contract are adapted from Azazel-Edge's
``py/azazel_edge/tactics_engine/scorer.py`` at commit
``47c880b2503d7f771bbdacba9b6205dafe03c4c7`` (MIT; see
``LICENSES/edge-tactical-scorer-MIT.txt``).

This module deliberately accepts normalized scoring signals. Product adapters
own parsing, text normalization, SID/class recognition, port classification,
and benign/deception identification. Importing the module performs no I/O and
loads no Edge modules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


_CLASS_WEIGHT: Final[dict[str, int]] = {
    "rce": 50,
    "c2": 48,
    "exfil": 46,
    "cred": 44,
    "phishing": 42,
    "mitm": 40,
    "scan": 36,
    "recon": 30,
}
_SEVERITY_BASE: Final[dict[int, int]] = {1: 38, 2: 30, 3: 24, 4: 18}
_UNKNOWN_SEVERITY_BASE: Final[int] = 16
_TOKEN_ONLY_CEILING: Final[int] = 39
_BENIGN_LEVEL: Final[int] = 25
_DECEPTION_FLOOR: Final[int] = 60
_SEV1_NO_THREAT_CAP: Final[int] = 35

# Input boundary limits. Unknown integer severities retain the fallback
# behavior, including Edge's negative/positive unknown values; signed 32-bit
# bounds keep arbitrary-precision integers from reaching factor formatting.
# The 8 canonical classes and Edge's one target-port mapping fit well under
# these caps.
_MIN_SEVERITY: Final[int] = -(1 << 31)
_MAX_SEVERITY: Final[int] = (1 << 31) - 1
_MAX_CLASSES: Final[int] = 32
_MAX_PORTS: Final[int] = 16
_MAX_TOKEN_CHARS: Final[int] = 64
_MIN_PORT: Final[int] = 1
_MAX_PORT: Final[int] = 65535


def _require_bounded_token(value: object, name: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{name} must be a str")
    if not 0 < len(value) <= _MAX_TOKEN_CHARS:
        raise ValueError(f"{name} must contain 1..{_MAX_TOKEN_CHARS} characters")


@dataclass(frozen=True)
class PortSignal:
    """A port corroboration already classified by the product adapter.

    ``kind`` is one of ``admin``, ``web``, ``dns``, or ``decoy``. The numeric
    port is retained for the compatible explanation factor. Unknown kinds are
    ignored, which lets adapters add categories without changing this kernel.
    """

    kind: str
    port: int

    def __post_init__(self) -> None:
        _require_bounded_token(self.kind, "PortSignal.kind")
        # ``type() is int`` rejects bool, which is an int subclass.
        if type(self.port) is not int:
            raise TypeError("PortSignal.port must be an int")
        if not _MIN_PORT <= self.port <= _MAX_PORT:
            raise ValueError(f"PortSignal.port must be in {_MIN_PORT}..{_MAX_PORT}")


@dataclass(frozen=True)
class FastAssessmentInput:
    """Normalized signals consumed by :func:`assess_fast`.

    ``classes`` contains recognized canonical class labels. ``token_only``
    means every recognized class came from text-only corroboration.
    ``deception_sid`` and ``benign_classless`` are classifications made by the
    caller; this module does not know product SIDs, classtypes, or vocabularies.
    ``action`` must already be normalized to lower case.
    """

    severity: int
    classes: tuple[str, ...] = ()
    token_only: bool = False
    ports: tuple[PortSignal, ...] = ()
    action: str = "allowed"
    deception_sid: bool = False
    benign_classless: bool = False

    def __post_init__(self) -> None:
        # ``type() is int`` rejects bool and numeric strings alike.
        if type(self.severity) is not int:
            raise TypeError("severity must be an int")
        if not _MIN_SEVERITY <= self.severity <= _MAX_SEVERITY:
            raise ValueError(f"severity must be in {_MIN_SEVERITY}..{_MAX_SEVERITY}")
        if type(self.classes) is not tuple:
            raise TypeError("classes must be a tuple")
        if len(self.classes) > _MAX_CLASSES:
            raise ValueError(f"classes must be a tuple of at most {_MAX_CLASSES} items")
        for name in self.classes:
            _require_bounded_token(name, "class")
        if type(self.ports) is not tuple:
            raise TypeError("ports must be a tuple")
        if len(self.ports) > _MAX_PORTS:
            raise ValueError(f"ports must be a tuple of at most {_MAX_PORTS} items")
        if not all(type(port) is PortSignal for port in self.ports):
            raise TypeError("ports must contain only PortSignal values")
        _require_bounded_token(self.action, "action")
        for flag in (self.token_only, self.deception_sid, self.benign_classless):
            if type(flag) is not bool:
                raise TypeError("token_only, deception_sid, and benign_classless must be bool")


@dataclass(frozen=True)
class FastAssessment:
    """A deterministic integer score and its ordered explanation factors."""

    score: int
    factors: tuple[str, ...]


def assess_fast(inputs: FastAssessmentInput) -> FastAssessment:
    """Score normalized signals with the Edge fast-assessment formula.

    Factor ordering is stable: severity, SID bonus, sorted threat classes,
    port corroboration, contained action, token ceiling, severity-1 cap,
    deception floor or benign dampener, then final clamp.
    """

    classes = tuple(sorted({name for name in inputs.classes if name in _CLASS_WEIGHT}))
    threat_weight = max((_CLASS_WEIGHT[name] for name in classes), default=0)
    score = _SEVERITY_BASE.get(inputs.severity, _UNKNOWN_SEVERITY_BASE)
    factors: list[str] = [f"severity={inputs.severity}"]

    if threat_weight > 0 or inputs.deception_sid:
        score += 5
        factors.append("sid_present")

    if threat_weight > 0:
        score += threat_weight
        factors.extend(f"threat_class={name}({_CLASS_WEIGHT[name]})" for name in classes)

    # The adapter classifies a single corroborating network port. Keep the
    # kernel tolerant of unknown kinds while preserving the canonical order.
    primary_port = None
    for kind in ("admin", "web", "dns"):
        primary_port = next((port for port in inputs.ports if port.kind == kind), None)
        if primary_port is not None:
            break
    if threat_weight > 0 and primary_port is not None:
        score += 8
        factor_kind = {"admin": "admin_port", "web": "web_port", "dns": "dns_port"}[primary_port.kind]
        factors.append(f"{factor_kind}={primary_port.port}")

    decoy_port = next((port for port in inputs.ports if port.kind == "decoy"), None)
    if decoy_port is not None:
        score += 10
        factors.append(f"decoy_port={decoy_port.port}")

    if inputs.action in {"blocked", "drop", "rejected"}:
        score += 2
        factors.append(f"action={inputs.action}(contained)")

    if inputs.token_only and threat_weight > 0:
        score = min(score, _TOKEN_ONLY_CEILING)
        factors.append("token_only_ceiling")

    if inputs.severity == 1 and threat_weight == 0:
        score = min(score, _SEV1_NO_THREAT_CAP)
        factors.append("sev1_no_threat_cap")

    if inputs.deception_sid:
        if score < _DECEPTION_FLOOR:
            score = _DECEPTION_FLOOR
            factors.append("deception_floor")
    elif inputs.benign_classless and threat_weight == 0:
        score = _BENIGN_LEVEL
        factors.append("benign_dampener")

    score = max(0, min(100, score))
    return FastAssessment(score=score, factors=tuple(factors))

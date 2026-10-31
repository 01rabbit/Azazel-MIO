"""Pure model boundary. Products own authorization and transport."""
from typing import Any, Mapping, Protocol

class MioModelError(RuntimeError):
    pass
class MioModelBlocked(MioModelError):
    pass
class MioModelUnavailable(MioModelError):
    pass
class StructuredTransport(Protocol):
    last_model: str
    def __call__(self, task: str, prompt: str) -> Mapping[str, Any]: ...

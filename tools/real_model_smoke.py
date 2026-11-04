#!/usr/bin/env python3
"""Opt-in smoke test for MIO with a locally installed Ollama model.

This developer tool sends only a fixed synthetic authentication scenario to
the Ollama API on loopback. It is not a product transport, an admission path,
or a substitute for Nexus runtime/HG validation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPResponse
import json
import re
import signal
import socket
import time

from azazel_mio import AssistantCore, MioSituationFrame, MioModelUnavailable
from azazel_mio.playbook import compiled_model_response_schema

OLLAMA_HOST = "127.0.0.1"
OLLAMA_PORT = 11434
CHAT_PATH = "/api/chat"
DEFAULT_MODEL = "qwen3.5:0.8b"
REQUEST_TIMEOUT_SECONDS = 35
RUN_TIMEOUT_SECONDS = 150
MAX_RESPONSE_BYTES = 1_000_000
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REMOTE_TAG_WORDS = frozenset({"cloud", "remote"})
_EXPECTED_TASK_SEQUENCE = ("generate_hypotheses", "identify_evidence_gaps", "recommend")
MAX_MODEL_TASKS = len(_EXPECTED_TASK_SEQUENCE)


class SmokeFailure(Exception):
    """Closed, non-sensitive failure reason for the local operator."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class RunDeadlineExceeded(BaseException):
    """Uncatchable by ordinary `except Exception` provider/MIO fallbacks."""


def _read_bounded(response: HTTPResponse) -> bytes:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise SmokeFailure("response_too_large")
    return raw


def _api_json(path: str, *, method: str = "GET", payload: dict | None = None) -> dict:
    if path not in {"/api/tags", "/api/version", CHAT_PATH}:
        raise SmokeFailure("api_path_refused")
    if method not in {"GET", "POST"} or (path == CHAT_PATH) != (method == "POST"):
        raise SmokeFailure("api_method_refused")
    if (path == CHAT_PATH) != (type(payload) is dict):
        raise SmokeFailure("api_payload_refused")
    connection = HTTPConnection(OLLAMA_HOST, OLLAMA_PORT, timeout=REQUEST_TIMEOUT_SECONDS)
    try:
        body = None if payload is None else json.dumps(payload, separators=(",", ":"))
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise SmokeFailure("redirect_refused")
        if response.status != 200:
            raise SmokeFailure("local_ollama_unavailable")
        raw = _read_bounded(response)
        value = json.loads(raw)
    except SmokeFailure:
        raise
    except (TimeoutError, socket.timeout, OSError):
        raise SmokeFailure("local_ollama_unavailable") from None
    except (ValueError, json.JSONDecodeError):
        raise SmokeFailure("local_ollama_response_invalid") from None
    finally:
        connection.close()
    if type(value) is not dict:
        raise SmokeFailure("local_ollama_response_invalid")
    return value


def _local_model_digest(model: str) -> str:
    words = re.split(r"[-._:]", model.lower())
    if any(word in _REMOTE_TAG_WORDS for word in words):
        raise SmokeFailure("remote_model_tag_refused")
    data = _api_json("/api/tags")
    models = data.get("models")
    if type(models) is not list:
        raise SmokeFailure("local_model_inventory_invalid")
    matches = [item for item in models if type(item) is dict and item.get("name") == model]
    if len(matches) != 1:
        raise SmokeFailure("model_not_installed_locally")
    item = matches[0]
    if item.get("remote_model") or item.get("remote_host"):
        raise SmokeFailure("remote_model_refused")
    if type(item.get("size")) is not int or item["size"] <= 0:
        raise SmokeFailure("local_model_size_unverified")
    digest = item.get("digest")
    if type(digest) is not str or not _DIGEST.fullmatch(digest):
        raise SmokeFailure("local_model_identity_missing")
    return digest


def _run_deadline(_signum, _frame) -> None:
    raise RunDeadlineExceeded()


def _model_calls_complete(calls: list[dict]) -> bool:
    return (tuple(call.get("task") for call in calls) == _EXPECTED_TASK_SEQUENCE
            and all(call.get("done_reason") == "stop" for call in calls))


class LocalOllamaStructuredTransport:
    """The caller-owned transport boundary, fixed to local loopback Ollama."""

    def __init__(self, model: str) -> None:
        if type(model) is not str or not _MODEL_ID.fullmatch(model):
            raise SmokeFailure("invalid_model_id")
        self.last_model = model
        self.model_digest = _local_model_digest(model)
        api_version = _api_json("/api/version").get("version")
        if type(api_version) is not str or not api_version or len(api_version) > 64:
            raise SmokeFailure("local_ollama_version_invalid")
        self.ollama_version = api_version
        self.calls: list[dict[str, int | float | str | None]] = []
        self.attempted_tasks: list[str] = []
        self.failure_code: str | None = None

    def __call__(self, task: str, prompt: str) -> dict:
        # Enforce the exact ordered task sequence before any request is built
        # or sent, so a misbehaving caller cannot drive extra model calls.
        attempted = self.attempted_tasks
        if (len(attempted) >= MAX_MODEL_TASKS
                or task != _EXPECTED_TASK_SEQUENCE[len(attempted)]):
            self.failure_code = "task_sequence_refused"
            raise MioModelUnavailable("task_sequence_refused") from None
        attempted.append(task)
        started = time.monotonic()
        try:
            schema = compiled_model_response_schema(task, prompt)
            payload = {
                "model": self.last_model,
                "messages": [{"role": "user", "content": prompt}],
                "format": schema,
                "stream": False,
                "think": False,
                "options": {"temperature": 0, "num_ctx": 4096, "num_predict": 768},
            }
            if _local_model_digest(self.last_model) != self.model_digest:
                raise SmokeFailure("model_artifact_changed")
            data = _api_json(CHAT_PATH, method="POST", payload=payload)
            message = data.get("message") if type(data) is dict else None
            content = message.get("content") if type(message) is dict else None
            if (type(data) is not dict or data.get("model") != self.last_model
                    or data.get("done_reason") != "stop"):
                raise SmokeFailure("model_identity_or_completion_mismatch")
            if type(content) is not str or not content:
                raise SmokeFailure("content_missing")
            result = json.loads(content, parse_constant=self._reject_constant)
            if type(result) is not dict:
                raise SmokeFailure("response_not_object")
            if _local_model_digest(self.last_model) != self.model_digest:
                raise SmokeFailure("model_artifact_changed")
        except SmokeFailure as exc:
            self.failure_code = exc.reason
            raise MioModelUnavailable("local_model_unavailable_or_invalid") from None
        except (ValueError, json.JSONDecodeError):
            self.failure_code = "local_model_response_invalid"
            raise MioModelUnavailable("local_model_response_invalid") from None
        except Exception:
            # Do not let provider diagnostics, prompts or generated text enter
            # MIO's trace or the operator-facing smoke output.
            self.failure_code = "local_model_unavailable_or_invalid"
            raise MioModelUnavailable("local_model_unavailable_or_invalid") from None

        self.calls.append({
            "task": task,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "prompt_tokens": self._nonnegative_int(data.get("prompt_eval_count")),
            "output_tokens": self._nonnegative_int(data.get("eval_count")),
            "done_reason": data.get("done_reason"),
        })
        return result

    @staticmethod
    def _reject_constant(value: str) -> None:
        raise ValueError("non_standard_json_constant")

    @staticmethod
    def _nonnegative_int(value: object) -> int | None:
        return value if type(value) is int and value >= 0 else None


def _frame(now: str) -> MioSituationFrame:
    return MioSituationFrame.build(
        frame_id="frame-local-model-smoke",
        trace_id="trace-local-model-smoke",
        created_at=now,
        mission="Investigate authentication failures while keeping communications available",
        current_defensive_state="OBSERVE",
        threat_level="UNKNOWN",
        known_facts=("AUTH_FAILURES_OBSERVED",),
        unknowns=("ADMIN_AUTOMATION_UNKNOWN",),
        evidence_refs=("ev:ssh:1",),
    )


def run(model: str, *, include_artifact_digest: bool = False) -> dict:
    if not hasattr(signal, "setitimer"):
        raise SmokeFailure("total_deadline_unavailable")
    previous_handler = None
    try:
        previous_handler = signal.signal(signal.SIGALRM, _run_deadline)
        signal.setitimer(signal.ITIMER_REAL, RUN_TIMEOUT_SECONDS)
    except (OSError, ValueError):
        if previous_handler is not None:
            signal.signal(signal.SIGALRM, previous_handler)
        raise SmokeFailure("total_deadline_unavailable") from None
    try:
        return _run_with_deadline(model, include_artifact_digest=include_artifact_digest)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def _run_with_deadline(model: str, *, include_artifact_digest: bool) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    frame = _frame(now)
    transport = LocalOllamaStructuredTransport(model)
    started = time.monotonic()
    assisted = AssistantCore(model=transport).explain(
        frame, now=now, knowledge_attempted=False
    ).to_dict()
    model_elapsed = round(time.monotonic() - started, 3)

    # Compare with the same fixed frame and no model. This is the core's
    # deterministic fallback, not a second runtime/admission path.
    fallback = AssistantCore().explain(
        frame, now=now, knowledge_attempted=False
    ).to_dict()
    if (assisted.get("state") != "complete"
            or assisted.get("generation_method") != "model"
            or len(assisted.get("hypotheses", ())) < 2
            or not _model_calls_complete(transport.calls)
            or transport.failure_code is not None
            or fallback.get("generation_method") != "static_reference"
            or "MODEL_NOT_AVAILABLE" not in fallback.get("unknowns", ())):
        raise SmokeFailure(transport.failure_code or "mio_real_model_smoke_not_accepted")

    report = {
        "model": model,
        "ollama_version": transport.ollama_version,
        "transport": "Ollama HTTP loopback injected as MIO StructuredTransport",
        "mio_state": assisted["state"],
        "mio_generation_method": assisted["generation_method"],
        "hypotheses": len(assisted["hypotheses"]),
        "model_calls": transport.calls,
        "model_elapsed_seconds": model_elapsed,
        "knowledge_outcome": assisted["dependency_outcome"]["knowledge"],
        "fallback_state": fallback["state"],
        "fallback_generation_method": fallback["generation_method"],
        "fallback_marks_model_missing": "MODEL_NOT_AVAILABLE" in fallback["unknowns"],
    }
    if include_artifact_digest:
        report["local_model_artifact_digest"] = transport.model_digest
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help="locally installed Ollama model tag (default: %(default)s)")
    parser.add_argument("--include-artifact-digest", action="store_true",
                        help="print the local model digest; keep this output in restricted records")
    args = parser.parse_args()
    try:
        report = run(args.model, include_artifact_digest=args.include_artifact_digest)
    except RunDeadlineExceeded:
        print(json.dumps({"status": "failed", "reason": "overall_deadline_exceeded"}, sort_keys=True))
        return 1
    except SmokeFailure as exc:
        # Fixed failure text only; never emit the prompt, response, path,
        # provider body, or arbitrary exception message.
        print(json.dumps({"status": "failed", "reason": exc.reason}, sort_keys=True))
        return 1
    except Exception:
        print(json.dumps({"status": "failed", "reason": "smoke_failed"}, sort_keys=True))
        return 1
    print(json.dumps({"status": "passed", **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

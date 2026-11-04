from __future__ import annotations

from io import BytesIO
from http.client import BadStatusLine, IncompleteRead
import json
import os
from pathlib import Path
import signal
import socket
import sys
import unittest
import time
from unittest.mock import patch
from contextlib import redirect_stdout
from io import StringIO
from datetime import datetime, timezone

from azazel_mio import AssistantCore, MioModelUnavailable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import real_model_smoke

# Deadline tests rely on SIGALRM/setitimer, which only exist on POSIX.
POSIX_SIGNAL_DEADLINE = unittest.skipUnless(
    os.name == "posix" and hasattr(real_model_smoke.signal, "setitimer")
    and hasattr(real_model_smoke.signal, "SIGALRM"),
    "requires POSIX SIGALRM/setitimer",
)

SECRET = "SECRET_PROMPT_AND_RESPONSE_TEXT"


def _bare_transport(model: str, digest: str):
    """A transport built without the network-touching constructor."""
    transport = object.__new__(real_model_smoke.LocalOllamaStructuredTransport)
    transport.last_model = model
    transport.model_digest = digest
    transport.calls = []
    transport.attempted_tasks = []
    transport.failure_code = None
    return transport


def _no_network(*_args, **_kwargs):
    raise AssertionError("network must not be used by fake-API tests")


class _FakeHTTPResponse:
    def __init__(self, status, body, read_error=None):
        self.status = status
        self._body = body
        self._read_error = read_error

    def read(self, limit):
        if self._read_error is not None:
            raise self._read_error
        return self._body[:limit]


def _fake_connection_class(sent, *, status=200, body=b"{}", request_error=None,
                           response_error=None, read_error=None):
    """An in-memory stand-in for HTTPConnection; it never opens a socket.

    Every connection event is appended to `sent` so tests can assert the
    exact host, port, timeout, method, path, body and close behavior.
    """
    class FakeHTTPConnection:
        def __init__(self, host, port, *, timeout):
            sent.append(("connect", host, port, timeout))

        def request(self, method, path, *, body, headers):
            sent.append(("request", method, path, body, dict(headers)))
            if request_error is not None:
                raise request_error

        def getresponse(self):
            if response_error is not None:
                raise response_error
            return _FakeHTTPResponse(status, body, read_error)

        def close(self):
            sent.append(("close",))

    return FakeHTTPConnection


class RealModelSmokeBoundaryTests(unittest.TestCase):
    def test_proxy_environment_is_not_used_and_redirects_are_refused(self):
        seen = []

        class Response:
            status = 302
            def read(self, _limit): return b""

        class Connection:
            def __init__(self, host, port, *, timeout):
                seen.append((host, port, timeout))
            def request(self, method, path, *, body, headers):
                seen.append((method, path))
            def getresponse(self): return Response()
            def close(self): pass

        with patch.dict(os.environ, {"HTTP_PROXY": "http://proxy.invalid:3128"}), \
                patch.object(real_model_smoke, "HTTPConnection", Connection):
            with self.assertRaises(real_model_smoke.SmokeFailure) as caught:
                real_model_smoke._api_json("/api/version")
        self.assertEqual(caught.exception.reason, "redirect_refused")
        self.assertEqual(seen[0][:2], ("127.0.0.1", 11434))
        self.assertEqual(seen[1], ("GET", "/api/version"))

    def test_remote_model_tags_are_refused_before_local_lookup(self):
        original = real_model_smoke._api_json
        real_model_smoke._api_json = lambda _path: self.fail("remote tag reached Ollama lookup")
        try:
            with self.assertRaises(real_model_smoke.SmokeFailure) as caught:
                real_model_smoke._local_model_digest("qwen3.5:0.8b-cloud")
            self.assertEqual(caught.exception.reason, "remote_model_tag_refused")
        finally:
            real_model_smoke._api_json = original

    def test_only_exact_locally_installed_tag_with_digest_is_accepted(self):
        digest = "a" * 64
        original = real_model_smoke._api_json
        real_model_smoke._api_json = lambda path: {
            "models": [{"name": "qwen3.5:0.8b", "digest": digest, "size": 123}]
        } if path == "/api/tags" else self.fail("unexpected endpoint")
        try:
            self.assertEqual(real_model_smoke._local_model_digest("qwen3.5:0.8b"), digest)
        finally:
            real_model_smoke._api_json = original

    def test_remote_metadata_and_zero_size_model_are_refused(self):
        original = real_model_smoke._api_json
        try:
            real_model_smoke._api_json = lambda _path: {
                "models": [{"name": "local-alias:1b", "digest": "a" * 64,
                            "size": 123, "remote_host": "https://upstream.invalid"}]
            }
            with self.assertRaises(real_model_smoke.SmokeFailure) as caught:
                real_model_smoke._local_model_digest("local-alias:1b")
            self.assertEqual(caught.exception.reason, "remote_model_refused")
            real_model_smoke._api_json = lambda _path: {
                "models": [{"name": "test-alias:1b", "digest": "a" * 64, "size": 0}]
            }
            with self.assertRaises(real_model_smoke.SmokeFailure) as caught:
                real_model_smoke._local_model_digest("test-alias:1b")
            self.assertEqual(caught.exception.reason, "local_model_size_unverified")
        finally:
            real_model_smoke._api_json = original

    def test_response_byte_limit_is_enforced(self):
        original = real_model_smoke.MAX_RESPONSE_BYTES
        real_model_smoke.MAX_RESPONSE_BYTES = 3
        try:
            with self.assertRaises(real_model_smoke.SmokeFailure) as caught:
                real_model_smoke._read_bounded(BytesIO(b"four"))
            self.assertEqual(caught.exception.reason, "response_too_large")
        finally:
            real_model_smoke.MAX_RESPONSE_BYTES = original

    def test_success_requires_exact_expected_task_sequence_and_stop_reason(self):
        good = [{"task": task, "done_reason": "stop"}
                for task in real_model_smoke._EXPECTED_TASK_SEQUENCE]
        self.assertTrue(real_model_smoke._model_calls_complete(good))
        self.assertFalse(real_model_smoke._model_calls_complete(good + [good[-1]]))
        self.assertFalse(real_model_smoke._model_calls_complete(good[:-1]))
        bad_reason = [dict(call) for call in good]
        bad_reason[0]["done_reason"] = "length"
        self.assertFalse(real_model_smoke._model_calls_complete(bad_reason))

    @POSIX_SIGNAL_DEADLINE
    def test_total_deadline_escapes_normal_exception_fallbacks(self):
        with patch.object(real_model_smoke, "RUN_TIMEOUT_SECONDS", 0.1), \
                patch.object(real_model_smoke, "_run_with_deadline",
                             side_effect=lambda *_args, **_kwargs: time.sleep(0.5)):
            with self.assertRaises(real_model_smoke.RunDeadlineExceeded):
                real_model_smoke.run("qwen3.5:0.8b")

    @POSIX_SIGNAL_DEADLINE
    def test_deadline_signal_propagates_through_assistant_core(self):
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        frame = real_model_smoke._frame(now)

        class SlowModel:
            last_model = "test-local-model"
            def __call__(self, _task, _prompt):
                time.sleep(0.5)
                return {}

        previous = real_model_smoke.signal.signal(real_model_smoke.signal.SIGALRM,
                                                   real_model_smoke._run_deadline)
        real_model_smoke.signal.setitimer(real_model_smoke.signal.ITIMER_REAL, 0.1)
        try:
            with self.assertRaises(real_model_smoke.RunDeadlineExceeded):
                AssistantCore(model=SlowModel()).explain(
                    frame, now=now, knowledge_attempted=False)
        finally:
            real_model_smoke.signal.setitimer(real_model_smoke.signal.ITIMER_REAL, 0)
            real_model_smoke.signal.signal(real_model_smoke.signal.SIGALRM, previous)

    def test_transport_rejects_wrong_model_truncation_and_non_json(self):
        digest = "a" * 64
        cases = [
            ({"model": "other:1b", "done_reason": "stop", "message": {"content": "{}"}},
             "model_identity_or_completion_mismatch"),
            ({"model": "local:1b", "done_reason": "length", "message": {"content": "{}"}},
             "model_identity_or_completion_mismatch"),
            ({"model": "local:1b", "done_reason": "stop", "message": {"content": ""}},
             "content_missing"),
            ({"model": "local:1b", "done_reason": "stop", "message": {"content": "[]"}},
             "response_not_object"),
            ({"model": "local:1b", "done_reason": "stop", "message": {"content": '{"x":NaN}'}},
             "local_model_response_invalid"),
        ]
        for data, reason in cases:
            transport = _bare_transport("local:1b", digest)
            with patch.object(real_model_smoke, "compiled_model_response_schema", return_value={}), \
                    patch.object(real_model_smoke, "_local_model_digest", return_value=digest), \
                    patch.object(real_model_smoke, "_api_json", return_value=data):
                with self.assertRaises(real_model_smoke.MioModelUnavailable):
                    transport("generate_hypotheses", "synthetic prompt")
            self.assertEqual(transport.failure_code, reason)

    def test_digest_change_before_or_after_inference_is_rejected(self):
        digest, changed = "a" * 64, "b" * 64
        response = {"model": "local:1b", "done_reason": "stop",
                    "message": {"content": "{}"}}
        for sequence in ([changed], [digest, changed]):
            transport = _bare_transport("local:1b", digest)
            with patch.object(real_model_smoke, "compiled_model_response_schema", return_value={}), \
                    patch.object(real_model_smoke, "_local_model_digest", side_effect=sequence), \
                    patch.object(real_model_smoke, "_api_json", return_value=response):
                with self.assertRaises(real_model_smoke.MioModelUnavailable):
                    transport("generate_hypotheses", "synthetic prompt")
            self.assertEqual(transport.failure_code, "model_artifact_changed")

    def test_paths_and_methods_are_allowlisted(self):
        with patch.object(real_model_smoke, "HTTPConnection",
                          side_effect=AssertionError("connection must not be opened")):
            with self.assertRaises(real_model_smoke.SmokeFailure):
                real_model_smoke._api_json("/api/delete")
            with self.assertRaises(real_model_smoke.SmokeFailure):
                real_model_smoke._api_json("/api/tags", method="POST", payload={})

    def test_transport_enforces_exact_ordered_three_task_sequence(self):
        digest = "a" * 64
        ok = {"model": "local:1b", "done_reason": "stop", "message": {"content": "{}"}}
        with patch.object(real_model_smoke, "compiled_model_response_schema", return_value={}), \
                patch.object(real_model_smoke, "_local_model_digest", return_value=digest), \
                patch.object(real_model_smoke, "_api_json", return_value=ok) as api:
            # Out-of-order first task is refused before any request is built.
            transport = _bare_transport("local:1b", digest)
            with self.assertRaises(MioModelUnavailable):
                transport("recommend", "synthetic prompt")
            self.assertEqual(transport.failure_code, "task_sequence_refused")
            self.assertEqual(api.call_count, 0)

            # Exactly the three expected tasks succeed in order...
            transport = _bare_transport("local:1b", digest)
            for task in real_model_smoke._EXPECTED_TASK_SEQUENCE:
                transport(task, "synthetic prompt")
            self.assertEqual(api.call_count, 3)
            # ...and a fourth call is refused without another request.
            with self.assertRaises(MioModelUnavailable):
                transport("recommend", "synthetic prompt")
            self.assertEqual(transport.failure_code, "task_sequence_refused")
            self.assertEqual(api.call_count, 3)

    def test_api_json_maps_every_transport_failure_to_closed_reason(self):
        cases = [
            ({"status": 302}, "redirect_refused"),
            ({"status": 500}, "local_ollama_unavailable"),
            ({"status": 200, "request_error": TimeoutError()}, "local_ollama_unavailable"),
            ({"status": 200, "response_error": socket.timeout()}, "local_ollama_unavailable"),
            ({"status": 200, "request_error": ConnectionRefusedError()}, "local_ollama_unavailable"),
            ({"status": 200, "response_error": BadStatusLine("SECRET")}, "local_ollama_unavailable"),
            ({"status": 200, "read_error": IncompleteRead(b"SECRET")}, "local_ollama_unavailable"),
            ({"status": 200, "body": b"{"}, "local_ollama_response_invalid"),
            ({"status": 200, "body": b"[]"}, "local_ollama_response_invalid"),
            ({"status": 200, "body": b'"text"'}, "local_ollama_response_invalid"),
        ]
        for kwargs, reason in cases:
            with self.subTest(reason=reason, kwargs=kwargs):
                sent = []
                with patch.object(real_model_smoke, "HTTPConnection",
                                  _fake_connection_class(sent, **kwargs)):
                    with self.assertRaises(real_model_smoke.SmokeFailure) as caught:
                        real_model_smoke._api_json("/api/version")
                self.assertEqual(caught.exception.reason, reason)
                self.assertEqual(sent[0], ("connect", "127.0.0.1", 11434, 35))
                self.assertEqual(sent[-1], ("close",))

    def test_api_json_refuses_oversized_body_and_accepts_bounded_object(self):
        sent = []
        with patch.object(real_model_smoke, "MAX_RESPONSE_BYTES", 3), \
                patch.object(real_model_smoke, "HTTPConnection",
                             _fake_connection_class(sent, body=b"four")):
            with self.assertRaises(real_model_smoke.SmokeFailure) as caught:
                real_model_smoke._api_json("/api/version")
        self.assertEqual(caught.exception.reason, "response_too_large")
        self.assertEqual(sent[-1], ("close",))

        sent = []
        with patch.object(real_model_smoke, "HTTPConnection",
                          _fake_connection_class(sent, body=b'{"version":"0.1.0"}')):
            self.assertEqual(real_model_smoke._api_json("/api/version"),
                             {"version": "0.1.0"})
        self.assertEqual(sent[-1], ("close",))

    def test_chat_payload_has_exact_limits_and_one_synthetic_user_message(self):
        digest = "a" * 64
        prompt = "synthetic prompt"
        schema = {"type": "object", "properties": {}}
        reply = json.dumps({"model": "local:1b", "done_reason": "stop",
                            "message": {"content": "{}"}}).encode()
        sent = []
        transport = _bare_transport("local:1b", digest)
        with patch.object(real_model_smoke, "compiled_model_response_schema",
                          return_value=schema), \
                patch.object(real_model_smoke, "_local_model_digest", return_value=digest), \
                patch.object(real_model_smoke, "HTTPConnection",
                             _fake_connection_class(sent, body=reply)):
            self.assertEqual(transport("generate_hypotheses", prompt), {})
        requests = [event for event in sent if event[0] == "request"]
        self.assertEqual(len(requests), 1)
        _, method, path, body, headers = requests[0]
        self.assertEqual((method, path), ("POST", "/api/chat"))
        self.assertEqual(headers, {"Content-Type": "application/json"})
        payload = json.loads(body)
        self.assertEqual(payload, {
            "model": "local:1b",
            "messages": [{"role": "user", "content": prompt}],
            "format": schema,
            "stream": False,
            "think": False,
            "options": {"temperature": 0, "num_ctx": 4096, "num_predict": 768},
        })
        self.assertEqual(len(payload["messages"]), 1)
        self.assertEqual(payload["messages"][0]["role"], "user")

    def test_failure_code_keeps_first_reason(self):
        digest = "a" * 64
        replies = [
            {"model": "local:1b", "done_reason": "stop", "message": {"content": ""}},
            {"model": "local:1b", "done_reason": "stop", "message": {"content": "[]"}},
        ]
        transport = _bare_transport("local:1b", digest)
        with patch.object(real_model_smoke, "compiled_model_response_schema", return_value={}), \
                patch.object(real_model_smoke, "_local_model_digest", return_value=digest), \
                patch.object(real_model_smoke, "_api_json", side_effect=replies):
            with self.assertRaises(MioModelUnavailable):
                transport("generate_hypotheses", "synthetic prompt")
            with self.assertRaises(MioModelUnavailable):
                transport("identify_evidence_gaps", "synthetic prompt")
        self.assertEqual(transport.failure_code, "content_missing")

    def test_ollama_version_must_be_bounded_safe_characters(self):
        for version in ("0.12.3", "0.13.0-rc1+build.7"):
            with patch.object(real_model_smoke, "_local_model_digest", return_value="a" * 64), \
                    patch.object(real_model_smoke, "_api_json", return_value={"version": version}):
                transport = real_model_smoke.LocalOllamaStructuredTransport("local:1b")
            self.assertEqual(transport.ollama_version, version)
        for bad in ("0.1\x1b[31mSECRET", "0.1 SECRET", "", "v" * 65, "0.1\n", 7):
            with self.subTest(version=bad), \
                    patch.object(real_model_smoke, "_local_model_digest", return_value="a" * 64), \
                    patch.object(real_model_smoke, "_api_json", return_value={"version": bad}):
                with self.assertRaises(real_model_smoke.SmokeFailure) as caught:
                    real_model_smoke.LocalOllamaStructuredTransport("local:1b")
                self.assertEqual(caught.exception.reason, "local_ollama_version_invalid")

    @POSIX_SIGNAL_DEADLINE
    def test_none_previous_sigalrm_handler_is_restored_to_default(self):
        installs = []

        def fake_signal(signum, handler):
            installs.append(handler)
            if handler is None:
                # Mirrors the real signal.signal, which rejects None.
                raise TypeError("signal handler must be callable or SIG_DFL/SIG_IGN")
            return None  # prior handler not installed from Python

        with patch.object(real_model_smoke.signal, "signal", new=fake_signal), \
                patch.object(real_model_smoke.signal, "setitimer", new=lambda *_args: 0), \
                patch.object(real_model_smoke, "_run_with_deadline", return_value={"ok": True}):
            self.assertEqual(real_model_smoke.run("qwen3.5:0.8b"), {"ok": True})
        self.assertEqual(installs, [real_model_smoke._run_deadline, signal.SIG_DFL])

    def test_cli_redacts_overall_deadline_and_arbitrary_exception(self):
        argv = ["real_model_smoke", "--model", "qwen3.5:0.8b"]
        with patch.object(sys, "argv", argv), \
                patch.object(real_model_smoke, "run",
                             side_effect=real_model_smoke.RunDeadlineExceeded()), \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(real_model_smoke.main(), 1)
        self.assertEqual(output.getvalue().strip(),
                         '{"reason": "overall_deadline_exceeded", "status": "failed"}')

        with patch.object(sys, "argv", argv), \
                patch.object(real_model_smoke, "run",
                             side_effect=RuntimeError(f"{SECRET} prompt text")), \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(real_model_smoke.main(), 1)
        self.assertEqual(output.getvalue().strip(),
                         '{"reason": "smoke_failed", "status": "failed"}')
        self.assertNotIn(SECRET, output.getvalue())

    def test_cli_failure_prints_only_closed_reason(self):
        with patch.object(sys, "argv", ["real_model_smoke", "--model", "qwen3.5:0.8b"]), \
                patch.object(real_model_smoke, "run",
                             side_effect=real_model_smoke.SmokeFailure("local_ollama_unavailable")), \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(real_model_smoke.main(), 1)
        self.assertEqual(output.getvalue().strip(),
                         '{"reason": "local_ollama_unavailable", "status": "failed"}')

    def test_assistant_core_degrades_on_model_unavailable_without_leaking(self):
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        frame = real_model_smoke._frame(now)
        calls = []

        class FailingModel:
            last_model = "test-local-model"
            def __call__(self, task, prompt):
                calls.append(task)
                raise MioModelUnavailable(f"{SECRET} {prompt}")

        result = AssistantCore(model=FailingModel()).explain(
            frame, now=now, knowledge_attempted=False).to_dict()
        # One bounded attempt, then the deterministic static fallback.
        self.assertEqual(calls, ["generate_hypotheses"])
        self.assertNotEqual(result["state"], "complete")
        self.assertEqual(result["generation_method"], "static_reference")
        self.assertTrue(result["hypotheses"])
        self.assertEqual(result["hypotheses"][0]["kind"], "static_alternative")
        # Neither the exception text nor the prompt may reach the output.
        self.assertNotIn(SECRET, json.dumps(result, sort_keys=True))

    @POSIX_SIGNAL_DEADLINE
    def test_run_with_fake_local_api_accepts_valid_model_and_bounds_report(self):
        digest = "a" * 64
        model = "qwen3.5:0.8b"
        ref = "ev:ssh:1"
        responses = [
            {"hypotheses": [
                {"hypothesis_id": "h1", "hypothesis_alternative_id": "credential_attack",
                 "status": "proposed", "statement": "The failures may reflect credential attack activity.",
                 "supporting_evidence_refs": [ref], "contradicting_evidence_refs": [],
                 "assumptions": [], "falsification_conditions": ["Check successful logins."],
                 "expected_observations": [], "missing_evidence": []},
                {"hypothesis_id": "h2", "hypothesis_alternative_id": "misconfigured_automation",
                 "status": "proposed", "statement": "The failures may reflect misconfigured automation.",
                 "supporting_evidence_refs": [], "contradicting_evidence_refs": [],
                 "assumptions": [], "falsification_conditions": ["Compare the schedule."],
                 "expected_observations": [], "missing_evidence": ["automation schedule"]},
            ]},
            {"evidence_gaps": []},
            {"summary": "Review observed authentication failures.",
             "recommended_action": "OBSERVE", "rationale": "The frame does not establish compromise.",
             "evidence_refs": [ref], "limitations": [SECRET]},
        ]
        chat_index = 0
        submitted_prompts = []

        def fake_api(path, *, method="GET", payload=None):
            nonlocal chat_index
            if path == "/api/tags":
                return {"models": [{"name": model, "digest": digest, "size": 123}]}
            if path == "/api/version":
                return {"version": "0.0.0-test"}
            if path == real_model_smoke.CHAT_PATH:
                self.assertEqual(method, "POST")
                submitted_prompts.append(payload["messages"][0]["content"])
                result = responses[chat_index]
                chat_index += 1
                return {"model": model, "done_reason": "stop",
                        "message": {"content": json.dumps(result)},
                        "prompt_eval_count": 7, "eval_count": 3}
            raise AssertionError("unexpected endpoint")

        with patch.object(real_model_smoke, "_api_json", side_effect=fake_api), \
                patch.object(real_model_smoke, "HTTPConnection", side_effect=_no_network):
            report = real_model_smoke.run(model)
        self.assertEqual(chat_index, 3)
        self.assertEqual([call["task"] for call in report["model_calls"]],
                         list(real_model_smoke._EXPECTED_TASK_SEQUENCE))
        self.assertEqual(report["mio_state"], "complete")
        self.assertEqual(report["mio_generation_method"], "model")
        self.assertNotIn("local_model_artifact_digest", report)
        rendered = json.dumps(report, sort_keys=True)
        self.assertNotIn(SECRET, rendered)
        self.assertTrue(submitted_prompts)
        self.assertTrue(all(prompt not in rendered for prompt in submitted_prompts))

        # Restricted records may include the local artifact digest only when
        # the caller explicitly opts in; exercise this through the same
        # successful core path rather than a CLI stub.
        chat_index = 0
        with patch.object(real_model_smoke, "_api_json", side_effect=fake_api), \
                patch.object(real_model_smoke, "HTTPConnection", side_effect=_no_network):
            restricted = real_model_smoke.run(model, include_artifact_digest=True)
        self.assertEqual(chat_index, 3)
        self.assertEqual(restricted["local_model_artifact_digest"], digest)
        self.assertNotIn(SECRET, json.dumps(restricted, sort_keys=True))

    @POSIX_SIGNAL_DEADLINE
    def test_cli_digest_is_omitted_by_default_and_only_added_on_request(self):
        seen = []

        def fake_run(model, *, include_artifact_digest=False):
            seen.append(include_artifact_digest)
            report = {"model": model, "hypotheses": 2}
            if include_artifact_digest:
                report["local_model_artifact_digest"] = "a" * 64
            return report

        for argv, expected_flag in ((["x", "--model", "qwen3.5:0.8b"], False),
                                    (["x", "--model", "qwen3.5:0.8b",
                                      "--include-artifact-digest"], True)):
            out = StringIO()
            with patch.object(sys, "argv", argv), \
                    patch.object(real_model_smoke, "run", side_effect=fake_run), \
                    redirect_stdout(out):
                self.assertEqual(real_model_smoke.main(), 0)
            printed = json.loads(out.getvalue())
            self.assertEqual(printed["status"], "passed")
            self.assertEqual("local_model_artifact_digest" in printed, expected_flag)
            self.assertEqual(seen[-1], expected_flag)
            self.assertNotIn(SECRET, out.getvalue())


if __name__ == "__main__":
    unittest.main()

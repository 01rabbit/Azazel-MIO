# Local real-model smoke test

This opt-in developer check exercises the public MIO `AssistantCore` with a
real model already installed in local Ollama. It uses a fixed synthetic
authentication-failure frame and the model's real structured response. The
transport is a small test-side adapter; the MIO core remains transport-neutral.

It does **not** admit a model to Nexus or Edge, alter product routing, verify
truthfulness or operational usefulness, or substitute for the Nexus runtime,
resource-measurement, HG, hardware, or production-admission gates. No real
incident, Knowledge response, or attacker-controlled text is sent. The script
uses a direct `HTTPConnection` to the fixed `127.0.0.1:11434` address, so
environment proxies are not consulted and redirects are refused. Before
inference it verifies the tag is in the Ollama `/api/tags` inventory, requires
a positive reported size and digest, rejects the documented `remote_model` /
`remote_host` metadata, and refuses `cloud` / `remote` tag components. These
inventory checks are a conservative heuristic, not proof of where a
misconfigured or compromised daemon executes a model. It checks the response model and completion
reason, and checks that the inventory digest is unchanged immediately before
and after each call. That digest check is best effort: Ollama's chat response
does not include the artifact digest, so it cannot cryptographically bind the
response to a model blob. The local daemon's integrity/configuration is also
outside this tool's proof. The digest is omitted from normal output;
`--include-artifact-digest` prints it only for restricted local records.

## Run

Start the already installed Ollama service and use a local model tag:

```sh
PYTHONPATH=src python3 tools/real_model_smoke.py --model qwen3.5:0.8b
```

The script submits the synthetic frame through the normal MIO `AssistantCore`
and validates the bounded response using MIO's prompt-derived JSON schema. It
requires exactly the hypothesis, evidence-gap, and recommendation tasks to
complete once each with `done_reason=stop`, requires no transport failure, and
puts a hard 150-second deadline around the whole run.
It then runs the same frame with no model and verifies that MIO returns its
deterministic fallback with `MODEL_NOT_AVAILABLE`. The JSON report includes
the model tag, Ollama version, task sequence, local token counts and observed
elapsed times; it does not declare a performance threshold. Record the full
source commit/tree and local model digest in the restricted run record when
using the result as evidence.

The transport enforces the task sequence itself: before building any request it
accepts only the next task in the exact order `generate_hypotheses`,
`identify_evidence_gaps`, `recommend`, at most three in total. Any other call
fails closed with the fixed reason `task_sequence_refused` and sends no request.

A pass proves only that this MIO source version accepted one synthetic
response from that local model and retained its no-model fallback. It does
not prove that any product's ordinary adapter or admission path can start that
model.

## Unit tests

`tests/test_real_model_smoke_tool.py` runs with no model and no network. It
covers the allowlist, remote-tag refusal, digest checks, the task-sequence
guard, and MIO's degradation to its static fallback when the transport raises
`MioModelUnavailable` (one attempt, no leaked exception text or prompt). It
also drives `_run_with_deadline` and the CLI against a fake local API, asserting
that prompts and model response text are absent from output and that the
artifact digest is omitted by default and printed only with
`--include-artifact-digest`. The fake-API run returns a schema-valid synthetic
response through all three MIO tasks and checks the accepted report shape. It
does not make an HTTP request or prove a real model's behavior; malformed and
truncated transport responses are covered by separate unit tests.

The deadline tests use `SIGALRM`/`setitimer` and are skipped on platforms
without POSIX signals.

These tests are not evidence that a real model was run. Only an explicit
`tools/real_model_smoke.py --model <tag>` invocation against a locally installed
model produces evidence of that kind.

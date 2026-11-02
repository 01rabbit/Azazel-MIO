# IR fast-assessment adapter and CLI candidate command (offline slice)

**Status:** local candidate on branch `codex/ir-fast-assessment-adapter` from base `0dacea878bd6652b49658d06c9a05ce5be9639a1`, stacked on PR #11 (head `3148caf97ef492ad40e7b2186cd54522e1919e84`). Not merged, not admitted, and not wired to any product.

## Purpose

`src/azazel_mio/ir_adapter.py` links verified case evidence to the existing Edge-derived kernel `azazel_mio.fast_assessment.assess_fast`. The adapter is a pure callable: it performs no model, network or file I/O, and it adds no scoring weights or rules. Every score and factor comes from the kernel. The adapter does not infer classes, labels, severity or ports from raw text.

`mio-ir assessment candidate` is the read-only command that feeds the adapter. The caller supplies normalized signals in a strict JSON document. The command loads the selected case's timeline and evidence verification from the existing IR store, runs the adapter, and prints the result to stdout. It never writes an assessment back to the store.

## Stacking on PR #11

This change depends on PR #11, which provides the IR store and its CLI. The branch contains that work as an ancestor. This change does three things on top of it:

- `cli.timeline` and `cli.verify` rows each gain an additive `case_id` field. The rows keep every existing field, including `record`. Nothing is removed or renamed in PR #11's output.
- The adapter reads the timeline record number from `record`, the key PR #11 already emits. It no longer reads `record_number` from timeline rows.
- The report JSON (`report generate`) carries the same additive `case_id` in its timeline and evidence entries.

Callers must pass the timeline and verify results from the same selected case. The `case_id` check rejects rows from any other case, but the adapter cannot tell which case the caller meant to select. It relies on that check and on the same-case input.

## Command

```
mio-ir assessment candidate --case ID --file normalized-input.json
```

- Read-only with respect to case data. Like every `mio-ir` command, it runs the idempotent schema bootstrap on the store first. On a fresh `MIO_IR_HOME` that creates the store directory and an empty database. Once the bootstrap completes, the command sets `PRAGMA query_only=ON` on its connection, so all post-bootstrap SQL is query-only: the SELECT verification and timeline calls run, and any write attempt fails. It also reads evidence objects for verification.
- Prints one JSON object to stdout and exits `0`. On any validation failure it prints `error: ...` to stderr, prints nothing to stdout, and exits `1`.
- An empty `candidates` list is valid and returns the abstention status.

### Input file

The file must be a regular, non-symlink file of at most 512 KiB, read as UTF-8. It is rejected if it contains duplicate object keys or a non-finite number (`NaN`, `Infinity`).

Schema `mio.ir.fast-assessment-inputs.v1`. Every key shown is required unless marked optional. Unknown keys are rejected at every object level.

```json
{
  "schema_version": "mio.ir.fast-assessment-inputs.v1",
  "case_id": 1,
  "candidates": [
    {
      "event_id": 1,
      "evidence_id": 1,
      "record_number": 1,
      "normalizer_version": "synthetic-normalizer-1",
      "inputs": {
        "severity": 2,
        "classes": ["c2"],
        "token_only": false,
        "ports": [{"kind": "web", "port": 443}],
        "action": "drop",
        "deception_sid": false,
        "benign_classless": false
      }
    }
  ]
}
```

| Field | Type and rule |
| --- | --- |
| `schema_version` | Exactly `mio.ir.fast-assessment-inputs.v1`. |
| `case_id` | Strict integer equal to `--case`. |
| `candidates` | List of at most 256 candidate objects. |
| `event_id`, `evidence_id`, `record_number` | Strict positive integers. `event_id` and `evidence_id` must match a timeline row of the selected case. `record_number` must match that row's `record`. |
| `normalizer_version` | Canonical text: `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}`. |
| `inputs.severity` | Integer 0 to 255. |
| `inputs.classes` | List of at most 16 lower-case tokens (`[a-z][a-z0-9_-]{0,31}`). |
| `inputs.token_only`, `inputs.deception_sid`, `inputs.benign_classless` | Booleans. |
| `inputs.ports` | List of at most 16 objects, each with exactly `kind` (lower-case token) and `port` (integer 1 to 65535). |
| `inputs.action` | Lower-case token. |
| `conflict_evidence_ids` (optional) | List of at most 16 unique strict positive integers. Each must be integrity-verified evidence in the same case. The conflict itself is caller-asserted and not verified by the adapter. |

There is deliberately no field for raw evidence text, a summary, or a label. Any such key is an unknown key and is rejected. The adapter never infers a class, severity or port from text.

Classes and ports are caller-classified. The kernel ignores class names outside its known set and port kinds outside its known set, exactly as documented in `fast_assessment.py`.

### Output

```json
{
  "schema": "ir-fast-assessment-candidates/0.1",
  "adapter_version": "ir-fast-assessment-adapter-0.1",
  "kernel_source_revision": "Azazel-Edge/py/azazel_edge/tactics_engine/scorer.py@47c880b2503d7f771bbdacba9b6205dafe03c4c7",
  "case_id": 1,
  "status": "candidates",
  "candidates": [
    {
      "event_id": 1,
      "record_number": 1,
      "evidence_refs": [1],
      "normalizer_version": "synthetic-normalizer-1",
      "provenance": "caller_asserted_unverified",
      "status": "scored",
      "score": 93,
      "factors": ["severity=2", "sid_present", "threat_class=c2(48)", "web_port=443", "action=drop(contained)"],
      "conflict_evidence_ids": [],
      "explanation": "Candidate-only advisory priority index from caller-asserted normalized signals; factors are the kernel terms. Not a fact, probability or authorization."
    }
  ],
  "limitations": ["..."]
}
```

- `kernel_source_revision` is a static string on every result, including the empty-abstention result. It names the pinned Edge source the kernel is derived from: `Azazel-Edge/py/azazel_edge/tactics_engine/scorer.py@47c880b2503d7f771bbdacba9b6205dafe03c4c7`. It identifies the algorithm source only; the scoring formula is unchanged by this field.
- `status` is `candidates` when candidates were supplied and `abstained_no_normalized_input` for an empty list.
- A candidate with `conflict_evidence_ids` has `status = "abstained_conflict"`, `score = null`, `factors = []`. The kernel is not called for it. This abstention reflects a caller-asserted conflict involving integrity-verified evidence; the conflict semantics themselves remain unverified. Its `explanation` says so.
- Other candidates have `status = "scored"`. `score` is the kernel's integer. `factors` are the kernel's ordered terms.
- Entries are sorted by `event_id`. The output has no probability field, no action or playbook field, and no case-level score.

## Validation and fail-closed rules

Validation completes before the kernel is called. Any failure raises `ValueError`, and the command exits `1` with no stdout.

- The document must be an object with exactly the keys above. Unknown or missing keys are rejected at the document, candidate, input and port levels.
- `schema_version` must match exactly. `case_id` must be a strict integer equal to `--case`.
- The selected case must exist.
- Each timeline row must carry `case_id`, `event_id`, `evidence_id` and `record`, all strict positive integers, and must belong to the selected case. A duplicate event is rejected.
- Each verified row must belong to the selected case. A duplicate evidence id is rejected.
- Each candidate's `(event_id, evidence_id, record_number)` must match the timeline row for that event. Its evidence must be `valid is True` in the same case. A duplicate `event_id` is rejected.
- Each `conflict_evidence_ids` entry must be a strict positive integer naming integrity-verified evidence in the same case. The adapter does not check whether that evidence actually contradicts the signals. Non-integers, booleans and nested arrays or objects fail with `ValueError` before any uniqueness check or kernel call, and the command exits `1` with no stdout.
- Field values are bounded and typed as listed above. Booleans are not accepted as integers, and numeric strings are not accepted as ids.
- Input bounds: at most 1000 timeline rows, 1000 verified rows and 256 candidates. A case whose timeline or evidence rows exceed 1000 fails closed with `timeline exceeds bound` or `verified_evidence exceeds bound`. The bound is unchanged by this change.

Unknown signal values are not errors. Anything the kernel does not recognize reaches it unchanged, and the kernel's existing fallback applies.

## Trust and provenance

- **Input trust:** every normalized signal is supplied by the caller and is marked `caller_asserted_unverified`. The command checks structure, types, bounds and linkage only. It does not verify that a signal is correct or that it matches the raw evidence.
- **Conflict trust:** `conflict_evidence_ids` is caller-asserted. The command verifies only that each referenced evidence object is integrity-verified and belongs to the same case. It does not verify that the evidence contradicts the signals, so a conflict abstention is a caller's claim, not a checked finding.
- **Evidence trust:** `verify` recomputes each evidence object's SHA-256 against the store. The command uses those results, so a candidate referencing tampered or missing evidence is rejected. A digest match shows only that the stored bytes are unchanged since import. It does not show that the evidence is authentic or complete.
- **Output status:** the output is an advisory candidate. It is not a verified fact, not a calibrated probability, and not training ground truth. The score is an ordinal advisory priority index, and only the kernel's ordering and factors are meaningful.
- **No promotion:** nothing in this change writes to the store or to any label, fact or training set. Candidates are not promoted to facts or training labels by this command or by any output of it.
- **No aggregation:** each event is scored independently. The command and adapter produce no case-level score, ranking or roll-up.
- **No authority:** the output authorizes no control, enforcement, containment, decoy launch or exposure, and no playbook selection. Edge's deterministic path and product admission remain the only authorities for any action. Model or IR output is data, not authority.

## Non-goals

- No IR parsing, raw-text inference, label or class recognition, or new weights.
- No model, LLM, network access, or any write to case data.
- No Fabric wire contract, product adapter, persistence, or admission change.
- No changes to `assessment.py`, `fast_assessment.py`, packaging or configuration beyond PR #11's existing `mio-ir` entry point.

## Verification status

Validation was run on the PR #11 stack using the existing macOS arm64 Python 3.12.14 / pytest 9.2.0 environment. No virtual environment or dependencies were created for these checks.

- Focused adapter + CLI workflow: `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:cacheprovider tests/test_ir_adapter.py tests/test_ir_workflow.py` — **102 passed, 14 subtests passed**.
- Full MIO suite: `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -ra -q -p no:cacheprovider` — **424 passed, 99 subtests passed**, no skips or deselections.
- `git diff --check` passed.

The tests exercise malformed and deeply nested JSON rejection, verified evidence linkage, caller-asserted conflict abstention, query-only store access, empty-input abstention, stable kernel outputs and preservation of case/evidence references. These are local tests only; GitHub Actions and Debian ARM64 guest verification have not been established for this stacked Draft candidate. The exact tested head and full commands are recorded in the Draft PR description.

# Frozen session replay pilot v1

Tracking #58/#57. This fixes **software acceptance data**, not an identification
accuracy dataset or a Knowledge-curated training snapshot. The project-authored
24 normalized cases cover browser/healthcheck/scanner/auth patterns, unverified
AI declaration, copied canary, shared-source ambiguity, loss, restart, hidden
HTTP, uncertain clock and stale observations. No actual client/model was run.
Both actor axes therefore remain unknown; a scenario name never supplies truth.

`tests/fixtures/session_pilot_v1/manifest.json` pins `cases.json` by canonical
SHA-256, source, generation, rights, privacy and acceptance. `manifest.sha256`
pins the manifest; `expected.json` fixes the deterministic result. Hashes prove
content binding, not independent registration, source truth or human review.
Change cases/criteria only as a new corpus version after reviewing the golden
and digest changes, before evaluating a candidate.

Twelve development replay cases and twelve reserved replay cases have disjoint
incident/entity/time/content-family IDs. Both remain `replay_eval`, not an
independent held-out human/AI cohort. Group reuse is rejected. The reserved
set is already visible to maintainers; do not rebrand it as unseen real truth.
Existing learning_data/learning_offline and Knowledge #111 retain curation,
training eligibility, licensing and promotion ownership.

Mechanical pass requires zero identity verdicts, maliciousness verdicts,
authorized actions, model calls and expected-status mismatches. Missing and
clock/shared-source/capture cases must withhold hypotheses. False-positive,
recall/calibration and minimum-coverage efficacy thresholds remain **unset**:
there are no independently labelled positives/negatives here. A later capture
study must freeze those thresholds and its sample-size/power plan before
training/tuning and must retain uncertain/mixed labels.

```sh
PYTHONPATH=src python -m azazel_mio.session_pilot \
  tests/fixtures/session_pilot_v1/manifest.json tests/fixtures/session_pilot_v1/cases.json
PYTHONPATH=src python -m pytest -q tests/test_session_pilot.py
```

The CLI exits nonzero for invalid input or a failed mechanical gate. Every
report remains `mechanical_only`, with automatic promotion and verified real
holdout false. No core registration, model, product pin or admission changes.

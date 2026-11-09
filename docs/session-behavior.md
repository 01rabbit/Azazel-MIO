# Bounded session behavior hypotheses and offline evaluation

Tracking: #57 and #58; shared assessment/learning baseline remains #2 and source
reuse #14. Status: task-local, in-process software helper; no product pin, live
adapter, model admission or calibrated AI identification is implied.

`azazel_mio.session_behavior.assess_session(frame, window, as_of=...)` accepts an
existing MioSituationFrame and bounded normalized SessionWindow. Features use a
closed vocabulary and bool/None values with existing model-safe evidence refs
that must belong to that exact frame. Inputs contain no raw HTTP body, packet,
IP address, token, instruction string or executable command. Product adapters
own capture, correlation, normalization, boot/session scope, trusted time,
feature version, freshness budget and handling exceptions outside the hot path.

The helper reuses MioHypothesis for three unresolved alternatives: AI-assisted
tooling, conventional automation/scanner/scripted retry, and legitimate or
human-directed activity. Reasons and checks are fixed non-executable templates.
Timing, error-followed mutation, discovery-followed access, declared-client and
canary observations can support a hypothesis; spoofing, scanners, copied links,
prefetch and legitimate monitoring remain alternatives. No numeric weights,
probabilities, named-actor identity, malicious verdict or severity escalation
are invented. `identity_label=unknown`, `abstained=true`, `probability=null`,
`maliciousness=not_assessed`, `model_calls=0` and `authorized_actions=[]` hold even
when hypotheses are available. This is not an identification classifier that
has earned deployment.

A stale/noncurrent window, frame truncation, capture gap, shared-source ambiguity
or uncertain clock withholds hypotheses with machine-readable reasons. None
means unavailable, not false. An observed negative feature still requires source
evidence. Empty/sparse input remains insufficient. All references, booleans,
feature tuples, timestamps and capacities are revalidated at the call boundary;
a cross-frame reference, secret/address-shaped ID, duplicate feature or injected
instruction is rejected. The input frame and its defensive state are unchanged.

Bounds: at most nine named features and 16 refs each, IDs under the existing
128-character opaque grammar, a maximum one-hour observation window and product
freshness budget capped at one hour (default 300 seconds). These are software
caps; target runtime/overhead measurements and reviewed calibration remain open.

## Evaluation boundary

`session_evaluation.evaluate_session_predictions` measures a supplied candidate's
bool/None AI-assistance decisions against independently supplied SessionLabel
rows. It uses existing learning_data canonical digests/time parsing and creates
no training/inference runtime. Hypothesis strings and heuristic scores are not
accepted as identity decisions. In particular the current helper always
abstains: its coverage is zero and it earns `no_identification_claim`, not a
perfect classification score.

AI assistance and maliciousness labels are separate axes; this first report
scores the AI axis only and never claims attack detection from that result.
Unknown/mixed truth stays unknown, not a negative label. It reports confusion
counts on covered labeled rows, positive/negative denominators, missing outputs,
abstention/coverage, precision, all-positive recall (including abstention cost)
and FPR over all independently labeled negatives. Empty precision/coverage
metrics are null. FPR alone cannot earn a claim at zero coverage.

Cases have unique IDs and explicit incident/entity/time/content-family group,
split and observation time. Cross-split group reuse or temporal inversion is
refused; teacher/model labels are not accepted truth. These checks do not grant
training rights or prove label-availability time: curated snapshot eligibility,
review/outcome availability and complete training split gates remain exclusively
with learning_data/learning_offline and Knowledge #111. Replay evaluation is
reported as its own cohort, never an independent real-world holdout.

The report fixes `automatic_promotion=false`,
`real_world_holdout_verified=false` and calibration-not-estimated. A deliberately
all-positive detector fails the FPR test on the controlled negative case. No
result changes Edge's risk/action policy, admits a model or upgrades teacher
labels into source facts. Pair these metrics with independently captured system
outcomes under Azazel#67 / Edge#393 to assess actual defensive benefit.

## Verification and remaining gates

```sh
PYTHONPATH=src python -m pytest -q tests/test_session_behavior.py tests/test_session_evaluation.py
```

Tests cover alternatives/abstention, incomplete/NAT/clock/stale inputs, frame/ref
binding, sensitive and instruction-shaped input, missing versus negative,
immutable frames, no network/process calls, deliberately bad predictions,
leakage and denominator handling. The entire shared-core suite must also pass.

Representative independently labeled capture, no-canary/behavior-only/canary-only
ablations, held-out identification/calibration and Pi/x86 resource measurements
remain open. There is no automatic hook in AssistantCore, no training on import,
no new wire schema and no prompt/template or D3b candidate change. Edge #547
retains the optional post-decision product adapter. Existing product pins remain
unchanged until independent consumer review and offline artifact gates pass.

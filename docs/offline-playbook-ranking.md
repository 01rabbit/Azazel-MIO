# Offline playbook ranking: evaluation milestone

This branch evaluates one bounded advisory task. The baseline is the existing
`select_playbook`, including its generic fallback and selection-rules digest.
It supplies only its existing first choice: no new baseline or fictitious
secondary ordering is added. No normal Edge/Nexus composition changes, model
activation, automatic training, authorization, or execution are introduced.

## Internal records and rejection gates

`azazel_mio.learning_data.LearningExample` is an internal bounded Python record,
not a Fabric wire contract or new Knowledge database. It retains these separately:

- validated SituationFrame and feature-as-of/prediction time;
- incident, entity and UTC date groups;
- source/snapshot/generation, use rights and rights reference, feature/label
  versions, source quality and lineage;
- direct fact codes and evidence references;
- optional teacher candidate with model/prompt/Knowledge snapshot versions;
- reviewer disposition, evidence basis, label and review time;
- independently observed outcome, timestamp, fact codes and references.

Each `ObservedOutcome` is bound to the exact example ID, canonical frame digest,
frame evidence references and a distinct practice record reference. Its evidence
must come from that frame/direct-evidence context. An independent-outcome review
must cite evidence on that outcome. These checks establish correspondence
inside a record; curated origin and semantic identity still require the
product-validated snapshot input and separately pinned current consumption
context. A reference string alone does not prove that practice occurred.

The teacher candidate is never a training or holdout label. A label requires an
accepted/corrected independent review based on direct facts or a separately
recorded observed outcome. Training further requires an accepted/corrected
independent-outcome review and a bound practice outcome for every training row;
direct-fact reviews can inform evaluation but cannot fit a candidate.
Teacher-only/held/unreviewed labels, contradictory
review/outcome labels, poisoned/unverified sources, unknown rights, missing
lineage, expiry/revocation and version mismatches are quarantined. The internal
API does not authenticate a source or prove its assertions: the future curated
snapshot adapter must perform those checks and preserve the evidence.

The feature extractor reuses the existing selector's token families and excludes
`known_facts`, teacher, outcome and reviewer fields. It emits six bounded flags:
the five existing keyword-family matches and available deception context. Feature
origins are closed; future frame/features and label IDs embedded in feature text
are rejected. These mechanical gates do not prove that a dishonest source has
never paraphrased future information; authenticated lineage and data review
remain necessary.

Missing/unknown incident/entity/time identities cannot become independent groups.
Cross-partition incident, entity or UTC-date overlap rejects the split. The latest
review/outcome availability of an earlier partition must precede every prediction
in the next partition. Identical semantic frame content is deduplicated within a
partition; cross-split copies and conflicting duplicate labels reject the dataset.
Public replay can only enter `replay_eval`, never training or independent holdout.

## Candidates and measured evaluation

`azazel_mio.learning_offline` fits a nearest-centroid supervised candidate from
reviewed training labels and a pattern-memory novelty candidate from training
features. Novelty is the nearest normalized feature mismatch, not maliciousness.
The novelty candidate retains the original selector on familiar inputs and
abstains on unfamiliar patterns. Unseen feature dimensions, absent features and
centroid ties explicitly abstain. No dependency beyond the Python standard
library is required.

Evaluation compares the baseline and both candidates on separate validation/test
partitions. It reports top-1 accuracy, reciprocal rank (unranked labels contribute
zero), coverage/abstention, wrong specific selections, missed expected specific
playbooks, configured wrong-selection/abstention costs, drift abstentions and
actual call timing. Abstentions and selection errors have mutually exclusive
costs. Distances, novelty, rules and teacher confidence are not probabilities;
probability calibration is `not_estimated`, not an invented ECE value. Target
process RSS is unknown until measured separately. Timing is volatile; model
parameters and data digests remain reproducible.

The committed local manifest `examples/public-replay-ranking-eval.json` consumes
two existing public Edge canonical frames from commit
`890643aab842aa8f323459975073e9430ab6141a`, with the retained MIT/Edge notice.
They share one replay cohort, have no independent labels and carry evaluation-only
rights. They test baseline coverage, not accuracy, effectiveness or real-world
generalization. No artifact can be trained from that manifest. Synthetic labelled
fixtures in the tests exercise comparison machinery; they are not real-world
holdout evidence. The optional validated-input boundary is documented in
[curated-snapshot-input.md](curated-snapshot-input.md). Reports derive input
connection from actual consumption bindings; independent holdout remains unmet.
Every report retains the baseline even if a candidate wins a fixture comparison.

## Separate commands and immutable artifacts

From a workspace with `PYTHONPATH=src`:

```sh
python -m azazel_mio.learning_offline examples/public-replay-ranking-eval.json --report report.json --artifact candidate.json
python -m azazel_mio.playbook_ranker frame.json
```

A local evaluation manifest contains exactly `examples`, `partitions`, `now`,
`artifact_expires_at`, `revoked_snapshots` and `costs`. Each example uses the closed
internal record shape. Output creation is exclusive: existing report/artifact
files are never overwritten. With no eligible separated training/validation/test
data, the report records the gap and no candidate file is produced.

Artifacts are bounded non-executable JSON: numeric centroids/patterns, complete
training-row digests, source generation/rights/lineage, feature/label/runtime
compatibility, feature-definition digest, expiry and evaluation-report digest.
They are always `evaluation_only`; expiry is bounded by every training source's
expiry. No pickle, arbitrary callable, command, hidden reasoning or import path
is accepted. Modified content/digests and incompatible feature/runtime versions
are rejected.

The separate `EvaluationRegistry` validates the exact evaluation report when
registering an artifact. Registration does not select it. Explicit evaluation
selection, artifact/source revocation and rollback are separate operations:

```sh
python -m azazel_mio.ranking_registry register --artifact candidate.json --evaluation-report report.json --now 2026-10-31T00:00:00Z --out registry0.json
python -m azazel_mio.ranking_registry select-evaluation --state registry0.json --target ARTIFACT_DIGEST --now 2026-10-31T00:00:00Z --out registry1.json
python -m azazel_mio.playbook_ranker frame.json --artifact candidate.json --registry registry1.json --now 2026-10-31T00:00:00Z
```

Registry files also use exclusive new outputs. `revoke-artifact`, `revoke-snapshot`
and `rollback` select no expired/revoked artifact. Runtime inference always keeps
its top-level choice equal to the existing baseline; a selected artifact only
adds an explicitly evaluation-only `candidate` result. Missing/incompatible/stale
candidates fall back to baseline. This registry is not product admission or a
production rollout mechanism. Imports start no learning, I/O, network or process.

## Remaining integration and RL boundary

Knowledge's optional curated-snapshot bridge now has an internal receipt/input
binding boundary; actual connection is reported only when those inputs validate.
Authenticated product-side rights/revocation and source-origin checks remain with
that adapter. Operational producer/process evidence, real-world holdout,
representative costs/calibration, target RSS/latency, Edge/Nexus learned-candidate
adapters and independent review remain outstanding.
The original normal-path/real-Knowledge work continues separately and is not
replaced by this milestone. No shared wire schema or Knowledge store is added.

RL is a later isolated experiment. A possible advisory-observation simulation
would record frame/hypothesis state, allowed read-only evidence choice, independent
result and confounders; reward would account for useful discrimination, cost and
abstention. Teacher imitation is not RL, correlation is not causal success, and
no live restriction/redirect/exposure exploration or self-issued permission is
part of this implementation. This branch implements no RL algorithm.

## Shared generic/abstention policy (FL-02)

Evaluation policy `playbook-method-comparison.v2` treats the existing generic
playbook as a legitimate method choice for baseline, centroid and pattern-novelty
candidates alike. If independent reviewed labels call for generic, every method
selecting it receives the same accuracy and zero error cost. If a specific
playbook was expected, generic receives the same wrong-selection cost for every
method. This is method-selection accuracy, never attack/benign truth or a
calibrated probability.

The selector's generic fallback reason is retained in `fallback_reasons` and a
separate context count; it is not a baseline-only abstention penalty. Genuine
unavailable/unsupported predictions (feature drift, absent candidate features,
ranking ties or unfamiliar patterns) remain explicit abstentions with the same
coverage/cost/calibration treatment for every method. Unlabelled data still has
no accuracy or cost claim. Identical operational choices cannot establish
candidate superiority merely by changing the method label or calling the same
generic playbook confident. All adoption remains disabled.

The ranking runtime version is now `mio-offline-ranking.v2`; prior candidate
artifacts must be reevaluated/reissued under the corrected policy. Existing
feature and label vocabularies, the deterministic selector and baseline default
are unchanged. Old incompatible artifacts still fall back to baseline.

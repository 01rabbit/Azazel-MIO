# Local observation objectives (deception-observation-v1)

Status: local MIO output only. No Edge or Deception integration is connected.

`ReasoningOutcome.observation_objectives` lists `MioObservationObjective`
records. Each one says only which validated hypotheses a future observation
should help distinguish.

## Contract

- Fields: `objective_id` (local, deterministic `obs-<24 hex>`), `frame_id`,
  `trace_id`, `source_gap_id` (the MIO evidence-gap ID), `hypothesis_ids`
  (1–8 unique IDs of live hypotheses).
- Parsed gap IDs retain at most the first 8 unique valid hypothesis IDs
  (`contracts._model_id_list` with limit 8), so `hypothesis_ids` can never
  exceed the objective bound of 8.
- Fixed authority: `authority="advisory_only"`, `executable=False`. Any other
  value is rejected at construction. The object is frozen.
- `objective_id` is a deterministic function of the frame ID, trace ID, and
  gap ID only: the same inputs always yield the same ID. It is not unique per
  cycle, and it does not encode the current generation. Edge owns
  current-generation freshness and deduplication/replay handling; Edge must not
  assume per-cycle uniqueness.
- It carries no question text, capability, target, environment, package,
  tier, command, activation, or lease selector. The gap itself, including its
  question and capability, stays in the local `evidence_gaps` result.
- MIO does not import Fabric types and does not reproduce Fabric's typed-ref
  grammar.

## When it is emitted

Only when all of these hold:

- the cycle state is `COMPLETE`;
- the selected playbook is `deception-observation-v1`, whether it was chosen by
  default routing or selected explicitly;
- the frame's `deception_status` is `available`, i.e. the frame carries valid
  deception context. An explicit playbook selection does not bypass this:
  a deception playbook with any other status emits nothing;
- the gap is marked `eligible` by the gap scorer. An ineligible gap (for
  example an unregistered capability, a capability outside the playbook
  allowlist, no targets, a cycle broker budget allocated to higher-ranked gaps,
  or a low score) never yields an objective, even though the gap stays in
  `evidence_gaps`. The scorer greedily allocates no more than the remaining
  broker-call budget to eligible gaps. Eligibility means an objective may be
  proposed; it does not certify that the selected capability call returned
  useful evidence;
- the gap and hypothesis IDs have passed the cycle's existing validation.

Eligibility means an objective *may be proposed*. It does not certify a
successful capability call or a collected result; those remain separate cycle
trace records and evidence.

The loop passes the eligible gap IDs to the pure projector explicitly, so the
projector itself never consults the broker or the scorer.

Cancel and supersession are re-checked immediately after the final
recommendation model call, so a flip during that call yields
`OPERATOR_CANCELLED` / `STALE_SUPERSEDED` with no objectives.

Every other state emits nothing: error fallback, validation rejection, budget
exhaustion, dependency unavailable, operator cancellation, and superseded
cycles. Existing validated gaps are not carried out of an incomplete cycle.
Falsified and superseded hypotheses are excluded.

The projection is pure. It takes no broker and adds no capability requests.
Its inputs are the frame, the playbook ID, the cycle state, the validated
hypotheses and gaps, and the eligible gap ID set.

## Local projection diagnostic (not a shared contract)

`ReasoningOutcome.observation_projection` carries an
`ObservationProjectionReport`. It is a local MIO diagnostic of what the
projector did. It is not a Fabric or Edge wire contract, it has no generation
or freshness semantics, and `to_diagnostic()` is a convenience for local logs
and tests only.

- `state_skip`: set when no per-gap evaluation happened. Closed codes:
  `not_complete`, `wrong_playbook`, `deception_unavailable`,
  `invalid_frame_binding`, `malformed_input`.
- `gap_outcomes`: one closed code per evaluated gap, in input order, bounded to
  the cycle's `ReasoningBudget.max_gaps`. Codes: `emitted`, `not_eligible`,
  `invalid_id`, `duplicate_gap`, `no_live_hypotheses`.
- `unreported_gap_count`: gaps beyond that bound, not listed in `gap_outcomes`.
- `emitted_count` and `omitted_hypothesis_count`: counts over all gaps. The
  second counts live hypotheses cut by `MAX_OBJECTIVE_HYPOTHESES` (8).

The report never contains raw gap or hypothesis IDs, question text, or
capability names. Malformed inputs fail closed: no objectives and a
`malformed_input` state skip. Non-COMPLETE terminal outcomes record only
`state_skip = not_complete`.

The objective payload (`MioObservationObjective.to_dict()`) and the
`project_observation_objectives` return shape are unchanged. The report is
produced by `project_observation_report`, which returns the same objectives
plus the report.

## Edge dependency (not implemented here)

Edge must independently authorize any observation; an objective is never
authorization. It maps the local
`objective_id` to Fabric's typed `observation_objective:` ref only after the
Fabric v0.2 proposal is accepted. Until then MIO→Edge/Deception is not
connected, and this object does not authorize, activate, or request anything.

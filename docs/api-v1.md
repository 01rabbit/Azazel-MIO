# M.I.O. internal API v1

`azazel_mio.assistant.AssistantCore(model=None).explain(frame, *, knowledge=(), now: str, knowledge_attempted: bool = True, cancel_check=None, stale_check=None) -> Assistance`

`frame` is `azazel_mio.contracts.MioSituationFrame` (existing Edge v2 semantics).
`AssistantCore(model, coordinator=...)` may opt into product-neutral request lifecycle
coordination. Coordinated responses add `cycle_disposition`: `current` means the
cycle was accepted by the coordinator; any other value (`backpressure`,
`in_flight_duplicate`, or a fixed stale/cancel/restart reason) means the result is
not current. For every non-current disposition, observations, hypotheses,
unknowns, checks, knowledge, handoff, and reasoning trace are empty, and dependency
outcomes are `unavailable`. Consumers must not use the frame ID or state in such a
response as a current assessment. Calls without a coordinator retain the original
response shape and behavior.

`Assistance.to_dict()` returns schema_version (`mio.assistance.v1`), trace_id,
frame_id, generation_method (`static_reference` or `model`), state, observations,
hypotheses, unknowns, next_checks, knowledge, handoff, reasoning_trace.
The v1 response retains those fields and adds the optional
`dependency_outcome` object. Its `knowledge` value uses the closed enum
`available | absent | not_queried | timeout | expired | rejected | unavailable`; `deception`
uses `available | absent | timeout | rejected | unavailable` (`expired` is
only applicable to date-bounded Knowledge context).
This additive field is orthogonal to `state` (which remains
`dependency_unavailable` when the reasoning loop reports that state) and does
not describe Edge authority or action. Existing v1 consumers may ignore the
unknown field; consumers that validate object keys must accept this documented
v1 extension. `next_checks` may add fixed, scenario-specific read-only checks
when these typed outcomes are present. Dependency-specific checks use only
closed status values and typed expiry validation; authentication checks are
gated by the selected closed playbook ID. None use peer response prose.
`knowledge_attempted` defaults to `True`, preserving existing behavior. A caller
may pass the exact boolean `False` to report `not_queried` only when the frame
has no Knowledge refs or adverse dependency status and no Knowledge context,
reference, or advisory inputs were supplied. Invalid values raise `TypeError`.
The result adds a fixed next-check stating that this fast assessment did not
query Knowledge and directing the consumer to the separate validated Knowledge
analysis lane. It contains no action recommendation and does not change the
serialized `MioSituationFrame` schema.
Existing BoundedReasoningLoop, ReasoningCoordinator, playbook and broker APIs keep
their names. For `generate_hypotheses`, multi-prompt playbooks now require at least
two hypotheses with distinct `hypothesis_alternative_id` values selected from
trusted playbook slots. Every multi-prompt playbook has a benign or unresolved
slot, and at least one such slot must be selected. The schema advertises
`minItems: 2` and an enum of that playbook's slot IDs. `update_hypotheses` also
requires the field and preserves the existing slot for stable hypothesis IDs.
The selected slot ID is included in each hypothesis and in a trace event, marked
`model_proposed_unverified`; the trace records the associated trusted role with
the field `proposed_role` and same verification status. This checks slot diversity, not whether the prose
actually fits a slot. The prose remains model-proposed and unverified; slot roles
are not evidence, facts, or authority, and MIO does not claim semantic competition
is validated. Adapters must return the new field and use IDs from the supplied enum. Invalid slot selections end in
`validation_rejected` and the deterministic no-model handoff. Prompt template
version is `1.5.0`. Custom playbooks must define one unique slot per prompt and at
least one benign or unresolved role. There is no enforcement operation or
executable recommendation.

`VerifiedKnowledgeContext(source: str, generation: str, as_of: str, expires_at: str,
facts: tuple[str, ...], inferences: tuple[str, ...], evidence_refs: tuple[str, ...] = ())`
is an internal projection, not a wire contract. Products perform authentication,
authorization, signature/schema/revocation/privacy checks before construction.
MIO bounds and checks all fields again, rejects expired/future/malformed contexts,
and preserves facts and inferences separately. A context grants no authority.
`now` is mandatory, timezone-aware ISO 8601, supplied by the product clock.

`KnowledgeLiteAdvisory(technique_id, name, summary, claim_id, bundle_digest,
freshness, generation, as_of, citation, revocation_status, trust_check="verified",
expires_at=None)` is accepted through `explain(...,
knowledge_lite_advisories=(...), now=...)`. It is projected as
`kind=knowledge_lite_advisory`, `source_kind=knowledge_lite`, and
`claim_status=reported_unverified`. Its summary remains only a reported claim:
it is not placed in observations or VerifiedKnowledgeContext facts/inferences.
The projection preserves the claim, bundle, generation, timestamp, citation,
freshness, trust check, and revocation status. Missing expiry stays `null`; MIO
does not infer an expiry. A supplied expiry must be timezone-aware, later than
`as_of`, and later than the caller's `now`.

`freshness` is the closed enum `current | static`; `trust_check` must be
`verified`; `revocation_status` is `clear | unknown | revoked`, with revoked
claims rejected and unknown status retained under the weaker
`unverified_advisory_revocation_unknown` trust label. A `current`
claim is labelled `current_at_lookup`, not treated as timeless: callers must
recheck the claim and revocation status before relying on it. The no-model path
also emits a fixed read-only recheck suggestion. Knowledge Lite has no per-claim
expiry, so consumers must not substitute the bundle freshness label for expiry.
When a valid advisory is supplied with no other Knowledge outcome,
`dependency_outcome.knowledge` changes from `absent` to `available`. It reports
that Knowledge supplied a usable advisory projection, not that the claim was
verified or promoted to a fact. Existing timeout, expiry, rejection, or
unavailable outcomes retain precedence over an advisory.

Products generate opaque trace/frame IDs from their accepted incident and current
boot/material generation. Callers never take these IDs from operator/model text.
Changed boot or material generation must use a new frame ID and supersede/cancel
old work; coordinator retains its existing strict completion ticket checks.
No result from a cancelled/stale frame is offered as a current explanation.

The pure package imports no Edge/Nexus modules and opens no network, files or
processes at import. Products own governance, HTTP, OS persistence and audit sinks.

Generated ID grammar: `mio-<16 lowercase hex nonce>-<1..12 decimal counter>` for trace_id; append `:frame` for frame_id. The process nonce is generated by the product (never a host identifier); other pre-existing fixture ID forms remain accepted.

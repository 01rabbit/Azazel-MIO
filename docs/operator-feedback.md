# Local operator disposition reports

`azazel_mio.operator_feedback.OperatorDispositionLog` links an operator review to
an original `MioSituationFrame` and completed `ReasoningOutcome`. Construct it
with `frame=...`, `outcome=...`, then call `append(record, now=adapter_clock)`.
Every `OperatorDisposition` repeats the exact trace, cycle, advisory, and
`sha256:`-prefixed canonical frame digest. The reasoning trace records this
material digest at frame entry, so replacing material under the same frame ID
fails validation. A second canonical digest binds every recommendation field
(summary, rationale, limitations, evidence, action, advisory ID, executable flag)
to the recommendation trace event. Replacing material under the same advisory ID
fails validation. Legacy traces without either digest are deliberately refused.
The constructor also requires strict consecutive event sequence numbers, one
initial frame event, one penultimate recommendation event, and one final complete
event, with matching cycle identity, state and projected payloads. These checks
establish internal consistency; adapter custody of the original trace remains
necessary because hashes alone do not authenticate a producer.

Records contain a digest reference for the reviewer, a disposition
(`accepted`, `corrected`, `rejected`, `held`), a timezone-aware review time, and
1–32 evidence references already present in the frame. Optional Edge decision
and action references are SHA-256 references to adapter-owned records, never
credentials, URLs, raw prompts, or action commands. A reference's syntax does
not establish the existence, identity, or authenticity of its target.

`outcome` is `unknown` until action reporting is supplied. Other values are
`pending`, `succeeded`, `failed`, or `not_applied`; each requires an action
reference and observation time. Observation time must follow review time and
not exceed the adapter's clock. `succeeded` requires a defensive applied state;
`pending`, `failed`, and `not_applied` forbid one. `failed` reports an attempted
action that failed without asserting a resulting applied state; `not_applied`
reports that the action was not applied, without asserting an attempt. These
are operator-reported facts, not proof of execution or causation. A correction or later outcome is a new record
with a new record reference; prior entries are retained. Review timestamps must
be nondecreasing in append order (equal timestamps are allowed). Outcome times
must also be nondecreasing for the same action reference. A later result can be
appended using the original review time or a later review time, provided it does
not precede the last appended review. An earlier observation arriving late is
refused rather than inserted into history. If newer reviews have already been
appended, report a fresh review and fresh observation satisfying these bounds;
do not rewrite the timestamp of the old observation. Archival late-arrival
support needs a separate ingestion-time contract. A log holds at most
256 records and rejects overflow without evicting history. `records()` returns
an immutable tuple. The adapter owns durable append-only persistence, reviewer
authentication, source provenance, and selecting the original completed cycle.
This in-memory helper is not a multi-writer storage service.

Every exported record declares `authority=operator_report_unverified`.
There is no recommendation input, execution hook, learning label conversion,
ranker registration, or production promotion in this module. Reports do not
enter prompt material or change recommendation authority. A later offline
curation process would need independent source/rights validation, grouping,
quarantine, label review, and evaluation under the existing `LearningExample`
contract. Acceptance of a recommendation does not supply those checks and
never automatically promotes a learning candidate to production.

Current scope excludes cycles without a completed advisory, post-frame evidence,
and automatic feedback collection in product adapters. Those require separate
contracts; this helper refuses to guess their linkage.

# Local operator disposition reports

`azazel_mio.operator_feedback.OperatorDispositionLog` links an operator review to
an original `MioSituationFrame` and completed `ReasoningOutcome`. Construct it
with `frame=...`, `outcome=...`, then call `append(record, now=adapter_clock)`.
Every `OperatorDisposition` repeats the exact trace, cycle, advisory, and
`sha256:`-prefixed canonical frame digest. The reasoning trace records this
material digest at frame entry, so replacing material under the same frame ID
fails validation. Legacy traces without the digest are deliberately refused.

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
`pending` and `not_applied` forbid one. These are operator-reported facts, not
proof of execution or causation. A correction or later outcome is a new record
with a new record reference; prior entries are retained. A log holds at most
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

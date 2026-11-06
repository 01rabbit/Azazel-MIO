# M.I.O. internal API v1

`azazel_mio.assistant.AssistantCore(model=None, *, coordinator=None).explain(frame, *, knowledge=(), references=(), reported_knowledge=(), now: str, knowledge_lite_advisories=(), knowledge_attempted: bool = True, knowledge_context_response=None, fabric_knowledge_context_response=None, cancel_check=None, stale_check=None) -> Assistance`

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

## Product model boundary and measurement

The optional `model` argument is a product-provided callable with the
`(task: str, prompt: str) -> Mapping[str, Any]` shape. Product code owns provider
selection, authorization, transport, deadlines, cancellation and any token or
resource-usage measurements. To retain bounded per-call elapsed time and outcome
metadata in memory, products may wrap that callable:

```python
from azazel_mio import AssistantCore, MeasuredTransport

tasks = (
    "generate_hypotheses",
    "identify_evidence_gaps",
    "update_hypotheses",
    "recommend",
)
measured = MeasuredTransport(provider_transport, allowed_tasks=tasks)
assistance = AssistantCore(model=measured).explain(frame, now=product_clock())
for call in measured.records():
    record_metric(call.task, call.elapsed_ns, call.outcome)
```

`MeasuredTransport` passes task and prompt through unchanged and returns the
provider result unchanged. Its immutable records contain only an allowlisted
task label, elapsed nanoseconds and `success`/`failure`; prompt, response and
exception text are not retained. Unknown task labels are recorded as `other`.
History is bounded (256 records by default; caller limit 1–4096) and process-local;
it is not a durable audit log. Timing is best-effort: a clock/history failure may
omit a record but does not change the provider result or exception. The wrapper
does not add a call limit; `ReasoningBudget` remains the per-cycle core bound.
It does not report token counts, model loading, RSS, or resource supply. Providers
that expose usage must report and validate those values in product-owned metrics.
This wrapper and MIO output do not authorize a provider or request execution of
a capability.

## Assistance response and Knowledge projections

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

`KnowledgeLiteAdvisory(technique_id, name, summary: str | None, claim_id, bundle_digest,
freshness, generation, as_of, citation, revocation_status, trust_check="verified",
expires_at=None, source_citation=None)` is accepted through `explain(...,
knowledge_lite_advisories=(...), now=...)`. It is projected as
`kind=knowledge_lite_advisory`, `source_kind=knowledge_lite`, and
`claim_status=reported_unverified`. Its summary remains only a reported claim:
it is not placed in observations or VerifiedKnowledgeContext facts/inferences.
`summary` may be empty and is preserved exactly, with no fabricated fallback.
Static-reference exception: a producer that supplies `summary=None` (no summary at
all) is accepted only when every other check passes, `freshness` is `static`,
`revocation_status` is `clear`, `expires_at` is absent, and `technique_id` matches
`T[0-9]{4}(\.[0-9]{3})?` (format only; catalogue membership is not checked). MIO then projects the advisory with `summary: ""` and
never synthesizes replacement prose. It stays `reported_unverified`, `unverified_advisory_only`,
and advisory-only: no observation, known fact, evidence, truth, or authority is
created. Any other `None` summary (including `current`, `unknown`/`revoked`
revocation, a supplied expiry, a malformed technique ID, or failed bindings)
is rejected. Blank or whitespace-only names are rejected, and names must contain
only printable characters.
`citation` remains the canonical identifier; adapters mapping a KnowledgeRef use
its `claim_id` for this field, not its human-readable dataset citation.
The optional trailing `source_citation` carries that source's dataset citation
separately as untrusted display text. It accepts at most 160 printable characters,
including the empty string, under Knowledge's already-cleaned plain-text policy
(no HTML/Markdown formatting, HTTP URLs, or control characters). MIO rejects
unclean text rather than rewriting source content. `None` omits the projected
field, preserving the output shape for existing callers; explicit `""` includes
`source_citation: ""`. Source citations establish no trust or authority and do
not enable learning, fact promotion, or enforcement.
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

`KnowledgeContextResponseAdvisory(context_response: Mapping[str, Any])` accepts
one bounded response matching the `ContextResponse` schema at Knowledge
`09d234cde0ceb447a3ebc7e9704eef4758ac4a4d`. MIO checks required and optional
top-level fields, JSON size/depth/node limits, and selected field types. It
emits a separate `knowledge_context_response_advisory` receipt with
`claim_status=reported_unverified`. The projection contains only public
ATT&CK technique IDs from `threat_context.attack_mapping`, sorted unique
`source_groups` from `threat_context.ioc_matches[*].sources`, typed
`source_freshness` values (`oldest_feed_days`, `attack_version`), and a
canonical defensive state from MIO's closed vocabulary. It drops source text,
IOC values, actor/event data, advisory/provenance IDs, scores, recommendations
and actions, references, and other metadata. This advisory is not prompt
material, an observation, a verified fact, evidence, or authority. Invalid or
oversize input is rejected and degrades the result. A valid response marks
Knowledge available only when the frame has no stronger dependency outcome.

Source groups are Knowledge-reported source labels, not truth attribution or
proof of licensing, origin, or currentness. At the pinned Knowledge revision,
`correlate/pipeline.py` takes `SourceRef.group` from configured feed groups
(falling back to feed IDs) and emits sorted unique groups per IOC match;
`config/feeds.yaml` includes `abusech`, `spamhaus`, and `edge_reported`.
MIO accepts only ASCII labels matching `[a-z][a-z0-9_-]{0,31}`, at most
32 IOC matches, 16 labels per match, 64 label occurrences in total, and
16 distinct labels. Malformed or excessive source collections reject the
whole receipt; no partial source set or truncation is emitted. Missing or empty
match/source lists project to `source_groups=[]`; they supply no identity and
do not by themselves make an otherwise empty projection useful. Source groups
remain unverified receipt metadata and never enter prompts, observations,
verified facts, or training. Existing JSON size/depth/node bounds still apply.

### Fabric Knowledge Context response v1 (separate input)

`FabricKnowledgeContextResponseAdvisory(response: Mapping[str, Any])`, passed as
`AssistantCore.explain(..., fabric_knowledge_context_response=...)`, accepts one
Fabric `knowledge-context-response/v1` payload (Fabric PR #76,
`50494cf769978abdbad21626a130d6525c83135d`). It is a different contract from
`KnowledgeContextResponseAdvisory` (legacy Knowledge `/v1/context`); neither
wrapper is accepted by the other's keyword, and the legacy input, output key and
behavior are unchanged. MIO has no Fabric runtime dependency: the check is a
stdlib re-implementation of the wire shape.

Validation is strict and fail-closed: exact field sets at every level (unknown
or directive-shaped keys such as `action` or `command` are rejected), exact
`str`/`list`/`dict` JSON types, Fabric identifier/opaque-reference grammar
(opaque refs may not contain `://`), printable bounded text, the Fabric
list caps (64 facts, 32 inferences, 8 provenance/method refs, 16 basis facts,
16 unknowns/limitations), explicit-offset instants with
`as_of <= generated_at < expires_at`, distinct and non-dangling fact/inference
IDs, and a MIO-specific stricter node cap (2048; Fabric does not define a
node-count cap), depth (8) and canonical UTF-8 size (128 KiB) limits. A payload
can therefore be valid under Fabric's walker yet rejected by MIO's additional
resource bound. Any failure rejects the whole payload with no partial
projection. A response with neither facts nor inferences is still useful when
it carries bounded unknowns or limitations;
only an entirely empty result is rejected. A response whose
`expires_at` is not later than the caller's `now` is rejected as expired
(`dependency_outcome.knowledge=expired`); future-dated `generated_at` values are
rejected. Rejection adds `KNOWLEDGE_CONTEXT_REJECTED` and leaves the rest of the
result unchanged.

A valid response adds a separate top-level `fabric_knowledge_context_advisory`
object (absent otherwise, so the default output shape is unchanged):
`kind=fabric_knowledge_context_response_advisory`,
`source_kind=fabric_knowledge_context_response_v1`, `schema_version`,
`claim_status=source_reported_unverified`, `authority=advisory_only`,
`trust=unverified_advisory_only`, `snapshot_state`
(`complete|partial|stale`), UTC `generated_at`/`expires_at`, `facts`,
`inferences`, `unknowns` and `limitations`. Each fact carries
`claim_class=source_reported_fact`, `fact_id`, `subject`, `predicate`, `value`
and `provenance_count`. Each inference carries `claim_class=inference`,
`inference_id`, `subject`, `statement` and the `basis_fact_ids` it cites; facts
and inferences are never merged. Request/correlation/provider IDs, source and
snapshot refs, provenance refs and method refs are validated but not copied.
Fact and inference source IDs (`fact_id`, `inference_id`) are validated as identifiers
but are not copied. MIO emits bounded local references instead: `fact-1`, `fact-2`, …
and `inference-1`, `inference-2`, … in response order. Each inference's
`basis_fact_ids` is remapped to the local fact references, so the claim relationships
are preserved while source identifiers do not appear in the output. Malformed,
duplicate, or dangling source references still reject the whole payload.

A `partial` or `stale` snapshot remains visible in this separate unverified
advisory, but it is not reported as a healthy Knowledge dependency. When it is
the only Knowledge context, `dependency_outcome.knowledge` is `unavailable`,
the output includes the fixed `KNOWLEDGE_CONTEXT_PARTIAL` or
`KNOWLEDGE_CONTEXT_STALE` unknown, and `next_checks` asks for an authorized
current full-node snapshot. That fixed check is placed first so optional checks
cannot crowd it out. Here `unavailable` means no complete current
snapshot was supplied; it does not claim that the transport or service was
unreachable. A separate complete Knowledge source retains the aggregate
`available` outcome while the incomplete Fabric receipt and its unknown remain
visible.

Copied prose is refused, not shown, when it contains a non-global IPv4 or IPv6
literal; a MAC literal in colon, hyphen or Cisco dotted form; labelled shorthand IPv4 with
two or three numeric parts (for example `ip 127.1` or `src:10.1`) that expands to a non-global
address; or a local-only host name. Before checking, MIO builds a scan-only copy in which
common defang forms are read as the characters they hide: `[.]`, `(.)`, `{.}` and `[dot]`,
`(dot)`, `{dot}` (case-insensitive) become `.`, and `[:]`, `(:)`, `{:}` become `:`, with
optional spaces inside and around the brackets. The original text must pass and so must
the normalized copy, so `10[.]0[.]0[.]5` is refused while `8[.]8[.]8[.]8` remains usable
as written. Only the original text is ever shown. IPv6 suffixes are tested from each
hex-letter or separator-colon boundary, except a decimal digit after a decimal digit and a
colon that begins or continues `::`, so a glued prefix (`srcfe80::1`), a digit-prefixed
prefix (`1fe80::1`) or a separator prefix (`Dec:fd00::1`) cannot hide a non-global suffix.
Shorthand IPv4 is interpreted in prose only when an address label sits immediately before
it. Short protocol-like labels `ip`, `ipv4`, `src`, `dst` and `addr` may be followed by optional
spaces, colon, equal sign or dot (`ip 127.1`, `src:10.1`, `dst=10.1.2`). Full English labels
`source`, `destination`, `address` and `host` count only when followed by an explicit colon or
equal sign, optionally followed by spaces (`source:127.1`, `destination=192.168.1`,
`host: 10.1.2`). Bare phrase forms such as `host 10.1.2`, `source 127.1` or
`The destination. 10.5 GB` are treated as prose and are not refused. A short label may be
glued to the number (`ip127.1`, `src10.1`) and is still refused when the shorthand expands to a
non-global address. Under a label, a shorthand part with more than one digit that begins with `0`
(for example `ip 0177.1`, `src 010.1`, `ip 0177.0.1`) is refused as ambiguous, because inet_aton-style
parsers may read it as octal. Labelled dotted groups of two to four numeric parts are scanned, each
part decimal digits (any length) or `0x` plus hex digits. Labelled hex shorthand (`ip 0x7f.1`,
`src 0x7f.0.0.1`) is refused as ambiguous. A labelled four-part decimal group is parsed as IPv4 and
refused when invalid (`src 10.0.0.0177`, `ip 10.1000` as two-part shorthand expands to a private address)
or non-global; valid global literals are preserved. Labelled `ip 0.75` is refused because it denotes
non-global shorthand (`0.0.0.75`), whereas unlabelled `confidence 0.75` is preserved.
A letter before the label does not start one (`tip 0.75` and `tip 0x7f.1` are ordinary text).
Ordinary decimal, version and unit text such as `confidence 0.75`, `version 0.9.1`, `10.5 GB`
and an unlabelled dotted version such as `10.1.2` remains usable. As a fail-closed
consequence, a public address with a private-looking group after a colon (for example
`2606:4700:fd00::1`) is also refused. Ordinary version and date text such as `15.1.2`,
`2026-10-30` and `23:00:00` remains usable. Any `scheme://` URL embedded in a copied subject or prose string, whatever its `entity_type`,
has its host parsed and screened with the host rules below: shorthand, integer and hex hosts
(`http://127.1/`, `http://2130706433/`, `http://0x7f.1/`), non-global IP literals, single-label
hosts, userinfo (`@`), percent-encoded or backslash authorities and invalid ports are refused,
while public hosts (`https://example.com/a`, `http://8.8.8.8/`) remain usable.
A typed address subject (`entity_type` `ip` and its aliases such as `ipv4`, `ipv6`, `ip_address`,
`*_ip`, `*_addr`, case-insensitive) must be exactly one globally routable IP literal: shorthand, private or
reserved addresses, IPv4-mapped IPv6 and dotted names are refused. Host subjects (`host`,
`hostname`, `fqdn`, `domain`) must be a global IP literal or a dotted name whose final label
is not all-numeric and not hex-like address notation; a bare single label is refused. A final label matching
`0[xX][0-9A-Fa-f]*` (for example `127.0x1`, `0x7f.0x1`, `10.0x1`) is refused because inet_aton-style parsers
read it as address shorthand, while ordinary names such as `host-1.example.com` remain usable.
Entity types are normalized (camelCase split, separators read as `_`) and matched by token or known compact alias,
so `srcIP`, `srcip`, `ClientIP`, `remoteAddr`, `source_address`, `peer_address`, `address_v4`, `attackerip`,
`remoteaddress`, `sourceaddress`, `attackeraddr`, `c2ip` and `ip4` are address types. `iphone`, `ipsec_policy`,
`mac_addr`, `email_addr`, `sender_address` and `wallet_address` are not. URL types (`url`, `uri`, `link`, `href`,
`*_url`, `*_uri`)
use the same strict authority checks with or without a scheme; a bracketed IPv6 host such as
`https://[2606:4700:4700::1111]` is kept intact. The embedded-URL scan also covers nested and comma-joined
URLs (`https://example.com/f?u=http://2130706433/`), and DNS host labels must be ASCII letters, digits and
hyphens (at most 63 characters per label, 253 in total).
IPv6 IPv4-compatible (`::/96`), IPv4-translated/SIIT (`::ffff:0:0:0/96`), NAT64
(`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`) and Teredo (`2001::/32`) addresses are always refused,
even when the embedded IPv4 address is public. These prefix decisions are independent of the Python version;
other address classes still use that version's `ipaddress.is_global` table. Zone-scoped IPv6 literals with an
interface suffix such as `%eth0` are also refused.
Other entity types get no address-type validation, but copied strings are still screened for URL hosts and address
literals. A `scheme://` URL embedded in any copied string is checked, including nested or comma-joined URLs;
scheme-less URLs in other entity types are not parsed. Typed URL values do get strict authority checks without a
scheme. Address-tokened subjects must be a single public IP; non-IP values such as CIDR or reputation text are
refused as unsupported. DNS hostnames must use ASCII letters, digits and hyphens; underscores, trailing-dot names
and IDNs are refused. The generic URL scan does not decode percent-encoded URLs or parse malformed URL-like prose
such as `http:127.1` or `//127.1/`.

Residual limits: an arbitrary privately owned FQDN under a public suffix (for example
an internal `srv.example.com`) is indistinguishable at this layer, so upstream P0
policy and source controls remain required. Unseparated 12-hex MAC forms and malformed
IPv6 with a dotted tail are not detected here. Disambiguation is conservative: unlabelled
shorthand notation (for example a bare `127.1` or `10.1` in prose) is treated as ambiguous
prose and preserved, not classified as an IP, so an address written without one of the labels
above is not refused. Bare full-word phrase forms (for example `host 127.1` or `address 10.1`
without a colon or equal sign) are likewise preserved as prose, a residual case. Defang normalization covers only the forms listed above:
other encodings (for example `hxxp`, `[at]`, full-width or Unicode dots, or unbracketed
spaces such as `10 . 0 . 0 . 5`) are not normalized. Shorthand separated from its label by a
dash or underscore (`ip-127.1`, `ip_127.1`) is not refused, and shorthand preceded by a digit
and dot (`2026.10.1`) is read as part of a longer dotted number, not as shorthand. Public
IPv6 suffixes that begin with a private-looking group are refused fail-closed.

All provider claims are source-reported, unverified and advisory-only. They are
never converted into `observations`, known facts, `knowledge_refs`, evidence,
authorization or model prompt material, and free text is carried as inert data.
A valid `complete` response marks `dependency_outcome.knowledge` `available`
only when the frame has no stronger outcome. A `partial` or `stale` response
uses `unavailable` as described above. This means the response passed MIO
validation and is within its time window; it does not mean its claims were
independently corroborated. Request and correlation identifiers are checked for shape only:
this API receives no corresponding request and does not verify that they match
one. When the legacy and Fabric advisory inputs are both supplied, a valid
input can keep the aggregate dependency outcome `available` while a rejected
input is separately reported as `KNOWLEDGE_CONTEXT_REJECTED`. Construction does
not authenticate the provider. If a coordinated
explanation is superseded, cancelled, or cannot start because of backpressure,
its Knowledge advisories are omitted with the other non-current material.

This is an in-process input seam only. Production networking, authentication
principal and token rotation, TLS, privacy/retention approval, and request
deadline ownership remain product-adapter inputs and are not implemented.
MIO does not infer response generation, expiry, or revocation.

Products generate opaque trace/frame IDs from their accepted incident and current
boot/material generation. Callers never take these IDs from operator/model text.
Changed boot or material generation must use a new frame ID and supersede/cancel
old work; coordinator retains its existing strict completion ticket checks.
No result from a cancelled/stale frame is offered as a current explanation.

The pure package imports no Edge/Nexus modules and opens no network, files or
processes at import. Products own governance, HTTP, OS persistence and audit sinks.

Generated ID grammar: `mio-<16 lowercase hex nonce>-<1..12 decimal counter>` for trace_id; append `:frame` for frame_id. The process nonce is generated by the product (never a host identifier); other pre-existing fixture ID forms remain accepted.

Capability Broker construction is a setup boundary: with an injected audit
sink it starts one daemon dispatcher before returning. Construction may wait
for Python thread bootstrap; process-control exceptions from startup propagate
after preserving the sole reservation. Ordinary startup exceptions are retained
as observable `start_failures` and `startup_uncertain` state. No audit thread is
started at import or when no sink is configured. `submit()` never starts,
restarts, joins, or waits for the audit dispatcher, and startup never holds the
queue lock. A delayed dispatcher bootstrap cannot extend submit latency.

A broker and its `for_new_cycle()` descendants share that single dispatcher and
a pending queue bounded by `audit_capacity` (clamped to 1–4096), plus at most one
record executing in the sink. New cycles only register weak ownership; they do
not start another thread. An idle dispatcher remains available while any broker
in its family exists. After every family owner is garbage collected, the worker
drains accepted records and exits after observing the empty owner set (checked
at most every 0.1 seconds while idle). Weak ownership never retains a broker,
and a live parent necessarily remains an owner while creating a descendant.
A hung sink retains its sole worker until it returns. `close()` cancels the
reasoning cycle without waiting for or discarding audit delivery; a closed
broker can still audit typed refusals.

Results include `audit_sink_queued`, `audit_sink_full`, or
`audit_sink_startup_uncertain` (`audit_sink_record_failed` if fallback recording
also fails). Saturation drops the newest sink admission without changing
capability status, data, or provenance; sanitized local history remains bounded.
`audit_delivery_stats()` reports shared `accepted`, `delivered`, `failed`,
`dropped`, `pending`, `capacity`, `worker_running`, `worker_reserved`,
`startup_uncertain`, `start_attempts`, and `start_failures`, plus per-cycle
`local_evicted`. `worker_running` means the dispatcher is processing a record;
an idle dispatcher still holds `worker_reserved`. Sink exceptions increment
`failed`. Failed/dropped deliveries are not retried; queued is not a durability
acknowledgement. Handler timeout bounds handler waiting; validation,
sanitization and scheduling still add overhead.

An ambiguous startup failure retains its exact reservation permanently until
that worker runs. Further submissions may fill the bounded queue but cannot
start another dispatcher. If no thread was actually launched, that family's
audit delivery remains stalled permanently. No `ident`/`is_alive` observation
is used to infer that a delayed bootstrap cannot run. There is no process-exit
flush guarantee; products requiring durable audit persistence must monitor the
counters and own persistence. Independently constructed families each own one
reservation; applications should reuse a broker family across reasoning cycles.

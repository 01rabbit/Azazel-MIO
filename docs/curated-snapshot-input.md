# Curated snapshot input provenance, internal API v1

`azazel_mio.snapshot_input` receives immutable, bounded internal projections from
the Knowledge-owned offline adapter. It imports no Knowledge/Edge/Nexus/Fabric
modules, parses no private store/wire records, and performs no network or file I/O.
Knowledge owns read-only export, canonical snapshot validation, trusted content
origin/digest pinning, current SourceAdmission, purpose/scope/privacy checks and
current revocations. Fabric owns the descriptive shared snapshot contract.

## Internal boundary

The adapter constructs `ConsumedSnapshotInput` with consumption receipt identity,
source/generation, snapshot as-of and expiry, tenant/privacy, current validation
and revocation versions, source references/counts and metadata identity. Its
`SnapshotSourceBinding` records the learning-relevant source policy projection;
`SnapshotRecordBinding` binds an actual source record to the product-verified
frame, incident/entity/boot/generation/time and correlation evidence. The adapter
also supplies a separate current `SnapshotInputContext` (tenant/privacy, check
time, revocation version and revoked references). A receipt alone is insufficient.

`metadata_canonical_json` is bounded opaque identity material. MIO only checks its
UTF-8 SHA-256 against `metadata_digest`; it does not interpret the private admission
JSON. The Knowledge adapter owns deriving source bindings from those validated
admissions. Frame identity uses Knowledge's raw UTF-8/non-ASCII-escaped SHA-256,
not the ASCII-escaped `sha256:` learning-manifest digest. Source payload digests
and trusted frame context association remain the product adapter's responsibility.
These hashes and projections do not authenticate a caller or prove observation
truth, source honesty, independent labels, holdout quality or product admission.

`evaluate(..., snapshot_inputs=(input,), snapshot_context=context)` checks:

- current tenant/privacy/check time/revocation version and revoked snapshot,
  source and record references, including the older `revoked_snapshots` input;
- snapshot/content-ID binding, metadata digest material, source validity windows,
  closed feature/label versions, bounded counts and unique source/record mappings;
- each actual example's snapshot/generation/as-of/expiry/rights/rights-reference/
  lineage and its incident/entity groups against the source projection;
- actual validated frame identity, source-observation/frame/snapshot time order,
  and correlation evidence membership in both the frame and direct evidence.

A curated example without a matching accepted input is quarantined. The standalone
fixture-fitting helper cannot bypass this evaluation path for curated rows. The
existing default baseline and all teacher/reviewer/outcome, split, deduplication,
expiry, revocation and artifact compatibility gates remain in force.

## Connection is separate from eligibility

`knowledge_curated_snapshot_connected` is derived from consistent record inputs
actually passed to evaluation. It cannot be enabled with a boolean or a current
context alone. Reports retain snapshot/source identity and bounded rejection and
frame-quarantine reasons in `snapshot_input_provenance`; the opaque admission JSON
is not copied into reports. No network/live-service claim follows from this flag.

The existing Knowledge observation has no current defensive state. Without a
product-verified `trusted_frames[record_ref]` context, the adapter supplies an
explicit quarantined input and `missing_frame_context` binding. MIO records that
limited input coverage, passes it through its malformed-example gate and does not
construct a frame, add UNKNOWN to the existing five states, or invent OBSERVE.
Such a snapshot can be connected as input while supplying zero usable examples.

Valid frames with missing review, unknown groups or missing independent outcomes
also remain ineligible under the existing gates. `curated_training_eligible_examples`
counts only accepted, bound training-partition rows with training rights;
`curated_reviewed_label_count` and
`curated_independent_outcome_labels_available` derive from actual accepted
review/outcome records. A receipt's independent-label boolean is not an input to
those decisions. Source policy cannot be expanded by a receipt.

Even a fully labelled synthetic projection produces only an evaluation-only
artifact and retains `select_playbook` as the default/top-level choice.
`real_world_holdout_verified` remains false; calibration and target process RSS
remain unknown. Knowledge's actual optional bridge tests are a separate scope
from MIO's synthetic typed-projection tests and from production ingestion/process
checks. Input interoperability is not completion of the learning Goal.

## Immutable learning semantics and consumption context (FL-01)

Source/frame correspondence alone does not authorize later labels. Each bound
record now carries `learning_payload_digest`, computed by
`learning_payload_digest(example)` over the entire closed LearningExample,
including direct facts/evidence, feature origins, teacher candidate, reviewer,
observed outcome, labels and all identity/lineage fields. Absence of annotations
is itself bound. No learning field may be appended under that same binding.

The separate current `SnapshotInputContext.consumption_bindings` pins each
snapshot ID to `consumed_projection_digest(input)`, which covers the complete
consumption projection, including those semantic digests. A caller that changes
an example and recomputes its record digest still disagrees with the original
frozen context. The projection digest identifies a consumption receipt distinct
from the source snapshot's content ID.

The product boundary must create these digests only from its source-validated
original projection and independently retain the current context pin. Hashing a
new untrusted payload does not authenticate annotations and cannot repin an old
context. Legitimate later human review requires separately authenticated,
versioned annotation provenance and a new producer-issued receipt/context. The
current Knowledge bridge has no such annotation input: it still emits unlabeled
observations. Synthetic tests of a separately minted projection are not evidence
of a real annotation authority or real-world labels.

For constructor compatibility, old producers may omit the new digests/pins. Such
inputs can still demonstrate source/frame connection coverage, but their learning
semantics are quarantined as `snapshot_learning_semantics_unbound`; they cannot
count as curated reviewed/independent labels or train an artifact. Reports expose
`learning_projection_pinned`, `learning_bound_examples`, semantic rejection codes
and consumption projection identity separately from source connection. Neither
kind of digest is a signature, truth guarantee, holdout proof or product admission.

Outcome records also bind the practice record reference, exact example ID,
frame digest and frame evidence context. Reviewer evidence for an
independent-outcome label must be drawn from that outcome's bound evidence.
The current Knowledge bridge does not export reviewed practice outcomes; it
emits no outcome or reviewer annotation, so current curated observations cannot
train a candidate. Any future producer must derive these bindings from
independently validated practice records and pin them in a new consumption
context. Supplying IDs or evidence strings alone is insufficient.

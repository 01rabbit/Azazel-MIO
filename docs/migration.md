# Public Edge core extraction

Source: 01rabbit/Azazel-Edge commit
`47c880b2503d7f771bbdacba9b6205dafe03c4c7`, `py/azazel_edge/mio/`.
The broker, contracts, scoring, frame builder, grounding, handoff, ID grammar,
lifecycle, playbooks, reasoning, redaction, replay, trace and claim audit moved
without semantic redesign. Edge keeps import aliases, governance/model transport,
OS trace persistence/export, evaluation and resource measurement tooling.

The source is public MIT-licensed code. LICENSE preserves the original
`Copyright (c) 2026 Azazel-Edge contributors` and full permission notice.
New assistant composition, packaging and regression tests are adaptations of this
public MIT core under the same license and contributor notice; no private Nexus
or Knowledge source was copied. This is an inherited license, not a new license
selection for unrelated private material.

Ownership decision: common cognitive semantics now belong to Azazel-MIO. Edge
continues to own observations, deterministic decisions and enforcement. Nexus
owns product lifecycle and its adapters. Fabric owns shared wire contracts.

The schema owner constant changes from `azazel_edge.mio.contracts` to
`azazel_mio.contracts`. This is Python ownership metadata, outside the v2 wire
field set and canonical frame bytes; old imports return the same shared module.
All fixture/golden and replay tests still apply. Import-time process-local entropy
keys in broker/reasoning are now created lazily at first actual audit/error use,
so merely importing the library does not request randomness or start work.

## Prompt and adapter compatibility

Prompt template version `1.5.0` changes the structured output for
`generate_hypotheses` and `update_hypotheses`. For every multi-prompt playbook, adapters must return at
least two hypotheses with distinct `hypothesis_alternative_id` values from the
trusted playbook's enum, including at least one slot assigned the trusted role
`benign` or `unresolved`. The schema advertises `minItems: 2` and the slot enum.
This validates slot diversity only; it does not establish that statement prose
semantically matches a slot. Prose remains model-proposed and unverified, and a
slot role is never treated as evidence, fact, or authority. This is a compatibility
change for adapters that do not return the new field or use distinct trusted IDs.
Custom playbooks must define one unique slot per prompt and at least one benign
or unresolved role.
Stable hypothesis IDs must keep their original slot. The selected ID appears in
Assistance and a trace event marked `model_proposed_unverified`; the trace also
shows its `proposed_role` with that same verification status. Invalid selections
follow the existing deterministic no-model handoff path.


## Compatibility and rollout matrix

This matrix records claims at the 2026-11-02 [inventory cut](architecture/ai-inventory.md). The project direction assigns common assistance semantics to MIO; it does not assert a consumer switch or another product owner's acceptance.

| Product / common-core combination | Compatibility claim | Evidence and remaining gate |
| --- | --- | --- |
| Existing product paths / MIO main `6302e665c3ac6cf7004407965299d81dc9ddfc8a` | Existing product operation does not require assuming PR #15 API availability. | Main is a foundation baseline; no migration completion claim. |
| Legacy Edge imports / extracted shared core | Historical aliases and unchanged frame-v2 bytes are the intended seam. | Original extraction fixtures/replay apply to their source versions; validate installed aliases, packaging and golden records for the actual release pair. |
| Edge #525 `e4c0661dcfd0f3835d174292756e2cff7a1b84fa` / MIO #15 `26a5046dd493a3587f0b03dbc574211ff781d1d1` | Optional auxiliary/model lanes; deterministic Edge decisions retain authority. | Source inspection only for this exact pair in this docs update. Edge current-head CI fails module-installer coverage. No exact-pair release, HIL or production claim. |
| Nexus #398 `c90deb865735e1e53fac86d2a49b53753caf82c8` / MIO #15 | Shared fast assistance candidate; product inference remains separate. | Earlier local base `3e6170e` and fixture-based test results are historical, not exact-head certification. Current exact-pair process, admission/resource and rollout evidence remains to be attached. |
| Product old adapter / new prompt `1.5.0` | Adapters missing distinct trusted alternative IDs are incompatible with the structured multi-prompt requirement above. | Reject invalid output and degrade explicitly; do not silently interpret old output as the new schema. |
| Product adapter / MIO #16–#18 stack | Feedback, citations and ContextResponse are candidate additions; availability must be feature/version checked. | Validate the selected wheel/head with the consumer. A #18 projection test is not live producer or model integration. |
| Refreshed local Edge stack / newer MIO candidates | Local-only candidate combinations, not public current PR heads. | Keep tests tied to their exact candidate hashes; do not transfer them to public PRs or main. |
| Missing MIO/model/Knowledge | Explicit unavailable/unknown/static guidance; Edge deterministic path remains independent. | Degraded-path tests apply only to their tested source combinations; unproven external/HG/admission gates remain open. |

This documentation-only refresh ran no tests and changes no code or contracts. Historical fixture, unit, replay, process and single-event smoke results are not interchangeable with current-head CI, live authenticated Knowledge, HIL or production evidence. Verified operational training labels and the shared separate-time Knowledge-to-LLM path remain unavailable; migration must not imply either exists. Each rollout still needs product acceptance, exact installed-version/packaging checks, canonical-frame/replay compatibility, cancellation/stale-result behavior and the applicable admission/resource/egress gates.

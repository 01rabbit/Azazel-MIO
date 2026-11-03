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

This matrix records claims at the 2026-11-03 [inventory cut](architecture/ai-inventory.md). The project direction assigns common assistance semantics to MIO; it does not assert a consumer switch or another product owner's acceptance.

| Product / common-core combination | Compatibility claim | Evidence and remaining gate |
| --- | --- | --- |
| Existing product paths / MIO main `3cdfe4c5643161bc260471e7085d1eb6b44a6fe2` | Main includes merged #15–#23, #25, #26, #28, #30, #32, #34 and #35, including bounded advisory APIs, offline learning validation, fast assessment and scorer parity coverage. | Library availability does not establish an installed consumer switch or migration completion. |
| Legacy Edge imports / extracted shared core | Historical aliases and unchanged frame-v2 bytes are the intended seam. | Original extraction fixtures/replay apply to their source versions; validate installed aliases, packaging and golden records for the actual release pair. |
| Edge #525 `80445737f2ae6df2cae3bcdd7e79176352dffe24` / MIO #21 merge `9fedb01bc9936531407a5181aa8fa5553ec19d55` | Draft/unmerged optional auxiliary/model lanes; deterministic Edge decisions retain authority. `requirements/runtime.txt` at the cited Edge head still pins this MIO merge/source commit. | Source/pin inspection only for this exact pair in this docs update; no exact-pair tests run or certification claimed. [Exact-head CI](https://github.com/01rabbit/Azazel-Edge/actions/runs/41455849678) has 8 successes and 3 skips (SO-02, SO-11 and Dependency review). The earlier installer failure was at old head `0534ed0`. No release, HIL or production claim. |
| Product old adapter / new prompt `1.5.0` | Adapters missing distinct trusted alternative IDs are incompatible with the structured multi-prompt requirement above. | Reject invalid output and degrade explicitly; do not silently interpret old output as the new schema. |
| Product adapter / MIO #16–#18 stack | Feedback, citations and ContextResponse are merged additions; installed availability must be feature/version checked. | Validate the selected wheel/head with the consumer. A #18 projection test is not live producer or model integration. |
| Edge #532 `a1775f61208156886bf3c2f75ef9bc2fa5c62cd7` / base Edge #525 `80445737f2ae6df2cae3bcdd7e79176352dffe24` | Open/draft Knowledge lane candidate based on #525; no merged consumer switch. | At this exact head, the focused CPython 3.14.7 command `PYTHONPATH=<MIO-source-at-merge-37fbdb1>/src:.:py python -m pytest -q -rs -p no:cacheprovider tests/test_knowledge_slow_lane.py tests/test_knowledge_receipt_operator.py tests/test_dashboard_data_contract.py tests/test_issue477_config_mismatch_v1.py` recorded 334 passed and 1 skipped; the MIO source was `37fbdb1e6b076400c79a90235c56822d45977c56`, and the skip required local Knowledge/Fabric source exports that were unavailable. [The PR body records this command and result](https://github.com/01rabbit/Azazel-Edge/pull/532). GitHub checks are empty because the PR targets a non-main base. Local evidence does not establish passing CI, release, HIL or production operation. Edge #526–#531 and #533 are closed; their branch refs remain. |
| Missing MIO/model/Knowledge | Explicit unavailable/unknown/static guidance; Edge deterministic path remains independent. | Degraded-path tests apply only to their tested source combinations; unproven external/HG/admission gates remain open. |

Edge #525's committed MIO pin is older than current MIO main `3cdfe4c5643161bc260471e7085d1eb6b44a6fe2`; its current PR head, pin, and CI status are listed in the inventory. MIO #24 is an offline IR adapter only, not product runtime adoption. Nexus implementation details are maintained privately and are not part of this public evidence; full-node and admitted-model behavior remain unverified. No consumer repin is inferred from the MIO merges.

This documentation-only refresh changes no code or contracts. Local Markdown link/anchor checks validate documentation references only; historical full Python 3.12 suite results do not validate this refreshed tree or certify the product pairs above. Historical fixture, unit, replay, process and single-event smoke results are not interchangeable with current-head CI, live authenticated Knowledge, HIL or production evidence. Verified operational training labels and the shared separate-time Knowledge-to-LLM path remain unavailable; migration must not imply either exists. Each rollout still needs product acceptance, exact installed-version/packaging checks, canonical-frame/replay compatibility, cancellation/stale-result behavior and the applicable admission/resource/egress gates.

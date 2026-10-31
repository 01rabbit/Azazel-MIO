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

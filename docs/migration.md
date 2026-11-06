# Public Edge core extraction

## Current integration status (2026-11-06)

MIO main is `57464216a08456d1b97ef292f7558c21b0ff0b34` (README #46 merged).
MIO #47 remains an unmerged candidate at
`a1807bf7abb08788b834ae038f7a8b46d09d0acc`, version
`0.1.0.dev20261106+gitbb6dcfd`. Its implementation label `bb6dcfd` is separate
from the consumer source pin `a1807bf`; see [artifact identity](versioning.md#current-candidate-artifact-2026-11-06).
Edge main `3e6ccf4d3cffdf0d101c69392c3f7a9cc1a65f0c` still pins MIO
`9fedb01bc9936531407a5181aa8fa5553ec19d55`. Edge #538 at
`df98300f08a294f33482ef13579192447c9d0ac0` and Nexus #405 at
`28900ebec35acdb618776340bfdc3065725d12bf` are unmerged candidates pinning
MIO `a1807bf7abb08788b834ae038f7a8b46d09d0acc`; neither changes its product's
main dependency. Edge #538 acceptance checks the exact VCS source and package
version, including installed `direct_url.json` provenance and the actual build
record; it does not require canonical wheel byte equality. Nexus #405's
offline lock additionally requires the exact canonical wheel SHA-256 recorded
in the artifact identity reference above. Source/version acceptance and exact
artifact acceptance are distinct; version alone does not satisfy either.
Fabric stable is `v0.10.0`; Edge, Knowledge, Deception and
Nexus's optional `fabric` extra declare it, while Gadget remains on `v0.9.0`.
Fabric Knowledge Context v1 is experimental (integrated by #86).
Nexus #402/#403 are merged software integrations; the Context broker remains
default-disabled and uncommissioned. Knowledge #116, MIO #47 and Nexus #405
remain unmerged. These source observations establish no production model
admission, HG acceptance, live full-node commissioning, release or deployment.

## Historical source evidence (through 2026-11-04)

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

This matrix records claims at the 2026-11-03 [inventory cut](architecture/ai-inventory.md), with public-source updates checked on 2026-11-04 below. The project direction assigns common assistance semantics to MIO; it does not assert a consumer switch or another product owner's acceptance.

| Product / common-core combination | Compatibility claim | Evidence and remaining gate |
| --- | --- | --- |
| Existing product paths / MIO main `3cdfe4c5643161bc260471e7085d1eb6b44a6fe2` | Main includes merged #15–#23, #25, #26, #28, #30, #32, #34 and #35, including bounded advisory APIs, offline learning validation, fast assessment and scorer parity coverage. | Library availability does not establish an installed consumer switch or migration completion. |
| As of 2026-11-04, MIO integration build / main at PR #42's base `5bb09c8d28c57604dc1c63903b98fed7587b49ea` (tree `75b20e000a0be2dad1c9aae3219e5cf5f14700bf`; earlier main `4d2fd786` after #43 and `4d92b445` after #39 are historical) | PR #41 source head `b441d431532507387fb81f1e03e31fd1aea57b68` and merge `e4a0e504bae91153f3dcb8105f8658ff80d4e884` have source tree `f879a97422f14aeca0c6cee75e97cb4b5268a747`; docs-only PR #39 advanced main to 4d92 without changing `pyproject.toml`, `src/`, or `tests/`. Package metadata remains `0.1.0+git.c31c244`. PR #43 adds defensive-state metadata validation; #44 adds a local-model developer smoke tool; #45 adds a bounded measured transport wrapper. These are not part of the older `b441`/`e4a0` Edge pin or process run. | The local version suffix is an artifact label, not the source commit. Record source commit/tree, reproducible build inputs and artifact hash in the consuming lock/verification record; this inventory is not a release or artifact publication. |
| Legacy Edge imports / extracted shared core | Historical aliases and unchanged frame-v2 bytes are the intended seam. | Original extraction fixtures/replay apply to their source versions; validate installed aliases, packaging and golden records for the actual release pair. |
| As of 2026-11-04, Edge #525 final head `2d95d52a19f63f3b20a66852e777bf52b7fd051d` / MIO #21 merge `9fedb01bc9936531407a5181aa8fa5553ec19d55` | Merged 2026-11-03 as `6801d838f1c1d9d018e7bc074ce897fc6aa11dd1`; optional auxiliary/model lanes, while deterministic Edge decisions retain authority. Current Edge main `38c2b07774c61b86209d0cd94ce2e7689d38600c` still pins MIO `9fedb01` in `requirements/runtime.txt`. | Exact final-head CI run [41557996408](https://github.com/01rabbit/Azazel-Edge/actions/runs/41557996408) succeeded with 8 successful jobs and 3 skips (SO-02, SO-11 and Dependency review). This CI result is not an installed-artifact or product acceptance claim. No release, HIL or production claim. |
| Product old adapter / new prompt `1.5.0` | Adapters missing distinct trusted alternative IDs are incompatible with the structured multi-prompt requirement above. | Reject invalid output and degrade explicitly; do not silently interpret old output as the new schema. |
| Product adapter / MIO #16–#18 stack | Feedback, citations and ContextResponse are merged additions; installed availability must be feature/version checked. | Validate the selected wheel/head with the consumer. A #18 projection test is not live producer or model integration. |
| As of 2026-11-04, Edge #532 final head `7c3e5ed45fa8fd2c30049200cd3fcc36765a6c40` / base Edge #525 | Merged 2026-11-03 as `d5952e0d7c2dc5d6fbb506cf177dbe824ae70f4e`; Knowledge analysis lane candidate is now part of Edge main. | Final-head CI run [41566141766](https://github.com/01rabbit/Azazel-Edge/actions/runs/41566141766) succeeded with 8 successful jobs and 3 skips (SO-02, SO-11 and Dependency review). The PR body reports a pre-merge focused CPython 3.14.7 run of 334 passed and 1 skipped; this documentation refresh did not reproduce it. No release, HIL or production claim. At the 2026-11-03 evidence cut, Edge #526–#531 and #533 were closed; their branch refs remained. |
| As of 2026-11-04, Edge #537 / #538 Drafts | #537 proposes Fabric `v0.9.0rc5`; #538 is OPEN/Draft at head `b271da358b8a58661308cbab80ae938ee7c193ee` (base `38c2b07774c61b86209d0cd94ce2e7689d38600c`) and names MIO main `5bb09c8d28c57604dc1c63903b98fed7587b49ea` (tree `75b20e000a0be2dad1c9aae3219e5cf5f14700bf`) as its candidate dependency; its earlier head `04efcd5` proposed `b441d431532507387fb81f1e03e31fd1aea57b68`. Both remain unmerged and do not change Edge main. | At Edge main `38c2b07774c61b86209d0cd94ce2e7689d38600c`, runtime still pins MIO `9fedb01bc9936531407a5181aa8fa5553ec19d55`. The Draft candidates are not installed-release evidence. Exact candidate CI run [41782621952](https://github.com/01rabbit/Azazel-Edge/actions/runs/41782621952) succeeded with eight executed jobs; the [Python tests job](https://github.com/01rabbit/Azazel-Edge/actions/runs/41782621952/job/126417451920) reports 18,250 passed, 82 skipped and 230 subtests. Dependency Review, SO-02 and SO-11 were workflow skips; pytest skip reasons are unavailable, and CI did not run the task-local process harness. The separate [MIO #1 process-evidence comment](https://github.com/01rabbit/Azazel-MIO/issues/1#issuecomment-6624081713) at `b271da3` is synthetic source-level software evidence only. Earlier-head records (`04efcd5` CI run [41760314464](https://github.com/01rabbit/Azazel-Edge/actions/runs/41760314464); local harness at `3e71c61b4ab01880fe002e1421e0a07c5f53a10c`) are historical. See the [AI inventory](architecture/ai-inventory.md). |
| Knowledge full-node service / Knowledge Lite bundle | Full-node API behavior and Lite-bundle use are different compatibility claims. | Public Knowledge source documents both profiles; this MIO inventory does not establish a current product integration for either. Confirm transport/authenticity/freshness/privacy and lifecycle before declaring either pairing interoperable. |
| Missing MIO/model/Knowledge | Explicit unavailable/unknown/static guidance; Edge deterministic path remains independent. | Degraded-path tests apply only to their tested source combinations; unproven external/hostile-load (HG)/admission gates remain open. |

As of 2026-11-04, Edge #525 and #532 are merged. At Edge main `38c2b07774c61b86209d0cd94ce2e7689d38600c`, the runtime pin remains MIO `9fedb01bc9936531407a5181aa8fa5553ec19d55`, older than MIO main at PR #42's base `5bb09c8d28c57604dc1c63903b98fed7587b49ea`; Draft #538 names that MIO main commit as its candidate dependency (its earlier `04efcd5` head proposed `b441d431532507387fb81f1e03e31fd1aea57b68`) but is not part of Edge main. The `b271da3` candidate process run used MIO tree `75b20e0` (which includes merged MIO PRs #43–#45), but does not claim isolated coverage of each of those PRs; it used Fabric main rather than #537's proposed `v0.9.0rc5`. The earlier `b441d431`/`e4a0e504` process run predates MIO #43–#45. A synthetic normal-event smoke for Edge/MIO source `38c2` / `9fedb01` is recorded in [MIO #1](https://github.com/01rabbit/Azazel-MIO/issues/1#issuecomment-6608772543); it is not a broad parity corpus or installed deployment proof. MIO #24 is an offline IR adapter only, not product runtime adoption. Nexus implementation details are maintained privately and are not part of this public evidence; full-node and admitted-model behavior are not claimed here. No consumer repin is inferred from the MIO merges.

This documentation-only refresh changes no code or contracts. Local Markdown link/anchor checks validate documentation references only; historical full Python 3.12 suite results do not validate this refreshed tree or certify the product pairs above. Historical fixture, unit, replay, process and single-event smoke results are not interchangeable with current-head CI, live authenticated Knowledge, HIL or production evidence. Verified operational training labels remain unavailable. The shared separate-time Knowledge-to-LLM path is not established on MIO or Edge main; the local, uncommitted #538 candidate harness exercised an Edge process route on synthetic input only and does not make that path available to any consumer. The separate Nexus full-node Knowledge path is not proven and remains contract-gated. Migration must not imply that any of these exists in main or production. Each rollout still needs product acceptance, exact installed-version/packaging checks, canonical-frame/replay compatibility, cancellation/stale-result behavior and the applicable admission/resource/egress gates.

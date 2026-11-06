# ADR: Ownership boundaries for M.I.O.

## Current integration status (2026-11-06)

MIO main is `57464216a08456d1b97ef292f7558c21b0ff0b34` (README #46 merged).
MIO #47 remains an unmerged candidate at
`a1807bf7abb08788b834ae038f7a8b46d09d0acc`, version
`0.1.0.dev20261106+gitbb6dcfd`. Its implementation label `bb6dcfd` is separate
from the consumer source pin `a1807bf`; see [artifact identity](../versioning.md#current-candidate-artifact-2026-11-06).
Edge main `3e6ccf4d3cffdf0d101c69392c3f7a9cc1a65f0c` still pins MIO
`9fedb01bc9936531407a5181aa8fa5553ec19d55`. Edge #538 at
`df98300f08a294f33482ef13579192447c9d0ac0` and Nexus #405 at
`28900ebec35acdb618776340bfdc3065725d12bf` are unmerged candidates pinning
MIO `a1807bf7abb08788b834ae038f7a8b46d09d0acc`; neither changes its product's
main dependency. Fabric stable is `v0.10.0`; Edge, Knowledge, Deception and
Nexus's optional `fabric` extra declare it, while Gadget remains on `v0.9.0`.
Fabric Knowledge Context v1 is experimental (integrated by #86).
Nexus #402/#403 are merged software integrations; the Context broker remains
default-disabled and uncommissioned. Knowledge #116, MIO #47 and Nexus #405
remain unmerged. These source observations establish no production model
admission, HG acceptance, live full-node commissioning, release or deployment.

## Historical source evidence (through 2026-11-04)

**Status:** Project-owner direction recorded; cross-product adoption and contract acceptance pending.
**Decision date:** 2026-10-31; direction/evidence refresh 2026-11-03 and 2026-11-04

The project owner's explicit goal is to make MIO the source of truth for common AI assistance. This records that direction, not consent from Edge, Nexus, Knowledge, Fabric, or Deception owners, and not a completed migration. Product-specific acceptance, rollout, and wire-contract decisions remain pending. The historical evidence base is MIO `main` `3cdfe4c5643161bc260471e7085d1eb6b44a6fe2`, including merged PRs #15–#23, #25, #26, #28, #30, #32, #34 and #35. MIO PR #41 merged source head `b441d431532507387fb81f1e03e31fd1aea57b68` as `e4a0e504bae91153f3dcb8105f8658ff80d4e884`; docs-only PR #39 later advanced main to `4d92b4451a3bf1ec44eb7215ebadb0fd05879c1d`; subsequent main advances included #43 (`4d2fd786`) and #44–#45, yielding the PR #42 base main `5bb09c8d28c57604dc1c63903b98fed7587b49ea` (tree `75b20e000a0be2dad1c9aae3219e5cf5f14700bf`). PR #43 adds defensive-state metadata validation, #44 adds an opt-in local-model developer smoke tool, and #45 adds a measured transport wrapper; these do not change package version or dependency pins. The package metadata remains local version `0.1.0+git.c31c244`; consult the [versioning policy](../versioning.md) and consumer lock for source/build/artifact identity rather than interpreting that suffix as the main SHA. The [inventory](ai-inventory.md) records public source heads and merge commits; merged library capability does not establish product adoption. MIO #11, #24, #27, #29, #31, #33 and #36 remain open/draft at the 2026-11-03 evidence cut; #24 is an offline IR adapter only. Nexus implementation details are maintained privately and are not part of this public evidence.

## Context and decision

Azazel products need shared, evidence-aware assistance without giving a model authority over enforcement or embedding product lifecycle assumptions in a common reasoning library. M.I.O. owns product-neutral cognition and explanation: bounded interpretation of accepted observations, hypothesis and unknown representation, evidence-linked explanation, read-only information requests, handoff content, model abstraction, and behavioral evaluation. M.I.O. does not own product authorization, process supervision, persistence, transport, model deployment, or actuation.

| Component | Owns | Explicitly does not own |
| --- | --- | --- |
| **Azazel-MIO** | Shared cognition and explanation semantics, bounded context composition, model-independent behavior, model adapter interface, handoff shape, evaluation semantics | Product authorization, observation collection, process supervision, durable product audit sinks, enforcement, shared wire protocol |
| **Azazel-Edge** | Observation, deterministic judgment, enforcement, expiry and rollback; record of actual applied result | Common cognition authority or model-driven controls |
| **Azazel-Nexus** | Product admission, runtime/model selection and supervision, resource measurement, service integration and operator entry | Replacing Edge judgment or common cognition semantics |
| **Azazel-Knowledge** | Sourced facts/context, ingestion, provenance/trust assessment, validation, storage, search and delivery | M.I.O. conclusions or product authorization |
| **Azazel-Fabric** | Cross-product wire schemas and compatibility/version policy | Internal M.I.O. Python API or reasoning policy |
| **Azazel-Deception** | Approved decoy execution, isolation, exposure control and observation collection | M.I.O. decisions to launch or expose a runtime |

Edge remains the deterministic decision and enforcement authority. M.I.O. may explain an Edge result or suggest a check; only Edge's authorized deterministic path decides and applies controls. Nexus owns host lifecycle and operator entry. Knowledge content and model output are data, not authority. Deception actions require their approved product control path; an AI hypothesis cannot launch or expose a decoy.

## Candidate routes and migration boundaries

The [AI inventory](ai-inventory.md) records exact public merged MIO heads, public product candidate heads and remaining public product callsites; the [migration matrix](../migration.md#compatibility-and-rollout-matrix) records supported claims and unproven combinations. Shared semantics belong in MIO under the project direction; moving those semantics does not move Edge's immediate deterministic decisions/enforcement, Nexus lifecycle/admission/operator entry, Knowledge provenance, or Fabric wire contracts.

Edge still contains legacy product model paths. Its optional PR #525 auxiliary path calls the shared core without a model; its separate model/Knowledge work is not evidence that all product assistance has migrated. At the 2026-11-03 evidence cut, public Edge PRs #525 and #532 were open/draft, with #532 based on #525. Both merged on 2026-11-03: #525 as `6801d838f1c1d9d018e7bc074ce897fc6aa11dd1` (final head `2d95d52a19f63f3b20a66852e777bf52b7fd051d`) and #532 as `d5952e0d7c2dc5d6fbb506cf177dbe824ae70f4e` (final head `7c3e5ed45fa8fd2c30049200cd3fcc36765a6c40`). Edge main `38c2b07774c61b86209d0cd94ce2e7689d38600c` still pins MIO `9fedb01bc9936531407a5181aa8fa5553ec19d55`; Draft #538 (current head `b271da3`) names MIO main `5bb09c8d28c57604dc1c63903b98fed7587b49ea` as its candidate dependency (its earlier head proposed `b441d431532507387fb81f1e03e31fd1aea57b68`) but is not merged. Draft #537 proposes Fabric `v0.9.0rc5`. The [inventory](ai-inventory.md) records these public states and evidence limits. Edge #526–#531 and #533 are closed, with branch refs retained. Nexus full-node and admitted-model behavior remain unverified; Nexus implementation details are maintained privately and are not part of this public evidence. Knowledge full-node service interoperability and Knowledge Lite bundle use are separate claims; neither is asserted here as a current product deployment. A common separate-time Knowledge-to-LLM reasoning path has not been established.

Keep the MIO internal Python API (`docs/api-v1.md`) separate from Fabric wire contracts. Product adapters translate at the boundary. Preserve frame v2 canonical bytes and replay behavior when changing Python ownership metadata; compatibility requires verification for each release combination. Extraction or import aliases alone do not prove a deployed consumer switch.

## Safety and rollout constraints

- Keep observed facts, Knowledge reports, model hypotheses, Edge decisions and applied outcomes separately labeled and linked to provenance.
- Missing, rejected, stale, cancelled or timed-out model/Knowledge inputs must degrade to explicit unknowns or static guidance; they must not block Edge's deterministic path.
- Product adapters provide trusted time, identifiers, authentication, authorization, cancellation/supersession, egress policy and persistence. Model output cannot choose trusted playbooks or identifiers.
- MIO requests remain bounded and read-only. No control, permission change, deception launch/exposure, or arbitrary command is an MIO operation.
- External model egress requires product consent, data classification/minimization, destination approval and a budget. No default remote egress is implied.
- Treat unit/replay, process integration, VM, HIL and production evidence as distinct claims.

## Review required

Product owners must confirm the Edge and Nexus adapter seams, Knowledge trust/generation and revocation contract, REST-to-Fabric mapping/version policy, and Deception approved-control flow before cross-product contracts and rollout are accepted. The project-owner direction above does not supply those approvals. Tracking references: MIO #1, #2, #12, #14; Edge #524; Knowledge #111; Fabric #72. This ADR remains proposed and does not assert completed integration.

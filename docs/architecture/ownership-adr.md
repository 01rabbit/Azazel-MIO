# ADR: Ownership boundaries for M.I.O.

**Status:** Project-owner direction recorded; cross-product adoption and contract acceptance pending.
**Decision date:** 2026-10-31; direction/evidence refresh 2026-11-02

The project owner's explicit goal is to make MIO the source of truth for common AI assistance. This records that direction, not consent from Edge, Nexus, Knowledge, Fabric, or Deception owners, and not a completed migration. Product-specific acceptance, rollout, and wire-contract decisions remain pending. The evidence base is MIO `main` `1aaddd76b40cc049f662e990a49e994b7be8636b`, including merged PRs #15, #17, #18, #16, #19 (ownership/inventory documentation), #21 (bounded validation diagnostics) and #20 (tests-only learning-input integrity coverage). The [inventory](ai-inventory.md) records their final heads and merge commits; merged library capability does not establish product adoption. MIO #11 and #22 remain open/draft. This follow-up documentation candidate is local and not merged.

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

Edge still contains legacy product model paths. Its optional PR #525 auxiliary path calls the shared core without a model; its separate model/Knowledge work and refreshed local stack are not evidence that all product assistance has migrated. Edge #525–#530 remain open/draft; #525 current-head CI has two installer-coverage failures. The private consumer integration remains stacked/draft, and full-node, Lite and model end-to-end proof is not complete. A common separate-time Knowledge-to-LLM reasoning path has not been established.

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

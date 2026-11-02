# ADR: Ownership boundaries for M.I.O.

**Status:** Proposed; owner agreement and product migration are not established.
**Decision date:** 2026-10-31

**Evidence update (2026-11-01):** Current Edge and Nexus working candidates now contain the routes summarized in [the AI inventory](ai-inventory.md). This updates candidate evidence only. It does not establish main/release adoption, product-owner agreement, HIL, or production operation.

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

| Area | Current candidate evidence | Compatibility and limit |
| --- | --- | --- |
| Edge shared assistance | Edge candidate asynchronously routes a bounded event through `py/azazel_edge_ai/mio_live_auxiliary.py` to `AssistantCore`; the optional model lane is separate in `py/azazel_edge_ai/agent.py`. One local-only `qwen3.5:0.8b` smoke passed for one event. | Keep Edge deterministic judgment/enforcement in control. This does not prove HIL, production operation, or an Edge main/release switch. Retain compatibility imports during any staged source migration and verify frame/replay behavior before release. |
| Nexus runtime path | The local Nexus candidate source contains entryd → locald → MIO `AssistantCore` fast assistance in `runtime/src/azazel_nexus_runtime/mio_entryd.py`, `mio_locald.py`, and `mio_fast_assistance.py`. An isolated ARM64/Python 3.12 verification passed 264 shared-wheel tests and one degraded no-wheel real-process test; a post-commit repeat passed the same checks. Independent audit of the candidate tree and logs completed with no discrepancies; there is no public PR head yet. | This verifies the local consumer path with a re-signed test Knowledge fixture, not a live Knowledge producer or full-node interoperability. It is not CI, HIL, mainline, release, or production evidence. Nexus retains admission, launch, runtime health, resource controls and operator presentation. This is not live Edge producer-to-API proof; Nexus main/release adoption is unverified. |
| Knowledge and shared contracts | Nexus candidate provides an authenticated local Knowledge Lite socket/client in `runtime/src/azazel_nexus_runtime/knowledge_lited.py` and `knowledge_client.py`; MIO accepts caller-projected typed Knowledge context. Separately, `mio_referenced.py` serves deterministic, model-free references from verified Mission Pack playbooks, with no Knowledge or MIO model path. | The test bundle is a fixture, not a live Knowledge producer. Approved Knowledge REST authentication/configuration is absent; downstream revocation behavior for MIO-consumed references is unknown. The Mission Pack playbook reference is not a Knowledge deep-reference route. Fabric owns cross-product schemas. REST-to-Fabric mapping/version policy remains undecided. |

Keep the MIO internal Python API (`docs/api-v1.md`) separate from Fabric wire contracts. Product adapters translate at the boundary. Preserve established frame v2 bytes and replay behavior when changing Python ownership metadata; verify compatibility against fixtures/golden records before release. Source extraction and compatibility aliases indicate migration work, not a completed Edge switch.

## Historical evidence superseded by the current candidate cut

An earlier 2026-11-01 review recorded Edge MIO as shadow/replay work, described a failed Qwen 0.8B attempt, and cited an older Nexus route/test status. Those were historical results for that earlier candidate state. The current Edge candidate has the single-event local smoke recorded above; the local Nexus candidate's isolated ARM64/Python 3.12 verification passed 264 shared-wheel tests and one degraded no-wheel real-process test using a re-signed Knowledge fixture, and a post-commit repeat passed the same checks. Independent audit of the candidate tree and logs completed with no discrepancies. The candidate has no public PR head. This newer evidence supersedes earlier status only at local candidate scope. It does not establish live Knowledge producer/full-node interoperability, CI, mainline or release adoption, HIL, or production operation.

## Safety and rollout constraints

- Keep observed facts, Knowledge reports, model hypotheses, Edge decisions and applied outcomes separately labeled and linked to provenance.
- Missing, rejected, stale, cancelled or timed-out model/Knowledge inputs must degrade to explicit unknowns or static guidance; they must not block Edge's deterministic path.
- Product adapters provide trusted time, identifiers, authentication, authorization, cancellation/supersession, egress policy and persistence. Model output cannot choose trusted playbooks or identifiers.
- MIO requests remain bounded and read-only. No control, permission change, deception launch/exposure, or arbitrary command is an MIO operation.
- External model egress requires product consent, data classification/minimization, destination approval and a budget. No default remote egress is implied.
- Treat unit/replay, process integration, VM, HIL and production evidence as distinct claims.

## Review required

Product owners must confirm the Edge and Nexus adapter seams, Knowledge trust/generation and revocation contract, REST-to-Fabric mapping/version policy, and Deception approved-control flow before this ADR is accepted. Tracking references: MIO #1, #2, #12, #14; Edge #524; Nexus #395; Knowledge #111; Fabric #72. This ADR remains proposed and does not assert completed integration.

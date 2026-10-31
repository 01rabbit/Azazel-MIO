# ADR: Ownership boundaries for M.I.O.

**Status:** Proposed; documents intended ownership, not completed product migration.

**Decision date:** 2026-10-31

**Evidence note (2026-11-01):** This remains a proposed ownership boundary. The combined MIO candidate is `65a75834291df47467a1022407eea8b839a5b9f8`; Edge `0ead255d7aee32dcb505f582a1179709487d20a`, Knowledge `b260ac725fea4e3da6ae2d182e7d9d4d8ec87f1c`, and Fabric `76169d1082512384a7a2092e0d989b4847a30bd9` are workspace candidates. This evidence does not establish owner agreement, release, or production adoption.

## Context and decision

Azazel products need shared, evidence-aware assistance without giving a model authority over enforcement or making product lifecycle assumptions part of a common reasoning library. M.I.O. owns product-neutral interpretation of accepted observations: bounded reasoning, hypothesis and unknown representation, evidence-linked explanations, safe read-only information requests, handoff content, and behavioral evaluation. M.I.O. does not own input authentication, product permissions, network transport, persistence, model deployment, or actuation.

| Component | Owns | Explicitly does not own |
| --- | --- | --- |
| **Azazel-MIO** | Shared reasoning semantics, bounded context composition, model-independent behavior, model adapter interface, explanation/handoff shape, replay/evaluation semantics | Product authorization, collection, process supervision, durable audit sinks, enforcement, shared wire protocol |
| **Azazel-Edge** | Local telemetry and observation, deterministic risk/control decisions, communication policy, enforcement, expiry and rollback; observability of actual applied result | Shared cognitive semantics and model authority |
| **Azazel-Nexus** | Product lifecycle, admission and consent, resource budgets, model/runtime selection and process launch/health, service integration, operator UI | Independent enforcement of Edge controls; common reasoning semantics |
| **Azazel-Knowledge** | Curated knowledge lifecycle: ingestion, provenance/trust assessment, validation, storage, search and delivery | M.I.O. conclusions or product authorization |
| **Azazel-Fabric** | Cross-product wire types and compatibility/version policy | Internal M.I.O. Python API and reasoning policy |
| **Azazel-Deception** | Isolation and lifecycle of approved deception runtimes, exposure controls, and collection of their observations | M.I.O. decisions to launch, expose, or manage a runtime |

Edge remains the deterministic enforcement authority. M.I.O. may propose a check or explain an Edge decision; only Edge's authorized deterministic path decides and applies a control. Nexus owns the product agent process, admission and resource supervision. A returned explanation or Knowledge item is data, never an authorization. Deception operations require their own approved product control path; an AI hypothesis cannot cause launch or exposure.

## Migration and compatibility

The MIO candidate's `docs/migration.md` records extraction of public Edge core at Edge commit `47c880b2503d7f771bbdacba9b6205dafe03c4c7`; this is a source-history statement, not evidence that Edge production has switched to M.I.O. Edge may retain deprecated import aliases during a staged migration. The Python owner metadata may change while the v2 frame wire field set and canonical bytes remain stable; verify this with existing golden/replay fixtures before release. Fabric, not M.I.O., owns any cross-product wire versioning.

| Existing/source area | Intended target | Compatibility/migration treatment | Evidence state |
| --- | --- | --- | --- |
| Edge `py/azazel_edge/mio/` shared broker, frame/contracts, scoring, grounding, handoff, lifecycle, playbooks, reasoning, redaction, replay, trace, claim audit | M.I.O. core; Edge adapter retains observation and deterministic enforcement | Keep old Edge imports as aliases while callers migrate; preserve frame v2 bytes, fixture/golden behavior and trace semantics | Extracted in MIO candidate history; product adoption and production rollout unverified |
| Edge model transport/governance and deployment/resource measurement | Edge/Nexus product adapter according to deployment site; stable narrow MIO model-call interface underneath | Product keeps consent, endpoint allow-list, classification/minimization, timeout and budget controls; adapter maps approved structured response/errors | Proposed boundary. Process evidence used older Edge `3cad7e7...` plus MIO `f7f8a1e...` and covered transport only with model-disabled fallback; current Edge Qwen 0.8B attempt failed. No model success or production enablement established. |
| Edge OS trace persistence/export and local execution outcome | Edge | MIO returns explanation/trace data only; Edge persists accepted inputs, decisions, applied results, expiry and rollback using its existing audit boundary | Target only; no completed migration claim |
| Nexus startup/admission/runtime/resource and operator presentation | Nexus | Nexus adapter constructs bounded MIO frame, applies generation/cancellation tickets, supervises the agent process and projects result into UI | Nexus route candidate `64f522d...` has 45 exact installed-wheel tests passing; dependency lock/pin and product-process proof remain absent. Nexus retains lifecycle/UI ownership; release adoption is unverified. |
| Knowledge service | Knowledge; MIO consumes adapter-projected contexts | Authenticate origin, authorize, validate signature/schema/revocation/privacy and generations before creating context; preserve explicit unverified reports | Workspace candidate `b260ac7...`; MIO API accepts typed context values. Live production route and verified learning corpus remain unverified. |
| Shared product wire payloads | Fabric | Translate Fabric wire data at product adapters; do not freeze MIO internal Python structs as cross-product API | Workspace candidate `76169d1...`; ownership boundary is proposed and mapping/version compatibility has not been agreed or verified in a release. |

The `docs/api-v1.md` describes an internal Python API (`AssistantCore.explain`) and typed Knowledge projections; it is not a Fabric wire contract, deployment guarantee, or claim of product integration. `docs/migration.md` describes extraction lineage and import/schema-owner compatibility. Read them together: extraction establishes a candidate common-code source and intended ownership, while product adoption, persistence integration, and runtime deployment remain separate work.

## Safety and rollout constraints

- Observation facts, Knowledge reports, model hypotheses, Edge decisions and applied outcomes remain separately labeled and linked to provenance.
- Model and Knowledge loss, rejection, staleness, cancellation or timeout must degrade to explicit unknowns/static guidance; never block Edge's deterministic control path.
- Product adapters provide trusted time, opaque IDs, authentication, authorization, cancellation/supersession, egress policy and persistence. Model output cannot choose trusted playbooks or identifiers.
- MIO requests stay bounded and read-only. No control, permission change, deception launch/exposure, or arbitrary command is exposed as an MIO operation.
- External model egress requires product consent, data classification/minimization, destination approval and a budget. No default remote egress is implied.
- Verify unit/replay behavior, service integration, VM and hardware separately; a candidate fixture or lab run is not production proof.

## Review required

Product owners should confirm the exact Edge and Nexus adapter seams, Fabric mapping/version policy, Knowledge trust-generation contract, and Deception approved-control flow before treating this ADR as accepted. This ADR does not assert those integrations are complete.

# AI inventory and source-to-target map

**Evidence cut:** 2026-11-01. This inventory records public source responsibilities and the current cross-repository candidate evidence. It is not a release, deployment, or HIL attestation.

## Source responsibilities

| System | Responsibility |
| --- | --- |
| **Azazel-MIO** | Common cognition and explanation over caller-projected observations and knowledge; bounded hypotheses, unknowns, checks, handoff, model abstraction and evaluation. MIO grants no product or enforcement authority. |
| **Azazel-Edge** | Observation and deterministic judgment, enforcement, expiry and rollback. Edge remains the authority for applied controls. |
| **Azazel-Nexus** | Product admission, runtime/model selection and supervision, resource measurement, integration and operator entry. |
| **Azazel-Knowledge** | Sourced facts/context, provenance and trust assessment, validation, storage, search and delivery. |
| **Azazel-Fabric** | Shared cross-product wire schemas and compatibility policy. |
| **Azazel-Deception** | Approved decoy execution and isolation, exposure controls and observation collection. |

Product adapters own identity, authentication, authorization, trusted identifiers, cancellation, persistence, model egress policy and mapping to shared wire types. A MIO explanation, model hypothesis, suggested check, or Knowledge reference is advisory data, never an authorization or an action.

## MIO common API

`AssistantCore.explain` composes a validated frame and optional typed Knowledge projections into an `Assistance` result. The optional model callable is injected by the caller; the common package does not launch a model process or make network requests. The API can return observations, unverified hypotheses, unknowns, next checks, Knowledge projections, handoff information and a bounded reasoning trace. It does not itself provide product UI or operational audit persistence.

The capability broker and bounded reasoning loop are in-process facilities. Their capabilities are allowlisted, read-only and bounded; they do not provide action authority. Offline replay, ranking and learning workflows do not establish a verified practice corpus, production learned artifact, or automatic promotion.

## Current product candidate routes

The following evidence is from current working candidates, not repository main, a release, or production adoption. Mainline product switches are not established.

| Candidate route | Current evidence | Boundary and evidence limit |
| --- | --- | --- |
| **Edge event → MIO** | Edge candidate `py/azazel_edge_ai/mio_live_auxiliary.py` asynchronously passes bounded event context to `azazel_mio.assistant.AssistantCore`; `py/azazel_edge_ai/agent.py` contains the separate optional model lane. One local-only smoke using `qwen3.5:0.8b` passed for one event. | Fast assistance is separate from Edge's deterministic judgment and enforcement. The one-event local smoke is not HIL, production, or broad reliability evidence. The candidate has not switched Edge main/release. |
| **Nexus entryd → locald → AssistantCore fast path** | The local Nexus candidate source contains the bounded process route to MIO `AssistantCore` in `runtime/src/azazel_nexus_runtime/mio_entryd.py`, `mio_locald.py`, and `mio_fast_assistance.py`. An isolated ARM64/Python 3.12 verification passed 264 shared-wheel tests and one degraded no-wheel real-process test; a post-commit repeat passed the same checks. Independent audit of the candidate tree and logs completed with no discrepancies. No public PR head exists yet. | This verifies the local consumer path with a re-signed test Knowledge fixture; it does not verify a live Knowledge producer or full-node interoperability. It is not CI, HIL, mainline, release, or production evidence. No live Edge producer-to-API claim is established. Nexus main/release is not switched. |
| **Nexus Knowledge Lite and playbook reference** | The Nexus candidate provides a separate authenticated local Knowledge Lite socket/client in `runtime/src/azazel_nexus_runtime/knowledge_lited.py` and `knowledge_client.py`. Separately, `mio_referenced.py` serves deterministic, model-free references from verified Mission Pack playbooks; it does not use Knowledge or the MIO model path. | Approved Knowledge REST authentication/configuration and live full-node producer interoperability are absent. Downstream revocation handling for MIO-consumed Knowledge references is unknown. The playbook reference is not a Knowledge deep-reference route. |

These are candidate code and process-test claims. The test fixture and local smoke do not prove live producer provenance, full API interoperability, HIL behavior, or deployment. No local workspace path, private run artifact, token, or digest is evidence for this inventory.

## Historical note and supersession

The earlier 2026-11-01 inventory described Edge MIO as shadow/replay work, said product routes were not established, and noted the absence of a Knowledge snapshot producer from this MIO repository. Those statements describe the earlier evidence cut and repository scope. They are superseded for current candidate status by the route evidence above; they remain accurate as limits on main/release adoption and live Knowledge/API claims. The MIO repository itself still does not contain the Edge or Nexus adapters or a live Knowledge producer.

## Evidence and tracking

Source code and fixtures establish only their stated route and process boundary. They do not by themselves prove production deployment, hardware behavior, live Knowledge authentication, HIL, or mainline adoption. Relevant tracking references: MIO #1, #2, #12, #14; Edge #524; Nexus #395; Knowledge #111; Fabric #72. Open decisions include the product adapter seams, Knowledge trust/generation and revocation contract, and REST-to-Fabric mapping/version policy. Fabric owns shared wire contracts; the MIO Python API is not one. MIO owns no execution authority or automatic promotion.

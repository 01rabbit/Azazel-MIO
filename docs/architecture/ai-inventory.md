# AI inventory and source-to-target map

**Evidence cut:** 2026-11-01. This document describes public source responsibilities and the present integration state. It is not a deployment attestation or a test report.

## Source responsibilities

| System | Responsibility |
| --- | --- |
| **Azazel-MIO** | Product-neutral, bounded reasoning over caller-projected observations and knowledge; structured hypotheses, unknowns, checks, explanations and handoff data. Model access is injected through an adapter. MIO grants no product or enforcement authority. |
| **Azazel-Edge** | Telemetry observation, deterministic risk and control decisions, communication policy, enforcement, expiry and rollback. Edge remains the authority for applied controls. |
| **Azazel-Nexus** | Product lifecycle, admission and consent, runtime selection and supervision, resource budgets and operator presentation. |
| **Azazel-Knowledge** | Curated knowledge ingestion, provenance and trust assessment, validation, storage, search and delivery. |
| **Azazel-Fabric** | Cross-product wire types and their compatibility policy. |
| **Azazel-Deception** | Approved deception runtime isolation, exposure controls and collection of observations. |

MIO returns advisory reasoning data. A suggested check, explanation, hypothesis, or Knowledge item is not an authorization or an action. Product adapters own authentication, authorization, trusted identifiers, cancellation, persistence, model egress policy and any product integration.

## Current MIO behavior

`AssistantCore.explain` composes a validated frame and optional typed Knowledge projections into an `Assistance` result. The optional model callable is injected by the caller; this package does not launch a model process or make network requests itself. Results contain observations, explicitly unverified hypotheses, unknowns, next checks, Knowledge projections, handoff information and a bounded reasoning trace. The common API does not persist operational audit records or present a product UI.

The capability broker and bounded reasoning loop are available to the in-process reasoning path. Capabilities are allowlisted, read-only and bounded; evidence references are restricted to the shared closed identifier grammar. Broker audit records are sanitized. These facilities do not provide action authority.

Offline replay, ranking and learning components support evaluation workflows. They do not establish a verified practice corpus, production learned artifact, or automatic promotion of learned behavior.

## Integration state

Edge MIO use is currently shadow/replay work. The shared MIO source extraction and Edge compatibility aliases describe a migration path; they do not establish a completed product switch or production integration. Edge continues to own deterministic decisions and enforcement.

Product integration remains incomplete. The product integration path is not established as a released or production route. The Knowledge snapshot producer is absent from this public MIO source, and live Knowledge authentication, trust validation and delivery are not established here. Nexus lifecycle and UI remain Nexus responsibilities; Fabric remains the owner of cross-product wire contracts. No model deployment or external model egress is implied by this package.

## Evidence boundaries

Source code and its fixtures describe intended behavior within this repository. They do not by themselves prove product-process interoperability, deployment, hardware behavior, production adoption, or model-generation success. Any future integration claim should identify its public source and current main responsibilities, and distinguish replay or shadow evidence from live product operation. No local workspace paths or private run artifacts are evidence for this public inventory.

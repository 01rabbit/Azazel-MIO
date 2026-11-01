# AI inventory and source-to-target map

**Evidence cut: 2026-11-02.** Project-owner direction makes MIO the common AI assistance source of truth; see the [ownership ADR](ownership-adr.md). This is a source inventory, not cross-product owner consent, merged adoption, deployment, or a production contract. PR status was read from GitHub at this cut. Local refreshed candidates are not public PR heads.

## Exact public candidates

All rows are **OPEN / Draft**, not merged integration. Head identifiers are immutable source anchors; PR/check status can change.

| Repository / PR | Exact head | Scope and limit |
| --- | --- | --- |
| [MIO #15](https://github.com/01rabbit/Azazel-MIO/pull/15) | `26a5046dd493a3587f0b03dbc574211ff781d1d1` | Shared advisory API, bounded reasoning/audit delivery, lifecycle and offline evaluation. Public main is `6302e665c3ac6cf7004407965299d81dc9ddfc8a`; candidate capabilities are not main capabilities. |
| [MIO #16](https://github.com/01rabbit/Azazel-MIO/pull/16) | `92401c43b101bafcaf40f04d1ab1be86fdc097e3` | Non-authoritative operator feedback; not verified operational labels or automatic training. |
| [MIO #17](https://github.com/01rabbit/Azazel-MIO/pull/17) | `5cf1a93a1bff4486e02b3813bfa43b63ff2a7328` | Bounded source citations and empty-summary handling. |
| [MIO #18](https://github.com/01rabbit/Azazel-MIO/pull/18) | `7a9cc624e4c0b3795b0258ac95a0650364a22a80` | Request-scoped ContextResponse advisory projection and bounded source-group labels. These stacked PRs are not four independent integrations. |
| [Edge #525](https://github.com/01rabbit/Azazel-Edge/pull/525) | `e4c0661dcfd0f3835d174292756e2cff7a1b84fa` | Optional shared auxiliary and separate model lanes. [Current-head CI](https://github.com/01rabbit/Azazel-Edge/actions/runs/41359895210) has Python test failures in module-installer coverage; passing other checks does not make CI green. Refreshed Edge stack candidates remain local only. |
| [Nexus #398](https://github.com/01rabbit/Azazel-Nexus/pull/398) | `c90deb865735e1e53fac86d2a49b53753caf82c8` | Shared fast assistance through product daemons. Earlier local test-base `3e6170e` is not this head; earlier test counts must not be reassigned to this head. |

## Actual product callsites and target ownership

| Source at the anchored head | Current behavior | Target and remaining work |
| --- | --- | --- |
| [Edge agent.py](https://github.com/01rabbit/Azazel-Edge/blob/e4c0661dcfd0f3835d174292756e2cff7a1b84fa/py/azazel_edge_ai/agent.py) | Retains product model/manual/operator paths and deterministic scoring/action handling; imports separate MIO auxiliary/model lanes. | MIO owns common assistance semantics. Inventory and migrate each legacy path explicitly; presence of a new lane does not retire those callsites. Edge retains immediate deterministic decisions and enforcement. |
| [Edge mio_live_auxiliary.py](https://github.com/01rabbit/Azazel-Edge/blob/e4c0661dcfd0f3835d174292756e2cff7a1b84fa/py/azazel_edge_ai/mio_live_auxiliary.py) | Constructs `AssistantCore(model=None)` and calls `explain` with `knowledge_attempted=False`; stores bounded generation-scoped source input separately. | PR-only shared model-free assistance, not proof that Knowledge/LLM separate-time reasoning is connected. |
| [Nexus mio_fast_assistance.py](https://github.com/01rabbit/Azazel-Nexus/blob/c90deb865735e1e53fac86d2a49b53753caf82c8/runtime/src/azazel_nexus_runtime/mio_fast_assistance.py) | Projects untrusted request summaries, optionally looks up local Knowledge context within a software budget, then calls the shared core. | Common interpretation in MIO; Nexus retains trusted boundary, budgets, lifecycle, admission and operator entry. A software deadline is not a measured hardware guarantee. |
| [Nexus mio_locald.py](https://github.com/01rabbit/Azazel-Nexus/blob/c90deb865735e1e53fac86d2a49b53753caf82c8/runtime/src/azazel_nexus_runtime/mio_locald.py) | Dispatches fast assistance; retains product retrieval/inference orchestration in `retrieval_pipeline`. | No claim that all cognition has moved. Local inference is not evidence of a shared asynchronous Knowledge-to-LLM route or admitted production model. |
| [Nexus mio_referenced.py](https://github.com/01rabbit/Azazel-Nexus/blob/c90deb865735e1e53fac86d2a49b53753caf82c8/runtime/src/azazel_nexus_runtime/mio_referenced.py) | Separate deterministic Mission Pack reference service. | Not the Knowledge deep-reference/model reasoning path. |
| [MIO assistant.py (#15)](https://github.com/01rabbit/Azazel-MIO/blob/26a5046dd493a3587f0b03dbc574211ff781d1d1/src/azazel_mio/assistant.py), [#18 projection](https://github.com/01rabbit/Azazel-MIO/blob/7a9cc624e4c0b3795b0258ac95a0650364a22a80/src/azazel_mio/assistant.py) | Shared API consumes caller-projected typed context; optional injected model callable. #18 adds a separate ContextResponse projection seam. | Projection validation does not authenticate a live producer, approve its contract, or establish downstream revocation behavior. Knowledge owns provenance/trust/freshness; Fabric owns wire compatibility. |
| [MIO learning_data.py](https://github.com/01rabbit/Azazel-MIO/blob/26a5046dd493a3587f0b03dbc574211ff781d1d1/src/azazel_mio/learning_data.py), [learning_offline.py](https://github.com/01rabbit/Azazel-MIO/blob/26a5046dd493a3587f0b03dbc574211ff781d1d1/src/azazel_mio/learning_offline.py) | Bounded internal offline records/evaluation; teacher proposals and reviewer dispositions are separate. | Verified operational labels, independent outcomes, corpus/holdout and actual production training are unavailable in this evidence cut. Operator feedback is not ground truth. No automatic promotion. |

## Remaining evidence and contracts

The shared separate-time Knowledge/LLM path remains absent as an established integrated path in this cut. Synthetic local process exercises, fixtures and single-event model smokes support only their specific route and source version. They do not establish live producer authentication/full-node interoperability, external model approval, hostile-load (HG) behavior, HIL, hardware latency/resource guarantees, admission gates, main/release adoption, or production operation.

Product owners still need to accept adapter seams, source trust/freshness/revocation, identity and authorization, external egress/data policy, cancellation/persistence, and rollout. Fabric wire mapping/version policy remains pending; the internal MIO Python API is not that contract. Model hypotheses and Knowledge-reported displays remain advisory data, never authorization or applied outcomes. No owner agreement is inferred from a PR, local test, or the project-owner direction.

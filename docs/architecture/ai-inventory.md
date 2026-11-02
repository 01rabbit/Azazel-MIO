# AI inventory and source-to-target map

**Evidence cut: 2026-11-02.** Project-owner direction makes MIO the common AI assistance source of truth; see the [ownership ADR](ownership-adr.md). This is a source inventory, not cross-product owner consent, merged adoption, deployment, or a production contract. PR status was read from GitHub at this cut. The evidence base is MIO main `1aaddd76b40cc049f662e990a49e994b7be8636b`; this follow-up documentation candidate is local and not merged. Local refreshed candidates are not public PR heads.

## Exact public source anchors

MIO #15, #16, #17, #18, #19, #20 and #21 are **MERGED** into the evidence base. MIO #11 and #22 and Edge #525–#530 remain **OPEN / Draft**. Merged common-core code does not establish consumer adoption. Head identifiers are immutable source anchors; PR/check status can change.

| Repository / PR | Exact head | Scope and limit |
| --- | --- | --- |
| [MIO #15](https://github.com/01rabbit/Azazel-MIO/pull/15) | `6df0d75c1ebf835dd9b3d764300c6743335174ce` | Shared advisory API, bounded reasoning/audit delivery, lifecycle and offline evaluation. Merged as `5b92c53f45b981bf2a1420839d3ef0fe2f20215a`; included in current main. |
| [MIO #16](https://github.com/01rabbit/Azazel-MIO/pull/16) | `b5c6a99a7359dfc911dc03bb761e4dfc7af4da45` | Merged as `c6a0e0d6ef589693bc7bd54a4c2c1cdf32371524`: bounded non-authoritative operator feedback; not ground truth, verified operational labels or automatic training. |
| [MIO #17](https://github.com/01rabbit/Azazel-MIO/pull/17) | `204f82dc67e039ae79cdcfccdf4bc93ce8ed4fab` | Merged as `629b483d9f27a227f0c4750ec829227eeeba25bb`: bounded source citations and empty-summary handling. |
| [MIO #18](https://github.com/01rabbit/Azazel-MIO/pull/18) | `899362d35c4ed4f29c28039cfeb7bc6f6098e6af` | Request-scoped ContextResponse advisory projection and bounded source-group labels. Merged as `054fb17b9153b380c0930946bcc3ef7c2a63f535`; these stacked PRs are not four independent integrations. |
| [MIO #20](https://github.com/01rabbit/Azazel-MIO/pull/20) | `868bb6f82f015d324fac007b88aac64be8a8f3d1` | Merged as `fecac668e59525f6426e46d4cf7b699fcba3ff50`: tests-only learning-input integrity coverage; no runtime API addition. |
| [MIO #21](https://github.com/01rabbit/Azazel-MIO/pull/21) | `a8b1bee1775f483a7b2d7d33538896c9446a9b0c` | Merged as `9fedb01bc9936531407a5181aa8fa5553ec19d55`: bounded model-output validation diagnostics; included in current main. |
| [Edge #525](https://github.com/01rabbit/Azazel-Edge/pull/525) | `0534ed048235a92c5677c6d815321149fa6c96d5` | Draft/unmerged optional shared auxiliary and separate model lanes; committed `requirements/runtime.txt` pins MIO `9fedb01bc9936531407a5181aa8fa5553ec19d55` (#21 merge). [Current-head CI](https://github.com/01rabbit/Azazel-Edge/actions/runs/41377335195) has exactly two Python test failures in module-installer coverage (both auxiliary/model modules are missing from installer coverage); passing other checks does not make CI green. Refreshed Edge stack candidates remain local only. |
| [MIO #19](https://github.com/01rabbit/Azazel-MIO/pull/19) | `914c9296324a2fc594610daa02d825890e69e4cd` | Ownership/inventory documentation; merged as the evidence base `1aaddd76b40cc049f662e990a49e994b7be8636b`. This follow-up candidate is not that merge. |
| [MIO #11](https://github.com/01rabbit/Azazel-MIO/pull/11) | `1e2546ac5aeca09a3927cdeb2b630ea83cf2479c` | Open/draft offline IR foundation; not merged adoption. |
| [MIO #22](https://github.com/01rabbit/Azazel-MIO/pull/22) | `0aaec8be21621b0f93908ea47c20f47eea60f32f` | Open/draft bounded deterministic advisory baseline; not part of the evidence base. |
| [Edge #526](https://github.com/01rabbit/Azazel-Edge/pull/526) | `6d7f7fcf0cc4296ace053090e9a6813852b649f1` | Open/draft shadow assessment comparison. |
| [Edge #527](https://github.com/01rabbit/Azazel-Edge/pull/527) | `0b88d36cf69c411ad6ec63c6acef79202e05a924` | Open/draft operator assessment comparison. |
| [Edge #528](https://github.com/01rabbit/Azazel-Edge/pull/528) | `df61bd9847acc49d41d96d48e42046b858fb93da` | Open/draft suppression of unavailable comparisons. |
| [Edge #529](https://github.com/01rabbit/Azazel-Edge/pull/529) | `f0e625648c2a8a74b303849f1caa828ef9e7b25c` | Open/draft bounded slow Knowledge receipt. |
| [Edge #530](https://github.com/01rabbit/Azazel-Edge/pull/530) | `37b2df5801ec188647e29ad1dfbe591fae11425e` | Open/draft operator-panel Knowledge receipt. These stacked candidates do not establish merged integration. |

The private consumer integration remains stacked/draft. Full-node, Lite and model end-to-end proof is not complete; private implementation identifiers are omitted from this public inventory.

## Actual product callsites and target ownership

| Source at the anchored head | Current behavior | Target and remaining work |
| --- | --- | --- |
| [Edge agent.py](https://github.com/01rabbit/Azazel-Edge/blob/0534ed048235a92c5677c6d815321149fa6c96d5/py/azazel_edge_ai/agent.py) | Retains product model/manual/operator paths and deterministic scoring/action handling; imports separate MIO auxiliary/model lanes. | MIO owns common assistance semantics. Inventory and migrate each legacy path explicitly; presence of a new lane does not retire those callsites. Edge retains immediate deterministic decisions and enforcement. |
| [Edge mio_live_auxiliary.py](https://github.com/01rabbit/Azazel-Edge/blob/0534ed048235a92c5677c6d815321149fa6c96d5/py/azazel_edge_ai/mio_live_auxiliary.py) | Constructs `AssistantCore(model=None)` and calls `explain` with `knowledge_attempted=False`; stores bounded generation-scoped source input separately. | PR-only shared model-free assistance, not proof that Knowledge/LLM separate-time reasoning is connected. |
| [MIO assistant.py (#15)](https://github.com/01rabbit/Azazel-MIO/blob/6df0d75c1ebf835dd9b3d764300c6743335174ce/src/azazel_mio/assistant.py), [#18 projection](https://github.com/01rabbit/Azazel-MIO/blob/899362d35c4ed4f29c28039cfeb7bc6f6098e6af/src/azazel_mio/assistant.py) | Shared API consumes caller-projected typed context; optional injected model callable. #18 adds a separate ContextResponse projection seam. | Projection validation does not authenticate a live producer, approve its contract, or establish downstream revocation behavior. Knowledge owns provenance/trust/freshness; Fabric owns wire compatibility. |
| [MIO learning_data.py](https://github.com/01rabbit/Azazel-MIO/blob/6df0d75c1ebf835dd9b3d764300c6743335174ce/src/azazel_mio/learning_data.py), [learning_offline.py](https://github.com/01rabbit/Azazel-MIO/blob/6df0d75c1ebf835dd9b3d764300c6743335174ce/src/azazel_mio/learning_offline.py) | Bounded internal offline records/evaluation; teacher proposals and reviewer dispositions are separate. | Verified operational labels, independent outcomes, corpus/holdout and actual production training are unavailable in this evidence cut. Operator feedback is not ground truth. No automatic promotion. |

## Remaining evidence and contracts

The shared separate-time Knowledge/LLM path remains absent as an established integrated path in this cut. Synthetic local process exercises, fixtures and single-event model smokes support only their specific route and source version. They do not establish live producer authentication/full-node interoperability, external model approval, hostile-load (HG) behavior, HIL, hardware latency/resource guarantees, admission gates, main/release adoption, or production operation.

Product owners still need to accept adapter seams, source trust/freshness/revocation, identity and authorization, external egress/data policy, cancellation/persistence, and rollout. Fabric wire mapping/version policy remains pending; the internal MIO Python API is not that contract. Model hypotheses and Knowledge-reported displays remain advisory data, never authorization or applied outcomes. No owner agreement is inferred from a PR, local test, or the project-owner direction.

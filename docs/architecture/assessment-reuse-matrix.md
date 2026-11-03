# Assessment reuse matrix (MIO Issue 14)

Scope: documentation only. It changes no code, contracts, pins or rollout state.

Evidence SHAs (current MIO kernel and Edge scorer rows were re-read on 2026-11-04 at these commits):

- MIO current main: `4d92b4451a3bf1ec44eb7215ebadb0fd05879c1d` (tree `0970dad5a8c87b0ce002b4e24c9505301e7a0f2a`). Docs-only PR #39 advanced main from the PR #41 merge `e4a0e504bae91153f3dcb8105f8658ff80d4e884`; `src/`, `tests/`, and package metadata are unchanged. The kernel source evidence below is anchored to `e4a0`, and the earlier `03913bfcd6b9658ee6f52bd210297d96a7afdafe` and `88f26c59b91c97b8fedbc690f95766bc28928e97` observations are historical where cited.
- Edge public `main`: `38c2b07774c61b86209d0cd94ce2e7689d38600c` (scorer, agent and model-lane rows re-read at this SHA)
- Edge `cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8`: the Rust decision-loop and Rust severity rows (sections 2 and 6) are still observed only at this earlier SHA; they were not re-read at `38c2`.
- As of 2026-11-04, Edge requirements pin the MIO source commit `9fedb01bc9936531407a5181aa8fa5553ec19d55` (`requirements/runtime.txt` L10). This is older than current MIO main `4d92b4451a3bf1ec44eb7215ebadb0fd05879c1d`; open Draft #538 proposes source `b441d431532507387fb81f1e03e31fd1aea57b68` but has not changed Edge main. Package availability alone does not prove runtime deployment.

Labels:

- **Observed**: read in the cited source at the cited SHA.
- **Docstring claim**: a statement in a source's own comments, not checked against code here.
- **Proposed**: a reuse suggestion. No source here establishes it.
- **Unknown**: not inspected in this pass.

Review limits: the Rust evidence is one file (`main.rs`). I did not read the rest of the crate, its tests, or its configuration defaults.

## 1. Status of the authority boundary

- **Proposed ADR, not accepted.** The MIO ownership ADR says it "remains proposed and does not assert completed integration" and that product owners must confirm adapter seams before cross-product contracts and rollout are accepted ([ownership-adr.md L42](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/docs/architecture/ownership-adr.md#L42)).
- The ADR's proposed text is that MIO "may explain an Edge result or suggest a check" while Edge keeps deterministic decision and enforcement authority ([ownership-adr.md L21](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/docs/architecture/ownership-adr.md#L21)). No Edge owner agreement is shown here.

## 2. Edge live decision path (observed)

Source: Edge `docs/architecture/decision-loop.md` at `cbc5d77` ([L8–L40](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/docs/architecture/decision-loop.md#L8-L40)).

- The doc says "Only the first one changes the network" ([L8](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/docs/architecture/decision-loop.md#L8)).
- Live path steps 1–3: the Rust core reads EVE lines, `decide_defense()` selects an action, then `maybe_enforce()` applies it ([L10–L23](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/docs/architecture/decision-loop.md#L10-L23)). So the Rust side decides first.
- Step 4: the core forwards the decision event to the AI agent, one-way ([L24–L25](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/docs/architecture/decision-loop.md#L24-L25)).
- Step 5: the agent computes the tactical score and the second-pass SOC evaluation. The doc says "None of this changes the decision" ([L26–L29](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/docs/architecture/decision-loop.md#L26-L29)).
- Replay and dry-run path: the Python `ActionArbiter` appears there, and the doc says nothing in that path is applied to the network ([L34–L39](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/docs/architecture/decision-loop.md#L34-L39)).

Rust severity logic (observed, [`rust/azazel-edge-core/src/main.rs`](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/rust/azazel-edge-core/src/main.rs)):

- Severity is read from the alert, defaults to `3`, and is clamped to at most `10` ([L358](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/rust/azazel-edge-core/src/main.rs#L358)).
- Risk score formula: `risk_score = min(100, (11 - severity) * 9)` ([L374](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/rust/azazel-edge-core/src/main.rs#L374)). The formula assigns higher risk scores to smaller severity values.
- `decide_defense()` branches by severity ([L433–L479](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/rust/azazel-edge-core/src/main.rs#L433-L479)):
  - `<=1`: `throttle`
  - `<=2`: `redirect`
  - `==3`: `throttle`
  - `==4`: `notify`
  - `>=5`: `observe` (`baseline_observe_only`, [L472–L478](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/rust/azazel-edge-core/src/main.rs#L472-L478))
- High-risk condition: `risk_score >= 80 || severity >= 4` ([L1257](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/rust/azazel-edge-core/src/main.rs#L1257)). It appears in the redirect fallback when no prepared port mapping matches. That branch passes its policy-named action through `normalize_safe_action` ([L1257–L1263](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/rust/azazel-edge-core/src/main.rs#L1257-L1263)); the helper converts `isolate` and `redirect` to `notify`, passes `observe`, `notify` and `throttle` through, and returns the caller's default, which is `notify` at both call sites ([L181–L187](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/rust/azazel-edge-core/src/main.rs#L181-L187), [L1261](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/rust/azazel-edge-core/src/main.rs#L1261), [L1263](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/rust/azazel-edge-core/src/main.rs#L1263)). I did not trace reachability, so this remains a branch-level observation.
- Call order: `decide_defense` ([L1554](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/rust/azazel-edge-core/src/main.rs#L1554)) runs before `maybe_enforce` ([L1555](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/rust/azazel-edge-core/src/main.rs#L1555)).

`decision-loop.md` L16–L18 describes the shipped unit as observe-only (enforcement off, dry run, level `advisory`). I did not verify those settings in configuration.

## 3. Edge Python tactical scorer (advisory layer)

Source: `py/azazel_edge/tactics_engine/scorer.py` at `38c2` ([link](https://github.com/01rabbit/Azazel-Edge/blob/38c2b07774c61b86209d0cd94ce2e7689d38600c/py/azazel_edge/tactics_engine/scorer.py)).

- **Docstring claim** (L8–L13): scores are calibrated to downstream gates, with bands `<40` auto-dismiss, `40-59` LLM-advisory only, `60-84` HIGH, `85-100` CRITICAL. The bands are attributed to the docstring. They are not an authority statement, and I did not verify the gates' code.
- This scorer is a different algorithm from the Rust severity decision above. It computes an advisory score from SIDs, classtypes, tokens and ports.
- **Observed at `38c2` (shared-core comparison):** `TacticalScorer.score` computes Edge's local score and factors first. It then imports `azazel_mio.fast_assessment` (`FastAssessmentInput`, `PortSignal`, `assess_fast`) on the same path (L246–L247) and calls `assess_fast` (L252). The MIO score and factors are used only when they equal Edge's local values exactly; then `source="shared_core"` (L265–L271). Otherwise `source="edge_local"` and Edge's value is kept. An import failure or a malformed or raising result is recorded in `shadow` as `unavailable` or `degraded` (L248–L249, L276–L278). `shadow["authority"]` is `comparison_only`. The comparison is advisory-only: it does not own the Rust decision or enforcement.
- **Call path at `38c2`:** `_build_advisory` in `py/azazel_edge_ai/agent.py` (L1786) calls `SCORER.score(features)` at L1802. The agent calls `_build_advisory` at L3290.

## 4. MIO fast-assessment kernel (observed, with docstring claims)

- `assess_fast` takes normalized inputs and returns a score plus ordered factors ([fast_assessment.py at MIO main](https://github.com/01rabbit/Azazel-MIO/blob/e4a0e504bae91153f3dcb8105f8658ff80d4e884/src/azazel_mio/fast_assessment.py)). It is a pure function over `FastAssessmentInput`. A source search at `e4a0` found the function definition but no caller inside MIO `src/`; its consumers are product adapters.
- **Observed (direct constant comparison at fixed current SHAs):** I read the MIO constants at `e4a0` and Edge scorer at `38c2`, then compared the two class-weight maps, severity bases, unknown-severity base, token-only ceiling, benign level, deception floor, and severity-1 cap with an AST literal-value script. All values matched. This is a static constant comparison only, not a behavioral or parity test. MIO `e4a0` also validates bounded input sizes/types; this check did not compare those checks with Edge's adapter.
- **Edge live wiring (observed at `38c2`):** Edge's scorer imports and calls `assess_fast` as a comparison (section 3). Edge main still pins MIO `9fedb01`; open Draft #538 proposes source `b441d43` but is not main adoption.
- **Docstring claims** in the MIO module: it is adapted from Edge's scorer at commit `47c880b`, and importing it does no I/O and loads no Edge modules. `47c880b` appears only in this MIO attribution; it was not verified against Edge history.
- **Not claimed here:** any parity test result. The MIO parity-vector documentation is linked at [fast-assessment.md](https://github.com/01rabbit/Azazel-MIO/blob/e4a0e504bae91153f3dcb8105f8658ff80d4e884/docs/fast-assessment.md); this pass did not rerun that suite.
- **Resolved at `38c2`:** Edge imports this kernel, but only in `TacticalScorer.score` as a comparison (section 3). Import is inside the function, so package absence degrades to `unavailable`. This does not make the kernel the decision path.

## 5. Replay and learning

- **Replay (MIO):** [`replay.py`](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/replay.py) runs fixtures through the bounded reasoning loop with a named playbook. It does not score alerts.
- **Learning (MIO):** the module docstring says "Offline-only training/evaluation" ([learning_offline.py L1](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/learning_offline.py#L1)). The gate code requires replay to be evaluation-only ([L52](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/learning_offline.py#L52)) and training to use an accepted or corrected independent outcome ([L55–L57](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/learning_offline.py#L55-L57)).
- **Observed, narrow:** the two cited MIO locations involve `automatic_promotion`. `learning_offline.py` L173 contains a decision record with `"automatic_promotion": False` ([link](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/learning_offline.py#L173)). `ranking_registry.py` L55 rejects an evaluation report unless `automatic_promotion is False` ([link](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/ranking_registry.py#L55)).
- The cited locations are not an exhaustive guarantee. I did not search for every promotion path, so whether any other code path can promote a learned artifact into a live path is **Unknown**.
- **Unknown (Edge):** Edge replay and learning code. Not inspected.

## 6. Matrix

| Area | MIO (SHA per row) | Edge (SHA per cell) | Status |
|---|---|---|---|
| Live decision | None. | Rust `decide_defense` then `maybe_enforce` (`main.rs` L1554–L1555). | Observed call order and Edge document claim; cross-product agreement not established. |
| Advisory score | `assess_fast` at MIO `e4a0` (pure kernel; no caller inside MIO `src/`). | At `38c2`, `TacticalScorer.score` (`scorer.py` L246–L271) calls `assess_fast` as a comparison and uses its score/factors only on exact match; `_build_advisory` calls `SCORER.score` (`agent.py` L1802). The decision-loop doc (`cbc5d77`, L26–L29) says the scorer runs after the decision and does not change it. | Observed at `38c2`. Comparison only; `shadow.authority` is `comparison_only`. Static constants all match; no behavioral parity claim. Not a replacement for the Rust decision path. |
| Optional model-assisted explanation | `AssistantCore` (MIO assistant API; the model callable is injected). | Opt-in lane `LIVE_MIO_MODEL_LANE` (`agent.py` L2741), gated by `AZAZEL_MIO_MODEL_ENABLED` (default `0`, L199). `_analyze_mio_fast_result` (L2464) builds `AssistantCore(model=StructuredTransport())`; the transport calls the product Ollama path `_ollama_chat` (L2340). Separately, `mio_live_auxiliary.py` (L504) constructs `AssistantCore(model=None)`. | Observed at `38c2`. Opt-in and governed submission. `mio-live-auxiliary.md` L79–L105 covers this model lane and states that advisory authority remains unchanged; L27's `read_only_advisory` is the no-model auxiliary lane. I did not trace every consumer of the model-lane output. |
| Raw parsing and classification | Out of scope; caller pre-classifies. | Scorer derives SID, classtype, token and port signals itself. | Observed. Stays in Edge. |
| Replay | Fixture replay, no alert scoring. | Not inspected. | MIO observed. Edge Unknown. |
| Learning | Offline-only per docstring and gate code. | Not inspected. | MIO observed. Edge Unknown. |
| Cross-product agreement | ADR is proposed. | Not inspected. | Not established. |

## 7. Proposed reuse (not established)

- **P1.** Keep parsing, classification and deception/benign identification in Edge. Edge passes only normalized signals to MIO.
- **P2.** Edge `38c2` already compares the Python scorer with `assess_fast` on the ordinary event path and uses MIO's score/factors only on exact match (section 3); its scorer test covers exact match and failure cases. A fixed-head synthetic event smoke at `38c2` / pinned MIO `9fedb01` observed `79 = 79` with matching factors ([MIO #1 checkpoint](https://github.com/01rabbit/Azazel-MIO/issues/1#issuecomment-6608772543)). This is one synthetic event, not a broad parity corpus; keep the fixed-vector parity tests (`tests/test_fast_assessment.py`, not re-verified here) as the intended acceptance evidence. Separate local process evidence for Edge #538's candidate Knowledge/model path is recorded in the [AI inventory](ai-inventory.md); it does not establish scorer parity or main adoption. This is not acceptance.
- **P3.** Use MIO output only as an advisory explanation or shadow comparison. The Rust decision path stays authoritative.
- **P4.** Any learned change goes through human review and the offline gates. This is a proposed rule. The narrow observed checks in section 5 do not prove that no other promotion path exists.
- **P5.** The Rust severity decision and the Python tactical score are separate algorithms. Parity checks between MIO and Edge should target the Python advisory scorer. A Rust-to-Python parity check would be a separate, unproposed item.

## 8. Out of scope

- No tests were run on this documentation-only candidate. The separate fixed-head synthetic event model smoke is summarized in P2 and linked there; it is not a parity corpus. A separate task-local, uncommitted Edge #538 candidate process harness (local supplemental evidence on synthetic input, not Edge CI, not installed-package proof and not main behavior) is recorded in the [AI inventory](ai-inventory.md) current status. No product acceptance, rollout, HIL, or production claim is made.

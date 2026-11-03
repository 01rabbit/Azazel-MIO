# Assessment reuse matrix (MIO Issue 14)

Scope: documentation only. It changes no code, contracts, pins or rollout state.

Evidence SHAs:

- MIO base: `88f26c59b91c97b8fedbc690f95766bc28928e97`
- Edge public `main`: `cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8`

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

Source: `py/azazel_edge/tactics_engine/scorer.py` at `cbc5d77` ([link](https://github.com/01rabbit/Azazel-Edge/blob/cbc5d77df88a7c0c2aa9f1e8cd3ef4f81aa18be8/py/azazel_edge/tactics_engine/scorer.py)).

- **Docstring claim** (L8–L13): scores are calibrated to downstream gates, with bands `<40` auto-dismiss, `40-59` LLM-advisory only, `60-84` HIGH, `85-100` CRITICAL. The bands are attributed to the docstring. They are not an authority statement, and I did not verify the gates' code.
- This scorer is a different algorithm from the Rust severity decision above. It computes an advisory score from SIDs, classtypes, tokens and ports.

## 4. MIO fast-assessment kernel (observed, with docstring claims)

- `assess_fast` takes normalized inputs and returns a score plus ordered factors ([fast_assessment.py](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/fast_assessment.py)).
- **Observed (direct comparison):** I compared the constants in MIO `88f26c5` (`fast_assessment.py`) directly with the Edge scorer at `cbc5d77`. The class weights, severity bases, token ceiling `39`, deception floor `60`, benign level `25` and severity-1 cap `35` match. This is a constant-level comparison only, not a behavior or parity test.
- **Docstring claims** in the MIO module (L1–L12): it is adapted from Edge's scorer at commit `47c880b`, and importing it does no I/O and loads no Edge modules. `47c880b` appears only in this MIO attribution; I did not verify it against Edge history.
- **Not claimed here:** any parity test result. The MIO docs also name a revision for parity vectors ([fast-assessment.md](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/docs/fast-assessment.md)). This pass did not check that claim.
- **Unknown:** whether any Edge module imports this kernel.

## 5. Replay and learning

- **Replay (MIO):** [`replay.py`](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/replay.py) runs fixtures through the bounded reasoning loop with a named playbook. It does not score alerts.
- **Learning (MIO):** the module docstring says "Offline-only training/evaluation" ([learning_offline.py L1](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/learning_offline.py#L1)). The gate code requires replay to be evaluation-only ([L52](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/learning_offline.py#L52)) and training to use an accepted or corrected independent outcome ([L55–L57](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/learning_offline.py#L55-L57)).
- **Observed, narrow:** the two cited MIO locations involve `automatic_promotion`. `learning_offline.py` L173 contains a decision record with `"automatic_promotion": False` ([link](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/learning_offline.py#L173)). `ranking_registry.py` L55 rejects an evaluation report unless `automatic_promotion is False` ([link](https://github.com/01rabbit/Azazel-MIO/blob/88f26c59b91c97b8fedbc690f95766bc28928e97/src/azazel_mio/ranking_registry.py#L55)).
- The cited locations are not an exhaustive guarantee. I did not search for every promotion path, so whether any other code path can promote a learned artifact into a live path is **Unknown**.
- **Unknown (Edge):** Edge replay and learning code. Not inspected.

## 6. Matrix

| Area | MIO (base SHA) | Edge `cbc5d77` | Status |
|---|---|---|---|
| Live decision | None. | Rust `decide_defense` then `maybe_enforce` (`main.rs` L1554–L1555). | Observed call order and Edge document claim; cross-product agreement not established. |
| Advisory score | `assess_fast` (kernel, not wired to any live path shown here). | Python `TacticalScorer` runs after the decision, does not change it (`decision-loop.md` L26–L29). | Observed. Constants match. Wiring Unknown. |
| Raw parsing and classification | Out of scope; caller pre-classifies. | Scorer derives SID, classtype, token and port signals itself. | Observed. Stays in Edge. |
| Replay | Fixture replay, no alert scoring. | Not inspected. | MIO observed. Edge Unknown. |
| Learning | Offline-only per docstring and gate code. | Not inspected. | MIO observed. Edge Unknown. |
| Cross-product agreement | ADR is proposed. | Not inspected. | Not established. |

## 7. Proposed reuse (not established)

- **P1.** Keep parsing, classification and deception/benign identification in Edge. Edge passes only normalized signals to MIO.
- **P2.** Before any Edge adapter uses MIO output, compare score and factor output between the Edge Python scorer and `assess_fast` on the same normalized vectors, at the Edge head that would ship. This has not been run.
- **P3.** Use MIO output only as an advisory explanation or shadow comparison. The Rust decision path stays authoritative.
- **P4.** Any learned change goes through human review and the offline gates. This is a proposed rule. The narrow observed checks in section 5 do not prove that no other promotion path exists.
- **P5.** The Rust severity decision and the Python tactical score are separate algorithms. Parity checks between MIO and Edge should target the Python advisory scorer. A Rust-to-Python parity check would be a separate, unproposed item.

## 8. Out of scope

- No tests were run. No commits or pushes were made.
- No product acceptance, rollout, HIL, or production claim is made.

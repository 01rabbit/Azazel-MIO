# MioDeceptionContext: limitations and evidence_refs

`MioDeceptionContext.coerce` (the AZ-06 facts projection carried in
`MioSituationFrame.deception_context`) accepts two optional fields in addition
to the identifiers, lifecycle state and observation refs.

| Field | Grammar | Cap |
| --- | --- | --- |
| `limitations` | lower-case snake identifier, `[a-z][a-z0-9_]{2,63}`, no address shape, no secret word | 32 (`SITUATION_FRAME_DECEPTION_LIMITATIONS_CAP`) |
| `evidence_refs` | opaque ID (`opaque_id`: no address shape, no secret shape), e.g. objective, hypothesis, frame, decision or session refs | 16 (`SITUATION_FRAME_DECEPTION_EVIDENCE_REFS_CAP`) |

## Semantics

- Both are carried as opaque identifiers. MIO does not resolve, fetch or
  interpret a ref, and does not look up what a limitation means.
- A limitation is an unresolved condition (for example
  `no_interaction_observed_is_not_evidence_of_safety`). It is never added to
  `known_facts` and is not a label for training or ranking. It confers no
  authority.
- Attacker-derived strings are not accepted: only the identifier grammars above.

## Rejection

Unlike `observation_refs`, which silently drops invalid entries, an invalid
`limitations` or `evidence_refs` rejects the whole context (`coerce` returns
`None`; `MioSituationFrame.build` then reports the deception dependency as
degraded, `from_dict` raises). Rejected: a non-list value, more entries than
the cap, a non-string, a grammar or address/secret violation, and any entry
with a segment (split on `_ - : .`) in `DECEPTION_CONTEXT_FORBIDDEN_WORDS`
(`activate`, `authorized`, `execute`, `override`, `allow`, `grant`, ...; a
superset of `grounding.FORBIDDEN_DIRECTIVE_KEYS`).

## Compatibility

Both fields default to empty. `to_dict()` emits them only when non-empty, so a
context without them serializes byte-for-byte as before and stored
`mio.situation_frame.v2` frames remain valid; no schema version change. When
the frame exceeds its byte budget, `evidence_refs` then `limitations` are
trimmed after `observation_refs` (the context itself stays).

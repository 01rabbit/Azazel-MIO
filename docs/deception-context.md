# MioDeceptionContext: limitations and evidence_refs

`MioDeceptionContext.coerce` (the AZ-06 facts projection carried in
`MioSituationFrame.deception_context`) accepts two optional fields in addition
to the identifiers, lifecycle state and observation refs.

| Field | Grammar | Cap |
| --- | --- | --- |
| `limitations` | `[a-z][a-z0-9_]{2,63}(:[A-Za-z0-9._-]{1,64})?` (optional parameter), no secret word | 32 (`SITUATION_FRAME_DECEPTION_LIMITATIONS_CAP`) |
| `evidence_refs` | `[a-z][a-z0-9_]{0,31}:` kind prefix plus a body of `[A-Za-z0-9._~@=+:-]` (1 to 128), no address or secret shape; e.g. `advisory:mio-hypothesis-f1~h1`, `frame:<id>`, `decision:<id>` | 16 (`SITUATION_FRAME_DECEPTION_EVIDENCE_REFS_CAP`) |

## Semantics

- Both are carried as opaque identifiers. MIO does not resolve, fetch or
  interpret a ref, and does not look up what a limitation means.
- A limitation is an unresolved condition (for example
  `no_interaction_observed_is_not_evidence_of_safety`). It is never added to
  `known_facts` and is not a label for training or ranking. It confers no
  authority.
- Strings that do not match the grammars above, and entries containing an
  imperative word, are not accepted.

## Dropped entries

An entry is dropped on its own; the context is kept. Dropped: a non-string,
a grammar, address or secret violation, an entry past the cap, and any entry
with a segment (split on `_ - . ~ : @ = +`, lower-cased) in
`DECEPTION_CONTEXT_FORBIDDEN_WORDS` (`activate`, `authorized`, `execute`,
`run`, `block`, `isolate`, `redirect`, `override`, `enforce`, `grant`, `granted`, `bypass`, ...; 35 words). Segments are compared whole, so
`redirection`, `isolation` and `active` pass. The shared convention splits on `_ - . ~ :`; MIO also splits on `@ = +`, which is stricter (it can only drop more). A non-list value drops that
field. `MioDeceptionContext.coerce_with_drops` reports whether anything was
dropped, and `MioSituationFrame.build` then adds the unknown
`DECEPTION_CONTEXT_ENTRY_DROPPED`.

## Compatibility

Both fields default to empty. `to_dict()` emits them only when non-empty, so a
context without them serializes byte-for-byte as before and stored
`mio.situation_frame.v2` frames remain valid; no schema version change. An
explicit empty list is dropped to the same canonical form by `build`, but
`from_dict` of a stored frame carrying `[]` is rejected as non-canonical. When
the frame exceeds its byte budget, `observation_refs` then `evidence_refs`
are trimmed first; `limitations` follow `known_facts`. The full order is evidence_refs, known_facts, limitations, contradictions, unknowns.

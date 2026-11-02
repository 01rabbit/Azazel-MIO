# Portable fast assessment kernel

`azazel_mio.fast_assessment.assess_fast` is a pure score-combination kernel
ported from Edge's `TacticalScorer` at
`47c880b2503d7f771bbdacba9b6205dafe03c4c7`. The input is already normalized;
Edge remains responsible for raw event parsing, lowercase and integer
coercion, exact SID and classtype recognition, token matching, port
classification, and deciding whether the alert is a deception SID or a
classless benign category. No Edge module is imported here.

The API accepts canonical classes, a token-only flag, classified port signals,
the normalized action, and the product's deception/benign classifications. It
returns an integer score and an ordered tuple of factors. Known class weights
are combined by maximum, never by sum. Unknown class or port labels are
ignored.

The order and score semantics are locked by independent golden values in
`tests/test_fast_assessment.py`, including token and severity caps, the
deception floor below 60 and the already-above-floor path, benign dampening,
and unknown labels. A deception score below 60 is raised to exactly 60; an
unfloored score of 61 is also possible. The goldens cover both the exact floor
result and a score already above the floor.
Edge adapter integration remains a separate change and must compare complete
score/factor outputs before it replaces any local calculation.

The adapted source retains Edge's MIT notice in
`LICENSES/edge-tactical-scorer-MIT.txt`.

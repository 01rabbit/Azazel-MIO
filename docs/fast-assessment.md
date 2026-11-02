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

The order and score semantics are covered by local kernel goldens and a
separate source-derived parity slice in `tests/test_fast_assessment.py`. The
parity vectors use already-normalized inputs and expected score/factor tuples
independently run with Edge `TacticalScorer.score()` from source revision
`47c880b2503d7f771bbdacba9b6205dafe03c4c7`. Parity claims are scoped to the
`47c880b` algorithm. The source is present at Edge PR head
`df61bd9847acc49d41d96d48e42046b858fb93da`, which adds shadow comparison
bookkeeping while preserving the score and factor algorithm.

The vectors cover unknown severity/class fallback, the token-only ceiling at
39, class/port/action factor ordering with a score of 93, benign dampening at
25, a deception SID path already above the 60 floor, and a low-severity real
deception SID with a low-weight class (severity 4, `recon`, no ports) that is
raised to the floor. The 93 vector uses Edge SID `9901251`, a deception SID,
and the floor does not alter it because its score is already above 60.

The low-severity floor vector was also run directly against the Edge scorer
during independent review: Edge SID `9901101`, severity 4, no ports produces 60
with `severity=4`, `sid_present`, `threat_class=recon(30)`, and
`deception_floor`. Its expected MIO score and factors are the same.

The Edge-side feature mappings are: `suricata_sev=9`, no class-producing
SID/category/signature, action unknown; token-only `c2 beacon`, port 22,
rejected; SID `9901251` (c2, deception SID) plus signature token `exfil`, port
443, drop; classless category `misc-activity`; SID `9901101` with port 18080;
and SID `9901101` at severity 4 with no port. These are source-to-normalized
fixture mappings, not raw-event parser tests.

Edge's scorer defines score bands below 40, 40-59, 60-84, and 85-100; it does
not emit a recommendation field. Edge remains authoritative for raw event
parsing, normalization, enforcement, and any recommendation. MIO only compares
the kernel's advisory score and ordered factors against these normalized
signals.

Edge adapter integration remains a separate change and must compare complete
score/factor outputs before it replaces any local calculation.

The adapted source retains Edge's MIT notice in
`LICENSES/edge-tactical-scorer-MIT.txt`.

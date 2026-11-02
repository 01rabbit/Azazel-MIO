# Synthetic adversarial IR fixtures

All files here are fictional, synthetic test inputs for `tests/test_ir_adversarial.py`.
They are not evidence from any real system and carry no verdict.

- `malformed.jsonl`: second line is an unterminated JSON object.
- `malformed.json`: a JSON array that is cut off before it closes.
- `injection.jsonl`: summaries containing instruction-like text. The text is stored and
  reported as plain data; it must not change verification results or report fields.

# Advisory assessment baseline (experimental)

This is a reusable MIO core prototype, **not** an IR parser, malware detector, calibrated risk probability or production defensive decision engine. Inputs must be explicitly validated signals from a trusted adapter/reviewer. Unrecognized signals are counted and do not imply benign behavior. Rule weights are provisional for tests only and must be evaluated against a representative dataset and existing Edge baselines before admission. No network, LLM or execution capability. Integration with the standalone IR adapter and Fabric remains a separate change.

Run with Python 3.12+:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_assessment.py'
```

No test execution or ARM64 guest validation is claimed by this document.

import unittest
from azazel_mio.assessment import Observation, assess

class AssessmentTests(unittest.TestCase):
    def test_empty_abstains(self):
        result = assess("case-1", [])
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertEqual(result["priority_index"], 0)

    def test_traceable_and_deterministic(self):
        items = [Observation("a", "ev-2", "suspicious_process"),
                 Observation("a", "ev-1", "suspicious_process"),
                 Observation("a", "ev-3", "unusual_outbound")]
        self.assertEqual(assess("a", items), assess("a", reversed(items)))
        result = assess("a", items)
        self.assertEqual(result["priority_index"], 50)
        self.assertEqual(result["authorized_actions"], [])
        self.assertEqual(result["rule_hits"][0]["evidence_ids"], ["ev-1", "ev-2"])

    def test_cross_case_rejected(self):
        with self.assertRaises(ValueError):
            assess("a", [Observation("b", "ev", "suspicious_process")])

    def test_unknown_signal_not_assumed_benign(self):
        result = assess("a", [Observation("a", "ev", "unknown")])
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertEqual(result["unsupported_observations"], 1)

    def test_duplicate_does_not_inflate(self):
        one = Observation("a", "ev", "authentication_failures")
        self.assertEqual(assess("a", [one, one])["priority_index"], 15)

    def test_lazy_inputs_are_bounded(self):
        for finite in (False, True):
            with self.subTest(finite=finite):
                pulls = []

                def observations():
                    while not finite or len(pulls) < 10002:
                        pulls.append(None)
                        if len(pulls) > 10001:
                            self.fail("consumed beyond limit plus one")
                        yield Observation("a", "ev", "suspicious_process")

                with self.assertRaisesRegex(ValueError, "^too many observations$"):
                    assess("a", observations())
                self.assertEqual(len(pulls), 10001)

    def test_exact_limit_is_accepted(self):
        result = assess("a", (Observation("a", "ev", "suspicious_process")
                              for _ in range(10000)))
        self.assertEqual(result["priority_index"], 30)

    def test_invalid_fields_have_controlled_errors(self):
        invalid = (None, 1, [], {}, "", " ", " padded", "padded ",
                   "a\nb", "a\x00b", "x" * 257)
        for value in invalid:
            with self.subTest(field="case_id", value=value):
                with self.assertRaisesRegex(ValueError, "^invalid case_id$"):
                    assess(value, [])
            with self.subTest(field="observation.case_id", value=value):
                with self.assertRaisesRegex(ValueError, "^invalid or cross-case observation$"):
                    assess("a", [Observation(value, "ev", "suspicious_process")])
            with self.subTest(field="evidence_id", value=value):
                with self.assertRaisesRegex(ValueError, "^invalid evidence reference$"):
                    assess("a", [Observation("a", value, "suspicious_process")])
            with self.subTest(field="signal", value=value):
                with self.assertRaisesRegex(ValueError, "^invalid signal$"):
                    assess("a", [Observation("a", "ev", value)])
        with self.assertRaisesRegex(ValueError, "^invalid signal$"):
            assess("a", [Observation("a", "ev", "x" * 129)])

    def test_field_length_boundaries(self):
        result = assess("a" * 256, [Observation("a" * 256, "e" * 256, "s" * 128)])
        self.assertEqual(result["unsupported_observations"], 1)

    def test_invalid_observation_and_collection(self):
        for value in (None, 1, object()):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "^observations must be iterable$"):
                    assess("a", value)
                with self.assertRaisesRegex(ValueError, "^invalid or cross-case observation$"):
                    assess("a", [value])

if __name__ == "__main__":
    unittest.main()

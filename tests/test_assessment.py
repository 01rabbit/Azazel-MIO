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

if __name__ == "__main__":
    unittest.main()
